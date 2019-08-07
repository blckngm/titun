// Copyright 2018 Guanhao Yin <sopium@mysterious.site>

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

// XXX: named pipe security???

use crate::ipc::commands::*;
use crate::ipc::parse::*;
use crate::wireguard::re_exports::U8Array;
use crate::wireguard::{SetPeerCommand, WgState, WgStateOut};
use failure::{Error, ResultExt};
use futures::io::BufWriter;
use futures::prelude::*;
use hex::encode;
use std::marker::Unpin;
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::SystemTime;

#[cfg(windows)]
pub async fn ipc_server(wg: Weak<WgState>, dev_name: &str) -> Result<(), Error> {
    use crate::ipc::windows_named_pipe::*;

    let mut path = Path::new(r#"\\.\pipe\wireguard"#).join(dev_name);
    path.set_extension("sock");
    let mut listener = AsyncPipeListener::bind(path).context("Bind IPC socket")?;
    loop {
        let wg = wg.clone();
        let stream = listener.accept().await?;
        tokio::spawn(async move {
            serve(&wg, stream).await.unwrap_or_else(|e| {
                warn!("Error serving IPC connection: {}", e);
            });
        });
    }
}

#[cfg(not(windows))]
pub async fn ipc_server(wg: Weak<WgState>, dev_name: &str) -> Result<(), Error> {
    use futures::prelude::*;
    use futures::select;
    use nix::sys::stat::{umask, Mode};
    use pin_utils::pin_mut;
    use std::fs::{create_dir_all, remove_file};
    use tokio::net::UnixListener;

    umask(Mode::from_bits(0o077).unwrap());
    let dir = Path::new(r#"/var/run/wireguard"#);
    create_dir_all(&dir).context("Create directory /var/run/wireguard")?;
    let mut path = dir.join(dev_name);
    path.set_extension("sock");
    let _ = remove_file(path.as_path());
    let mut listener = UnixListener::bind(path.as_path()).context("Bind IPC socket.")?;

    crate::systemd::notify_ready().unwrap_or_else(|e| warn!("Failed to notify systemd: {}", e));

    let deleted = super::wait_delete::wait_delete(&path).fuse();
    pin_mut!(deleted);

    loop {
        let accept = listener.accept().fuse();
        pin_mut!(accept);
        let wg = wg.clone();
        let (stream, _) = select! {
            stream_or_err = accept => stream_or_err?,
            deleted = deleted => {
                deleted?;
                info!("IPC socket deleted. Shutting down.");
                return Ok(());
            },
        };
        let stream = super::compat::Compat::new(stream);
        tokio::spawn(async move {
            serve(&wg, stream).await.unwrap_or_else(|e| {
                warn!("Error serving IPC connection: {}", e);
            })
        });
    }
}

macro_rules! writeln {
    ($dst:expr, $fmt:expr, $($arg:tt)*) => {{
        let it = format!(concat!($fmt, "\n"), $($arg)*);
        $dst.write_all(it.as_bytes()).await
    }};
    ($dst:expr, $fmt:expr) => {
        $dst.write_all(concat!($fmt, "\n").as_bytes()).await
    };
    ($dst:expr) => {
        $dst.write_all("\n".as_bytes()).await
    };
}

async fn write_wg_state(
    mut w: impl AsyncWrite + Unpin + 'static,
    state: &WgStateOut,
) -> Result<(), ::std::io::Error> {
    writeln!(w, "private_key={}", encode(state.private_key.as_slice()))?;
    writeln!(w, "listen_port={}", state.listen_port)?;
    if state.fwmark != 0 {
        writeln!(w, "fwmark={}", state.fwmark)?;
    }
    for p in &state.peers {
        writeln!(w, "public_key={}", encode(p.public_key.as_slice()))?;
        if let Some(ref psk) = p.preshared_key {
            writeln!(w, "preshared_key={}", encode(psk))?;
        }
        for a in &p.allowed_ips {
            writeln!(w, "allowed_ip={}/{}", a.0, a.1)?;
        }
        writeln!(
            w,
            "persistent_keepalive_interval={}",
            p.persistent_keepalive_interval.unwrap_or(0)
        )?;
        if let Some(ref e) = p.endpoint {
            writeln!(w, "endpoint={}", e)?;
        }
        writeln!(w, "rx_bytes={}", p.rx_bytes)?;
        writeln!(w, "tx_bytes={}", p.tx_bytes)?;
        if let Some(ref t) = p.last_handshake_time {
            let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
            let secs = d.as_secs();
            let nanos = d.subsec_nanos();
            writeln!(w, "last_handshake_time_sec={}", secs)?;
            writeln!(w, "last_handshake_time_nsec={}", nanos)?;
        }
    }
    writeln!(w, "errno=0")?;
    writeln!(w)?;
    w.flush().await
}

async fn write_error(
    mut stream: impl AsyncWrite + Unpin + 'static,
    errno: i32,
) -> Result<(), ::std::io::Error> {
    writeln!(stream, "errno={}", errno)?;
    writeln!(stream)?;
    stream.flush().await
}

async fn process_wg_set(wg: &Arc<WgState>, command: WgSetCommand) {
    if let Some(key) = command.private_key {
        wg.set_key(key);
    }
    if let Some(p) = command.listen_port {
        wg.set_port(p).await.unwrap_or_else(|e| {
            warn!("Failed to set port: {}", e);
        });
    }
    if let Some(fwmark) = command.fwmark {
        wg.set_fwmark(fwmark).unwrap_or_else(|e| {
            warn!("Failed to set fwmark: {}", e);
        });
    }
    if command.replace_peers {
        wg.remove_all_peers();
    }
    for p in command.peers {
        if p.remove {
            wg.remove_peer(&p.public_key);
            continue;
        }
        if !wg.peer_exists(&p.public_key) {
            wg.clone().add_peer(&p.public_key).unwrap();
        }
        wg.set_peer(SetPeerCommand {
            public_key: p.public_key,
            preshared_key: p.preshared_key,
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips,
            persistent_keepalive_interval: p.persistent_keepalive_interval,
            replace_allowed_ips: p.replace_allowed_ips,
        })
        .unwrap();
    }
}

pub async fn serve<S>(wg: &Weak<WgState>, stream: S) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + 'static,
{
    let (stream_r, stream_w) = stream.split();

    let stream_w = BufWriter::with_capacity(4096, stream_w);

    // TODO: limit total length of input stream.
    let c = match parse_command_io(stream_r).await {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(()),
        Err(e) => {
            drop(write_error(stream_w, /* EINVAL */ 22));
            return Err(e);
        }
    };
    let wg = match wg.upgrade() {
        None => {
            write_error(stream_w, /* ENXIO */ 6).await?;
            bail!("WgState no longer available");
        }
        Some(wg) => wg,
    };
    match c {
        WgIpcCommand::Get => {
            let state = wg.get_state();
            write_wg_state(stream_w, &state).await?;
        }
        WgIpcCommand::Set(sc) => {
            // FnMut hack.
            process_wg_set(&wg, sc).await;
            write_error(stream_w, 0).await?;
        }
    }
    Ok(())
}
