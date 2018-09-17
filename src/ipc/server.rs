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
use hex::encode;
use std::io::BufWriter;
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::SystemTime;
use tokio::codec::FramedRead;
use tokio::prelude::*;

#[cfg(windows)]
pub async fn start_ipc_server(wg: Weak<WgState>, dev_name: &str) -> Result<(), Error> {
    // TODO.
    unimplemented!()
}

#[cfg(unix)]
pub async fn start_ipc_server(wg: Weak<WgState>, dev_name: &str) -> Result<(), Error> {
    use crate::cancellation::CancellationTokenSource;
    use nix::sys::stat::{umask, Mode};
    use std::fs::{create_dir_all, remove_file};
    use tokio::net::UnixListener;

    let source = CancellationTokenSource::new();

    umask(Mode::from_bits(0o077).unwrap());
    let dir = Path::new(r#"/run/wireguard"#);
    create_dir_all(&dir).context("Create directory /run/wireguard")?;
    let mut path = dir.join(dev_name);
    path.set_extension("sock");
    let _ = remove_file(path.as_path());
    let listener = UnixListener::bind(path.as_path()).context("Bind IPC socket.")?;
    let mut incoming = listener.incoming();
    loop {
        let stream = await!(incoming.next()).unwrap()?;
        let wg = wg.clone();
        source.spawn_async(
            async move {
                if let Err(e) = await!(serve(wg, stream)) {
                    warn!("Error serving IPC: {}", e);
                }
            },
        );
    }
}

// TODO: optimization: don't use format.
macro_rules! writeln_async {
    ($dst:expr, $fmt:expr, $($arg:tt)*) => {{
        let it = format!(concat!($fmt, "\n"), $($arg)*);
        await!($dst.write_all_async(it.as_bytes()))
    }};
    ($dst:expr, $fmt:expr) => {
        await!($dst.write_all_async(concat!($fmt, "\n").as_bytes()))
    };
    ($dst:expr) => {
        await!($dst.write_all_async("\n".as_bytes()))
    };
}

async fn write_wg_state(
    w: impl AsyncWrite + 'static,
    state: WgStateOut,
) -> Result<(), ::std::io::Error> {
    let mut w = BufWriter::with_capacity(4096, w);
    writeln_async!(w, "private_key={}", encode(state.private_key.as_slice()))?;
    writeln_async!(w, "listen_port={}", state.listen_port)?;
    if state.fwmark != 0 {
        writeln_async!(w, "fwmark={}", state.fwmark)?;
    }
    for p in &state.peers {
        writeln_async!(w, "public_key={}", encode(p.public_key.as_slice()))?;
        if let Some(ref psk) = p.preshared_key {
            writeln_async!(w, "preshared_key={}", encode(psk))?;
        }
        for a in &p.allowed_ips {
            writeln_async!(w, "allowed_ip={}/{}", a.0, a.1)?;
        }
        writeln_async!(
            w,
            "persistent_keepalive_interval={}",
            p.persistent_keepalive_interval.unwrap_or(0)
        )?;
        if let Some(ref e) = p.endpoint {
            writeln_async!(w, "endpoint={}", e)?;
        }
        writeln_async!(w, "rx_bytes={}", p.rx_bytes)?;
        writeln_async!(w, "tx_bytes={}", p.tx_bytes)?;
        if let Some(ref t) = p.last_handshake_time {
            let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
            let secs = d.as_secs();
            let nanos = d.subsec_nanos();
            writeln_async!(w, "last_handshake_time_sec={}", secs)?;
            writeln_async!(w, "last_handshake_time_nsec={}", nanos)?;
        }
    }
    writeln_async!(w, "errno=0")?;
    writeln_async!(w)?;
    await!(w.flush_async())
}

async fn write_error(mut stream: impl AsyncWrite, errno: i32) -> Result<(), ::std::io::Error> {
    let output = format!("errno={}\n\n", errno);
    await!(stream.write_all_async(output.as_bytes()))?;
    Ok(())
}

fn process_wg_set(wg: &Arc<WgState>, command: WgSetCommand) {
    if let Some(key) = command.private_key {
        wg.set_key(key);
    }
    if let Some(p) = command.listen_port {
        wg.set_port(p).unwrap_or_else(|e| {
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
            wg.add_peer(&p.public_key);
        }
        wg.set_peer(SetPeerCommand {
            public_key: p.public_key,
            preshared_key: p.preshared_key,
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips,
            persistent_keepalive_interval: p.persistent_keepalive_interval,
            replace_allowed_ips: p.replace_allowed_ips,
        }).unwrap();
    }
}

pub async fn serve<S>(wg: Weak<WgState>, stream: S) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + 'static,
{
    let (read_half, write_half) = stream.split();

    let mut commands = FramedRead::new(read_half, command_decoder());

    let c = match await!(commands.next()) {
        Some(Err(ReadCommandError::IoError(e))) => {
            bail!("IO Error: {}", e);
        }
        Some(Err(ReadCommandError::ParseError(e))) => {
            await!(write_error(write_half, /* EINVAL */ 22))?;
            bail!("Failed to parse command: {:?}", e);
        }
        Some(Err(ReadCommandError::TooLarge)) => {
            await!(write_error(write_half, /* ENOMEM */ 12))?;
            bail!("Failed to read command, command too large.");
        }
        None => return Ok(()),
        Some(Ok(c)) => c,
    };
    let wg = match wg.upgrade() {
        None => {
            await!(write_error(write_half, /* ENXIO */ 6))?;
            bail!("WgState no longer available");
        }
        Some(wg) => wg,
    };
    match c {
        WgIpcCommand::Get => {
            await!(write_wg_state(write_half, wg.get_state()))?;
        }
        WgIpcCommand::Set(sc) => {
            process_wg_set(&wg, sc);
            await!(write_error(write_half, 0))?;
        }
    }
    Ok(())
}
