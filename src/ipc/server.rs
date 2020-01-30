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
use crate::wireguard::{SetPeerCommand, WgState, WgStateOut};
use anyhow::Context;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Weak};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::oneshot::Sender;

#[cfg(windows)]
pub async fn ipc_server(
    wg: Weak<WgState>,
    dev_name: &OsStr,
    ready: Sender<()>,
) -> anyhow::Result<()> {
    use crate::ipc::windows_named_pipe::*;

    let name = dev_name.to_string_lossy().into_owned();
    let mut path = Path::new(r#"\\.\pipe\wireguard"#).join(dev_name);
    path.set_extension("sock");
    let mut listener = AsyncPipeListener::bind(path).context("failed to bind IPC socket")?;
    let _ = ready.send(());
    loop {
        let wg = wg.clone();
        let stream = listener.accept().await?;
        let name = name.clone();
        tokio::spawn(async move {
            serve(&wg, stream, name).await.unwrap_or_else(|e| {
                warn!("Error serving IPC connection: {:#}", e);
            });
        });
    }
}

#[cfg(not(windows))]
pub async fn ipc_server(
    wg: Weak<WgState>,
    dev_name: &OsStr,
    ready: Sender<()>,
) -> anyhow::Result<()> {
    use nix::sys::stat::{umask, Mode};
    use std::fs::{create_dir_all, remove_file};
    use tokio::net::UnixListener;

    umask(Mode::from_bits(0o077).unwrap());
    let dir = Path::new(r#"/var/run/wireguard"#);
    create_dir_all(&dir).context("failed to create directory /var/run/wireguard")?;
    let mut path = dir.join(dev_name);
    path.set_extension("sock");
    let _ = remove_file(path.as_path());
    let mut listener = UnixListener::bind(path.as_path()).context("failed to bind IPC socket")?;

    let deleted = super::wait_delete::wait_delete(&path, ready);
    tokio::pin!(deleted);

    loop {
        tokio::select! {
            deleted_result = &mut deleted => {
                deleted_result?;
                info!("IPC socket deleted. Shutting down.");
                return Ok(());
            }
            accept_result = listener.accept() => {
                let (stream, _) = accept_result?;
                let wg = wg.clone();
                tokio::spawn(async move {
                    serve(&wg, stream).await.unwrap_or_else(|e| {
                        warn!("Error serving IPC connection: {:#}", e);
                    });
                });
            }
        }
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

#[cfg(not(windows))]
async fn write_wg_state(
    mut w: impl AsyncWrite + Unpin + 'static,
    state: WgStateOut,
) -> io::Result<()> {
    use crate::wireguard::re_exports::U8Array;
    use hex::encode;
    use std::time::SystemTime;

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
            p.persistent_keepalive_interval,
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

#[cfg(windows)]
async fn write_wg_state(
    mut w: impl AsyncWrite + Unpin + 'static,
    state: WgStateOut,
    name: String,
) -> io::Result<()> {
    let state: state_json::WgStateOutJson = (name, state).into();
    let state_json_str = serde_json::to_string(&state).expect("serialize status");
    w.write_all(state_json_str.as_bytes()).await?;
    w.flush().await
}

async fn write_error(mut stream: impl AsyncWrite + Unpin + 'static, errno: i32) -> io::Result<()> {
    writeln!(stream, "errno={}", errno)?;
    writeln!(stream)?;
    stream.flush().await
}

async fn process_wg_set(wg: &Arc<WgState>, command: WgSetCommand) -> io::Result<()> {
    info!("processing a set request");
    let _state_change = wg.state_change_advisory.lock().await;

    if let Some(key) = command.private_key {
        info!("set private key");
        wg.set_key(key);
    }
    if let Some(p) = command.listen_port {
        info!("set listen port");
        wg.set_port(p).await.map_err(|e| {
            warn!("failed to set port: {:#}", e);
            e
        })?;
    }
    if let Some(fwmark) = command.fwmark {
        info!("set fwmark");
        wg.set_fwmark(fwmark).map_err(|e| {
            warn!("failed to set fwmark: {:#}", e);
            e
        })?;
    }
    if command.replace_peers {
        info!("will replace all peers");
        wg.remove_all_peers();
    }
    for p in command.peers {
        info!("setting peer {}", base64::encode(&p.public_key));
        if p.remove {
            info!("removing peer");
            wg.remove_peer(&p.public_key);
            continue;
        }
        if !wg.peer_exists(&p.public_key) {
            info!("adding peer");
            wg.clone().add_peer(&p.public_key).unwrap();
        }
        wg.set_peer(SetPeerCommand {
            public_key: p.public_key,
            preshared_key: p.preshared_key,
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips,
            keepalive: p.persistent_keepalive_interval,
            replace_allowed_ips: p.replace_allowed_ips,
        })
        .unwrap();
    }
    Ok(())
}

pub async fn serve<S>(
    wg: &Weak<WgState>,
    stream: S,
    #[cfg(windows)] name: String,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + 'static,
{
    let (stream_r, stream_w) = tokio::io::split(stream);

    let stream_w = BufWriter::with_capacity(4096, stream_w);

    let c = match parse_command_io(stream_r.take(1024 * 1024)).await {
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
            write_wg_state(
                stream_w,
                state,
                #[cfg(windows)]
                name,
            )
            .await?;
        }
        WgIpcCommand::Set(sc) => {
            // FnMut hack.
            let errno = match process_wg_set(&wg, sc).await {
                Ok(()) => 0,
                Err(e) => e.raw_os_error().unwrap(),
            };
            write_error(stream_w, errno).await?;
        }
    }
    Ok(())
}

#[cfg(windows)]
mod state_json {
    use crate::wireguard::types::{PeerStateOut, WgStateOut};
    use serde::Serialize;
    use std::net::SocketAddr;
    use std::time::SystemTime;

    /// State of WireGuard interface.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WgStateOutJson {
        name: String,
        /// Self public key.
        public_key: String,
        /// Peers.
        peers: Vec<PeerStateOutJson>,
        /// Port.
        listen_port: u16,
        /// Fwmark.
        fwmark: u32,
    }

    /// State of a peer.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PeerStateOutJson {
        /// Public key.
        public_key: String,
        /// Pre-shared key.
        preshared_key: bool,
        /// Endpoint.
        endpoint: Option<SocketAddr>,
        /// Last handshake time seconds after UNIX epoch.
        last_handshake_time_sec: Option<u64>,
        /// Received bytes.
        rx_bytes: u64,
        /// Sent bytes.
        tx_bytes: u64,
        /// Persistent keep-alive interval.
        ///
        /// Zero value means persistent keepalive is not enabled.
        persistent_keepalive_interval: u16,
        /// Allowed IP addresses.
        allowed_ips: Vec<String>,
    }

    impl From<(String, WgStateOut)> for WgStateOutJson {
        fn from((name, state): (String, WgStateOut)) -> WgStateOutJson {
            WgStateOutJson {
                name,
                public_key: base64::encode(state.private_key.public_key()),
                listen_port: state.listen_port,
                fwmark: state.fwmark,
                peers: state.peers.into_iter().map(|p| p.into()).collect(),
            }
        }
    }

    impl From<PeerStateOut> for PeerStateOutJson {
        fn from(p: PeerStateOut) -> PeerStateOutJson {
            PeerStateOutJson {
                public_key: base64::encode(&p.public_key),
                preshared_key: p.preshared_key.is_some(),
                endpoint: p.endpoint,
                last_handshake_time_sec: p
                    .last_handshake_time
                    .map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                persistent_keepalive_interval: p.persistent_keepalive_interval,
                allowed_ips: p
                    .allowed_ips
                    .into_iter()
                    .map(|(a, p)| {
                        let max_prefix_len = if a.is_ipv4() { 32 } else { 128 };
                        if p == max_prefix_len {
                            format!("{}", a)
                        } else {
                            format!("{}/{}", a, p)
                        }
                    })
                    .collect(),
            }
        }
    }
}
