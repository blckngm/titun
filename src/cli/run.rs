// Copyright 2017, 2019 Guanhao Yin <sopium@mysterious.site>

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

use crate::async_utils::AsyncScope;
#[cfg(unix)]
use crate::cli::daemonize::NotifyHandle;
use crate::cli::Config;
use crate::ipc::ipc_server;
use crate::wireguard::*;
use anyhow::{Context, Error};
use futures::prelude::*;

#[cfg(not(unix))]
type NotifyHandle = ();

fn schedule_force_shutdown() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        warn!("Clean shutdown seem to have failed. Force shutting down.");
        std::process::exit(0);
    });
}

#[cfg(unix)]
async fn do_reload(mut file: &std::fs::File, wg: &std::sync::Arc<WgState>) -> Result<(), Error> {
    use std::io::{Seek, SeekFrom};

    file.seek(SeekFrom::Start(0))?;
    let new_config = super::load_config_from_file(file)?;
    crate::cli::reload(wg, new_config).await
}

#[cfg(unix)]
async fn reload_on_sighup(
    file: Option<std::fs::File>,
    weak: std::sync::Weak<WgState>,
) -> Result<(), Error> {
    use tokio_net::signal::unix::{signal, SignalKind};
    while let Some(_) = signal(SignalKind::hangup())?.next().await {
        if let Some(ref file) = file {
            if let Some(wg) = weak.upgrade() {
                info!("reloading");
                do_reload(file, &wg)
                    .await
                    .unwrap_or_else(|e| warn!("error in reloading: {}", e));
            }
        }
    }
    Ok(())
}

pub async fn run(c: Config, notify: Option<NotifyHandle>) -> Result<(), Error> {
    #[cfg(unix)]
    let mut c = c;
    let scope0 = AsyncScope::new();

    scope0.clone().spawn_canceller(async move {
        let mut ctrl_c = tokio_net::signal::ctrl_c().unwrap();
        ctrl_c.next().await;
        info!("Received SIGINT or Ctrl-C, shutting down.");
    });

    if c.general.exit_stdin_eof {
        let scope = scope0.clone();
        std::thread::spawn(move || {
            use std::io::Read;

            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let mut buf = vec![0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Err(e) => {
                        warn!("Error read from stdin: {}", e);
                        break;
                    }
                    _ => (),
                }
            }
            info!("Stdin EOF, shutting down.");
            scope.cancel();
        });
    }
    #[cfg(unix)]
    scope0.clone().spawn_canceller(async move {
        use tokio_net::signal::unix::{signal, SignalKind};

        let mut term = signal(SignalKind::terminate()).unwrap();
        term.next().await;
        info!("Received SIGTERM, shutting down.");
    });

    let dev_name = c.interface.name.unwrap();

    #[cfg(windows)]
    let tun = AsyncTun::open(
        &dev_name,
        c.network.map(|n| (n.address, n.prefix_len)).unwrap(),
    )
    .context("failed to open tun device")?;
    #[cfg(unix)]
    let tun = AsyncTun::open(&dev_name).context("failed to open tun device")?;

    info!("setting port, fwmark and private key");
    let info = WgInfo {
        port: c.interface.listen_port.unwrap_or(0),
        fwmark: c.interface.fwmark.unwrap_or(0),
        key: c.interface.private_key,
    };
    let wg = WgState::new(info, tun)?;

    for p in c.peers {
        info!("adding peer {}", base64::encode(&p.public_key));
        wg.clone().add_peer(&p.public_key)?;
        wg.set_peer(SetPeerCommand {
            public_key: p.public_key,
            preshared_key: p.preshared_key,
            endpoint: p.endpoint,
            keepalive: p.keepalive.map(|x| x.get()),
            replace_allowed_ips: true,
            allowed_ips: p.allowed_ips,
        })?;
    }

    let weak = std::sync::Arc::downgrade(&wg);

    scope0.clone().spawn_canceller(WgState::run(wg));

    #[cfg(unix)]
    {
        let weak1 = weak.clone();
        let file = c.general.config_file.take();
        scope0.clone().spawn_canceller(async move {
            reload_on_sighup(file, weak1)
                .await
                .unwrap_or_else(|e| warn!("error in reload_on_sighup: {}", e))
        });
    }

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    scope0.clone().spawn_canceller(async move {
        ipc_server(weak, &dev_name, ready_tx)
            .await
            .unwrap_or_else(|e| error!("IPC server error: {}", e))
    });

    if ready_rx.await.is_ok() {
        #[cfg(unix)]
        {
            if c.general.group.is_some() || c.general.user.is_some() {
                let p = privdrop::PrivDrop::default();
                let p = if let Some(ref user) = c.general.user {
                    p.user(user)
                } else {
                    p
                };
                let p = if let Some(ref group) = c.general.group {
                    p.group(group)
                } else {
                    p
                };
                p.apply().context("failed to change user and group")?;
            }

            if c.general.foreground {
                crate::systemd::notify_ready()
                    .unwrap_or_else(|e| warn!("failed to notify systemd: {}", e));
            } else {
                notify
                    .unwrap()
                    .notify(0)
                    .context("failed to notify grand parent")?;
            }
        }
        // So rustc does not warn about unused.
        #[cfg(not(unix))]
        drop(notify);
    }

    scope0.cancelled().await;
    schedule_force_shutdown();
    Ok(())
}
