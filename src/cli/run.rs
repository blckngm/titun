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
use anyhow::Context;
use std::net::SocketAddr;

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
async fn do_reload(
    config_file_path: std::path::PathBuf,
    wg: &std::sync::Arc<WgState>,
) -> anyhow::Result<()> {
    let new_config =
        tokio::task::spawn_blocking(move || super::load_config_from_path(&config_file_path, false))
            .await
            .expect("join load_config_from_path")?;
    crate::cli::reload(wg, new_config).await
}

#[cfg(unix)]
async fn reload_on_sighup(
    config_file_path: Option<std::path::PathBuf>,
    weak: std::sync::Weak<WgState>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    while let Some(_) = signal(SignalKind::hangup())?.recv().await {
        if let Some(ref config_file_path) = config_file_path {
            if let Some(wg) = weak.upgrade() {
                info!("reloading");
                do_reload(config_file_path.clone(), &wg)
                    .await
                    .unwrap_or_else(|e| warn!("error in reloading: {}", e));
            }
        }
    }
    Ok(())
}

pub async fn run(c: Config<SocketAddr>, notify: Option<NotifyHandle>) -> anyhow::Result<()> {
    #[cfg(unix)]
    let mut c = c;
    let scope0 = AsyncScope::new();

    scope0.clone().spawn_canceller(async move {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|e| warn!("ctrl_c failed: {}", e));
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
        use tokio::signal::unix::{signal, SignalKind};

        let mut term = signal(SignalKind::terminate()).unwrap();
        term.recv().await;
        info!("Received SIGTERM, shutting down.");
    });

    let dev_name = c.interface.name.unwrap();

    #[cfg(windows)]
    let tun = AsyncTun::open(
        &dev_name,
        c.network.map(|n| (n.address, n.prefix_len)).unwrap(),
    )
    .context("failed to open tun interface")?;
    #[cfg(unix)]
    let tun = AsyncTun::open(&dev_name).context("failed to open tun interface")?;

    let wg = WgState::new(tun)?;
    info!("setting privatge key");
    wg.set_key(c.interface.private_key);
    if let Some(port) = c.interface.listen_port {
        info!("setting port");
        wg.set_port(port).await.context("failed to set port")?;
    }
    if let Some(fwmark) = c.interface.fwmark {
        info!("setting fwmark");
        wg.set_fwmark(fwmark).context("failed to set fwmark")?;
    }

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

    scope0
        .clone()
        .spawn_canceller(wg.clone().task_update_cookie_secret());
    #[cfg(not(windows))]
    scope0.clone().spawn_canceller(wg.clone().task_update_mtu());
    scope0.clone().spawn_canceller(wg.clone().task_rx());
    scope0.clone().spawn_canceller(wg.clone().task_tx());

    #[cfg(unix)]
    {
        let weak1 = weak.clone();
        let config_file_path = c.general.config_file_path.take();
        scope0.clone().spawn_canceller(async move {
            reload_on_sighup(config_file_path, weak1)
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
                super::systemd::notify_ready()
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
        let _notify = notify;
    }

    scope0.cancelled().await;
    schedule_force_shutdown();
    Ok(())
}
