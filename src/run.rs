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
use crate::ipc::ipc_server;
use crate::wireguard::re_exports::{DH, X25519};
use crate::wireguard::*;
use failure::{Error, ResultExt};
use futures::prelude::*;

pub struct Config {
    pub dev_name: String,
    pub exit_stdin_eof: bool,
    #[cfg(windows)]
    pub network: (::std::net::Ipv4Addr, u32),
}

fn schedule_force_shutdown() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        warn!("Clean shutdown seem to have failed. Force shutting down.");
        std::process::exit(0);
    });
}

pub async fn run(c: Config) -> Result<(), Error> {
    let scope0 = AsyncScope::new();

    scope0.clone().spawn_canceller(async move {
        let mut ctrl_c = tokio_signal::CtrlC::new().unwrap();
        ctrl_c.next().await;
        info!("Received SIGINT or Ctrl-C, shutting down.");
    });

    if c.exit_stdin_eof {
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
        use tokio_signal::unix::{Signal, SIGTERM};

        let mut term = Signal::new(SIGTERM).unwrap();
        term.next().await;
        info!("Received SIGTERM, shutting down.");
    });

    #[cfg(windows)]
    let tun = AsyncTun::open(&c.dev_name, c.network).context("Open tun device")?;
    #[cfg(unix)]
    let tun = AsyncTun::open(&c.dev_name).context("Open tun device")?;
    let wg = WgState::new(
        WgInfo {
            port: 0,
            fwmark: 0,
            key: X25519::genkey(),
        },
        tun,
    )?;

    let weak = ::std::sync::Arc::downgrade(&wg);

    scope0.clone().spawn_canceller(WgState::run(wg));

    scope0.clone().spawn_canceller(async move {
        ipc_server(weak, &c.dev_name)
            .await
            .unwrap_or_else(|e| error!("IPC server error: {}", e))
    });

    scope0.cancelled().await;
    schedule_force_shutdown();
    Ok(())
}
