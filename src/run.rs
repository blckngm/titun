// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

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
use futures::compat::Future01CompatExt;
use tokio::prelude::*;

pub struct Config {
    pub dev_name: String,
    pub exit_stdin_eof: bool,
    #[cfg(windows)]
    pub network: (::std::net::Ipv4Addr, u32),
}

pub async fn run(c: Config) -> Result<(), Error> {
    let scope0 = AsyncScope::new();

    // XXX: On windows, tokio-signal will spawn a never ended task
    // and prevent the event loop from shuting down on itself.
    #[cfg(windows)]
    let scope = scope0.clone();
    #[cfg(windows)]
    crate::async_utils::tokio_spawn(async move {
        use crate::async_utils::delay;
        use std::time::Duration;

        await!(scope.cancelled());
        await!(delay(Duration::from_millis(100)));
        std::process::exit(0);
    });

    scope0.spawn_canceller(async move {
        let mut ctrl_c = await!(tokio_signal::ctrl_c().compat()).unwrap();
        await!(ctrl_c.next());
        info!("Received SIGINT or Ctrl-C, shutting down.");
    });

    if c.exit_stdin_eof {
        scope0.spawn_canceller(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 4096];
            loop {
                match await!(stdin.read_async(&mut buf)) {
                    Ok(0) => break,
                    Err(e) => {
                        warn!("Read from stdin error: {}", e);
                        break;
                    }
                    _ => (),
                }
            }
            info!("Stdin EOF, shutting down.");
        });
    }
    #[cfg(unix)]
    scope0.spawn_canceller(async move {
        use tokio_signal::unix::{Signal, SIGTERM};

        let mut term = await!(Signal::new(SIGTERM).compat()).unwrap();
        await!(term.next());
        info!("Received SIGTERM, shutting down.");
    });

    #[cfg(windows)]
    let tun = Tun::open_async(&c.dev_name, c.network).context("Open tun device")?;
    #[cfg(target_os = "linux")]
    let tun = Tun::create_async(Some(&c.dev_name)).context("Open tun device")?;
    let wg = WgState::new(
        WgInfo {
            port: 0,
            fwmark: 0,
            key: X25519::genkey(),
        },
        tun,
    )?;

    let weak = ::std::sync::Arc::downgrade(&wg);

    scope0.spawn_canceller(WgState::run(wg));

    scope0.spawn_canceller(async move {
        await!(ipc_server(weak, &c.dev_name))
            .unwrap_or_else(|e| error!("Failed to start IPC server: {}", e))
    });

    await!(scope0.cancelled());
    Ok(())
}
