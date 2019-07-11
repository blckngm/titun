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

pub async fn run(c: Config) -> Result<(), Error> {
    let scope0 = AsyncScope::new();

    scope0.clone().spawn_canceller(async move {
        let mut ctrl_c = tokio_signal::CtrlC::new().await.unwrap();
        ctrl_c.next().await;
        info!("Received SIGINT or Ctrl-C, shutting down.");

        // XXX: shutdown not working properly on windows.
        #[cfg(windows)]
        std::process::exit(0);
    });

    // TODO: restore this functionality.
    // if c.exit_stdin_eof {
    //     scope0.clone().spawn_canceller(async move {
    //         let mut stdin = tokio::io::stdin();
    //         let mut buf = [0u8; 4096];
    //         loop {
    //             match stdin.read_async(&mut buf).await {
    //                 Ok(0) => break,
    //                 Err(e) => {
    //                     warn!("Read from stdin error: {}", e);
    //                     break;
    //                 }
    //                 _ => (),
    //             }
    //         }
    //         info!("Stdin EOF, shutting down.");
    //     });
    // }
    #[cfg(unix)]
    scope0.clone().spawn_canceller(async move {
        use tokio_signal::unix::{Signal, SIGTERM};

        let mut term = Signal::new(SIGTERM).await.unwrap();
        term.next().await;
        info!("Received SIGTERM, shutting down.");
    });

    #[cfg(windows)]
    let tun = Tun::open_async(&c.dev_name, c.network).context("Open tun device")?;
    #[cfg(unix)]
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

    scope0.clone().spawn_canceller(WgState::run(wg));

    scope0.clone().spawn_canceller(async move {
        ipc_server(weak, &c.dev_name)
            .await
            .unwrap_or_else(|e| error!("IPC server error: {}", e))
    });

    scope0.cancelled().await;
    Ok(())
}
