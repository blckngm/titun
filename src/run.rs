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

use crate::cancellation::*;
use crate::ipc::start_ipc_server;
use crate::systemd;
use crate::wireguard::re_exports::{DH, X25519};
use crate::wireguard::*;
use failure::{Error, ResultExt};
use futures::channel::mpsc::*;
use futures::future::FutureObj;
use futures::StreamExt;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::prelude::*;

pub struct Config {
    pub dev_name: String,
    pub exit_stdin_eof: bool,
    #[cfg(windows)]
    pub network: (::std::net::Ipv4Addr, u32),
}

pub async fn run(c: Config) -> Result<(), Error> {
    let source0 = Arc::new(Mutex::new(CancellationTokenSource::new()));

    // XXX: On windows, tokio-signal will spawn a never ended task
    // and prevent the event loop from shuting down on itself.
    #[cfg(windows)]
    let token = source0.lock().get_token();
    #[cfg(windows)]
    spawn_async!(
        async move {
            await!(token.cancelled());
            sleep!(ms 100);
            std::process::exit(0);
        }
    );

    let source = source0.clone();
    source0.lock().spawn_async(
        async move {
            let mut ctrl_c = await!(tokio_signal::ctrl_c()).unwrap();
            await!(ctrl_c.next());
            debug!("Received SIGINT or Ctrl-C, shutting down.");
            source.lock().cancel();
        },
    );
    if c.exit_stdin_eof {
        let source = source0.clone();
        // Cannot use tokio's stdin in single threaded runtime. So use an OS thread.
        std::thread::Builder::new()
            .name("wait-stdin".into())
            .spawn(move || {
                use std::io::{stdin, Read};
                let mut buf = [0u8; 4096];
                loop {
                    match stdin().read(&mut buf) {
                        Ok(0) => break,
                        Err(e) => {
                            warn!("Read from stdin error: {}", e);
                            break;
                        }
                        _ => (),
                    }
                }
                debug!("Stdin EOF, shutting down.");
                source.lock().cancel();
            })
            .unwrap();
    }
    #[cfg(unix)]
    let source = source0.clone();
    #[cfg(unix)]
    source0.lock().spawn_async(
        async move {
            use tokio_signal::unix::{Signal, SIGTERM};

            let mut term = await!(Signal::new(SIGTERM)).unwrap();
            await!(term.next());
            debug!("Received SIGTERM, shutting down.");
            source.lock().cancel();
        },
    );

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
    source0.lock().spawn_async(WgState::run(wg));

    let (tx, mut rx) = channel::<FutureObj<'static, ()>>(0);
    source0.lock().spawn_async(
        async move {
            while let Some(action) = await!(rx.next()) {
                await!(action);
            }
        },
    );

    start_ipc_server(weak, &c.dev_name, tx)?;
    systemd::notify_ready();

    Ok(())
}
