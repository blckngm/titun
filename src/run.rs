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

use ctrlc;
use failure::{Error, ResultExt};
use ipc::start_ipc_server;
use std::io::{stdin, Read};
use std::sync::mpsc::channel;
use std::thread::Builder;
use systemd;
use wireguard::re_exports::{X25519, DH};
use wireguard::*;

pub struct Config {
    pub dev_name: String,
    pub exit_stdin_eof: bool,
    #[cfg(windows)]
    pub network: (::std::net::Ipv4Addr, u32),
}

pub fn run(c: Config) -> Result<(), Error> {
    #[cfg(windows)]
    let tun = Tun::open(&c.dev_name, c.network).context("Open tun device")?;
    #[cfg(not(windows))]
    let tun = Tun::create(Some(&c.dev_name)).context("Open tun device")?;
    let wg = WgState::new(
        WgInfo {
            port: 0,
            fwmark: 0,
            key: X25519::genkey(),
        },
        tun,
    )?;

    let weak = ::std::sync::Arc::downgrade(&wg);
    start_ipc_server(weak, &c.dev_name)?;

    systemd::notify_ready();

    let (exit_tx, exit_rx) = channel();
    {
        let exit_tx = exit_tx.clone();
        ctrlc::set_handler(move || {
            exit_tx.send(()).unwrap();
        }).expect("Error setting Ctrl-C handler");
    }

    if c.exit_stdin_eof {
        let exit_tx = exit_tx.clone();
        Builder::new()
            .name("wait-stdin".to_string())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stdin().read(&mut buf) {
                        Err(_) => break,
                        Ok(0) => break,
                        _ => (),
                    }
                }
                exit_tx.send(()).unwrap();
            })
            .unwrap();
    }

    exit_rx.recv().unwrap();

    debug!("Received signal, shuting down.");
    wg.exit();
    drop(wg);

    Ok(())
}
