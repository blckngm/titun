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

#![feature(async_await, await_macro, futures_api)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

use base64::{decode, encode};
use clap::{App, AppSettings, Arg, SubCommand};
use failure::{Error, ResultExt};
use futures::{FutureExt, TryFutureExt};
use std::io::{stdin, Read};
use titun::run::*;
use titun::wireguard::re_exports::{U8Array, DH, X25519};

fn main() -> Result<(), Error> {
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        std::process::exit(2);
    }));

    env_logger::init();

    let sub_tun = SubCommand::with_name("tun")
        .display_order(1)
        .arg(
            Arg::with_name("dev")
                .long("dev")
                .value_name("DEVICE_NAME")
                .required(true)
                .help("Device name"),
        )
        .arg(
            Arg::with_name("exit-stdin-eof")
                .long("exit-stdin-eof")
                .help("Exit if stdin is closed"),
        );
    #[cfg(windows)]
    let sub_tun = sub_tun.arg(
        Arg::with_name("network")
            .long("network")
            .value_name("IP/PREFIX_LEN")
            .required(true)
            .help("Network configuration for the device"),
    );
    let sub_genkey = SubCommand::with_name("genkey").display_order(2);
    let sub_pubkey = SubCommand::with_name("pubkey").display_order(3);

    let version = if !env!("GIT_HASH").is_empty() {
        concat!(clap::crate_version!(), "-", env!("GIT_HASH"))
    } else {
        clap::crate_version!()
    };

    let app = App::new("titun")
        .version(version)
        .about(include_str!("copyright.txt"))
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(sub_tun)
        .subcommand(sub_genkey)
        .subcommand(sub_pubkey);

    let matches = app.get_matches();

    match matches.subcommand() {
        ("genkey", _) => {
            println!("{}", encode(<X25519 as DH>::genkey().as_slice()));
        }
        ("pubkey", _) => {
            let mut buffer = String::new();
            stdin().read_to_string(&mut buffer)?;
            let k = decode(buffer.trim()).context("Base64 decode key")?;
            if k.len() == 32 {
                let k = <X25519 as DH>::Key::from_slice(&k);
                let pk = <X25519 as DH>::pubkey(&k);
                println!("{}", encode(pk.as_slice()));
            } else {
                bail!(
                    "Expect base64 encoded X25519 secret key (32-byte long), got {} bytes",
                    k.len()
                );
            }
        }
        ("tun", Some(m)) => {
            info!("titun {}", version);
            #[cfg(windows)]
            let network = {
                let network = m.value_of("network").unwrap();
                let parts: Vec<_> = network.split('/').take(3).collect();
                if parts.len() != 2 {
                    bail!("Invalid network: {}", network);
                }
                let addr: ::std::net::Ipv4Addr = parts[0].parse()?;
                let prefix = parts[1].parse()?;
                if prefix > 32 {
                    bail!("Invalid network: {}", network);
                }
                (addr, prefix)
            };
            let config = Config {
                dev_name: m.value_of("dev").unwrap().to_string(),
                exit_stdin_eof: m.is_present("exit-stdin-eof"),
                #[cfg(windows)]
                network,
            };
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on_all(
                async move {
                    if let Err(err) = await!(run(config)) {
                        error!("Error: {}", err);
                        std::process::exit(1);
                    }
                }
                    .unit_error()
                    .boxed()
                    .compat(),
            )
            .unwrap();
        }
        _ => {
            unreachable!();
        }
    }

    Ok(())
}
