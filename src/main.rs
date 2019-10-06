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

#[cfg(windows)]
use failure::bail;
use failure::Error;
use log::info;
use std::ffi::OsString;
#[cfg(windows)]
use std::net::Ipv4Addr;
use structopt::{clap::crate_version, StructOpt};
use titun::run::*;

fn main() {
    real_main().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
}

#[cfg(windows)]
fn parse_network(network: &str) -> Result<(Ipv4Addr, u32), Error> {
    let parts: Vec<_> = network.split('/').take(3).collect();
    if parts.len() != 2 {
        bail!("Invalid network: {}", network);
    }
    let addr: ::std::net::Ipv4Addr = parts[0].parse()?;
    let prefix = parts[1].parse()?;
    if prefix > 32 {
        bail!("Invalid network: {}", network);
    }
    Ok((addr, prefix))
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab")]
struct Options {
    #[structopt(short, long, help = "Run in foreground (don't daemonize)")]
    foreground: bool,

    #[structopt(long, help = "Exit if stdin is closed")]
    exit_stdin_eof: bool,

    #[cfg(windows)]
    #[structopt(
        long,
        value_name = "IP/PREFIX_LEN",
        parse(try_from_str = parse_network),
        help = "Network configuration for the device",
    )]
    network: (Ipv4Addr, u32),

    #[structopt(value_name = "DEVICE_NAME", help = "Device name", parse(from_os_str))]
    dev: OsString,
}

fn real_main() -> Result<(), Error> {
    env_logger::init();

    let version = if !env!("GIT_HASH").is_empty() {
        concat!(crate_version!(), "-", env!("GIT_HASH"))
    } else {
        crate_version!()
    };

    let options = Options::from_clap(
        &Options::clap()
            .about(include_str!("copyright.txt"))
            .version(version)
            .get_matches(),
    );

    info!("titun {}", version);
    let config = Config {
        dev_name: options.dev,
        exit_stdin_eof: options.exit_stdin_eof,
        #[cfg(windows)]
        network: options.network,
        daemonize: !options.foreground,
    };
    let threads = if let Ok(Ok(t)) = std::env::var("TITUN_THREADS").map(|t| t.parse()) {
        t
    } else {
        std::cmp::min(2, num_cpus::get())
    };
    info!("Will spawn {} worker threads", threads);
    let rt = tokio::runtime::Builder::new()
        .core_threads(threads)
        .build()?;
    rt.block_on(run(config))?;

    Ok(())
}
