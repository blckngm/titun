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

use clap::{App, Arg};
#[cfg(windows)]
use failure::bail;
use failure::Error;
use log::info;
use titun::run::*;

fn main() {
    real_main().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
}

fn real_main() -> Result<(), Error> {
    env_logger::init();

    let version = if !env!("GIT_HASH").is_empty() {
        concat!(clap::crate_version!(), "-", env!("GIT_HASH"))
    } else {
        clap::crate_version!()
    };

    let app = App::new("titun")
        .version(version)
        .about(include_str!("copyright.txt"))
        .arg(
            Arg::with_name("dev")
                .value_name("DEVICE_NAME")
                .required(true)
                .help("Device name"),
        )
        .arg(
            Arg::with_name("foreground")
                .short("f")
                .long("foreground")
                .help("Run in foreground (don't daemonize)"),
        )
        .arg(
            Arg::with_name("exit-stdin-eof")
                .long("exit-stdin-eof")
                .help("Exit if stdin is closed"),
        );
    #[cfg(windows)]
    let app = app.arg(
        Arg::with_name("network")
            .long("network")
            .value_name("IP/PREFIX_LEN")
            .required(true)
            .help("Network configuration for the device"),
    );

    let m = app.get_matches();

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
        daemonize: !m.is_present("foreground"),
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
