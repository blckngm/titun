// Copyright 2017, 2018, 2019 Guanhao Yin <sopium@mysterious.site>

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

use anyhow::{bail, Context, Error};
use log::info;
use rand::{rngs::OsRng, RngCore};
use std::ffi::OsString;
use std::io::{stdin, Read};
#[cfg(windows)]
use std::net::Ipv4Addr;
use std::path::PathBuf;
use structopt::{clap::crate_version, clap::AppSettings, StructOpt};
use titun::cli;
use titun::wireguard::re_exports::{U8Array, DH, X25519};

fn main() {
    real_main().unwrap_or_else(|e| {
        eprint!("Error: {:?}", e);
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

    #[structopt(short, long, help = "Load initial configuration from TOML file")]
    config_file: Option<PathBuf>,

    #[structopt(long, hidden = true, help = "Exit if stdin is closed")]
    exit_stdin_eof: bool,

    #[cfg(windows)]
    #[structopt(
        long,
        value_name = "IP/PREFIX_LEN",
        parse(try_from_str = parse_network),
        help = "Network configuration for the device",
    )]
    network: Option<(Ipv4Addr, u32)>,

    #[structopt(long, help = "Set logging (env_logger)", env = "RUST_LOG")]
    log: Option<String>,

    #[structopt(long, help = "Number of worker threads", env = "TITUN_THREADS")]
    threads: Option<usize>,

    #[cfg(unix)]
    #[structopt(long, help = "Change to user (drop privilege)")]
    user: Option<String>,

    #[cfg(unix)]
    #[structopt(long, help = "Change to group")]
    group: Option<String>,

    #[structopt(value_name = "DEVICE_NAME", help = "Device name", parse(from_os_str))]
    dev: Option<OsString>,

    // This field is never accessed.
    #[allow(unused)]
    #[structopt(subcommand)]
    cmd: Option<Cmd>,
}

impl Options {
    fn run(self, version: &str) -> Result<(), Error> {
        let options = self;

        let mut config = if let Some(ref p) = options.config_file {
            cli::load_config_from_path(&p)?
        } else {
            cli::Config {
                #[cfg(windows)]
                network: None,
                general: Default::default(),
                interface: cli::InterfaceConfig {
                    name: None,
                    private_key: X25519::genkey(),
                    fwmark: None,
                    listen_port: None,
                },
                peers: Vec::new(),
            }
        };

        if options.foreground {
            config.general.foreground = true;
        }

        #[cfg(unix)]
        {
            if options.user.is_some() {
                config.general.user = options.user;
            }

            if options.group.is_some() {
                config.general.group = options.group;
            }
        }

        let log = options
            .log
            .as_ref()
            .map(|x| x.as_str())
            .or(config.general.log.as_ref().map(|x| x.as_str()))
            .unwrap_or("warn");
        std::env::set_var("RUST_LOG", log);
        env_logger::init();

        if options.exit_stdin_eof {
            config.general.exit_stdin_eof = options.exit_stdin_eof;
        }

        if options.dev.is_some() {
            config.interface.name = options.dev;
        }
        if config.interface.name.is_none() {
            bail!("device name is never specified\nSpecify a device name via command line arg or in config file in `Interface.Name`.");
        }

        #[cfg(windows)]
        {
            if let Some((address, prefix_len)) = options.network {
                config.network = Some(cli::NetworkConfig {
                    address,
                    prefix_len,
                });
            }
            if config.network.is_none() {
                bail!("network is never specified\nSpecify a network via command line options --network or in configuration file in `Netowrk`.");
            }
        }

        let threads = options
            .threads
            .or(config.general.threads)
            .unwrap_or_else(|| std::cmp::min(2, num_cpus::get()));

        info!("titun {}", version);
        info!("Will spawn {} worker threads", threads);
        #[cfg(unix)]
        let notify = if config.general.foreground {
            None
        } else {
            Some(cli::daemonize::daemonize().context("failed to daemonize")?)
        };
        #[cfg(not(unix))]
        let notify = None;
        let rt = tokio::runtime::Builder::new()
            .core_threads(threads)
            .panic_handler(|e| std::panic::resume_unwind(e))
            .build()?;
        rt.block_on(cli::run(config, notify))
    }
}

#[derive(StructOpt)]
enum Cmd {
    #[structopt(about = "Show device status")]
    Show {
        #[structopt(help = "Devices to show. Omit to show all", parse(from_os_str))]
        devices: Vec<OsString>,
    },
    #[structopt(about = "Check configuration file validity")]
    Check { config_file: PathBuf },
    #[structopt(about = "Generate private key")]
    Genkey,
    #[structopt(about = "Calculate public key from the private key read from stdin")]
    Pubkey,
    #[structopt(about = "Generate preshared key")]
    Genpsk,
    #[structopt(about = "Transform wg config files to TOML")]
    Transform {
        #[structopt(long)]
        overwrite: bool,
        #[structopt(help = "Config file to read. Read from stdin if not present")]
        config_file: Option<PathBuf>,
    },
}

impl Cmd {
    async fn run(self) -> Result<(), Error> {
        match self {
            Cmd::Show { devices } => {
                #[cfg(unix)]
                titun::cli::show(devices).await?;
                #[cfg(not(unix))]
                {
                    drop(devices);
                    anyhow::bail!("the show command is not implemented on this platform");
                }
            }
            Cmd::Check { config_file: p } => {
                cli::load_config_from_path(&p)?;
            }
            Cmd::Genpsk => {
                let mut k = [0u8; 32];
                OsRng.fill_bytes(&mut k);
                println!("{}", base64::encode(&k));
            }
            Cmd::Genkey => {
                let k = X25519::genkey();
                println!("{}", base64::encode(k.as_slice()));
            }
            Cmd::Pubkey => {
                let mut buffer = String::new();
                stdin().read_to_string(&mut buffer)?;
                let k =
                    base64::decode(buffer.trim()).context("failed to base64 decode private key")?;
                if k.len() == 32 {
                    let k = <X25519 as DH>::Key::from_slice(&k);
                    let pk = <X25519 as DH>::pubkey(&k);
                    println!("{}", base64::encode(pk.as_slice()));
                } else {
                    bail!(
                        "Expect base64 encoded X25519 secret key (32-byte long), got {} bytes",
                        k.len()
                    );
                }
            }
            Cmd::Transform {
                overwrite,
                config_file,
            } => {
                use std::io::{Seek, SeekFrom, Write};

                if let Some(config_file) = config_file {
                    let mut o = std::fs::OpenOptions::new();
                    o.read(true);
                    if overwrite {
                        o.write(true);
                    }
                    let mut f = o.open(config_file).context("open")?;
                    let mut content = String::new();
                    f.read_to_string(&mut content).context("read_to_string")?;
                    let transformed = titun::cli::transform::maybe_transform(content);
                    if overwrite {
                        f.seek(SeekFrom::Start(0)).context("seek")?;
                        f.set_len(0).context("set_len")?;
                        f.write_all(transformed.as_bytes()).context("write")?;
                        f.sync_all().context("sync")?;
                    } else {
                        print!("{}", transformed);
                    }
                } else {
                    let mut content = String::new();
                    std::io::stdin()
                        .read_to_string(&mut content)
                        .context("read_to_string")?;
                    let transformed = titun::cli::transform::maybe_transform(content);
                    print!("{}", transformed);
                }
            }
        }
        Ok(())
    }
}

fn real_main() -> Result<(), Error> {
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        std::process::exit(2);
    }));

    let version = if !env!("GIT_HASH").is_empty() {
        concat!(crate_version!(), "-", env!("GIT_HASH"))
    } else {
        crate_version!()
    };

    let matches = Options::clap()
        .about(include_str!("copyright.txt"))
        .version(version)
        .setting(AppSettings::UnifiedHelpMessage)
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::SubcommandsNegateReqs)
        .setting(AppSettings::ArgsNegateSubcommands)
        .get_matches();

    if matches.subcommand_name().is_none() {
        let options = Options::from_clap(&matches);
        options.run(version)?;
    } else {
        let cmd = Cmd::from_clap(&matches);
        let mut rt = tokio::runtime::current_thread::Runtime::new()?;
        rt.block_on(cmd.run())?;
    }

    Ok(())
}
