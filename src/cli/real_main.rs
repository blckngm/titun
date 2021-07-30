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

use crate::cli;
use crate::wireguard::re_exports::{U8Array, DH, X25519};
use anyhow::{bail, Context};
use log::info;
use rand::{rngs::OsRng, RngCore};
use std::ffi::OsString;
use std::io::{stdin, Read};
use std::path::PathBuf;
use structopt::{clap::crate_version, clap::AppSettings, StructOpt};
use tokio::sync::oneshot;

#[derive(StructOpt)]
#[structopt(rename_all = "kebab")]
struct Options {
    #[structopt(short, long, help = "Run in foreground (don't daemonize)")]
    foreground: bool,

    #[structopt(
        short,
        long,
        help = "Load initial configuration from TOML file",
        required_unless = "dev"
    )]
    config_file: Option<PathBuf>,

    #[cfg(windows)]
    #[structopt(long, hidden = true, help = "Exit if stdin is closed")]
    exit_stdin_eof: bool,

    // On windows, the program is intended to run as a Windows Service. In that
    // case, any logs will be discarded if they are simply written to stderr. So
    // we provide an option to redirect logging to a named pipe.
    #[cfg(windows)]
    #[structopt(
        long,
        hidden = true,
        help = "Redirect logging to the specified named pipe"
    )]
    log_pipe: Option<PathBuf>,

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

    #[structopt(
        value_name = "INTERFACE_NAME",
        help = "Interface name",
        parse(from_os_str),
        required_unless = "config-file"
    )]
    dev: Option<OsString>,

    // This field is never accessed.
    #[allow(unused)]
    #[structopt(subcommand)]
    cmd: Option<Cmd>,
}

impl Options {
    fn run(self, version: &str, stop_rx: Option<oneshot::Receiver<()>>) -> anyhow::Result<()> {
        let options = self;

        // Too bad env_logger does not support logging to a file.
        //
        // We redirect stderr to the file with SetStdHandle.
        #[cfg(windows)]
        {
            if let Some(ref log_pipe) = options.log_pipe {
                use std::io;
                use std::os::windows::io::IntoRawHandle;
                use winapi::um::processenv::*;
                use winapi::um::winbase::*;

                let pipe = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(log_pipe)
                    .context("connect to log_pipe")?;

                let h = pipe.into_raw_handle();

                if unsafe { SetStdHandle(STD_ERROR_HANDLE, h) } == 0 {
                    return Err(io::Error::last_os_error())
                        .context("SetStdHandle")
                        .context("redirecting logging");
                };
            }
        }

        let mut config = if let Some(ref p) = options.config_file {
            cli::load_config_from_path(p, true)?
        } else {
            cli::Config::default()
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
            .as_deref()
            .or_else(|| config.general.log.as_deref())
            .unwrap_or("warn");
        std::env::set_var("RUST_LOG", log);
        let mut builder = env_logger::Builder::from_default_env();
        if std::env::var_os("NOTIFY_SOCKET").is_some() {
            // Disable log timestamp when running in systemd.
            builder.format_timestamp(None);
        } else {
            builder.format_timestamp_millis();
        }
        builder.init();

        if options.dev.is_some() {
            config.interface.name = options.dev;
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
            Some(unsafe { cli::daemonize::daemonize() }.context("failed to daemonize")?)
        };
        #[cfg(not(unix))]
        let notify = None;
        // On windows we make use `tokio::executor::threadpool::blocking`, so it
        // must use the threadpool runtime.
        if threads > 1 || cfg!(windows) {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(threads)
                .build()?;
            rt.block_on(cli::run(config, notify, stop_rx))
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cli::run(config, notify, stop_rx))
        }
    }
}

#[derive(StructOpt)]
enum Cmd {
    #[structopt(about = "Show interface status")]
    Show {
        #[structopt(help = "Interfaces to show. Omit to show all", parse(from_os_str))]
        interfaces: Vec<OsString>,
    },
    #[structopt(about = "Check configuration file validity")]
    Check {
        config_file: PathBuf,
        #[structopt(long)]
        print: bool,
    },
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
    async fn run(self) -> anyhow::Result<()> {
        match self {
            Cmd::Show { interfaces } => {
                #[cfg(unix)]
                cli::show(interfaces).await?;
                #[cfg(not(unix))]
                {
                    drop(interfaces);
                    anyhow::bail!("the show command is not implemented on this platform");
                }
            }
            Cmd::Check {
                config_file: p,
                print,
            } => {
                let config = cli::load_config_from_path(&p, true)?;
                if print {
                    print!(
                        "{}",
                        toml::to_string_pretty(&config).context("serialize config file")?
                    );
                }
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
                    println!("{}", base64::encode(&pk));
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
                    let transformed = cli::transform::maybe_transform(content);
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
                    let transformed = cli::transform::maybe_transform(content);
                    print!("{}", transformed);
                }
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct WindowsServiceArgs {
    pub interface_name: OsString,
    pub exit_stdin_eof: bool,
    pub args: Vec<OsString>,
}

/// Validate command line arguments and config file, get interface name and args
/// to re-run as windows service. Also initiate logger for this process.
#[cfg(windows)]
pub fn windows_service_args() -> anyhow::Result<Option<WindowsServiceArgs>> {
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

        let config = if let Some(ref p) = options.config_file {
            cli::load_config_from_path(p, true)?
        } else {
            cli::Config::default()
        };

        let interface_name = options
            .dev
            .clone()
            .or(config.interface.name)
            .expect("interface name is None");

        let mut args: Vec<OsString> = Vec::new();
        if let Some(config_file) = options.config_file {
            args.push("-c".into());
            args.push(config_file.into());
        }

        let log = options
            .log
            .clone()
            .or(config.general.log)
            .unwrap_or_else(|| "warn".into());
        std::env::set_var("RUST_LOG", log);
        let mut builder = env_logger::Builder::from_default_env();
        builder.format_timestamp_millis();
        builder.init();

        if let Some(log) = options.log {
            args.push("--log".into());
            args.push(log.into())
        }

        if let Some(threads) = options.threads {
            args.push(format!("--threads={}", threads).into());
        }

        if let Some(dev) = options.dev {
            args.push(dev);
        }

        Ok(Some(WindowsServiceArgs {
            interface_name,
            exit_stdin_eof: options.exit_stdin_eof,
            args,
        }))
    } else {
        Ok(None)
    }
}

pub fn real_main(stop_rx: Option<oneshot::Receiver<()>>) -> anyhow::Result<()> {
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
        options.run(version, stop_rx)?;
    } else {
        let cmd = Cmd::from_clap(&matches);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(cmd.run())?;
    }

    Ok(())
}
