// Copyright 2019 Yin Guanhao <sopium@mysterious.site>

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

use crate::wireguard::re_exports::{DH, X25519};
use ansi_term::{Color, Style};
use anyhow::Context;
use base64;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::timeout;

pub async fn show(interfaces: Vec<OsString>) -> anyhow::Result<()> {
    let mut is_first = true;
    if interfaces.is_empty() {
        let read_dir = match Path::new("/var/run/wireguard").read_dir() {
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            r => r?,
        };
        for sock in read_dir {
            let path = sock?.path();
            if path.extension() != Some(OsStr::new("sock")) {
                continue;
            }
            let dev_name = path.file_stem().unwrap();
            let print_anything = timeout(
                Duration::from_secs(3),
                get_and_print_status(dev_name, is_first),
            )
            .await
            .unwrap_or_else(|e| Err(e.into()))
            .map(|_| true)
            .unwrap_or_else(|e| {
                if let Some(io_error) = e.root_cause().downcast_ref::<std::io::Error>() {
                    if io_error.kind() == std::io::ErrorKind::ConnectionRefused {
                        // Ignore connection refused errors.
                        return false;
                    }
                }

                if !is_first {
                    println!();
                }
                eprintln!(
                    "Failed to get status of {}: {}",
                    dev_name.to_string_lossy(),
                    e
                );
                true
            });
            if print_anything {
                is_first = false;
            }
        }
    } else {
        for d in &interfaces {
            timeout(Duration::from_secs(3), get_and_print_status(d, is_first))
                .await
                .unwrap_or_else(|e| Err(e.into()))
                .unwrap_or_else(|e| {
                    if !is_first {
                        println!();
                    }
                    eprintln!("Failed to get status of {}: {}", d.to_string_lossy(), e);
                });
            is_first = false;
        }
    }
    Ok(())
}

async fn get_and_print_status(dev_name: &OsStr, is_first: bool) -> anyhow::Result<()> {
    let path = Path::new("/var/run/wireguard/")
        .join(dev_name)
        .with_extension("sock");
    let mut stream = UnixStream::connect(&path)
        .await
        .context("failed to connect to socket")?;
    stream.write_all(b"get=1\n\n").await?;

    let state_or_errno = crate::ipc::parse::parse_get_response_io(stream)
        .await
        .context("failed to read or parse response")?;

    match state_or_errno {
        Err(errno) => {
            let io_error = std::io::Error::from_raw_os_error(errno);
            bail!(
                "socket responed with errno={}, which means {}",
                errno,
                io_error
            );
        }
        Ok(state) => {
            let is_tty = atty::is(atty::Stream::Stdout);

            macro_rules! if_tty {
                ($s:expr) => {
                    if is_tty {
                        $s
                    } else {
                        Style::new()
                    }
                };
            }

            let green_bold = if_tty!(Color::Green.bold());
            let green = if_tty!(Color::Green.normal());
            let bold = if_tty!(Style::new().bold());
            let yellow_bold = if_tty!(Color::Yellow.bold());
            let yellow = if_tty!(Color::Yellow.normal());
            let cyan = if_tty!(Color::Cyan.normal());

            if !is_first {
                println!();
            }
            print!("{}", green_bold.paint("interface"));
            println!(": {}", green.paint(dev_name.to_string_lossy()));

            let pk = <X25519 as DH>::pubkey(&state.private_key);
            let pk = base64::encode(&pk);
            println!("  {}: {}", bold.paint("public key"), pk);

            println!("  {}: (hidden)", bold.paint("private key"));

            println!("  {}: {}", bold.paint("listening port"), state.listen_port);

            if state.fwmark != 0 {
                println!("  {}: 0x{:x}", bold.paint("fwmark"), state.fwmark);
            }

            for p in &state.peers {
                println!();
                println!(
                    "{}: {}",
                    yellow_bold.paint("peer"),
                    yellow.paint(base64::encode(&p.public_key))
                );
                if p.preshared_key.is_some() {
                    println!("  {}: (hidden)", bold.paint("preshared key"));
                }
                if let Some(ref e) = p.endpoint {
                    println!("  {}: {}", bold.paint("endpoint"), e);
                }
                if !p.allowed_ips.is_empty() {
                    println!(
                        "  {}: {}",
                        bold.paint("allowed ips"),
                        p.allowed_ips
                            .iter()
                            .map(|(ip, plen)| format!("{}{}{}", ip, cyan.paint("/"), plen))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                if let Some(ref t) = p.last_handshake_time {
                    print!("  {}: ", bold.paint("last handshake"));
                    let duration = t.elapsed().unwrap_or_else(|_| Duration::from_secs(0));
                    let secs = duration.as_secs();
                    if secs < 1 {
                        println!("just now");
                    } else {
                        print_human_time(secs, cyan);
                        println!(" ago");
                    }
                }
                if p.tx_bytes > 0 || p.rx_bytes > 0 {
                    print!("  {}: ", bold.paint("transfer"));

                    print_human_size(p.rx_bytes, cyan);
                    print!(" received, ");
                    print_human_size(p.tx_bytes, cyan);
                    println!(" sent");
                }
                if p.persistent_keepalive_interval > 0 {
                    print!("  {}: every ", bold.paint("persistent keepalive"));
                    print_human_time(p.persistent_keepalive_interval.into(), cyan);
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn print_human_time(secs: u64, unit_style: Style) {
    let hours = secs / (60 * 60);
    let minutes = secs % (60 * 60) / 60;
    let seconds = secs % 60;

    let mut is_first = true;

    if hours > 0 {
        print!(
            "{} {}",
            hours,
            if hours > 1 {
                unit_style.paint("hours")
            } else {
                unit_style.paint("hour")
            }
        );
        is_first = false;
    };
    if minutes > 0 {
        if !is_first {
            print!(", ");
        }
        print!(
            "{} {}",
            minutes,
            if minutes > 1 {
                unit_style.paint("minutes")
            } else {
                unit_style.paint("minute")
            }
        );
        is_first = false;
    }
    if seconds > 0 {
        if !is_first {
            print!(", ");
        }
        print!(
            "{} {}",
            seconds,
            if seconds > 1 {
                unit_style.paint("seconds")
            } else {
                unit_style.paint("second")
            }
        )
    }
}

fn print_human_size(bytes: u64, unit_style: Style) {
    if bytes < 1024 {
        print!("{} {}", bytes, unit_style.paint("B"));
    } else if bytes < 1024 * 1024 {
        let kib = bytes as f64 / 1024.;
        print!("{:.2} {}", kib, unit_style.paint("KiB"));
    } else if bytes < 1024 * 1024 * 1024 {
        let mib = bytes as f64 / (1024. * 1024.);
        print!("{:.2} {}", mib, unit_style.paint("MiB"));
    } else {
        let gib = bytes as f64 / (1024. * 1024. * 1024.);
        print!("{:.2} {}", gib, unit_style.paint("GiB"));
    }
}
