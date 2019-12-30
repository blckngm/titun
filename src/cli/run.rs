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
#[cfg(unix)]
use crate::cli::daemonize::NotifyHandle;
use crate::cli::Config;
use crate::ipc::ipc_server;
use crate::wireguard::*;
use anyhow::Context;
use std::net::*;
use tokio::sync::oneshot;

#[cfg(not(unix))]
type NotifyHandle = ();

#[cfg(unix)]
async fn do_reload(
    config_file_path: std::path::PathBuf,
    wg: &std::sync::Arc<WgState>,
) -> anyhow::Result<()> {
    let new_config =
        tokio::task::spawn_blocking(move || super::load_config_from_path(&config_file_path, false))
            .await
            .expect("join load_config_from_path")?;
    crate::cli::reload(wg, new_config).await
}

#[cfg(unix)]
async fn reload_on_sighup(
    config_file_path: Option<std::path::PathBuf>,
    weak: std::sync::Weak<WgState>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    while let Some(_) = signal(SignalKind::hangup())?.recv().await {
        if let Some(ref config_file_path) = config_file_path {
            if let Some(wg) = weak.upgrade() {
                info!("reloading");
                do_reload(config_file_path.clone(), &wg)
                    .await
                    .unwrap_or_else(|e| warn!("error in reloading: {:#}", e));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn get_block_ranges_v4(dns_servers: &[Ipv4Addr]) -> Vec<(IpAddr, IpAddr)> {
    let mut result = Vec::with_capacity(dns_servers.len() + 1);
    let mut previous: u32 = 0;
    for &server in dns_servers {
        let server: u32 = server.into();
        if previous < server {
            result.push((IpAddr::V4(previous.into()), IpAddr::V4((server - 1).into())));
        }
        if server == u32::max_value() {
            return result;
        }

        previous = server + 1;
    }
    result.push((
        IpAddr::V4(previous.into()),
        IpAddr::V4(u32::max_value().into()),
    ));
    result
}

#[cfg(windows)]
fn get_block_ranges_v6(dns_servers: &[Ipv6Addr]) -> Vec<(IpAddr, IpAddr)> {
    let mut result = Vec::with_capacity(dns_servers.len() + 1);
    let mut previous: u128 = 0;
    for &server in dns_servers {
        let server: u128 = server.into();
        if previous < server {
            result.push((IpAddr::V6(previous.into()), IpAddr::V6((server - 1).into())));
        }
        if server == u128::max_value() {
            return result;
        }

        previous = server + 1;
    }
    result.push((
        IpAddr::V6(previous.into()),
        IpAddr::V6(u128::max_value().into()),
    ));
    result
}

#[cfg(windows)]
#[allow(clippy::cognitive_complexity)]
async fn network_config(c: &Config<SocketAddr>) -> anyhow::Result<()> {
    use tokio::process::Command;

    let name = c.interface.name.as_ref().unwrap();

    let address = if let Some(ref a) = c.interface.address {
        a
    } else {
        return Ok(());
    };
    let mask = if address.is_ipv4() {
        IpAddr::V4(u32::max_value().into())
    } else {
        IpAddr::V6(u128::max_value().into())
    };

    info!("set interface ip address to {}", address);
    let output = Command::new("netsh")
        .args(&["interface", "ip", "set", "address"])
        .arg(name)
        .arg("static")
        .arg(format!("{}", address))
        .arg(format!("{}", mask))
        .output()
        .await
        .context("run netsh")?;
    if !output.status.success() {
        bail!(
            "failed to set address, command output: {}",
            String::from_utf8_lossy(&output.stdout),
        );
    }

    if !c.interface.dns.is_empty() {
        for dns in &c.interface.dns {
            info!("add DNS server {}", dns);
            let output = Command::new("netsh")
                .args(&["interface", "ip", "set", "dns"])
                .arg(name)
                .arg("static")
                .arg(format!("{}", dns))
                .output()
                .await
                .context("run netsh")?;
            if !output.status.success() {
                warn!(
                    "failed to set dns server, command output: {}",
                    String::from_utf8_lossy(&output.stdout),
                );
            }
        }

        // Block DNS servers on every other addresses.
        //
        // We add windows firewall rules to block DNS traffic to the full IPv4
        // and IPv6 ranges except our servers.
        //
        // XXX: What if the user is not using windows firewall.

        let mut dns_servers_v4: Vec<Ipv4Addr> = c
            .interface
            .dns
            .iter()
            .filter_map(|a| match a {
                IpAddr::V4(a) => Some(*a),
                _ => None,
            })
            .collect();
        dns_servers_v4.sort();
        dns_servers_v4.dedup();

        let mut dns_servers_v6: Vec<Ipv6Addr> = c
            .interface
            .dns
            .iter()
            .filter_map(|a| match a {
                IpAddr::V6(a) => Some(*a),
                _ => None,
            })
            .collect();
        dns_servers_v6.sort();
        dns_servers_v6.dedup();

        let ranges_v4 = get_block_ranges_v4(&dns_servers_v4);
        let ranges_v6 = get_block_ranges_v6(&dns_servers_v6);

        let ranges = ranges_v4.into_iter().chain(ranges_v6.into_iter());
        let ranges = ranges
            .map(|(start, end)| format!("{}-{}", start, end))
            .collect::<Vec<_>>()
            .join(",");

        async fn block(ranges: &str) -> anyhow::Result<()> {
            let script = format!(
                r#"New-NetFirewallRule -PolicyStore ActiveStore -DisplayName TiTunDNSBlock -Group TiTunDNSBlock -Direction Outbound -Action Block -RemoteAddress {} -RemotePort 53 -Protocol UDP
New-NetFirewallRule -PolicyStore ActiveStore -DisplayName TiTunDNSBlock -Group TiTunDNSBlock -Direction Outbound -Action Block -RemoteAddress {} -RemotePort 53 -Protocol TCP
"#,
                ranges, ranges,
            );
            let output = Command::new("powershell")
                .arg("-command")
                .arg(script)
                .output()
                .await
                .context("run powershell")?;
            if !output.status.success() {
                bail!("{}", String::from_utf8_lossy(&output.stderr));
            }
            Ok(())
        }

        // It's a bit slow, so do it in the background.
        tokio::spawn(async move {
            scopeguard::defer! {{
                info!("unblock other DNS servers");
                std::process::Command::new("powershell")
                    .arg("-command")
                    .arg("Get-NetFirewallRule -PolicyStore ActiveStore -Group TiTunDNSBlock | Remove-NetFirewallRule")
                    .output()
                    .and_then(|o| {
                        if !o.status.success() {
                            warn!(
                                "failed to unblock dns servers: {}",
                                String::from_utf8_lossy(&o.stderr),
                            );
                        }
                        Ok(())
                    }).unwrap_or_else(|e| {
                        warn!("failed to unblock dns servers: failed to run powershell: {}", e);
                    });
            }};

            info!("block DNS servers in ranges {}", ranges);
            if let Err(e) = block(&ranges).await {
                warn!("failed to block DNS servers in ranges {}: {:#}", ranges, e);
            }

            futures::future::pending::<()>().await
        });
    }

    if let Some(mtu) = c.interface.mtu {
        info!("set MTU to {}", mtu);

        let output = Command::new("netsh")
            .args(&["interface", "ipv4", "set", "subinterface"])
            .arg(name)
            .arg(format!("mtu={}", mtu))
            .output()
            .await
            .context("run netsh")?;
        if !output.status.success() {
            warn!(
                "failed to set mtu, command output: {}",
                String::from_utf8_lossy(&output.stdout),
            );
        }
    }

    let mut if_index: Option<u32> = None;
    let output = Command::new("netsh")
        .args(&["interface", "ip", "show", "interfaces"])
        .arg(name)
        .output()
        .await
        .context("run netsh")?;
    for l in String::from_utf8_lossy(&output.stdout).lines() {
        if l.starts_with("IfIndex") {
            if_index = Some(
                l["IfIndex".len()..]
                    .trim_matches(|c| c == ' ' || c == ':')
                    .parse()
                    .context("parse ifIndex")?,
            );
            break;
        }
    }
    let if_index = if_index.context("did not find ifIndex")?;

    for p in &c.peers {
        let mut routes: Vec<(IpAddr, u32)> = Vec::new();
        if let Some(ref e) = p.endpoint {
            // If this peer has an endpoint specified, make sure it's excluded
            // from the added routes.
            for &(a, p) in &p.allowed_ips {
                match (a, e.ip()) {
                    (IpAddr::V4(a), IpAddr::V4(e)) => {
                        crate::wireguard::ip_lookup_trie::cidr_minus(a, p, e, &mut routes)
                    }
                    (IpAddr::V6(a), IpAddr::V6(e)) => {
                        crate::wireguard::ip_lookup_trie::cidr_minus(a, p, e, &mut routes)
                    }
                    _ => routes.push((a, p)),
                }
            }
        } else {
            routes.extend(&p.allowed_ips);
        }

        for (a, p) in routes {
            info!("add route {}/{}", a, p);

            use num_traits::{PrimInt, Unsigned};

            fn bit_len<K>() -> u32 {
                (std::mem::size_of::<K>() * 8) as u32
            }

            fn to_mask<K>(prefix_len: u32) -> K
            where
                K: Unsigned + PrimInt,
            {
                match prefix_len {
                    0 => K::zero(),
                    _ => K::max_value().unsigned_shl(bit_len::<K>() - prefix_len),
                }
            }

            let mask = if a.is_ipv4() {
                IpAddr::V4(to_mask::<u32>(p).into())
            } else {
                IpAddr::V6(to_mask::<u128>(p).into())
            };

            let output = Command::new("route")
                .arg("add")
                .arg(format!("{}", a))
                .arg("mask")
                .arg(format!("{}", mask))
                // Gateway is our local address.
                .arg(format!("{}", address))
                .arg("if")
                .arg(format!("{}", if_index))
                .output()
                .await
                .context("run netsh")?;
            if !output.status.success() {
                warn!(
                    "failed to add route, command output: {}",
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        }
    }

    Ok(())
}

pub async fn run(
    c: Config<SocketAddr>,
    notify: Option<NotifyHandle>,
    stop_rx: Option<oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    let mut c = c;
    let scope0 = AsyncScope::new();

    scope0.clone().spawn_canceller(async move {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|e| warn!("ctrl_c failed: {:#}", e));
        info!("Received SIGINT or Ctrl-C, shutting down.");
    });

    if let Some(stop_rx) = stop_rx {
        scope0.clone().spawn_canceller(async move {
            stop_rx.await.unwrap();
        });
    }

    #[cfg(unix)]
    scope0.clone().spawn_canceller(async move {
        use tokio::signal::unix::{signal, SignalKind};

        let mut term = signal(SignalKind::terminate()).unwrap();
        term.recv().await;
        info!("Received SIGTERM, shutting down.");
    });

    let dev_name = c.interface.name.clone().unwrap();

    let tun = AsyncTun::open(&dev_name).context("failed to open tun interface")?;
    #[cfg(windows)]
    {
        if let Err(e) = network_config(&c).await {
            warn!("failed to configure network: {:#}", e);
        }
    }

    let wg = WgState::new(tun)?;
    info!("setting privatge key");
    wg.set_key(c.interface.private_key);
    if let Some(port) = c.interface.listen_port {
        info!("setting port");
        wg.set_port(port).await.context("failed to set port")?;
    }
    if let Some(fwmark) = c.interface.fwmark {
        info!("setting fwmark");
        wg.set_fwmark(fwmark).context("failed to set fwmark")?;
    }

    for p in c.peers {
        info!("adding peer {}", base64::encode(&p.public_key));
        wg.clone().add_peer(&p.public_key)?;
        wg.set_peer(SetPeerCommand {
            public_key: p.public_key,
            preshared_key: p.preshared_key,
            endpoint: p.endpoint,
            keepalive: p.keepalive.map(|x| x.get()),
            replace_allowed_ips: true,
            allowed_ips: p.allowed_ips,
        })?;
    }

    let weak = std::sync::Arc::downgrade(&wg);

    scope0
        .clone()
        .spawn_canceller(wg.clone().task_update_cookie_secret());
    #[cfg(not(windows))]
    scope0.clone().spawn_canceller(wg.clone().task_update_mtu());
    scope0.clone().spawn_canceller(wg.clone().task_rx());
    scope0.clone().spawn_canceller(wg.clone().task_tx());

    #[cfg(unix)]
    {
        let weak1 = weak.clone();
        let config_file_path = c.general.config_file_path.take();
        scope0.clone().spawn_canceller(async move {
            reload_on_sighup(config_file_path, weak1)
                .await
                .unwrap_or_else(|e| warn!("error in reload_on_sighup: {:#}", e))
        });
    }

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    scope0.clone().spawn_canceller(async move {
        ipc_server(weak, &dev_name, ready_tx)
            .await
            .unwrap_or_else(|e| error!("IPC server error: {:#}", e))
    });

    if ready_rx.await.is_ok() {
        #[cfg(unix)]
        {
            if c.general.group.is_some() || c.general.user.is_some() {
                let p = privdrop::PrivDrop::default();
                let p = if let Some(ref user) = c.general.user {
                    p.user(user)
                } else {
                    p
                };
                let p = if let Some(ref group) = c.general.group {
                    p.group(group)
                } else {
                    p
                };
                p.apply().context("failed to change user and group")?;
            }

            if c.general.foreground {
                super::systemd::notify_ready()
                    .unwrap_or_else(|e| warn!("failed to notify systemd: {:#}", e));
            } else {
                notify
                    .unwrap()
                    .notify(0)
                    .context("failed to notify grand parent")?;
            }
        }
        // So rustc does not warn about unused.
        #[cfg(not(unix))]
        let _notify = notify;
    }

    scope0.cancelled().await;
    Ok(())
}
