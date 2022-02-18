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

use anyhow::Context;
use itertools::Itertools;
use std::net::*;
use tokio::process::Command;

use crate::cli::{ipset::IpSet, Config};
#[cfg(windows)]
use crate::utils::to_mask;

#[cfg(windows)]
#[allow(clippy::cognitive_complexity)]
pub async fn network_config(c: &Config<SocketAddr>) -> anyhow::Result<()> {
    if c.interface.address.is_empty() {
        return Ok(());
    }

    let name = c
        .interface
        .name
        .as_ref()
        .unwrap()
        .to_str()
        .context("interface name")?;

    let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

    for &(address, prefix_len) in &c.interface.address {
        let mask = if address.is_ipv4() {
            IpAddr::V4(to_mask::<u32>(prefix_len).into())
        } else {
            IpAddr::V6(to_mask::<u128>(prefix_len).into())
        };

        info!("set interface ip address {}/{}", address, prefix_len);
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
    }

    if !c.interface.dns.is_empty() {
        for dns in &c.interface.dns {
            info!("add DNS server {}", dns);
            let output = Command::new("netsh")
                .args(&["interface", "ip", "set", "dns"])
                .arg(name)
                .arg("static")
                .arg(format!("{}", dns))
                .arg("validate=no")
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
            .format_with(",", |(start, end), f| f(&format_args!("{}-{}", start, end)))
            .to_string();

        tasks.push(tokio::spawn(async move {
            info!("block other DNS servers");
            block_dns(&ranges).await.context("block other dns servers")?;
            info!("blocked other DNS servers");

            tokio::spawn(async move {
                scopeguard::defer! {
                    info!("unblock other DNS servers");
                    std::process::Command::new("powershell")
                        .arg("-noprofile")
                        .arg("-command")
                        .arg("Get-NetFirewallRule -PolicyStore ActiveStore -Group TiTunDNSBlock | Remove-NetFirewallRule")
                        .output()
                        .map(|o| {
                            if !o.status.success() {
                                warn!(
                                    "failed to unblock dns servers: {}",
                                    String::from_utf8_lossy(&o.stderr),
                                );
                            }
                        }).unwrap_or_else(|e| {
                            warn!("failed to unblock dns servers: failed to run powershell: {}", e);
                        });
                };
                futures::future::pending::<()>().await;
            });
            Ok(())
        }));
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

    let mut routes = IpSet::new();

    for p in &c.peers {
        for &(a, p) in &p.allowed_ips {
            routes.insert(a, p);
        }
    }
    for p in &c.peers {
        for &(a, p) in &p.exclude_routes {
            routes.remove(a, p);
        }
        for &a in &p.endpoint {
            routes.remove(a.ip(), if a.is_ipv4() { 32 } else { 128 });
        }
    }

    let name: String = name.into();
    tasks.push(tokio::spawn(async move {
        add_routes(&name, routes).await?;
        Ok(())
    }));

    for h in tasks {
        if let Ok(Err(e)) = h.await {
            warn!("{:#}", e);
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
async fn block_dns(ranges: &str) -> anyhow::Result<()> {
    let script = format!(
        "New-NetFirewallRule -PolicyStore ActiveStore -DisplayName TiTunDNSBlockUDP -Group TiTunDNSBlock -Direction Outbound -Action Block -RemoteAddress {} -RemotePort 53 -Protocol UDP\n\
         New-NetFirewallRule -PolicyStore ActiveStore -DisplayName TiTunDNSBlockTCP -Group TiTunDNSBlock -Direction Outbound -Action Block -RemoteAddress {} -RemotePort 53 -Protocol TCP",
        ranges, ranges,
    );
    let output = Command::new("powershell")
        .arg("-noprofile")
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

#[cfg(windows)]
async fn add_routes(
    interface_name: &str,
    routes: impl IntoIterator<Item = (IpAddr, u32)>,
) -> anyhow::Result<()> {
    let mut script = String::new();

    for (address, prefix_len) in routes {
        use std::fmt::Write;
        info!("add route {}/{}", address, prefix_len);
        let address: IpAddr = match address {
            IpAddr::V4(a4) => Ipv4Addr::from(u32::from(a4) & to_mask::<u32>(prefix_len)).into(),
            IpAddr::V6(a6) => Ipv6Addr::from(u128::from(a6) & to_mask::<u128>(prefix_len)).into(),
        };
        writeln!(
            script,
            "New-NetRoute -DestinationPrefix {}/{} -InterfaceAlias {}",
            address, prefix_len, interface_name
        )
        .unwrap();
    }

    let output = Command::new("powershell")
        .arg("-noprofile")
        .arg("-command")
        .arg(script)
        .output()
        .await
        .context("run powershell")?;
    if !output.status.success() {
        warn!(
            "failed to add routes, command output: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    } else {
        info!("added routes");
    }

    Ok(())
}

#[cfg(not(windows))]
async fn get_primary_network_service_name() -> anyhow::Result<String> {
    use tokio::io::AsyncBufReadExt;

    let mut out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let out = out.stdout.take().unwrap();
    let mut out = tokio::io::BufReader::new(out);
    let mut buf = String::new();
    out.read_line(&mut buf).await?;
    buf.clear();
    out.read_line(&mut buf).await?;
    buf.truncate(buf.len() - 1);
    Ok(buf)
}

#[cfg(not(windows))]
async fn add_route(ip: IpAddr, l: u32, gateway: &str, dev: &str) -> anyhow::Result<()> {
    let route_result = if cfg!(target_os = "macos") {
        Command::new("route")
            .arg("add")
            .arg(format!("{}/{}", ip, l))
            .arg(gateway)
            .output()
    } else {
        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg(format!("{}/{}", ip, l))
            .arg("dev")
            .arg(dev)
            .output()
    }
    .await
    .context("route add")?;
    if !route_result.status.success() {
        anyhow::bail!(
            r#"failed to add route {}/{}
command stdout:
===============
{}
===============
command stderr:
===============
{}
===============
"#,
            ip,
            l,
            String::from_utf8_lossy(&route_result.stdout),
            String::from_utf8_lossy(&route_result.stdout)
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub async fn network_config(c: &Config<SocketAddr>) -> anyhow::Result<()> {
    let name = c
        .interface
        .name
        .as_ref()
        .unwrap()
        .to_str()
        .context("interface name")?;

    // Set up, ip, mtu.
    let self_ip = if let Some((ip, _)) = c.interface.address.iter().next() {
        ip.to_string()
    } else {
        return Ok(());
    };
    let peer_ip = &self_ip;
    let mtu = c.interface.mtu.unwrap_or(1280).to_string();
    log::info!("setting the interface up, mtu {}, ip {}", mtu, self_ip);
    if cfg!(target_os = "linux") {
        if !Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(name)
            .arg("up")
            .arg("mtu")
            .arg(mtu)
            .status()
            .await
            .context("ip")?
            .success()
        {
            anyhow::bail!("failed to set interfaced up and mtu");
        }
        if !Command::new("ip")
            .arg("addr")
            .arg("add")
            .arg(&self_ip)
            .arg("dev")
            .arg(name)
            .status()
            .await
            .context("ip")?
            .success()
        {
            anyhow::bail!("failed to set interfaced ip");
        }
    } else {
        let ifconfig_result = Command::new("ifconfig")
            .arg(name)
            .arg("up")
            .arg("mtu")
            .arg(mtu)
            .arg(&self_ip)
            .arg(peer_ip)
            .status()
            .await
            .context("ifconfig")?;
        if !ifconfig_result.success() {
            anyhow::bail!("failed to set interface up, mtu and ip");
        }
    }

    // Set DNS.
    if cfg!(target_os = "macos") && !c.interface.dns.is_empty() {
        let service_name = get_primary_network_service_name()
            .await
            .context("get primary networkservice name")?;
        log::info!(
            "setting DNS servers of networkservice {}: {}",
            service_name,
            c.interface.dns.iter().format(", ")
        );
        let networksetup_result = Command::new("networksetup")
            .arg("-setdnsservers")
            .arg(&service_name)
            .args(c.interface.dns.iter().map(|d| d.to_string()))
            .status()
            .await
            .context("networksetup")?;
        if !networksetup_result.success() {
            anyhow::bail!("failed to set dns server");
        }
        // Flush DNS cache.
        let dscacheutil_result = Command::new("dscacheutil")
            .arg("-flushcache")
            .status()
            .await
            .context("dscacheutil")?;
        if !dscacheutil_result.success() {
            anyhow::bail!("failed to flush DNS cache");
        }
        let killall_result = Command::new("killall")
            .arg("-HUP")
            .arg("mDNSResponder")
            .status()
            .await
            .context("killall")?;
        if !killall_result.success() {
            anyhow::bail!("failed to flush DNS cache");
        }
        tokio::spawn(async move {
            scopeguard::defer! {
                info!("reset DNS settings of networkservice: {}", service_name);
                let _ = std::process::Command::new("networksetup")
                    .arg("-setdnsservers")
                    .arg(service_name)
                    .arg("empty")
                    .status();
            };
            futures::future::pending::<()>().await;
        });
    }

    if cfg!(target_os = "linux") && !c.interface.dns.is_empty() {
        log::info!(
            "settings DNS servers {}",
            c.interface.dns.iter().format(", ")
        );

        Command::new("systemd-resolve")
            .args(
                c.interface
                    .dns
                    .iter()
                    .flat_map(|d| std::array::IntoIter::new(["--set-dns".into(), d.to_string()])),
            )
            .arg("--interface")
            .arg(name)
            .status()
            .await
            .context("systemd-resolve")?;

        log::warn!("DNS servers added by other interfaces might still be active. If this is not desirable you need to manually remove them.");
    }

    // Set Route.
    let mut routes = IpSet::new();

    for p in &c.peers {
        for &(a, p) in &p.allowed_ips {
            routes.insert(a, p);
        }
    }
    for p in &c.peers {
        for &(a, p) in &p.exclude_routes {
            routes.remove(a, p);
        }
        for &a in &p.endpoint {
            routes.remove(a.ip(), if a.is_ipv4() { 32 } else { 128 });
        }
    }

    let mut added = 0;
    for (ip, l) in routes {
        if added < 10 {
            log::info!("adding route {}/{} via {}", ip, l, self_ip);
        } else if added % 100 == 0 {
            log::info!("added {} routes", added);
        }
        if let Err(e) = add_route(ip, l, &self_ip, name).await {
            log::warn!("failed to add route {}/{}: {}", ip, l, e);
        }
        added += 1;
    }
    if added > 10 {
        log::info!("all routes added ({} routes)", added);
    }
    Ok(())
}
