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

#![cfg(windows)]

use anyhow::Context;
use std::net::*;
use tokio::process::Command;

use crate::cli::Config;
use crate::wireguard::ip_lookup_trie::to_mask;

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
            .map(|(start, end)| format!("{}-{}", start, end))
            .collect::<Vec<_>>()
            .join(",");

        tasks.push(tokio::spawn(async move {
            info!("block other DNS servers");
            block_dns(&ranges).await.context("block other dns servers")?;
            info!("blocked other DNS servers");

            tokio::spawn(async move {
                scopeguard::defer! {{
                    info!("unblock other DNS servers");
                    std::process::Command::new("powershell")
                        .arg("-noprofile")
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

    let mut routes = Vec::new();

    for p in &c.peers {
        if let Some(ref e) = p.endpoint {
            let e = e.ip();
            let len = if e.is_ipv4() { 32 } else { 128 };
            let e_default = if e.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
            tasks.push(tokio::spawn(async move {
                info!("fixate route to {}", e);
                let script = format!(r##"$r = try {{
    (Find-NetRoute -RemoteIpAddress {})[1]
}} catch {{
    Write-Host $_
    (Get-NetRoute {})
}}
Write-Host "nextHop:" $r.NextHop "ifIndex:" $r.ifIndex
[void](New-NetRoute -PolicyStore ActiveStore -DestinationPrefix {}/{} -NextHop $r.NextHop -ifIndex $r.ifIndex)"##,
                    e,
                    e_default,
                    e,
                    len,
                );
                let output = Command::new("powershell")
                    .arg("-noprofile")
                    .arg("-command")
                    .arg(script)
                    .output()
                    .await
                    .context("run powershell")?;
                if !output.status.success() {
                    warn!(
                        "failed to fixate route to {}, command output: {}",
                        e,
                        String::from_utf8_lossy(&output.stderr),
                    );
                } else {
                    info!("fixated route to {}: {}", e, String::from_utf8_lossy(&output.stdout).trim());
                    tokio::spawn(async move {
                        scopeguard::defer! {{
                            info!("delete route to {}", e);
                            std::process::Command::new("powershell")
                                .arg("-command")
                                .arg(format!("Remove-NetRoute -PolicyStore ActiveStore -DestinationPrefix {}/{} -Confirm:$false", e, len))
                                .output()
                                .and_then(|o| {
                                    if !o.status.success() {
                                        warn!(
                                            "failed to delete route to {}: {}",
                                            e,
                                            String::from_utf8_lossy(&o.stderr),
                                        );
                                    }
                                    Ok(())
                                }).unwrap_or_else(|err| {
                                    warn!("failed to delete route to {}, failed to run powershell: {}", e, err);
                                });
                        }};

                        futures::future::pending::<()>().await;
                    });
                }
                Ok(())
            }));
        }

        for &(a, p) in &p.allowed_ips {
            if p == 0 {
                if a.is_ipv4() {
                    routes.push((IpAddr::V4(0.into()), 1));
                    routes.push((IpAddr::V4([128, 0, 0, 1].into()), 1));
                } else {
                    routes.push((IpAddr::V6(0.into()), 1));
                    routes.push((IpAddr::V6((1u128 << 127).into()), 1));
                }
            } else {
                routes.push((a, p));
            }
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
