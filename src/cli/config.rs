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
use crate::wireguard::{X25519Key, X25519Pubkey};
use anyhow::Context;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

/// Read and parse configuration from the file at the specified path.
///
/// `print_warnings`: Print warnings to stderr directly instead of go through
/// the logger.
pub fn load_config_from_path(p: &Path, print_warnings: bool) -> anyhow::Result<Config<SocketAddr>> {
    let file = OpenOptions::new()
        .read(true)
        .open(p)
        .context("failed to open config file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match file.metadata() {
            Err(_) => (),
            Ok(m) => {
                if m.mode() & 0o004 != 0 {
                    if print_warnings {
                        eprintln!(
                            "[WARN  titun::cli::config] configuration file is world readable"
                        );
                    } else {
                        warn!("configuration file is world readable");
                    }
                }
            }
        }
    }
    let mut config = load_config_from_file(&file, print_warnings)?;
    config.interface.name = Some(p.file_stem().context("file_stem")?.into());
    #[cfg(unix)]
    {
        config.general.config_file_path = Some(p.into());
    }
    Ok(config)
}

/// Read and parse configuration from file.
///
/// `print_warnings`: Print warnings to stderr directly instead of go through
/// the logger.
fn load_config_from_file(
    mut file: &File,
    print_warnings: bool,
) -> anyhow::Result<Config<SocketAddr>> {
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .context("failed to read config file")?;
    file_content = super::transform::maybe_transform(file_content);
    let config: Config<String> =
        toml::from_str(&file_content).context("failed to parse config file")?;

    // Verify that there are no duplicated peers. And warn about duplicated routes.
    let mut previous_peers = HashSet::new();
    let mut previous_routes = HashSet::new();

    for p in &config.peers {
        if !previous_peers.insert(p.public_key) {
            bail!(
                "invalid config file: peer {} appeared multiple times",
                base64::encode(&p.public_key)
            );
        }
        for &route in &p.allowed_ips {
            if !previous_routes.insert(route) {
                if print_warnings {
                    eprintln!(
                        "[WARN  titun::cli::config] allowed IP {}/{} appeared multiple times",
                        route.0, route.1
                    );
                } else {
                    warn!("allowed IP {}/{} appeared multiple time", route.0, route.1);
                }
            }
        }
    }

    config.resolve_addresses(print_warnings)
}

// Endpoint is the type of peer endpoints. It is expected to be either `String`
// or `SocketAddr`. First we parse config using `String`, then we parse and/or
// resolve the endpoints, and turn it into `SocketAddr`.
#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config<Endpoint> {
    #[serde(default)]
    pub general: GeneralConfig,

    pub interface: InterfaceConfig,

    #[serde(default, rename = "Peer")]
    pub peers: Vec<PeerConfig<Endpoint>>,
}

impl<T> Default for Config<T> {
    fn default() -> Config<T> {
        Config {
            general: GeneralConfig::default(),
            interface: InterfaceConfig {
                name: None,
                private_key: X25519::genkey(),
                fwmark: None,
                listen_port: None,
                mtu: None,
                address: BTreeSet::new(),
                dns: vec![],
            },
            peers: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct GeneralConfig {
    pub log: Option<String>,

    // Change to this user.
    #[cfg(unix)]
    pub user: Option<String>,

    // Change to this group.
    #[cfg(unix)]
    pub group: Option<String>,

    #[serde(skip)]
    pub config_file_path: Option<PathBuf>,

    #[serde(default)]
    pub foreground: bool,

    pub threads: Option<usize>,
}

impl Eq for GeneralConfig {}

impl PartialEq<GeneralConfig> for GeneralConfig {
    /// config_file is ignored in comparison.
    fn eq(&self, other: &GeneralConfig) -> bool {
        #[cfg(unix)]
        let ug = self.user == other.user && self.group == other.group;
        #[cfg(not(unix))]
        let ug = true;
        self.log == other.log
            && ug
            && self.foreground == other.foreground
            && self.threads == other.threads
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InterfaceConfig {
    // Interface name.
    //
    // It is either explicitly set via command line argument or inferred from
    // the stem of the config file name.
    #[serde(skip)]
    pub name: Option<OsString>,

    #[serde(alias = "Key", with = "base64_u8_array")]
    pub private_key: X25519Key,

    #[serde(alias = "Port")]
    pub listen_port: Option<u16>,

    #[serde(rename = "FwMark", alias = "Mark")]
    pub fwmark: Option<u32>,

    #[serde(default, with = "ip_prefix_len")]
    pub address: BTreeSet<(IpAddr, u32)>,

    #[serde(rename = "MTU", alias = "Mtu")]
    pub mtu: Option<u32>,

    #[serde(rename = "DNS", alias = "Dns", default, with = "ip_addr_vec")]
    pub dns: Vec<IpAddr>,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct PeerConfig<Endpoint> {
    /// Peer public key.
    #[serde(with = "base64_u8_array")]
    pub public_key: X25519Pubkey,

    /// Pre-shared key.
    #[serde(alias = "PSK", default, with = "base64_u8_array_optional")]
    pub preshared_key: Option<[u8; 32]>,

    /// Peer endpoint.
    pub endpoint: Option<Endpoint>,

    /// Don't route these addresses.
    #[serde(rename = "ExcludeRoutes", default, with = "ip_prefix_len")]
    pub exclude_routes: BTreeSet<(IpAddr, u32)>,

    /// Allowed source IPs.
    #[serde(
        rename = "AllowedIPs",
        alias = "AllowedIP",
        alias = "AllowedIp",
        alias = "AllowedIps",
        alias = "Route",
        alias = "Routes",
        default,
        with = "ip_prefix_len"
    )]
    pub allowed_ips: BTreeSet<(IpAddr, u32)>,

    /// Persistent keep-alive interval.
    /// Valid values: 1 - 0xfffe.
    #[serde(alias = "PersistentKeepalive")]
    pub keepalive: Option<NonZeroU16>,
}

fn resolve_address(addr: &str) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    match addr.to_socket_addrs() {
        Err(e) => Err(e.into()),
        Ok(mut addrs) => match addrs.next() {
            None => Err(anyhow::anyhow!("host not found")),
            Some(a) => Ok(a),
        },
    }
}

impl Config<String> {
    fn resolve_addresses(self, print_warnings: bool) -> anyhow::Result<Config<SocketAddr>> {
        let mut peers = Vec::with_capacity(self.peers.len());
        for p in self.peers {
            let endpoint = if let Some(endpoint) = p.endpoint {
                match resolve_address(&endpoint) {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        if let Some(e) = e.downcast_ref::<std::io::Error>() {
                            // Reject invalid syntax, but warn and ignore resolution failures.
                            if e.kind() == std::io::ErrorKind::InvalidInput {
                                bail!("invalid endpoint: {}", endpoint);
                            }
                        }
                        if print_warnings {
                            eprintln!(
                                "[WARN  titun::cli::config] failed to resolve endpoint {}: {}",
                                endpoint, e
                            );
                        } else {
                            warn!("failed to resolve {}: {:#}", endpoint, e);
                        }
                        None
                    }
                }
            } else {
                None
            };
            peers.push(PeerConfig {
                public_key: p.public_key,
                preshared_key: p.preshared_key,
                endpoint,
                allowed_ips: p.allowed_ips,
                exclude_routes: p.exclude_routes,
                keepalive: p.keepalive,
            });
        }
        Ok(Config {
            general: self.general,
            interface: self.interface,
            peers,
        })
    }
}

mod base64_u8_array {
    use super::*;
    use noise_protocol::U8Array;

    pub fn serialize<T: U8Array, S: Serializer>(t: &T, s: S) -> Result<S::Ok, S::Error> {
        let mut result = [0u8; 64];
        let len = base64::encode_config_slice(t.as_slice(), base64::STANDARD, &mut result[..]);
        s.serialize_str(std::str::from_utf8(&result[..len]).unwrap())
    }

    pub fn deserialize<'de, T: U8Array, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
        use serde::de::Error;

        let string: Cow<'_, str> = Deserialize::deserialize(d)?;
        let vec =
            base64::decode(string.as_ref()).map_err(|_| Error::custom("base64 decode failed"))?;

        if vec.len() != T::len() {
            return Err(Error::custom("invalid length"));
        }

        Ok(T::from_slice(vec.as_slice()))
    }
}

mod ip_prefix_len {
    use super::*;

    pub fn serialize<S: Serializer>(t: &BTreeSet<(IpAddr, u32)>, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let mut seq = s.serialize_seq(t.len().into())?;

        struct IpAndPrefixLen {
            ip: IpAddr,
            prefix_len: u32,
        }

        impl Serialize for IpAndPrefixLen {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let max_prefix_len = if self.ip.is_ipv4() { 32 } else { 128 };

                if self.prefix_len == max_prefix_len {
                    s.collect_str(&self.ip)
                } else {
                    s.collect_str(&format_args!("{}/{}", self.ip, self.prefix_len))
                }
            }
        }

        for &(ip, prefix_len) in t {
            seq.serialize_element(&IpAndPrefixLen { ip, prefix_len })?;
        }

        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeSet<(IpAddr, u32)>, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;

        struct AllowedIPsVisitor;

        impl AllowedIPsVisitor {
            fn parse<E: Error>(v: &str) -> Result<(IpAddr, u32), E> {
                let mut parts = v.splitn(2, '/');
                let ip: IpAddr = parts
                    .next()
                    .unwrap()
                    .parse()
                    .map_err(|_| Error::custom("failed to parse allowed IPs"))?;
                let max_prefix_len = if ip.is_ipv4() { 32 } else { 128 };
                let prefix_len: u32 = parts
                    .next()
                    .map(|x| x.parse())
                    .unwrap_or(Ok(max_prefix_len))
                    .map_err(|_| Error::custom("failed to parse allowed IPs"))?;
                if prefix_len > max_prefix_len {
                    return Err(Error::custom("prefix length is too large"));
                }
                Ok((ip, prefix_len))
            }
        }

        impl<'de> Visitor<'de> for AllowedIPsVisitor {
            type Value = BTreeSet<(IpAddr, u32)>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "an allowed IP (IP/PREFIX_LEN) or an array of allowed IPs"
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let v = Self::parse(v)?;
                let mut r = BTreeSet::new();
                r.insert(v);
                Ok(r)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, <A as SeqAccess<'de>>::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut result = BTreeSet::new();
                while let Some(v) = seq.next_element()? {
                    let v: Cow<'_, str> = v;
                    let p = Self::parse(&v)?;
                    result.insert(p);
                }
                Ok(result)
            }
        }

        d.deserialize_any(AllowedIPsVisitor)
    }
}

mod ip_addr_vec {
    use super::*;

    pub fn serialize<S: Serializer>(t: &[IpAddr], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let mut seq = s.serialize_seq(t.len().into())?;

        for addr in t {
            seq.serialize_element(addr)?;
        }

        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpAddr>, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;

        struct IpAddrVecVisitor;

        impl<'de> Visitor<'de> for IpAddrVecVisitor {
            type Value = Vec<IpAddr>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an IP address or an array of IP addresses")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let a: IpAddr = v
                    .parse()
                    .map_err(|_| Error::custom("failed to parse ip address"))?;
                Ok(vec![a])
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, <A as SeqAccess<'de>>::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut result = Vec::new();
                while let Some(v) = seq.next_element()? {
                    let v: Cow<'_, str> = v;
                    let a = v
                        .parse()
                        .map_err(|_| Error::custom("failed to parse ip address"))?;
                    result.push(a);
                }
                Ok(result)
            }
        }

        d.deserialize_any(IpAddrVecVisitor)
    }
}

mod base64_u8_array_optional {
    use super::*;
    use noise_protocol::U8Array;

    pub fn serialize<T: U8Array, S: Serializer>(t: &Option<T>, s: S) -> Result<S::Ok, S::Error> {
        if let Some(x) = t.as_ref() {
            let mut result = [0u8; 64];
            let len = base64::encode_config_slice(x.as_slice(), base64::STANDARD, &mut result[..]);
            s.serialize_some(std::str::from_utf8(&result[..len]).unwrap())
        } else {
            s.serialize_none()
        }
    }

    pub fn deserialize<'de, T: U8Array, D: Deserializer<'de>>(d: D) -> Result<Option<T>, D::Error> {
        super::base64_u8_array::deserialize(d).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noise_protocol::U8Array;

    const EXAMPLE_CONFIG: &str = r##"[Interface]
ListenPort = 7777
PrivateKey = "2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM="
FwMark = 33
DNS = "1.1.1.1"

[[Peer]]
PublicKey = "Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4="
PresharedKey = "w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k="
AllowedIPs = "192.168.77.1"
Endpoint = "192.168.3.1:7777"
PersistentKeepalive = 17
"##;

    const EXAMPLE_CONFIG_INVALID_ENDPOINT: &str = r##"[Interface]
PrivateKey = "2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM="

[Network]
Address = "192.168.77.0"
PrefixLen = 24

[[Peer]]
PublicKey = "Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4="
Endpoint = "host.no.port.invalid"
"##;

    #[test]
    fn resolve_invalid_endpoint() {
        let config: Config<String> = toml::from_str(EXAMPLE_CONFIG_INVALID_ENDPOINT).unwrap();

        let err = config.resolve_addresses(true).unwrap_err();
        assert!(format!("{}", err).contains("invalid endpoint"));
    }

    #[test]
    fn resolve_not_found() {
        let mut config: Config<String> = toml::from_str(EXAMPLE_CONFIG_INVALID_ENDPOINT).unwrap();
        config.peers[0].endpoint = Some("not.found.invalid:3238".into());

        let config = config.resolve_addresses(true).unwrap();
        assert!(config.peers[0].endpoint.is_none());
    }

    #[test]
    fn deserialization() {
        let config: Config<String> = toml::from_str(EXAMPLE_CONFIG).unwrap();
        let config = config.resolve_addresses(true).unwrap();
        assert_eq!(
            config,
            Config {
                general: GeneralConfig::default(),
                interface: InterfaceConfig {
                    name: None,
                    listen_port: Some(7777),
                    private_key: U8Array::from_slice(
                        &base64::decode("2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM=").unwrap()
                    ),
                    address: BTreeSet::new(),
                    mtu: None,
                    dns: vec![IpAddr::V4([1, 1, 1, 1].into())],
                    fwmark: Some(33),
                },
                peers: vec![PeerConfig {
                    public_key: U8Array::from_slice(
                        &base64::decode("Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4=").unwrap()
                    ),
                    preshared_key: Some(U8Array::from_slice(
                        &base64::decode("w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k=").unwrap()
                    )),
                    endpoint: Some("192.168.3.1:7777".parse().unwrap()),
                    allowed_ips: std::array::IntoIter::new([("192.168.77.1".parse().unwrap(), 32)])
                        .collect(),
                    exclude_routes: BTreeSet::new(),
                    keepalive: NonZeroU16::new(17),
                }],
            }
        );
    }
}
