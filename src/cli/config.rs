use crate::wireguard::{X25519Key, X25519Pubkey};
use anyhow::{Context, Error};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::Path;

pub fn load_config_from_path(p: &Path) -> Result<Config, Error> {
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
                    // env-logger is not initialized yet. Fake it.
                    eprintln!("[WARN  titun::cli::config] configuration file is world readable");
                }
            }
        }
    }
    let config = load_config_from_file(&file)?;
    #[cfg(unix)]
    let mut config = config;
    #[cfg(unix)]
    {
        use std::io::{Seek, SeekFrom};

        // Store the file handle for reloading.
        match (&file).seek(SeekFrom::Start(0)) {
            // Unless the file does not support seeking.
            Err(_) => (),
            Ok(_) => config.general.config_file = Some(file),
        }
    }
    Ok(config)
}

pub fn load_config_from_file(mut file: &File) -> Result<Config, Error> {
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .context("failed to read config file")?;
    let config: Config = toml::from_str(&file_content).context("failed to parse config file")?;

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
                warn!("allowed IP {}/{} appeared multiple times", route.0, route.1)
            }
        }
    }

    // Verify that `network.prefix_len` is valid.
    #[cfg(windows)]
    {
        if let Some(ref n) = config.network {
            if n.prefix_len > 32 {
                bail!(
                    "invalid config file: prefix length {} is too large, should be <= 32",
                    n.prefix_len,
                );
            }
        }
    }

    Ok(config)
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,

    pub interface: InterfaceConfig,

    #[cfg(windows)]
    pub network: Option<NetworkConfig>,

    #[serde(default, rename = "Peer")]
    pub peers: Vec<PeerConfig>,
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

    // Only command line option.
    #[serde(skip)]
    pub exit_stdin_eof: bool,

    #[serde(skip)]
    pub config_file: Option<File>,

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
            && self.exit_stdin_eof == other.exit_stdin_eof
            && self.foreground == other.foreground
            && self.threads == other.threads
    }
}

#[cfg(windows)]
#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkConfig {
    pub address: std::net::Ipv4Addr,
    pub prefix_len: u32,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InterfaceConfig {
    #[serde(default, with = "os_string_actually_string")]
    pub name: Option<OsString>,

    #[serde(alias = "Key", with = "base64_u8_array")]
    pub private_key: X25519Key,

    #[serde(alias = "Port")]
    pub listen_port: Option<u16>,

    #[serde(rename = "FwMark", alias = "Mark")]
    pub fwmark: Option<u32>,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct PeerConfig {
    /// Peer public key.
    #[serde(with = "base64_u8_array")]
    pub public_key: X25519Pubkey,

    /// Pre-shared key.
    #[serde(alias = "PSK", default, with = "base64_u8_array_optional")]
    pub preshared_key: Option<[u8; 32]>,

    /// Peer endpoint.
    pub endpoint: Option<SocketAddr>,

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

mod os_string_actually_string {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<OsString>, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        if let Some(ref v) = v {
            s.serialize_some(v.to_str().ok_or_else(|| Error::custom("not utf-8"))?)
        } else {
            s.serialize_none()
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<OsString>, D::Error> {
        let v: String = Deserialize::deserialize(d)?;
        Ok(Some(v.into()))
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
Name = "tun7"
ListenPort = 7777
PrivateKey = "2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM="
FwMark = 33

[Network]
Address = "192.168.77.0"
PrefixLen = 24

[[Peer]]
PublicKey = "Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4="
PresharedKey = "w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k="
AllowedIPs = "192.168.77.1"
Endpoint = "192.168.3.1:7777"
PersistentKeepalive = 17
"##;

    #[test]
    fn deserialization() {
        let config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(
            config,
            Config {
                general: GeneralConfig::default(),
                interface: InterfaceConfig {
                    name: Some("tun7".into()),
                    listen_port: Some(7777),
                    private_key: U8Array::from_slice(
                        &base64::decode("2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM=").unwrap()
                    ),
                    fwmark: Some(33),
                },
                #[cfg(windows)]
                network: Some(NetworkConfig {
                    address: "192.168.77.0".parse().unwrap(),
                    prefix_len: 24,
                }),
                peers: vec![PeerConfig {
                    public_key: U8Array::from_slice(
                        &base64::decode("Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4=").unwrap()
                    ),
                    preshared_key: Some(U8Array::from_slice(
                        &base64::decode("w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k=").unwrap()
                    )),
                    endpoint: Some("192.168.3.1:7777".parse().unwrap()),
                    allowed_ips: [("192.168.77.1".parse().unwrap(), 32)]
                        .iter()
                        .cloned()
                        .collect(),
                    keepalive: NonZeroU16::new(17),
                }],
            }
        );
    }
}
