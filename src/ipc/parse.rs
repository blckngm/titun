// Copyright 2018 Guanhao Yin <sopium@mysterious.site>

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

use crate::ipc::commands::*;
use crate::wireguard::re_exports::U8Array;
use crate::wireguard::X25519Key;
use crate::wireguard::{PeerStateOut, WgStateOut};
use futures::prelude::*;
use hex::decode;
use std::collections::BTreeSet;
use std::io;
use std::time::{Duration, SystemTime};
use tokio::io::AsyncRead;

// Futures has a `Peekable`, but it does not have an async `peek` method,
// and I could not define one on top of its `peek` due to lifetime issues.
struct Peekable<S: Stream + Unpin> {
    inner: S,
    peeked: Option<S::Item>,
}

impl<S, R, E> Peekable<S>
where
    S: Stream<Item = Result<R, E>> + Unpin,
    R: 'static,
{
    fn new(inner: S) -> Self {
        Self {
            inner,
            peeked: None,
        }
    }

    async fn try_next(&mut self) -> Result<Option<R>, E> {
        loop {
            if let Some(x) = self.peeked.take() {
                return match x {
                    Ok(x) => Ok(Some(x)),
                    Err(e) => Err(e),
                };
            }

            self.peeked = self.inner.next().await;
            if self.peeked.is_none() {
                return Ok(None);
            }
        }
    }

    async fn try_peek(&mut self) -> Result<Option<&'_ R>, E> {
        loop {
            match self.peeked {
                Some(Ok(ref x)) => return Ok(Some(x)),
                Some(Err(_)) => {
                    let e = match self.peeked.take() {
                        Some(Err(e)) => e,
                        _ => unreachable!(),
                    };
                    return Err(e);
                }
                None => {
                    self.peeked = self.inner.next().await;
                    if self.peeked.is_none() {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

async fn parse_peer<S>(stream: &mut Peekable<S>) -> anyhow::Result<WgSetPeerCommand>
where
    S: Stream<Item = io::Result<String>> + Unpin,
{
    let public_key_line = match stream.try_next().await? {
        None => bail!("Unexpected end of input stream"),
        Some(line) => line,
    };
    let mut kv = public_key_line.splitn(2, '=');
    let k = kv.next().unwrap();
    let v = match kv.next() {
        None => bail!("Invalid line: {}", public_key_line),
        Some(v) => v,
    };
    if k != "public_key" {
        bail!("Unexpected line {}, expected public_key", public_key_line);
    }
    let v = decode(v)?;
    if v.len() != 32 {
        bail!("Invalid length public key");
    }
    let public_key = U8Array::from_slice(&v[..]);

    let mut peer = WgSetPeerCommand {
        public_key,
        remove: false,
        preshared_key: None,
        endpoint: None,
        persistent_keepalive_interval: None,
        replace_allowed_ips: false,
        allowed_ips: BTreeSet::new(),
    };

    loop {
        let line = match stream.try_peek().await? {
            None => bail!("Unexpected end of input stream"),
            Some(line) => line,
        };
        if line.is_empty() || line.starts_with("public_key") {
            break;
        }
        let mut kv = line.splitn(2, '=');
        let k = kv.next().unwrap();
        let v = match kv.next() {
            None => bail!("Invalid line: {}", public_key_line),
            Some(v) => v,
        };
        match k {
            "remove" => peer.remove = v.parse()?,
            "preshared_key" => {
                let v = decode(v)?;
                if v.len() != 32 {
                    bail!("Invalid length for preshared key");
                }
                peer.preshared_key = Some(U8Array::from_slice(&v[..]));
            }
            "endpoint" => peer.endpoint = Some(v.parse()?),
            "persistent_keepalive_interval" => {
                peer.persistent_keepalive_interval = Some(v.parse()?)
            }
            "replace_allowed_ips" => peer.replace_allowed_ips = v.parse()?,
            "allowed_ip" => {
                let mut parts = v.splitn(2, '/');
                let ip = parts.next().unwrap();
                let prefix_len = match parts.next() {
                    None => bail!("Invalid allowed ip: {}", v),
                    Some(x) => x,
                };
                let ip: std::net::IpAddr = ip.parse()?;
                let prefix_len: u32 = prefix_len.parse()?;
                if prefix_len > if ip.is_ipv4() { 32 } else { 128 } {
                    bail!("Invalid prefix length: {}", prefix_len);
                }
                peer.allowed_ips.insert((ip, prefix_len));
            }
            _ => break,
        }
        stream.try_next().await.unwrap();
    }

    Ok(peer)
}

async fn parse_set_command<S>(stream: &mut Peekable<S>) -> anyhow::Result<WgSetCommand>
where
    S: Stream<Item = io::Result<String>> + Unpin,
{
    let mut command = WgSetCommand {
        private_key: None,
        fwmark: None,
        listen_port: None,
        replace_peers: false,
        peers: vec![],
    };
    'outer: loop {
        let line = match stream.try_peek().await? {
            None => bail!("Unexpected end of input stream"),
            Some(line) => line,
        };
        if line.is_empty() {
            stream.try_next().await.unwrap();
            break;
        } else if line.starts_with("public_key") {
            loop {
                let peer = parse_peer(stream).await?;
                command.peers.push(peer);
                let line = match stream.try_peek().await? {
                    None => bail!("Unexpected end of input stream"),
                    Some(line) => line,
                };
                if line.is_empty() {
                    break 'outer;
                }
            }
        } else {
            let line = stream.try_next().await.unwrap().unwrap();
            let mut kv = line.splitn(2, '=');
            let key = kv.next().unwrap();
            let value = match kv.next() {
                None => bail!("Invalid line: {}", line),
                Some(v) => v,
            };
            match key {
                "private_key" => {
                    let v = decode(value)?;
                    if v.len() != 32 {
                        bail!("Invalid length for private_key");
                    }
                    command.private_key = Some(X25519Key::from_slice(&v[..]));
                }
                "fwmark" => command.fwmark = Some(value.parse()?),
                "listen_port" => command.listen_port = Some(value.parse()?),
                "replace_peers" => command.replace_peers = value.parse()?,
                _ => bail!("Unexpected key: {}", key),
            }
        }
    }
    Ok(command)
}

pub async fn parse_command<S>(stream: S) -> anyhow::Result<Option<WgIpcCommand>>
where
    S: Stream<Item = io::Result<String>> + Unpin,
{
    let mut stream = Peekable::new(stream);

    let first_line = match stream.try_next().await? {
        None => return Ok(None),
        Some(line) => line,
    };
    match first_line.as_ref() {
        "get=1" => {
            let empty_line = match stream.try_next().await? {
                None => bail!("Unexpected end of input stream"),
                Some(line) => line,
            };
            if !empty_line.is_empty() {
                bail!("Expected empty line, got {}", empty_line);
            }
            Ok(Some(WgIpcCommand::Get))
        }
        "set=1" => Ok(Some(WgIpcCommand::Set(
            parse_set_command(&mut stream).await?,
        ))),
        _ => bail!("Unexpected command {}", first_line),
    }
}

pub async fn parse_command_io<R>(stream: R) -> anyhow::Result<Option<WgIpcCommand>>
where
    R: AsyncRead + Unpin,
{
    let codec = tokio_util::codec::LinesCodec::new_with_max_length(128);
    let lines = tokio_util::codec::FramedRead::new(stream, codec).map_err(|e| match e {
        tokio_util::codec::LinesCodecError::MaxLineLengthExceeded => {
            io::Error::new(io::ErrorKind::Other, "max line length exceeded")
        }
        tokio_util::codec::LinesCodecError::Io(e) => e,
    });
    parse_command(lines).await
}

async fn parse_peer_state_out<S>(stream: &mut Peekable<S>) -> anyhow::Result<PeerStateOut>
where
    S: Stream<Item = io::Result<String>> + Unpin,
{
    let public_key_line = match stream.try_next().await? {
        None => bail!("Unexpected end of input stream"),
        Some(line) => line,
    };
    let mut kv = public_key_line.splitn(2, '=');
    let k = kv.next().unwrap();
    let v = match kv.next() {
        None => bail!("Invalid line: {}", public_key_line),
        Some(v) => v,
    };
    if k != "public_key" {
        bail!("Unexpected line {}, expected public_key", public_key_line);
    }
    let v = decode(v)?;
    if v.len() != 32 {
        bail!("Invalid length public key");
    }
    let public_key = U8Array::from_slice(&v[..]);

    let mut peer = PeerStateOut {
        public_key,
        preshared_key: None,
        endpoint: None,
        persistent_keepalive_interval: 0,
        allowed_ips: BTreeSet::new(),
        last_handshake_time: None,
        rx_bytes: 0,
        tx_bytes: 0,
    };

    loop {
        let line = match stream.try_peek().await? {
            None => bail!("Unexpected end of input stream"),
            Some(line) => line,
        };
        if line.is_empty() || line.starts_with("public_key") {
            break;
        }
        let mut kv = line.splitn(2, '=');
        let k = kv.next().unwrap();
        let v = match kv.next() {
            None => bail!("Invalid line: {}", public_key_line),
            Some(v) => v,
        };
        match k {
            "last_handshake_time_sec" => {
                let sec = v.parse()?;
                peer.last_handshake_time = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(sec));
            }
            "last_handshake_time_nsec" => {
                let usec = v.parse()?;
                if let Some(ref mut t) = peer.last_handshake_time {
                    *t += Duration::from_nanos(usec);
                } else {
                    bail!("Get last_handshake_time_nsec but no last_handshake_time_sec");
                }
            }
            "rx_bytes" => peer.rx_bytes = v.parse()?,
            "tx_bytes" => peer.tx_bytes = v.parse()?,
            "preshared_key" => {
                let v = decode(v)?;
                if v.len() != 32 {
                    bail!("Invalid length for preshared key");
                }
                peer.preshared_key = Some(U8Array::from_slice(&v[..]));
            }
            "endpoint" => peer.endpoint = Some(v.parse()?),
            "persistent_keepalive_interval" => peer.persistent_keepalive_interval = v.parse()?,
            "allowed_ip" => {
                let mut parts = v.splitn(2, '/');
                let ip = parts.next().unwrap();
                let prefix_len = match parts.next() {
                    None => bail!("Invalid allowed ip: {}", v),
                    Some(x) => x,
                };
                let ip: std::net::IpAddr = ip.parse()?;
                let prefix_len: u32 = prefix_len.parse()?;
                if prefix_len > if ip.is_ipv4() { 32 } else { 128 } {
                    bail!("Invalid prefix length: {}", prefix_len);
                }
                peer.allowed_ips.insert((ip, prefix_len));
            }
            _ => break,
        }
        stream.try_next().await.unwrap();
    }

    Ok(peer)
}

async fn parse_wg_state_out<S>(stream: &mut Peekable<S>) -> anyhow::Result<WgStateOut>
where
    S: Stream<Item = io::Result<String>> + Unpin,
{
    let mut state = WgStateOut {
        private_key: X25519Key::new(),
        peers: vec![],
        listen_port: 0,
        fwmark: 0,
    };
    'outer: loop {
        let line = match stream.try_peek().await? {
            None => bail!("Unexpected end of input stream"),
            Some(line) => line,
        };
        if line.is_empty() {
            stream.try_next().await.unwrap();
            break;
        } else if line.starts_with("public_key") {
            loop {
                let peer = parse_peer_state_out(stream).await?;
                state.peers.push(peer);
                let line = match stream.try_peek().await? {
                    None => bail!("Unexpected end of input stream"),
                    Some(line) => line,
                };
                if !line.starts_with("public_key") {
                    break 'outer;
                }
            }
        } else {
            let line = stream.try_next().await.unwrap().unwrap();
            let mut kv = line.splitn(2, '=');
            let key = kv.next().unwrap();
            let value = match kv.next() {
                None => bail!("Invalid line: {}", line),
                Some(v) => v,
            };
            match key {
                "private_key" => {
                    let v = decode(value)?;
                    if v.len() != 32 {
                        bail!("Invalid length for private_key");
                    }
                    state.private_key = X25519Key::from_slice(&v[..]);
                }
                "fwmark" => state.fwmark = value.parse()?,
                "listen_port" => state.listen_port = value.parse()?,
                // XXX: Check protocol version and errno.
                "errno" => break,
                "protocol_version" => break,
                _ => bail!("Unexpected key: {}", key),
            }
        }
    }
    Ok(state)
}

pub async fn parse_get_response<S>(stream: S) -> anyhow::Result<Result<WgStateOut, i32>>
where
    S: Stream<Item = io::Result<String>> + Unpin,
{
    let mut stream = Peekable::new(stream);

    let first_line = match stream.try_peek().await? {
        None => bail!("Empty response"),
        Some(line) => line,
    };

    if first_line.starts_with("errno=") {
        let mut kv = first_line.splitn(2, '=');
        kv.next().unwrap();
        let v = match kv.next() {
            None => bail!("Invalid line: {}", first_line),
            Some(v) => v,
        };
        let errno: i32 = v.parse()?;
        Ok(Err(errno))
    } else {
        let state: WgStateOut = parse_wg_state_out(&mut stream).await?;
        Ok(Ok(state))
    }
}

pub async fn parse_get_response_io<R>(stream: R) -> anyhow::Result<Result<WgStateOut, i32>>
where
    R: AsyncRead + Unpin,
{
    let codec = tokio_util::codec::LinesCodec::new_with_max_length(128);
    let lines = tokio_util::codec::FramedRead::new(stream, codec).map_err(|e| match e {
        tokio_util::codec::LinesCodecError::MaxLineLengthExceeded => {
            io::Error::new(io::ErrorKind::Other, "max line length exceeded")
        }
        tokio_util::codec::LinesCodecError::Io(e) => e,
    });
    parse_get_response(lines).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        futures::executor::block_on(async {
            let stream = stream::iter(vec!["get=1", ""]).map(|x| Ok(x.to_owned()));
            let result = parse_command(stream).await;
            assert_eq!(result.unwrap(), Some(WgIpcCommand::Get));

            let stream = stream::iter(
                include_str!("example.txt")
                    .lines()
                    .map(|x| Ok(x.to_owned())),
            );
            let result = parse_command(stream).await;
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_parsing_get_response() -> anyhow::Result<()> {
        futures::executor::block_on(async {
            assert!(
                parse_get_response_io(&include_bytes!("example_response.txt")[..])
                    .await?
                    .is_ok()
            );
            assert!(
                parse_get_response_io(&include_bytes!("example_response_1.txt")[..])
                    .await?
                    .is_ok()
            );
            assert!(
                parse_get_response_io(&include_bytes!("example_response_2.txt")[..])
                    .await?
                    .is_ok()
            );
            Ok(())
        })
    }
}
