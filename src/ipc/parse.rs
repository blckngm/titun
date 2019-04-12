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
use failure::Error;
use hex::decode;
use std::marker::Unpin;
use tokio::prelude::stream::Fuse;
use tokio::prelude::*;

struct Peekable<S: Stream> {
    stream: Fuse<S>,
    peeked: Option<S::Item>,
}

impl<S: Stream> Stream for Peekable<S> {
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Some(item) = self.peeked.take() {
            return Ok(Async::Ready(Some(item)));
        }
        self.stream.poll()
    }
}

impl<S: Stream + Unpin> Peekable<S> {
    pub fn new(stream: S) -> Self {
        Peekable {
            stream: stream.fuse(),
            peeked: None,
        }
    }

    pub async fn peek(&mut self) -> Result<Option<&S::Item>, S::Error> {
        if self.peeked.is_some() {
            return Ok(self.peeked.as_ref());
        }
        match await!(self.stream.next()) {
            Some(Ok(item)) => {
                self.peeked = Some(item);
                Ok(self.peeked.as_ref())
            }
            None => Ok(None),
            Some(Err(e)) => Err(e),
        }
    }
}

async fn parse_peer<S>(stream: &mut Peekable<S>) -> Result<WgSetPeerCommand, Error>
where
    S: Stream<Item = String, Error = std::io::Error> + Unpin,
{
    let public_key_line = match await!(stream.next()) {
        None => bail!("Unexpected end of input stream"),
        Some(line_or_err) => line_or_err?,
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
        allowed_ips: vec![],
    };

    loop {
        let line = match await!(stream.peek())? {
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
                peer.allowed_ips.push((ip, prefix_len));
            }
            _ => break,
        }
        await!(stream.next());
    }

    Ok(peer)
}

async fn parse_set_command<S>(stream: &mut Peekable<S>) -> Result<WgSetCommand, Error>
where
    S: Stream<Item = String, Error = std::io::Error> + Unpin,
{
    let mut command = WgSetCommand {
        private_key: None,
        fwmark: None,
        listen_port: None,
        replace_peers: false,
        peers: vec![],
    };
    'outer: loop {
        let line = match await!(stream.peek())? {
            None => bail!("Unexpected end of input stream"),
            Some(line) => line,
        };
        if line.is_empty() {
            await!(stream.next());
            break;
        } else if line.starts_with("public_key") {
            loop {
                let peer = await!(parse_peer(stream))?;
                command.peers.push(peer);
                let line = match await!(stream.peek())? {
                    None => bail!("Unexpected end of input stream"),
                    Some(line) => line,
                };
                if line.is_empty() {
                    break 'outer;
                }
            }
        } else {
            let line = await!(stream.next()).unwrap().unwrap();
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

pub async fn parse_command<S>(stream: S) -> Result<Option<WgIpcCommand>, Error>
where
    S: Stream<Item = String, Error = std::io::Error> + Unpin,
{
    let mut stream = Peekable::new(stream);

    let first_line = match await!(stream.next()) {
        None => return Ok(None),
        Some(line_or_err) => line_or_err?,
    };
    match first_line.as_ref() {
        "get=1" => {
            let empty_line = match await!(stream.next()) {
                None => bail!("Unexpected end of input stream"),
                Some(line_or_err) => line_or_err?,
            };
            if !empty_line.is_empty() {
                bail!("Expected empty line, got {}", empty_line);
            }
            Ok(Some(WgIpcCommand::Get))
        }
        "set=1" => Ok(Some(WgIpcCommand::Set(await!(parse_set_command(
            &mut stream
        ))?))),
        _ => bail!("Unexpected command {}", first_line),
    }
}

pub async fn parse_command_io<R>(stream: R) -> Result<Option<WgIpcCommand>, Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let lines_codec = tokio::codec::LinesCodec::new_with_max_length(128);
    let lines_stream = tokio::codec::FramedRead::new(stream, lines_codec);
    await!(parse_command(lines_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        futures::executor::block_on(async {
            let stream = stream::iter_ok(vec!["get=1".into(), "".into()]);
            let result = await!(parse_command(stream));
            assert_eq!(result.unwrap(), Some(WgIpcCommand::Get));

            let stream = stream::iter_ok(include_str!("example.txt").lines().map(|x| x.into()));
            let result = await!(parse_command(stream));
            assert!(result.is_ok());
        });
    }
}
