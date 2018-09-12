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

use bytes::BytesMut;
use combine::parser::byte::{byte, bytes, digit};
use combine::parser::range::recognize;
use combine::parser::repeat::skip_until;
use combine::*;
use crate::wireguard::re_exports::U8Array;
use crate::wireguard::X25519Key;
use failure::Error;
use hex::decode;
use std::fmt::Debug;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::codec::Decoder;

use super::commands::*;

struct HexArr<A>(A);

impl<A> FromStr for HexArr<A>
where
    A: U8Array,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = decode(s)?;
        if v.len() != A::len() {
            bail!("Wrong length");
        }
        Ok(HexArr(A::from_slice(&v)))
    }
}

#[inline(always)]
fn newline<I>() -> impl Parser<Input = I, Output = ()>
where
    I: Stream<Item = u8>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    byte(b'\n')
        .map(|_| ())
        .or((byte(b'\r'), byte(b'\n')).map(|_| ()))
}

#[inline(always)]
fn hex_parser<'a, I, A>() -> impl Parser<Input = I, Output = A>
where
    A: U8Array,
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    from_str(recognize(skip_until(newline())))
        .expected("base64 encoded value")
        .map(|a: HexArr<A>| a.0)
}

#[inline(always)]
fn string<'a, I>(r: &'static str) -> impl Parser<Input = I, Output = ()>
where
    I: Stream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    // Cannot use `range`, it does work with skip_many, choice and partial parsing.
    bytes(r.as_bytes()).map(|_| ())
}

#[inline(always)]
fn bool_parser<'a, I>() -> impl Parser<Input = I, Output = bool>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    string("true")
        .map(|_| true)
        .or(string("false").map(|_| false))
        .expected("boolean")
}

#[inline(always)]
fn u16_parser<'a, I>() -> impl Parser<Input = I, Output = u16>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    from_str(recognize(skip_many1(digit()))).expected("number")
}

#[inline(always)]
fn u32_parser<'a, I>() -> impl Parser<Input = I, Output = u32>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    from_str(recognize(skip_many1(digit()))).expected("number")
}

fn allowed_ip_parser<'a, I>() -> impl Parser<Input = I, Output = (IpAddr, u32)>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    let ipv6_with_brackets = between(
        byte(b'['),
        byte(b']'),
        from_str(recognize(skip_until(byte(b']')))),
    ).map(IpAddr::V6);
    let ip_addr = from_str(recognize(skip_until(newline().or(byte(b'/').map(|_| ())))));
    let prefix_len = optional(byte(b'/').with(u32_parser()));
    (ipv6_with_brackets.or(ip_addr), prefix_len)
        .map(|(a, p): (IpAddr, _)| (a, p.unwrap_or_else(|| if a.is_ipv4() { 32 } else { 128 })))
}

macro_rules! kv {
    ($name:expr, $v:expr) => {
        r#try(string(concat!($name, "="))).with($v).skip(newline())
    };
}

fn peer_command_parser<'a, I>() -> impl Parser<Input = I, Output = WgSetPeerCommand>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    macro_rules! set_field {
        ($name:tt, $v:expr) => {{
            kv!(stringify!($name), $v).map(|x| {
                Box::new(move |c: &mut WgSetPeerCommand| {
                    c.$name = Clone::clone(&x);
                }) as Box<dyn Fn(&mut WgSetPeerCommand)>
            })
        }};
    }
    macro_rules! set_field_some {
        ($name:tt, $v:expr) => {{
            kv!(stringify!($name), $v).map(|x| {
                Box::new(move |c: &mut WgSetPeerCommand| {
                    c.$name = Some(Clone::clone(&x));
                }) as Box<dyn Fn(&mut WgSetPeerCommand)>
            })
        }};
    }

    let public_key = kv!("public_key", hex_parser::<_, [u8; 32]>());
    let remove = set_field!(remove, bool_parser());
    let preshared_key = set_field_some!(preshared_key, hex_parser::<_, [u8; 32]>());
    let endpoint = set_field_some!(endpoint, from_str(recognize(skip_until(newline()))));
    let persistent_keepalive_interval =
        set_field_some!(persistent_keepalive_interval, u16_parser());
    let replace_allowed_ips = set_field!(replace_allowed_ips, bool_parser());

    let allowed_ip = kv!("allowed_ip", allowed_ip_parser()).map(|a| {
        Box::new(move |c: &mut WgSetPeerCommand| {
            c.allowed_ips.push(a);
        }) as Box<dyn Fn(&mut WgSetPeerCommand)>
    });

    (
        public_key,
        many::<Vec<_>, _>(choice!(
            remove,
            preshared_key,
            endpoint,
            persistent_keepalive_interval,
            replace_allowed_ips,
            allowed_ip
        )),
    )
        .map(move |(pk, fs)| {
            let mut result = WgSetPeerCommand {
                public_key: pk,
                remove: false,
                preshared_key: None,
                endpoint: None,
                persistent_keepalive_interval: None,
                replace_allowed_ips: false,
                allowed_ips: vec![],
            };
            for f in fs {
                (f)(&mut result);
            }
            result
        })
}

fn set_command_parser<'a, I>() -> impl Parser<Input = I, Output = WgSetCommand>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    macro_rules! set_field {
        ($name:tt, $v:expr) => {{
            kv!(stringify!($name), $v).map(|x| {
                Box::new(move |c: &mut WgSetCommand| {
                    c.$name = x.clone();
                }) as Box<dyn Fn(&mut WgSetCommand)>
            })
        }};
    }
    macro_rules! set_field_some {
        ($name:tt, $v:expr) => {{
            kv!(stringify!($name), $v).map(|x| {
                Box::new(move |c: &mut WgSetCommand| {
                    c.$name = Some(x.clone());
                }) as Box<dyn Fn(&mut WgSetCommand)>
            })
        }};
    }

    let header = string("set=1").skip(newline());

    let private_key = set_field_some!(private_key, hex_parser::<_, X25519Key>());
    let listen_port = set_field_some!(listen_port, u16_parser());
    let fwmark = set_field_some!(fwmark, u32_parser());
    let replace_peers = set_field!(replace_peers, bool_parser());

    (
        header,
        many::<Vec<_>, _>(choice!(private_key, fwmark, listen_port, replace_peers)),
        many(peer_command_parser()),
        newline(),
    )
        .map(move |(_, ms, peers, _)| {
            let mut result = WgSetCommand {
                private_key: None,
                listen_port: None,
                fwmark: None,
                replace_peers: false,
                peers: vec![],
            };

            for m in ms {
                (m)(&mut result);
            }

            result.peers = peers;
            result
        })
}

pub fn command_parser<'a, I>() -> impl Parser<Input = I, Output = WgIpcCommand>
where
    I: RangeStream<Item = u8, Range = &'a [u8]>,
    I::Error: ParseError<u8, I::Range, I::Position>,
{
    let get_command = r#try(string("get=1"))
        .skip(newline())
        .skip(newline())
        .map(|_| WgIpcCommand::Get);

    get_command.or(set_command_parser().map(WgIpcCommand::Set))
}

#[derive(Debug)]
pub enum ReadCommandError {
    TooLarge,
    ParseError(Box<dyn Debug + 'static + Send>),
    IoError(std::io::Error),
}

impl From<std::io::Error> for ReadCommandError {
    fn from(e: std::io::Error) -> Self {
        ReadCommandError::IoError(e)
    }
}

#[derive(Default)]
pub struct CommandDecoder {}

impl Decoder for CommandDecoder {
    type Item = WgIpcCommand;
    type Error = ReadCommandError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        if src.len() > 1024 * 1024 {
            return Err(ReadCommandError::TooLarge);
        }

        for i in 0..src.len() - 1 {
            if src[i] == b'\n' && src[i + 1] == b'\n' {
                let chunk = src.split_to(i + 2);
                match command_parser().parse(&chunk[..]) {
                    Ok((c, _)) => return Ok(Some(c)),
                    Err(e) => return Err(ReadCommandError::ParseError(Box::new(e))),
                };
            }
        }
        Ok(None)
    }
}

pub fn command_decoder() -> CommandDecoder {
    Default::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_cidr_parser() {
        assert_eq!(
            allowed_ip_parser().parse(b"1.2.3.4/5".as_ref()).unwrap().0,
            ("1.2.3.4".parse().unwrap(), 5)
        );
        assert_eq!(
            allowed_ip_parser()
                .parse(b"[2018:3:4::7]".as_ref())
                .unwrap()
                .0,
            ("2018:3:4::7".parse().unwrap(), 128)
        );
    }

    #[test]
    fn test_parser() {
        assert_eq!(
            command_parser().parse(b"get=1\n\n".as_ref()),
            Ok((WgIpcCommand::Get, "".as_bytes()))
        );

        assert!(command_parser().parse("set=1\n\n".as_bytes()).is_ok());

        let input = &include_bytes!("example.txt")[..];
        println!("Result: {:?}", command_parser().easy_parse(input));
        assert!(command_parser().easy_parse(input).is_ok());
    }

    #[test]
    fn test_decoder() {
        use bytes::BufMut;

        let mut decoder = command_decoder();
        let mut buf = BytesMut::with_capacity(4096);
        buf.put("get=1\n".as_bytes());
        assert_eq!(decoder.decode(&mut buf).unwrap(), None);
        buf.put("\ng".as_bytes());
        assert_eq!(decoder.decode(&mut buf).unwrap(), Some(WgIpcCommand::Get));
        assert_eq!(buf, "g".as_bytes());
    }
}
