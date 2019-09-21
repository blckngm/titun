// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

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

use crate::crypto::noise_crypto_impls::X25519;
use noise_protocol::DH;
use rand::prelude::*;
use rand::rngs::OsRng;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU16;
use std::ops::Deref;
use std::time::SystemTime;

/// X25519 private key.
pub type X25519Key = <X25519 as DH>::Key;
/// X25519 pubkey key.
pub type X25519Pubkey = <X25519 as DH>::Pubkey;

/// Config info about a WireGuard peer.
#[derive(Clone)]
pub struct PeerInfo {
    /// Peer public key.
    pub public_key: X25519Pubkey,
    /// Pre-shared key.
    pub psk: Option<[u8; 32]>,
    /// Peer endpoint.
    pub endpoint: Option<SocketAddrV6>,
    /// Allowed source IPs.
    pub allowed_ips: Vec<(IpAddr, u32)>,
    /// Persistent keep-alive interval in seconds.
    /// Valid values: 1 - 0xfffe.
    pub keepalive: Option<NonZeroU16>,
    /// Allow roaming.
    pub roaming: bool,
}

/// Config info about a WireGuard interface.
pub struct WgInfo {
    /// Self private key.
    pub key: X25519Key,
    pub fwmark: u32,
    /// Current listen port.
    pub port: u16,
}

impl WgInfo {
    pub fn pubkey(&self) -> &X25519Pubkey {
        self.key.public_key()
    }
}

/// State of WireGuard interface.
pub struct WgStateOut {
    /// Self private key.
    pub private_key: X25519Key,
    /// Peers.
    pub peers: Vec<PeerStateOut>,
    /// Port.
    pub listen_port: u16,
    /// Fwmark.
    pub fwmark: u32,
}

/// State of a peer.
pub struct PeerStateOut {
    /// Public key.
    pub public_key: X25519Pubkey,
    /// Pre-shared key.
    pub preshared_key: Option<[u8; 32]>,
    /// Endpoint.
    pub endpoint: Option<SocketAddr>,
    /// Last handshake time.
    pub last_handshake_time: Option<SystemTime>,
    /// Received bytes.
    pub rx_bytes: u64,
    /// Sent bytes.
    pub tx_bytes: u64,
    /// Persistent keep-alive interval.
    ///
    /// Zero value means persistent keepalive is not enabled.
    pub persistent_keepalive_interval: u16,
    /// Allowed IP addresses.
    pub allowed_ips: Vec<(IpAddr, u32)>,
}

/// Sender index or receiver index.
///
/// WireGuard treats an index as a `u32` in little endian.
/// Why not just treat it as a 4-byte array?
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Id(pub [u8; 4]);

impl Id {
    /// Generate a new random ID.
    pub fn gen() -> Id {
        let mut id = [0u8; 4];
        OsRng.fill_bytes(&mut id);
        Id(id)
    }

    /// Create Id from a slice.
    ///
    /// # Panics
    ///
    /// Slice must be 4 bytes long.
    pub fn from_slice(id: &[u8]) -> Id {
        let mut ret = Id([0u8; 4]);
        ret.0.copy_from_slice(id);
        ret
    }

    /// As slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Id {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PeerInfo {
    /// Return an identifier suitable for logging.
    pub(crate) fn log_id(&self) -> String {
        let mut pk = base64::encode(&self.public_key);
        pk.truncate(10);
        pk
    }
}
