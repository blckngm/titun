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

use crate::wireguard::X25519Key;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Eq, PartialEq)]
pub enum WgIpcCommand {
    Get,
    Set(WgSetCommand),
}

#[derive(Debug, Eq, PartialEq)]
pub struct WgSetCommand {
    pub private_key: Option<X25519Key>,
    pub fwmark: Option<u32>,
    pub listen_port: Option<u16>,
    pub replace_peers: bool,
    pub peers: Vec<WgSetPeerCommand>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WgSetPeerCommand {
    pub public_key: [u8; 32],
    pub remove: bool,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: Option<u16>,
    pub replace_allowed_ips: bool,
    pub allowed_ips: BTreeSet<(IpAddr, u32)>,
}
