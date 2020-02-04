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

use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// Parse an IPv4/v6 packet, returns total length, source, destination.
pub fn parse_ip_packet(packet: &[u8]) -> Result<(u16, IpAddr, IpAddr), ()> {
    if packet.len() < 20 {
        return Err(());
    }

    let v = packet[0] >> 4;

    if v == 4 {
        // IPv4.
        let len = u16::from_be_bytes(packet[2..4].try_into().unwrap());
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&packet[12..16]);
        let src = Ipv4Addr::from(addr);
        addr.copy_from_slice(&packet[16..20]);
        let dst = Ipv4Addr::from(addr);
        Ok((len, From::from(src), From::from(dst)))
    } else if v == 6 {
        // IPv6.
        if packet.len() < 40 {
            return Err(());
        }
        let len = u16::from_be_bytes(packet[4..6].try_into().unwrap());
        if packet.len() < len as usize {
            return Err(());
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&packet[8..24]);
        let src = Ipv6Addr::from(addr);
        addr.copy_from_slice(&packet[24..40]);
        let dst = Ipv6Addr::from(addr);
        Ok((len, From::from(src), From::from(dst)))
    } else {
        Err(())
    }
}

/// Convert IPv4 address to IPv4-mapped IPv6 address.
pub fn map_ipv4_to_ipv6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
        SocketAddr::V6(a) => a,
    }
}

/// Convert IPv4-mapped IPv6 address back to IPv4.
pub fn unmap_ipv4_from_ipv6(addr: SocketAddrV6) -> SocketAddr {
    if addr.ip().segments()[..6] == [0, 0, 0, 0, 0, 0xffff] {
        (addr.ip().to_ipv4().unwrap(), addr.port()).into()
    } else {
        addr.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn qc_ipv4_map_unmap(addr: SocketAddr) {
        assert_eq!(addr, unmap_ipv4_from_ipv6(map_ipv4_to_ipv6(addr)));
    }

    #[test]
    fn ipv4_map_unmap_v6_localhost() {
        let addr = "[::1]:7819".parse().unwrap();
        assert_eq!(addr, unmap_ipv4_from_ipv6(map_ipv4_to_ipv6(addr)));
    }
}
