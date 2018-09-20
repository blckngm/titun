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

//! IP routing table.
//!
//! Uses the "Linear Search on Prefix Lengths" approach described in
//! <https://raminaji.wordpress.com/search-by-length-algorithms/>. It is very
//! easy to implement, and the performance should be good enough.

use fnv::FnvHashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use vec_map::VecMap;

pub struct IpLookupTable<A, T> {
    tables: VecMap<FnvHashMap<A, T>>,
}

/// IPv4 or IPv6 addresses.
pub trait Address: Sized + Copy + Eq + Ord + Hash {
    fn mask_with_prefix(self, prefix: u32) -> Self;
}

impl<A, T> Default for IpLookupTable<A, T> {
    fn default() -> Self {
        IpLookupTable {
            tables: VecMap::new(),
        }
    }
}

impl<A, T> IpLookupTable<A, T>
where
    A: Address,
{
    pub fn new() -> Self {
        IpLookupTable {
            tables: VecMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, a: A, prefix: u32) -> Option<&T> {
        let masked = a.mask_with_prefix(prefix);
        self.tables
            .get(prefix as usize)
            .and_then(|t| t.get(&masked))
    }

    pub fn insert(&mut self, a: A, prefix: u32, t: T) -> Option<T> {
        let masked = a.mask_with_prefix(prefix);
        self.tables
            .entry(prefix as usize)
            .or_insert(Default::default())
            .insert(masked, t)
    }

    pub fn longest_match(&self, a: A) -> Option<&T> {
        for (prefix, table) in self.tables.iter().rev() {
            let x = table.get(&a.mask_with_prefix(prefix as u32));
            if x.is_some() {
                return x;
            }
        }
        None
    }

    pub fn remove(&mut self, a: A, prefix: u32) -> Option<T> {
        let masked = a.mask_with_prefix(prefix);
        self.tables
            .get_mut(prefix as usize)
            .and_then(|t| t.remove(&masked))
    }
}

impl Address for Ipv4Addr {
    fn mask_with_prefix(self, prefix: u32) -> Self {
        let mask = if prefix == 0 {
            0u32
        } else {
            (!0u32) << (32 - prefix)
        };
        Ipv4Addr::from(u32::from(self) & mask)
    }
}

impl Address for Ipv6Addr {
    fn mask_with_prefix(self, prefix: u32) -> Self {
        let mask = if prefix == 0 {
            0u128
        } else {
            (!0u128) << (128 - prefix)
        };
        Ipv6Addr::from(u128::from(self) & mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_mask() {
        let a = Ipv4Addr::new(192, 168, 9, 7);
        assert_eq!(a.mask_with_prefix(32), a);
        assert_eq!(a.mask_with_prefix(24), Ipv4Addr::new(192, 168, 9, 0));
        assert_eq!(a.mask_with_prefix(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_ipv6_mask() {
        let a: Ipv6Addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
        assert_eq!(a.mask_with_prefix(128), a);
        assert_eq!(
            a.mask_with_prefix(64),
            "2001:0db8:85a3:0000::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(a.mask_with_prefix(0), Ipv6Addr::from(0u128));
    }

    #[test]
    fn routing_table() {
        let mut t = IpLookupTable::new();
        t.insert(Ipv4Addr::new(192, 168, 9, 233), 32, 99);
        t.insert(Ipv4Addr::new(192, 168, 9, 0), 24, 1);
        t.insert(Ipv4Addr::new(192, 168, 1, 0), 16, 2);
        t.insert(Ipv4Addr::new(10, 0, 77, 3), 8, 3);
        assert_eq!(t.longest_match(Ipv4Addr::new(192, 168, 9, 233)), Some(&99));
        assert_eq!(t.longest_match(Ipv4Addr::new(192, 168, 9, 1)), Some(&1));
        assert_eq!(t.longest_match(Ipv4Addr::new(192, 168, 10, 1)), Some(&2));
        assert_eq!(t.longest_match(Ipv4Addr::new(10, 27, 10, 1)), Some(&3));
        assert_eq!(t.longest_match(Ipv4Addr::new(8, 8, 8, 8)), None);
        assert!(t.remove(Ipv4Addr::new(10, 0, 0, 0), 8).is_some());
        t.insert(Ipv4Addr::new(10, 0, 77, 3), 0, 4);
        assert_eq!(t.longest_match(Ipv4Addr::new(172, 24, 7, 9)), Some(&4));
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_routing_table_four_levels(b: &mut crate::test::Bencher) {
        let mut t = IpLookupTable::new();
        t.insert(Ipv4Addr::new(192, 168, 9, 233), 32, 99);
        t.insert(Ipv4Addr::new(192, 168, 9, 0), 24, 1);
        t.insert(Ipv4Addr::new(192, 168, 1, 0), 16, 2);
        t.insert(Ipv4Addr::new(10, 0, 77, 3), 8, 3);

        b.iter(|| t.longest_match(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_routing_table_one_level(b: &mut crate::test::Bencher) {
        let mut t = IpLookupTable::new();
        t.insert(Ipv4Addr::new(192, 168, 9, 233), 32, 99);
        t.insert(Ipv4Addr::new(192, 168, 9, 3), 32, 1);
        t.insert(Ipv4Addr::new(192, 168, 1, 9), 32, 2);
        t.insert(Ipv4Addr::new(10, 0, 77, 3), 32, 3);

        b.iter(|| t.longest_match(Ipv4Addr::new(192, 168, 9, 233)));
    }
}
