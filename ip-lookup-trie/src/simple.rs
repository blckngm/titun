// Copyright 2019 Guanhao Yin <sopium@mysterious.site>

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

//! A even simpler table: linear search of prefix lengthes.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct IpLookupTable<A, T> {
    // Sorted vec of (prefix len, table).
    vec: Vec<(u32, HashMap<A, T>)>,
}

/// IPv4 or IPv6 addresses.
pub trait Address: Sized + Copy + Eq + Ord + Hash {
    fn mask_with_prefix(self, prefix: u32) -> Self;
}

impl<A, T> Default for IpLookupTable<A, T> {
    fn default() -> Self {
        IpLookupTable { vec: Vec::new() }
    }
}

impl<A, T> IpLookupTable<A, T>
where
    A: Address,
{
    pub fn new() -> Self {
        IpLookupTable { vec: Vec::new() }
    }

    pub fn insert(&mut self, a: A, prefix: u32, t: T) -> Option<T> {
        let masked = a.mask_with_prefix(prefix);

        // Hash table for prefix len `prefix`.
        let table = match self.vec.binary_search_by_key(&prefix, |x| x.0) {
            Ok(i) => &mut self.vec[i].1,
            Err(i) => {
                self.vec.insert(i, (prefix, Default::default()));
                &mut self.vec[i].1
            }
        };

        table.insert(masked, t)
    }

    pub fn longest_match(&self, a: A) -> Option<&T> {
        for (prefix, table) in self.vec.iter().rev() {
            let x = table.get(&a.mask_with_prefix(*prefix));
            if x.is_some() {
                return x;
            }
        }
        None
    }

    pub fn remove(&mut self, a: A, prefix: u32) -> Option<T> {
        match self.vec.binary_search_by_key(&prefix, |x| x.0) {
            Ok(i) => {
                let t = &mut self.vec[i].1;
                let masked = a.mask_with_prefix(prefix);
                let result = t.remove(&masked);
                if t.is_empty() {
                    self.vec.remove(i);
                }
                result
            }
            _ => None,
        }
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
