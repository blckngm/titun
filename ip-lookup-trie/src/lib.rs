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

//! IP longest prefix lookup table (i.e., routing table).
//!
//! Implemented as patricia tries.
//!
//! ```
//! # use std::net::Ipv4Addr;
//! # use ip_lookup_trie::*;
//!
//! let mut t = IpLookupTable::new();
//! t.insert(Ipv4Addr::new(0, 0, 0, 0), 0, 0);
//! t.insert(Ipv4Addr::new(192, 168, 0, 0), 16, 1);
//! t.insert(Ipv4Addr::new(192, 168, 72, 0), 24, 2);
//! t.insert(Ipv4Addr::new(10, 0, 0, 0), 8, 33);
//!
//! assert_eq!(t.longest_match(Ipv4Addr::new(10, 2, 3, 6)), Some(&33));
//! assert_eq!(t.longest_match(Ipv4Addr::new(172, 8, 33, 9)), Some(&0));
//! assert_eq!(t.longest_match(Ipv4Addr::new(192, 168, 72, 39)), Some(&2));
//!
//! t.remove(Ipv4Addr::new(0, 0, 0, 0), 0);
//! assert_eq!(t.longest_match(Ipv4Addr::new(172, 8, 33, 9)), None);
//! ```

#![deny(missing_debug_implementations, missing_docs)]

use num_traits::{PrimInt, Unsigned};

use std::fmt::LowerHex;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[derive(Debug)]
struct Trie<K: LowerHex, T> {
    root: Option<Box<TrieNode<K, T>>>,
}

struct TrieNode<K, T> {
    k: K,
    len: u32,
    left: Option<Box<TrieNode<K, T>>>,
    right: Option<Box<TrieNode<K, T>>>,
    value: Option<T>,
}

impl<K: LowerHex, T: std::fmt::Debug> std::fmt::Debug for TrieNode<K, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.debug_struct("TrieNode")
            .field("k", &format!("{:#x}", self.k))
            .field("len", &self.len)
            .field("left", &self.left)
            .field("right", &self.right)
            .field("value", &self.value)
            .finish()
    }
}

impl<K, T> Default for Trie<K, T>
where
    K: Unsigned + PrimInt + LowerHex,
{
    fn default() -> Self {
        Trie::new()
    }
}

impl<K, T> Trie<K, T>
where
    K: Unsigned + PrimInt + LowerHex,
{
    pub fn new() -> Self {
        Trie { root: None }
    }

    fn insert(&mut self, k: K, k_len: u32, v: T) -> Option<T> {
        assert!(k_len <= bit_len::<K>());

        let mask = to_mask(k_len);
        let k = k & mask;
        match self.root {
            None => {
                let n = TrieNode {
                    k,
                    len: k_len,
                    left: None,
                    right: None,
                    value: Some(v),
                };
                self.root = Some(Box::new(n));
                None
            }
            Some(ref mut n) => n.insert(k, k_len, v),
        }
    }

    fn remove(&mut self, k: K, k_len: u32) -> Option<T> {
        assert!(k_len <= bit_len::<K>());

        if let Some(r) = self.root.take() {
            let (result, new_root) = r.remove(k, k_len);
            self.root = new_root;
            result
        } else {
            None
        }
    }

    #[cfg(test)]
    fn self_check(&self) -> Result<(), String> {
        if let Some(ref n) = self.root {
            n.self_check()
        } else {
            Ok(())
        }
    }

    fn longest_match(&self, k: K) -> Option<&T> {
        self.root.as_ref().and_then(|n| n.longest_match(k))
    }
}

fn bit_len<K>() -> u32 {
    (std::mem::size_of::<K>() * 8) as u32
}

fn to_mask<K>(prefix_len: u32) -> K
where
    K: Unsigned + PrimInt,
{
    match prefix_len {
        0 => K::zero(),
        _ => K::max_value().unsigned_shl(bit_len::<K>() - prefix_len),
    }
}

fn next_bit_mask1<K>(len: u32) -> K
where
    K: Unsigned + PrimInt,
{
    (K::one().rotate_right(1)).unsigned_shr(len)
}

fn common_prefix_len<K>(k1: K, len1: u32, k2: K, len2: u32) -> u32
where
    K: Unsigned + PrimInt,
{
    let smaller_len = std::cmp::min(len1, len2);
    std::cmp::min(smaller_len, (k1 ^ k2).leading_zeros())
}

impl<K, T> TrieNode<K, T>
where
    K: Unsigned + PrimInt + LowerHex,
{
    fn insert(&mut self, k: K, k_len: u32, v: T) -> Option<T> {
        let self_mask: K = to_mask(self.len);
        if self.len == k_len && self.k & self_mask == k & self_mask {
            // Replace value of this node.
            return self.value.replace(v);
        }
        if k_len > self.len && (k & self_mask == self.k & self_mask) {
            // Self key is a prefix of the inserted key,
            // Insert to a child node.
            let next_bit_mask = next_bit_mask1(self.len);
            let to_insert = if k & next_bit_mask != K::zero() {
                &mut self.right
            } else {
                &mut self.left
            };
            return to_insert
                .get_or_insert_with(|| {
                    Box::new(TrieNode {
                        k,
                        len: k_len,
                        left: None,
                        right: None,
                        value: None,
                    })
                })
                .insert(k, k_len, v);
        }

        // Split:
        //
        // Change self mask so that new self key is the common prefix of
        // old self key and the inserted key.

        let common_prefix_len = common_prefix_len(self.k, self.len, k, k_len);
        let new_mask = to_mask(common_prefix_len);

        let old_self = std::mem::replace(
            self,
            TrieNode {
                k: self.k & new_mask,
                len: common_prefix_len,
                left: None,
                right: None,
                value: None,
            },
        );

        let next_bit_mask = next_bit_mask1(common_prefix_len);
        let old_self_next_bit_is_set = (old_self.k & next_bit_mask) != K::zero();

        // If the next bit of the old self key is set, the old self
        // becomes the right child. Otherwise it becomes the left child.
        let (old_self_child, new_node_child) = if old_self_next_bit_is_set {
            (&mut self.right, &mut self.left)
        } else {
            (&mut self.left, &mut self.right)
        };

        *old_self_child = Some(Box::new(old_self));
        if k_len != self.len {
            // The inserted key becomes the other child node.
            *new_node_child = Some(Box::new(TrieNode {
                k,
                len: k_len,
                left: None,
                right: None,
                value: Some(v),
            }))
        } else {
            // The inserted key is at the new self node.
            self.value = Some(v);
        }

        None
    }

    fn remove(mut self: Box<Self>, k: K, k_len: u32) -> (Option<T>, Option<Box<Self>>) {
        let mask = to_mask(k_len);
        let self_mask = to_mask(self.len);
        if self_mask == mask && self.k & mask == k & mask {
            // Matches self. Remove value.
            let r = self.value.take();
            // If a child is none, this node is no longer necessary, return the other child.
            let new_node = if self.left.is_none() {
                self.right.take()
            } else if self.right.is_none() {
                self.left.take()
            } else {
                Some(self)
            };
            return (r, new_node);
        }

        if k_len <= self.len || k & self_mask != self.k & self_mask {
            // Didn't find a match.
            return (None, Some(self));
        }

        // Remove from a child.
        let nbm = next_bit_mask1(self.len);
        let nb_set = (k & nbm) != K::zero();
        let child = if nb_set {
            &mut self.right
        } else {
            &mut self.left
        };
        let result = if let Some(n) = child.take() {
            let (result, new) = n.remove(k, k_len);
            *child = new;
            result
        } else {
            None
        };

        // Return a child if self is no longer necessary.
        if self.value.is_none() {
            if self.left.is_none() {
                return (result, self.right);
            } else if self.right.is_none() {
                return (result, self.left);
            }
        }

        (result, Some(self))
    }

    fn longest_match(&self, k: K) -> Option<&T> {
        let mut n = self;
        let mut current_best = None;

        loop {
            let n_mask = to_mask(n.len);
            if n.k & n_mask == k & n_mask {
                if n.value.is_some() {
                    current_best = n.value.as_ref();
                }
                if n_mask != K::max_value() {
                    let nbm = next_bit_mask1(n.len);
                    let nb_set = (k & nbm) != K::zero();
                    let next_node = if nb_set { &n.right } else { &n.left };
                    if let Some(ref next_node) = next_node {
                        n = next_node;
                        continue;
                    }
                }
            }
            break;
        }

        current_best
    }

    #[cfg(test)]
    fn self_check(&self) -> Result<(), String> {
        if self.len > bit_len::<K>() {
            return Err(format!("Invalid len: {}", self.len));
        }

        if self.k & to_mask(self.len) != self.k {
            return Err(format!("Unmasked k: {:#x}, len {}", self.k, self.len));
        }

        if self.value.is_none() && (self.left.is_none() || self.right.is_none()) {
            return Err("node has only one child and no value".to_string());
        }

        if let Some(ref l) = self.left {
            l.self_check_as_child(self.k, self.len, false)?;
        }
        if let Some(ref r) = self.right {
            r.self_check_as_child(self.k, self.len, true)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn self_check_as_child(
        &self,
        parent_k: K,
        parent_len: u32,
        right_child: bool,
    ) -> Result<(), String> {
        if parent_len >= self.len {
            return Err(format!(
                "parent_len {} >= self.len {}",
                parent_len, self.len,
            ));
        }
        let nbm = next_bit_mask1(parent_len);
        if ((self.k & nbm) != K::zero()) != right_child {
            return Err("wrong child position".to_string());
        }
        if (self.k & to_mask(parent_len)) != parent_k {
            return Err(format!(
                "parent_k {:#x} is not a prefix of self.k {:#x}",
                parent_k, self.k
            ));
        }
        self.self_check()
    }
}

/// Something that is equivalent to a fixed size unsigned integer, thus can be used
/// as keys in the prefix lookup table.
///
/// Most notably, [`Ipv4Addr`](std::net::Ipv4Addr) and
/// [`Ipv6Addr`](std::net::Ipv6Addr).
pub trait Address {
    /// The integer type that this type is equivalent to.
    type U: Unsigned + PrimInt + LowerHex;

    /// Convert to the integer type.
    fn into_integer(self) -> Self::U;
}

impl Address for Ipv4Addr {
    type U = u32;

    fn into_integer(self) -> u32 {
        self.into()
    }
}

impl Address for Ipv6Addr {
    type U = u128;

    fn into_integer(self) -> u128 {
        self.into()
    }
}

/// IP longest prefix lookup table.
#[derive(Debug)]
pub struct IpLookupTable<A: Address, T> {
    trie: Trie<A::U, T>,
}

impl<A: Address, T> Default for IpLookupTable<A, T> {
    fn default() -> IpLookupTable<A, T> {
        IpLookupTable::new()
    }
}

impl<A: Address, T> IpLookupTable<A, T> {
    /// Create a new table.
    pub fn new() -> Self {
        IpLookupTable { trie: Trie::new() }
    }

    /// Insert an prefix with an associated value.
    ///
    /// Returns the original value associated with that prefix.
    ///
    /// # Panics
    ///
    /// If `prefix_len` is larger than the number of bits in `A`.
    pub fn insert(&mut self, prefix: A, prefix_len: u32, t: T) -> Option<T> {
        self.trie.insert(prefix.into_integer(), prefix_len, t)
    }

    /// Remove a prefix.
    ///
    /// Returns the removed value.
    ///
    /// # Panics
    ///
    /// If `prefix_len` is larger than the number of bits in `A`.
    pub fn remove(&mut self, prefix: A, prefix_len: u32) -> Option<T> {
        self.trie.remove(prefix.into_integer(), prefix_len)
    }

    /// Find the longest match.
    pub fn longest_match(&self, addr: A) -> Option<&T> {
        self.trie.longest_match(addr.into_integer())
    }

    #[cfg(test)]
    pub fn self_check(&self) -> Result<(), String> {
        self.trie.self_check()
    }
}

#[cfg(test)]
mod simple;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_to_mask() {
        assert_eq!(to_mask::<u32>(32), 0xffff_ffffu32);
        assert_eq!(to_mask::<u32>(0), 0u32);
        assert_eq!(to_mask::<u32>(24), 0xffff_ff00u32);
        assert_eq!(
            to_mask::<u32>(1),
            0b1000_0000_0000_0000_0000_0000_0000_0000u32
        );
        assert_eq!(
            to_mask::<u32>(31),
            0b1111_1111_1111_1111_1111_1111_1111_1110u32
        );
    }

    #[test]
    fn test_next_bit_mask() {
        let nbm0: u32 = next_bit_mask1(0);
        assert_eq!(nbm0, 1u32 << 31);
        for len in 1..=31 {
            let mask: u32 = to_mask(len);
            let nbm: u32 = next_bit_mask1(len);
            assert_eq!(mask, !((nbm << 1) - 1));
        }
    }

    #[derive(Copy, Clone, Debug)]
    struct Len(u32);

    impl quickcheck::Arbitrary for Len {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            Len(g.next_u32() % 33)
        }
    }

    #[derive(Copy, Clone, Debug)]
    struct Len6(u32);

    impl quickcheck::Arbitrary for Len6 {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            Len6(g.next_u32() % 129)
        }
    }

    #[quickcheck]
    fn qc_insert_and_self_check(v: Vec<(Ipv4Addr, Len, u32)>) {
        let mut table = IpLookupTable::new();
        for (a, l, v) in v {
            table.insert(a, l.0, v);
        }
        table.self_check().unwrap();
    }

    #[quickcheck]
    fn qc_insert_remove(mut v: Vec<(Ipv4Addr, Len, u32)>, r: Vec<(Ipv4Addr, Len)>) {
        use rand::prelude::*;

        let mut table = IpLookupTable::new();
        for (a, l, v) in &v {
            table.insert(*a, l.0, *v);
        }
        table.self_check().unwrap();

        v.shuffle(&mut thread_rng());

        for (a, l, _) in v {
            table.remove(a, l.0);
        }
        table.self_check().unwrap();

        for (a, l) in r {
            table.remove(a, l.0);
        }
        table.self_check().unwrap();

        assert!(table.trie.root.is_none());
    }

    #[quickcheck]
    fn qc_insert_and_self_check_v6(v: Vec<(Ipv6Addr, Len6, u32)>) {
        let mut table = IpLookupTable::new();
        for (a, l, v) in v {
            table.insert(a, l.0, v);
        }
        table.self_check().unwrap();
    }

    #[quickcheck]
    fn qc_same_with_simple(mut v: Vec<(Ipv4Addr, Len, u32)>, l: Vec<Ipv4Addr>) {
        use rand::prelude::*;

        let mut table = IpLookupTable::new();
        let mut table1 = simple::IpLookupTable::new();
        for (a, l, v) in &v {
            assert_eq!(table.insert(*a, l.0, *v), table1.insert(*a, l.0, *v),);
        }

        let rlen = v.len() / 2;
        let (r, r1) = v.partial_shuffle(&mut thread_rng(), rlen);
        for (a, l, _) in r {
            assert_eq!(table.remove(*a, l.0), table1.remove(*a, l.0));
        }

        for a in l {
            assert_eq!(table.longest_match(a), table1.longest_match(a),);
        }

        for (a, l, _) in r1 {
            assert_eq!(table.remove(*a, l.0), table1.remove(*a, l.0));
        }
    }

    #[quickcheck]
    fn qc_same_with_simple_v6(mut v: Vec<(Ipv6Addr, Len, u32)>, l: Vec<Ipv6Addr>) {
        use rand::prelude::*;

        let mut table = IpLookupTable::new();
        let mut table1 = simple::IpLookupTable::new();
        for (a, l, v) in &v {
            assert_eq!(table.insert(*a, l.0, *v), table1.insert(*a, l.0, *v),);
        }

        let rlen = v.len() / 2;
        let (r, r1) = v.partial_shuffle(&mut thread_rng(), rlen);
        for (a, l, _) in r {
            assert_eq!(table.remove(*a, l.0), table1.remove(*a, l.0));
        }

        for a in l {
            assert_eq!(table.longest_match(a), table1.longest_match(a),);
        }

        for (a, l, _) in r1 {
            assert_eq!(table.remove(*a, l.0), table1.remove(*a, l.0));
        }
    }

    #[test]
    fn it_works() {
        let mut table = IpLookupTable::new();
        assert_eq!(table.insert(Ipv4Addr::new(10, 132, 179, 1), 24, 5), None);
        assert_eq!(table.insert(Ipv4Addr::new(10, 132, 179, 1), 32, 6), None);
        assert_eq!(table.insert(Ipv4Addr::new(0, 0, 0, 0), 0, 0), None);
        assert_eq!(table.insert(Ipv4Addr::new(0, 0, 0, 0), 0, 0), Some(0));
        assert_eq!(table.insert(Ipv4Addr::new(10, 132, 179, 1), 32, 6), Some(6));
        assert_eq!(table.insert(Ipv4Addr::new(10, 132, 179, 1), 24, 5), Some(5));

        assert_eq!(
            table.longest_match(Ipv4Addr::new(10, 132, 179, 1)),
            Some(&6)
        );
        assert_eq!(
            table.longest_match(Ipv4Addr::new(10, 132, 179, 2)),
            Some(&5)
        );
        assert_eq!(
            table.longest_match(Ipv4Addr::new(10, 132, 179, 255)),
            Some(&5)
        );
        assert_eq!(
            table.longest_match(Ipv4Addr::new(10, 132, 180, 1)),
            Some(&0)
        );
        assert_eq!(table.longest_match(Ipv4Addr::new(1, 1, 1, 1)), Some(&0));
        assert_eq!(
            table.longest_match(Ipv4Addr::new(255, 255, 255, 255)),
            Some(&0)
        );
    }

    #[test]
    fn it_works_v6() {
        let mut table = IpLookupTable::new();

        table.insert(Ipv6Addr::UNSPECIFIED, 0, 0);
        table.insert(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap(),
            64,
            1,
        );
        table.insert(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap(),
            128,
            2,
        );

        assert_eq!(
            table.longest_match("2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap()),
            Some(&2)
        );
        assert_eq!(
            table.longest_match("2001:0db8:85a3:0000:0001:8a2e:0370:7334".parse().unwrap()),
            Some(&1)
        );
        assert_eq!(
            table.longest_match("2002:0db8:85a3:0000:0001:8a2e:0370:7334".parse().unwrap()),
            Some(&0)
        );
    }
}