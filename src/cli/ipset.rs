// Copyright 2021 Guanhao Yin <sopium@mysterious.site>

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

use std::{
    fmt::{self},
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use num_traits::{PrimInt, Unsigned};

use crate::utils::{bit_len, common_prefix_len, next_bit_mask1, to_mask};

/// Patricia trie for CIDR sets. This is different from the IP lookup trie
/// because it automatically splits and merges CIDRs.
///
/// Leaf nodes represent set members.
#[derive(PartialEq, Eq, Clone)]
struct TrieNode<K, KDebug> {
    k: K,
    len: u32,
    left: Option<Box<TrieNode<K, KDebug>>>,
    right: Option<Box<TrieNode<K, KDebug>>>,
    phantom_debug: PhantomData<KDebug>,
}

impl<K: Copy, KDebug: From<K> + fmt::Debug> fmt::Debug for TrieNode<K, KDebug> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TrieNode")
            .field("k", &KDebug::from(self.k))
            .field("len", &self.len)
            .field("left", &self.left)
            .field("right", &self.right)
            .finish()
    }
}

struct TrieIter<K, KDebug> {
    stack: Vec<TrieNode<K, KDebug>>,
}

impl<K, KDebug> TrieIter<K, KDebug> {
    fn new(root: Option<Box<TrieNode<K, KDebug>>>) -> Self {
        Self {
            stack: root.map(|n| *n).into_iter().collect(),
        }
    }
}

impl<K, KDebug> Iterator for TrieIter<K, KDebug> {
    type Item = (K, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(n) = self.stack.pop() {
            if n.is_leaf() {
                Some((n.k, n.len))
            } else {
                if let Some(n) = n.right {
                    self.stack.push(*n);
                }
                if let Some(n) = n.left {
                    self.stack.push(*n);
                }
                self.next()
            }
        } else {
            None
        }
    }
}

impl<K, KDebug> TrieNode<K, KDebug> {
    fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }
}

impl<K, KDebug> TrieNode<K, KDebug>
where
    K: Unsigned + PrimInt,
    KDebug: From<K> + fmt::Debug,
{
    fn new(k: K, len: u32) -> Self {
        Self {
            k: k & to_mask(len),
            len,
            left: None,
            right: None,
            phantom_debug: PhantomData,
        }
    }

    fn maybe_merge(&mut self) {
        if let (Some(l), Some(r)) = (self.left.as_deref(), self.right.as_deref()) {
            if l.is_leaf() && r.is_leaf() && l.len == r.len && l.len == self.len + 1 {
                self.left = None;
                self.right = None;
            }
        }
    }

    fn insert_option(this: &mut Option<Box<Self>>, k: K, k_len: u32) {
        assert!(k_len <= bit_len::<K>());

        if let Some(this) = this {
            this.insert(k, k_len);
        } else {
            *this = Some(Box::new(TrieNode::new(k, k_len)));
        }
    }

    fn insert(&mut self, k: K, k_len: u32) {
        let self_mask: K = to_mask(self.len);
        if self.len == k_len && self.k & self_mask == k & self_mask {
            // Self node is equal to k/k_len, just make it a leaf node.
            self.left = None;
            self.right = None;
            return;
        }
        if k_len > self.len && (k & self_mask == self.k & self_mask) {
            if self.is_leaf() {
                // Self contains k/k_len and is a leaf node, nothing to do.
                return;
            }
            // Otherwise, insert to a child node.
            let next_bit_mask = next_bit_mask1(self.len);
            let next_bit_set = (k & next_bit_mask) != K::zero();
            let to_insert = if next_bit_set {
                &mut self.right
            } else {
                &mut self.left
            };
            Self::insert_option(to_insert, k, k_len);
            self.maybe_merge();
            return;
        }

        let k_mask = to_mask(k_len);
        if k_len < self.len && k & k_mask == self.k & k_mask {
            // k/k_len contains self, replace self with k/k_len.
            *self = TrieNode::new(k, k_len);
            return;
        }

        let common_prefix_len = common_prefix_len(self.k, self.len, k, k_len);

        if Some(common_prefix_len) == self.len.checked_sub(1) && self.is_leaf() && self.len == k_len
        {
            // Self is merged with k.
            *self = TrieNode::new(k, common_prefix_len);
            return;
        }

        // Split:
        //
        // Create new node, make self and the inserted node as children of the new node.

        let new_node = TrieNode::new(self.k, common_prefix_len);
        let old_self = std::mem::replace(self, new_node);

        let next_bit_mask = next_bit_mask1(common_prefix_len);
        let old_self_next_bit_is_set = (old_self.k & next_bit_mask) != K::zero();

        if old_self_next_bit_is_set {
            self.right = Some(Box::new(old_self));
            self.left = Some(Box::new(TrieNode::new(k, k_len)));
        } else {
            self.left = Some(Box::new(old_self));
            self.right = Some(Box::new(TrieNode::new(k, k_len)));
        }
    }

    fn remove(mut self: Box<Self>, k: K, k_len: u32) -> Option<Box<Self>> {
        assert!(k_len <= bit_len::<K>());

        let mask = to_mask(k_len);
        if self.len >= k_len && self.k & mask == k & mask {
            // Matches this node. Just remove it.
            return None;
        }

        let self_mask = to_mask(self.len);
        if k_len <= self.len || k & self_mask != self.k & self_mask {
            // Nothing to remove here.
            return Some(self);
        }

        let next_bit_mask = next_bit_mask1(self.len);
        let nb_set = (k & next_bit_mask) != K::zero();

        if self.is_leaf() {
            // Split this node and remove from a child.
            self.left = Some(Box::new(TrieNode::new(self.k, self.len + 1)));
            self.right = Some(Box::new(TrieNode::new(
                self.k | next_bit_mask,
                self.len + 1,
            )));
        }
        // Remove from child node.
        let (to_remove, the_other) = if nb_set {
            (&mut self.right, &mut self.left)
        } else {
            (&mut self.left, &mut self.right)
        };
        if let Some(n) = to_remove.take() {
            let n = n.remove(k, k_len);
            if n.is_none() {
                return the_other.take();
            }
            *to_remove = n;
        }

        Some(self)
    }

    fn contains(&self, k: K) -> bool {
        if self.is_leaf() {
            let self_mask = to_mask(self.len);
            self.k & self_mask == k & self_mask
        } else {
            let nbm = next_bit_mask1(self.len);
            let nb = (k & nbm) != K::zero();
            if nb {
                self.right.as_ref()
            } else {
                self.left.as_ref()
            }
            .map_or(false, |n| n.contains(k))
        }
    }

    #[cfg(test)]
    fn self_check(&self) -> Result<(), String> {
        if self.len > bit_len::<K>() {
            return Err(format!("Invalid len: {}", self.len));
        }

        if self.k & to_mask(self.len) != self.k {
            return Err(format!(
                "Unmasked k: {:?}, len {}",
                KDebug::from(self.k),
                self.len
            ));
        }

        if self.left.is_some() && self.right.is_none()
            || self.left.is_none() && self.right.is_some()
        {
            return Err("only have one child, should be merged".into());
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
                "parent_k {:?} is not a prefix of self.k {:?}",
                KDebug::from(parent_k),
                KDebug::from(self.k),
            ));
        }
        self.self_check()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpSet {
    trie4: Option<Box<TrieNode<u32, Ipv4Addr>>>,
    trie6: Option<Box<TrieNode<u128, Ipv6Addr>>>,
}

impl Default for IpSet {
    fn default() -> Self {
        Self::new()
    }
}

impl IpSet {
    pub fn new() -> Self {
        IpSet {
            trie4: None,
            trie6: None,
        }
    }

    // XXX: What about v4-mapped and v4-compatible IPv6 addresses?

    pub fn insert(&mut self, ip: IpAddr, prefix_len: u32) {
        match ip {
            IpAddr::V4(ip) => {
                TrieNode::insert_option(&mut self.trie4, ip.into(), prefix_len);
            }
            IpAddr::V6(ip) => {
                TrieNode::insert_option(&mut self.trie6, ip.into(), prefix_len);
            }
        }
    }

    pub fn remove(&mut self, ip: IpAddr, prefix_len: u32) {
        match ip {
            IpAddr::V4(ip) => {
                if let Some(n) = self.trie4.take() {
                    self.trie4 = n.remove(ip.into(), prefix_len);
                }
            }
            IpAddr::V6(ip) => {
                if let Some(n) = self.trie6.take() {
                    self.trie6 = n.remove(ip.into(), prefix_len);
                }
            }
        }
    }

    #[allow(unused)]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.trie4.as_ref().map_or(false, |n| n.contains(ip.into())),
            IpAddr::V6(ip) => self.trie6.as_ref().map_or(false, |n| n.contains(ip.into())),
        }
    }
}

impl IntoIterator for IpSet {
    type Item = (IpAddr, u32);
    type IntoIter = IpSetIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IpSetIntoIter {
            trie4_iter: TrieIter::new(self.trie4),
            trie6_iter: TrieIter::new(self.trie6),
        }
    }
}

pub struct IpSetIntoIter {
    trie4_iter: TrieIter<u32, Ipv4Addr>,
    trie6_iter: TrieIter<u128, Ipv6Addr>,
}

impl Iterator for IpSetIntoIter {
    type Item = (IpAddr, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((ip, l)) = self.trie4_iter.next() {
            return Some((Ipv4Addr::from(ip).into(), l));
        }
        if let Some((ip, l)) = self.trie6_iter.next() {
            return Some((Ipv6Addr::from(ip).into(), l));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use quickcheck_macros::quickcheck;
    use std::net::Ipv4Addr;

    #[test]
    fn it_works() {
        let mut set = IpSet::new();

        for i in 0..=255 {
            set.insert(Ipv4Addr::new(192, 168, 1, i).into(), 32);
            set.trie4.as_ref().unwrap().self_check().unwrap();
            assert!(set.contains(Ipv4Addr::new(192, 168, 1, i).into()));
        }
        for i in 0..=255 {
            set.insert(Ipv4Addr::new(192, 168, 0, i).into(), 32);
            set.trie4.as_ref().unwrap().self_check().unwrap();
            assert!(set.contains(Ipv4Addr::new(192, 168, 0, i).into()));
        }
        assert_eq!(
            set,
            IpSet {
                trie4: Some(Box::new(TrieNode::new(
                    Ipv4Addr::new(192, 168, 0, 0).into(),
                    23
                ))),
                trie6: None,
            }
        );

        set.insert(Ipv4Addr::new(192, 167, 0, 0).into(), 16);

        assert_eq!(
            "192.167.0.0/16, 192.168.0.0/23",
            set.clone()
                .into_iter()
                .format_with(", ", |(ip, len), f| f(&format_args!("{}/{}", ip, len)))
                .to_string()
        );

        set.remove(Ipv4Addr::new(192, 168, 0, 0).into(), 23);
        assert_eq!(
            set,
            IpSet {
                trie4: Some(Box::new(TrieNode::new(
                    Ipv4Addr::new(192, 167, 0, 0).into(),
                    16
                ))),
                trie6: None,
            }
        );

        set.remove(Ipv4Addr::from(0).into(), 0);
        assert_eq!(set.trie4, None);
    }

    #[derive(Copy, Clone, Debug)]
    struct Len(u32);

    impl quickcheck::Arbitrary for Len {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Len(u32::arbitrary(g) % 33)
        }
    }

    #[quickcheck]
    fn qc_ipset(inserts: Vec<(Ipv4Addr, Len)>, removes: Vec<(Ipv4Addr, Len)>) {
        let mut set = IpSet::new();
        for (ip, l) in inserts.iter().copied() {
            set.insert(ip.into(), l.0);
            set.trie4.as_ref().unwrap().self_check().unwrap();
            assert!(set.contains(ip.into()));
        }
        for (ip, _) in inserts {
            assert!(set.contains(ip.into()));
        }
        for (ip, l) in removes {
            set.remove(ip.into(), l.0);
            if let Some(ref trie4) = set.trie4 {
                trie4.self_check().unwrap();
            }
            assert!(!set.contains(ip.into()));
        }
    }

    #[quickcheck]
    fn qc_ipset_law(inserts: Vec<(Ipv4Addr, Len)>, a: (Ipv4Addr, Len)) {
        let mut set = IpSet::new();
        for (ip, l) in inserts {
            set.insert(ip.into(), l.0);
        }

        let set0 = set.clone();

        // (S + a) - a == S - a

        let mut set1 = set0.clone();

        set.insert(a.0.into(), a.1 .0);
        set.remove(a.0.into(), a.1 .0);

        set1.remove(a.0.into(), a.1 .0);

        assert_eq!(set1, set);

        // (S - a) + a == S + a

        let mut set2 = set0.clone();
        let mut set = set0;

        set.remove(a.0.into(), a.1 .0);
        set.insert(a.0.into(), a.1 .0);

        set2.insert(a.0.into(), a.1 .0);

        assert_eq!(set2, set);
    }
}
