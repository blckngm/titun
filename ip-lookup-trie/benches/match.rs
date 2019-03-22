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

#![feature(test)]

extern crate test;
use crate::test::Bencher;

use ip_lookup_trie::IpLookupTable;
use std::net::Ipv4Addr;

#[bench]
fn bench_match(b: &mut Bencher) {
    let mut t = IpLookupTable::new();
    t.insert(Ipv4Addr::new(192, 168, 9, 233), 32, 99);
    t.insert(Ipv4Addr::new(192, 168, 9, 0), 24, 1);
    t.insert(Ipv4Addr::new(192, 168, 1, 0), 16, 2);
    t.insert(Ipv4Addr::new(10, 0, 77, 3), 8, 3);

    let a = Ipv4Addr::new(192, 168, 9, 233);

    b.iter(|| t.longest_match(a));
}
