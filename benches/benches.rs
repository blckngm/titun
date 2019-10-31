// Copyright 2019 Yin Guanhao <sopium@mysterious.site>

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

mod anti_replay;
mod crypto;
mod handshake;
mod ip_lookup_trie;
mod load_monitor;
mod timer;

use criterion::{criterion_group, criterion_main, Criterion};

criterion_group!(benches, register_benches);
criterion_main!(benches);

fn register_benches(c: &mut Criterion) {
    anti_replay::register_benches(c);
    crypto::register_benches(c);
    handshake::register_benches(c);
    ip_lookup_trie::register_benches(c);
    load_monitor::register_benches(c);
    timer::register_benches(c);
}
