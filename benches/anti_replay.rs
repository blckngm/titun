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

use criterion::{criterion_group, criterion_main, Criterion};
use titun::wireguard::anti_replay::AntiReplay;

criterion_group!(benches, register_benches,);
criterion_main!(benches);

fn register_benches(c: &mut Criterion) {
    c.bench_function("anti replay sequential", |b| {
        let mut ar = AntiReplay::new();
        let mut seq = 0;

        b.iter(|| {
            assert!(ar.check_and_update(seq));
            seq += 1;
        });
    });
    c.bench_function("anti replay old", |b| {
        let mut ar = AntiReplay::new();
        ar.check_and_update(12345);
        ar.check_and_update(11234);

        b.iter(|| {
            assert!(!ar.check_and_update(11234));
        });
    });
    c.bench_function("anti replay large skip", |b| {
        let mut ar = AntiReplay::new();
        let mut seq = 0;

        b.iter(|| {
            assert!(ar.check_and_update(seq));
            seq += 30000;
        });
    });
}
