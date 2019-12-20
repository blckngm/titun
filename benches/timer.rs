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

use criterion::Criterion;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::Arc;
use std::time::Duration;
use titun::wireguard::timer::create_timer_async;

pub fn register_benches(c: &mut Criterion) {
    c.bench_function("timer adjust and activate", |b| {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let run = Arc::new(AtomicBool::new(false));
            let t = create_timer_async(move || {
                run.store(true, SeqCst);
                async {}
            });

            b.iter(|| {
                t.adjust_and_activate(Duration::from_secs(10));
            });
        });
    });
}
