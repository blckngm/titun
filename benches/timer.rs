use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::Arc;
use std::time::Duration;
use titun::wireguard::timer::create_timer_async;

criterion_group!(benches, register_benches,);
criterion_main!(benches);

fn register_benches(c: &mut Criterion) {
    c.bench_function("timer adjust and activate", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let run = Arc::new(AtomicBool::new(false));
            let t = {
                let run = run.clone();
                create_timer_async(move || {
                    run.store(true, SeqCst);
                    async { () }
                })
            };

            b.iter(|| {
                t.adjust_and_activate(Duration::from_secs(10));
            });
        });
    });
}
