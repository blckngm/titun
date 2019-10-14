use criterion::{criterion_group, criterion_main, Criterion};
use titun::wireguard::load_monitor::LoadMonitor;

criterion_group!(benches, register_benches,);
criterion_main!(benches);

fn register_benches(c: &mut Criterion) {
    c.bench_function("load monitor check", |b| {
        let mut u = LoadMonitor::new(100);

        b.iter(|| u.check());
    });
}
