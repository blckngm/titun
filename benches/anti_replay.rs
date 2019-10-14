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
