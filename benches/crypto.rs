use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::{rngs::OsRng, RngCore};
use std::convert::TryInto;
use titun::crypto;
use titun::wireguard::re_exports::*;

criterion_group!(benches, register_benches);
criterion_main!(benches);

fn register_benches(c: &mut Criterion) {
    c.bench_function("hchacha", |b| {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000090000004a0000000031415927").unwrap();
        let key = &key[..].try_into().unwrap();
        let nonce = &nonce[..].try_into().unwrap();

        b.iter(|| crypto::xchacha20poly1305::hchacha(key, nonce));
    });

    c.bench_function("XChaCha20Poly1305 encrypt", |b| {
        let k = [0u8; 32];
        let n = [1u8; 24];
        let ad = [2u8; 16];
        let data = [3u8; 16];
        let mut out = [0u8; 32];

        b.iter(|| {
            crypto::xchacha20poly1305::encrypt(&k, &n, &ad, &data, &mut out);
        });
    });

    const MSG_LEN: usize = 1400;
    let mut group = c.benchmark_group("ChaCha20Poly1305 throughput");
    group.throughput(Throughput::Bytes(MSG_LEN as u64));
    group.bench_function("ChaCha20Poly1305 encrypt", |b| {
        let mut rng = OsRng;

        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let key = Sensitive::from_slice(&key);
        let mut data = [0u8; MSG_LEN];
        rng.fill_bytes(&mut data);
        let mut nonce = 0;
        let mut out = [0u8; MSG_LEN + 16];

        b.iter(|| {
            ChaCha20Poly1305::encrypt(&key, nonce, &[], &data, &mut out);
            nonce = nonce + 1;
        })
    });
    group.finish();
}
