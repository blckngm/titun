// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

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

use packed_simd::{shuffle, u32x4, u8x16, IntoBits};
use ring::aead::*;
use std::convert::TryInto;

#[inline(always)]
fn rotate_left_16(use_byte_shuffle: bool, x: u32x4) -> u32x4 {
    if use_byte_shuffle {
        let x: u8x16 = x.into_bits();
        let x: u8x16 = shuffle!(x, [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]);
        x.into_bits()
    } else {
        use packed_simd::u16x8;
        let x: u16x8 = x.into_bits();
        let x: u16x8 = shuffle!(x, [1, 0, 3, 2, 5, 4, 7, 6]);
        x.into_bits()
    }
}

#[inline(always)]
fn rotate_left_8(use_byte_shuffle: bool, x: u32x4) -> u32x4 {
    if use_byte_shuffle {
        let x: u8x16 = x.into_bits();
        let x: u8x16 = shuffle!(x, [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]);
        x.into_bits()
    } else {
        x.rotate_left(u32x4::splat(8))
    }
}

#[inline(always)]
fn round(use_byte_shuffle: bool, state: &mut [u32x4; 4]) {
    state[0] += state[1];
    state[3] ^= state[0];
    state[3] = rotate_left_16(use_byte_shuffle, state[3]);

    state[2] += state[3];
    state[1] ^= state[2];
    state[1] = state[1].rotate_left(u32x4::splat(12));

    state[0] += state[1];
    state[3] ^= state[0];
    state[3] = rotate_left_8(use_byte_shuffle, state[3]);

    state[2] += state[3];
    state[1] ^= state[2];
    state[1] = state[1].rotate_left(u32x4::splat(7));
}

#[inline(always)]
fn shuffle(state: &mut [u32x4; 4]) {
    state[0] = shuffle!(state[0], [1, 2, 3, 0]);
    state[1] = shuffle!(state[1], [2, 3, 0, 1]);
    state[2] = shuffle!(state[2], [3, 0, 1, 2]);
}

#[inline(always)]
fn unshuffle(state: &mut [u32x4; 4]) {
    state[0] = shuffle!(state[0], [3, 0, 1, 2]);
    state[1] = shuffle!(state[1], [2, 3, 0, 1]);
    state[2] = shuffle!(state[2], [1, 2, 3, 0]);
}

#[inline(always)]
fn round_pair(use_byte_shuffle: bool, state: &mut [u32x4; 4]) {
    round(use_byte_shuffle, state);
    shuffle(state);
    round(use_byte_shuffle, state);
    unshuffle(state);
}

#[inline(always)]
fn hchacha_real(use_byte_shuffle: bool, key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state: [u32x4; 4] = [
        u32x4::new(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574),
        u32x4::from_le(u8x16::from_slice_unaligned(&key[..16]).into_bits()),
        u32x4::from_le(u8x16::from_slice_unaligned(&key[16..]).into_bits()),
        u32x4::from_le(u8x16::from_slice_unaligned(&nonce[..]).into_bits()),
    ];

    for _ in 0..10 {
        round_pair(use_byte_shuffle, &mut state);
    }

    let mut out = [0u8; 32];
    let s0: u8x16 = state[0].to_le().into_bits();
    s0.write_to_slice_unaligned(&mut out[..16]);
    let s3: u8x16 = state[3].to_le().into_bits();
    s3.write_to_slice_unaligned(&mut out[16..]);
    out
}

fn hchacha(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    use lazy_static::lazy_static;
    lazy_static! {
        static ref HCHACHA_IMPL: unsafe fn (key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] = {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if is_x86_feature_detected!("sse3") {
                    #[target_feature(enable = "sse3")]
                    unsafe fn hchacha_sse3(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
                        hchacha_real(true, key, nonce)
                    }
                    return hchacha_sse3;
                }
            }
            // TODO: ARM/AArch64 NOEN.
            fn hchacha_fallback(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
                hchacha_real(false, key, nonce)
            }
            hchacha_fallback
        };
    }
    unsafe { HCHACHA_IMPL(key, nonce) }
}

pub fn encrypt(key: &[u8], nonce: &[u8], ad: &[u8], p: &[u8], out: &mut [u8]) {
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);
    assert_eq!(p.len() + 16, out.len());

    let (hchacha_nonce, chacha_nonce) = nonce.split_at(16);
    let real_key = hchacha(key.try_into().unwrap(), hchacha_nonce.try_into().unwrap());
    let mut real_nonce = [0u8; 12];
    real_nonce[4..].copy_from_slice(chacha_nonce);

    let key = SealingKey::new(&CHACHA20_POLY1305, &real_key).unwrap();
    let aad = Aad::from(ad);
    let nonce = Nonce::assume_unique_for_key(real_nonce);

    seal(&key, nonce, aad, p, out).unwrap();
}

pub fn decrypt(key: &[u8], nonce: &[u8], ad: &[u8], c: &[u8], out: &mut [u8]) -> Result<(), ()> {
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);
    assert_eq!(out.len() + 16, c.len());

    let (hchacha_nonce, chacha_nonce) = nonce.split_at(16);
    let real_key = hchacha(key.try_into().unwrap(), hchacha_nonce.try_into().unwrap());
    let mut real_nonce = [0u8; 12];
    real_nonce[4..].copy_from_slice(chacha_nonce);

    let key = OpeningKey::new(&CHACHA20_POLY1305, &real_key).unwrap();
    let aad = Aad::from(ad);
    let nonce = Nonce::assume_unique_for_key(real_nonce);

    open(&key, nonce, aad, c, out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hchacha_vectors() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000090000004a0000000031415927").unwrap();
        let key = &key[..].try_into().unwrap();
        let nonce = &nonce[..].try_into().unwrap();
        let result = hchacha(key, nonce);
        assert_eq!(
            result,
            &hex::decode("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
                .unwrap()[..]
        );
    }

    #[test]
    fn xchacha20_poly1305_vectors() {
        let message = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let expected_encrypted = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49",
        )
        .unwrap();

        let mut encrypted = vec![0u8; message.len() + 16];
        encrypt(&key, &nonce, &aad, &message, &mut encrypted);
        assert_eq!(encrypted, expected_encrypted);

        let mut decrypted = vec![0u8; message.len()];
        assert!(decrypt(&key, &nonce, &aad, &encrypted, &mut decrypted).is_ok());
        assert_eq!(decrypted, message);
    }

    #[test]
    fn round_trip() {
        let k = [0u8; 32];
        let n = [1u8; 24];
        let ad = [2u8; 16];
        let data = [3u8; 16];
        let mut out = [0u8; 32];

        encrypt(&k, &n, &ad, &data, &mut out);
        let mut out1 = [0u8; 16];
        assert!(decrypt(&k, &n, &ad, &out, &mut out1).is_ok());
        out[0] = out[0].wrapping_add(1);
        assert!(decrypt(&k, &n, &ad, &out, &mut out1).is_err());
    }
}

#[cfg(all(feature = "bench", test))]
mod benches {
    use super::*;

    #[bench]
    fn hchacha(b: &mut crate::test::Bencher) {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000090000004a0000000031415927").unwrap();
        let key = &key[..].try_into().unwrap();
        let nonce = &nonce[..].try_into().unwrap();

        b.iter(|| super::hchacha(key, nonce));
    }

    #[bench]
    fn bench_encrypt(b: &mut crate::test::Bencher) {
        let k = [0u8; 32];
        let n = [1u8; 24];
        let ad = [2u8; 16];
        let data = [3u8; 16];
        let mut out = [0u8; 32];

        b.iter(|| {
            encrypt(&k, &n, &ad, &data, &mut out);
        });
    }
}
