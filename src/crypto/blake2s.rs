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

// Based on blake2-rfc:
//
// Copyright 2015 blake2-rfc Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::simd::u32x4;
use std::convert::TryInto;

pub const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

pub struct Blake2sResult {
    h: [u8; 32],
    nn: usize,
}

impl Blake2sResult {
    fn from_vecs(h: &[u32x4; 2], nn: usize) -> Self {
        let mut result = Self { h: [0u8; 32], nn };
        h[0].store_le((&mut result.h[0..16]).try_into().unwrap());
        h[1].store_le((&mut result.h[16..32]).try_into().unwrap());
        result
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.h[..self.nn]
    }

    // #[inline]
    // pub fn len(&self) -> usize {
    //     self.nn
    // }
}

impl AsRef<[u8]> for Blake2sResult {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Blake2s {
    m: [u32; 16],
    h: [u32x4; 2],
    t: u64,
    nn: usize,
}

#[inline(always)]
fn iv0() -> u32x4 {
    u32x4::new(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)
}

#[inline(always)]
fn iv1() -> u32x4 {
    u32x4::new(0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
}

#[inline(always)]
fn quarter_round(v: &mut [u32x4; 4], rd: u32, rb: u32, m: u32x4, bs: bool) {
    v[0] = v[0] + v[1] + m.from_le();
    v[3] = (v[3] ^ v[0]).rotate_right_const(rd, bs);
    v[2] = v[2] + v[3];
    v[1] = (v[1] ^ v[2]).rotate_right_const(rb, bs);
}

#[inline(always)]
fn shuffle(v: &mut [u32x4; 4]) {
    v[1] = v[1].shuffle_left(1);
    v[2] = v[2].shuffle_left(2);
    v[3] = v[3].shuffle_left(3);
}

#[inline(always)]
fn unshuffle(v: &mut [u32x4; 4]) {
    v[1] = v[1].shuffle_right(1);
    v[2] = v[2].shuffle_right(2);
    v[3] = v[3].shuffle_right(3);
}

#[inline(always)]
fn round(v: &mut [u32x4; 4], m: &[u32; 16], s: &[usize; 16], bs: bool) {
    quarter_round(v, 16, 12, u32x4::gather(m, s[0], s[2], s[4], s[6]), bs);
    quarter_round(v, 8, 7, u32x4::gather(m, s[1], s[3], s[5], s[7]), bs);
    shuffle(v);
    quarter_round(v, 16, 12, u32x4::gather(m, s[8], s[10], s[12], s[14]), bs);
    quarter_round(v, 8, 7, u32x4::gather(m, s[9], s[11], s[13], s[15]), bs);
    unshuffle(v);
}

pub fn blake2s(nn: usize, key: &[u8], data: &[u8]) -> Blake2sResult {
    Blake2s::with_key(nn, key).update(data).finalize()
}

impl Blake2s {
    #[inline]
    pub fn new(nn: usize) -> Self {
        Self::with_key(nn, &[])
    }

    pub fn with_key(nn: usize, k: &[u8]) -> Self {
        let kk = k.len();
        assert!(nn >= 1 && nn <= 32 && kk <= 32);

        let p0 = 0x01010000 ^ ((kk as u32) << 8) ^ (nn as u32);
        let mut state = Self {
            m: [0; 16],
            h: [iv0() ^ u32x4::new(p0, 0, 0, 0), iv1()],
            t: 0,
            nn: nn,
        };

        if kk > 0 {
            state.m_as_mut_bytes()[..k.len()].copy_from_slice(k);
            state.t = 32 * 2;
        }
        state
    }

    #[inline(always)]
    fn m_as_mut_bytes(&mut self) -> &mut [u8] {
        let m_as_u8: &mut [u8; 64] = unsafe { std::mem::transmute(&mut self.m) };
        m_as_u8
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let mut rest = data;

        let off = (self.t % (32 * 2)) as usize;
        if off != 0 || self.t == 0 {
            let len = std::cmp::min((32 * 2) - off, rest.len());

            let part = &rest[..len];
            rest = &rest[part.len()..];

            self.m_as_mut_bytes()[off..(off + part.len())].copy_from_slice(part);
            self.t = self
                .t
                .checked_add(part.len() as u64)
                .expect("hash data length overflow");
        }

        while rest.len() >= 32 * 2 {
            self.compress(0, 0);

            let part = &rest[..(32 * 2)];
            rest = &rest[part.len()..];

            self.m_as_mut_bytes()[..part.len()].copy_from_slice(part);
            self.t = self
                .t
                .checked_add(part.len() as u64)
                .expect("hash data length overflow");
        }

        if rest.len() > 0 {
            self.compress(0, 0);

            self.m_as_mut_bytes()[..rest.len()].copy_from_slice(rest);
            self.t = self
                .t
                .checked_add(rest.len() as u64)
                .expect("hash data length overflow");
        }

        self
    }

    fn compress(&mut self, f0: u32, f1: u32) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if is_x86_feature_detected!("ssse3") {
                unsafe {
                    return self.compress_ssse3(f0, f1);
                }
            }
        }
        self.compress_fallback(f0, f1);
    }

    fn compress_fallback(&mut self, f0: u32, f1: u32) {
        self.compress_real(f0, f1, false);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "ssse3")]
    unsafe fn compress_ssse3(&mut self, f0: u32, f1: u32) {
        self.compress_real(f0, f1, true);
    }

    #[inline(always)]
    fn compress_real(&mut self, f0: u32, f1: u32, use_byte_shuffle: bool) {
        let m = &self.m;
        let h = &mut self.h;

        let t0 = self.t as u32;
        let t1 = (self.t >> 32) as u32;

        let mut v = [h[0], h[1], iv0(), iv1() ^ u32x4::new(t0, t1, f0, f1)];

        round(&mut v, m, &SIGMA[0], use_byte_shuffle);
        round(&mut v, m, &SIGMA[1], use_byte_shuffle);
        round(&mut v, m, &SIGMA[2], use_byte_shuffle);
        round(&mut v, m, &SIGMA[3], use_byte_shuffle);
        round(&mut v, m, &SIGMA[4], use_byte_shuffle);
        round(&mut v, m, &SIGMA[5], use_byte_shuffle);
        round(&mut v, m, &SIGMA[6], use_byte_shuffle);
        round(&mut v, m, &SIGMA[7], use_byte_shuffle);
        round(&mut v, m, &SIGMA[8], use_byte_shuffle);
        round(&mut v, m, &SIGMA[9], use_byte_shuffle);

        h[0] = h[0] ^ (v[0] ^ v[2]);
        h[1] = h[1] ^ (v[1] ^ v[3]);
    }

    fn finalize_with_flag(&mut self, flag: u32) {
        let off = (self.t % 64) as usize;
        if off != 0 {
            for b in &mut self.m_as_mut_bytes()[off..] {
                *b = 0;
            }
        }
        self.compress(!0, flag);
    }

    fn get_result(&self) -> Blake2sResult {
        Blake2sResult::from_vecs(&self.h, self.nn)
    }

    #[inline]
    pub fn finalize(&mut self) -> Blake2sResult {
        self.finalize_with_flag(0);
        self.get_result()
    }
}

#[cfg(test)]
mod test {
    use super::Blake2s;

    #[test]
    fn vector_0() {
        let input = hex::decode("").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let expected =
            hex::decode("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
                .unwrap();

        let result = Blake2s::with_key(32, &key).update(&input).finalize();
        assert_eq!(expected, result.as_bytes());
    }

    #[test]
    fn vector_1() {
        let input = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let expected =
            hex::decode("2afdf3c82abc4867f5de111286c2b3be7d6e48657ba923cfbf101a6dfcf9db9a")
                .unwrap();

        let result = Blake2s::with_key(32, &key).update(&input).finalize();
        assert_eq!(expected, result.as_bytes());
    }

    #[test]
    fn vector_1_split() {
        let input0 = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1").unwrap();
        let input1 = hex::decode("c2c3c4c5c6c7c8c9cacbcccdcecfd0d1").unwrap();
        let input2 =
            hex::decode("d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let expected =
            hex::decode("2afdf3c82abc4867f5de111286c2b3be7d6e48657ba923cfbf101a6dfcf9db9a")
                .unwrap();
        let result = Blake2s::with_key(32, &key)
            .update(&input0)
            .update(&input1)
            .update(&input2)
            .finalize();
        assert_eq!(expected, result.as_bytes());
    }
}

#[cfg(all(feature = "bench", test))]
mod benches {
    use super::Blake2s;
    use rand::prelude::*;

    #[bench]
    fn blake2s(b: &mut crate::test::Bencher) {
        let mut input = [0u8; 16];
        thread_rng().fill_bytes(&mut input);

        b.bytes = 16;

        b.iter(|| Blake2s::new(32).update(&input).finalize());
    }
}
