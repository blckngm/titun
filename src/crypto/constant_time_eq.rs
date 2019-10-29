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

// Based on https://github.com/cesarb/constant_time_eq
// Which is licensed under CC0.

// This function is non-inline to prevent the optimizer from looking inside it.
#[cfg(not(target_feature = "sse2"))]
#[inline(never)]
fn constant_time_ne_16(a: &[u8; 16], b: &[u8; 16]) -> u8 {
    let mut tmp = 0;
    for i in 0..16 {
        tmp |= a[i] ^ b[i];
    }
    tmp // The compare with 0 must happen outside this function.
}

#[cfg(target_feature = "sse2")]
#[inline]
pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    // Clippy: These are unaligned loads, so casting to more aligned pointer is fine.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let a = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let b = _mm_loadu_si128(b.as_ptr() as *const __m128i);
        _mm_movemask_epi8(_mm_cmpeq_epi8(a, b)) == 0xffff
    }
}

#[cfg(not(target_feature = "sse2"))]
#[inline]
pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    constant_time_ne_16(a, b) == 0
}

#[cfg(test)]
#[test]
fn test_constant_time_eq_16() {
    use rand::prelude::*;

    let mut a = [0u8; 16];
    thread_rng().fill_bytes(&mut a);
    let b = a;

    assert!(constant_time_eq_16(&a, &b));

    for i in 0..16 {
        let mut c = b;
        c[i] = c[i].wrapping_add(1);
        assert!(!constant_time_eq_16(&a, &c));
    }
}
