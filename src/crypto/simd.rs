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

//! Portable SIMD vectors that works on stable rust and
//! works with runtime CPU feature detection.

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
mod simd_x86 {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    #[repr(transparent)]
    #[allow(non_camel_case_types)]
    #[derive(Copy, Clone)]
    pub struct u32x4(__m128i);

    pub trait Machine: Copy {
        fn has_ssse3(&self) -> bool {
            false
        }
        fn has_sse41(&self) -> bool {
            false
        }
    }

    pub type BaselineMachine = SSE2Machine;

    #[derive(Copy, Clone)]
    pub struct SSE2Machine;

    impl SSE2Machine {
        pub fn new() -> Self {
            Self
        }
    }

    impl Machine for SSE2Machine {}

    #[derive(Copy, Clone)]
    pub struct SSSE3Machine;

    impl SSSE3Machine {
        pub unsafe fn new() -> Self {
            Self
        }
    }

    impl Machine for SSSE3Machine {
        fn has_ssse3(&self) -> bool {
            true
        }
    }

    #[derive(Copy, Clone)]
    pub struct SSE41Machine;

    impl SSE41Machine {
        pub unsafe fn new() -> Self {
            Self
        }
    }

    impl Machine for SSE41Machine {
        fn has_ssse3(&self) -> bool {
            true
        }

        fn has_sse41(&self) -> bool {
            true
        }
    }

    impl std::fmt::Debug for u32x4 {
        #[allow(clippy::many_single_char_names)]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            let mut x = [0u32; 4];
            unsafe {
                // Clippy: This is unaligned store, so casting to more aligned pointer is fine.
                #[allow(clippy::cast_ptr_alignment)]
                _mm_storeu_si128(&mut x as *mut _ as *mut _, self.0);
            }
            let [a, b, c, d] = x;
            write!(f, "(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x})", a, b, c, d)?;
            Ok(())
        }
    }

    macro_rules! shuffle16 {
        ($v:expr, [
            $x0:literal, $x1:literal, $x2:literal, $x3:literal,
            $x4:literal, $x5:literal, $x6:literal, $x7:literal,
            $x8:literal, $x9:literal, $x10:literal, $x11:literal,
            $x12:literal, $x13:literal, $x14:literal, $x15:literal
        ]) => {{
            let s = _mm_set_epi8(
                $x15, $x14, $x13, $x12, $x11, $x10, $x9, $x8, $x7, $x6, $x5, $x4, $x3, $x2, $x1,
                $x0,
            );
            _mm_shuffle_epi8($v, s)
        }};
    }

    #[allow(non_snake_case)]
    const fn _MM_SHUFFLE_REV(w: u32, x: u32, y: u32, z: u32) -> i32 {
        ((z << 6) | (y << 4) | (x << 2) | w) as i32
    }

    impl u32x4 {
        #[inline(always)]
        pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
            // Reversed.
            unsafe { Self(_mm_setr_epi32(a as i32, b as i32, c as i32, d as i32)) }
        }

        #[inline(always)]
        pub fn load_le(addr: &[u8; 16]) -> Self {
            // Clippy: This is unaligned load, so casting to more aligned pointer is fine.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                Self(_mm_loadu_si128(addr as *const u8 as *const _))
            }
        }

        #[inline(always)]
        pub fn store_le(self, addr: &mut [u8; 16]) {
            // Clippy: This is unaligned store, so casting to more aligned pointer is fine.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                _mm_storeu_si128(addr as *mut _ as *mut _, self.0);
            }
        }

        #[inline(always)]
        pub fn gather<M: Machine>(
            src: &[u32x4; 4],
            i0: usize,
            i1: usize,
            i2: usize,
            i3: usize,
            m: M,
        ) -> Self {
            if m.has_sse41() {
                // Make LLVM generate efficient loads and shuffles.
                macro_rules! get {
                    ($i:expr) => {{
                        let a = $i / 4;
                        let b = $i % 4;
                        let r = match b {
                            0 => _mm_extract_epi32(src[a].0, 0),
                            1 => _mm_extract_epi32(src[a].0, 1),
                            2 => _mm_extract_epi32(src[a].0, 2),
                            3 => _mm_extract_epi32(src[a].0, 3),
                            _ => unreachable!(),
                        };
                        r as u32
                    }};
                }
                unsafe { u32x4::new(get!(i0), get!(i1), get!(i2), get!(i3)) }
            } else {
                unsafe {
                    let src: &[u32; 16] = &*(src as *const _ as *const [u32; 16]);
                    u32x4::new(src[i0], src[i1], src[i2], src[i3])
                }
            }
        }

        #[inline(always)]
        pub fn from_le(x: Self) -> Self {
            x
        }

        /// # Safety
        ///
        /// `use_byte_shuffle` should be set only when PSHUFB is available. (SSSE3+).
        #[inline(always)]
        pub fn rotate_left_const<M: Machine>(self, amt: u32, m: M) -> Self {
            match amt {
                16 => self.rotate_left_16(m),
                8 => self.rotate_left_8(m),
                24 => self.rotate_left_24(m),
                x => self.rotate_left_any(x),
            }
        }

        #[inline(always)]
        pub fn rotate_right_const<M: Machine>(self, amt: u32, m: M) -> Self {
            self.rotate_left_const(32 - amt, m)
        }

        #[inline(always)]
        fn rotate_left_16<M: Machine>(self, m: M) -> Self {
            unsafe {
                if m.has_ssse3() {
                    Self(shuffle16!(
                        self.0,
                        [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]
                    ))
                } else {
                    Self(_mm_shufflelo_epi16(
                        _mm_shufflehi_epi16(self.0, 0b10_11_00_01),
                        0b10_11_00_01,
                    ))
                }
            }
        }

        #[inline(always)]
        fn rotate_left_any(self, amt: u32) -> Self {
            // It must be a constant, so use a macro.
            macro_rules! r {
                ($amt:literal) => {{
                    let a = _mm_slli_epi32(self.0, $amt);
                    let b = _mm_srli_epi32(self.0, 32 - $amt);
                    Self(a) | Self(b)
                }};
            }
            unsafe {
                match amt {
                    0 => self,
                    1 => r!(1),
                    2 => r!(2),
                    3 => r!(3),
                    4 => r!(4),
                    5 => r!(5),
                    6 => r!(6),
                    7 => r!(7),
                    8 => r!(8),
                    9 => r!(9),
                    10 => r!(10),
                    11 => r!(11),
                    12 => r!(12),
                    13 => r!(13),
                    14 => r!(14),
                    15 => r!(15),
                    16 => r!(16),
                    17 => r!(17),
                    18 => r!(18),
                    19 => r!(19),
                    20 => r!(20),
                    21 => r!(21),
                    22 => r!(22),
                    23 => r!(23),
                    24 => r!(24),
                    25 => r!(25),
                    26 => r!(26),
                    27 => r!(27),
                    28 => r!(28),
                    29 => r!(29),
                    30 => r!(30),
                    31 => r!(31),
                    _ => unreachable!(),
                }
            }
        }

        #[inline(always)]
        fn rotate_left_8<M: Machine>(self, m: M) -> Self {
            unsafe {
                if m.has_ssse3() {
                    Self(shuffle16!(
                        self.0,
                        [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]
                    ))
                } else {
                    self.rotate_left_any(8)
                }
            }
        }

        #[inline(always)]
        fn rotate_left_24<M: Machine>(self, m: M) -> Self {
            unsafe {
                if m.has_ssse3() {
                    Self(shuffle16!(
                        self.0,
                        [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]
                    ))
                } else {
                    self.rotate_left_any(24)
                }
            }
        }

        #[inline(always)]
        pub fn shuffle_left(self, amt: u32) -> Self {
            unsafe {
                match amt {
                    1 => Self(_mm_shuffle_epi32(self.0, _MM_SHUFFLE_REV(1, 2, 3, 0))),
                    2 => Self(_mm_shuffle_epi32(self.0, _MM_SHUFFLE_REV(2, 3, 0, 1))),
                    3 => Self(_mm_shuffle_epi32(self.0, _MM_SHUFFLE_REV(3, 0, 1, 2))),
                    _ => unreachable!(),
                }
            }
        }

        #[inline(always)]
        pub fn shuffle_right(self, amt: u32) -> Self {
            self.shuffle_left(4 - amt)
        }
    }

    impl std::ops::Add<u32x4> for u32x4 {
        type Output = u32x4;

        #[inline(always)]
        fn add(self, other: u32x4) -> u32x4 {
            unsafe { Self(_mm_add_epi32(self.0, other.0)) }
        }
    }

    impl std::ops::AddAssign<u32x4> for u32x4 {
        #[inline(always)]
        fn add_assign(&mut self, other: u32x4) {
            *self = (*self) + other
        }
    }

    impl std::ops::BitXor<u32x4> for u32x4 {
        type Output = u32x4;
        #[inline(always)]
        fn bitxor(self, other: u32x4) -> u32x4 {
            unsafe { Self(_mm_xor_si128(self.0, other.0)) }
        }
    }

    impl std::ops::BitXorAssign<u32x4> for u32x4 {
        #[inline(always)]
        fn bitxor_assign(&mut self, other: u32x4) {
            *self = (*self) ^ other
        }
    }

    impl std::ops::BitOr<u32x4> for u32x4 {
        type Output = u32x4;
        #[inline(always)]
        fn bitor(self, other: u32x4) -> u32x4 {
            unsafe { Self(_mm_or_si128(self.0, other.0)) }
        }
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
mod simd_fallback {
    pub trait Machine: Copy {}

    #[derive(Copy, Clone)]
    pub struct BaselineMachine;

    impl BaselineMachine {
        pub fn new() -> Self {
            Self
        }
    }

    impl Machine for BaselineMachine {}

    #[repr(transparent)]
    #[allow(non_camel_case_types)]
    #[derive(Copy, Clone)]
    pub struct u32x4(packed_simd::u32x4);

    impl std::fmt::Debug for u32x4 {
        #[allow(clippy::many_single_char_names)]
        fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            let mut arr = [0u32; 4];
            self.0.write_to_slice_unaligned(&mut arr);
            let [a, b, c, d] = arr;
            write!(f, "(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x})", a, b, c, d)?;
            Ok(())
        }
    }

    impl u32x4 {
        #[inline(always)]
        pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
            u32x4(packed_simd::u32x4::new(a, b, c, d))
        }

        #[inline(always)]
        pub fn load_le(addr: &[u8; 16]) -> Self {
            use packed_simd::IntoBits;
            let v = packed_simd::u8x16::from_slice_unaligned(addr).into_bits();
            u32x4(packed_simd::u32x4::from_le(v))
        }

        #[inline(always)]
        pub fn store_le(self, addr: &mut [u8; 16]) {
            use packed_simd::IntoBits;

            let v: packed_simd::u8x16 = self.0.to_le().into_bits();
            v.write_to_slice_unaligned(addr);
        }

        #[inline(always)]
        pub fn gather<M>(
            src: &[u32x4; 4],
            i0: usize,
            i1: usize,
            i2: usize,
            i3: usize,
            _: M,
        ) -> Self {
            unsafe {
                let src: &[u32; 16] = std::mem::transmute(src);
                u32x4::new(src[i0], src[i1], src[i2], src[i3])
            }
        }

        #[inline(always)]
        pub fn from_le(x: Self) -> Self {
            u32x4(packed_simd::u32x4::from_le(x.0))
        }

        #[inline(always)]
        pub fn rotate_left_const<M>(self, amt: u32, _: M) -> Self {
            u32x4(self.0.rotate_left(packed_simd::u32x4::splat(amt)))
        }

        #[inline(always)]
        pub fn rotate_right_const<M>(self, amt: u32, _: M) -> Self {
            u32x4(self.0.rotate_right(packed_simd::u32x4::splat(amt)))
        }

        #[inline(always)]
        pub fn shuffle_left(self, amt: u32) -> Self {
            use packed_simd::shuffle;
            match amt {
                1 => u32x4(shuffle!(self.0, [1, 2, 3, 0])),
                2 => u32x4(shuffle!(self.0, [2, 3, 0, 1])),
                3 => u32x4(shuffle!(self.0, [3, 0, 1, 2])),
                _ => unreachable!(),
            }
        }

        #[inline(always)]
        pub fn shuffle_right(self, amt: u32) -> Self {
            self.shuffle_left(4 - amt)
        }
    }

    impl std::ops::Add<u32x4> for u32x4 {
        type Output = u32x4;

        #[inline(always)]
        fn add(self, other: u32x4) -> u32x4 {
            u32x4(self.0 + other.0)
        }
    }

    impl std::ops::AddAssign<u32x4> for u32x4 {
        #[inline(always)]
        fn add_assign(&mut self, other: u32x4) {
            *self = (*self) + other
        }
    }

    impl std::ops::BitXor<u32x4> for u32x4 {
        type Output = u32x4;
        #[inline(always)]
        fn bitxor(self, other: u32x4) -> u32x4 {
            u32x4(self.0 ^ other.0)
        }
    }

    impl std::ops::BitXorAssign<u32x4> for u32x4 {
        #[inline(always)]
        fn bitxor_assign(&mut self, other: u32x4) {
            *self = (*self) ^ other
        }
    }

    impl std::ops::BitOr<u32x4> for u32x4 {
        type Output = u32x4;
        #[inline(always)]
        fn bitor(self, other: u32x4) -> u32x4 {
            u32x4(self.0 | other.0)
        }
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub use simd_fallback::*;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use simd_x86::*;
