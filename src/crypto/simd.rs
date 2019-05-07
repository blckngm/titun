#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
mod simd_impl {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    #[repr(transparent)]
    #[allow(non_camel_case_types)]
    #[derive(Copy, Clone)]
    pub struct u32x4(__m128i);

    impl std::fmt::Debug for u32x4 {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            let mut x = [0u32; 4];
            unsafe {
                _mm_storeu_si128(&mut x as *mut _ as *mut _, self.0);
            }
            let [a, b, c, d] = x;
            write!(f, "(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x})", a, b, c, d)?;
            Ok(())
        }
    }

    // Note that arguments order is reversed.
    #[allow(non_snake_case)]
    const fn _MM_SHUFFLE(w: u32, x: u32, y: u32, z: u32) -> i32 {
        ((z << 6) | (y << 4) | (x << 2) | w) as i32
    }

    impl u32x4 {
        #[inline(always)]
        pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
            // Reversed.
            unsafe { Self(_mm_set_epi32(d as i32, c as i32, b as i32, a as i32)) }
        }

        #[inline(always)]
        pub fn load(addr: &[u8; 16]) -> Self {
            unsafe { Self(_mm_loadu_si128(addr as *const u8 as *const _)) }
        }

        #[inline(always)]
        pub fn store(self, addr: &mut [u8; 16]) {
            unsafe {
                _mm_storeu_si128(addr as *mut _ as *mut _, self.0);
            }
        }

        #[inline(always)]
        pub fn rotate_left_16(self) -> Self {
            unsafe {
                Self(_mm_shufflelo_epi16(
                    _mm_shufflehi_epi16(self.0, 0b10_11_00_01),
                    0b10_11_00_01,
                ))
            }
        }

        #[inline(always)]
        pub fn rotate_left_12(self) -> Self {
            unsafe {
                let a = _mm_slli_epi32(self.0, 12);
                let b = _mm_srli_epi32(self.0, 20);
                Self(a) | Self(b)
            }
        }

        #[inline(always)]
        pub fn rotate_left_8(self, use_byte_shuffle: bool) -> Self {
            unsafe {
                if use_byte_shuffle {
                    let sv = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
                    Self(_mm_shuffle_epi8(self.0, sv))
                } else {
                    let a = _mm_slli_epi32(self.0, 8);
                    let b = _mm_srli_epi32(self.0, 24);
                    Self(a) | Self(b)
                }
            }
        }

        #[inline(always)]
        pub fn rotate_left_7(self) -> Self {
            unsafe {
                let a = _mm_slli_epi32(self.0, 7);
                let b = _mm_srli_epi32(self.0, 25);
                Self(a) | Self(b)
            }
        }

        #[inline(always)]
        pub fn shuffle_1230(self) -> Self {
            unsafe { Self(_mm_shuffle_epi32(self.0, _MM_SHUFFLE(1, 2, 3, 0))) }
        }

        #[inline(always)]
        pub fn shuffle_2301(self) -> Self {
            unsafe { Self(_mm_shuffle_epi32(self.0, _MM_SHUFFLE(2, 3, 0, 1))) }
        }

        #[inline(always)]
        pub fn shuffle_3012(self) -> Self {
            unsafe { Self(_mm_shuffle_epi32(self.0, _MM_SHUFFLE(3, 0, 1, 2))) }
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

pub use simd_impl::*;
