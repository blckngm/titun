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
