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

use libsodium_sys::{
    crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt,
};
use std::ptr::{null, null_mut};

pub fn encrypt(key: &[u8], nonce: &[u8], ad: &[u8], p: &[u8], out: &mut [u8]) {
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);
    assert_eq!(p.len() + 16, out.len());

    let mut out_len = out.len() as u64;

    unsafe {
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.as_mut_ptr(),
            &mut out_len,
            p.as_ptr(),
            p.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            null(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
}

pub fn decrypt(key: &[u8], nonce: &[u8], ad: &[u8], c: &[u8], out: &mut [u8]) -> Result<(), ()> {
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);
    assert_eq!(out.len() + 16, c.len());

    let mut out_len = out.len() as u64;

    let r = unsafe {
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.as_mut_ptr(),
            &mut out_len,
            null_mut(),
            c.as_ptr(),
            c.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    if r != 0 {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    use wireguard::re_exports::sodium_init;

    #[bench]
    fn bench_encrypt(b: &mut ::test::Bencher) {
        let k = [0u8; 32];
        let n = [1u8; 24];
        let ad = [2u8; 16];
        let data = [3u8; 16];
        let mut out = [0u8; 32];

        sodium_init().unwrap();

        b.iter(|| {
            encrypt(&k, &n, &ad, &data, &mut out);
        });
    }
}
