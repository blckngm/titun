// Copyright 2018 Guanhao Yin <sopium@mysterious.site>

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

use core::convert::TryInto;
use core::sync::atomic::{compiler_fence, Ordering};
use noise_protocol::*;
use rand::prelude::*;
use rand::rngs::OsRng;
use std::fmt;
use titun_hacl::{
    chacha20_poly1305_multiplexed_aead_decrypt, chacha20_poly1305_multiplexed_aead_encrypt,
    curve25519_multiplexed_ecdh, curve25519_multiplexed_secret_to_public,
};

#[derive(Eq, PartialEq)]
pub struct X25519Key {
    key: Sensitive,
    public_key: [u8; 32],
}

impl X25519Key {
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl fmt::Debug for X25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Key {{ key: {} }}", base64::encode(&self.key.0))
    }
}

impl U8Array for X25519Key {
    fn new() -> Self {
        U8Array::from_slice(&[0u8; 32])
    }

    fn new_with(v: u8) -> Self {
        U8Array::from_slice(&[v; 32])
    }

    fn from_slice(s: &[u8]) -> Self {
        let s = Sensitive::from_slice(s);
        let pk = curve25519_multiplexed_secret_to_public(&s.0);
        X25519Key {
            key: s,
            public_key: pk,
        }
    }

    fn len() -> usize {
        32
    }

    fn as_slice(&self) -> &[u8] {
        &(self.key).0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!()
    }

    fn clone(&self) -> Self {
        X25519Key {
            key: self.key.clone(),
            public_key: self.public_key,
        }
    }
}

#[derive(PartialEq, Eq)]
#[repr(C, align(16))]
pub struct Sensitive([u8; 32]);

// Zeroing out after use. (Use of write_volatile and compiler_fence is inspired by zeroize.)
impl Drop for Sensitive {
    fn drop(&mut self) {
        #[cfg(target_feature = "sse2")]
        unsafe {
            #[cfg(target_arch = "x86")]
            use std::arch::x86::{__m128, _mm_setzero_ps};
            #[cfg(target_arch = "x86_64")]
            use std::arch::x86_64::{__m128, _mm_setzero_ps};

            // write_volatile won't be optimized out.
            // repr(C, align(16)) makes ptr property aligned.
            let ptr = self as *mut Sensitive as *mut __m128;
            // write_volatile for *mut __m128 generates efficient and compact movaps/vmovaps instructions.
            ptr.write_volatile(_mm_setzero_ps());
            ptr.offset(1).write_volatile(_mm_setzero_ps());
        }
        #[cfg(not(target_feature = "sse2"))]
        unsafe {
            // write_volatile won't be optimized out.
            // repr(C, align(16)) makes ptr properly aligned.
            let ptr = self as *mut Sensitive as *mut u64;
            for i in 0..4 {
                ptr.offset(i).write_volatile(0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl U8Array for Sensitive {
    fn new() -> Self {
        Sensitive([0; 32])
    }

    fn new_with(v: u8) -> Self {
        Sensitive([v; 32])
    }

    fn from_slice(s: &[u8]) -> Self {
        Sensitive(s.try_into().unwrap())
    }

    fn len() -> usize {
        32
    }

    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

pub enum X25519 {}

pub enum ChaCha20Poly1305 {}

impl DH for X25519 {
    type Key = X25519Key;
    type Pubkey = [u8; 32];
    type Output = Sensitive;

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        X25519Key::from_slice(&k)
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        k.public_key
    }

    /// Returns `Err(())` if DH output is all-zero.
    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Result<Self::Output, ()> {
        Ok(Sensitive(curve25519_multiplexed_ecdh(&k.key.0, pk)?))
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Key = Sensitive;

    fn name() -> &'static str {
        "ChaChaPoly"
    }

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), plaintext.len() + 16);

        let (cipher, mac) = out.split_at_mut(plaintext.len());
        let mac = mac.try_into().unwrap();

        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&nonce.to_le_bytes());

        chacha20_poly1305_multiplexed_aead_encrypt(&k.0, &n, ad, plaintext, cipher, mac);
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()> {
        assert_eq!(out.len() + 16, ciphertext.len());

        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&nonce.to_le_bytes());

        let (cipher, mac) = ciphertext.split_at(out.len());
        let mac = mac.try_into().unwrap();

        chacha20_poly1305_multiplexed_aead_decrypt(&k.0, &n, ad, out, cipher, mac)
    }
}
