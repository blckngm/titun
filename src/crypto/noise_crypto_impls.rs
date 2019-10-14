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

use noise_protocol::*;
use rand::prelude::*;
use rand::rngs::OsRng;
use ring::aead::*;
use ring::agreement::*;

#[derive(Eq, PartialEq)]
pub struct X25519Key {
    key: Sensitive<[u8; 32]>,
    public_key: [u8; 32],
}

impl X25519Key {
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl ::std::fmt::Debug for X25519Key {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> Result<(), ::std::fmt::Error> {
        write!(f, "X25519Key {{ key: {} }}", ::base64::encode(&self.key.0))
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
        let e = EphemeralPrivateKey::actually_static(&X25519, s.as_slice()).unwrap();
        let pk = U8Array::from_slice(e.compute_public_key().unwrap().as_ref());
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
pub struct Sensitive<A: U8Array>(A);

// Best effort zeroing out after use.
impl<A> Drop for Sensitive<A>
where
    A: U8Array,
{
    #[inline(never)]
    fn drop(&mut self) {
        let s = self.0.as_mut();
        for b in s {
            *b = 0;
        }
    }
}

impl<A> U8Array for Sensitive<A>
where
    A: U8Array,
{
    fn new() -> Self {
        Sensitive(A::new())
    }

    fn new_with(v: u8) -> Self {
        Sensitive(A::new_with(v))
    }

    fn from_slice(s: &[u8]) -> Self {
        Sensitive(A::from_slice(s))
    }

    fn len() -> usize {
        A::len()
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

pub enum X25519 {}

pub enum ChaCha20Poly1305 {}

impl DH for X25519 {
    type Key = X25519Key;
    type Pubkey = [u8; 32];
    type Output = Sensitive<[u8; 32]>;

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
        let e = EphemeralPrivateKey::actually_static(&X25519, k.as_slice()).unwrap();
        let mut out = Sensitive([0u8; 32]);
        agree(e, pk, out.as_mut()).map(|_| out).map_err(|_| ())
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Key = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "ChaChaPoly"
    }

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), plaintext.len() + 16);

        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&nonce.to_le_bytes());

        let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, k.as_slice()).unwrap());
        let aad = Aad::from(ad);
        let n = Nonce::assume_unique_for_key(n);

        k.seal(n, aad, plaintext, out).unwrap();
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

        let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, k.as_slice()).unwrap());
        let aad = Aad::from(ad);
        let n = Nonce::assume_unique_for_key(n);

        k.open(n, aad, ciphertext, out).map_err(|_| ())
    }
}
