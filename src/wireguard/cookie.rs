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

use crate::crypto::xchacha20poly1305::{decrypt, encrypt};
use crate::wireguard::{Id, X25519Pubkey};
use blake2s_simd::{Hash, Params, State};
use rand::prelude::*;
use rand::rngs::OsRng;
use ring::constant_time::verify_slices_are_equal;

pub type Cookie = [u8; 16];

const LABEL_COOKIE: &[u8] = b"cookie--";

fn blake2s(len: usize, key: &[u8], input: &[u8]) -> Hash {
    Params::new().hash_length(len).key(key).hash(input)
}

/// Calc cookie according to a secret and a bytes representation of peer address.
///
/// This is a pure function.
pub fn calc_cookie(secret: &[u8], remote_addr: &[u8]) -> Cookie {
    let mut out = [0u8; 16];
    let r = blake2s(16, secret, remote_addr);
    out.copy_from_slice(r.as_bytes());
    out
}

/// Generate cookie reply message (64 bytes).
pub fn cookie_reply(
    pubkey: &X25519Pubkey,
    cookie: &Cookie,
    peer_index: Id,
    mac1: &[u8],
) -> [u8; 64] {
    let mut out = [0u8; 64];

    // Type and zeros.
    out[0..4].copy_from_slice(&[3, 0, 0, 0]);
    // Receiver index.
    out[4..8].copy_from_slice(peer_index.as_slice());

    {
        let (nonce, encrypted_cookie) = out[8..64].split_at_mut(24);
        OsRng.fill_bytes(nonce);

        // Calc encryption key.
        let temp = State::new().update(LABEL_COOKIE).update(pubkey).finalize();

        // Encrypt cookie.
        encrypt(temp.as_bytes(), nonce, mac1, cookie, encrypted_cookie);
    }

    out
}

pub fn process_cookie_reply(
    peer_pubkey: &X25519Pubkey,
    mac1: &[u8],
    msg: &[u8],
) -> Result<Cookie, ()> {
    if msg.len() != 64 {
        return Err(());
    }

    if msg[..4] != [3, 0, 0, 0] {
        return Err(());
    }

    // msg[4..8] is sender index, skip.

    let nonce = &msg[8..32];

    let ciphertext = &msg[32..64];

    // Calc encryption key.
    let temp = State::new()
        .update(LABEL_COOKIE)
        .update(peer_pubkey)
        .finalize();

    let mut cookie = [0u8; 16];
    decrypt(temp.as_bytes(), nonce, mac1, ciphertext, &mut cookie)?;
    Ok(cookie)
}

/// Extract `mac1` from a message.
///
/// # Panics
///
/// If the message is not at least 32-byte long.
pub fn get_mac1(m: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let len = m.len();
    out.copy_from_slice(&m[len - 32..len - 16]);
    out
}

pub fn cookie_sign(m: &mut [u8], cookie: Option<&Cookie>) {
    if cookie.is_none() {
        return;
    }
    let len = m.len();
    let (m1, m2) = m.split_at_mut(len - 16);
    let mac2 = blake2s(16, cookie.unwrap(), m1);
    m2.copy_from_slice(mac2.as_bytes());
}

pub fn cookie_verify(m: &[u8], cookie: &Cookie) -> bool {
    if m.len() < 16 {
        return false;
    }
    let (m, mac2) = m.split_at(m.len() - 16);
    let mac2_ = blake2s(16, cookie, m);
    verify_slices_are_equal(mac2_.as_bytes(), mac2)
        .map(|_| true)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie() {
        let mut rng = OsRng;
        let mut pk = [0u8; 32];
        rng.fill_bytes(&mut pk);

        let mut mac1 = [0u8; 16];
        rng.fill_bytes(&mut mac1);

        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        let cookie = calc_cookie(&secret, b"1.2.3.4");

        let reply = cookie_reply(&pk, &cookie, Id::gen(), &mac1);

        let cookie1 = process_cookie_reply(&pk, &mac1, &reply).unwrap();

        assert_eq!(&cookie, &cookie1);
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_cookie_reply(b: &mut crate::test::Bencher) {
        let mut rng = OsRng;

        let mut pk = [0u8; 32];
        rng.fill_bytes(&mut pk);

        let mut mac1 = [0u8; 16];
        rng.fill_bytes(&mut mac1);

        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        b.iter(|| {
            let cookie = calc_cookie(&secret, b"1.2.3.4");

            let reply = cookie_reply(&pk, &cookie, Id::gen(), &mac1);

            reply
        });
    }
}
