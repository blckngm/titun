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

use crate::crypto::noise_crypto_impls::{ChaCha20Poly1305, X25519};
use crate::wireguard::*;
use blake2s_simd::{Params, State};
use noise_protocol::patterns::noise_ik_psk2;
use noise_protocol::*;
use ring::constant_time::verify_slices_are_equal;
use std::convert::TryInto;
use tai64::TAI64N;

const PROLOGUE: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub const HANDSHAKE_INIT_LEN: usize = 148;
pub const HANDSHAKE_RESP_LEN: usize = 92;
/// Timestamp precision: 50 micro seconds.
const TIMESTAMP_PRECISION: u32 = 50_000;

pub type HS = HandshakeState<X25519, ChaCha20Poly1305, NoiseBlake2s>;

#[derive(Clone, Default)]
pub struct NoiseBlake2s(State);

impl Hash for NoiseBlake2s {
    type Output = [u8; 32];
    type Block = [u8; 64];

    fn name() -> &'static str {
        "BLAKE2s"
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self) -> Self::Output {
        Self::Output::from_slice(self.0.finalize().as_bytes())
    }
}

/// WireGuard `MAC` function, aka. keyed blake2s with 16-byte output.
fn mac(key: &[u8], data: &[&[u8]]) -> [u8; 16] {
    let mut mac = [0u8; 16];
    let mut blake2s = Params::new().hash_length(16).key(key).to_state();
    for d in data {
        blake2s.update(d);
    }
    mac.copy_from_slice(blake2s.finalize().as_bytes());
    mac
}

// WireGuard `HASH` function, aka. blake2s with 32-byte output.
macro_rules! hash {
    ($x1:expr, $x2:expr) => {{
        State::new().update($x1).update($x2).finalize()
    }};
}

/// Generate handshake initiation message.
///
/// Will generate a new ephemeral key and use current timestamp.
///
/// Returns: Message, noise handshake state.
pub fn initiate(
    wg: &WgInfo,
    peer: &PeerInfo,
    self_index: Id,
) -> Result<([u8; HANDSHAKE_INIT_LEN], HS), ()> {
    let mut msg = [0u8; HANDSHAKE_INIT_LEN];

    let mut hs = {
        let mut hsbuilder = HandshakeStateBuilder::<X25519>::new();
        hsbuilder.set_pattern(noise_ik_psk2());
        hsbuilder.set_is_initiator(true);
        hsbuilder.set_prologue(PROLOGUE);
        hsbuilder.set_s(wg.key.clone());
        hsbuilder.set_rs(peer.public_key);
        hsbuilder.build_handshake_state()
    };
    hs.push_psk(&peer.psk.unwrap_or([0u8; 32]));

    // Type and reserved zeros.
    msg[0..4].copy_from_slice(&[1, 0, 0, 0]);
    // Self index.
    msg[4..8].copy_from_slice(self_index.as_slice());

    // Noise part: e, s, timestamp.
    let mut timestamp = TAI64N::now();
    // Truncate the timestamp to avoid being a timing oracle for other attacks.
    timestamp.1 = timestamp.1 / TIMESTAMP_PRECISION * TIMESTAMP_PRECISION;
    hs.write_message(&timestamp.to_bytes(), &mut msg[8..116])
        .map_err(|_| ())?;

    // Mac1.
    let mac1_key = hash!(LABEL_MAC1, &peer.public_key);
    let mac1 = mac(mac1_key.as_ref(), &[&msg[..116]]);
    msg[116..132].copy_from_slice(&mac1);

    Ok((msg, hs))
}

pub struct InitProcessResult {
    pub peer_id: Id,
    pub timestamp: TAI64N,
    pub handshake_state: HS,
}

/// Process a handshake initiation message.
///
/// Will generate a new ephemeral key.
///
/// # Panics
///
/// If the message length is not `HANDSHAKE_INIT_LEN`.
pub fn process_initiation(wg: &WgInfo, msg: &[u8]) -> Result<InitProcessResult, ()> {
    assert_eq!(msg.len(), HANDSHAKE_INIT_LEN);

    // Check type and zeros.
    if msg[0..4] != [1, 0, 0, 0] {
        return Err(());
    }

    // Peer index.
    let peer_index = Id::from_slice(&msg[4..8]);

    let mut hs: HS = {
        let mut hsbuilder = HandshakeStateBuilder::<X25519>::new();
        hsbuilder.set_is_initiator(false);
        hsbuilder.set_prologue(PROLOGUE);
        hsbuilder.set_pattern(noise_ik_psk2());
        hsbuilder.set_s(wg.key.clone());
        hsbuilder.build_handshake_state()
    };

    // Noise message, contains encrypted timestamp.
    let mut timestamp = [0u8; 12];
    hs.read_message(&msg[8..116], &mut timestamp)
        .map_err(|_| ())?;
    let timestamp = timestamp.try_into().map_err(|_| ())?;

    Ok(InitProcessResult {
        peer_id: peer_index,
        timestamp,
        handshake_state: hs,
    })
}

/// Generate handshake response message.
/// PSK should be set on the handshake state inside process result according to peer static key.
pub fn responde(
    _wg: &WgInfo,
    result: &mut InitProcessResult,
    self_id: Id,
) -> Result<[u8; HANDSHAKE_RESP_LEN], ()> {
    let mut response = [0u8; HANDSHAKE_RESP_LEN];

    // Type and zeros.
    response[0..4].copy_from_slice(&[2, 0, 0, 0]);
    response[4..8].copy_from_slice(self_id.as_slice());
    response[8..12].copy_from_slice(result.peer_id.as_slice());

    let hs = &mut result.handshake_state;

    hs.write_message(&[], &mut response[12..60])
        .map_err(|_| ())?;

    let key = hash!(LABEL_MAC1, hs.get_rs().as_ref().unwrap());
    let mac1 = mac(key.as_ref(), &[&response[..60]]);
    response[60..76].copy_from_slice(&mac1);

    Ok(response)
}

/// Process handshake response message.
///
/// Returns peer index.
///
/// # Panics
///
/// If the message length is not `HANDSHAKE_RESP_LEN`.
pub fn process_response(hs: &mut HS, msg: &[u8]) -> Result<Id, ()> {
    assert_eq!(msg.len(), HANDSHAKE_RESP_LEN);

    // Check type and zeros.
    if msg[0..4] != [2, 0, 0, 0] {
        return Err(());
    }

    // Peer index.
    let peer_index = Id::from_slice(&msg[4..8]);

    // msg[8..12] is self index, skip.

    let mut out = [];

    hs.read_message(&msg[12..60], &mut out).map_err(|_| ())?;

    Ok(peer_index)
}

/// Verify `mac1` of a message.
///
/// # Panics
///
/// If the message is not at least 32-byte long.
pub fn verify_mac1(wg: &WgInfo, msg: &[u8]) -> bool {
    let mac1_pos = msg.len() - 32;
    let (m, macs) = msg.split_at(mac1_pos);
    let mac1 = &macs[..16];

    let key = hash!(LABEL_MAC1, wg.pubkey());
    let expected_mac1 = mac(key.as_ref(), &[m]);
    verify_slices_are_equal(&expected_mac1, mac1)
        .map(|_| true)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    #[test]
    fn wg_handshake_init_responde() {
        let k = X25519::genkey();
        let init = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let init_peer = PeerInfo {
            public_key: Clone::clone(resp.pubkey()),
            psk: None,
            endpoint: None,
            allowed_ips: BTreeSet::new(),
            keepalive: None,
            roaming: true,
        };

        let si = Id::gen();
        let (m0, mut ihs) = initiate(&init, &init_peer, si).unwrap();
        assert!(verify_mac1(&resp, &m0));
        let mut result0 = process_initiation(&resp, &m0).unwrap();
        assert_eq!(result0.handshake_state.get_rs(), Some(*init.pubkey()));
        result0.handshake_state.push_psk(&[0u8; 32]);
        let ri = Id::gen();
        let m1 = responde(&resp, &mut result0, ri).unwrap();
        assert!(verify_mac1(&init, &m1));
        let ri1 = process_response(&mut ihs, &m1).unwrap();

        assert_eq!(result0.peer_id, si);
        assert_eq!(ri1, ri);

        assert_eq!(ihs.get_hash(), result0.handshake_state.get_hash());
    }

    #[test]
    fn wg_handshake_init_responde_with_psk() {
        let mut psk = [0u8; 32];
        OsRng.fill_bytes(&mut psk);

        let k = X25519::genkey();
        let init = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let init_peer = PeerInfo {
            public_key: *resp.pubkey(),
            psk: Some(psk),
            endpoint: None,
            allowed_ips: BTreeSet::new(),
            keepalive: None,
            roaming: true,
        };

        let si = Id::gen();
        let (m0, mut ihs) = initiate(&init, &init_peer, si).unwrap();
        assert!(verify_mac1(&resp, &m0));
        let mut result0 = process_initiation(&resp, &m0).unwrap();
        result0.handshake_state.push_psk(&psk);
        let ri = Id::gen();
        let m1 = responde(&resp, &mut result0, ri).unwrap();
        assert!(verify_mac1(&init, &m1));
        let ri1 = process_response(&mut ihs, &m1).unwrap();

        assert_eq!(result0.peer_id, si);
        assert_eq!(ri1, ri);

        assert_eq!(ihs.get_hash(), result0.handshake_state.get_hash());
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_handshake_init(b: &mut crate::test::Bencher) {
        let k = X25519::genkey();
        let init = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let init_peer = PeerInfo {
            public_key: *resp.pubkey(),
            psk: None,
            endpoint: None,
            allowed_ips: BTreeSet::new(),
            keepalive: None,
            roaming: true,
        };

        b.iter(|| {
            let si = Id::gen();
            initiate(&init, &init_peer, si)
        });
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_handshake_resp(b: &mut crate::test::Bencher) {
        let k = X25519::genkey();
        let init = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let init_peer = PeerInfo {
            public_key: *resp.pubkey(),
            psk: None,
            endpoint: None,
            allowed_ips: BTreeSet::new(),
            keepalive: None,
            roaming: true,
        };

        let si = Id::gen();
        let (m0, _) = initiate(&init, &init_peer, si).unwrap();

        b.iter(|| {
            let mut result0 = process_initiation(&resp, &m0).unwrap();
            result0.handshake_state.push_psk(&[0u8; 32]);
            let ri = Id::gen();
            responde(&resp, &mut result0, ri)
        });
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_handshake_process_resp(b: &mut crate::test::Bencher) {
        let k = X25519::genkey();
        let init = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let init_peer = PeerInfo {
            public_key: *resp.pubkey(),
            psk: None,
            endpoint: None,
            allowed_ips: BTreeSet::new(),
            keepalive: None,
            roaming: true,
        };

        let si = Id::gen();
        let (m0, ihs) = initiate(&init, &init_peer, si).unwrap();
        assert!(verify_mac1(&resp, &m0));
        let mut result0 = process_initiation(&resp, &m0).unwrap();
        result0.handshake_state.push_psk(&[0u8; 32]);
        let ri = Id::gen();
        let m1 = responde(&resp, &mut result0, ri).unwrap();
        assert!(verify_mac1(&init, &m1));

        b.iter(|| {
            let mut hs = ihs.clone();
            process_response(&mut hs, &m1).unwrap();
        });
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_verify_mac1(b: &mut crate::test::Bencher) {
        let k = X25519::genkey();
        let init = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            key: k,
            fwmark: 0,
            port: 0,
        };

        let init_peer = PeerInfo {
            public_key: *resp.pubkey(),
            psk: None,
            endpoint: None,
            allowed_ips: BTreeSet::new(),
            keepalive: None,
            roaming: true,
        };

        let si = Id::gen();
        let (m0, _) = initiate(&init, &init_peer, si).unwrap();
        b.iter(|| verify_mac1(&resp, &m0));
    }
}
