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

use crate::async_utils::{delay, AsyncScope};
use crate::crypto::noise_rust_sodium::ChaCha20Poly1305;
use crate::wireguard::*;
use byteorder::{ByteOrder, LittleEndian};
use noise_protocol::Cipher;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// That is, 2 ^ 64 - 2 ^ 16 - 1;
const REKEY_AFTER_MESSAGES: u64 = 0xffff_ffff_fffe_ffff;
// That is, 2 ^ 64 - 2 ^ 4 - 1;
const REJECT_AFTER_MESSAGES: u64 = 0xffff_ffff_ffff_ffef;

pub type SecretKey = <ChaCha20Poly1305 as Cipher>::Key;

/// A WireGuard transport session.
pub struct Transport {
    pub self_id: IdMapGuard,
    pub peer_id: Id,
    pub is_initiator: bool,
    // Is set to true after REKEY_AFTER_TIME if `is_initiator`. And after
    // (REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT) if not initiator.
    pub should_handshake: AtomicBool,
    // If we are responder, whether we have received anything.
    pub has_received: AtomicBool,
    // Set to true after REJECT_AFTER_TIME, or after sending
    // REJECT_AFTER_MESSAGES.
    pub not_too_old: AtomicBool,
    pub created: Instant,

    pub send_key: SecretKey,
    pub send_counter: AtomicU64,

    pub recv_key: SecretKey,
    pub recv_ar: Mutex<AntiReplay>,

    scope: Arc<AsyncScope>,
}

impl Transport {
    pub fn new_from_hs(self_id: IdMapGuard, peer_id: Id, hs: &HS) -> Arc<Transport> {
        let (x, y) = hs.get_ciphers();
        let (s, r) = if hs.get_is_initiator() {
            (x, y)
        } else {
            (y, x)
        };
        let sk = s.extract().0;
        let rk = r.extract().0;

        let transport = Arc::new(Transport {
            self_id,
            peer_id,
            should_handshake: AtomicBool::new(false),
            is_initiator: hs.get_is_initiator(),
            has_received: AtomicBool::new(false),
            not_too_old: AtomicBool::new(true),
            send_key: sk,
            recv_key: rk,
            created: tokio::clock::now(),
            recv_ar: Mutex::new(AntiReplay::new()),
            send_counter: AtomicU64::new(0),
            scope: AsyncScope::new(),
        });

        let handshake_after = if transport.is_initiator {
            REKEY_AFTER_TIME
        } else {
            REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        };

        let weak = Arc::downgrade(&transport);
        transport.scope.spawn_async(
            async move {
                await!(delay(Duration::from_secs(handshake_after)));
                if let Some(t) = weak.upgrade() {
                    t.should_handshake.store(true, Ordering::Relaxed);
                }
            },
        );

        let weak = Arc::downgrade(&transport);
        transport.scope.spawn_async(
            async move {
                await!(delay(Duration::from_secs(REJECT_AFTER_TIME)));
                if let Some(t) = weak.upgrade() {
                    t.not_too_old.store(false, Ordering::Relaxed);
                }
            },
        );

        transport
    }

    pub fn get_should_send(&self) -> bool {
        (self.is_initiator || self.has_received.load(Ordering::Relaxed))
            && self.not_too_old.load(Ordering::Relaxed)
    }

    pub fn get_self_id(&self) -> Id {
        self.self_id.id
    }

    /// Expect packet with padding.
    ///
    /// Returns: Whether the operation is successful. Whether this transport
    /// thinks we should rekey.
    ///
    /// Length: out.len() = msg.len() + 32.
    pub fn encrypt(&self, msg: &[u8], out: &mut [u8]) -> (Result<(), ()>, bool) {
        let c = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let should_rekey = self.is_initiator
            && (self.should_handshake.load(Ordering::Relaxed) || c >= REKEY_AFTER_MESSAGES);

        // Even more unlikely...
        if c >= REJECT_AFTER_MESSAGES {
            self.not_too_old.store(false, Ordering::Relaxed);
            return (Err(()), should_rekey);
        }

        out[0..4].copy_from_slice(&[4, 0, 0, 0]);
        out[4..8].copy_from_slice(self.peer_id.as_slice());
        LittleEndian::write_u64(&mut out[8..16], c);

        <ChaCha20Poly1305 as Cipher>::encrypt(&self.send_key, c, &[], msg, &mut out[16..]);

        (Ok(()), should_rekey)
    }

    /// Returns packet maybe with padding, and whether this transport thinks we
    /// should rekey.
    ///
    /// Length: out.len() + 32 = msg.len().
    pub fn decrypt(&self, msg: &[u8], out: &mut [u8]) -> Result<bool, ()> {
        if msg.len() < 32 {
            return Err(());
        }

        if !self.not_too_old.load(Ordering::Relaxed) {
            return Err(());
        }

        if msg[0..4] != [4, 0, 0, 0] {
            return Err(());
        }

        let counter = LittleEndian::read_u64(&msg[8..16]);

        if counter >= REJECT_AFTER_MESSAGES {
            return Err(());
        }

        if <ChaCha20Poly1305 as Cipher>::decrypt(&self.recv_key, counter, &[], &msg[16..], out)
            .is_err()
        {
            return Err(());
        }

        if !self.recv_ar.lock().check_and_update(counter) {
            return Err(());
        }

        if !self.is_initiator {
            self.has_received.store(true, Ordering::Relaxed);
            Ok(self.should_handshake.load(Ordering::Relaxed))
        } else {
            Ok(false)
        }
    }
}
