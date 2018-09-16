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

use arrayvec::ArrayVec;
use crate::atomic::{AtomicU64, Ordering};
use crate::cancellation::CancellationTokenSource;
use crate::wireguard::*;
use failure::Error;
use rand::{thread_rng, Rng};
use std::collections::VecDeque;
use std::net::SocketAddrV6;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tai64::TAI64N;

pub type SharedPeerState = Arc<RwLock<PeerState>>;

pub struct PeerState {
    pub info: PeerInfo,
    pub last_handshake: Option<TAI64N>,
    pub cookie: Option<(Cookie, Instant)>,
    pub last_mac1: Option<[u8; 16]>,
    pub handshake: Option<Handshake>,

    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,

    pub queue: Mutex<VecDeque<Vec<u8>>>,

    pub transports: ArrayVec<[Arc<Transport>; 3]>,

    // Rekey because of send but not recv in...
    pub rekey_no_recv: Option<TimerHandle>,
    // Keep alive because of recv but not send in...
    pub keep_alive: Option<TimerHandle>,
    // Persistent keep-alive.
    pub persistent_keep_alive: Option<TimerHandle>,
    // Stop handshake after REKEY_ATTEMPT_TIME.
    pub stop_handshake: Option<TimerHandle>,
    // Clear all sessions if no new handshake in REJECT_AFTER_TIME * 3.
    pub clear: Option<TimerHandle>,
}

pub struct Handshake {
    pub self_id: IdMapGuard,
    pub hs: HS,
    pub resend: CancellationTokenSource,
}

impl PeerState {
    pub fn get_endpoint(&self) -> Option<SocketAddrV6> {
        self.info.endpoint
    }

    pub fn set_endpoint(&mut self, a: SocketAddrV6) {
        self.info.endpoint = Some(a)
    }

    pub fn get_cookie(&self) -> Option<&Cookie> {
        self.cookie?;
        if self.cookie.as_ref().unwrap().1.elapsed() >= Duration::from_secs(120) {
            return None;
        }
        Some(&self.cookie.as_ref().unwrap().0)
    }

    pub fn get_last_handshake_time(&self) -> Option<SystemTime> {
        self.transports.iter().next().map(|t| {
            let dur = t.created.elapsed();
            SystemTime::now() - dur
        })
    }

    pub fn clear(&mut self) {
        self.handshake = None;
        self.transports.clear();

        self.queue.lock().unwrap().clear();

        self.rekey_no_recv.as_ref().unwrap().de_activate();
        self.keep_alive.as_ref().unwrap().de_activate();
        self.clear.as_ref().unwrap().de_activate();
    }

    pub fn on_new_transport(&self) {
        self.stop_handshake.as_ref().unwrap().de_activate();
        self.clear
            .as_ref()
            .unwrap()
            .adjust_and_activate_secs(3 * REJECT_AFTER_TIME);
    }

    /// Add `size` bytes to the received bytes counter.
    pub fn count_recv(&self, size: usize) {
        self.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Add `size` bytes to the sent bytes counter.
    pub fn count_send(&self, size: usize) {
        self.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn on_recv(&self, is_keepalive: bool) {
        self.rekey_no_recv.as_ref().unwrap().de_activate();
        if !is_keepalive {
            self.keep_alive
                .as_ref()
                .unwrap()
                .adjust_and_activate_if_not_activated(KEEPALIVE_TIMEOUT);
        }
    }

    pub fn on_send_transport(&self) {
        self.keep_alive.as_ref().unwrap().de_activate();
        self.rekey_no_recv
            .as_ref()
            .unwrap()
            .adjust_and_activate_if_not_activated(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        if let Some(i) = self.info.keep_alive_interval {
            self.persistent_keep_alive
                .as_ref()
                .unwrap()
                .adjust_and_activate_secs(u64::from(i));
        }
    }

    pub fn on_send_keepalive(&self) {
        self.keep_alive.as_ref().unwrap().de_activate();
        if let Some(i) = self.info.keep_alive_interval {
            self.persistent_keep_alive
                .as_ref()
                .unwrap()
                .adjust_and_activate_secs(u64::from(i));
        }
    }

    pub fn push_transport(&mut self, t: Arc<Transport>) {
        self.on_new_transport();

        if self.transports.is_full() {
            self.transports.pop();
        }
        self.transports.insert(0, t);
    }

    pub fn really_should_handshake(&self) -> bool {
        self.handshake.is_none() && !self.have_fresh_unconfirmed_transport()
    }

    /// Do we have a transport where we are responder, that is very young and
    /// not confirmed. In this case, do not initiate handshake to avoid a
    /// thundering herd situation.
    pub fn have_fresh_unconfirmed_transport(&self) -> bool {
        for t in &self.transports {
            if !t.is_initiator && t.created.elapsed() < Duration::from_secs(10) {
                return true;
            }
        }
        false
    }

    /// Find a transport to send packet.
    pub fn find_transport_to_send(&self) -> Option<&Transport> {
        for t in &self.transports {
            if t.get_should_send() {
                return Some(t);
            }
        }
        None
    }

    pub fn find_transport_by_id(&self, id: Id) -> Option<&Transport> {
        for t in &self.transports {
            if t.get_self_id() == id {
                return Some(t);
            }
        }
        None
    }

    pub fn enqueue_packet(&self, p: &[u8]) {
        self.stop_handshake
            .as_ref()
            .unwrap()
            .adjust_and_activate_secs(REKEY_ATTEMPT_TIME);

        let mut queue = self.queue.lock().unwrap();
        while queue.len() >= QUEUE_SIZE {
            queue.pop_front();
        }
        queue.push_back(p.to_vec());
    }

    pub fn dequeue_all(&self) -> VecDeque<Vec<u8>> {
        let mut queue = self.queue.lock().unwrap();
        let mut out = VecDeque::with_capacity(QUEUE_SIZE);
        ::std::mem::swap(&mut out, &mut queue);
        out
    }
}

/// Add a peer to a WG interface.
///
/// Returns `Err` if the peer's public key conflicts with any existing peers.
pub fn wg_add_peer(wg: &Arc<WgState>, public_key: &X25519Pubkey) -> Result<(), Error> {
    // Lock pubkey_map.
    let mut pubkey_map = wg.pubkey_map.write().unwrap();

    if pubkey_map.get(public_key).is_some() {
        bail!("Public key already exists.");
    }

    let ps = PeerState {
        info: PeerInfo {
            peer_pubkey: *public_key,
            endpoint: None,
            keep_alive_interval: None,
            psk: None,
            allowed_ips: vec![],
        },
        last_handshake: None,
        last_mac1: None,
        cookie: None,
        handshake: None,
        rx_bytes: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        queue: Mutex::new(VecDeque::with_capacity(QUEUE_SIZE)),
        transports: ArrayVec::new(),
        rekey_no_recv: None,
        keep_alive: None,
        stop_handshake: None,
        persistent_keep_alive: None,
        clear: None,
    };
    let ps = Arc::new(RwLock::new(ps));

    macro_rules! timer {
        ($action:expr) => {{
            let wg = Arc::downgrade(wg);
            let ps = Arc::downgrade(&ps);
            Some(create_timer_async(move || {
                let wg = wg.clone();
                let ps = ps.clone();
                async move {
                    if let (Some(wg), Some(ps)) = (wg.upgrade(), ps.upgrade()) {
                        await!($action(wg, ps));
                    }
                }
            }))
        }};
    }

    // Init timers.
    {
        // Lock peer.
        let mut psw = ps.write().unwrap();
        psw.rekey_no_recv = timer!(async move |wg, ps| {
            debug!("Timer: rekey_no_recv.");
            do_handshake(&wg, &ps);
        });
        psw.keep_alive = timer!(async move |wg: Arc<WgState>, ps: SharedPeerState| {
            debug!("Timer: keep alive.");
            let should_handshake = await!(do_keep_alive1(&ps, &wg));
            if should_handshake {
                do_handshake(&wg, &ps);
            }
        });
        psw.persistent_keep_alive = timer!(async move |wg: Arc<WgState>, ps: SharedPeerState| {
            debug!("Timer: persistent_keep_alive.");
            let should_handshake = await!(do_keep_alive1(&ps, &wg));
            if should_handshake {
                do_handshake(&wg, &ps);
            }
            let p = ps.read().unwrap();
            if let Some(i) = p.info.keep_alive_interval {
                p.persistent_keep_alive
                    .as_ref()
                    .unwrap()
                    .adjust_and_activate_secs(u64::from(i));
            }
        });
        psw.stop_handshake = timer!(async move |_, ps: SharedPeerState| {
            debug!("Timer: stop handshake.");
            ps.write().unwrap().handshake = None;
        });
        psw.clear = timer!(async move |_, ps: SharedPeerState| {
            debug!("Timer: clear.");
            ps.write().unwrap().clear();
        });
    }

    pubkey_map.insert(*public_key, ps);

    Ok(())
}

/// Start handshake.
///
/// Better not hold any locks when calling this.
//
/// Nothing happens if there is already an ongoing handshake for this peer.
/// Nothing happens if we don't know peer endpoint.
pub fn do_handshake<'a>(wg: &'a Arc<WgState>, peer0: &'a SharedPeerState) {
    let source = CancellationTokenSource::new();

    {
        // Lock info.
        let info = wg.info.read().unwrap();

        // Lock peer.
        let mut peer = peer0.write().unwrap();
        if peer.handshake.is_some() {
            return;
        }
        if peer.get_endpoint().is_none() {
            return;
        }

        let id = Id::gen();
        // Lock id_map.
        wg.id_map.write().unwrap().insert(id, peer0.clone());
        let handle = IdMapGuard::new(Arc::downgrade(&wg), id);

        let initiate_result = initiate(&info, &peer.info, id);
        if initiate_result.is_err() {
            error!("Failed to generate handshake initiation message.");
            return;
        }
        let (mut i, hs) = initiate_result.unwrap();
        cookie_sign(&mut i, peer.get_cookie());

        peer.count_send((&i).len());

        peer.last_mac1 = Some(get_mac1(&i));

        let buffer = i;
        {
            let wg = Arc::downgrade(wg);
            let peer = Arc::downgrade(peer0);
            source.spawn_async(
                async move {
                    loop {
                        if let (Some(wg), Some(peer)) = (wg.upgrade(), peer.upgrade()) {
                            let endpoint = peer.read().unwrap().info.endpoint;
                            if let Some(e) = endpoint {
                                info!("Handshake init.");
                                await!(wg.send_to_async(&buffer, e));
                                peer.read().unwrap().count_send(buffer.len());
                            }
                        }
                        let delay_ms = thread_rng().gen_range(5_000, 5_300);
                        sleep!(ms delay_ms);
                    }
                },
            );
        }

        peer.handshake = Some(Handshake {
            self_id: handle,
            hs,
            resend: source,
        });

        peer.stop_handshake
            .as_ref()
            .unwrap()
            .adjust_and_activate_if_not_activated(REKEY_ATTEMPT_TIME);

        peer.clear
            .as_ref()
            .unwrap()
            .adjust_and_activate_if_not_activated(3 * REJECT_AFTER_TIME);
    }
}

#[must_use]
pub async fn do_keep_alive1<'a>(peer0: &'a SharedPeerState, wg: &'a WgState) -> bool {
    let endpoint;
    let mut out = [0u8; 32];
    let should_handshake = {
        let peer = peer0.read().unwrap();

        endpoint = match peer.get_endpoint() {
            Some(e) => e,
            None => return false,
        };

        let t = peer.find_transport_to_send();
        if t.is_none() {
            return peer.really_should_handshake();
        }
        let t = t.unwrap();

        let (result, should_handshake) = t.encrypt(&[], &mut out);
        let should_handshake = should_handshake && peer.really_should_handshake();
        if result.is_err() {
            return should_handshake;
        }

        peer.count_send(out.len());

        peer.on_send_keepalive();
        should_handshake
    };
    await!(wg.send_to_async(&out, endpoint));
    should_handshake
}
