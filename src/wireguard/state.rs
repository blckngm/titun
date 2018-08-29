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

use atomic::{AtomicBool, Ordering};
use failure::Error;
use fnv::FnvHashMap;
use noise_protocol::U8Array;
use sodiumoxide::randombytes::randombytes_into;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::mem::uninitialized;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::{spawn, Builder, JoinHandle};
use std::time::Instant;
use wireguard::re_exports::sodium_init;
use wireguard::*;

// Some Constants.

// Timeouts, in seconds.
pub const REKEY_AFTER_TIME: u64 = 120;
pub const REJECT_AFTER_TIME: u64 = 180;
pub const REKEY_TIMEOUT: u64 = 5;
pub const KEEPALIVE_TIMEOUT: u64 = 10;
pub const REKEY_ATTEMPT_TIME: u64 = 90;

const BUFSIZE: usize = 65536;

// How many packets to queue.
pub const QUEUE_SIZE: usize = 16;

// How many handshake messages per second is considered normal load.
const HANDSHAKES_PER_SEC: u32 = 250;

// Locking order:
//
//   info > pubkey_map > any peers > id_map > anything else
//   any peers > rt4 > rt6

/// State of a WG interface.
pub struct WgState {
    pub(crate) info: RwLock<WgInfo>,

    pub(crate) pubkey_map: RwLock<HashMap<X25519Pubkey, SharedPeerState>>,
    pub(crate) id_map: RwLock<FnvHashMap<Id, SharedPeerState>>,
    // Also should be keep in sync. But these should change less often.
    pub(crate) rt4: RwLock<IpLookupTable<Ipv4Addr, SharedPeerState>>,
    pub(crate) rt6: RwLock<IpLookupTable<Ipv6Addr, SharedPeerState>>,

    pub(crate) load_monitor: Mutex<LoadMonitor>,
    // The secret used to calc cookie.
    pub(crate) cookie_secret: RwLock<[u8; 32]>,
    pub(crate) cookie_reset_timer: Mutex<Option<TimerHandle>>,

    pub(crate) exiting: AtomicBool,

    // RwLock<Arc<_>> is like a RCU structure, i.e., it can be updated while the
    // old value is still in use.
    pub(crate) socket: RwLock<Arc<UdpSocket>>,
    pub(crate) tun: Tun,

    pub(crate) worker_threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for WgState {
    fn drop(&mut self) {
        debug!("WgState dropped.");
    }
}

/// Removes `Id` from `id_map` when dropped.
pub struct IdMapGuard {
    pub wg: Weak<WgState>,
    pub id: Id,
}

impl Drop for IdMapGuard {
    fn drop(&mut self) {
        if let Some(wg) = self.wg.upgrade() {
            if let Ok(mut id_map) = wg.id_map.try_write() {
                id_map.remove(&self.id);
                return;
            }
            let id = self.id;
            spawn(move || {
                wg.id_map.write().unwrap().remove(&id);
            });
        }
    }
}

impl IdMapGuard {
    pub fn new(wg: Weak<WgState>, id: Id) -> Self {
        Self { wg, id }
    }
}

fn udp_process_handshake_init(wg: &Arc<WgState>, p: &[u8], addr: SocketAddrV6) {
    if p.len() != HANDSHAKE_INIT_LEN {
        return;
    }

    // Lock info.
    let info = wg.info.read().unwrap();
    if !verify_mac1(&info, p) {
        return;
    }

    if wg.check_handshake_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), &addr.ip().octets());
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = get_mac1(p);
            let reply = cookie_reply(info.pubkey(), &cookie, peer_id, &mac1);
            wg.socket.read().unwrap().send_to(&reply, addr).unwrap();
            return;
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    if let Ok(mut r) = process_initiation(&info, p) {
        let r_pubkey = r.handshake_state.get_rs().unwrap();
        if let Some(peer0) = wg.find_peer_by_pubkey(&r_pubkey) {
            // Lock peer.
            let mut peer = peer0.write().unwrap();

            peer.count_recv(p.len());

            // Compare timestamp.
            if Some(r.timestamp) > peer.last_handshake {
                peer.last_handshake = Some(r.timestamp);
            } else {
                debug!("Handshake timestamp smaller.");
                return;
            }

            let self_id = Id::gen();
            r.handshake_state
                .push_psk(&peer.info.psk.unwrap_or([0u8; 32]));
            let response = responde(&info, &mut r, self_id);
            if response.is_err() {
                error!("Failed to generate handshake response.");
                return;
            }
            let mut response = response.unwrap();

            // Save mac1.
            peer.last_mac1 = Some(get_mac1(&response));

            cookie_sign(&mut response, peer.get_cookie());

            wg.socket.read().unwrap().send_to(&response, addr).unwrap();
            peer.count_send((&response).len());

            let t = Transport::new_from_hs(
                IdMapGuard::new(Arc::downgrade(wg), self_id),
                r.peer_id,
                &r.handshake_state,
            );
            peer.set_endpoint(addr);
            peer.push_transport(t);
            // Now that handshake is successful as responder, no need to do
            // handshake as initiator.
            peer.handshake = None;

            // Lock id_map.
            wg.id_map.write().unwrap().insert(self_id, peer0.clone());
            info!("Handshake successful as responder.");
        } else {
            debug!("Get handshake init, but can't find peer by pubkey.");
        }
    } else {
        debug!("Get handshake init, but authentication/decryption failed.");
    }
}

fn udp_process_handshake_resp(wg: &WgState, p: &[u8], addr: SocketAddrV6) {
    if p.len() != HANDSHAKE_RESP_LEN {
        return;
    }

    // Lock info.
    let info = wg.info.read().unwrap();
    if !verify_mac1(&info, p) {
        return;
    }

    if wg.check_handshake_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), &addr.ip().octets());
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = get_mac1(p);
            let reply = cookie_reply(info.pubkey(), &cookie, peer_id, &mac1);
            wg.socket.read().unwrap().send_to(&reply, addr).unwrap();
            return;
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    let self_id = Id::from_slice(&p[8..12]);

    if let Some(peer0) = wg.find_peer_by_id(self_id) {
        let (peer_id, hs) = {
            // Lock peer.
            let peer = peer0.read().unwrap();
            peer.count_recv(p.len());
            if peer.handshake.is_none() {
                debug!("Get handshake response message, but don't know id.");
                return;
            }
            let handshake = peer.handshake.as_ref().unwrap();
            if handshake.self_id.id != self_id {
                debug!("Get handshake response message, but don't know id.");
                return;
            }

            let mut hs = handshake.hs.clone();
            if let Ok(peer_id) = process_response(&mut hs, p) {
                (peer_id, hs)
            } else {
                debug!("Get handshake response message, auth/decryption failed.");
                return;
            }
            // Release peer.
        };
        info!("Handshake successful as initiator.");
        // Lock peer.
        let mut peer = peer0.write().unwrap();
        let handle = peer.handshake.take().unwrap().self_id;
        let t = Transport::new_from_hs(handle, peer_id, &hs);
        peer.push_transport(t.clone());
        peer.set_endpoint(addr);

        let queued_packets = peer.dequeue_all();
        if queued_packets.is_empty() {
            // Send a keep alive packet for key confirmation if there are
            // nothing else to send.
            peer.keep_alive
                .as_ref()
                .unwrap()
                .adjust_and_activate_secs(1);
        } else {
            // Send queued packets.
            let mut buf: [u8; BUFSIZE] = unsafe { uninitialized() };
            for p in queued_packets {
                let encrypted = &mut buf[..p.len() + 32];
                t.encrypt(&p, encrypted).0.unwrap();
                wg.socket.read().unwrap().send_to(encrypted, addr).unwrap();
                peer.count_send(encrypted.len());
            }
            peer.on_send_transport();
        }

        // Lock id_map.
        wg.id_map.write().unwrap().insert(self_id, peer0.clone());
    } else {
        debug!("Get handshake response message, but don't know id.");
    }
}

fn udp_process_cookie_reply(wg: &WgState, p: &[u8]) {
    let self_id = Id::from_slice(&p[4..8]);

    if let Some(peer) = wg.find_peer_by_id(self_id) {
        // Lock peer.
        let mut peer = peer.write().unwrap();
        peer.count_recv(p.len());
        if let Some(mac1) = peer.last_mac1 {
            if let Ok(cookie) = process_cookie_reply(&peer.info.peer_pubkey, &mac1, p) {
                peer.cookie = Some((cookie, Instant::now()));
            } else {
                debug!("Process cookie reply: auth/decryption failed.");
            }
        }
    }
}

fn udp_process_transport(wg: &Arc<WgState>, p: &[u8], addr: SocketAddrV6) {
    if p.len() < 32 {
        return;
    }

    let self_id = Id::from_slice(&p[4..8]);

    let maybe_peer0 = wg.find_peer_by_id(self_id);

    if maybe_peer0.is_none() {
        debug!("Get transport message, but don't know id.");
        return;
    }

    let peer0 = maybe_peer0.unwrap();
    let mut should_set_endpoint = false;
    let mut should_handshake = false;
    {
        // Lock peer.
        let peer = peer0.read().unwrap();
        peer.count_recv(p.len());
        if let Some(t) = peer.find_transport_by_id(self_id) {
            let mut buff: [u8; BUFSIZE] = unsafe { uninitialized() };
            let decrypted = &mut buff[..p.len() - 32];
            let decrypt_result = t.decrypt(p, decrypted);
            if decrypt_result.1 {
                should_handshake = peer.really_should_handshake();
            }
            if decrypt_result.0.is_ok() {
                if let Ok((len, src, _)) = parse_ip_packet(decrypted) {
                    // Reverse path filtering.
                    let peer1 = wg.find_peer_by_ip(src);
                    if peer1.is_none() || !Arc::ptr_eq(&peer0, &peer1.unwrap()) {
                        debug!("Get transport message: allowed IPs check failed.");
                    } else if len as usize <= decrypted.len() {
                        wg.tun.write(&decrypted[..len as usize]).unwrap();
                    } else {
                        debug!("Get transport message: packet truncated?");
                    }
                }
                peer.on_recv(decrypted.is_empty());
                if peer.info.endpoint != Some(addr) {
                    should_set_endpoint = true;
                }
            } else {
                debug!("Get transport message, decryption failed.");
            }
        }
        // Release peer.
    };
    if should_set_endpoint {
        // Lock peer.
        peer0.write().unwrap().set_endpoint(addr);
    }
    if should_handshake {
        do_handshake(&wg, &peer0);
    }
}

/// Receiving loop.
fn udp_processing(wg: &Arc<WgState>) {
    let mut p = [0u8; BUFSIZE];
    loop {
        if wg.exiting.load(Ordering::Relaxed) {
            break;
        }
        // Clone the `Arc` to not hold the lock while blocking.
        let socket = {
            let guard = wg.socket.read().unwrap();
            guard.clone()
        };
        let (len, addr) = match socket.recv_from(&mut p) {
            Ok(x) => x,
            Err(e) => if e.kind() == ErrorKind::Interrupted {
                continue;
            } else {
                panic!("recv_from failed: {}", e);
            },
        };

        let addr = match addr {
            SocketAddr::V6(a6) => a6,
            _ => unreachable!(),
        };

        if len < 12 {
            continue;
        }

        let type_ = p[0];
        let p = &p[..len];

        match type_ {
            1 => udp_process_handshake_init(&wg, p, addr),
            2 => udp_process_handshake_resp(&wg, p, addr),
            3 => udp_process_cookie_reply(&wg, p),
            4 => udp_process_transport(&wg, p, addr),
            _ => (),
        }
    }
}

// Packets >= MAX_PADDING won't be padded.
// 1280 should be a reasonable conservative choice.
const MAX_PADDING: usize = 1280;

const PADDING_MASK: usize = 0b1111;

fn pad_len(len: usize) -> usize {
    if len >= MAX_PADDING {
        len
    } else {
        // Next multiply of 16.
        (len & !PADDING_MASK) + if len & PADDING_MASK == 0 { 0 } else { 16 }
    }
}

#[cfg(test)]
#[test]
fn padding() {
    assert_eq!(pad_len(0), 0);
    for i in 1..16 {
        assert_eq!(pad_len(i), 16);
    }

    for i in 17..32 {
        assert_eq!(pad_len(i), 32);
    }

    for i in 1265..1280 {
        assert_eq!(pad_len(i), 1280);
    }
}

/// Sending thread loop.
fn tun_packet_processing(wg: &Arc<WgState>) {
    let mut pkt = [0u8; BUFSIZE];
    loop {
        if wg.exiting.load(Ordering::Relaxed) {
            break;
        }
        let len = match wg.tun.read(&mut pkt) {
            Ok(x) => x,
            Err(e) => if e.kind() == ErrorKind::Interrupted {
                continue;
            } else {
                panic!("Tun read failed: {}", e);
            },
        };

        let padded_len = pad_len(len);
        // Do not leak other packets' data!
        for b in &mut pkt[len..padded_len] {
            *b = 0;
        }
        let pkt = &pkt[..padded_len];

        let parse_result = parse_ip_packet(pkt);
        if parse_result.is_err() {
            error!("Get packet from TUN device, but failed to parse it!");
            continue;
        }
        let dst = parse_result.unwrap().2;

        let peer = wg.find_peer_by_ip(dst);
        if peer.is_none() {
            // TODO ICMP no route to host.
            match dst {
                IpAddr::V6(i) if i.segments()[0] == 0xff02 => (),
                _ => debug!("No route to host: {}", dst),
            };
            continue;
        }
        let peer0 = peer.unwrap();
        let should_handshake = {
            // Lock peer.
            let peer = peer0.read().unwrap();
            if peer.get_endpoint().is_none() {
                // TODO ICMP host unreachable?
                continue;
            }

            if let Some(t) = peer.find_transport_to_send() {
                let mut encrypted: [u8; BUFSIZE] = unsafe { uninitialized() };
                let encrypted = &mut encrypted[..pkt.len() + 32];
                let (result, should_handshake) = t.encrypt(pkt, encrypted);
                if result.is_ok() {
                    wg.socket
                        .read()
                        .unwrap()
                        .send_to(encrypted, peer.get_endpoint().unwrap())
                        .unwrap();
                    peer.count_send(encrypted.len());
                    peer.on_send_transport();
                }
                should_handshake && peer.really_should_handshake()
            } else {
                peer.enqueue_packet(pkt);

                peer.really_should_handshake()
            }
            // Release peer.
        };

        if should_handshake {
            do_handshake(&wg, &peer0);
        }
    }
}

/// Data structure passed to [WgState::set_peer].
pub struct SetPeerCommand {
    pub public_key: [u8; 32],
    /// Update if `Some`.
    pub preshared_key: Option<[u8; 32]>,
    /// Update if `Some`.
    pub endpoint: Option<SocketAddr>,
    /// Update if `Some`.
    ///
    /// Update to `None` if it is `Some(0)`.
    pub persistent_keepalive_interval: Option<u16>,
    pub replace_allowed_ips: bool,
    /// Replace if `replace_allowed_ips`, append otherwise.
    pub allowed_ips: Vec<(IpAddr, u32)>,
}

impl WgState {
    /// Create a new `WgState`, start worker threads.
    pub fn new(mut info: WgInfo, tun: Tun) -> Result<Arc<WgState>, Error> {
        sodium_init().map_err(|_| format_err!("Failed to init libsodium"))?;
        #[cfg(not(windows))]
        interrupt::init()?;

        let mut cookie = [0u8; 32];
        randombytes_into(&mut cookie);

        let socket = WgState::prepare_socket(&mut info.port, info.fwmark)?;

        let wg = Arc::new(WgState {
            info: RwLock::new(info),
            pubkey_map: RwLock::new(HashMap::with_capacity(1)),
            id_map: RwLock::new(Default::default()),
            rt4: RwLock::new(IpLookupTable::new()),
            rt6: RwLock::new(IpLookupTable::new()),
            load_monitor: Mutex::new(LoadMonitor::new(HANDSHAKES_PER_SEC)),
            cookie_secret: RwLock::new(cookie),
            cookie_reset_timer: Mutex::new(None),
            exiting: AtomicBool::new(false),
            socket: RwLock::new(Arc::new(socket)),
            tun,
            worker_threads: Mutex::new(vec![]),
        });
        {
            let weak_wg = Arc::downgrade(&wg);
            let cookie_reset_timer = TimerHandle::create(Box::new(move || {
                if let Some(wg) = weak_wg.upgrade() {
                    let mut cookie_secret = wg.cookie_secret.write().unwrap();
                    randombytes_into(cookie_secret.deref_mut());
                    wg.cookie_reset_timer
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .adjust_and_activate_secs(120);
                }
            }));
            cookie_reset_timer.adjust_and_activate_secs(120);
            *wg.cookie_reset_timer.lock().unwrap() = Some(cookie_reset_timer);
        }
        {
            let mut handles = wg.worker_threads.lock().unwrap();
            {
                let wg = wg.clone();
                handles.push(
                    Builder::new()
                        .name("rx".to_string())
                        .spawn(move || udp_processing(&wg))
                        .unwrap(),
                );
            }
            {
                let wg = wg.clone();
                handles.push(
                    Builder::new()
                        .name("tx".to_string())
                        .spawn(move || tun_packet_processing(&wg))
                        .unwrap(),
                );
            }
        }
        Ok(wg)
    }

    // These methods help a lot in avoiding deadlocks.

    // Create a new socket, set IPv6 only to false, set fwmark, and bind.
    fn prepare_socket(port: &mut u16, fwmark: u32) -> Result<UdpSocket, Error> {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::ipv6(), Type::dgram(), None)?;
        sock.set_only_v6(false)?;
        if fwmark != 0 {
            set_fwmark(&sock, fwmark)?;
        }
        sock.bind(&From::from(SocketAddr::from((
            Ipv6Addr::from([0u8; 16]),
            *port,
        ))))?;
        if *port == 0 {
            *port = sock.local_addr().unwrap().as_inet6().unwrap().port();
        }
        Ok(sock.into_udp_socket())
    }

    fn find_peer_by_id(&self, id: Id) -> Option<SharedPeerState> {
        self.id_map.read().unwrap().get(&id).cloned()
    }

    /// Check whether a peer exists.
    pub fn peer_exists(&self, pk: &X25519Pubkey) -> bool {
        self.find_peer_by_pubkey(pk).is_some()
    }

    fn find_peer_by_pubkey(&self, pk: &X25519Pubkey) -> Option<SharedPeerState> {
        self.pubkey_map.read().unwrap().get(pk).cloned()
    }

    /// Find peer by ip address, consulting the routing tables.
    fn find_peer_by_ip(&self, addr: IpAddr) -> Option<SharedPeerState> {
        match addr {
            IpAddr::V4(ip4) => self.rt4.read().unwrap().longest_match(ip4).cloned(),
            IpAddr::V6(ip6) => self.rt6.read().unwrap().longest_match(ip6).cloned(),
        }
    }

    fn check_handshake_load(&self) -> bool {
        self.load_monitor.lock().unwrap().check()
    }

    fn get_cookie_secret(&self) -> [u8; 32] {
        *self.cookie_secret.read().unwrap()
    }

    /// Remove all peers.
    pub fn remove_all_peers(&self) {
        let peers: Vec<X25519Pubkey> = self.pubkey_map.read().unwrap().keys().cloned().collect();
        for p in peers {
            self.remove_peer(&p);
        }
    }

    /// Stop all worker threads.
    pub fn exit(&self) {
        self.exiting.store(true, Ordering::Relaxed);

        // Remove peers to break reference loop.
        self.remove_all_peers();

        let mut handles = self.worker_threads.lock().unwrap();

        // Interrupt worker threads.
        #[cfg(not(windows))]
        {
            for h in handles.iter() {
                interrupt::interrupt(h).unwrap();
            }
        }
        #[cfg(windows)]
        {
            use std::net::{Ipv6Addr, SocketAddr};
            // Send a packet to ourselves to wake up the UDP thread.
            let sock = self.socket.read().unwrap();
            let port = sock.local_addr().unwrap().port();
            let addr = SocketAddr::from((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), port));
            sock.send_to(&[0], &addr).unwrap();
            // Wake up the tun thread.
            self.tun.interrupt();
        }

        // Join worker threads.
        for h in handles.drain(..) {
            h.join().unwrap();
        }
    }

    /// Get interface and peer state.
    pub fn get_state(&self) -> WgStateOut {
        let peers = {
            // Lock pubkey map.
            let pubkey_map = self.pubkey_map.read().unwrap();

            pubkey_map
                .values()
                .map(|p| {
                    // Lock peer.
                    let peer = p.read().unwrap();

                    PeerStateOut {
                        public_key: peer.info.peer_pubkey,
                        preshared_key: peer.info.psk,
                        endpoint: peer.info.endpoint.map(unmap_ipv4_from_ipv6),
                        last_handshake_time: peer.get_last_handshake_time(),
                        rx_bytes: peer.rx_bytes.load(Ordering::Relaxed),
                        tx_bytes: peer.tx_bytes.load(Ordering::Relaxed),
                        persistent_keepalive_interval: peer.info.keep_alive_interval,
                        allowed_ips: peer.info.allowed_ips.clone(),
                    }
                    // Release peer.
                })
                .collect()
            // Release pubkey map.
        };

        // Lock info.
        let info = self.info.read().unwrap();
        WgStateOut {
            private_key: info.key.clone(),
            peers,
            fwmark: info.fwmark,
            listen_port: info.port,
        }
        // Release info.
    }

    /// Change key.
    ///
    /// All existing sessions and handshakes will be cleared.
    pub fn set_key(&self, key: X25519Key) {
        // Lock info.
        let mut info = self.info.write().unwrap();

        // Lock pubkey map.
        let pubkey_map = self.pubkey_map.read().unwrap();

        for p in pubkey_map.values() {
            // Lock peer.
            p.write().unwrap().clear();
            // Release peer.
        }

        drop(pubkey_map);
        // Release pubkey_map.

        info.key = key;
    }

    /// Change listen port.
    pub fn set_port(&self, mut new_port: u16) -> Result<(), Error> {
        let mut info = self.info.write().unwrap();
        let info = info.deref_mut();
        if new_port == info.port {
            return Ok(());
        }
        let socket = WgState::prepare_socket(&mut new_port, info.fwmark)?;
        let clone = socket.try_clone()?;
        *self.socket.write().unwrap() = Arc::new(socket);
        // Send an empty packet to wake up `recvfrom` so the new socket will be
        // used.
        let addr = SocketAddr::from((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), info.port));
        clone.send_to(&[], addr)?;
        info.port = new_port;
        Ok(())
    }

    /// Set fwmark of the UDP socket.
    pub fn set_fwmark(&self, new_fwmark: u32) -> Result<(), Error> {
        let mut info = self.info.write().unwrap();
        if info.fwmark == new_fwmark {
            return Ok(());
        }
        set_fwmark(self.socket.read().unwrap().deref().deref(), new_fwmark)?;
        info.fwmark = new_fwmark;
        Ok(())
    }

    /// Change configuration of a peer. Will return error if the peer does not
    /// exist.
    pub fn set_peer(&self, command: SetPeerCommand) -> Result<(), Error> {
        let peer0 = self
            .find_peer_by_pubkey(&command.public_key)
            .ok_or_else(|| format_err!("Peer not found"))?;

        // Lock peer.
        let mut peer = peer0.write().unwrap();

        if let Some(psk) = command.preshared_key {
            peer.clear();
            peer.info.psk = Some(psk);
        }

        if let Some(endpoint) = command.endpoint {
            peer.info.endpoint = Some(map_ipv4_to_ipv6(endpoint));
        }

        if let Some(interval) = command.persistent_keepalive_interval {
            peer.info.keep_alive_interval = if interval > 0 { Some(interval) } else { None };
            if interval > 0 {
                peer.persistent_keep_alive
                    .as_ref()
                    .unwrap()
                    .adjust_and_activate_secs(5);
            } else {
                peer.persistent_keep_alive.as_ref().unwrap().de_activate();
            }
        }

        if command.replace_allowed_ips || !command.allowed_ips.is_empty() {
            // Lock rt4.
            let mut rt4 = self.rt4.write().unwrap();
            // Lock rt6.
            let mut rt6 = self.rt6.write().unwrap();

            if command.replace_allowed_ips {
                for &(a, m) in &peer.info.allowed_ips {
                    let p = match a {
                        IpAddr::V4(a) => rt4.remove(a, m),
                        IpAddr::V6(a) => rt6.remove(a, m),
                    }.unwrap();
                    assert!(Arc::ptr_eq(&p, &peer0));
                }
                peer.info.allowed_ips.clear();
            }
            for (a, m) in command.allowed_ips {
                let old_peer = match a {
                    IpAddr::V4(a) => rt4.insert(a, m, peer0.clone()),
                    IpAddr::V6(a) => rt6.insert(a, m, peer0.clone()),
                };
                let should_add = if let Some(old_peer) = old_peer {
                    if !Arc::ptr_eq(&old_peer, &peer0) {
                        let his_allowed_ips = &mut old_peer.write().unwrap().info.allowed_ips;
                        let i = his_allowed_ips.iter().position(|x| *x == (a, m)).unwrap();
                        his_allowed_ips.remove(i);
                        true
                    } else {
                        false
                    }
                } else {
                    true
                };
                if should_add {
                    peer.info.allowed_ips.push((a, m));
                }
            }
        }
        Ok(())
    }

    /// Remove a peer.
    ///
    /// Returns whether a peer is actually removed.
    pub fn remove_peer(&self, peer_pubkey: &X25519Pubkey) -> bool {
        // Remove from pubkey_map.
        // Lock pubkey_map.
        let mut pubkey_map = self.pubkey_map.write().unwrap();
        let p = pubkey_map.remove(peer_pubkey);
        if p.is_none() {
            // Release pubkey_map.
            return false;
        }
        let p = p.unwrap();
        drop(pubkey_map);
        // Release pubkey_map.

        // Lock peer.
        let mut peer = p.write().unwrap();
        // This will remove peer from `id_map` through `IdMapGuard`.
        peer.clear();

        // Remove from rt4 / rt6.

        // Lock rt4.
        let mut rt4 = self.rt4.write().unwrap();
        // Lock rt6.
        let mut rt6 = self.rt6.write().unwrap();
        for &(a, m) in &peer.info.allowed_ips {
            match a {
                IpAddr::V4(a) => rt4.remove(a, m),
                IpAddr::V6(a) => rt6.remove(a, m),
            };
        }

        true
    }
}

#[cfg(target_os = "linux")]
fn set_fwmark<Socket>(s: &Socket, fwmark: u32) -> Result<(), Error>
where
    Socket: ::std::os::unix::io::AsRawFd,
{
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::Mark;

    setsockopt(s.as_raw_fd(), Mark, &fwmark)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_fwmark<T>(_s: &T, _fwmark: u32) -> Result<(), Error> {
    warn!("fwmark is not supported on this platform.");
    Ok(())
}
