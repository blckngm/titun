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

use crate::async_utils::{yield_once, AsyncScope};
use crate::udp_socket::*;
use crate::wireguard::*;
use anyhow::Error;
use fnv::FnvHashMap;
use futures::future::{select, Either};
use futures::prelude::*;
use ip_lookup_trie::IpLookupTable;
use noise_protocol::U8Array;
use parking_lot::{Mutex, RwLock};
use pin_utils::pin_mut;
use rand::prelude::*;
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::mpsc::*;
use tokio::timer::delay_for;

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

    pub(crate) socket: Mutex<Arc<UdpSocket>>,
    pub(crate) socket_sender: Mutex<Option<Sender<UdpSocket>>>,
    pub(crate) tun: AsyncTun,
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
            if let Some(mut id_map) = wg.id_map.try_write() {
                id_map.remove(&self.id);
                return;
            }
            let id = self.id;
            tokio::spawn(async move {
                wg.id_map.write().remove(&id);
            });
        }
    }
}

impl IdMapGuard {
    pub fn new(wg: Weak<WgState>, id: Id) -> Self {
        Self { wg, id }
    }
}

fn udp_process_handshake_init<'a>(
    wg: &'a Arc<WgState>,
    p: &'a [u8],
    addr: SocketAddrV6,
) -> impl Future<Output = ()> + 'a {
    let no_action = async {}.right_future();

    if p.len() != HANDSHAKE_INIT_LEN {
        return no_action;
    }

    // Lock info.
    let info = wg.info.read();
    if !verify_mac1(&info, p) {
        return no_action;
    }

    if wg.check_handshake_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), &addr.ip().octets());
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = get_mac1(p);
            let reply = cookie_reply(info.pubkey(), &cookie, peer_id, &mac1);
            return async move {
                let _ = wg.send_to(&reply[..], addr).await;
            }
                .left_future()
                .left_future();
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    if let Ok(mut r) = process_initiation(&info, p) {
        let r_pubkey = r.handshake_state.get_rs().unwrap();
        if let Some(peer0) = wg.find_peer_by_pubkey(&r_pubkey) {
            // Lock peer.
            let mut peer = peer0.write();

            peer.count_recv(p.len());

            // Compare timestamp.
            if Some(r.timestamp) > peer.last_handshake {
                peer.last_handshake = Some(r.timestamp);
            } else {
                debug!("{}: Handshake timestamp smaller.", peer.info.log_id());
                return no_action;
            }

            let self_id = Id::gen();
            r.handshake_state
                .push_psk(&peer.info.psk.unwrap_or([0u8; 32]));
            let mut response = match responde(&info, &mut r, self_id) {
                Err(_) => {
                    error!(
                        "{}: Failed to generate handshake response.",
                        peer.info.log_id()
                    );
                    return no_action;
                }
                Ok(r) => r,
            };

            // Save mac1.
            peer.last_mac1 = Some(get_mac1(&response));

            cookie_sign(&mut response, peer.get_cookie());

            peer.count_send((&response).len());

            let t = Transport::new_from_hs(
                IdMapGuard::new(Arc::downgrade(wg), self_id),
                r.peer_id,
                &r.handshake_state,
            );
            if peer.info.roaming {
                peer.set_endpoint(addr);
            }
            peer.push_transport(t);
            // Now that handshake is successful as responder, no need to do
            // handshake as initiator.
            peer.handshake = None;
            peer.handshake_resend_scope = None;

            // Lock id_map.
            wg.id_map.write().insert(self_id, peer0.clone());
            debug!("{}: Handshake successful as responder.", peer.info.log_id());
            return async move {
                let _ = wg.send_to(&response[..], addr).await;
            }
                .right_future()
                .left_future();
        } else {
            debug!("Get handshake init, but can't find peer by pubkey.");
        }
    } else {
        debug!("Get handshake init, but authentication/decryption failed.");
    }
    no_action
}

fn udp_process_handshake_resp<'a>(
    wg: &'a WgState,
    p: &'a [u8],
    addr: SocketAddrV6,
    buffer: &'a mut [u8],
) -> impl Future<Output = ()> + Send + 'a {
    let no_action = async {}.left_future();

    if p.len() != HANDSHAKE_RESP_LEN {
        return no_action;
    }

    // Lock info.
    let info = wg.info.read();
    if !verify_mac1(&info, p) {
        return no_action;
    }

    if wg.check_handshake_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), &addr.ip().octets());
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = get_mac1(p);
            let reply = cookie_reply(info.pubkey(), &cookie, peer_id, &mac1);
            return async move {
                let _ = wg.send_to(&reply, addr).await;
            }
                .left_future()
                .right_future();
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    let self_id = Id::from_slice(&p[8..12]);

    if let Some(peer0) = wg.find_peer_by_id(self_id) {
        let (peer_id, hs) = {
            // Lock peer.
            let peer = peer0.read();
            peer.count_recv(p.len());
            let handshake = match peer.handshake {
                Some(ref h) => h,
                None => {
                    debug!(
                        "{}: Get handshake response message, but don't know id.",
                        peer.info.log_id()
                    );
                    return no_action;
                }
            };
            if handshake.self_id.id != self_id {
                debug!(
                    "{}: Get handshake response message, but don't know id.",
                    peer.info.log_id()
                );
                return no_action;
            }

            let mut hs = handshake.hs.clone();
            if let Ok(peer_id) = process_response(&mut hs, p) {
                debug!("{}: Handshake successful as initiator.", peer.info.log_id());
                (peer_id, hs)
            } else {
                debug!(
                    "{}: Get handshake response message, auth/decryption failed.",
                    peer.info.log_id()
                );
                return no_action;
            }
            // Release peer.
        };
        // Lock id_map.
        wg.id_map.write().insert(self_id, peer0.clone());
        // Release id_map.
        // Lock peer.
        let mut peer = peer0.write();
        peer.handshake_resend_scope = None;
        let handle = peer.handshake.take().unwrap().self_id;
        let t = Transport::new_from_hs(handle, peer_id, &hs);
        peer.push_transport(t.clone());
        if peer.info.roaming {
            peer.set_endpoint(addr);
        }

        let queued_packets = peer.dequeue_all();
        if queued_packets.is_empty() {
            // Send a keep alive packet for key confirmation if there are
            // nothing else to send.
            peer.keepalive.adjust_and_activate_secs(1);
        } else {
            // Send queued packets.
            for p in &queued_packets {
                peer.count_send(p.len() + 32);
            }
            peer.on_send_transport();
            return async move {
                for p in queued_packets {
                    let encrypted = &mut buffer[..p.len() + 32];
                    t.encrypt(&p, encrypted).0.unwrap();
                    let _ = wg.send_to(encrypted, addr).await;
                }
            }
                .right_future()
                .right_future();
        }
    } else {
        debug!("Get handshake response message, but don't know id.");
    }
    no_action
}

fn udp_process_cookie_reply(wg: &WgState, p: &[u8]) {
    let self_id = Id::from_slice(&p[4..8]);

    if let Some(peer) = wg.find_peer_by_id(self_id) {
        // Lock peer.
        let mut peer = peer.write();
        peer.count_recv(p.len());
        if let Some(mac1) = peer.last_mac1 {
            if let Ok(cookie) = process_cookie_reply(&peer.info.public_key, &mac1, p) {
                peer.cookie = Some((cookie, tokio::clock::now()));
            } else {
                debug!(
                    "{}: Process cookie reply: auth/decryption failed.",
                    peer.info.log_id()
                );
            }
        }
    }
}

async fn udp_process_transport<'a>(
    wg: &'a Arc<WgState>,
    p: &'a [u8],
    addr: SocketAddrV6,
    buffer: &'a mut [u8],
) {
    if p.len() < 32 {
        return;
    }

    let self_id = Id::from_slice(&p[4..8]);

    let peer0 = match wg.find_peer_by_id(self_id) {
        Some(p) => p,
        None => {
            debug!("Get transport message, but don't know id.");
            return;
        }
    };

    let decrypted = &mut buffer[..p.len() - 32];
    let mut should_write = false;
    let mut packet_len = 0;

    let mut should_set_endpoint = false;
    let mut should_handshake = false;
    {
        // Lock peer.
        let peer = peer0.read();
        peer.count_recv(p.len());
        if let Some(t) = peer.find_transport_by_id(self_id) {
            match t.decrypt(p, decrypted) {
                Ok(h) => {
                    should_handshake = h && peer.really_should_handshake();
                    peer.on_recv(decrypted.is_empty());
                    if peer.info.endpoint != Some(addr) && peer.info.roaming {
                        should_set_endpoint = true;
                    }
                    if let Ok((len, src, _)) = parse_ip_packet(decrypted) {
                        // Reverse path filtering.
                        let peer1 = wg.find_peer_by_ip(src);
                        if peer1.is_none() || !Arc::ptr_eq(&peer0, &peer1.unwrap()) {
                            debug!(
                                "{}: Get transport message: allowed IPs check failed.",
                                peer.info.log_id()
                            );
                        } else if len as usize <= decrypted.len() {
                            should_write = true;
                            packet_len = len as usize;
                        } else {
                            debug!(
                                "{}: Get transport message: packet truncated?",
                                peer.info.log_id()
                            );
                        }
                    }
                }
                Err(_) => {
                    debug!(
                        "{}: Get transport message, decryption failed.",
                        peer.info.log_id()
                    );
                }
            }
        }
        // Release peer.
    };
    if should_write {
        let _ = wg.tun.write(&decrypted[..packet_len]).await;
    }
    if should_set_endpoint {
        // Lock peer.
        peer0.write().set_endpoint(addr);
    }
    if should_handshake {
        do_handshake(&wg, &peer0);
    }
}

/// Receiving loop.
async fn udp_processing(wg: Arc<WgState>, mut receiver: Receiver<UdpSocket>) {
    let mut p = vec![0u8; BUFSIZE];
    let mut buffer = vec![0u8; BUFSIZE];
    loop {
        for _ in 0..1024 {
            let (len, addr) = {
                let socket = wg.socket.lock().clone();
                let recv = socket.recv_from(&mut p);
                pin_mut!(recv);
                match select(recv, receiver.next()).await {
                    Either::Left((recv_result, _)) => recv_result.unwrap(),
                    Either::Right((socket, _)) => {
                        *wg.socket.lock() = Arc::new(socket.unwrap());
                        continue;
                    }
                }
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
                1 => udp_process_handshake_init(&wg, p, addr).await,
                2 => udp_process_handshake_resp(&wg, p, addr, &mut buffer).await,
                3 => udp_process_cookie_reply(&wg, p),
                4 => udp_process_transport(&wg, p, addr, &mut buffer).await,
                _ => (),
            }
        }
        yield_once().await;
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
async fn tun_packet_processing(wg: Arc<WgState>) {
    let mut pkt = vec![0u8; BUFSIZE];
    let mut encrypted = vec![0u8; BUFSIZE];
    loop {
        for _ in 0..1024 {
            let len = wg.tun.read(&mut pkt).await.unwrap();

            let padded_len = pad_len(len);
            // Do not leak other packets' data!
            for b in &mut pkt[len..padded_len] {
                *b = 0;
            }
            let pkt = &pkt[..padded_len];

            let dst = match parse_ip_packet(pkt) {
                Ok((_, _, dst)) => dst,
                Err(_) => {
                    error!("Get packet from TUN device, but failed to parse it!");
                    continue;
                }
            };

            let peer0 = match wg.find_peer_by_ip(dst) {
                Some(peer) => peer,
                None => {
                    // TODO ICMP no route to host.
                    match dst {
                        IpAddr::V6(i) if i.segments()[0] == 0xff02 => (),
                        _ => debug!("No route to host: {}", dst),
                    };
                    continue;
                }
            };

            let encrypted = &mut encrypted[..pkt.len() + 32];
            let endpoint;
            let mut should_send = false;

            let should_handshake = {
                // Lock peer.
                let peer = peer0.read();
                endpoint = match peer.get_endpoint() {
                    None => continue,
                    Some(e) => e,
                };

                if let Some(t) = peer.find_transport_to_send() {
                    let (result, should_handshake) = t.encrypt(pkt, encrypted);
                    if result.is_ok() {
                        should_send = true;
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

            if should_send {
                let _ = wg.send_to(encrypted, endpoint).await;
            }

            if should_handshake {
                do_handshake(&wg, &peer0);
            }
        }
        yield_once().await;
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
    pub keepalive: Option<u16>,
    pub replace_allowed_ips: bool,
    /// Replace if `replace_allowed_ips`, append otherwise.
    pub allowed_ips: BTreeSet<(IpAddr, u32)>,
}

impl WgState {
    /// Create a new `WgState`, start worker threads.
    pub fn new(mut info: WgInfo, tun: AsyncTun) -> Result<Arc<WgState>, Error> {
        let mut cookie = [0u8; 32];
        OsRng.fill_bytes(&mut cookie);

        let socket = WgState::prepare_socket(&mut info.port, info.fwmark)?;

        let wg = Arc::new(WgState {
            info: RwLock::new(info),
            pubkey_map: RwLock::new(HashMap::with_capacity(1)),
            id_map: RwLock::new(Default::default()),
            rt4: RwLock::new(IpLookupTable::new()),
            rt6: RwLock::new(IpLookupTable::new()),
            load_monitor: Mutex::new(LoadMonitor::new(HANDSHAKES_PER_SEC)),
            cookie_secret: RwLock::new(cookie),
            socket: Mutex::new(Arc::new(socket)),
            socket_sender: Mutex::new(None),
            tun,
        });
        Ok(wg)
    }

    pub async fn run(wg: Arc<WgState>) {
        let scope = AsyncScope::new();
        {
            let wg = wg.clone();
            scope.spawn_async(async move {
                loop {
                    delay_for(Duration::from_secs(120)).await;
                    let mut cookie = wg.cookie_secret.write();
                    OsRng.fill_bytes(&mut cookie[..]);
                }
            });
        }
        let (sender, receiver) = channel(0);
        *wg.socket_sender.lock() = Some(sender);
        scope.spawn_async(udp_processing(wg.clone(), receiver));
        scope.spawn_async(tun_packet_processing(wg));
        scope.cancelled().await;
    }

    // Create a new socket, set IPv6 only to false, set fwmark, and bind.
    fn prepare_socket(port: &mut u16, fwmark: u32) -> Result<UdpSocket, std::io::Error> {
        let socket = net2::UdpBuilder::new_v6()?
            .only_v6(false)?
            .bind((Ipv6Addr::UNSPECIFIED, *port))?;

        if *port == 0 {
            *port = socket.local_addr()?.port();
        }

        let socket = UdpSocket::from_std(socket)?;

        if fwmark != 0 {
            set_fwmark(&socket, fwmark)?;
        }
        Ok(socket)
    }

    pub(crate) async fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: impl Into<SocketAddr> + 'static,
    ) -> Result<usize, std::io::Error> {
        let target = target.into();
        let socket = self.socket.lock().clone();
        socket.send_to(buf, &target).await
    }

    /// Add a pper.
    // XXX: change to `self: &Arc<Self>` once it's allowed in stable.
    pub fn add_peer(self: Arc<Self>, public_key: &X25519Pubkey) -> Result<(), Error> {
        wg_add_peer(&self, public_key)
    }

    fn find_peer_by_id(&self, id: Id) -> Option<SharedPeerState> {
        self.id_map.read().get(&id).cloned()
    }

    /// Check whether a peer exists.
    pub fn peer_exists(&self, pk: &X25519Pubkey) -> bool {
        self.find_peer_by_pubkey(pk).is_some()
    }

    fn find_peer_by_pubkey(&self, pk: &X25519Pubkey) -> Option<SharedPeerState> {
        self.pubkey_map.read().get(pk).cloned()
    }

    /// Find peer by ip address, consulting the routing tables.
    fn find_peer_by_ip(&self, addr: IpAddr) -> Option<SharedPeerState> {
        match addr {
            IpAddr::V4(ip4) => self.rt4.read().longest_match(ip4).cloned(),
            IpAddr::V6(ip6) => self.rt6.read().longest_match(ip6).cloned(),
        }
    }

    fn check_handshake_load(&self) -> bool {
        if std::env::var("TITUN_INTEROPE_TEST").is_ok() {
            true
        } else {
            self.load_monitor.lock().check()
        }
    }

    fn get_cookie_secret(&self) -> [u8; 32] {
        *self.cookie_secret.read()
    }

    /// Remove all peers.
    pub fn remove_all_peers(&self) {
        let peers: Vec<X25519Pubkey> = self.pubkey_map.read().keys().cloned().collect();
        for p in peers {
            self.remove_peer(&p);
        }
    }

    /// Get interface and peer state.
    pub fn get_state(&self) -> WgStateOut {
        let peers = {
            // Lock pubkey map.
            let pubkey_map = self.pubkey_map.read();

            pubkey_map
                .values()
                .map(|p| {
                    // Lock peer.
                    let peer = p.read();

                    PeerStateOut {
                        public_key: peer.info.public_key,
                        preshared_key: peer.info.psk,
                        endpoint: peer.info.endpoint.map(unmap_ipv4_from_ipv6),
                        last_handshake_time: peer.get_last_handshake_time(),
                        rx_bytes: peer.rx_bytes.load(Ordering::Relaxed),
                        tx_bytes: peer.tx_bytes.load(Ordering::Relaxed),
                        persistent_keepalive_interval: peer.info.keepalive.map_or(0, |x| x.get()),
                        allowed_ips: peer.info.allowed_ips.clone(),
                    }
                    // Release peer.
                })
                .collect()
            // Release pubkey map.
        };

        // Lock info.
        let info = self.info.read();
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
        let mut info = self.info.write();

        // Lock pubkey map.
        let pubkey_map = self.pubkey_map.read();

        for p in pubkey_map.values() {
            // Lock peer.
            p.write().clear();
            // Release peer.
        }

        drop(pubkey_map);
        // Release pubkey_map.

        info.key = key;
    }

    /// Change listen port.
    pub async fn set_port(&self, mut new_port: u16) -> Result<(), std::io::Error> {
        if new_port == self.info.read().port {
            return Ok(());
        }
        let new_socket = WgState::prepare_socket(&mut new_port, self.info.read().fwmark)?;
        let mut sender = self.socket_sender.lock().as_ref().unwrap().clone();
        sender.send(new_socket).await.unwrap();
        self.info.write().port = new_port;
        Ok(())
    }

    /// Set fwmark of the UDP socket.
    pub fn set_fwmark(&self, new_fwmark: u32) -> Result<(), std::io::Error> {
        let mut info = self.info.write();
        if info.fwmark == new_fwmark {
            return Ok(());
        }
        {
            let socket: &UdpSocket = &self.socket.lock();
            set_fwmark(socket, new_fwmark)?;
        }
        info.fwmark = new_fwmark;
        Ok(())
    }

    /// Change configuration of a peer. Will return error if the peer does not
    /// exist.
    pub fn set_peer(&self, command: SetPeerCommand) -> Result<(), Error> {
        let peer0 = self
            .find_peer_by_pubkey(&command.public_key)
            .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;

        // Lock peer.
        let mut peer = peer0.write();

        if peer.info.psk != command.preshared_key {
            debug!("setting peer psk");
            peer.clear();
            peer.info.psk = command.preshared_key;
        }

        if let Some(endpoint) = command.endpoint {
            if peer.info.endpoint != Some(map_ipv4_to_ipv6(endpoint)) {
                debug!("setting peer endpoint");
                peer.info.endpoint = Some(map_ipv4_to_ipv6(endpoint));
            }
            peer.info.roaming = false;
        }

        if let Some(interval) = command.keepalive {
            if peer.info.keepalive != std::num::NonZeroU16::new(interval) {
                debug!("setting peer keepalive");
                peer.info.keepalive = std::num::NonZeroU16::new(interval);
                if interval > 0 {
                    peer.persistent_keepalive.adjust_and_activate_secs(5);
                } else {
                    peer.persistent_keepalive.de_activate();
                }
            }
        }

        // We should not take locks of other peers when we are holding `rt4` and
        // `rt6` locks, that would violate our lock order. So remove them later.
        let mut to_remove_others: Vec<(SharedPeerState, (IpAddr, u32))> = Vec::new();

        // Lock rt4.
        let mut rt4 = self.rt4.write();
        // Lock rt6.
        let mut rt6 = self.rt6.write();
        if command.replace_allowed_ips {
            for &(a, m) in peer.info.allowed_ips.difference(&command.allowed_ips) {
                debug!("removing allowed ip {}/{}", a, m);
                match a {
                    IpAddr::V4(a) => rt4.remove(a, m),
                    IpAddr::V6(a) => rt6.remove(a, m),
                };
            }

            for &(a, m) in command.allowed_ips.difference(&peer.info.allowed_ips) {
                debug!("adding allowed ip {}/{}", a, m);
                let old_peer = match a {
                    IpAddr::V4(a) => rt4.insert(a, m, peer0.clone()),
                    IpAddr::V6(a) => rt6.insert(a, m, peer0.clone()),
                };
                if let Some(old_peer) = old_peer {
                    to_remove_others.push((old_peer, (a, m)));
                }
            }

            peer.info.allowed_ips = command.allowed_ips;
        } else {
            for (a, m) in command.allowed_ips {
                if !peer.info.allowed_ips.contains(&(a, m)) {
                    debug!("adding allowed ip {}/{}", a, m);
                    let old_peer = match a {
                        IpAddr::V4(a) => rt4.insert(a, m, peer0.clone()),
                        IpAddr::V6(a) => rt6.insert(a, m, peer0.clone()),
                    };
                    if let Some(old_peer) = old_peer {
                        to_remove_others.push((old_peer, (a, m)));
                    }
                    peer.info.allowed_ips.insert((a, m));
                }
            }
        }

        drop(rt4);
        drop(rt6);

        for (old_peer, (a, m)) in to_remove_others {
            let mut old_peer = old_peer.write();
            debug!(
                "removing allowed ip {}/{} from old peer: {}",
                a,
                m,
                base64::encode(&old_peer.info.public_key)
            );
            assert!(old_peer.info.allowed_ips.remove(&(a, m)));
        }

        Ok(())
    }

    /// Remove a peer.
    ///
    /// Returns whether a peer is actually removed.
    pub fn remove_peer(&self, peer_pubkey: &X25519Pubkey) -> bool {
        // Remove from pubkey_map.
        let p = match self.pubkey_map.write().remove(peer_pubkey) {
            Some(p) => p,
            None => return false,
        };

        // Lock peer.
        let mut peer = p.write();
        // This will remove peer from `id_map` through `IdMapGuard`.
        peer.clear();

        // Remove from rt4 / rt6.

        // Lock rt4.
        let mut rt4 = self.rt4.write();
        // Lock rt6.
        let mut rt6 = self.rt6.write();
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
fn set_fwmark<Socket>(s: &Socket, fwmark: u32) -> Result<(), std::io::Error>
where
    Socket: ::std::os::unix::io::AsRawFd,
{
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::Mark;

    setsockopt(s.as_raw_fd(), Mark, &fwmark).map_err(|_| std::io::Error::last_os_error())?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_fwmark<T>(_s: &T, _fwmark: u32) -> Result<(), std::io::Error> {
    warn!("fwmark is not supported on this platform.");
    Ok(())
}
