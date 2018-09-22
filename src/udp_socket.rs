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

use mio::net::UdpSocket as MioUdpSocket;
use parking_lot::RwLock;
use std::net::{Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::prelude::*;
use tokio::reactor::PollEvented2;
use tokio::sync::mpsc::*;

/// Like tokio UdpSocket, but can be sent to from multiple tasks.
pub struct UdpSocket {
    socket: Arc<PollEvented2<MioUdpSocket>>,
    send_tx: Sender<(Vec<u8>, SocketAddr, Sender<()>)>,
}

impl UdpSocket {
    pub fn bind(port: &mut u16) -> Result<UdpSocket, std::io::Error> {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::ipv6(), Type::dgram(), None)?;
        sock.set_nonblocking(true)?;
        sock.set_only_v6(false)?;
        sock.bind(&From::from(SocketAddr::from((
            Ipv6Addr::from([0u8; 16]),
            *port,
        ))))?;
        if *port == 0 {
            *port = sock.local_addr().unwrap().as_inet6().unwrap().port();
        }
        let std_sock = sock.into_udp_socket();
        let mio_sock = MioUdpSocket::from_socket(std_sock)?;
        let socket = Arc::new(PollEvented2::new(mio_sock));

        let socket_clone = socket.clone();
        let (send_tx, mut send_rx) = channel::<(Vec<u8>, SocketAddr, Sender<()>)>(0);
        tokio::spawn_async(
            async move {
                while let Some(Ok((dgram, target, mut done))) = await!(send_rx.next()) {
                    let _ = await!(UdpSocket::real_send_to_async(
                        &socket_clone,
                        &dgram[..],
                        target
                    ));
                    await!(done.send_async(())).unwrap();
                }
            },
        );

        Ok(UdpSocket { socket, send_tx })
    }

    pub fn poll_recv_from(&self, buf: &mut [u8]) -> Poll<(usize, SocketAddr), std::io::Error> {
        match self.socket.poll_read_ready(mio::Ready::readable()) {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(_)) => (),
            Err(e) => return Err(e),
        }

        match self.socket.get_ref().recv_from(buf) {
            Ok(x) => Ok(x.into()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.clear_read_ready(mio::Ready::readable())?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    fn poll_send_to(
        socket: &PollEvented2<MioUdpSocket>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<usize, std::io::Error> {
        match socket.poll_write_ready() {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(_)) => (),
            Err(e) => return Err(e),
        }

        match socket.get_ref().send_to(buf, &target) {
            Ok(n) => Ok(n.into()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                socket.clear_write_ready()?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    /// Async recvfrom.
    ///
    /// Only one task should use this.
    pub fn recv_from_async<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl Future<Item = (usize, SocketAddr), Error = std::io::Error> + 'a {
        future::poll_fn(move || self.poll_recv_from(buf))
    }

    fn real_send_to_async<'a>(
        socket: &'a PollEvented2<MioUdpSocket>,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> impl Future<Item = usize, Error = std::io::Error> + 'a {
        future::poll_fn(move || UdpSocket::poll_send_to(socket, buf, target))
    }

    /// Async sendto.
    ///
    /// Multiple tasks can call this concurrently.
    pub async fn send_to_async<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Result<usize, std::io::Error> {
        // First try to send directly.
        match self.socket.get_ref().send_to(buf, &target) {
            Ok(len) => return Ok(len),
            Err(e) => if e.kind() != std::io::ErrorKind::WouldBlock {
                return Err(e);
            },
        }
        let (tx, mut rx) = channel(0);
        // If would block, send via queue.
        await!(self.send_tx.clone().send((buf.to_vec(), target, tx)));
        let _ = await!(rx.next());
        Ok(buf.len())
    }
}

pub async fn udp_send_to_async<'a>(
    socket: &'a RwLock<UdpSocket>,
    buf: &'a [u8],
    target: SocketAddr,
) -> Result<usize, std::io::Error> {
    let send_tx;
    {
        let socket = socket.read();
        match socket.socket.get_ref().send_to(buf, &target) {
            Ok(len) => return Ok(len),
            Err(e) => if e.kind() != std::io::ErrorKind::WouldBlock {
                return Err(e);
            },
        }
        send_tx = socket.send_tx.clone();
    }
    let (tx, mut rx) = channel(0);
    // If would block, send via queue.
    await!(send_tx.send((buf.to_vec(), target, tx)));
    let _ = await!(rx.next());
    Ok(buf.len())
}

#[cfg(unix)]
impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> i32 {
        self.socket.get_ref().as_raw_fd()
    }
}
