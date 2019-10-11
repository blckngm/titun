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

use futures::future::poll_fn;
use futures::ready;
use mio::net::UdpSocket as MioUdpSocket;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::task::{Context, Poll};
use tokio::sync::Mutex;
use tokio_net::util::PollEvented;

/// Like tokio UdpSocket, but can be used from multiple tasks concurrently.
pub struct UdpSocket {
    socket: PollEvented<MioUdpSocket>,
    send_lock: Mutex<()>,
    recv_lock: Mutex<()>,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket) -> Result<UdpSocket, std::io::Error> {
        socket.set_nonblocking(true)?;
        let socket = PollEvented::new(MioUdpSocket::from_socket(socket)?);
        Ok(UdpSocket {
            socket,
            send_lock: Mutex::new(()),
            recv_lock: Mutex::new(()),
        })
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        ready!(self.socket.poll_read_ready(cx, mio::Ready::readable()))?;

        match self.socket.get_ref().recv_from(buf) {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        ready!(self.socket.poll_write_ready(cx))?;

        match self.socket.get_ref().send_to(buf, target) {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    pub async fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let _guard = self.recv_lock.lock().await;
        poll_fn(move |cx| self.poll_recv_from(cx, buf)).await
    }

    pub async fn send_to<'a>(&'a self, buf: &'a [u8], target: &'a SocketAddr) -> io::Result<usize> {
        let _guard = self.send_lock.lock().await;
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
}

#[cfg(unix)]
impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> i32 {
        self.socket.get_ref().as_raw_fd()
    }
}
