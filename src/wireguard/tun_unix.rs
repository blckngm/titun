// Copyright 2017, 2018, 2019 Guanhao Yin <sopium@mysterious.site>

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

#![cfg(unix)]

use anyhow::Context as _;
use futures::future::poll_fn;
use futures::ready;
use mio::event::Evented;
use mio::unix::{EventedFd, UnixReady};
use mio::{Poll as MioPoll, PollOpt, Ready, Token};
use nix::fcntl::{open, OFlag};
use nix::libc;
use nix::sys::stat::Mode;
use nix::unistd::{close, read, write};
use std::ffi::CString;
use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::task::{Context, Poll};
use tokio_net::util::PollEvented;

mod ffi {
    use nix::libc;

    extern "C" {
        pub fn get_mtu(socket_fd: libc::c_int, ifindex: libc::c_uint) -> libc::c_int;
        #[cfg(target_os = "linux")]
        pub fn tunsetiff(tun_fd: libc::c_int, name: *const u8) -> libc::c_int;
        #[cfg(target_os = "freebsd")]
        pub fn tunsifhead(tun_fd: libc::c_int) -> libc::c_int;
    }
}

/// A tun interface.
#[derive(Debug)]
pub struct AsyncTun {
    io: PollEvented<Tun>,
}

impl AsyncTun {
    pub fn open(name: &OsStr) -> anyhow::Result<AsyncTun> {
        let tun = Tun::open(name, OFlag::O_NONBLOCK)?;
        Ok(AsyncTun {
            io: PollEvented::new(tun),
        })
    }

    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let ready = Ready::readable() | UnixReady::error();
        ready!(self.io.poll_read_ready(cx, ready))?;
        match self.io.get_ref().read(buf) {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, ready)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_write_ready(cx))?;

        match self.io.get_ref().write(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    pub(crate) fn get_mtu(&self) -> io::Result<u32> {
        use nix::sys::socket::*;
        let socket = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|_| io::Error::last_os_error())?;
        let mtu = unsafe { ffi::get_mtu(socket, self.io.get_ref().index) };
        if mtu < 0 {
            let err = io::Error::last_os_error();
            let _ = close(socket);
            Err(err)
        } else {
            let _ = close(socket);
            Ok(mtu as u32)
        }
    }

    // Should be used from only one task.
    pub(crate) async fn read<'a>(&'a self, buf: &'a mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_read(cx, buf)).await
    }

    // Should be used from only one task.
    pub(crate) async fn write<'a>(&'a self, buf: &'a [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_write(cx, buf)).await
    }
}

#[derive(Debug)]
struct Tun {
    fd: i32,
    /// Interface index.
    index: u32,
}

/// The file descriptor will be closed when the Tun is dropped.
impl Drop for Tun {
    fn drop(&mut self) {
        // Ignore error...
        let _ = close(self.fd);
    }
}

impl Tun {
    /// Create a tun interface.

    /// O_CLOEXEC, IFF_NO_PI.
    #[cfg(target_os = "linux")]
    pub fn open(name: &OsStr, extra_flags: OFlag) -> anyhow::Result<Tun> {
        if name.len() > nix::libc::IF_NAMESIZE - 1 {
            bail!("interface name is too long.");
        }

        let name_cstring = CString::new(name.as_bytes())?;
        let name_c_bytes = name_cstring.as_bytes_with_nul();

        let fd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_CLOEXEC | extra_flags,
            Mode::empty(),
        )?;

        // Make the `fd` owned by a `Tun`, so that if any
        // error occurs below, the `fd` is `close`d.
        let mut tun = Tun { fd, index: 0 };

        if unsafe { ffi::tunsetiff(fd, name_c_bytes.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // XXX: possible race if another process changes the name before we get
        // the index.
        tun.index = {
            let r = unsafe { libc::if_nametoindex(name_c_bytes.as_ptr() as *const _) };
            if r > 0 {
                Ok(r)
            } else {
                Err(io::Error::last_os_error())
            }
        }
        .context("get interface index")?;

        Ok(tun)
    }

    // BSD systems.
    #[cfg(target_os = "freebsd")]
    pub fn open(name: &OsStr, extra_flags: OFlag) -> anyhow::Result<Tun> {
        use std::path::Path;

        {
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("invalid tun interface name: {}", name.to_string_lossy()))?;

            if !name.starts_with("tun") || name[3..].parse::<u32>().is_err() {
                bail!(
                    "invalid tun interface name: {}: must be tunN where N is an integer",
                    name
                );
            }
        }
        let fd = open(
            &Path::new("/dev").join(name),
            OFlag::O_CLOEXEC | OFlag::O_RDWR | extra_flags,
            Mode::empty(),
        )?;
        let mut tun = Tun { fd, index: 0 };

        let name_cstring = CString::new(name.as_bytes())?;
        let name_c_bytes = name_cstring.as_bytes_with_nul();

        // XXX: this will fail the interface has previously been created and renamed.
        tun.index = {
            let r = unsafe { libc::if_nametoindex(name_c_bytes.as_ptr() as *const _) };
            if r > 0 {
                Ok(r)
            } else {
                Err(io::Error::last_os_error())
            }
        }
        .context("get interface index")?;

        // Call TUNSIFHEAD, without this, IPv6 in tunnel won't work.
        if unsafe { ffi::tunsifhead(fd) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(tun)
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

impl Tun {
    /// Read a packet from the tun interface.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if cfg!(target_os = "freebsd") {
            use nix::sys::uio::{readv, IoVec};

            let mut af_head = [0u8; 4];
            readv(
                self.fd,
                &mut [
                    IoVec::from_mut_slice(&mut af_head),
                    IoVec::from_mut_slice(buf),
                ],
            )
            .map(|len| len - 4)
            .map_err(|_| io::Error::last_os_error())
        } else {
            read(self.fd, buf).map_err(|_| io::Error::last_os_error())
        }
    }

    /// Write a packet to tun interface.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if cfg!(target_os = "freebsd") {
            use nix::libc::{AF_INET, AF_INET6};
            use nix::sys::uio::{writev, IoVec};

            let ip_version = buf[0] >> 4;
            let af: i32 = match ip_version {
                // IPv4 => AF_INET
                4 => AF_INET,
                // IPv6 => AF_INET6
                6 => AF_INET6,
                // Impossible.
                _ => {
                    debug_assert!(false);
                    AF_INET
                }
            };
            let af_header = af.to_be_bytes();
            writev(
                self.fd,
                &[IoVec::from_slice(&af_header), IoVec::from_slice(buf)],
            )
            .map(|len| len - 4)
            .map_err(|_| io::Error::last_os_error())
        } else {
            write(self.fd, buf).map_err(|_| io::Error::last_os_error())
        }
    }
}

impl Evented for Tun {
    fn register(
        &self,
        poll: &MioPoll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &MioPoll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &MioPoll) -> io::Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}

#[cfg(all(test, feature = "sudo-tests"))]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::future::FutureExt;
    use tokio::net::process::Command;

    const SELF_IP: &str = "10.33.178.2";
    const PEER_IP: &str = "10.33.178.1";

    #[tokio::test]
    async fn test_tun_ping_and_read() -> anyhow::Result<()> {
        let name = OsStr::new("tun7");
        let t = AsyncTun::open(name)?;

        Command::new("ifconfig")
            .arg(name)
            .arg("up")
            .output()
            .await?;

        // Linux.
        #[cfg(target_os = "linux")]
        Command::new("ip")
            .args(&["addr", "add", SELF_IP, "peer", PEER_IP, "dev"])
            .arg(name)
            .output()
            .await?;
        // BSD.
        #[cfg(not(target_os = "linux"))]
        Command::new("ifconfig")
            .arg(name)
            .args(&[SELF_IP, PEER_IP])
            .output()
            .await?;
        let _ping = Command::new("ping")
            .stdout(std::process::Stdio::null())
            .args(&["-f", "-c", "5", PEER_IP])
            .spawn()?;

        let mut buf = [0u8; 2048];

        async {
            for _ in 0..5 {
                t.read(&mut buf).await?;
            }
            Ok(()) as anyhow::Result<_>
        }
            .timeout(Duration::from_secs(2))
            .await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_get_mtu() -> anyhow::Result<()> {
        let name = OsStr::new("tun10");
        let tun = AsyncTun::open(name)?;

        Command::new("ifconfig")
            .arg(name)
            .args(&["mtu", "1280"])
            .output()
            .await?;
        let mtu = tun.get_mtu()?;
        assert_eq!(mtu, 1280);

        if cfg!(target_os = "linux") {
            Command::new("ip")
                .args(&["link", "set"])
                .arg(name)
                .args(&["name", "tun57"])
                .output()
                .await?;
        } else {
            // Assume BSD.
            Command::new("ifconfig")
                .arg(name)
                .args(&["name", "tun57"])
                .output()
                .await?;
        }
        Command::new("ifconfig")
            .arg("tun57")
            .args(&["mtu", "9000"])
            .output()
            .await?;
        let mtu = tun.get_mtu()?;
        assert_eq!(mtu, 9000);

        Ok(())
    }
}
