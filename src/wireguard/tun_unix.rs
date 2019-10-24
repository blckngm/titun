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
use nix::libc::{if_indextoname, if_nametoindex, IF_NAMESIZE};
use nix::sys::stat::Mode;
use nix::unistd::{close, read, write};
use std::ffi::CString;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::task::{Context, Poll};
use tokio_net::util::PollEvented;

#[allow(unused)]
mod ioctl {
    use nix::libc::{c_int, c_short};
    use nix::*;

    // Linux.
    ioctl_write_int!(tunsetiff, b'T', 202);

    pub const IFF_TUN: c_short = 0x0001;
    pub const IFF_NO_PI: c_short = 0x1000;

    #[repr(C, align(4))]
    pub struct ifreq {
        pub name: [u8; 16], // Use u8 becuase that's what CString and CStr wants.
        pub flags: c_short,
    }

    #[repr(C)]
    pub struct ifreq_mtu {
        pub name: [u8; 16],
        pub mtu: c_int,
    }

    #[cfg(target_os = "linux")]
    ioctl_readwrite_bad!(siocgifmtu, nix::libc::SIOCGIFMTU, ifreq_mtu);
    #[cfg(target_os = "freebsd")]
    ioctl_readwrite_bad!(siocgifmtu, 3223349555, ifreq_mtu);

    // FreeBSD.
    ioctl_write_ptr!(tunsifhead, b't', 96, i32);
}

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

    pub fn get_mtu(&self) -> io::Result<u32> {
        use nix::sys::socket::*;
        unsafe {
            let mut req: ioctl::ifreq_mtu = mem::zeroed();
            assert_eq!(IF_NAMESIZE, 16);
            if if_indextoname(self.io.get_ref().index, req.name.as_mut_ptr() as *mut _).is_null() {
                return Err(io::Error::last_os_error());
            }
            let socket = socket(
                AddressFamily::Inet,
                SockType::Datagram,
                SockFlag::SOCK_CLOEXEC,
                None,
            )
            .map_err(|_| io::Error::last_os_error())?;
            match ioctl::siocgifmtu(socket, &mut req) {
                Ok(_) => {
                    let _ = close(socket);
                    Ok(req.mtu as u32)
                }
                Err(_) => {
                    let e = io::Error::last_os_error();
                    let _ = close(socket);
                    Err(e)
                }
            }
        }
    }

    // Should be used from only one task.
    pub async fn read<'a>(&'a self, buf: &'a mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_read(cx, buf)).await
    }

    // Should be used from only one task.
    pub async fn write<'a>(&'a self, buf: &'a [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_write(cx, buf)).await
    }
}

/// A linux tun interface.
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
        if name.len() > 15 {
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

        let mut ifr = ioctl::ifreq {
            name: [0; 16],
            flags: ioctl::IFF_TUN | ioctl::IFF_NO_PI,
        };

        ifr.name[..name_c_bytes.len()].copy_from_slice(name_c_bytes);

        unsafe { ioctl::tunsetiff(fd, &mut ifr as *mut _ as _) }?;
        // XXX: possible race if another process changes the name before we get
        // the index.
        tun.index = unsafe {
            let r = if_nametoindex(name_c_bytes.as_ptr() as *const _);
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
    #[cfg(not(target_os = "linux"))]
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
        tun.index = unsafe {
            let r = if_nametoindex(name_c_bytes.as_ptr() as *const _);
            if r > 0 {
                Ok(r)
            } else {
                Err(io::Error::last_os_error())
            }
        }
        .context("get interface index")?;

        if cfg!(target_os = "freebsd") {
            unsafe {
                // Call TUNSIFHEAD, without this, IPv6 in tunnel won't work.
                ioctl::tunsifhead(fd, &mut 1)?;
            }
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

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Tun::read(self, buf)
    }
}

impl<'a> Read for &'a Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Tun::read(self, buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Tun::write(self, buf)
    }

    /// flush() for Tun is a no-op.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Tun::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
