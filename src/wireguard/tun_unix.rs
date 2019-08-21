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

use failure::Error;
use futures::future::poll_fn;
use futures::ready;
use mio::event::Evented;
use mio::unix::{EventedFd, UnixReady};
use mio::{Poll as MioPoll, PollOpt, Ready, Token};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{close, read, write};
use std::io::{self, Error as IOError, Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::task::{Context, Poll};
use tokio_net::util::PollEvented;

#[allow(unused)]
mod ioctl {
    use nix::libc::c_short;
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

    // FreeBSD.
    ioctl_write_ptr!(tunsifhead, b't', 96, i32);
}

#[derive(Debug)]
pub struct AsyncTun {
    io: PollEvented<Tun>,
}

impl AsyncTun {
    pub fn open(name: impl AsRef<str>) -> Result<AsyncTun, Error> {
        let tun = Tun::open(name.as_ref(), OFlag::O_NONBLOCK)?;
        Ok(AsyncTun {
            io: PollEvented::new(tun),
        })
    }

    pub fn get_name(&self) -> &str {
        self.io.get_ref().get_name()
    }

    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, IOError>> {
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

    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IOError>> {
        ready!(self.io.poll_write_ready(cx))?;

        match self.io.get_ref().write(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    // Should be used from only one task.
    pub async fn read<'a>(&'a self, buf: &'a mut [u8]) -> Result<usize, IOError> {
        poll_fn(|cx| self.poll_read(cx, buf)).await
    }

    // Should be used from only one task.
    pub async fn write<'a>(&'a self, buf: &'a [u8]) -> Result<usize, IOError> {
        poll_fn(|cx| self.poll_write(cx, buf)).await
    }
}

/// A linux tun device.
#[derive(Debug)]
struct Tun {
    fd: i32,
    name: String,
}

/// The file descriptor will be closed when the Tun is dropped.
impl Drop for Tun {
    fn drop(&mut self) {
        // Ignore error...
        let _ = close(self.fd);
    }
}

impl Tun {
    /// Create a tun device.

    /// O_CLOEXEC, IFF_NO_PI.
    #[cfg(target_os = "linux")]
    pub fn open(name: &str, extra_flags: OFlag) -> Result<Tun, Error> {
        use std::ffi::{CStr, CString};

        if name.len() > 15 {
            bail!("Device name is too long.");
        }

        let name = CString::new(name)?;
        let name = name.as_bytes_with_nul();

        let fd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_CLOEXEC | extra_flags,
            Mode::empty(),
        )?;

        // Make the `fd` owned by a `Tun`, so that if any
        // error occurs below, the `fd` is `close`d.
        let mut tun = Tun {
            fd,
            name: "".to_string(),
        };

        let mut ifr = ioctl::ifreq {
            name: [0; 16],
            flags: ioctl::IFF_TUN | ioctl::IFF_NO_PI,
        };

        ifr.name[..name.len()].copy_from_slice(name);

        unsafe { ioctl::tunsetiff(fd, &mut ifr as *mut _ as _) }?;

        let namelen = ifr.name.iter().position(|x| *x == 0).unwrap() + 1;

        let name = CStr::from_bytes_with_nul(&ifr.name[..namelen])
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        tun.name = name;
        Ok(tun)
    }

    // BSD systems.
    #[cfg(not(target_os = "linux"))]
    pub fn open(name: &str, extra_flags: OFlag) -> Result<Tun, Error> {
        use std::path::Path;

        let name = name.to_string();
        if !name.starts_with("tun") || name[3..].parse::<u32>().is_err() {
            bail!(
                "Invalid tun device name {}: must be tunN where N is an integer.",
                name
            );
        }
        let fd = open(
            &Path::new("/dev").join(&name),
            OFlag::O_CLOEXEC | OFlag::O_RDWR | extra_flags,
            Mode::empty(),
        )?;
        let tun = Tun { fd, name };

        if cfg!(target_os = "freebsd") {
            unsafe {
                // Call TUNSIFHEAD, without this, IPv6 in tunnel won't work.
                ioctl::tunsifhead(fd, &mut 1)?;
            }
        }

        Ok(tun)
    }

    /// Get name of this device. Should be the same name if you have
    /// passed one in when createing the device.
    pub fn get_name(&self) -> &str {
        self.name.as_str()
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
    /// Read a packet from the tun device.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, IOError> {
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
            .map_err(|_| IOError::last_os_error())
        } else {
            read(self.fd, buf).map_err(|_| IOError::last_os_error())
        }
    }

    /// Write a packet to tun device.
    pub fn write(&self, buf: &[u8]) -> Result<usize, IOError> {
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
            .map_err(|_| IOError::last_os_error())
        } else {
            write(self.fd, buf).map_err(|_| IOError::last_os_error())
        }
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IOError> {
        Tun::read(self, buf)
    }
}

impl<'a> Read for &'a Tun {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IOError> {
        Tun::read(self, buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IOError> {
        Tun::write(self, buf)
    }

    /// flush() for Tun is a no-op.
    fn flush(&mut self) -> Result<(), IOError> {
        Ok(())
    }
}

impl<'a> Write for &'a Tun {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IOError> {
        Tun::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), IOError> {
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
