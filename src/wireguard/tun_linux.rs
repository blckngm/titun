// Copyright 2017, 2018 Guanhao Yin <sopium@mysterious.site>

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

#![cfg(target_os = "linux")]

use failure::Error;
use mio::event::Evented;
use mio::unix::{EventedFd, UnixReady};
use mio::{Poll, PollOpt, Ready, Token};
use nix::fcntl::{fcntl, open, FcntlArg, OFlag};
use nix::libc::c_short;
use nix::sys::stat::Mode;
use nix::unistd::{close, read, write};
use std::ffi::{CStr, CString};
use std::io::{self, Error as IOError, Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use tokio::prelude::{future, Async, Future};
use tokio::reactor::PollEvented2;

mod ioctl {
    use super::*;

    ioctl_write_int!(tunsetiff, b'T', 202);

    pub const IFF_TUN: c_short = 0x0001;
    pub const IFF_NO_PI: c_short = 0x1000;

    #[repr(C, align(4))]
    pub struct ifreq {
        pub name: [u8; 16], // Use u8 becuase that's what CString and CStr wants.
        pub flags: c_short,
    }
}

#[derive(Debug)]
pub struct AsyncTun {
    io: PollEvented2<Tun>,
}

impl AsyncTun {
    pub fn get_name(&self) -> &str {
        self.io.get_ref().get_name()
    }

    pub fn poll_read(&self, buf: &mut [u8]) -> Result<Async<usize>, IOError> {
        let ready = Ready::readable() | UnixReady::error();
        match self.io.poll_read_ready(ready) {
            Ok(Async::Ready(_)) => (),
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(e) => return Err(e),
        }
        match self.io.get_ref().read(buf) {
            Ok(x) => Ok(x.into()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(ready)?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn read_async<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl Future<Item = usize, Error = IOError> + 'a {
        future::poll_fn(move || self.poll_read(buf))
    }

    pub async fn write_async<'a>(&'a self, buf: &'a [u8]) -> Result<usize, IOError> {
        use tokio::prelude::AsyncWriteExt;

        let mut io = &self.io;

        await!(io.write_async(buf))
    }
}

/// A linux tun device.
#[derive(Debug)]
pub struct Tun {
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
    pub fn create(name: Option<&str>) -> Result<Tun, Error> {
        if let Some(n) = name {
            // IFNAMESIZ is 16.
            if n.len() > 15 {
                bail!("Device name is too long.");
            }
        }

        let name = CString::new(name.unwrap_or(""))?;
        let name = name.as_bytes_with_nul();

        let fd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;

        let mut ifr = ioctl::ifreq {
            name: [0; 16],
            flags: ioctl::IFF_TUN | ioctl::IFF_NO_PI,
        };

        ifr.name[..name.len()].copy_from_slice(name);

        unsafe { ioctl::tunsetiff(fd, &mut ifr as *mut _ as u64) }?;

        let namelen = ifr.name.iter().position(|x| *x == 0).unwrap() + 1;

        let name = CStr::from_bytes_with_nul(&ifr.name[..namelen])
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        Ok(Tun { fd, name })
    }

    pub fn create_async(name: Option<&str>) -> Result<AsyncTun, Error> {
        let tun = Tun::create(name)?;
        tun.set_nonblocking(true)?;
        Ok(AsyncTun {
            io: PollEvented2::new(tun),
        })
    }

    /// Get name of this device. Should be the same name if you have
    /// passed one in when createing the device.
    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<(), Error> {
        let flags = fcntl(self.fd, FcntlArg::F_GETFL)?;
        // XXX: Nix won't recognize O_LARGEFILE because libc O_LARGEFILE is 0!
        let mut flags = OFlag::from_bits_truncate(flags);
        flags.set(OFlag::O_NONBLOCK, nb);
        fcntl(self.fd, FcntlArg::F_SETFL(flags))?;
        Ok(())
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
        read(self.fd, buf).map_err(|_| IOError::last_os_error())
    }

    /// Write a packet to tun device.
    pub fn write(&self, buf: &[u8]) -> Result<usize, IOError> {
        write(self.fd, buf).map_err(|_| IOError::last_os_error())
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
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}
