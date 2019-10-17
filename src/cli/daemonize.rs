// Copyright 2019 Yin Guanhao <sopium@mysterious.site>

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

use anyhow::{Context, Error};
use nix;
use nix::sys::stat::{umask, Mode};
use nix::unistd::*;
use std::os::unix::io::RawFd;
use std::process::exit;

pub struct NotifyHandle {
    fd: RawFd,
}

impl NotifyHandle {
    pub fn notify(&self, status: u8) -> nix::Result<()> {
        write(self.fd, &[status])?;
        Ok(())
    }
}

impl Drop for NotifyHandle {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

macro_rules! ctx {
    ($e:expr) => {
        $e.context(stringify!($e))
    };
}

pub fn daemonize() -> Result<NotifyHandle, Error> {
    let (r, w) = ctx!(pipe())?;

    if ctx!(fork())?.is_parent() {
        close(w)?;
        let mut buf = [0u8; 1];
        let len = read(r, &mut buf)?;
        if len == 1 {
            exit(buf[0].into());
        } else {
            exit(1);
        }
    }
    let notify_handle = NotifyHandle { fd: w };
    ctx!(close(r))?;

    ctx!(chdir("/"))?;
    ctx!(setsid())?;
    umask(Mode::from_bits(0o027).unwrap());

    if ctx!(fork())?.is_parent() {
        std::process::exit(0);
    }

    Ok(notify_handle)
}
