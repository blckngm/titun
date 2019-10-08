use failure::{Error, ResultExt};
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
        $e.with_context(|e| format!("{}: {}", stringify!($e), e))
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
