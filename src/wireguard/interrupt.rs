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

//! Send a signal to interrupt blocking syscall on another thread.
//!
//! The signal SIGUSR2 is used.
//!
//! The `interrupt` function only interrupts a blocking syscall, if
//! there is one. It does not actually end or cancel that thread. It
//! is supposed to be used in conjunction with, e.g., an atomic
//! boolean flag.

#![cfg(unix)]

use failure::Error;
use nix::libc::{c_int, pthread_kill};
use nix::sys::signal::*;
use std::io::Error as IOError;
use std::os::unix::thread::JoinHandleExt;
use std::thread::JoinHandle;

extern "C" fn signal_handler_do_nothing(_: c_int) {}

const SIGNAL: Signal = Signal::SIGUSR2;

/// Setup signal handler.
pub fn init() -> Result<(), Error> {
    let handler = SigHandler::Handler(signal_handler_do_nothing);
    let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    unsafe {
        sigaction(SIGNAL, &action)?;
    }
    Ok(())
}

/// Send a signal to interrupt any blocking syscall.
pub fn interrupt<T>(j: &JoinHandle<T>) -> Result<(), Error> {
    unsafe {
        let errno = pthread_kill(j.as_pthread_t(), SIGNAL as c_int);
        if errno != 0 {
            Err(From::from(IOError::from_raw_os_error(errno)))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_interrupt() {
        super::init().unwrap();

        let t = thread::spawn(|| {
            // Ignore error.
            let _ = ::nix::unistd::pause();
        });

        thread::sleep(Duration::from_millis(100));

        interrupt(&t).unwrap();

        t.join().unwrap();
    }
}
