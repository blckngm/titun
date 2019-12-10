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

#![cfg(windows)]

//! Wintun support.

use std::cell::UnsafeCell;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::mem;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Context;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use wchar::*;
use widestring::*;
use winapi::shared::devguid::*;
use winapi::shared::guiddef::*;
use winapi::shared::minwindef::{FILETIME, HKEY};
use winapi::shared::ntdef::ULONG;
use winapi::shared::sddl::*;
use winapi::shared::winerror::*;
use winapi::um::cfgmgr32::*;
use winapi::um::combaseapi::*;
use winapi::um::fileapi::*;
use winapi::um::handleapi::*;
use winapi::um::ioapiset::*;
use winapi::um::minwinbase::*;
use winapi::um::namespaceapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::setupapi::*;
use winapi::um::synchapi::*;
use winapi::um::winbase::*;
use winapi::um::winioctl::*;
use winapi::um::winnt::*;
use winapi::um::winreg::*;
use winreg::RegKey;

macro_rules! unsafe_b {
    ($e:expr) => {{
        if unsafe { $e } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }};
}

macro_rules! unsafe_h {
    ($e:expr) => {{
        let r = unsafe { $e };
        if r.is_null() || r == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(HandleWrapper(r))
        }
    }};
}

macro_rules! unsafe_l {
    ($e:expr) => {{
        let r = unsafe { $e };
        if r != 0 {
            Err(io::Error::from_raw_os_error(r as i32))
        } else {
            Ok(())
        }
    }};
}

macro_rules! unsafe_cr {
    ($e:expr) => {{
        let r = unsafe { $e };
        match r {
            CR_SUCCESS => Ok(()),
            r => Err(anyhow::anyhow!("CR error, return value {}", r)),
        }
    }};
}

mod handle_wrapper;
use self::handle_wrapper::*;
mod pool;
use self::pool::*;
mod ring;
use self::ring::*;
mod interface;
use self::interface::*;
mod buffer;
use self::buffer::*;

/// A handle to a tun interface.
pub struct AsyncTun {
    handle: HandleWrapper,
    name: OsString,
    rings: TunRegisterRings,
    // A clone of `rings.send.tail_moved` (created by `DuplicateHandle`) wrapped
    // in `Arc` that can be sent to `spawn_blocking`.
    send_tail_moved_clone: Arc<HandleWrapper>,
    read_lock: AsyncMutex<()>,
    write_lock: Mutex<()>,
}

impl fmt::Debug for AsyncTun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncTun")
            .field("name", &self.name)
            .field("handle", &self.handle.0)
            .finish()
    }
}

#[allow(non_snake_case)]
const fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const TUN_IOCTL_REGISTER_RINGS: u32 = CTL_CODE(
    51820,
    0x970,
    METHOD_BUFFERED,
    FILE_READ_DATA | FILE_WRITE_DATA,
);

impl AsyncTun {
    /// Open a handle to a wintun interface.
    pub fn open(name: &OsStr) -> anyhow::Result<AsyncTun> {
        info!("opening wintun device {}", name.to_string_lossy());
        let interface = WINTUN_POOL.get_interface(name)?;
        if let Some(interface) = interface {
            interface.delete()?;
        }
        let interface = WINTUN_POOL.create_interface(name)?;
        let handle = interface.handle()?;
        let mut rings = TunRegisterRings::new()?;
        let mut _bytes_returned = 0u32;
        unsafe_b!(DeviceIoControl(
            handle.0,
            TUN_IOCTL_REGISTER_RINGS,
            &mut rings as *mut _ as *mut _,
            mem::size_of::<TunRegisterRings>() as u32,
            null_mut(),
            0,
            &mut _bytes_returned,
            null_mut(),
        ))
        .context("DeviceIoControl TUN_IOCTL_REGISTER_RINGS")?;

        let send_tail_moved_clone = {
            let mut handle: HANDLE = null_mut();
            let self_process = unsafe { GetCurrentProcess() };
            unsafe_b!(DuplicateHandle(
                self_process,
                rings.send.tail_moved.0,
                self_process,
                &mut handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ))
            .context("DuplicateHandle")?;
            Arc::new(HandleWrapper(handle))
        };

        Ok(Self {
            handle,
            name: name.into(),
            rings,
            send_tail_moved_clone,
            read_lock: AsyncMutex::new(()),
            write_lock: Mutex::new(()),
        })
    }

    /// Read a packet from the interface.
    ///
    /// Blocking.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let _read_lock_guard = self.read_lock.lock().await;
        unsafe { self.rings.read(buf, &self.send_tail_moved_clone).await }
    }

    /// Write a packet to the interface.
    ///
    /// Does not block.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let _write_lock_guard = self.write_lock.lock();
        unsafe { self.rings.write(buf) }
    }

    fn close(&self) -> anyhow::Result<()> {
        info!("closing wintun interface");
        let it = WINTUN_POOL
            .get_interface(&self.name)
            .context("get_iterface")?
            .ok_or_else(|| anyhow::anyhow!("get_interface None"))?;
        it.delete().context("delete")?;
        info!("closed wintun interface");
        Ok(())
    }
}

impl Drop for AsyncTun {
    fn drop(&mut self) {
        self.close()
            .unwrap_or_else(|e| warn!("failed to close tun: {:#}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_TUN_IOCTL_REGISTER_RINGS_value() {
        assert_eq!(TUN_IOCTL_REGISTER_RINGS, 0xca6c_e5c0);
    }

    #[test]
    fn test_open_and_close() {
        let _ = env_logger::try_init();
        let t = AsyncTun::open(OsStr::new("tun0"));
        println!("Tun::open(): {:?}", t);
    }
}
