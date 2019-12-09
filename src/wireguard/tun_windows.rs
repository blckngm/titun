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
use tokio::sync::mpsc::{channel, Receiver, Sender};
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
use winapi::um::securitybaseapi::*;
use winapi::um::setupapi::*;
use winapi::um::synchapi::*;
use winapi::um::winbase::*;
use winapi::um::winioctl::*;
use winapi::um::winnt::*;
use winapi::um::winreg::*;
use winreg::RegKey;

// Can't get create_interface to work. Use the wireguard-go dll for now.
const USE_RUST_SETUP_API: bool = false;

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

pub struct AsyncTun {
    tun: Arc<Tun>,
    channels: AsyncMutex<TunChannels>,
}

struct TunChannels {
    read_rx: Receiver<io::Result<(Box<[u8]>, usize)>>,
    buffer_tx: Sender<Box<[u8]>>,
}

impl Drop for AsyncTun {
    fn drop(&mut self) {
        self.tun.interrupt();
    }
}

impl AsyncTun {
    pub fn open(name: &OsStr) -> anyhow::Result<AsyncTun> {
        let tun = Tun::open(name)?;
        Ok(AsyncTun::new(tun))
    }

    fn new(tun: Tun) -> AsyncTun {
        let tun = Arc::new(tun);
        // read thread -> async fn read.
        let (mut read_tx, read_rx) = channel(2);
        // async fn read -> read thread, to reuse buffers.
        let (mut buffer_tx, mut buffer_rx) = channel::<Box<[u8]>>(2);
        buffer_tx.try_send(vec![0u8; 65536].into()).unwrap();
        buffer_tx.try_send(vec![0u8; 65536].into()).unwrap();
        // We run this in a separate thread so that the wintun intance can be
        // dropped.
        //
        // We let tokio manage this thread so that the tokio runtime is not
        // dropped before the wintun instance.
        tokio::spawn({
            let tun = tun.clone();
            async move {
                'outer: loop {
                    let mut buf = match buffer_rx.recv().await {
                        None => break,
                        Some(buf) => buf,
                    };
                    // We don't want to consume the `buf` when we get an
                    // `Err`. So loop until we get an `Ok`.
                    loop {
                        match tokio::task::block_in_place(|| tun.read(&mut buf[..])) {
                            Err(e) => {
                                if read_tx.send(Err(e)).await.is_err() {
                                    break 'outer;
                                }
                            }
                            Ok(len) => {
                                if read_tx.send(Ok((buf, len))).await.is_err() {
                                    break 'outer;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        });
        AsyncTun {
            tun,
            channels: AsyncMutex::new(TunChannels { read_rx, buffer_tx }),
        }
    }

    pub(crate) async fn read<'a>(&'a self, buf: &'a mut [u8]) -> io::Result<usize> {
        // Don't use `blocking` for operations that may block forever.

        let mut channels = self.channels.lock().await;

        let (p, p_len) = channels.read_rx.recv().await.unwrap()?;
        let len = std::cmp::min(p_len, buf.len());
        buf[..len].copy_from_slice(&p[..len]);
        channels.buffer_tx.send(p).await.unwrap();
        Ok(len)
    }

    pub(crate) async fn write<'a>(&'a self, buf: &'a [u8]) -> io::Result<usize> {
        self.tun.write(buf)
    }
}

/// A handle to a tun interface.
struct Tun {
    handle: HandleWrapper,
    name: OsString,
    rings: TunRegisterRings,
    read_lock: Mutex<()>,
    write_lock: Mutex<()>,
    cancel_event: HandleWrapper,
}

impl fmt::Debug for Tun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tun")
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

impl Tun {
    /// Open a handle to a wintun interface.
    pub fn open(name: &OsStr) -> anyhow::Result<Tun> {
        info!("opening wintun device {}", name.to_string_lossy());
        let handle = if USE_RUST_SETUP_API {
            let interface = WINTUN_POOL.get_interface(name)?;
            if let Some(interface) = interface {
                interface.delete()?;
            }
            let interface = WINTUN_POOL.create_interface(name)?;
            interface.handle()?
        } else {
            let name = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid name"))?;
            let handle = unsafe { WintunOpen(name.as_ptr(), name.len() as i32) };
            if handle.is_null() {
                bail!("wintun_create failed");
            }
            HandleWrapper(handle)
        };
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

        let cancel_event =
            unsafe_h!(CreateEventW(null_mut(), 1, 0, null_mut())).context("CreateEventW")?;

        Ok(Self {
            handle,
            name: name.into(),
            rings,
            read_lock: Mutex::new(()),
            write_lock: Mutex::new(()),
            cancel_event,
        })
    }

    /// Read a packet from the interface.
    ///
    /// Blocking.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let _read_lock_guard = self.read_lock.lock();
        unsafe { self.rings.read(buf, self.cancel_event.0) }
    }

    /// Write a packet to the interface.
    ///
    /// Does not block.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let _write_lock_guard = self.write_lock.lock();
        unsafe { self.rings.write(buf) }
    }

    /// Interrupt a blocking read operation on this Tun interface.
    pub fn interrupt(&self) {
        debug!("interrupt tun read");
        unsafe_b!(SetEvent(self.cancel_event.0)).unwrap();
    }

    fn close(&self) -> anyhow::Result<()> {
        info!("closing wintun interface");
        if USE_RUST_SETUP_API {
            let it = WINTUN_POOL
                .get_interface(&self.name)
                .context("get_iterface")?
                .ok_or_else(|| anyhow::anyhow!("get_interface None"))?;
            it.delete().context("delete")?;
            info!("closed wintun interface");
            Ok(())
        } else {
            let name = self.name.to_str().unwrap();
            unsafe {
                WintunClose(name.as_ptr(), name.len() as i32);
            }
            info!("closed wintun interface");
            Ok(())
        }
    }
}

unsafe impl Sync for Tun {}
unsafe impl Send for Tun {}

impl Drop for Tun {
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
        let t = Tun::open(OsStr::new("tun0"));
        println!("Tun::open(): {:?}", t);
    }
}
