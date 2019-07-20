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

//! Tap-windows TUN devices support.

use crate::async_utils::blocking;

use std::ffi::CString;
use std::fmt;
use std::io::{self, Error, ErrorKind, Read, Write};
use std::mem::zeroed;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::sync::Arc;

use futures::channel::mpsc::{channel, Receiver, Sender};
use futures::lock::Mutex as AsyncMutex;
use futures::prelude::*;
use parking_lot::Mutex;
use winapi::shared::winerror::ERROR_IO_PENDING;
use winapi::um::fileapi::{CreateFileA, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::{DeviceIoControl, GetOverlappedResult};
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::synchapi::{CreateEventA, SetEvent, WaitForMultipleObjects, WaitForSingleObject};
use winapi::um::winbase::{FILE_FLAG_OVERLAPPED, INFINITE};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use winreg::enums::*;
use winreg::RegKey;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const fn tap_control_code(request: u32, method: u32) -> u32 {
    ctl_code(34, request, method, 0)
}

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
    pub fn open(alias: &str, network: NetworkConfig) -> io::Result<AsyncTun> {
        let tun = Tun::open(alias, network)?;
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
        std::thread::spawn({
            let tun = tun.clone();
            move || {
                futures::executor::block_on(async move {
                    'outer: loop {
                        let mut buf = match buffer_rx.next().await {
                            None => break,
                            Some(buf) => buf,
                        };
                        // We don't want to consume the `buf` when we get an
                        // `Err`. So loop until we get an `Ok`.
                        loop {
                            match tun.read(&mut buf[..]) {
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
                });
            }
        });
        AsyncTun {
            tun,
            channels: AsyncMutex::new(TunChannels { read_rx, buffer_tx }),
        }
    }

    pub async fn read<'a>(&'a self, buf: &'a mut [u8]) -> io::Result<usize> {
        // Don't use `blocking` for operations that may block forever.

        let mut channels = self.channels.lock().await;

        let (p, p_len) = channels.read_rx.next().await.unwrap()?;
        let len = std::cmp::min(p_len, buf.len());
        buf[..len].copy_from_slice(&p[..len]);
        channels.buffer_tx.send(p).await.unwrap();
        Ok(len)
    }

    pub async fn write<'a>(&'a self, buf: &'a [u8]) -> io::Result<usize> {
        blocking(|| self.tun.write(buf)).await
    }
}

/// A handle to a tun device.
struct Tun {
    handle: HandleWrapper,
    read_overlapped: Mutex<OverlappedWrapper>,
    write_overlapped: Mutex<OverlappedWrapper>,
    cancel_event: HandleWrapper,
}

impl fmt::Debug for Tun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Tun")
            .field("handle", &self.handle.0)
            .finish()
    }
}

/// HANDLE wrapper that automatically closes.
#[derive(Debug)]
struct HandleWrapper(HANDLE);

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Overlapped wrapper that automatically creates and closes `hEvent`.
struct OverlappedWrapper {
    o: OVERLAPPED,
}

impl OverlappedWrapper {
    fn new() -> io::Result<OverlappedWrapper> {
        unsafe {
            let mut o: OVERLAPPED = zeroed();
            o.hEvent = CreateEventA(null_mut(), 0, 0, null_mut());
            if o.hEvent.is_null() {
                return Err(Error::last_os_error());
            }
            Ok(OverlappedWrapper { o })
        }
    }
}

impl Drop for OverlappedWrapper {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.o.hEvent);
        }
    }
}

macro_rules! continue_on_error {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(_) => continue,
        }
    };
}

/// Get network interface GUID from alias.
fn get_netcfg_instance_id(alias: &str) -> io::Result<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let connections = hklm.open_subkey(
        r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}",
    )?;
    for guid in connections.enum_keys() {
        // Could fail because \Connection does not exist, or because permission denied, continue.
        let guid = continue_on_error!(guid);
        let conn = continue_on_error!(connections.open_subkey(format!("{}\\Connection", guid)));
        let name: String = continue_on_error!(conn.get_value("Name"));
        if name == alias {
            return Ok(guid);
        }
    }
    Err(Error::from(ErrorKind::NotFound))
}

/// Show warning if interface is not a tap-windows device.
fn check_interface_is_tap(guid: &str) -> io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let adapters = hklm.open_subkey(
        r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}",
    )?;
    for a in adapters.enum_keys() {
        // Continue if cannot open.
        let a = continue_on_error!(a);
        let adapter = continue_on_error!(adapters.open_subkey(a));
        let instance_id: String = adapter.get_value("NetCfgInstanceId")?;
        if instance_id == guid {
            // Found matching interface.
            let component_id: String = adapter.get_value("ComponentId")?;
            if component_id != "tap0901" {
                warn!("The interface does not seem to be a Tap-Windows device.");
            }
            return Ok(());
        }
    }
    Err(Error::from(ErrorKind::NotFound))
}

type NetworkConfig = (Ipv4Addr, u32);

fn to_octets(n: NetworkConfig) -> [u8; 12] {
    assert!(n.1 <= 32);
    let mask = if n.1 == 0 {
        0u32
    } else {
        (!0u32) << (32 - n.1)
    };
    let network = u32::from(n.0) & mask;
    let mut output = [0u8; 12];
    output[0..4].copy_from_slice(&n.0.octets());
    output[4..8].copy_from_slice(&Ipv4Addr::from(network).octets());
    output[8..12].copy_from_slice(&Ipv4Addr::from(mask).octets());
    output
}

#[cfg(test)]
#[test]
fn test_to_octets() {
    let n = (Ipv4Addr::new(192, 168, 2, 9), 24);
    assert_eq!(
        to_octets(n),
        [192, 168, 2, 9, 192, 168, 2, 0, 255, 255, 255, 0]
    );
}

impl Tun {
    /// Open a handle to a tun device.
    ///
    /// The device should have already been created. If it does not exist, this function returns NOT_FOUND.
    ///
    /// * `alias` - e.g., `Local Area Network 2`.
    /// * `network` - Network configuration. Used in `TAP_IOCTL_CONFIG_TUN`.
    #[allow(non_snake_case)]
    pub fn open(alias: &str, network: NetworkConfig) -> io::Result<Tun> {
        let instance_id = get_netcfg_instance_id(alias)?;
        check_interface_is_tap(&instance_id)
            .unwrap_or_else(|e| warn!("Error checking interface: {}", e));
        let file_name = CString::new(format!("\\\\.\\Global\\{}.tap", instance_id)).unwrap();
        unsafe {
            // CreateFile.
            let handle = CreateFileA(
                file_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(Error::last_os_error());
            }
            let handle = HandleWrapper(handle);

            // DeviceIoControl, TAP_IOCTL_SET_MEDIA_STATUS.
            let TAP_IOCTL_SET_MEDIA_STATUS: u32 = tap_control_code(6, 0);
            let mut output_buffer = [0u8; 8];
            let mut bytes_returned = 0;
            let input = [1u8, 0, 0, 0];
            let result1 = DeviceIoControl(
                handle.0,
                TAP_IOCTL_SET_MEDIA_STATUS,
                input.as_ptr() as *mut _,
                4,
                output_buffer.as_mut_ptr() as *mut _,
                output_buffer.len() as u32,
                &mut bytes_returned,
                null_mut(),
            );
            if result1 == 0 {
                return Err(Error::last_os_error());
            }

            // DeviceIoControl, TAP_IOCTL_CONFIG_TUN.
            let TAP_IOCTL_CONFIG_TUN = tap_control_code(10, 0);
            let network_config = to_octets(network);
            let result2 = DeviceIoControl(
                handle.0,
                TAP_IOCTL_CONFIG_TUN,
                network_config.as_ptr() as *mut _,
                12,
                output_buffer.as_mut_ptr() as *mut _,
                output_buffer.len() as u32,
                &mut bytes_returned,
                null_mut(),
            );
            if result2 == 0 {
                return Err(Error::last_os_error());
            }

            let cancel_event = CreateEventA(null_mut(), 0, 0, null_mut());
            if cancel_event.is_null() {
                return Err(Error::last_os_error());
            }
            let cancel_event = HandleWrapper(cancel_event);

            Ok(Tun {
                handle,
                read_overlapped: Mutex::new(OverlappedWrapper::new()?),
                write_overlapped: Mutex::new(OverlappedWrapper::new()?),
                cancel_event,
            })
        }
    }

    /// Read a packet from the device.
    ///
    /// Blocking.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0;
        unsafe {
            let mut ow = self.read_overlapped.lock();
            let o = &mut ow.o;
            let result = ReadFile(
                self.handle.0,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_read,
                o,
            );
            if result != 0 {
                return Ok(bytes_read as usize);
            }
            let err = Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(err);
            }
            let events = [o.hEvent, self.cancel_event.0];
            let wait_result = WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE);
            match wait_result {
                // cancel_event is signaled.
                1 => return Err(Error::new(ErrorKind::Interrupted, "operation canceled")),
                // o.hEvent is signaled.
                0 => (),
                // Error.
                0xffff_ffff => return Err(Error::last_os_error()),
                _ => panic!("Unexppected wait result {}", wait_result),
            }
            let result = GetOverlappedResult(self.handle.0, o, &mut bytes_read, 0);
            if result == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(bytes_read as usize)
            }
        }
    }

    /// Write a packet to the device.
    ///
    /// Blocking.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0;
        unsafe {
            let mut ow = self.write_overlapped.lock();
            let o = &mut ow.o;
            let result = WriteFile(
                self.handle.0,
                buf.as_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_written,
                o,
            );
            if result != 0 {
                return Ok(bytes_written as usize);
            }
            let err = Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(err);
            }
            WaitForSingleObject(o.hEvent, INFINITE);
            let result = GetOverlappedResult(self.handle.0, o, &mut bytes_written, 0);
            if result == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(bytes_written as usize)
            }
        }
    }

    /// Interrupt a blocking read operation on this Tun device.
    pub fn interrupt(&self) {
        unsafe {
            SetEvent(self.cancel_event.0);
        }
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Tun::read(self, buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Tun::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

unsafe impl Sync for Tun {}
unsafe impl Send for Tun {}
