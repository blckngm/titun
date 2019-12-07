// Copyright 2019 Guanhao Yin <sopium@mysterious.site>

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

use super::*;

// Using a large capacity will cause stack overflow.
// https://github.com/rust-lang/rust/issues/53827
const TUN_RING_CAPACITY: usize = 128 * 1024;

#[repr(C)]
struct TunRing {
    // ABI compatible with u32, thus ULONG.
    head: AtomicU32,
    // ABI compatible with u32, thus ULONG.
    tail: AtomicU32,
    // ABI compatible with i32, thus LONG.
    alertable: AtomicI32,
    data: [u8; TUN_RING_CAPACITY + 0x10000],
}

fn _assert_ulong_is_u32() {
    let _x: ULONG = 0u32;
}

fn _assert_long_is_i32() {
    let _x: LONG = 0i32;
}

#[repr(C)]
struct TunRegisterRing {
    ring_size: u32,
    // ABI compatible with *mut TunRing.
    ring: Box<UnsafeCell<TunRing>>,
    // ABI compatible with HANDLE.
    tail_moved: HandleWrapper,
}

#[repr(C)]
pub struct TunRegisterRings {
    send: TunRegisterRing,
    receive: TunRegisterRing,
}

fn align_4(len: u32) -> u32 {
    (len + 0b11) & !0b11
}

impl TunRing {
    pub fn new() -> Self {
        unsafe { mem::zeroed() }
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        use core::convert::TryInto;

        let head = self.head.load(Ordering::SeqCst);
        let tail = self.tail.load(Ordering::SeqCst);
        if head == tail {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        if head >= TUN_RING_CAPACITY as u32 {
            error!("head >= CAPACITY");
            return Err(io::ErrorKind::InvalidData.into());
        }

        let len = u32::from_le_bytes(self.data[head as usize..][..4].try_into().unwrap());
        if len >= 0x10000 {
            error!("len >= 0x10000");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let new_head_unmod = head + 4 + align_4(len);
        let tail_unmod = if head > tail {
            tail + TUN_RING_CAPACITY as u32
        } else {
            tail
        };

        if new_head_unmod > tail_unmod {
            error!("head + len + 4 > tail (% CAPACITY)");
            return Err(io::ErrorKind::InvalidData.into());
        }

        let copy_len = std::cmp::min(len as usize, buf.len());
        buf[..copy_len].copy_from_slice(&self.data[head as usize + 4..][..copy_len]);

        let new_head = new_head_unmod % (TUN_RING_CAPACITY as u32);
        self.head.store(new_head, Ordering::SeqCst);

        Ok(copy_len)
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();

        if len >= 0x10000 {
            return Err(io::ErrorKind::InvalidInput.into());
        }

        let head = self.head.load(Ordering::SeqCst);
        let tail = self.tail.load(Ordering::SeqCst);

        if tail >= TUN_RING_CAPACITY as u32 {
            error!("tail >= CAPACITY");
            return Err(io::ErrorKind::InvalidData.into());
        }

        let head_unmod = if head > tail {
            head
        } else {
            head + TUN_RING_CAPACITY as u32
        };

        let new_tail_unmod = tail + 4 + align_4(len as u32);
        if new_tail_unmod >= head_unmod {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        let new_tail = new_tail_unmod % (TUN_RING_CAPACITY as u32);
        self.data[tail as usize..][..4].copy_from_slice(&u32::to_le_bytes(len as u32));
        self.data[tail as usize + 4..][..len].copy_from_slice(buf);

        self.tail.store(new_tail, Ordering::SeqCst);

        Ok(len)
    }
}

impl TunRegisterRing {
    fn new() -> io::Result<Self> {
        let tail_moved = unsafe_h!(CreateEventW(null_mut(), 0, 0, null_mut()))?;
        let ring = Box::new(UnsafeCell::new(TunRing::new()));
        Ok(Self {
            ring_size: mem::size_of::<TunRing>() as u32,
            ring,
            tail_moved,
        })
    }
}

impl TunRegisterRings {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            send: TunRegisterRing::new()?,
            receive: TunRegisterRing::new()?,
        })
    }

    /// # Safety
    ///
    /// Only one thread should call this.
    pub unsafe fn read(&self, buf: &mut [u8], canceled: HANDLE) -> io::Result<usize> {
        let send_ring = self.send.ring.get().as_mut().unwrap();
        let events = [self.send.tail_moved.0, canceled];
        loop {
            match send_ring.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    send_ring.alertable.store(1, Ordering::SeqCst);
                    match send_ring.read(buf) {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            let wait_result =
                                WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE);
                            match wait_result {
                                0 => (),
                                1 => return Err(io::ErrorKind::Interrupted.into()),
                                _ => unreachable!(),
                            }
                            send_ring.alertable.store(0, Ordering::SeqCst);
                            continue;
                        }
                        result => return result,
                    }
                }
                result => return result,
            }
        }
    }

    /// # Safety
    ///
    /// Only one thread should call this.
    pub unsafe fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let receive_ring = self.receive.ring.get().as_mut().unwrap();
        let result = receive_ring.write(buf);
        if let Err(ref e) = result {
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
        }
        if result.is_ok() && receive_ring.alertable.load(Ordering::SeqCst) != 0 {
            if SetEvent(self.receive.tail_moved.0) != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
            .expect("write SetEvent failed");
        }
        result
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
    fn test_align_4() {
        assert_eq!(align_4(4), 4);
        assert_eq!(align_4(5), 8);
        assert_eq!(align_4(6), 8);
        assert_eq!(align_4(7), 8);
        assert_eq!(align_4(8), 8);
    }

    #[test]
    fn test_ring_read_write() {
        let mut ring: TunRing = TunRing::new();
        let buf = [0u8; 7727];
        let mut read_buf = [0u8; 65536];

        for _ in 0..5 {
            // Write 10 packets, then read.
            for _ in 0..10 {
                ring.write(&buf[..]).unwrap();
            }

            for _ in 0..10 {
                let read_len = ring.read(&mut read_buf[..]).unwrap();
                assert_eq!(read_len, 7727);
            }

            // Write till full, then read all.
            let mut written_packets = 0;
            loop {
                match ring.write(&buf[..]) {
                    Ok(_) => {
                        written_packets += 1;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!(e),
                }
            }
            let mut read_packets = 0;
            loop {
                match ring.read(&mut read_buf[..]) {
                    Ok(len) => {
                        read_packets += 1;
                        assert_eq!(len, 7727);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!(e),
                }
            }
            assert_eq!(written_packets, read_packets);
        }
    }
}
