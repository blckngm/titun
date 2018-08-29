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

pub use self::imp::AtomicU64;
pub use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(target_pointer_width = "64")]
mod imp {
    use super::*;

    pub struct AtomicU64 {
        inner: AtomicUsize,
    }

    impl AtomicU64 {
        pub fn new(val: u64) -> AtomicU64 {
            AtomicU64 {
                inner: AtomicUsize::new(val as usize),
            }
        }

        pub fn load(&self, ordering: Ordering) -> u64 {
            self.inner.load(ordering) as u64
        }

        pub fn fetch_add(&self, val: u64, ordering: Ordering) -> u64 {
            self.inner.fetch_add(val as usize, ordering) as u64
        }
    }
}

#[cfg(not(target_pointer_width = "64"))]
mod imp {
    use super::*;
    use std::sync::Mutex;

    pub struct AtomicU64 {
        inner: Mutex<u64>,
    }

    impl AtomicU64 {
        pub fn new(val: u64) -> AtomicU64 {
            AtomicU64 {
                inner: Mutex::new(val),
            }
        }

        pub fn load(&self, _: Ordering) -> u64 {
            *self.inner.lock().unwrap()
        }

        pub fn fetch_add(&self, val: u64, _: Ordering) -> u64 {
            let mut lock = self.inner.lock().unwrap();
            let prev = *lock;
            *lock = prev + val;
            prev
        }
    }
}
