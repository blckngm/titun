// Copyright 2020 Yin Guanhao <sopium@mysterious.site>

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

//！ AtomicU64 is not available on all targets. Fallback to `Mutex<u64>` when it
//! is not.

pub use imp::U64Counter;

// XXX: Use target_has_atomic when it's stable.
#[cfg(any(target_arch = "mips", target_arch = "powerpc"))]
mod imp {
    use parking_lot::Mutex;

    pub struct U64Counter {
        inner: Mutex<u64>,
    }

    impl U64Counter {
        pub fn new(value: u64) -> U64Counter {
            U64Counter {
                inner: value.into(),
            }
        }

        pub fn fetch_add(&self, val: u64) -> u64 {
            let mut guard = self.inner.lock();
            let old_value = *guard;
            *guard = old_value.wrapping_add(val);
            old_value
        }

        pub fn load(&self) -> u64 {
            *self.inner.lock()
        }
    }
}

#[cfg(not(any(target_arch = "mips", target_arch = "powerpc")))]
mod imp {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct U64Counter {
        inner: AtomicU64,
    }

    impl U64Counter {
        pub fn new(value: u64) -> U64Counter {
            U64Counter {
                inner: value.into(),
            }
        }

        pub fn fetch_add(&self, val: u64) -> u64 {
            self.inner.fetch_add(val, Ordering::Relaxed)
        }

        pub fn load(&self) -> u64 {
            self.inner.load(Ordering::Relaxed)
        }
    }
}
