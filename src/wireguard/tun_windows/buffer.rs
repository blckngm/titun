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

/// A more aligned buffer of bytes.
pub struct Buffer {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

impl Drop for Buffer {
    fn drop(&mut self) {
        use std::alloc::*;

        unsafe {
            dealloc(
                self.ptr,
                Layout::from_size_align(std::cmp::max(self.len, 1), 4).unwrap(),
            )
        }
    }
}

#[allow(dead_code)]
impl Buffer {
    pub fn new(len: usize) -> Self {
        use std::alloc::*;
        let layout = Layout::from_size_align(std::cmp::max(len, 1), 4).unwrap();
        let ptr = unsafe { alloc_zeroed(layout) };
        Self { ptr, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn as_slice_u16(&self) -> &[u16] {
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            std::slice::from_raw_parts(self.ptr as *const u16, self.len / 2)
        }
    }

    pub fn as_slice_u16_mut(&mut self) -> &mut [u16] {
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr as *mut u16, self.len / 2)
        }
    }
}
