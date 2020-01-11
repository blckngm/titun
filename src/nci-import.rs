// Copyright 2020 Guanhao Yin <sopium@mysterious.site>

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

#![allow(unused_variables)]

pub type GUID = u128;

#[no_mangle]
pub extern "system" fn NciGetConnectionName(guid: &GUID, name: *mut u8, name_len: u32, out_len: &mut u32) -> u32 {
    0
}

#[no_mangle]
pub extern "system" fn NciSetConnectionName(guid: &GUID, name: *const u16) -> u32 {
    0
}
