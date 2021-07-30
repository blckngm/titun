// Copyright 2017, 2018 Guanhao Yin <sopium@mysterious.site>

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
#![allow(clippy::result_unit_err)]

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;

mod async_utils;
mod utils;

// Export for fuzzing.
#[doc(hidden)]
pub mod crypto;
// Export for fuzzing.
#[doc(hidden)]
pub mod ipc;

pub mod wireguard;

#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod windows_gui;
