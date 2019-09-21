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

#![cfg_attr(feature = "bench", feature(test))]

#[cfg(feature = "bench")]
extern crate test;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

mod async_utils;
// Export for fuzzing.
#[doc(hidden)]
pub mod crypto;
// Export for fuzzing.
#[doc(hidden)]
pub mod ipc;
mod udp_socket;

mod systemd;
pub mod wireguard;

#[doc(hidden)]
pub mod cli;
