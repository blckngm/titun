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

// Define our own todo before it is in stable.
#[allow(unused)]
macro_rules! todo {
    () => {
        unimplemented!()
    };
}

#[macro_use]
extern crate anyhow;
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

pub mod wireguard;

#[doc(hidden)]
pub mod cli;
