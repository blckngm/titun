// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

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

extern crate arrayvec;
extern crate byteorder;
#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
extern crate winreg;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[cfg(not(windows))]
#[macro_use]
extern crate nix;
extern crate ctrlc;
extern crate futures;
#[macro_use]
extern crate failure;
extern crate base64;
extern crate blake2_rfc;
#[macro_use]
extern crate combine;
extern crate fnv;
extern crate hex;
extern crate noise_protocol;
extern crate rand;
extern crate rust_sodium as sodiumoxide;
extern crate rust_sodium_sys as libsodium_sys;
extern crate socket2;
extern crate tai64;
extern crate tokio;
extern crate vec_map;

mod atomic;
mod crypto;
mod ipc;

#[doc(hidden)]
pub mod run;
mod systemd;
pub mod wireguard;
