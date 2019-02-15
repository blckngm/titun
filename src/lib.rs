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
#![feature(async_await, await_macro, futures_api, arbitrary_self_types)]

macro_rules! sleep {
    ($duration:expr) => {{
        use tokio::clock::now;
        use tokio::timer::Delay;

        await!(Delay::new(now() + $duration)).unwrap();
    }};
    (secs $secs:expr) => {{
        use std::time::Duration;
        sleep!(Duration::from_secs($secs));
    }};
    (ms $millis:expr) => {{
        use std::time::Duration;
        sleep!(Duration::from_millis($millis));
    }};
}

macro_rules! block_on_all_async {
    ($future:expr) => {{
        use futures::{FutureExt, TryFutureExt};

        tokio::runtime::current_thread::block_on_all($future.unit_error().boxed().compat()).unwrap()
    }};
}

macro_rules! spawn_async {
    ($future:expr) => {{
        use futures::{FutureExt, TryFutureExt};

        tokio::spawn($future.unit_error().boxed().compat())
    }};
}

#[cfg(feature = "bench")]
extern crate test;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
#[cfg(not(windows))]
#[macro_use]
extern crate nix;
#[macro_use]
extern crate tokio;
#[macro_use]
extern crate pin_utils;

mod cancellation;
mod crypto;
mod either;
mod ipc;
mod udp_socket;

#[doc(hidden)]
pub mod run;
mod systemd;
pub mod wireguard;
