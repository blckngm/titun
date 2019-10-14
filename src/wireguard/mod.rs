// Copyright 2017, 2019 Guanhao Yin <sopium@mysterious.site>

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

//! WireGuard protocol implementation.

/// Anti-Replay algorithm.
#[doc(hidden)]
pub mod anti_replay;
/// Cookie reply messages generation and parsing.
#[doc(hidden)]
pub mod cookie;
/// Handshake messages generation and parsing.
#[doc(hidden)]
pub mod handshake;
/// IP packet parsing.
mod ip;
/// Determine load.
#[doc(hidden)]
pub mod load_monitor;
/// Peer state.
mod peer_state;
/// The timer state machine, and actual IO stuff.
mod state;
#[doc(hidden)]
pub mod timer;
/// Transport, i.e., sessions.
mod transport;
/// Common types.
#[doc(hidden)]
pub mod types;

/// Tun device support on linux and BSDs.
mod tun_unix;
mod tun_windows;
#[cfg(unix)]
pub use self::tun_unix::*;
#[cfg(windows)]
pub use self::tun_windows::*;

/// Re-export some types and functions from noise, sodium, etc.
pub mod re_exports;

use self::anti_replay::*;
use self::cookie::*;
use self::handshake::*;
use self::ip::*;
use self::load_monitor::*;
use self::peer_state::*;
use self::state::*;
pub use self::state::{SetPeerCommand, WgState};
use self::timer::*;
use self::transport::*;
use self::types::*;
pub use self::types::{PeerInfo, PeerStateOut, WgInfo, WgStateOut, X25519Key, X25519Pubkey};
