// Copyright 2019 Yin Guanhao <sopium@mysterious.site>

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

mod config;
#[cfg(unix)]
pub mod daemonize;
mod real_main;
#[cfg(unix)]
mod reload;
mod run;
#[cfg(unix)]
mod show;
mod systemd;
pub mod transform;

pub use config::*;
#[doc(hidden)]
pub use real_main::real_main;
#[cfg(unix)]
pub use reload::reload;
pub use run::*;
#[cfg(unix)]
pub use show::show;
