// Copyright 2017,2019 Guanhao Yin <sopium@mysterious.site>

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

#![cfg(not(windows))]

pub fn notify_ready() -> anyhow::Result<()> {
    use std::env::var_os;
    use std::os::unix::net::UnixDatagram;

    if let Some(notify_socket) = var_os("NOTIFY_SOCKET") {
        let socket = UnixDatagram::unbound()?;
        socket.connect(notify_socket)?;
        socket.send(b"READY=1")?;
    }
    Ok(())
}
