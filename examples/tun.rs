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

// This program tries to open a tun device, bring it up, ping the peer
// and read packets from it.

// Need to run with root.

// Expected output:

// PING 192.0.2.7 (192.0.2.7) 56(84) bytes of data.
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// ...

extern crate failure;
extern crate titun;

use failure::Error;

fn main() -> Result<(), Error> {
    imp::main()
}

#[cfg(not(windows))]
mod imp {
    use failure::Error;
    use std::process::{Child, Command};
    use titun::wireguard::Tun;

    fn up_and_ping(name: &str) -> Result<Child, Error> {
        Command::new("ip")
            .args(&["link", "set", name, "up"])
            .output()?;
        // The network 192.0.2.0/24 is TEST-NET, suitable for use in
        // documentation and examples.
        Command::new("ip")
            .args(&["addr", "add", "192.0.2.8", "peer", "192.0.2.7", "dev", name])
            .output()?;
        Command::new("ping")
            .arg("192.0.2.7")
            .spawn()
            .map_err(From::from)
    }

    pub fn main() -> Result<(), Error> {
        let t = Tun::create(Some("tun-test-0"))?;

        up_and_ping(t.get_name())?;

        let mut buf = [0u8; 2048];

        loop {
            let l = t.read(&mut buf)?;
            println!("Got packet: {} bytes", l);
        }
    }
}

#[cfg(windows)]
mod imp {
    use failure::Error;

    pub fn main() -> Result<(), Error> {
        Ok(())
    }
}
