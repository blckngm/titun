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

// This program tries to open a tun device, bring it up, ping the peer
// and read packets from it.

// Need to run with root.

// PING 192.0.2.7 (192.0.2.7) 56(84) bytes of data.
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// ...
#![feature(async_await)]

use failure::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    imp::main().await
}

#[cfg(unix)]
mod imp {
    use failure::Error;
    use std::process::{Child, Command};
    use titun::wireguard::AsyncTun;

    fn up_and_ping(name: &str) -> Result<Child, Error> {
        Command::new("ifconfig").args(&[name, "up"]).output()?;
        // The network 192.0.2.0/24 is TEST-NET, suitable for use in
        // documentation and examples.

        // Linux.
        #[cfg(target_os = "linux")]
        Command::new("ip")
            .args(&["addr", "add", "192.0.2.8", "peer", "192.0.2.7", "dev", name])
            .output()?;
        // BSD.
        #[cfg(not(target_os = "linux"))]
        Command::new("ifconfig")
            .args(&[name, "192.0.2.8", "192.0.2.7"])
            .output()?;
        Command::new("ping")
            .arg("192.0.2.7")
            .spawn()
            .map_err(From::from)
    }

    pub async fn main() -> Result<(), Error> {
        let t = AsyncTun::open("tun7")?;

        up_and_ping(t.get_name())?;

        let mut buf = [0u8; 2048];

        loop {
            let l = t.read(&mut buf).await?;
            println!("Got packet: {} bytes", l);
        }
    }
}

#[cfg(windows)]
mod imp {
    use failure::Error;

    pub async fn main() -> Result<(), Error> {
        Ok(())
    }
}
