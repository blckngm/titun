// Copyright 2019 Guanhao Yin <sopium@mysterious.site>

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

#![cfg(unix)]

use std::path::Path;

// Polling on BSD.
//
// It is not possible to use kqueue to watch delete events on a socket:
// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=170177
#[cfg(not(target_os = "linux"))]
pub async fn wait_delete(path: &Path) -> Result<(), failure::Error> {
    let (tx, rx) = futures::channel::oneshot::channel();
    let path = path.to_owned();
    std::thread::spawn(move || {
        loop {
            if !path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        tx.send(Ok(())).unwrap();
    });
    rx.await.unwrap()
}

#[cfg(target_os = "linux")]
pub async fn wait_delete(p: &Path) -> Result<(), failure::Error> {
    // Use inotify on linux.
    use inotify::{Inotify, WatchMask};
    use tokio::prelude::*;

    let mut inotify = Inotify::init()?;
    // DELETE_SELF does not get triggered until all opened file descriptors
    // are closed. So watch for ATTRIB as well.
    inotify.add_watch(p, WatchMask::ATTRIB | WatchMask::DELETE_SELF)?;
    let buf = vec![0u8; 1024];
    let mut stream = inotify.event_stream(buf);
    loop {
        let _event = stream.next().await.unwrap()?;
        if !p.exists() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wait_delete() {
        use crate::async_utils::*;
        use nix::unistd::{mkstemp, unlink};
        use std::time::Duration;

        tokio_block_on_all(async {
            let mut file = std::env::temp_dir();
            file.push("test_wait_delete_XXXXXX");
            let (_, tmp_path) = mkstemp(&file).expect("mkstemp");
            {
                let tmp_path = tmp_path.clone();
                tokio_spawn(async move {
                    delay(Duration::from_millis(10)).await;
                    unlink(&tmp_path).expect("unlink");
                });
            }
            wait_delete(&tmp_path).await.expect("wait delete");
            assert!(!tmp_path.exists());
        });
    }
}
