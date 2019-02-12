// Copyright 2018 Guanhao Yin <sopium@mysterious.site>

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

use futures::channel::mpsc::*;
use futures::prelude::*;

pub struct CancellationTokenSource {
    receiver: Receiver<()>,
    sender: Sender<()>,
}

pub struct CancellationToken {
    sender: Sender<()>,
}

impl Default for CancellationTokenSource {
    fn default() -> CancellationTokenSource {
        CancellationTokenSource::new()
    }
}

impl CancellationTokenSource {
    pub fn new() -> Self {
        let (sender, receiver) = channel(0);
        CancellationTokenSource { receiver, sender }
    }

    pub fn cancel(&mut self) {
        self.receiver.close();
    }

    pub fn get_token(&self) -> CancellationToken {
        CancellationToken {
            sender: self.sender.clone(),
        }
    }

    pub fn spawn_async<T>(&self, future: T)
    where
        T: Future<Output = ()> + Send + 'static,
    {
        let cancelled = self.get_token().cancelled().fuse();
        spawn_async!(
            async move {
                pin_mut!(cancelled);
                let f = future.fuse();
                pin_mut!(f);
                select! {
                    _ = cancelled => (),
                    _ = f => (),
                }
            }
        );
    }
}

impl CancellationToken {
    pub async fn cancelled(mut self) {
        let mut infinite = stream::repeat(());
        await!(self.sender.send_all(&mut infinite)).unwrap_err();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation() {
        block_on_all_async!(
            async {
                let source = CancellationTokenSource::new();
                source.spawn_async(future::empty());
                source.spawn_async(future::empty());
                drop(source);
            }
        );
    }
}
