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

use futures::sync::mpsc::*;
use futures_util::FutureExt;
use std::future::Future as Future03;
use tokio::prelude::*;
use tokio_async_await::compat::backward::Compat;

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
        T: Future03<Output = ()> + Send + 'static,
    {
        let compat = Compat::new(future.map(|_| Ok(())));
        self.spawn(compat);
    }

    pub fn spawn<T>(&self, future: T)
    where
        T: Future<Item = (), Error = ()> + Send + 'static,
    {
        let cancelled = Compat::new(self.get_token().cancelled().map(|_| Ok(())));
        tokio::spawn(future.select(cancelled).then(|_| Ok(())));
    }
}

impl CancellationToken {
    pub async fn cancelled(self) {
        await!(self.sender.send_all(stream::repeat(()))).unwrap_err();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation() {
        tokio::run_async(
            async {
                let source = CancellationTokenSource::new();
                source.spawn(future::empty());
                source.spawn(future::empty());
                drop(source);
            },
        );
    }
}
