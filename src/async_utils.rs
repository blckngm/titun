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

use futures::future::Shared;
use futures::prelude::*;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::oneshot::*;

/// Manage a group of tasks.
pub struct AsyncScope {
    receiver: Shared<Pin<Box<dyn Future<Output = ()> + Send>>>,
    sender: Mutex<Option<Sender<()>>>,
}

impl AsyncScope {
    pub fn new() -> Arc<Self> {
        let (sender, receiver) = channel();
        Arc::new(AsyncScope {
            receiver: async move {
                let _ = receiver.await;
            }
            .boxed()
            .shared(),
            sender: Mutex::new(Some(sender)),
        })
    }

    pub fn cancelled(&self) -> impl Future<Output = ()> + Send + Unpin {
        self.receiver.clone()
    }

    pub fn cancel(&self) {
        self.sender.lock().take();
    }

    /// Spawn a future that is bound to this scope.
    ///
    /// The future is spawned with tokio's default executor.
    ///
    /// When this scope is dropped or cancelled, the future is cancelled.
    ///
    /// When the future completes, this scope is cancelled.
    pub fn spawn_canceller<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let w = Arc::downgrade(&self);
        self.spawn_async(async move {
            future.await;
            if let Some(c) = w.upgrade() {
                c.cancel();
            }
        });
    }

    /// Spawn a future that is bound to this scope.
    ///
    /// The future is spawned with tokio's default executor.
    ///
    /// When this scope is dropped or cancelled, the future is cancelled.
    pub fn spawn_async<T>(&self, future: T)
    where
        T: Future<Output = ()> + Send + 'static,
    {
        let cancelled = self.cancelled();

        tokio::spawn(async move {
            futures::select_biased! {
                _ = future.fuse() => {}
                _ = cancelled.fuse() => {}
            };
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(async {
            let scope = AsyncScope::new();
            scope.spawn_async(future::pending());
            scope.spawn_async(future::pending());
            drop(scope);
        });
    }
}
