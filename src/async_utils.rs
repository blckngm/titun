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

use futures::channel::oneshot::*;
use futures::future::select;
use futures::future::Shared;
use futures::prelude::*;
use parking_lot::Mutex;
use pin_utils::pin_mut;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// Manage a group of tasks.
pub struct AsyncScope {
    receiver: Shared<Receiver<()>>,
    sender: Mutex<Option<Sender<()>>>,
}

impl AsyncScope {
    pub fn new() -> Arc<Self> {
        let (sender, receiver) = channel();
        Arc::new(AsyncScope {
            receiver: receiver.shared(),
            sender: Mutex::new(Some(sender)),
        })
    }

    pub fn cancelled(&self) -> impl Future<Output = ()> + Send + Unpin {
        self.receiver.clone().unwrap_or_else(|_| ())
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
    // XXX: change to `self: &Arc<Self>` once it's allowed in stable.
    pub fn spawn_canceller<F>(self: Arc<Self>, future: F)
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
        let cancelled = self.receiver.clone();
        tokio::spawn(async move {
            pin_mut!(future);

            select(future, cancelled).await;
        });
    }
}

/// Returns a future that yields, allow other tasks to execute. Like `sched_yield` but for async code.
pub fn yield_once() -> YieldOnce {
    YieldOnce { pending: true }
}

pub struct YieldOnce {
    pending: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

pub async fn delay(duration: Duration) {
    use tokio::clock::now;
    use tokio::timer::Delay;

    Delay::new(now() + duration).await;
}

#[cfg(windows)]
pub fn blocking<T>(f: impl FnOnce() -> T) -> impl futures::Future<Output = T> + Unpin {
    use futures::future::poll_fn;
    use futures::prelude::*;

    // Hack for FnMut.
    let mut f = Some(f);
    poll_fn(move |_cx| {
        // The closure is not redundant!
        // https://github.com/rust-lang/rust-clippy/issues/3071
        #[allow(clippy::redundant_closure)]
        tokio_executor::threadpool::blocking(|| f.take().unwrap()())
    })
    .map(|x| x.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation() {
        let mut rt = tokio::runtime::current_thread::Runtime::new().unwrap();

        rt.spawn(async {
            let scope = AsyncScope::new();
            scope.spawn_async(future::pending());
            scope.spawn_async(future::pending());
            drop(scope);
        });

        rt.run().unwrap();
    }
}
