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
use futures::future::Shared;
use futures::prelude::*;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, Waker};
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
    pub fn spawn_canceller<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let w = Arc::downgrade(self);
        self.spawn_async(
            async move {
                await!(future);
                if let Some(c) = w.upgrade() {
                    c.cancel();
                }
            },
        );
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
        tokio_spawn(
            async move {
                pin_mut!(cancelled);
                let f = future.fuse();
                pin_mut!(f);
                select! {
                    _ = cancelled => (),
                    _ = f => (),
                }
            },
        );
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

    fn poll(mut self: Pin<&mut Self>, waker: &Waker) -> Poll<()> {
        if self.pending {
            self.pending = false;
            waker.wake();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

pub async fn delay(duration: Duration) {
    use futures::compat::Future01CompatExt;
    use tokio::clock::now;
    use tokio::timer::Delay;

    await!(Delay::new(now() + duration).compat()).unwrap();
}

pub fn tokio_block_on_all<T, Fut>(fut: Fut) -> T
where
    Fut: futures::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    use futures::*;
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on_all(fut.unit_error().boxed().compat()).unwrap()
}

pub fn tokio_spawn(fut: impl futures::Future<Output = ()> + Send + 'static) {
    use futures::*;
    tokio::spawn(fut.unit_error().boxed().compat());
}

#[cfg(windows)]
pub fn blocking<T>(f: impl FnOnce() -> T) -> impl futures::Future<Output = T> + Unpin {
    use futures::compat::Future01CompatExt;

    // Hack for FnMut.
    let mut f = Some(f);
    tokio::prelude::future::poll_fn(move || {
        // The closure is not redundant!
        // https://github.com/rust-lang/rust-clippy/issues/3071
        #[allow(clippy::redundant_closure)]
        tokio_threadpool::blocking(|| f.take().unwrap()())
    })
    .compat()
    .map(Result::unwrap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation() {
        crate::tokio_block_on_all(
            async {
                let scope = AsyncScope::new();
                scope.spawn_async(future::empty());
                scope.spawn_async(future::empty());
                drop(scope);
            },
        );
    }
}