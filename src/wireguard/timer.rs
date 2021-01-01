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

//! Timer that is optimized for frequent, repeated de-activation and adjust.
//!
//! Use tokio-timer under the hood.

use futures::future::poll_fn;
use futures::prelude::*;
use futures::ready;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::sync::oneshot::{channel, Sender};
use tokio::time::{sleep, Instant, Sleep};

struct TimerOptions {
    activated: AtomicBool,
    delay: Mutex<Sleep>,
}

pub struct TimerHandle {
    _tx: Sender<()>,
    options: Arc<TimerOptions>,
}

pub fn create_timer_async<F, Fut>(action: F) -> TimerHandle
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let (tx, mut rx) = channel();
    let options0 = Arc::new(TimerOptions {
        activated: AtomicBool::new(false),
        delay: Mutex::new(sleep(Duration::from_secs(0))),
    });
    let options = options0.clone();
    tokio::spawn(async move {
        loop {
            let wait_result = poll_fn(|cx| {
                // First check whether the handle is dropped.
                if rx.poll_unpin(cx).is_ready() {
                    return Poll::Ready(Err(()));
                }
                let mut delay = options.delay.lock();
                let mut delay = unsafe { Pin::new_unchecked(&mut *delay) };
                ready!(delay.as_mut().poll(cx));
                // Reset delay to get notified again.
                delay
                    .as_mut()
                    .reset(Instant::now() + Duration::from_secs(600));
                match delay.poll_unpin(cx) {
                    Poll::Pending => (),
                    _ => unreachable!(),
                }
                if options.activated.swap(false, SeqCst) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await;
            if wait_result.is_err() {
                break;
            }
            action().await;
        }
    });
    TimerHandle {
        _tx: tx,
        options: options0,
    }
}

impl TimerHandle {
    /// Reset the timer to some timer later.
    pub fn adjust_and_activate(&self, delay: Duration) {
        let mut d = self.options.delay.lock();
        unsafe { Pin::new_unchecked(&mut *d) }.reset(Instant::now() + delay);
        self.options.activated.store(true, SeqCst);
    }

    pub fn adjust_and_activate_secs(&self, secs: u64) {
        self.adjust_and_activate(Duration::from_secs(secs));
    }

    pub fn adjust_and_activate_if_not_activated(&self, secs: u64) {
        if !self.options.activated.load(SeqCst) {
            self.adjust_and_activate_secs(secs);
        }
    }

    /// De-activate the timer.
    pub fn de_activate(&self) {
        self.options.activated.store(false, SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc::channel;
    use tokio::time::timeout;

    #[tokio::test]
    async fn smoke() {
        let (tx, mut rx) = channel(1);
        let t = create_timer_async(move || {
            let tx = tx.clone();
            async move {
                tx.send(()).await.unwrap();
            }
        });

        t.adjust_and_activate(Duration::from_millis(10));
        rx.recv().await.unwrap();
    }

    #[tokio::test]
    async fn adjust_activate_de_activate() {
        let (tx, mut rx) = channel(1);

        let t = {
            create_timer_async(move || {
                let tx = tx.clone();
                async move {
                    tx.send(()).await.unwrap();
                }
            })
        };

        let t0 = Instant::now();
        t.adjust_and_activate(Duration::from_millis(10));
        t.adjust_and_activate(Duration::from_millis(100));
        rx.recv().await.unwrap();
        assert!(t0.elapsed() >= Duration::from_millis(90));

        t.adjust_and_activate(Duration::from_millis(10));
        t.de_activate();

        assert!(timeout(Duration::from_millis(20), rx.recv()).await.is_err());

        t.adjust_and_activate(Duration::from_millis(10));
        t.de_activate();
        t.adjust_and_activate(Duration::from_millis(15));

        rx.recv().await.unwrap();

        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());
    }
}
