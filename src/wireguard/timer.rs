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
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::clock::now;
use tokio::sync::oneshot::{channel, Sender};
use tokio::timer::Delay;

struct TimerOptions {
    activated: AtomicBool,
    delay: Mutex<Delay>,
}

pub struct TimerHandle {
    _tx: Sender<()>,
    options: Arc<TimerOptions>,
}

pub fn create_timer_async<F, Fut>(action: F) -> TimerHandle
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let (tx, mut rx) = channel();
    let options0 = Arc::new(TimerOptions {
        activated: AtomicBool::new(false),
        delay: Mutex::new(Delay::new(now())),
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
                ready!(delay.poll_unpin(cx));
                // Reset delay to get notified again.
                delay.reset(now() + Duration::from_secs(600));
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
        d.reset(now() + delay);
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
    use crate::async_utils::delay;
    use std::time::Duration;

    #[tokio::test]
    async fn smoke() {
        let run = Arc::new(AtomicBool::new(false));
        let t = {
            let run = run.clone();
            create_timer_async(move || {
                run.store(true, SeqCst);
                async { () }
            })
        };

        t.adjust_and_activate(Duration::from_millis(10));
        delay(Duration::from_millis(30)).await;
        assert!(run.load(SeqCst));
    }

    #[tokio::test]
    async fn adjust_activate_de_activate() {
        let run = Arc::new(AtomicBool::new(false));
        let t = {
            let run = run.clone();
            create_timer_async(move || {
                run.store(true, SeqCst);
                async { () }
            })
        };

        t.adjust_and_activate(Duration::from_millis(10));
        t.adjust_and_activate(Duration::from_millis(100));

        delay(Duration::from_millis(20)).await;
        assert!(!run.load(SeqCst));
        delay(Duration::from_millis(120)).await;
        assert!(run.load(SeqCst));

        run.store(false, SeqCst);

        t.adjust_and_activate(Duration::from_millis(10));
        t.de_activate();
        delay(Duration::from_millis(20)).await;
        assert!(!run.load(SeqCst));

        t.adjust_and_activate(Duration::from_millis(10));
        t.de_activate();
        t.adjust_and_activate(Duration::from_millis(15));
        delay(Duration::from_millis(30)).await;
        assert!(run.load(SeqCst));
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_timer_adjust_and_activate(b0: &mut crate::test::Bencher) {
        // Workaround lifetime issues.
        let b1 = Arc::new(Mutex::new(b0.clone()));
        let b = b1.clone();
        tokio::runtime::run(async move {
            let run = Arc::new(AtomicBool::new(false));
            let t = {
                let run = run.clone();
                create_timer_async(move || {
                    run.store(true, SeqCst);
                    async { () }
                })
            };

            b.lock().iter(|| {
                t.adjust_and_activate(Duration::from_secs(10));
            });
        });
        *b0 = b1.lock().clone();
    }
}
