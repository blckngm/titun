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

use futures::sync::oneshot::{channel, Sender};
use std::future::Future as Future03;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::clock::now;
use tokio::prelude::*;
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
    Fut: Future03<Output = ()> + Send,
{
    let (tx, mut rx) = channel();
    let options0 = Arc::new(TimerOptions {
        activated: AtomicBool::new(false),
        delay: Mutex::new(Delay::new(now())),
    });
    let options = options0.clone();
    tokio::spawn_async(
        async move {
            loop {
                match await!(future::poll_fn(|| {
                    match rx.poll() {
                        Ok(Async::NotReady) => (),
                        _ => return Err(()),
                    }
                    let mut delay = options.delay.lock().unwrap();
                    match delay.poll() {
                        Ok(Async::Ready(_)) => {
                            // Reset delay to get notified again.
                            delay.reset(now() + Duration::from_secs(600));
                            match delay.poll() {
                                Ok(Async::NotReady) => (),
                                _ => unreachable!(),
                            }
                            if options.activated.swap(false, SeqCst) {
                                Ok(Async::Ready(()))
                            } else {
                                Ok(Async::NotReady)
                            }
                        }
                        Ok(Async::NotReady) => Ok(Async::NotReady),
                        Err(e) => panic!(e),
                    }
                })) {
                    Err(_) => break,
                    _ => (),
                }
                await!(action());
            }
        },
    );
    TimerHandle {
        _tx: tx,
        options: options0,
    }
}

impl TimerHandle {
    /// Reset the timer to some timer later.
    pub fn adjust_and_activate(&self, delay: Duration) {
        let mut d = self.options.delay.lock().unwrap();
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

    #[test]
    fn smoke() {
        tokio::run_async(
            async {
                let run = Arc::new(AtomicBool::new(false));
                let t = {
                    let run = run.clone();
                    create_timer_async(move || {
                        run.store(true, SeqCst);
                        async { () }
                    })
                };

                t.adjust_and_activate(Duration::from_millis(10));
                sleep!(ms 30);
                assert!(run.load(SeqCst));
            },
        );
    }

    #[test]
    fn adjust_activate_de_activate() {
        tokio::run_async(
            async {
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
                sleep!(ms 20);
                assert!(!run.load(SeqCst));
                sleep!(ms 120);
                assert!(run.load(SeqCst));

                run.store(false, SeqCst);

                t.adjust_and_activate(Duration::from_millis(10));
                t.de_activate();
                sleep!(ms 20);
                assert!(!run.load(SeqCst));

                t.adjust_and_activate(Duration::from_millis(10));
                t.de_activate();
                t.adjust_and_activate(Duration::from_millis(15));
                sleep!(ms 30);
                assert!(run.load(SeqCst));
            },
        );
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_timer_adjust_and_activate(b0: &mut ::test::Bencher) {
        // Workaround lifetime issues.
        let b1 = Arc::new(Mutex::new(b0.clone()));
        let b = b1.clone();
        tokio::run_async(
            async move {
                let run = Arc::new(AtomicBool::new(false));
                let t = {
                    let run = run.clone();
                    create_timer_async(move || {
                        run.store(true, SeqCst);
                        async { () }
                    })
                };

                b.lock().unwrap().iter(|| {
                    t.adjust_and_activate(Duration::from_secs(10));
                });
            },
        );
        *b0 = b1.lock().unwrap().clone();
    }
}
