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

use futures::future::{empty, Future};
use futures::sync::oneshot::{channel, Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::clock::now;
use tokio::prelude::*;
use tokio::runtime::current_thread::{Handle, Runtime};
use tokio::timer::Delay;

lazy_static! {
    // Handle is not Sync. Each thread will make a own clone.
    static ref RUNTIME_HANDLE_SEED: Mutex<Handle> = Mutex::new({
        let (tx, rx) = ::std::sync::mpsc::channel();
        ::std::thread::Builder::new().name("timer".to_string()).spawn(move || {
            let mut rt = Runtime::new().unwrap();
            tx.send(rt.handle()).unwrap();
            drop(tx);
            rt.spawn(empty());
            rt.run().unwrap();
        }).unwrap();
        rx.recv().unwrap()
    });
}

thread_local! {
    static RUNTIME_HANDLE: Handle = RUNTIME_HANDLE_SEED.lock().unwrap().clone();
}

type Action = Box<Fn() + Send + Sync>;

struct TimerOptions {
    activated: AtomicBool,
    delay: Mutex<Delay>,
}

struct Timer {
    rx: Receiver<()>,
    options: Arc<TimerOptions>,
    action: Action,
}

pub struct TimerHandle {
    _tx: Sender<()>,
    options: Arc<TimerOptions>,
}

impl Future for Timer {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        match self.rx.poll() {
            Ok(Async::NotReady) => (),
            _ => {
                // Closed or signaled. Exit.
                return Ok(Async::Ready(()));
            }
        };
        let mut delay = self.options.delay.lock().unwrap();
        let should_run = match delay.poll() {
            Ok(Async::Ready(_)) => {
                let should_run = self.options.activated.swap(false, SeqCst);
                // Reset delay to get notified again.
                delay.reset(now() + Duration::from_secs(600));
                match delay.poll() {
                    Ok(Async::NotReady) => (),
                    _ => unreachable!(),
                }
                should_run
            }
            Ok(Async::NotReady) => false,
            Err(e) => panic!(e),
        };
        drop(delay);
        // Run action without hoding lock on delay.
        if should_run {
            (self.action)();
        }
        Ok(Async::NotReady)
    }
}

pub fn create_timer(action: Box<Fn() + Send + Sync>) -> TimerHandle {
    TimerHandle::create(action)
}

impl TimerHandle {
    /// Create a new timer of the given action.
    pub fn create(action: Action) -> TimerHandle {
        let (tx, rx) = channel();
        let options = Arc::new(TimerOptions {
            activated: AtomicBool::new(false),
            delay: Mutex::new(Delay::new(now())),
        });
        let t = Timer {
            rx,
            action,
            options: options.clone(),
        };
        RUNTIME_HANDLE.with(|r| r.spawn(t)).unwrap();
        TimerHandle { _tx: tx, options }
    }

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
    use std::thread::sleep;

    #[test]
    fn smoke() {
        let run = Arc::new(AtomicBool::new(false));
        let t = {
            let run = run.clone();
            TimerHandle::create(Box::new(move || {
                run.store(true, SeqCst);
            }))
        };

        t.adjust_and_activate(Duration::from_millis(10));
        sleep(Duration::from_millis(30));
        assert!(run.load(SeqCst));
    }

    #[test]
    fn adjust_activate_de_activate() {
        let run = Arc::new(AtomicBool::new(false));
        let t = {
            let run = run.clone();
            TimerHandle::create(Box::new(move || {
                run.store(true, SeqCst);
            }))
        };

        t.adjust_and_activate(Duration::from_millis(10));
        t.adjust_and_activate(Duration::from_millis(100));
        sleep(Duration::from_millis(20));
        assert!(!run.load(SeqCst));
        sleep(Duration::from_millis(120));
        assert!(run.load(SeqCst));

        run.store(false, SeqCst);

        t.adjust_and_activate(Duration::from_millis(10));
        t.de_activate();
        sleep(Duration::from_millis(20));
        assert!(!run.load(SeqCst));

        t.adjust_and_activate(Duration::from_millis(10));
        t.de_activate();
        t.adjust_and_activate(Duration::from_millis(15));
        sleep(Duration::from_millis(30));
        assert!(run.load(SeqCst));
    }

    #[cfg(feature = "bench")]
    #[bench]
    fn bench_timer_adjust_and_activate(b: &mut ::test::Bencher) {
        let run = Arc::new(AtomicBool::new(false));
        let t = {
            let run = run.clone();
            TimerHandle::create(Box::new(move || {
                run.store(true, SeqCst);
            }))
        };

        b.iter(|| {
            t.adjust_and_activate(Duration::from_secs(10));
        })
    }
}
