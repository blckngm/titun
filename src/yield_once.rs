use std::future::Future;
use std::pin::Pin;
use std::task::{Poll, Waker};

/// Returns a future that yields, allow other tasks to execute. Like `sched_yield` for async code.
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
