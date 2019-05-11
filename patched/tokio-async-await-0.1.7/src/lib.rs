#![cfg(feature = "async-await-preview")]
#![feature(rust_2018_preview, async_await)]
#![doc(html_root_url = "https://docs.rs/tokio-async-await/0.1.7")]
#![deny(missing_docs, missing_debug_implementations)]
#![cfg_attr(test, deny(warnings))]

//! A preview of Tokio w/ `async` / `await` support.

extern crate futures;
extern crate tokio_io;

/// Extracts the successful type of a `Poll<Result<T, E>>`.
///
/// This macro bakes in propagation of `Pending` and `Err` signals by returning early.
macro_rules! try_ready {
    ($x:expr) => {
        match $x {
            std::task::Poll::Ready(Ok(x)) => x,
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e.into())),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub mod compat;
pub mod io;
pub mod sink;
pub mod stream;
