use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_utils::unsafe_pinned;
use tokio::io::{AsyncRead, AsyncWrite};

/// Compability layer for futures-io.
#[derive(Debug)]
pub struct Compat<S> {
    inner: S,
}

impl<S> Compat<S> {
    unsafe_pinned!(inner: S);

    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead> futures::io::AsyncRead for Compat<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.inner().poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> futures::io::AsyncWrite for Compat<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner().poll_shutdown(cx)
    }
}
