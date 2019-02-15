// Copyright 2019 Guanhao Yin <sopium@mysterious.site>

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

use std::future::Future;
use std::pin::Pin;
use std::task::{LocalWaker, Poll};

#[derive(Debug)]
pub enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R, T> Future for Either<L, R>
where
    L: Future<Output = T>,
    R: Future<Output = T>,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, lw: &LocalWaker) -> Poll<T> {
        unsafe {
            match self.get_unchecked_mut() {
                Either::Left(l) => Pin::new_unchecked(l).poll(lw),
                Either::Right(r) => Pin::new_unchecked(r).poll(lw),
            }
        }
    }
}

pub trait FutureEitherExt: Sized {
    fn left_future<R>(self) -> Either<Self, R> {
        Either::Left(self)
    }
    fn right_future<L>(self) -> Either<L, Self> {
        Either::Right(self)
    }
}

impl<F, T> FutureEitherExt for F where F: Future<Output = T> + Sized {}
