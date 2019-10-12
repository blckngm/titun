// Based on https://gitlab.com/dgriffen/windows-named-pipe,
// Modified to impl Read for &PipeStream.

// Copyright (c) 2017, Daniel Griffen <daniel@griffen.io>
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.

// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![cfg(windows)]

use futures::StreamExt;
use std::borrow::Cow;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::windows::prelude::*;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{channel, Receiver};
use winapi::shared::minwindef::{DWORD, LPCVOID, LPVOID};
use winapi::shared::winerror::{ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED};
use winapi::um::fileapi::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
};
use winapi::um::winbase::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE, HANDLE};

pub struct AsyncPipeListener {
    rx: Receiver<io::Result<PipeStream>>,
}

impl AsyncPipeListener {
    pub fn bind<P: Into<Cow<'static, Path>>>(path: P) -> io::Result<Self> {
        let (mut tx, rx) = channel(1);
        let mut listener = PipeListener::bind(path)?;
        std::thread::spawn(move || {
            futures::executor::block_on(async move {
                loop {
                    let stream_or_error = listener.accept();
                    if tx.send(stream_or_error).await.is_err() {
                        break;
                    }
                }
            });
        });
        Ok(Self { rx })
    }

    pub async fn accept(&mut self) -> io::Result<PipeStream> {
        self.rx.next().await.unwrap()
    }
}

#[derive(Debug)]
pub struct PipeStream {
    server_half: bool,
    handle: Handle,
}

impl PipeStream {
    fn create_pipe(path: &Path) -> io::Result<HANDLE> {
        let mut os_str: OsString = path.as_os_str().into();
        os_str.push("\x00");
        let u16_slice = os_str.encode_wide().collect::<Vec<u16>>();

        let _ = unsafe { WaitNamedPipeW(u16_slice.as_ptr(), 0) };
        let handle = unsafe {
            CreateFileW(
                u16_slice.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ::std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ::std::ptr::null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE {
            Ok(handle)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<PipeStream> {
        let handle = PipeStream::create_pipe(path.as_ref())?;

        Ok(PipeStream {
            handle: Handle { inner: handle },
            server_half: false,
        })
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        let _ = unsafe { FlushFileBuffers(self.handle.inner) };
        if self.server_half {
            let _ = unsafe { DisconnectNamedPipe(self.handle.inner) };
        }
    }
}

impl<'a> Read for &'a PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0;
        let ok = unsafe {
            ReadFile(
                self.handle.inner,
                buf.as_mut_ptr() as LPVOID,
                buf.len() as DWORD,
                &mut bytes_read,
                ::std::ptr::null_mut(),
            )
        };

        if ok != 0 {
            Ok(bytes_read as usize)
        } else {
            match io::Error::last_os_error().raw_os_error().map(|x| x as u32) {
                Some(ERROR_PIPE_NOT_CONNECTED) => Ok(0),
                Some(err) => Err(io::Error::from_raw_os_error(err as i32)),
                _ => panic!(""),
            }
        }
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (self as &PipeStream).read(buf)
    }
}

impl<'a> Write for &'a PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0;
        let ok = unsafe {
            WriteFile(
                self.handle.inner,
                buf.as_ptr() as LPCVOID,
                buf.len() as DWORD,
                &mut bytes_written,
                ::std::ptr::null_mut(),
            )
        };

        if ok != 0 {
            Ok(bytes_written as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let ok = unsafe { FlushFileBuffers(self.handle.inner) };

        if ok != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl AsyncRead for PipeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // TODO: use dedicated thread and channel.
        tokio_executor::threadpool::blocking(|| self.read(buf)).map(|r| r.unwrap())
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio_executor::threadpool::blocking(|| self.write(buf)).map(|r| r.unwrap())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!()
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (self as &PipeStream).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (self as &PipeStream).flush()
    }
}

impl AsRawHandle for PipeStream {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.inner
    }
}

impl IntoRawHandle for PipeStream {
    fn into_raw_handle(self) -> RawHandle {
        self.handle.inner
    }
}

impl FromRawHandle for PipeStream {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        PipeStream {
            handle: Handle { inner: handle },
            server_half: false,
        }
    }
}

#[derive(Debug)]
struct PipeListener<'a> {
    path: Cow<'a, Path>,
    next_pipe: Handle,
}

impl<'a> PipeListener<'a> {
    fn create_pipe(path: &Path, first: bool) -> io::Result<Handle> {
        let mut os_str: OsString = path.as_os_str().into();
        os_str.push("\x00");
        let u16_slice = os_str.encode_wide().collect::<Vec<u16>>();

        let mut access_flags = PIPE_ACCESS_DUPLEX;
        if first {
            access_flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let handle = unsafe {
            CreateNamedPipeW(
                u16_slice.as_ptr(),
                access_flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                50,
                ::std::ptr::null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE {
            Ok(Handle { inner: handle })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn connect_pipe(handle: &Handle) -> io::Result<()> {
        let result = unsafe { ConnectNamedPipe(handle.inner, ::std::ptr::null_mut()) };

        if result != 0 {
            Ok(())
        } else {
            match io::Error::last_os_error().raw_os_error().map(|x| x as u32) {
                Some(ERROR_PIPE_CONNECTED) => Ok(()),
                Some(err) => Err(io::Error::from_raw_os_error(err as i32)),
                _ => panic!(""),
            }
        }
    }

    pub fn bind<P: Into<Cow<'a, Path>>>(path: P) -> io::Result<Self> {
        let path = path.into();
        let handle = PipeListener::create_pipe(&path, true)?;
        Ok(PipeListener {
            path,
            next_pipe: handle,
        })
    }

    pub fn accept(&mut self) -> io::Result<PipeStream> {
        let handle = ::std::mem::replace(
            &mut self.next_pipe,
            PipeListener::create_pipe(&self.path, false)?,
        );

        PipeListener::connect_pipe(&handle)?;

        Ok(PipeStream {
            handle,
            server_half: true,
        })
    }

    pub fn incoming<'b>(&'b mut self) -> Incoming<'b, 'a> {
        Incoming { listener: self }
    }
}

pub struct Incoming<'a, 'b>
where
    'b: 'a,
{
    listener: &'a mut PipeListener<'b>,
}

impl<'a, 'b> IntoIterator for &'a mut PipeListener<'b> {
    type Item = io::Result<PipeStream>;
    type IntoIter = Incoming<'a, 'b>;

    fn into_iter(self) -> Incoming<'a, 'b> {
        self.incoming()
    }
}

impl<'a, 'b> Iterator for Incoming<'a, 'b> {
    type Item = io::Result<PipeStream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;

    macro_rules! or_panic {
        ($e:expr) => {
            match $e {
                Ok(e) => e,
                Err(e) => {
                    panic!("{}", e);
                }
            }
        };
    }

    #[test]
    fn basic() {
        let socket_path = Path::new("//./pipe/basicsock");
        println!("{:?}", socket_path);
        let msg1 = b"hello";
        let msg2 = b"world!";

        let mut listener = or_panic!(PipeListener::bind(socket_path));
        let thread = thread::spawn(move || {
            let mut stream = or_panic!(listener.accept());
            let mut buf = [0; 5];
            or_panic!(stream.read(&mut buf));
            assert_eq!(&msg1[..], &buf[..]);
            or_panic!(stream.write_all(msg2));
        });

        let mut stream = or_panic!(PipeStream::connect(socket_path));

        or_panic!(stream.write_all(msg1));
        let mut buf = vec![];
        or_panic!(stream.read_to_end(&mut buf));
        assert_eq!(&msg2[..], &buf[..]);
        drop(stream);

        thread.join().unwrap();
    }

    #[test]
    fn iter() {
        let socket_path = Path::new("//./pipe/itersock");

        let mut listener = or_panic!(PipeListener::bind(socket_path));
        let thread = thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = or_panic!(stream);
                let mut buf = [0];
                or_panic!(stream.read(&mut buf));
            }
        });

        for _ in 0..2 {
            let mut stream = or_panic!(PipeStream::connect(socket_path));
            or_panic!(stream.write_all(&[0]));
        }

        thread.join().unwrap();
    }
}

#[derive(Debug)]
struct Handle {
    inner: HANDLE,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.inner) };
    }
}

unsafe impl Sync for Handle {}
unsafe impl Send for Handle {}
