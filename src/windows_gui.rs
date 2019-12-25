// Copyright 2017, 2018, 2019 Guanhao Yin <sopium@mysterious.site>

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

#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use anyhow::{bail, Context};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use web_view::*;

use crate::ipc::windows_named_pipe::PipeStream;

fn ignore_error<T, E>(_: Result<T, E>) {}

struct State {
    child: Option<Child>,
    interface_name: Option<String>,
}

async fn run(
    state: &Mutex<State>,
    config_file_path: String,
    handle: Handle<()>,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    if state.child.is_some() {
        bail!("already running");
    }
    let interface_name = Path::new(&config_file_path)
        .file_stem()
        .context("invalid file path, cannot get file stem")?
        .to_str()
        .context("invalid file path, non utf-8?")?
        .to_string();
    let mut child = Command::new("titun.exe")
        .arg("--exit-stdin-eof")
        .arg("--log=titun=debug")
        .arg("-c")
        .arg(&config_file_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // CREATE_NO_WINDOW
        .creation_flags(0x0800_0000)
        .spawn()
        .context("spawn titun.exe")?;
    let stderr = child.stderr().take().expect("child stderr");
    tokio::spawn(async move {
        let stderr = BufReader::new(stderr);
        let mut stderr_lines = stderr.lines();
        while let Some(Ok(line)) = stderr_lines.next().await {
            log::debug!("process log: {}", line);
            handle
                .dispatch(move |wv| {
                    ignore_error(wv.eval(&format!(
                        "onLog({})",
                        serde_json::to_string(&line).expect("to_json log line")
                    )));
                    Ok(())
                })
                .expect("dispatch");
        }
    });
    state.child = Some(child);
    state.interface_name = Some(interface_name);

    Ok(())
}

async fn stop(state: &Mutex<State>) -> anyhow::Result<ExitStatus> {
    let mut state = state.lock().await;
    state.interface_name = None;
    if let Some(mut child) = state.child.take() {
        let mut stdin = child.stdin().take().expect("child stdin");
        ignore_error(stdin.shutdown().await);
        drop(stdin);
        child.await.context("awaiting child")
    } else {
        bail!("no running process");
    }
}

async fn get_interface_status(state: &Mutex<State>) -> anyhow::Result<Option<serde_json::Value>> {
    let name = if let Some(name) = state.lock().await.interface_name.clone() {
        name
    } else {
        return Ok(None);
    };
    let pipe_name = format!(r#"\\.\pipe\wireguard\{}.sock"#, name);
    let mut stream = match PipeStream::connect(pipe_name) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    stream.write_all(b"get=1\n\n").await.context("write")?;
    serde_json::from_reader(stream)
        .map(Some)
        .context("deserialize status")
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", tag = "cmd")]
enum Request {
    #[serde(rename_all = "camelCase")]
    GetStatus { response_cb: String },
    #[serde(rename_all = "camelCase")]
    Run {
        response_cb: String,
        config_file_path: String,
    },
    #[serde(rename_all = "camelCase")]
    Stop { response_cb: String },
    #[serde(rename_all = "camelCase")]
    OpenFile { response_cb: String },
    #[serde(rename_all = "camelCase")]
    Exit { response_cb: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum Response<T> {
    Data(T),
    Error(String),
}

async fn handle_request_inner(
    state: &Mutex<State>,
    request: String,
    wv_handle: &Handle<()>,
) -> anyhow::Result<()> {
    let request: Request = serde_json::from_str(&request).context("deserialize request")?;
    // log::debug!("request: {:?}", request);
    fn eval<S: Serialize>(
        cb: String,
        response: anyhow::Result<S>,
        wv_handle: &Handle<()>,
    ) -> anyhow::Result<()> {
        let response_json = serde_json::to_string(&match response {
            Ok(r) => Response::Data(r),
            Err(e) => Response::Error(format!("{:#}", e)),
        })
        .context("serialize response")?;
        let script = format!("{}({})", cb, response_json);
        wv_handle
            .dispatch(move |wv| {
                // log::debug!("eval: {}", script);
                ignore_error(wv.eval(&script));
                Ok(())
            })
            .context("dispatch")
    }
    match request {
        Request::GetStatus { response_cb } => {
            let status_or_error = get_interface_status(state).await;
            eval(response_cb, status_or_error, wv_handle)
        }
        Request::OpenFile { response_cb } => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            wv_handle
                .dispatch(move |wv| {
                    let file = wv.dialog().open_file("open", "");
                    tx.send(file).expect("send");
                    Ok(())
                })
                .expect("dispatch");
            let file = match rx.await.expect("receive open file name") {
                Ok(Some(f)) => match f.to_str() {
                    Some(f) => Ok(Some(f.to_string())),
                    None => Err(anyhow::anyhow!("file name is not utf-8")),
                },
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            };
            eval(response_cb, file, wv_handle)
        }
        Request::Stop { response_cb } => {
            let stop_result = stop(state).await.map(|_| ());
            eval(response_cb, stop_result, wv_handle)
        }
        Request::Run {
            config_file_path,
            response_cb,
        } => {
            let run_result = run(state, config_file_path, wv_handle.clone()).await;
            eval(response_cb, run_result, wv_handle)
        }
        Request::Exit { .. } => wv_handle
            .dispatch(|wv| {
                wv.terminate();
                Ok(())
            })
            .context("dispatch"),
    }
}

async fn handle_request(state: Arc<Mutex<State>>, request: String, wv_handle: Handle<()>) {
    if let Err(e) = handle_request_inner(&state, request, &wv_handle).await {
        log::error!("failed to handle request: {:#}", e);
    }
}

pub fn run_windows_gui() {
    env_logger::init();

    let (rt_handle_tx, rt_handle_rx) = std::sync::mpsc::channel::<tokio::runtime::Handle>();

    std::thread::spawn(move || {
        let mut rt = tokio::runtime::Builder::new()
            .enable_all()
            .threaded_scheduler()
            .core_threads(1)
            .build()
            .unwrap();
        rt_handle_tx
            .send(rt.handle().clone())
            .expect("send rt handle");
        rt.block_on(futures::future::pending::<()>());
    });

    let rt_handle = rt_handle_rx.recv().expect("recv rt handle");
    let state = Arc::new(Mutex::new(State {
        child: None,
        interface_name: None,
    }));

    #[cfg(debug_assertions)]
    let content = Content::Url("http://localhost:3000");
    #[cfg(not(debug_assertions))]
    let content = Content::Html(include_str!("windows_gui.html"));

    builder()
        .title("TiTun")
        .content(content)
        .size(1024, 768)
        .resizable(true)
        .user_data(())
        .debug(cfg!(debug_assertions))
        .invoke_handler(|wv, arg| {
            rt_handle.spawn(handle_request(state.clone(), arg.into(), wv.handle()));
            Ok(())
        })
        .run()
        .unwrap();
}
