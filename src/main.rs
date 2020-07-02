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

#![windows_subsystem = "windows"]

use titun::cli::real_main;

#[cfg(windows)]
fn main() {
    // +----------------------------+
    // |                            |
    // |       +---------------+    |                 +-----------------+
    // |       |               |    |                 |                 |
    // |  GUI  |    Webview    |    |      STDIO      | Service Manager |
    // |   ^   |               |    <----------------->                 |
    // |   +--->               |    |                 +---^-------------+
    // |       +---------------+    |                     |
    // |                            |                     |
    // +--------------------^-------+                     |  Named Pipe
    //                      |                             |
    //                      |                             |
    //                      |                      +-----------+
    //                      |     IPC get status   |           |
    //                      +---------------------->  Service  |
    //                                             |           |
    //                                             +-----------+

    use std::ffi::OsString;
    use std::path::PathBuf;

    use titun::cli::windows_service_args;
    use titun::ipc::windows_named_pipe::*;

    use anyhow::Context;
    use futures::pin_mut;
    use log::*;
    use rand::prelude::*;
    use tokio::io::{stderr, stdin, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::oneshot;
    use winapi::shared::winerror::*;
    use windows_service::{
        define_windows_service,
        service::*,
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::*,
    };

    sodiumoxide::init().unwrap();

    if std::env::args().count() <= 1 {
        return titun::windows_gui::run_windows_gui();
    }

    // When running from the command line directly, this allows us to get
    // ctrl-c. When launched by the GUI, this will fail but we do not care.
    unsafe {
        winapi::um::wincon::AttachConsole(-1i32 as u32);
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let mut stop_tx = Some(stop_tx);
        let status_handle = service_control_handler::register("titun", move |event| match event {
            ServiceControl::Stop => {
                info!("received stop event");
                if let Some(stop_tx) = stop_tx.take() {
                    stop_tx.send(()).unwrap();
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .expect("service_control_handler::register");

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                process_id: None,
                wait_hint: std::time::Duration::default(),
            })
            .expect("set_service_status");

        real_main(Some(stop_rx)).unwrap_or_else(|e| {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        });

        // Some background threads can keep the process from exiting. Exit
        // explicitly.
        info!("now exiting");
        std::process::exit(0);
    }

    fn maybe_run_as_service() -> anyhow::Result<()> {
        let service_args = windows_service_args()?;

        let service_args = if let Some(service_args) = service_args {
            service_args
        } else {
            return real_main(None);
        };

        let service_name = format!("titun@{}", service_args.interface_name.to_string_lossy());

        let database: Option<&str> = None;
        let service_manager =
            ServiceManager::local_computer(database, ServiceManagerAccess::CREATE_SERVICE)
                .context("create service manager")?;

        match service_manager.open_service(&service_name, ServiceAccess::all()) {
            Ok(service) => {
                info!("found existing service, will stop and delete it");
                match service.stop() {
                    Ok(_) => (),
                    Err(windows_service::Error::Winapi(e))
                        if e.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE as i32)
                            || e.raw_os_error()
                                == Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL as i32) => {}
                    Err(e) => return Err(e).context("stop service"),
                }
                service.delete().context("delete service")?;
            }
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {}
            Err(e) => return Err(e).context("open service"),
        }

        let mut args = service_args.args;
        let mut bytes = [0u8; 16];
        thread_rng().fill_bytes(&mut bytes);
        let log_pipe_path: PathBuf =
            format!("\\\\.\\Pipe\\titun-log-{}", base64::encode(&bytes[..])).into();
        let mut log_pipe_listener =
            AsyncPipeListener::bind(log_pipe_path.clone()).context("bind log pipe listener")?;

        args.push("--log-pipe".into());
        args.push(log_pipe_path.into());

        let create_service_info = ServiceInfo {
            name: service_name.clone().into(),
            display_name: service_name.clone().into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe().context("get current executable path")?,
            launch_arguments: args,
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let service = loop {
            match service_manager.create_service(&create_service_info, ServiceAccess::all()) {
                Ok(s) => break s,
                Err(e) => {
                    if let windows_service::Error::Winapi(ref e) = e {
                        if e.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) {
                            debug!("service marked delete, retry in one second");
                            std::thread::sleep(std::time::Duration::from_secs(1));
                            continue;
                        }
                    }
                    return Err(e).context("create service")?;
                }
            }
        };
        service.start(&["titun"]).context("start service")?;
        info!("started service {}", service_name);

        let mut rt = tokio::runtime::Builder::new()
            .enable_all()
            // Have to use threaded because we use `block_in_place`.
            .threaded_scheduler()
            .core_threads(1)
            .build()
            .context("build tokio runtime")?;

        let exit_stdin_eof = service_args.exit_stdin_eof;
        rt.block_on(async move {
            let stdin_eof = tokio::spawn(async move {
                if exit_stdin_eof {
                    let mut stdin = stdin();
                    let mut buf = vec![0u8; 4096];
                    loop {
                        debug!("read stdin");
                        match stdin.read(&mut buf).await {
                            Ok(0) => {
                                info!("stdin EOF");
                                break;
                            }
                            Err(e) => {
                                warn!("Error read from stdin: {:#}", e);
                                break;
                            }
                            _ => (),
                        }
                    }
                } else {
                    futures::future::pending().await
                }
            });

            let log_pipe = log_pipe_listener
                .accept()
                .await
                .context("log_pipe_listener accept")?;
            let mut stderr = stderr();
            let copy = tokio::spawn(async move {
                let mut log_pipe = BufReader::new(log_pipe);
                let mut line = String::new();
                loop {
                    line.clear();
                    match log_pipe.read_line(&mut line).await {
                        Err(e) => break Err(e),
                        Ok(_) => {
                            if line.is_empty() {
                                break Ok(());
                            }
                            let line = format!(">>> {}", line);
                            let _ = stderr.write_all(line.as_bytes()).await;
                        }
                    }
                }
            });
            let ctrl_c = tokio::signal::ctrl_c();
            pin_mut!(ctrl_c);
            let ctrl_c_or_stdin_eof = futures::future::select(ctrl_c, stdin_eof);
            match futures::future::select(copy, ctrl_c_or_stdin_eof).await {
                futures::future::Either::Left((copy_result, _)) => {
                    info!("service unexpectedly stopped: {:?}", copy_result);
                    service.delete().context("delete service")?;
                }
                futures::future::Either::Right((_, copy)) => {
                    info!("received ctrl-c or stdin eof, will stop and delete service");
                    service.stop().context("stop service")?;
                    // Drain log_pipe.
                    let _ = copy.await;
                    service.delete().context("delete service")?;
                }
            }
            let r: anyhow::Result<()> = Ok(());
            r
        })?;

        Ok(())
    }

    service_dispatcher::start("titun", ffi_service_main).unwrap_or_else(|e| {
        match e {
            windows_service::Error::Winapi(e)
                if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) =>
            {
                // This process is not running as a service. Create a service and start it.
                maybe_run_as_service().unwrap_or_else(|e| {
                    eprintln!("Error: {:?}", e);
                });
            }
            _ => {
                eprintln!("failed to start service: {}", e);
                std::process::exit(1);
            }
        }
    });
}

#[cfg(not(windows))]
fn main() {
    sodiumoxide::init().unwrap();
    real_main(None).unwrap_or_else(|e| {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    });
}
