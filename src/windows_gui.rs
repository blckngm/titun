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

use std::cell::RefCell;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{bail, Context};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use widestring::WideCStr;
use winapi::shared::basetsd::*;
use winapi::shared::minwindef::*;
use winapi::shared::windef::*;
use winapi::um::combaseapi::*;
use winapi::um::commctrl::*;
use winapi::um::knownfolders::*;
use winapi::um::libloaderapi::*;
use winapi::um::shellapi::*;
use winapi::um::shlobj::*;
use winapi::um::winuser::*;
use winit::dpi::Size;
use winit::event::{Event, WindowEvent};
use winit::event_loop::{ControlFlow, EventLoop, EventLoopProxy};
use winit::platform::windows::WindowExtWindows;
use winit::window::WindowBuilder;

use crate::ipc::windows_named_pipe::PipeStream;

fn ignore_error<T, E>(_: Result<T, E>) {}

struct State {
    child: Option<Child>,
    interface_name: Option<String>,
}

#[derive(Debug)]
enum MyEvent {
    ExecuteScript(String),
    OpenFile(tokio::sync::oneshot::Sender<webview2::Result<Option<PathBuf>>>),
    Show,
    Hide,
    Exit,
    Minimized,
    Restored,
    Focus,
    Running,
    Stopped,
}

async fn run(
    state: &Mutex<State>,
    config_file_path: String,
    proxy: EventLoopProxy<MyEvent>,
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
        .env("RUST_BACKTRACE", "1")
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
    let stderr = child.stderr.take().expect("child stderr");
    ignore_error(proxy.send_event(MyEvent::Running));
    tokio::spawn(async move {
        let stderr = BufReader::new(stderr);
        let mut stderr_lines = stderr.lines();
        while let Some(Ok(line)) = stderr_lines.next().await {
            log::debug!("process log: {}", line);
            let script = format!(
                "onLog({})",
                serde_json::to_string(&line).expect("to_json log line")
            );
            ignore_error(proxy.send_event(MyEvent::ExecuteScript(script)));
        }
        ignore_error(proxy.send_event(MyEvent::Stopped));
    });
    state.child = Some(child);
    state.interface_name = Some(interface_name);

    Ok(())
}

async fn stop(state: &Mutex<State>) -> anyhow::Result<ExitStatus> {
    let mut state = state.lock().await;
    state.interface_name = None;
    if let Some(mut child) = state.child.take() {
        let mut stdin = child.stdin.take().expect("child stdin");
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
    #[serde(rename_all = "camelCase")]
    Hide { response_cb: String },
    #[serde(rename_all = "camelCase")]
    Focus { response_cb: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum Response<T> {
    Data(T),
    Error(String),
}

fn open_file_dialog(hwnd: HWND) -> webview2::Result<Option<PathBuf>> {
    use std::ffi::c_void;
    use webview2::check_hresult;
    use winapi::shared::winerror::{ERROR_CANCELLED, HRESULT_FROM_WIN32};
    use winapi::um::shobjidl::*;
    use winapi::um::shobjidl_core::*;
    use winapi::Interface;

    unsafe {
        let mut dialog: *mut IFileOpenDialog = ptr::null_mut();
        check_hresult(CoCreateInstance(
            &CLSID_FileOpenDialog,
            ptr::null_mut(),
            CLSCTX_ALL,
            &IFileOpenDialog::uuidof(),
            &mut dialog as *mut *mut IFileOpenDialog as *mut *mut c_void,
        ))?;
        let dialog: &IFileOpenDialog = &*dialog;
        scopeguard::defer! {
            dialog.Release();
        };

        let mut options = 0;
        check_hresult(dialog.GetOptions(&mut options))?;
        options |= FOS_NOCHANGEDIR | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST;
        check_hresult(dialog.SetOptions(options))?;

        match check_hresult(dialog.Show(hwnd)) {
            Ok(_) => {}
            Err(e) if e.hresult() == HRESULT_FROM_WIN32(ERROR_CANCELLED) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let mut result: *mut IShellItem = ptr::null_mut();
        check_hresult(dialog.GetResult(&mut result as *mut *mut _))?;
        let result = &*result;
        scopeguard::defer! {
            result.Release();
        }

        let mut path = ptr::null_mut();
        check_hresult(result.GetDisplayName(SIGDN_FILESYSPATH, &mut path))?;
        let path1 = WideCStr::from_ptr_str(path);
        CoTaskMemFree(path as _);

        Ok(Some(PathBuf::from(path1.to_os_string())))
    }
}

async fn handle_request_inner(
    state: &Mutex<State>,
    request: String,
    proxy: EventLoopProxy<MyEvent>,
) -> anyhow::Result<()> {
    let request: Request = serde_json::from_str(&request).context("deserialize request")?;
    // log::debug!("request: {:?}", request);
    fn eval<S: Serialize>(
        cb: String,
        response: anyhow::Result<S>,
        proxy: EventLoopProxy<MyEvent>,
    ) -> anyhow::Result<()> {
        let response_json = serde_json::to_string(&match response {
            Ok(r) => Response::Data(r),
            Err(e) => Response::Error(format!("{:#}", e)),
        })
        .context("serialize response")?;
        let script = format!("{}({})", cb, response_json);
        proxy
            .send_event(MyEvent::ExecuteScript(script))
            .context("proxy.send_event")
    }
    match request {
        Request::GetStatus { response_cb } => {
            let status_or_error = get_interface_status(state).await;
            eval(response_cb, status_or_error, proxy)
        }
        Request::OpenFile { response_cb } => {
            let (tx, rx) = tokio::sync::oneshot::channel();

            proxy
                .send_event(MyEvent::OpenFile(tx))
                .context("proxy.send_event")?;

            let file = match rx.await.context("received opened file")? {
                Ok(Some(f)) => match f.to_str() {
                    Some(f) => Ok(Some(f.to_string())),
                    None => Err(anyhow::anyhow!("file name is not utf-8")),
                },
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            };
            eval(response_cb, file, proxy)
        }
        Request::Stop { response_cb } => {
            let stop_result = stop(state).await.map(|_| ());
            eval(response_cb, stop_result, proxy)
        }
        Request::Run {
            config_file_path,
            response_cb,
        } => {
            let proxy1 = proxy.clone();
            let run_result = run(state, config_file_path, proxy1).await;
            eval(response_cb, run_result, proxy)
        }
        Request::Exit { .. } => proxy.send_event(MyEvent::Exit).map_err(|e| e.into()),
        Request::Hide { response_cb } => {
            proxy
                .send_event(MyEvent::Hide)
                .context("proxy.send_event")?;
            eval(response_cb, Ok(()), proxy)
        }
        Request::Focus { response_cb } => {
            proxy
                .send_event(MyEvent::Focus)
                .context("proxy.send_event")?;
            eval(response_cb, Ok(()), proxy)
        }
    }
}

async fn handle_request(state: Arc<Mutex<State>>, request: String, proxy: EventLoopProxy<MyEvent>) {
    if let Err(e) = handle_request_inner(&state, request, proxy).await {
        log::error!("failed to handle request: {:#}", e);
    }
}

const WM_NOTIFY_ICON: u32 = WM_APP + 1;
const COMMAND_EXIT: u32 = 1;

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
        ignore_error(rt_handle_tx.send(rt.handle().clone()));
        rt.block_on(futures::future::pending::<()>());
    });

    let rt_handle = rt_handle_rx.recv().expect("recv rt handle");
    let state = Arc::new(Mutex::new(State {
        child: None,
        interface_name: None,
    }));

    let event_loop = EventLoop::<MyEvent>::with_user_event();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("TiTun")
        .with_inner_size(Size::Logical((1024, 768).into()))
        .build(&event_loop)
        .unwrap();

    // The window need to be in foreground to show the popup menu from the
    // notify icon. We do not want to bring the main window to foreground, so
    // use another window for the notify icon.
    let notify_icon_window = WindowBuilder::new()
        .with_title("TiTun - NotifyIcon")
        .with_visible(false)
        .build(&event_loop)
        .unwrap();

    let icon = unsafe { LoadIconA(GetModuleHandleA(ptr::null()), MAKEINTRESOURCEA(1)) };

    let icon_red = unsafe { LoadIconA(GetModuleHandleA(ptr::null()), MAKEINTRESOURCEA(2)) };

    let mut notify_icon_data = unsafe {
        NOTIFYICONDATAA {
            cbSize: std::mem::size_of::<NOTIFYICONDATAA>() as _,
            hWnd: notify_icon_window.hwnd() as HWND,
            uFlags: NIF_MESSAGE | NIF_ICON,
            uCallbackMessage: WM_NOTIFY_ICON,
            hIcon: icon_red,
            ..mem::zeroed()
        }
    };

    #[allow(non_snake_case)]
    extern "system" fn subclass_wnd_proc(
        hWnd: HWND,
        uMsg: UINT,
        wParam: WPARAM,
        lParam: LPARAM,
        _uIdSubclass: UINT_PTR,
        dwRefData: DWORD_PTR,
    ) -> LRESULT {
        let proxy_ptr = dwRefData as *mut EventLoopProxy<MyEvent>;

        match uMsg {
            WM_SYSCOMMAND => match wParam {
                SC_MINIMIZE => {
                    let proxy = unsafe { &*proxy_ptr };
                    ignore_error(proxy.send_event(MyEvent::Minimized));
                }
                SC_RESTORE => {
                    let proxy = unsafe { &*proxy_ptr };
                    ignore_error(proxy.send_event(MyEvent::Restored));
                }
                _ => {}
            },
            WM_DESTROY => unsafe {
                RemoveWindowSubclass(hWnd, Some(subclass_wnd_proc), 0);
                Box::from_raw(dwRefData as *mut EventLoopProxy<MyEvent>);
            },
            _ => {}
        }
        unsafe { DefSubclassProc(hWnd, uMsg, wParam, lParam) }
    }

    #[allow(non_snake_case)]
    extern "system" fn notify_icon_window_subclass_wnd_proc(
        hWnd: HWND,
        uMsg: UINT,
        wParam: WPARAM,
        lParam: LPARAM,
        _uIdSubclass: UINT_PTR,
        dwRefData: DWORD_PTR,
    ) -> LRESULT {
        let proxy_ptr = dwRefData as *mut EventLoopProxy<MyEvent>;

        match uMsg {
            WM_NOTIFY_ICON => match lParam as u32 {
                WM_LBUTTONDOWN => {
                    let proxy = unsafe { &*proxy_ptr };
                    ignore_error(proxy.send_event(MyEvent::Show));
                    return 0;
                }
                WM_RBUTTONUP => unsafe {
                    let menu = CreatePopupMenu();
                    InsertMenuA(
                        menu,
                        0,
                        MF_BYPOSITION,
                        COMMAND_EXIT as usize,
                        b"Exit\0".as_ptr() as *const i8,
                    );
                    let mut point = mem::zeroed();
                    GetCursorPos(&mut point);
                    SetForegroundWindow(hWnd);
                    TrackPopupMenu(
                        menu,
                        TPM_RIGHTBUTTON,
                        point.x,
                        point.y,
                        0,
                        hWnd,
                        ptr::null(),
                    );
                    PostMessageA(hWnd, WM_NULL, 0, 0);
                    DestroyMenu(menu);
                },
                _ => {}
            },
            WM_COMMAND if wParam as u32 == COMMAND_EXIT => {
                let proxy = unsafe { &*proxy_ptr };
                ignore_error(proxy.send_event(MyEvent::Exit));
            }
            WM_DESTROY => unsafe {
                RemoveWindowSubclass(hWnd, Some(notify_icon_window_subclass_wnd_proc), 0);
                Box::from_raw(dwRefData as *mut EventLoopProxy<MyEvent>);
            },
            _ => {}
        }
        unsafe { DefSubclassProc(hWnd, uMsg, wParam, lParam) }
    }

    unsafe {
        SendMessageA(
            window.hwnd() as HWND,
            WM_SETICON,
            ICON_BIG as _,
            icon_red as _,
        );
        Shell_NotifyIconA(NIM_ADD, &mut notify_icon_data);
        let proxy_ptr = Box::into_raw(Box::new(proxy.clone()));
        SetWindowSubclass(
            window.hwnd() as HWND,
            Some(subclass_wnd_proc),
            0,
            proxy_ptr as DWORD_PTR,
        );
        let proxy_ptr = Box::into_raw(Box::new(proxy.clone()));
        SetWindowSubclass(
            notify_icon_window.hwnd() as HWND,
            Some(notify_icon_window_subclass_wnd_proc),
            0,
            proxy_ptr as DWORD_PTR,
        );
    }

    let webview: Rc<RefCell<Option<webview2::WebView>>> = Rc::new(RefCell::new(None));
    // `webview2::Controller` is previously named `webview2::Host`.
    let webview_host: Rc<RefCell<Option<webview2::Controller>>> = Rc::new(RefCell::new(None));

    let create_result = {
        let webview = webview.clone();
        let webview_host = webview_host.clone();
        let hwnd = window.hwnd() as HWND;

        // We can't and should not put the user data folder in `Program Files`.
        // So put it in the user's `AppData/Local` folder.
        let user_data_folder = unsafe {
            let mut app_data_local_path: *mut u16 = ptr::null_mut();
            SHGetKnownFolderPath(
                &FOLDERID_LocalAppData,
                0,
                ptr::null_mut(),
                &mut app_data_local_path,
            );
            let app_data_local_path1 = WideCStr::from_ptr_str(app_data_local_path);
            CoTaskMemFree(app_data_local_path as _);
            let mut path = PathBuf::from(app_data_local_path1.to_os_string());
            path.push("titun.exe.WebView2");
            path
        };

        webview2::EnvironmentBuilder::new()
            .with_user_data_folder(&user_data_folder)
            .build(move |env| {
                env.unwrap().create_controller(hwnd, move |h| {
                    let h = h.unwrap();
                    let w = h.get_webview().unwrap();

                    let _ = w.get_settings().map(|settings| {
                        let _ = settings.put_is_status_bar_enabled(false);
                        let _ = settings.put_are_default_context_menus_enabled(false);
                        let _ = settings.put_is_zoom_control_enabled(false);
                    });

                    unsafe {
                        let mut rect = mem::zeroed();
                        GetClientRect(hwnd, &mut rect);
                        ignore_error(h.put_bounds(rect));
                    }

                    w.add_web_message_received(move |_, args| {
                        let message = args.get_web_message_as_json()?;
                        rt_handle.spawn(handle_request(state.clone(), message, proxy.clone()));
                        Ok(())
                    })
                    .unwrap();

                    #[cfg(debug_assertions)]
                    w.navigate("http://localhost:3000").expect("navigate");
                    #[cfg(not(debug_assertions))]
                    w.navigate_to_string(include_str!("windows_gui.html"))
                        .expect("navigate_to_string");

                    *webview_host.borrow_mut() = Some(h);
                    *webview.borrow_mut() = Some(w);
                    Ok(())
                })
            })
    };

    if let Err(error) = create_result {
        let text = widestring::WideCString::from_str(format!(
            "Failed to create webview environment: {}.\nIs the new edge browser installed?",
            error
        ))
        .unwrap();
        let caption = wchar::wch_c!("Error").as_ptr();
        unsafe {
            MessageBoxW(
                window.hwnd() as HWND,
                text.as_ptr(),
                caption,
                MB_OK | MB_ICONERROR,
            );
            Shell_NotifyIconA(NIM_DELETE, &mut notify_icon_data);
        }
        return;
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent { event, window_id } if window_id == window.id() => match event {
                WindowEvent::CloseRequested => {
                    window.set_visible(false);
                }
                // Notify the webview when the parent window is moved.
                WindowEvent::Moved(_) => {
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.notify_parent_window_position_changed());
                    }
                }
                WindowEvent::Focused(true) => {
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.put_is_visible(true));
                        ignore_error(host.move_focus(webview2::MoveFocusReason::Programmatic));
                    }
                }
                // Update webview bounds when the parent window is resized.
                WindowEvent::Resized(new_size) => {
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        let r = RECT {
                            left: 0,
                            top: 0,
                            right: new_size.width as i32,
                            bottom: new_size.height as i32,
                        };
                        host.put_bounds(r).unwrap();
                    }
                }
                _ => {}
            },
            Event::UserEvent(my_event) => match my_event {
                MyEvent::Exit => {
                    unsafe {
                        Shell_NotifyIconA(NIM_DELETE, &mut notify_icon_data);
                    }
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.close());
                    }
                    *control_flow = ControlFlow::Exit;
                }
                MyEvent::Hide => {
                    window.set_visible(false);
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.put_is_visible(false));
                    }
                }
                MyEvent::Show => {
                    window.set_visible(true);
                    window.set_minimized(false);
                    unsafe {
                        SetForegroundWindow(window.hwnd() as _);
                    }
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.put_is_visible(true));
                        ignore_error(host.move_focus(webview2::MoveFocusReason::Programmatic));
                    }
                }
                MyEvent::Focus => {
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.move_focus(webview2::MoveFocusReason::Programmatic));
                    }
                }
                MyEvent::ExecuteScript(script) => {
                    if let Some(ref webview) = webview.borrow().as_ref() {
                        if let Err(error) = webview.execute_script(&script, |_| Ok(())) {
                            log::error!("failed to execute script: {}", error);
                        }
                    }
                }
                MyEvent::OpenFile(tx) => {
                    ignore_error(tx.send(open_file_dialog(window.hwnd() as HWND)));
                }
                MyEvent::Minimized => {
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.put_is_visible(false));
                    }
                }
                MyEvent::Restored => {
                    if let Some(ref host) = webview_host.borrow().as_ref() {
                        ignore_error(host.put_is_visible(true));
                        ignore_error(host.move_focus(webview2::MoveFocusReason::Programmatic));
                    }
                }
                MyEvent::Running => unsafe {
                    SendMessageA(window.hwnd() as HWND, WM_SETICON, ICON_BIG as _, icon as _);
                    notify_icon_data.hIcon = icon;
                    Shell_NotifyIconA(NIM_MODIFY, &mut notify_icon_data);
                },
                MyEvent::Stopped => unsafe {
                    SendMessageA(
                        window.hwnd() as HWND,
                        WM_SETICON,
                        ICON_BIG as _,
                        icon_red as _,
                    );
                    notify_icon_data.hIcon = icon_red;
                    Shell_NotifyIconA(NIM_MODIFY, &mut notify_icon_data);
                },
            },
            Event::MainEventsCleared => {
                // Application update code.

                // Queue a RedrawRequested event.
                window.request_redraw();
            }
            Event::RedrawRequested(_) => {}
            _ => (),
        }
    });
}
