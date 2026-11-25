//! Starting and stopping the service and switching learning mode from the
//! tray menu.
//!
//! Like the whitelist window, these need administrator rights the tray does
//! not have. Each menu item starts a second copy of this program
//! (`phoswire-tray --control <action>`) through UAC; that elevated copy does
//! the one thing asked, the same way `phoswire start`, `phoswire stop` or
//! `phoswire mode` would in an elevated terminal, reports a failure in a
//! message box, and exits. Only the fixed actions below are accepted.

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use phoswire::config::Mode;
use phoswire::ipc::{self, Reply, Request};
use phoswire::service;
use phoswire::win::{self, wide};
use windows_sys::core::w;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// Command-line switch that runs one action instead of the tray.
pub const ARG: &str = "--control";
/// Added when this program restarts itself through UAC, so that a start that
/// still lacks administrator rights reports it rather than trying again.
const RELAUNCHED_ARG: &str = "--elevated";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    LearningOn,
    LearningOff,
}

impl Action {
    fn arg(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::LearningOn => "learning-on",
            Action::LearningOff => "learning-off",
        }
    }

    fn parse(s: &str) -> Option<Action> {
        [Action::Start, Action::Stop, Action::LearningOn, Action::LearningOff].into_iter().find(|a| a.arg() == s)
    }

    fn what(self) -> &'static str {
        match self {
            Action::Start => "start Phoswire",
            Action::Stop => "stop Phoswire",
            Action::LearningOn => "switch on learning mode",
            Action::LearningOff => "switch off learning mode",
        }
    }

    /// Does it, with administrator rights.
    fn perform(self) -> Result<(), String> {
        let mode = match self {
            Action::Start => return service::start().map(drop),
            Action::Stop => return service::stop().map(drop),
            Action::LearningOn => Mode::Learning,
            Action::LearningOff => Mode::Normal,
        };
        match ipc::request(&Request::SetMode { mode, hours: None })? {
            Reply::Done { .. } => Ok(()),
            Reply::Error { message } => Err(message),
            _ => Err("unexpected answer from the service".into()),
        }
    }
}

/// From the tray menu: runs `action` in an elevated copy of this program
/// (Windows asks through UAC). Once that copy has finished, `done` is posted
/// to `owner`, so the tray can look again; it is posted too if UAC was
/// declined.
pub fn launch(owner: HWND, action: Action, done: u32) {
    match launch_elevated(owner, action) {
        Ok(Some(process)) => {
            let (process, owner) = (process as usize, owner as usize);
            std::thread::spawn(move || unsafe {
                WaitForSingleObject(process as HANDLE, INFINITE);
                CloseHandle(process as HANDLE);
                PostMessageW(owner as HWND, done, 0, 0);
            });
        }
        Ok(None) => {}
        Err(e) => message(owner, &e),
    }
}

/// `phoswire-tray --control <action>`: does the action, then exits.
pub fn run(args: &[String]) {
    let action = args
        .iter()
        .position(|a| a == ARG)
        .and_then(|i| args.get(i + 1))
        .and_then(|a| Action::parse(a));
    let Some(action) = action else {
        message(null_mut(), "Unknown action. Use --control start, stop, learning-on or learning-off.");
        return;
    };
    if !win::is_elevated() {
        if args.iter().any(|a| a == RELAUNCHED_ARG) {
            message(
                null_mut(),
                &format!("Phoswire needs administrator rights to {}, and was started without them.", action.what()),
            );
        } else if let Err(e) = launch_elevated(null_mut(), action) {
            message(null_mut(), &e);
        }
        return;
    }
    if let Err(e) = action.perform() {
        message(null_mut(), &format!("Could not {}: {e}", action.what()));
    }
}

/// Starts this program again with administrator rights to do `action`; the
/// handle of the new process, or `None` if UAC was declined.
fn launch_elevated(owner: HWND, action: Action) -> Result<Option<HANDLE>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find phoswire-tray.exe: {e}"))?;
    let file = wide(&exe.to_string_lossy());
    let params = wide(&format!("{ARG} {} {RELAUNCHED_ARG}", action.arg()));
    unsafe {
        let mut info: SHELLEXECUTEINFOW = zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
        info.hwnd = owner;
        info.lpVerb = w!("runas");
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) != 0 {
            return Ok((!info.hProcess.is_null()).then_some(info.hProcess));
        }
    }
    match win::last_error() {
        ERROR_CANCELLED => Ok(None),
        code => Err(format!("Could not {} with administrator rights (error {code}).", action.what())),
    }
}

fn message(owner: HWND, text: &str) {
    let text = wide(text);
    unsafe { MessageBoxW(owner, text.as_ptr(), w!("Phoswire"), MB_OK | MB_ICONERROR) };
}
