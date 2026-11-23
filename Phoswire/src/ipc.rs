//! Control channel between the CLI and the service: one JSON line each way
//! over a named pipe that only SYSTEM and Administrators may open.
//!
//! A second, read-only pipe serves the tray window, which runs without
//! administrator rights: any signed-in user may open it, and it answers only
//! requests that change nothing (`Request::read_only`).

use std::io::{BufRead, BufReader, Write};
use std::mem::zeroed;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::config::{Mode, Rule};
use crate::conns::AppConnections;
use crate::win::{handle_owner_trusted, last_error, process_path, sddl_to_sd, wide};

pub const PIPE_NAME: &str = r"\\.\pipe\phoswire";
pub const VIEW_PIPE_NAME: &str = r"\\.\pipe\phoswire-view";
/// SYSTEM and Administrators only. The owner is set explicitly because
/// clients check it to tell the service from an impostor.
const PIPE_SDDL: &str = "O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)";
/// As above, plus read and write (0x12019b: everything in generic read and
/// write except creating further instances of the pipe) for users signed in
/// at the computer.
const VIEW_PIPE_SDDL: &str = "O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";
const MAX_REQUEST: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    SetMode {
        mode: Mode,
        /// Learning only: revert to normal after this many hours.
        #[serde(default)]
        hours: Option<u32>,
    },
    Allow {
        path: String,
        service: Option<String>,
        inbound: bool,
        /// Withdraw inbound access from an existing rule.
        #[serde(default)]
        outbound_only: bool,
    },
    Remove { path: String, service: Option<String> },
    RemoveIndex { index: usize },
    List,
    Blocked,
    ClearBlocked,
    /// The open connections of every whitelisted program.
    Connections,
}

impl Request {
    /// Requests the viewer pipe may answer: they report and change nothing.
    pub fn read_only(&self) -> bool {
        matches!(self, Request::Status | Request::List | Request::Blocked | Request::Connections)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub mode: Mode,
    /// Unix seconds; set while learning.
    #[serde(default)]
    pub learning_since: Option<u64>,
    #[serde(default)]
    pub learning_until: Option<u64>,
    pub rules: usize,
    pub filters: usize,
    pub warnings: Vec<String>,
    /// Shared-host connections seen while learning that could not be tied to
    /// a service and therefore were not whitelisted.
    pub unresolved: Vec<String>,
    #[serde(default)]
    pub counters: Counters,
}

/// Diagnostics since the service started.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counters {
    /// "Connection allowed" events received from WFP.
    pub allow_events: u64,
    /// "Connection dropped" events received from WFP (from any firewall).
    pub drop_events: u64,
    /// Events discarded because they named no application or an unrelated layer.
    pub ignored_events: u64,
    pub learned_from_events: u64,
    pub learned_from_sockets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocked {
    pub path: String,
    pub inbound: bool,
    pub protocol: u8,
    pub remote: String,
    pub count: u64,
    /// Unix seconds.
    pub last: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Done { message: String },
    Status(Status),
    Rules { rules: Vec<Rule> },
    Blocked { entries: Vec<Blocked> },
    Connections { mode: Mode, apps: Vec<AppConnections> },
    Error { message: String },
}

/// Sends one request to the running service.
pub fn request(req: &Request) -> Result<Reply, String> {
    request_on(PIPE_NAME, false, req)
}

/// Sends a read-only request over the viewer pipe, which needs no
/// administrator rights.
pub fn view_request(req: &Request) -> Result<Reply, String> {
    request_on(VIEW_PIPE_NAME, true, req)
}

fn request_on(name: &str, viewer: bool, req: &Request) -> Result<Reply, String> {
    let mut last = None;
    // The server handles one client at a time; retry briefly if it is busy.
    for _ in 0..20 {
        // Identification level: whoever serves the pipe may see who we are but
        // can never act with our (elevated) token.
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name);
        match opened {
            Ok(mut pipe) => {
                // An unprivileged program can create a pipe with this name
                // while the service is down; never talk to one.
                match handle_owner_trusted(pipe.as_raw_handle() as HANDLE) {
                    Ok(true) => {}
                    Ok(false) => {
                        // Name the culprit: the service cannot evict it, but
                        // an administrator can.
                        let mut pid = 0u32;
                        let found = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) };
                        let holder = match (found != 0 && pid != 0, process_path(pid)) {
                            (true, Some(path)) => format!("process {pid} ({path})"),
                            (true, None) => format!("process {pid}"),
                            (false, _) => "another program".into(),
                        };
                        return Err(format!(
                            "{name} is not served by the Phoswire service: {holder}, running without \
                             administrator rights, has taken the name. Refusing to use it. The firewall itself \
                             keeps filtering; end that program and the service takes the name back within seconds."
                        ));
                    }
                    Err(code) => return Err(format!("cannot verify who serves {name} (error {code})")),
                }
                let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
                line.push('\n');
                pipe.write_all(line.as_bytes()).map_err(|e| format!("sending request: {e}"))?;
                let mut reply = String::new();
                BufReader::new(pipe)
                    .read_line(&mut reply)
                    .map_err(|e| format!("reading reply: {e}"))?;
                return serde_json::from_str(&reply).map_err(|e| format!("bad reply from service: {e}"));
            }
            Err(e) => {
                let busy = e.raw_os_error() == Some(231); // ERROR_PIPE_BUSY
                last = Some(e);
                if !busy {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    let e = last.unwrap();
    Err(match e.kind() {
        std::io::ErrorKind::NotFound if viewer => {
            "the Phoswire service is not running, or is too old to have the viewer pipe".into()
        }
        std::io::ErrorKind::PermissionDenied if viewer => {
            "access denied: the viewer pipe is only open to users signed in at this computer".into()
        }
        std::io::ErrorKind::NotFound => {
            "the Phoswire service is not running (run `phoswire install` or `phoswire start` from an elevated prompt)".into()
        }
        std::io::ErrorKind::PermissionDenied => {
            "access denied: controlling the firewall requires an elevated (Administrator) prompt".into()
        }
        _ => format!("cannot reach the Phoswire service: {e}"),
    })
}

/// Serves the control pipe forever on the calling thread.
pub fn serve(handler: impl FnMut(Request) -> Reply) -> Result<(), String> {
    serve_on(PIPE_NAME, PIPE_SDDL, handler)
}

/// Serves the viewer pipe forever on the calling thread. Requests that would
/// change anything are refused here, whatever `handler` would do with them.
pub fn serve_view(mut handler: impl FnMut(Request) -> Reply) -> Result<(), String> {
    serve_on(VIEW_PIPE_NAME, VIEW_PIPE_SDDL, |req| {
        if req.read_only() {
            handler(req)
        } else {
            Reply::Error { message: "the viewer pipe is read-only; use `phoswire` from an elevated prompt".into() }
        }
    })
}

fn serve_on(name: &str, sddl: &str, mut handler: impl FnMut(Request) -> Reply) -> Result<(), String> {
    let mut sd = sddl_to_sd(sddl)?;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.lpSecurityDescriptor = sd.as_mut_ptr().cast();

    let pipe: HANDLE = unsafe {
        CreateNamedPipeW(
            wide(name).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_REQUEST as u32,
            MAX_REQUEST as u32,
            0,
            &sa,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(format!("cannot create {name} (error {})", last_error()));
    }

    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) } != 0 || last_error() == ERROR_PIPE_CONNECTED;
        if connected {
            let reply = match read_line(pipe) {
                Some(line) => match serde_json::from_slice::<Request>(&line) {
                    Ok(req) => handler(req),
                    Err(e) => Reply::Error { message: format!("bad request: {e}") },
                },
                None => Reply::Error { message: "incomplete request".into() },
            };
            let mut out = serde_json::to_vec(&reply).unwrap_or_default();
            out.push(b'\n');
            unsafe {
                let mut written = 0u32;
                WriteFile(pipe, out.as_ptr(), out.len() as u32, &mut written, null_mut());
                FlushFileBuffers(pipe);
            }
        } else if last_error() != 0 {
            // Unexpected failure; avoid a hot loop.
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        unsafe { DisconnectNamedPipe(pipe) };
    }
}

fn read_line(pipe: HANDLE) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut read = 0u32;
        let ok = unsafe { ReadFile(pipe, buf.as_mut_ptr(), buf.len() as u32, &mut read, null_mut()) };
        if ok == 0 || read == 0 {
            return None;
        }
        line.extend_from_slice(&buf[..read as usize]);
        if let Some(end) = line.iter().position(|&b| b == b'\n') {
            line.truncate(end);
            return Some(line);
        }
        if line.len() > MAX_REQUEST {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client-side impostor check must be able to read the owner of a
    /// pipe it opened at identification level. A pipe made by an ordinary
    /// (non-elevated) process is exactly what an impostor's looks like.
    #[test]
    fn pipe_owner_can_be_read_by_the_client() {
        let name = format!("{PIPE_NAME}-test-{}", std::process::id());
        let server = unsafe {
            CreateNamedPipeW(
                wide(&name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE, "error {}", last_error());
        let client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&name)
            .unwrap();
        let verdict = handle_owner_trusted(client.as_raw_handle() as HANDLE);
        println!("owner trusted: {verdict:?}");
        assert!(verdict.is_ok(), "{verdict:?}");
    }

    /// The tray runs without administrator rights, so an ordinary user must
    /// get through the viewer pipe's permissions.
    #[test]
    fn viewer_pipe_admits_signed_in_users() {
        let name = format!("{VIEW_PIPE_NAME}-test-{}", std::process::id());
        // Setting an Administrators owner needs elevation, so the test pipe
        // keeps its default owner. An unelevated client then refuses it as an
        // impostor, but only after the open has passed the access check.
        let sddl = VIEW_PIPE_SDDL.trim_start_matches("O:BAG:SY");
        let server = name.clone();
        std::thread::spawn(move || serve_on(&server, sddl, |_| Reply::Done { message: "seen".into() }));
        std::thread::sleep(std::time::Duration::from_millis(300));
        match request_on(&name, true, &Request::List) {
            Ok(Reply::Done { message }) => assert_eq!(message, "seen"), // elevated: owner is Administrators
            Ok(other) => panic!("unexpected reply {other:?}"),
            Err(e) => assert!(e.contains("is not served by the Phoswire service"), "{e}"),
        }
    }

    #[test]
    fn only_requests_that_change_nothing_are_read_only() {
        assert!(Request::Status.read_only());
        assert!(Request::List.read_only());
        assert!(Request::Blocked.read_only());
        assert!(Request::Connections.read_only());
        assert!(!Request::ClearBlocked.read_only());
        assert!(!Request::RemoveIndex { index: 1 }.read_only());
        assert!(!Request::Remove { path: "x".into(), service: None }.read_only());
        assert!(!Request::SetMode { mode: Mode::Learning, hours: None }.read_only());
        // Parsed rather than built, so fields added to `Allow` later need no change here.
        let allow: Request = serde_json::from_str(r#"{"cmd":"allow","path":"x","service":null,"inbound":false}"#).unwrap();
        assert!(!allow.read_only());
    }
}
