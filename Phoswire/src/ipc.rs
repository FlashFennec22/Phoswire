//! Control channel between the CLI and the service: one JSON line each way
//! over a named pipe that only SYSTEM and Administrators may open.

use std::io::{BufRead, BufReader, Write};
use std::mem::zeroed;
use std::ptr::null_mut;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::config::{Mode, Rule};
use crate::win::{last_error, sddl_to_sd, wide};

pub const PIPE_NAME: &str = r"\\.\pipe\phoswire";
const MAX_REQUEST: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    SetMode { mode: Mode },
    Allow { path: String, service: Option<String>, inbound: bool },
    Remove { path: String, service: Option<String> },
    RemoveIndex { index: usize },
    List,
    Blocked,
    ClearBlocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub mode: Mode,
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
    Error { message: String },
}

/// Sends one request to the running service.
pub fn request(req: &Request) -> Result<Reply, String> {
    let mut last = None;
    // The server handles one client at a time; retry briefly if it is busy.
    for _ in 0..20 {
        match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(mut pipe) => {
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
        std::io::ErrorKind::NotFound => {
            "the Phoswire service is not running (run `phoswire install` or `phoswire start` from an elevated prompt)".into()
        }
        std::io::ErrorKind::PermissionDenied => {
            "access denied: controlling the firewall requires an elevated (Administrator) prompt".into()
        }
        _ => format!("cannot reach the Phoswire service: {e}"),
    })
}

/// Serves requests forever on the calling thread.
pub fn serve(mut handler: impl FnMut(Request) -> Reply) -> Result<(), String> {
    // SYSTEM and Administrators only; no access for anyone else.
    let mut sd = sddl_to_sd("D:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.lpSecurityDescriptor = sd.as_mut_ptr().cast();

    let pipe: HANDLE = unsafe {
        CreateNamedPipeW(
            wide(PIPE_NAME).as_ptr(),
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
        return Err(format!("cannot create control pipe (error {})", last_error()));
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
