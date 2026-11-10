//! Small Win32 helpers: strings, device paths, service SIDs, and mapping a
//! local port back to the process and services that own it.

use std::collections::{HashMap, HashSet};
use std::ptr::{null, null_mut};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, NO_ERROR,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::LookupAccountNameW;
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE,
    SERVICE_WIN32,
};

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const SDDL_REVISION_1: u32 = 1;

/// NUL-terminated UTF-16.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

pub fn last_error() -> u32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}

pub fn is_svchost(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with("\\svchost.exe")
}

// ---------------------------------------------------------------------------
// Device paths
// ---------------------------------------------------------------------------

/// `\device\harddiskvolume3` (lower case) -> `C:`
fn device_map() -> Vec<(String, String)> {
    let mut map = Vec::new();
    let mut buf = [0u16; 512];
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let n = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n > 0 {
            let target = unsafe { from_wide_ptr(buf.as_ptr()) };
            map.push((target.to_ascii_lowercase(), drive));
        }
    }
    // Longest device name first so `harddiskvolume1` never shadows `harddiskvolume10`.
    map.sort_by_key(|(dev, _)| std::cmp::Reverse(dev.len()));
    map
}

/// Converts `C:\dir\app.exe` into the lower-case NT device path WFP uses as
/// an application id (`\device\harddiskvolume3\dir\app.exe`), without opening
/// the file.
pub fn dos_to_nt(path: &str) -> Option<String> {
    let (drive, rest) = (path.get(..2)?, path.get(2..)?);
    if !drive.ends_with(':') || !rest.starts_with('\\') {
        return None;
    }
    let mut buf = [0u16; 512];
    let n = unsafe { QueryDosDeviceW(wide(drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    let device = unsafe { from_wide_ptr(buf.as_ptr()) };
    Some(format!("{device}{rest}").to_lowercase())
}

/// Converts the NT device path WFP reports (`\device\harddiskvolume3\...`)
/// into a drive-letter path. Anything else (e.g. `System`) is returned as is.
pub fn nt_to_dos(nt: &str) -> String {
    static MAP: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    if !nt.starts_with('\\') {
        return nt.to_string();
    }
    let lower = nt.to_ascii_lowercase();
    let lookup = |map: &[(String, String)]| {
        map.iter().find_map(|(dev, drive)| {
            let rest = lower.strip_prefix(dev.as_str())?;
            rest.starts_with('\\').then(|| format!("{}{}", drive, &nt[dev.len()..]))
        })
    };
    let mut map = MAP.lock().unwrap();
    if let Some(p) = lookup(&map) {
        return p;
    }
    // Unknown volume: drives may have been mounted since the map was built.
    *map = device_map();
    lookup(&map).unwrap_or_else(|| nt.to_string())
}

// ---------------------------------------------------------------------------
// Security descriptors
// ---------------------------------------------------------------------------

/// Converts SDDL into a self-relative security descriptor.
pub fn sddl_to_sd(sddl: &str) -> Result<Vec<u8>, String> {
    let mut sd = null_mut();
    let mut len = 0u32;
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(format!("bad security descriptor `{sddl}` (error {})", last_error()));
    }
    let bytes = unsafe { std::slice::from_raw_parts(sd as *const u8, len as usize).to_vec() };
    unsafe { LocalFree(sd) };
    Ok(bytes)
}

/// The `S-1-5-80-…` SID of a Windows service.
fn service_sid_string(service: &str) -> Result<String, String> {
    let account = wide(&format!("NT SERVICE\\{service}"));
    let mut sid = [0u8; 256];
    let mut sid_len = sid.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = 0;
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(format!("unknown service `{service}` (error {})", last_error()));
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) } == 0 {
        return Err(format!("cannot format SID of service `{service}`"));
    }
    let s = unsafe { from_wide_ptr(text) };
    unsafe { LocalFree(text.cast()) };
    Ok(s)
}

/// A security descriptor that only a token carrying the service's SID passes;
/// used as a WFP `ALE_USER_ID` condition to scope a rule to one service.
pub fn service_sd(service: &str) -> Result<Vec<u8>, String> {
    let sid = service_sid_string(service)?;
    sddl_to_sd(&format!("O:SYG:SYD:(A;;CCRC;;;{sid})"))
}

// ---------------------------------------------------------------------------
// Port -> process -> services
// ---------------------------------------------------------------------------

/// Calls a `GetExtended*Table`-style function, growing the buffer as needed.
/// The buffer is `u64`-backed so the table structs are suitably aligned.
fn fetch_table(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size = 0u32;
    call(null_mut(), &mut size);
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 64];
        size = (buf.len() * 8) as u32;
        match call(buf.as_mut_ptr().cast(), &mut size) {
            NO_ERROR => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return None,
        }
    }
    None
}

fn net_port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

/// Finds the process that currently owns `local_port`.
pub fn pid_for_port(protocol: u8, v6: bool, local_port: u16) -> Option<u32> {
    let af = if v6 { AF_INET6 } else { AF_INET };
    unsafe {
        match protocol {
            IPPROTO_TCP => {
                let buf = fetch_table(|p, s| GetExtendedTcpTable(p, s, 0, af, TCP_TABLE_OWNER_PID_ALL, 0))?;
                if v6 {
                    let t = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                    let rows: &[MIB_TCP6ROW_OWNER_PID] =
                        std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
                    rows.iter().find(|r| net_port(r.dwLocalPort) == local_port).map(|r| r.dwOwningPid)
                } else {
                    let t = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                    let rows: &[MIB_TCPROW_OWNER_PID] =
                        std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
                    rows.iter().find(|r| net_port(r.dwLocalPort) == local_port).map(|r| r.dwOwningPid)
                }
            }
            IPPROTO_UDP => {
                let buf = fetch_table(|p, s| GetExtendedUdpTable(p, s, 0, af, UDP_TABLE_OWNER_PID, 0))?;
                if v6 {
                    let t = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
                    let rows: &[MIB_UDP6ROW_OWNER_PID] =
                        std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
                    rows.iter().find(|r| net_port(r.dwLocalPort) == local_port).map(|r| r.dwOwningPid)
                } else {
                    let t = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                    let rows: &[MIB_UDPROW_OWNER_PID] =
                        std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
                    rows.iter().find(|r| net_port(r.dwLocalPort) == local_port).map(|r| r.dwOwningPid)
                }
            }
            _ => None,
        }
    }
}

/// Processes that currently hold a non-loopback TCP connection or UDP socket.
///
/// This is the learner's second source: unlike WFP net events it reports the
/// owning process directly, at the cost of missing connections that open and
/// close between two polls.
pub fn network_pids() -> HashSet<u32> {
    const LISTEN: u32 = 2; // MIB_TCP_STATE_LISTEN
    const V6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let v4_external = |addr: u32| addr != 0 && addr & 0xff != 127;
    let mut pids = HashSet::new();
    unsafe {
        if let Some(buf) = fetch_table(|p, s| GetExtendedTcpTable(p, s, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) {
            let t = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let rows: &[MIB_TCPROW_OWNER_PID] =
                std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
            pids.extend(
                rows.iter()
                    .filter(|r| r.dwState != LISTEN && v4_external(r.dwRemoteAddr))
                    .map(|r| r.dwOwningPid),
            );
        }
        if let Some(buf) = fetch_table(|p, s| GetExtendedTcpTable(p, s, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) {
            let t = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
            let rows: &[MIB_TCP6ROW_OWNER_PID] =
                std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
            pids.extend(
                rows.iter()
                    .filter(|r| r.dwState != LISTEN && r.ucRemoteAddr != [0; 16] && r.ucRemoteAddr != V6_LOOPBACK)
                    .map(|r| r.dwOwningPid),
            );
        }
        // UDP has no connections, so a socket bound to a real interface (or
        // to every interface) is the best available sign of network use.
        if let Some(buf) = fetch_table(|p, s| GetExtendedUdpTable(p, s, 0, AF_INET, UDP_TABLE_OWNER_PID, 0)) {
            let t = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
            let rows: &[MIB_UDPROW_OWNER_PID] =
                std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
            pids.extend(rows.iter().filter(|r| r.dwLocalAddr & 0xff != 127).map(|r| r.dwOwningPid));
        }
        if let Some(buf) = fetch_table(|p, s| GetExtendedUdpTable(p, s, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0)) {
            let t = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
            let rows: &[MIB_UDP6ROW_OWNER_PID] =
                std::slice::from_raw_parts((*t).table.as_ptr(), (*t).dwNumEntries as usize);
            pids.extend(rows.iter().filter(|r| r.ucLocalAddr != V6_LOOPBACK).map(|r| r.dwOwningPid));
        }
    }
    pids.remove(&0);
    pids
}

/// Full image path of a process; `System` for the kernel.
pub fn process_path(pid: u32) -> Option<String> {
    if pid == 4 {
        return Some(crate::config::SYSTEM_APP.to_string());
    }
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(process);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Running Win32 services grouped by the process that hosts them.
pub fn services_by_pid() -> HashMap<u32, Vec<String>> {
    let mut out: HashMap<u32, Vec<String>> = HashMap::new();
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return out;
        }
        let mut buf: Vec<u64> = vec![0; 32 * 1024];
        for _ in 0..4 {
            let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                null(),
            );
            if ok == 0 {
                if last_error() == ERROR_MORE_DATA {
                    buf = vec![0; buf.len() + (needed as usize).div_ceil(8) + 1024];
                    continue;
                }
                break;
            }
            let entries = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                count as usize,
            );
            for e in entries {
                let pid = e.ServiceStatusProcess.dwProcessId;
                if pid != 0 {
                    out.entry(pid).or_default().push(from_wide_ptr(e.lpServiceName));
                }
            }
            break;
        }
        CloseServiceHandle(scm);
    }
    out
}
