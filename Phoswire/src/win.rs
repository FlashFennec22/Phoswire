//! Small Win32 helpers: strings, device paths, service SIDs, and mapping a
//! local port back to the process and services that own it.

use std::collections::{HashMap, HashSet};
use std::ptr::{null, null_mut};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::core::GUID;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::UI::Shell::{
    SHGetKnownFolderPath, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX64,
    FOLDERID_ProgramFilesX86,
};

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
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    GetSecurityInfo, SetNamedSecurityInfoW, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    IsWellKnownSid, LookupAccountNameW, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID,
};
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
const SERVICE_USERSERVICE_INSTANCE: u32 = 0x80;

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

// ---------------------------------------------------------------------------
// System folders
// ---------------------------------------------------------------------------
//
// These are asked of Windows, never read from environment variables. The
// elevated CLI inherits its environment from the unelevated user, who could
// otherwise point `ProgramFiles` at a folder of their own and have the
// service installed there, to run whatever they then put in it as SYSTEM.

fn known_folder(id: &GUID) -> Option<String> {
    let mut path = null_mut();
    let hr = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut path) };
    let found = (hr >= 0 && !path.is_null()).then(|| unsafe { from_wide_ptr(path) });
    unsafe { CoTaskMemFree(path.cast()) };
    found.filter(|p| !p.is_empty())
}

/// `C:\Program Files`
pub fn program_files() -> &'static str {
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_ProgramFiles).unwrap_or_else(|| r"C:\Program Files".into()))
}

/// `C:\ProgramData`
pub fn program_data() -> &'static str {
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| known_folder(&FOLDERID_ProgramData).unwrap_or_else(|| r"C:\ProgramData".into()))
}

/// `C:\Windows`
pub fn windows_dir() -> &'static str {
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| {
        let mut buf = [0u16; 260];
        let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            r"C:\Windows".into()
        } else {
            String::from_utf16_lossy(&buf[..n])
        }
    })
}

/// `C:\Windows\System32\svchost.exe`, the shared Windows service host.
pub fn system_svchost() -> String {
    format!("{}\\System32\\svchost.exe", windows_dir())
}

/// True only for the real service host, not any file that shares its name.
pub fn is_svchost(path: &str) -> bool {
    path.eq_ignore_ascii_case(&system_svchost())
}

/// True when `path` is under Program Files or Windows, where ordinary users
/// cannot write by default.
fn in_protected_dir(path: &str) -> bool {
    static DIRS: OnceLock<Vec<String>> = OnceLock::new();
    let dirs = DIRS.get_or_init(|| {
        let mut dirs = vec![program_files().to_string(), windows_dir().to_string()];
        dirs.extend(known_folder(&FOLDERID_ProgramFilesX86));
        dirs.extend(known_folder(&FOLDERID_ProgramFilesX64));
        dirs.iter().map(|d| d.to_ascii_lowercase()).collect()
    });
    let lower = path.to_ascii_lowercase();
    dirs.iter().any(|dir| lower.strip_prefix(dir.as_str()).is_some_and(|rest| rest.starts_with('\\')))
}

/// True when a program without administrator rights cannot put a different
/// file at `path`, so the file a rule trusts cannot simply be swapped.
///
/// Being under Program Files or Windows is not enough: both contain folders
/// any user can write to (`C:\Windows\Temp`, badly installed applications),
/// so the permissions of the file and of its folder are checked as well.
pub fn path_protected(path: &str) -> bool {
    if path.eq_ignore_ascii_case(crate::config::SYSTEM_APP) {
        return true;
    }
    if !in_protected_dir(path) {
        return false;
    }
    // A file that is missing or cannot be examined is judged by where it is.
    let open = |p: &Path| open_to_unprivileged(p).unwrap_or(false);
    let file = Path::new(path);
    !(open(file) || file.parent().is_some_and(open))
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
    // Drive letters get reassigned (removable media), so the map expires.
    const MAX_AGE: Duration = Duration::from_secs(30);
    const MISS_REFRESH: Duration = Duration::from_secs(5);
    type DriveMap = (Option<Instant>, Vec<(String, String)>);
    static MAP: Mutex<DriveMap> = Mutex::new((None, Vec::new()));
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
    let mut guard = MAP.lock().unwrap();
    let age = guard.0.map(|at| at.elapsed());
    if age.is_none_or(|a| a > MAX_AGE) {
        *guard = (Some(Instant::now()), device_map());
    }
    if let Some(p) = lookup(&guard.1) {
        return p;
    }
    // Unknown volume: it may have been mounted since the map was built. Paths
    // with no drive letter at all (network shares) must not rebuild it every time.
    if age.is_some_and(|a| a > MISS_REFRESH && a <= MAX_AGE) {
        *guard = (Some(Instant::now()), device_map());
        if let Some(p) = lookup(&guard.1) {
            return p;
        }
    }
    nt.to_string()
}

/// The NT device path of something that has no drive letter: an NT path is
/// passed through, and `\\server\share\app.exe` becomes
/// `\device\mup\server\share\app.exe`. Never touches the file, so the
/// service does not authenticate to a remote server just to build a rule.
pub fn device_path(path: &str) -> Option<String> {
    let lower = path.to_lowercase();
    if lower.starts_with("\\device\\") {
        return Some(lower);
    }
    let unc = lower.strip_prefix("\\\\")?;
    (!unc.starts_with(['?', '.'])).then(|| format!("\\device\\mup\\{unc}"))
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

fn sid_trusted(sid: PSID) -> bool {
    !sid.is_null()
        && unsafe {
            IsWellKnownSid(sid, WinLocalSystemSid) != 0 || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
}

/// SYSTEM, Administrators or TrustedInstaller (which owns Windows itself).
fn sid_privileged(sid: PSID) -> bool {
    const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    if sid_trusted(sid) {
        return true;
    }
    let mut text = null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return false;
    }
    let s = unsafe { from_wide_ptr(text) };
    unsafe { LocalFree(text.cast()) };
    s == TRUSTED_INSTALLER
}

/// True when the permissions let an account other than the privileged ones
/// change, replace or delete the object (for a folder: add or remove files).
///
/// # Safety
/// `dacl` must be null or point to a valid ACL.
pub unsafe fn dacl_open_to_unprivileged(dacl: *const ACL) -> bool {
    // FILE_WRITE_DATA / ADD_FILE, FILE_APPEND_DATA / ADD_SUBDIRECTORY,
    // FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
    const WRITE: u32 = 0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const INHERIT_ONLY_ACE: u8 = 0x08;
    if dacl.is_null() {
        return true; // no permissions at all: everyone has full access
    }
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    let size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    if GetAclInformation(dacl, (&mut info as *mut ACL_SIZE_INFORMATION).cast(), size, AclSizeInformation) == 0 {
        return false;
    }
    (0..info.AceCount).any(|i| {
        let mut ace = null_mut();
        if GetAce(dacl, i, &mut ace) == 0 {
            return false;
        }
        let ace = ace as *const ACCESS_ALLOWED_ACE;
        let header = (*ace).Header;
        // Inherit-only entries describe what children get, not this object.
        header.AceType == ACCESS_ALLOWED_ACE_TYPE
            && header.AceFlags & INHERIT_ONLY_ACE == 0
            && (*ace).Mask & WRITE != 0
            && !sid_privileged(std::ptr::addr_of!((*ace).SidStart) as PSID)
    })
}

/// Whether an unprivileged account owns or may modify the file or folder;
/// `None` if it does not exist or its permissions cannot be read.
fn open_to_unprivileged(path: &Path) -> Option<bool> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut sd = null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide(&path.to_string_lossy()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if rc != NO_ERROR {
        return None;
    }
    // An owner can always rewrite the permissions, whatever they say now.
    let open = !sid_privileged(owner) || unsafe { dacl_open_to_unprivileged(dacl) };
    unsafe { LocalFree(sd) };
    Some(open)
}

/// True when the file or directory is owned by SYSTEM or Administrators,
/// i.e. it was not planted by an unprivileged user.
pub fn path_owner_trusted(path: &Path) -> bool {
    let mut owner: PSID = null_mut();
    let mut sd = null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide(&path.to_string_lossy()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if rc != NO_ERROR {
        return false;
    }
    let trusted = sid_trusted(owner);
    unsafe { LocalFree(sd) };
    trusted
}

/// Same check for an open kernel object such as a named pipe. `Err` carries
/// the Win32 error when the owner could not be read at all.
pub fn handle_owner_trusted(handle: HANDLE) -> Result<bool, u32> {
    let mut owner: PSID = null_mut();
    let mut sd = null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if rc != NO_ERROR {
        return Err(rc);
    }
    let trusted = sid_trusted(owner);
    unsafe { LocalFree(sd) };
    Ok(trusted)
}

/// Gives a directory to Administrators and replaces its permissions with
/// "SYSTEM and Administrators only", cutting off what it inherited from its
/// parent. Windows re-derives the permissions of everything inside it.
pub fn lock_down(dir: &Path) -> Result<(), String> {
    let mut sd = sddl_to_sd("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let name = wide(&dir.to_string_lossy());
    unsafe {
        let (mut owner, mut owner_defaulted): (PSID, i32) = (null_mut(), 0);
        let (mut dacl, mut present, mut dacl_defaulted): (*mut ACL, i32, i32) = (null_mut(), 0, 0);
        if GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut owner_defaulted) == 0
            || GetSecurityDescriptorDacl(sd.as_mut_ptr().cast(), &mut present, &mut dacl, &mut dacl_defaulted) == 0
            || present == 0
        {
            return Err(format!("cannot build permissions for {}", dir.display()));
        }
        let rc = SetNamedSecurityInfoW(
            name.as_ptr() as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            null_mut(),
        );
        if rc != NO_ERROR {
            return Err(format!("cannot restrict {} to administrators (error {rc})", dir.display()));
        }
    }
    Ok(())
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

/// Processes that currently hold a TCP connection to another machine.
///
/// This is the learner's second source: unlike WFP net events it reports the
/// owning process directly, at the cost of missing connections that open and
/// close between two polls.
///
/// UDP sockets are deliberately not counted. They have no connections, so
/// all the table can show is that a socket exists, and trusting that would
/// whitelist programs (and the kernel, for NetBIOS) that never sent anything.
/// UDP traffic is learned from net events, which report actual packets.
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
                // Per-user service instances ("CDPUserSvc_1a2b3") get a new
                // name, and so a new SID, at every logon; a rule for one
                // would be dead by the next session.
                let per_user = e.ServiceStatusProcess.dwServiceType & SERVICE_USERSERVICE_INSTANCE != 0;
                if pid != 0 && !per_user {
                    out.entry(pid).or_default().push(from_wide_ptr(e.lpServiceName));
                }
            }
            break;
        }
        CloseServiceHandle(scm);
    }
    out
}
