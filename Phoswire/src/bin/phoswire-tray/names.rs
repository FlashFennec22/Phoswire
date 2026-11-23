//! Host names for remote addresses, looked up on a thread of their own.
//!
//! The best name for an address is the one a program asked for, so the
//! Windows DNS client cache is searched first: it turns 142.250.180.14 into
//! `www.youtube.com` rather than the `lhr25s34-in-f14.1e100.net` that a
//! reverse lookup gives. Addresses not in the cache (programs that do their
//! own name resolution, entries that have expired) fall back to reverse DNS.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use phoswire::win::{from_wide_ptr, wide};
use windows_sys::core::{s, w};
use windows_sys::Win32::NetworkManagement::Dns::{
    DnsFree, DnsFreeFlat, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_NO_WIRE_QUERY, DNS_RECORDA, DNS_TYPE_A,
    DNS_TYPE_AAAA, DNS_TYPE_CNAME,
};
use windows_sys::Win32::Networking::WinSock::{GetNameInfoW, WSAStartup, NI_NAMEREQD, SOCKADDR, WSADATA};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW;

/// The DNS cache is re-read at most this often.
const CACHE_REFRESH: Duration = Duration::from_secs(3);
/// Reverse lookups made at the same time.
const PARALLEL_LOOKUPS: usize = 8;
/// Forget everything beyond this many addresses.
const MAX_NAMES: usize = 8192;

pub enum Lookup {
    Pending,
    Found(String),
    NoName,
}

#[derive(Default)]
struct Known {
    names: HashMap<IpAddr, Option<String>>,
    pending: HashSet<IpAddr>,
}

pub struct Resolver {
    known: Arc<Mutex<Known>>,
    tx: Sender<IpAddr>,
}

impl Resolver {
    /// Starts the lookup thread, which posts `notify` to `hwnd` whenever it
    /// has learned new names.
    pub fn start(hwnd: usize, notify: u32) -> Resolver {
        let known = Arc::new(Mutex::new(Known::default()));
        let (tx, rx) = channel();
        let k = known.clone();
        std::thread::spawn(move || run(rx, k, hwnd, notify));
        Resolver { known, tx }
    }

    /// The name of `ip`, starting a lookup the first time it is asked for.
    pub fn get(&self, ip: IpAddr) -> Lookup {
        let mut known = self.known.lock().unwrap();
        match known.names.get(&ip) {
            Some(Some(name)) => Lookup::Found(name.clone()),
            Some(None) => Lookup::NoName,
            None => {
                if known.pending.insert(ip) {
                    let _ = self.tx.send(ip);
                }
                Lookup::Pending
            }
        }
    }
}

fn run(rx: Receiver<IpAddr>, known: Arc<Mutex<Known>>, hwnd: usize, notify: u32) {
    unsafe {
        let mut data: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut data);
    }
    let post = || unsafe { PostMessageW(hwnd as _, notify, 0, 0) };
    let store = |ip: IpAddr, name: Option<String>| {
        let mut known = known.lock().unwrap();
        if known.names.len() >= MAX_NAMES {
            known.names.clear();
        }
        known.pending.remove(&ip);
        known.names.insert(ip, name);
    };
    let mut cache = DnsCache::default();
    while let Ok(first) = rx.recv() {
        let batch: Vec<IpAddr> = std::iter::once(first).chain(rx.try_iter()).collect();
        cache.refresh();
        let mut reverse = Vec::new();
        for ip in batch {
            match cache.names.get(&ip) {
                Some((_, name)) => store(ip, Some(name.clone())),
                None => reverse.push(ip),
            }
        }
        post();
        // Reverse lookups can take seconds each when a server does not
        // answer, so several run at once.
        for chunk in reverse.chunks(PARALLEL_LOOKUPS) {
            std::thread::scope(|scope| {
                for &ip in chunk {
                    scope.spawn(move || store(ip, reverse_lookup(ip)));
                }
            });
            post();
        }
    }
}

/// Addresses found in the DNS client cache, each with the name it was
/// looked up by.
#[derive(Default)]
struct DnsCache {
    /// Address -> (the name was an alias, name).
    names: HashMap<IpAddr, (bool, String)>,
    read: Option<Instant>,
}

/// `DNS_CACHE_ENTRY`, as returned by the undocumented `DnsGetCacheDataTable`
/// (the call behind `ipconfig /displaydns`).
#[repr(C)]
struct CacheEntry {
    next: *mut CacheEntry,
    name: *mut u16,
    kind: u16,
    data_length: u16,
    flags: u32,
}

type GetCacheDataTable = unsafe extern "system" fn(*mut *mut CacheEntry) -> i32;

impl DnsCache {
    fn refresh(&mut self) {
        if self.read.is_some_and(|at| at.elapsed() < CACHE_REFRESH) {
            return;
        }
        self.read = Some(Instant::now());
        // Undocumented, so looked up at run time: if a Windows update removes
        // it, names simply come from reverse lookups alone.
        let get: GetCacheDataTable = unsafe {
            let lib = LoadLibraryW(w!("dnsapi.dll"));
            match GetProcAddress(lib, s!("DnsGetCacheDataTable")) {
                Some(f) => std::mem::transmute::<unsafe extern "system" fn() -> isize, GetCacheDataTable>(f),
                None => return,
            }
        };
        let mut entry = null_mut();
        if unsafe { get(&mut entry) } == 0 {
            return;
        }
        let mut seen = HashSet::new();
        while !entry.is_null() {
            unsafe {
                let e = &*entry;
                let name = from_wide_ptr(e.name);
                if (e.kind == DNS_TYPE_A || e.kind == DNS_TYPE_AAAA) && seen.insert((name.to_lowercase(), e.kind)) {
                    self.add_records(&name, e.kind);
                }
                let next = e.next;
                DnsFree(e.name.cast(), DnsFreeFlat);
                DnsFree(entry.cast(), DnsFreeFlat);
                entry = next;
            }
        }
    }

    /// Reads the cached records for `name` (never asking a server) and maps
    /// each address in them to `name`.
    fn add_records(&mut self, name: &str, kind: u16) {
        let mut records: *mut DNS_RECORDA = null_mut();
        let rc = unsafe {
            DnsQuery_W(wide(name).as_ptr(), kind, DNS_QUERY_NO_WIRE_QUERY, null_mut(), &mut records, null_mut())
        };
        if rc != 0 || records.is_null() {
            return;
        }
        // A name that led to its addresses through a CNAME is what the
        // program asked for (`www.youtube.com`); the end of the chain
        // (`youtube-ui.l.google.com`) is the provider's internal name. Both
        // are in the cache, so the alias is preferred.
        let alias = unsafe { (*records).wType } == DNS_TYPE_CNAME;
        let mut r = records;
        while !r.is_null() {
            let rec = unsafe { &*r };
            let ip: Option<IpAddr> = match rec.wType {
                DNS_TYPE_A => Some(Ipv4Addr::from(unsafe { rec.Data.A.IpAddress }.to_ne_bytes()).into()),
                DNS_TYPE_AAAA => Some(Ipv6Addr::from(unsafe { rec.Data.AAAA.Ip6Address.IP6Byte }).into()),
                _ => None,
            };
            if let Some(ip) = ip {
                let better = self.names.get(&ip).is_none_or(|(was_alias, _)| alias && !was_alias);
                if better {
                    self.names.insert(ip, (alias, name.to_string()));
                }
            }
            r = rec.pNext;
        }
        unsafe { DnsFree(records.cast(), DnsFreeRecordList) };
    }
}

/// The PTR name of an address, if it has one.
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    // SOCKADDR_IN / SOCKADDR_IN6, built by hand: family, port, then the address.
    #[repr(C, align(8))]
    struct Raw([u8; 28]);
    let mut raw = Raw([0; 28]);
    let len = match ip {
        IpAddr::V4(v4) => {
            raw.0[..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
            raw.0[4..8].copy_from_slice(&v4.octets());
            16
        }
        IpAddr::V6(v6) => {
            raw.0[..2].copy_from_slice(&23u16.to_ne_bytes()); // AF_INET6
            raw.0[8..24].copy_from_slice(&v6.octets());
            28
        }
    };
    let mut host = [0u16; 1025];
    let rc = unsafe {
        GetNameInfoW(
            raw.0.as_ptr() as *const SOCKADDR,
            len,
            host.as_mut_ptr(),
            host.len() as u32,
            null_mut(),
            0,
            NI_NAMEREQD as i32,
        )
    };
    (rc == 0).then(|| unsafe { from_wide_ptr(host.as_ptr()) }).filter(|n| !n.is_empty())
}
