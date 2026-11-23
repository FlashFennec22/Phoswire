//! The connection list: a report-style list view in which every whitelisted
//! app is a collapsible group, and each row of a group is one connection.
//!
//! Refreshes are applied as differences (rows added, removed or changed)
//! rather than by rebuilding the list, so which groups are open, the
//! selection and the scroll position all survive the refresh every couple of
//! seconds.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::IpAddr;

use phoswire::config::Rule;
use phoswire::conns::AppConnections;
use phoswire::win::wide;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{InvalidateRect, PtInRect};
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageW, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_SETREDRAW,
};

/// (title, width at 96 dpi, right-aligned)
const COLUMNS: [(&str, i32, bool); 6] = [
    ("Remote host", 300, false),
    ("Address", 230, false),
    ("Port", 60, true),
    ("State", 100, false),
    ("Direction", 80, false),
    ("PID", 70, true),
];
const NCOLS: usize = COLUMNS.len();

type Texts = [String; NCOLS];

/// One row: a connection, or the placeholder of an app that has none.
#[derive(Clone, PartialEq, Eq, Hash)]
struct RowKey {
    group: String,
    conn: Option<(u32, IpAddr, u16, u16)>,
}

struct Group {
    id: i32,
    header: String,
    subtitle: String,
}

struct Row {
    param: isize,
    texts: Texts,
}

/// What a refresh asks the list to show for one app.
struct WantedGroup {
    key: String,
    header: String,
    subtitle: String,
    /// Sort order: apps with connections first, then by name.
    sort: (bool, String),
    rows: Vec<(RowKey, Texts)>,
}

pub struct View {
    pub hwnd: HWND,
    groups: HashMap<String, Group>,
    rows: HashMap<RowKey, Row>,
    /// Group id -> sort key, for the sort callback.
    sort_keys: HashMap<i32, (bool, String)>,
    order: Vec<i32>,
    next_group: i32,
    next_param: isize,
}

fn send(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> isize {
    unsafe { SendMessageW(hwnd, msg, wp, lp) }
}

fn ptr<T>(v: &T) -> LPARAM {
    v as *const T as LPARAM
}

impl View {
    /// Sets up columns and groups on a freshly created list view.
    pub fn new(hwnd: HWND, dpi: u32) -> View {
        let ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER;
        send(hwnd, LVM_SETEXTENDEDLISTVIEWSTYLE, ex as WPARAM, ex as LPARAM);
        unsafe { SetWindowTheme(hwnd, windows_sys::core::w!("Explorer"), std::ptr::null()) };
        for (i, (title, _, right)) in COLUMNS.iter().enumerate() {
            let mut text = wide(title);
            let mut col: LVCOLUMNW = unsafe { zeroed() };
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM;
            col.fmt = if *right { LVCFMT_RIGHT } else { LVCFMT_LEFT };
            col.pszText = text.as_mut_ptr();
            col.iSubItem = i as i32;
            send(hwnd, LVM_INSERTCOLUMNW, i, ptr(&col));
        }
        send(hwnd, LVM_ENABLEGROUPVIEW, 1, 0);
        unsafe { SetWindowSubclass(hwnd, Some(list_subclass), 1, 0) };
        let view = View {
            hwnd,
            groups: HashMap::new(),
            rows: HashMap::new(),
            sort_keys: HashMap::new(),
            order: Vec::new(),
            next_group: 1,
            next_param: 1,
        };
        view.set_dpi(dpi);
        view
    }

    pub fn set_dpi(&self, dpi: u32) {
        for (i, (_, width, _)) in COLUMNS.iter().enumerate() {
            send(self.hwnd, LVM_SETCOLUMNWIDTH, i, (width * dpi as i32 / 96) as LPARAM);
        }
    }

    /// Brings the list in line with `apps`. `host` gives the text of the
    /// host-name column for an address.
    pub fn update(&mut self, apps: &[AppConnections], show_idle: bool, host: &mut dyn FnMut(IpAddr) -> String) {
        let mut wanted: Vec<WantedGroup> = Vec::new();
        for app in apps {
            if app.connections.is_empty() && !show_idle {
                continue;
            }
            let key = group_key(&app.rule);
            let rows = if app.connections.is_empty() {
                let mut texts: Texts = Default::default();
                texts[0] = "No open connections".into();
                vec![(RowKey { group: key.clone(), conn: None }, texts)]
            } else {
                app.connections
                    .iter()
                    .map(|c| {
                        let texts: Texts = [
                            host(c.remote),
                            c.remote.to_string(),
                            c.remote_port.to_string(),
                            c.state.clone(),
                            if c.inbound { "Inbound" } else { "Outbound" }.into(),
                            c.pid.to_string(),
                        ];
                        let conn = Some((c.pid, c.remote, c.remote_port, c.local_port));
                        (RowKey { group: key.clone(), conn }, texts)
                    })
                    .collect()
            };
            let name = display_name(&app.rule);
            let n = app.connections.len();
            let count = match n {
                0 => "no connections".to_string(),
                1 => "1 connection".to_string(),
                n => format!("{n} connections"),
            };
            wanted.push(WantedGroup {
                key,
                header: format!("{name}    \u{2014}    {count}"),
                subtitle: subtitle(&app.rule),
                sort: (n == 0, name.to_lowercase()),
                rows,
            });
        }

        send(self.hwnd, WM_SETREDRAW, 0, 0);
        self.apply(wanted);
        send(self.hwnd, WM_SETREDRAW, 1, 0);
        unsafe { InvalidateRect(self.hwnd, std::ptr::null(), 1) };
    }

    fn apply(&mut self, wanted: Vec<WantedGroup>) {
        // Rows that are gone, including those of groups that are gone.
        let keep: std::collections::HashSet<&RowKey> = wanted.iter().flat_map(|g| g.rows.iter().map(|(k, _)| k)).collect();
        let gone: Vec<RowKey> = self.rows.keys().filter(|k| !keep.contains(k)).cloned().collect();
        for key in gone {
            if let Some(row) = self.rows.remove(&key) {
                let index = self.index_of(row.param);
                if index >= 0 {
                    send(self.hwnd, LVM_DELETEITEM, index as WPARAM, 0);
                }
            }
        }
        let live: std::collections::HashSet<&str> = wanted.iter().map(|g| g.key.as_str()).collect();
        let dead: Vec<String> = self.groups.keys().filter(|k| !live.contains(k.as_str())).cloned().collect();
        for key in dead {
            if let Some(g) = self.groups.remove(&key) {
                send(self.hwnd, LVM_REMOVEGROUP, g.id as WPARAM, 0);
                self.sort_keys.remove(&g.id);
            }
        }

        // New and changed groups and rows.
        for g in &wanted {
            let id = match self.groups.get_mut(&g.key) {
                Some(existing) => {
                    if existing.header != g.header || existing.subtitle != g.subtitle {
                        existing.header = g.header.clone();
                        existing.subtitle = g.subtitle.clone();
                        set_group_text(self.hwnd, existing.id, &g.header, &g.subtitle);
                    }
                    existing.id
                }
                None => {
                    let id = self.next_group;
                    self.next_group += 1;
                    insert_group(self.hwnd, id, &g.header, &g.subtitle);
                    self.groups.insert(
                        g.key.clone(),
                        Group { id, header: g.header.clone(), subtitle: g.subtitle.clone() },
                    );
                    id
                }
            };
            self.sort_keys.insert(id, g.sort.clone());
            for (key, texts) in &g.rows {
                match self.rows.get_mut(key) {
                    Some(row) => {
                        let index = {
                            let fi = LVFINDINFOW { flags: LVFI_PARAM, lParam: row.param, ..unsafe { zeroed() } };
                            send(self.hwnd, LVM_FINDITEMW, usize::MAX, ptr(&fi)) as i32
                        };
                        for (col, text) in texts.iter().enumerate() {
                            if index >= 0 && row.texts[col] != *text {
                                set_text(self.hwnd, index, col, text);
                            }
                        }
                        row.texts = texts.clone();
                    }
                    None => {
                        let param = self.next_param;
                        self.next_param += 1;
                        insert_row(self.hwnd, id, param, texts);
                        self.rows.insert(key.clone(), Row { param, texts: texts.clone() });
                    }
                }
            }
        }

        // Group order: sort only when it would change, so nothing jumps.
        let mut order: Vec<(i32, &(bool, String))> =
            wanted.iter().map(|g| (self.groups[&g.key].id, &g.sort)).collect();
        order.sort_by(|a, b| a.1.cmp(b.1));
        let order: Vec<i32> = order.into_iter().map(|(id, _)| id).collect();
        if order != self.order {
            send(self.hwnd, LVM_SORTGROUPS, compare_groups as *const () as usize, ptr(&self.sort_keys));
            self.order = order;
        }
    }

    fn index_of(&self, param: isize) -> i32 {
        let fi = LVFINDINFOW { flags: LVFI_PARAM, lParam: param, ..unsafe { zeroed() } };
        send(self.hwnd, LVM_FINDITEMW, usize::MAX, ptr(&fi)) as i32
    }

    /// Opens or closes every app.
    pub fn set_all_collapsed(&self, collapsed: bool) {
        send(self.hwnd, WM_SETREDRAW, 0, 0);
        for g in self.groups.values() {
            set_collapsed(self.hwnd, g.id, collapsed);
        }
        send(self.hwnd, WM_SETREDRAW, 1, 0);
        unsafe { InvalidateRect(self.hwnd, std::ptr::null(), 1) };
    }
}

fn set_collapsed(lv: HWND, id: i32, collapsed: bool) {
    let mut g: LVGROUP = unsafe { zeroed() };
    g.cbSize = size_of::<LVGROUP>() as u32;
    g.mask = LVGF_STATE;
    g.stateMask = LVGS_COLLAPSED;
    g.state = if collapsed { LVGS_COLLAPSED } else { 0 };
    send(lv, LVM_SETGROUPINFO, id as WPARAM, ptr(&g));
}

/// The id of the group whose header (title, path and arrow) is at `pt`.
fn header_at(lv: HWND, pt: POINT) -> Option<i32> {
    let count = send(lv, LVM_GETGROUPCOUNT, 0, 0).max(0) as usize;
    (0..count).find_map(|index| {
        let mut g: LVGROUP = unsafe { zeroed() };
        g.cbSize = size_of::<LVGROUP>() as u32;
        g.mask = LVGF_GROUPID;
        if send(lv, LVM_GETGROUPINFOBYINDEX, index, &mut g as *mut _ as LPARAM) == 0 {
            return None;
        }
        // LVM_GETGROUPRECT reads which part to measure from `top`.
        let mut rect = RECT { left: 0, top: LVGGR_HEADER as i32, right: 0, bottom: 0 };
        let found = send(lv, LVM_GETGROUPRECT, g.iGroupId as WPARAM, &mut rect as *mut _ as LPARAM) != 0
            && unsafe { PtInRect(&rect, pt) } != 0;
        found.then_some(g.iGroupId)
    })
}

/// Makes a click anywhere on an app's header open or close it, not only a
/// click on the small arrow at the far end. The list view sends no click
/// notification for headers, so the mouse is watched directly.
unsafe extern "system" fn list_subclass(
    hwnd: HWND,
    msg: u32,
    wp: WPARAM,
    lp: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if matches!(msg, WM_LBUTTONDOWN | WM_LBUTTONDBLCLK | WM_LBUTTONUP) {
        let pt = POINT { x: (lp & 0xffff) as i16 as i32, y: ((lp >> 16) & 0xffff) as i16 as i32 };
        if let Some(id) = header_at(hwnd, pt) {
            if msg != WM_LBUTTONUP {
                SetFocus(hwnd);
                let state = send(hwnd, LVM_GETGROUPSTATE, id as WPARAM, LVGS_COLLAPSED as LPARAM) as u32;
                set_collapsed(hwnd, id, state & LVGS_COLLAPSED == 0);
            }
            // Swallowed, release included: left alone, the list view would
            // also select every connection in the group.
            return 0;
        }
    }
    DefSubclassProc(hwnd, msg, wp, lp)
}

unsafe extern "system" fn compare_groups(a: i32, b: i32, keys: *mut c_void) -> i32 {
    let keys = &*(keys as *const HashMap<i32, (bool, String)>);
    match keys.get(&a).cmp(&keys.get(&b)) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

fn group_key(rule: &Rule) -> String {
    format!("{}|{}", rule.path.to_lowercase(), rule.service.as_deref().unwrap_or("").to_lowercase())
}

/// `firefox.exe`, or `svchost.exe [Dnscache]` for a rule limited to one service.
fn display_name(rule: &Rule) -> String {
    let file = rule.path.rsplit('\\').next().unwrap_or(&rule.path);
    match &rule.service {
        Some(s) => format!("{file} [{s}]"),
        None => file.to_string(),
    }
}

/// The full path, and how the rule came about.
fn subtitle(rule: &Rule) -> String {
    let how = match rule.source {
        phoswire::config::Source::Manual => "added by hand",
        phoswire::config::Source::Learned => "learned",
    };
    let inbound = if rule.inbound { ", accepts inbound connections" } else { "" };
    format!("{}    ({how}{inbound})", rule.path)
}

fn insert_group(lv: HWND, id: i32, header: &str, subtitle: &str) {
    let mut header = wide(header);
    let mut subtitle = wide(subtitle);
    let mut g: LVGROUP = unsafe { zeroed() };
    g.cbSize = size_of::<LVGROUP>() as u32;
    g.mask = LVGF_HEADER | LVGF_SUBTITLE | LVGF_GROUPID | LVGF_STATE;
    g.pszHeader = header.as_mut_ptr();
    g.pszSubtitle = subtitle.as_mut_ptr();
    g.iGroupId = id;
    // Apps start folded: the list reads as a list of apps until one is opened.
    g.stateMask = LVGS_COLLAPSIBLE | LVGS_COLLAPSED;
    g.state = LVGS_COLLAPSIBLE | LVGS_COLLAPSED;
    send(lv, LVM_INSERTGROUP, usize::MAX, ptr(&g));
}

fn set_group_text(lv: HWND, id: i32, header: &str, subtitle: &str) {
    let mut header = wide(header);
    let mut subtitle = wide(subtitle);
    let mut g: LVGROUP = unsafe { zeroed() };
    g.cbSize = size_of::<LVGROUP>() as u32;
    g.mask = LVGF_HEADER | LVGF_SUBTITLE;
    g.pszHeader = header.as_mut_ptr();
    g.pszSubtitle = subtitle.as_mut_ptr();
    send(lv, LVM_SETGROUPINFO, id as WPARAM, ptr(&g));
}

fn insert_row(lv: HWND, group: i32, param: isize, texts: &Texts) {
    let mut first = wide(&texts[0]);
    let mut item: LVITEMW = unsafe { zeroed() };
    item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_GROUPID;
    item.iItem = i32::MAX; // append
    item.pszText = first.as_mut_ptr();
    item.lParam = param;
    item.iGroupId = group;
    let index = send(lv, LVM_INSERTITEMW, 0, ptr(&item)) as i32;
    if index >= 0 {
        for (col, text) in texts.iter().enumerate().skip(1) {
            set_text(lv, index, col, text);
        }
    }
}

fn set_text(lv: HWND, index: i32, col: usize, text: &str) {
    let mut text = wide(text);
    let mut item: LVITEMW = unsafe { zeroed() };
    item.iSubItem = col as i32;
    item.pszText = text.as_mut_ptr();
    send(lv, LVM_SETITEMTEXTW, index as WPARAM, ptr(&item));
}
