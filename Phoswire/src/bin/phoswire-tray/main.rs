//! Phoswire tray: an icon in the notification area that opens a window
//! listing every whitelisted app, each folding open to show the addresses it
//! is connected to.
//!
//! It runs without administrator rights in the user's session and can only
//! look: it talks to the service over the read-only viewer pipe, which
//! refuses anything that would change the firewall. Changing the whitelist
//! happens in a separate window (`manage`) that runs with administrator
//! rights, started from the tray menu through UAC.
//!
//!   phoswire-tray            open the window (or bring it up if running)
//!   phoswire-tray --hidden   start with just the tray icon (for sign-in)
//!   phoswire-tray --manage   open the whitelist window (asks for
//!                            administrator rights)
//!   phoswire-tray --preview  without the service: every program with a
//!                            connection is shown as if it were whitelisted

#![windows_subsystem = "windows"]

mod icon;
mod manage;
mod names;
mod theme;
mod view;

use std::cell::RefCell;
use std::mem::{size_of, zeroed};
use std::net::IpAddr;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::Thread;
use std::time::Duration;

use phoswire::config::{Config, Mode, Source};
use phoswire::conns::{self, AppConnections};
use phoswire::ipc::{self, Reply, Request};
use phoswire::win::{self, wide};
use windows_sys::core::w;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::HiDpi::*;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use names::{Lookup, Resolver};
use view::View;

const CLASS: windows_sys::core::PCWSTR = w!("PhoswireTrayWindow");
const TITLE: &str = "Phoswire \u{2014} connections";

const WM_TRAY: u32 = WM_APP + 1;
const WM_SNAPSHOT: u32 = WM_APP + 2;
const WM_NAMES: u32 = WM_APP + 3;
const WM_SHOW: u32 = WM_APP + 4;
/// Take up the theme again; posted, so it runs when the window state is free.
const WM_RETHEME: u32 = WM_APP + 5;

const ID_LIST: usize = 100;
const ID_STATUS: usize = 101;
const ID_IDLE: usize = 102;
const ID_EXPAND: usize = 103;
const ID_COLLAPSE: usize = 104;
// Static-control styles (not in the windows-sys features used here).
const SS_LEFTNOWORDWRAP: u32 = 0xc;
const SS_CENTERIMAGE: u32 = 0x200;
const SS_ENDELLIPSIS: u32 = 0x4000;

const IDM_OPEN: usize = 1;
const IDM_EXIT: usize = 2;
const IDM_MANAGE: usize = 3;

/// How often the list is refreshed while the window is open, and the tray
/// tooltip while it is not.
const REFRESH_SHOWN: Duration = Duration::from_secs(2);
const REFRESH_HIDDEN: Duration = Duration::from_secs(15);

/// Sent by Explorer when the taskbar is recreated (Explorer restarted):
/// every tray icon must then be added again.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

enum Snapshot {
    Ok { mode: Mode, apps: Vec<AppConnections> },
    Err(String),
}

/// Shared between the window and the thread that asks the service.
struct Shared {
    visible: AtomicBool,
    latest: Mutex<Option<Snapshot>>,
    worker: OnceLock<Thread>,
}

struct App {
    hwnd: HWND,
    status: HWND,
    idle: HWND,
    expand: HWND,
    collapse: HWND,
    list: View,
    font: HFONT,
    dpi: u32,
    preview: bool,
    shared: Arc<Shared>,
    names: Resolver,
    snapshot: Option<Snapshot>,
    icon: HICON,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

/// Runs `f` on the window state, unless it is not set up yet or already in
/// use further up the stack (list-view calls send notifications back to the
/// window synchronously).
fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|app| app.try_borrow_mut().ok().and_then(|mut a| a.as_mut().map(f)))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let hidden = args.iter().any(|a| a == "--hidden");
    let preview = args.iter().any(|a| a == "--preview");
    if args.iter().any(|a| a == manage::ARG) {
        // A process of its own, with administrator rights; not the tray.
        manage::run(&args);
        return;
    }
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        // One per session: starting it again brings up the running one.
        let _instance = CreateMutexW(null(), 0, w!("Local\\PhoswireTray"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let other = FindWindowW(CLASS, null());
            if !other.is_null() {
                let mut pid = 0;
                GetWindowThreadProcessId(other, &mut pid);
                AllowSetForegroundWindow(pid);
                PostMessageW(other, WM_SHOW, 0, 0);
            }
            return;
        }

        let icc = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);
        TASKBAR_CREATED.store(RegisterWindowMessageW(w!("TaskbarCreated")), Ordering::Relaxed);

        let instance = GetModuleHandleW(null());
        // The pink neon ring, drawn at the sizes Windows asks for.
        let (big_icon, small_icon) = crate::icon::pair();
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            hIcon: big_icon,
            hIconSm: small_icon,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_WINDOW + 1) as usize as HBRUSH,
            lpszClassName: CLASS,
            ..zeroed()
        };
        RegisterClassExW(&class);

        let title = wide(TITLE);
        let hwnd = CreateWindowExW(
            0,
            CLASS,
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        if hwnd.is_null() {
            return;
        }
        // Size the window for the monitor it landed on.
        let dpi = GetDpiForWindow(hwnd).max(96);
        let scale = |v: i32| v * dpi as i32 / 96;
        SetWindowPos(hwnd, null_mut(), 0, 0, scale(960), scale(600), SWP_NOMOVE | SWP_NOZORDER);

        let child = |class: windows_sys::core::PCWSTR, text: &str, style: u32, id: usize| {
            let text = wide(text);
            CreateWindowExW(
                0,
                class,
                text.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                0,
                0,
                0,
                0,
                hwnd,
                id as HMENU,
                instance,
                null(),
            )
        };
        let status = child(w!("STATIC"), "Connecting to the Phoswire service\u{2026}", SS_LEFTNOWORDWRAP | SS_CENTERIMAGE | SS_ENDELLIPSIS, ID_STATUS);
        let expand = child(w!("BUTTON"), "Open all", WS_TABSTOP | BS_PUSHBUTTON as u32, ID_EXPAND);
        let collapse = child(w!("BUTTON"), "Close all", WS_TABSTOP | BS_PUSHBUTTON as u32, ID_COLLAPSE);
        let idle = child(w!("BUTTON"), "Show apps without connections", WS_TABSTOP | BS_AUTOCHECKBOX as u32, ID_IDLE);
        let list_hwnd = child(WC_LISTVIEWW, "", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, ID_LIST);

        let shared = Arc::new(Shared {
            visible: AtomicBool::new(!hidden),
            latest: Mutex::new(None),
            worker: OnceLock::new(),
        });
        let app = App {
            hwnd,
            status,
            idle,
            expand,
            collapse,
            list: View::new(list_hwnd, dpi),
            font: null_mut(),
            dpi,
            preview,
            shared: shared.clone(),
            names: Resolver::start(hwnd as usize, WM_NAMES),
            snapshot: None,
            icon: small_icon,
        };
        APP.with(|a| *a.borrow_mut() = Some(app));
        with_app(|a| {
            a.apply_font();
            a.apply_theme();
            a.layout();
            a.add_tray_icon();
        });

        // Ask the service on a thread of its own so a slow answer never
        // freezes the window.
        let s = shared.clone();
        let hwnd_value = hwnd as usize;
        let worker = std::thread::spawn(move || loop {
            let snapshot = fetch(preview);
            *s.latest.lock().unwrap() = Some(snapshot);
            PostMessageW(hwnd_value as HWND, WM_SNAPSHOT, 0, 0);
            let wait = if s.visible.load(Ordering::Relaxed) { REFRESH_SHOWN } else { REFRESH_HIDDEN };
            std::thread::park_timeout(wait);
        });
        let _ = shared.worker.set(worker.thread().clone());

        if !hidden {
            with_app(|a| a.show());
        }

        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

/// One look at the firewall: from the service, or (`--preview`) from the
/// connection table alone.
fn fetch(preview: bool) -> Snapshot {
    if preview {
        return Snapshot::Ok { mode: Mode::Normal, apps: preview_apps() };
    }
    match ipc::view_request(&Request::Connections) {
        Ok(Reply::Connections { mode, apps }) => Snapshot::Ok { mode, apps },
        Ok(Reply::Error { message }) => Snapshot::Err(message),
        Ok(_) => Snapshot::Err("unexpected answer from the service".into()),
        Err(e) => Snapshot::Err(e),
    }
}

/// Treats every program that has a connection as if it were whitelisted.
/// Without administrator rights some processes cannot be identified; their
/// connections are left out.
fn preview_apps() -> Vec<AppConnections> {
    let mut cfg = Config::default();
    let mut pids: Vec<u32> = win::tcp_table().iter().map(|r| r.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    for pid in pids {
        if let Some(path) = win::process_path(pid) {
            cfg.add(path, None, false, Source::Learned);
        }
    }
    conns::collect(&cfg.rules)
}

impl App {
    fn scale(&self, v: i32) -> i32 {
        v * self.dpi as i32 / 96
    }

    fn apply_font(&mut self) {
        unsafe {
            let mut metrics: NONCLIENTMETRICSW = zeroed();
            metrics.cbSize = size_of::<NONCLIENTMETRICSW>() as u32;
            SystemParametersInfoForDpi(
                SPI_GETNONCLIENTMETRICS,
                metrics.cbSize,
                &mut metrics as *mut _ as *mut _,
                0,
                self.dpi,
            );
            let font = CreateFontIndirectW(&metrics.lfMessageFont);
            for child in [self.status, self.idle, self.expand, self.collapse, self.list.hwnd] {
                SendMessageW(child, WM_SETFONT, font as WPARAM, 1);
            }
            if !self.font.is_null() {
                DeleteObject(self.font as HGDIOBJ);
            }
            self.font = font;
        }
    }

    /// Takes up the light or dark theme Windows asks for now.
    fn apply_theme(&mut self) {
        let theme = theme::reload();
        theme.apply_title_bar(self.hwnd);
        for button in [self.expand, self.collapse, self.idle] {
            theme.apply_button(button);
        }
        self.list.set_theme(&theme);
        unsafe {
            RedrawWindow(self.hwnd, null(), null_mut(), RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
        }
    }

    fn layout(&self) {
        unsafe {
            let mut rc: RECT = zeroed();
            GetClientRect(self.hwnd, &mut rc);
            let s = |v| self.scale(v);
            let (margin, bar) = (s(10), s(28));
            let (button, check) = (s(84), s(230));
            let mut x = rc.right - margin - check;
            MoveWindow(self.idle, x, margin, check, bar, 1);
            x -= s(8) + button;
            MoveWindow(self.collapse, x, margin, button, bar, 1);
            x -= s(6) + button;
            MoveWindow(self.expand, x, margin, button, bar, 1);
            MoveWindow(self.status, margin, margin, (x - s(12) - margin).max(0), bar, 1);
            let top = margin + bar + s(8);
            MoveWindow(self.list.hwnd, 0, top, rc.right, (rc.bottom - top).max(0), 1);
        }
    }

    fn show(&mut self) {
        unsafe {
            if IsIconic(self.hwnd) != 0 {
                ShowWindow(self.hwnd, SW_RESTORE);
            } else {
                ShowWindow(self.hwnd, SW_SHOW);
            }
            SetForegroundWindow(self.hwnd);
        }
        self.shared.visible.store(true, Ordering::Relaxed);
        // Refresh now rather than up to `REFRESH_HIDDEN` from now.
        if let Some(worker) = self.shared.worker.get() {
            worker.unpark();
        }
    }

    fn hide(&mut self) {
        unsafe { ShowWindow(self.hwnd, SW_HIDE) };
        self.shared.visible.store(false, Ordering::Relaxed);
    }

    fn tray_data(&self) -> NOTIFYICONDATAW {
        let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = 1;
        data
    }

    fn add_tray_icon(&self) {
        let mut data = self.tray_data();
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.uCallbackMessage = WM_TRAY;
        data.hIcon = self.icon;
        copy_tip(&mut data.szTip, "Phoswire");
        unsafe { Shell_NotifyIconW(NIM_ADD, &data) };
    }

    fn set_tooltip(&self, text: &str) {
        let mut data = self.tray_data();
        data.uFlags = NIF_TIP;
        copy_tip(&mut data.szTip, text);
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
    }

    fn remove_tray_icon(&self) {
        let data = self.tray_data();
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    }

    /// Takes the newest answer from the worker thread and shows it.
    fn take_snapshot(&mut self) {
        let latest = self.shared.latest.lock().unwrap().take();
        if let Some(s) = latest {
            self.snapshot = Some(s);
            self.render();
        }
    }

    fn render(&mut self) {
        let show_idle = unsafe { SendMessageW(self.idle, BM_GETCHECK, 0, 0) } == BST_CHECKED as isize;
        let (status, tip) = match &self.snapshot {
            None => return,
            Some(Snapshot::Err(e)) => (format!("Not connected: {e}"), "Phoswire: service unreachable".to_string()),
            Some(Snapshot::Ok { mode, apps }) => {
                let total: usize = apps.iter().map(|a| a.connections.len()).sum();
                let busy = apps.iter().filter(|a| !a.connections.is_empty()).count();
                let mode_text = match (self.preview, mode) {
                    (true, _) => "Preview (not from the service)",
                    (_, Mode::Normal) => "Normal mode",
                    (_, Mode::Learning) => "Learning mode: outbound traffic is open",
                    (_, Mode::Disabled) => "Disabled: Phoswire is not filtering",
                };
                (
                    format!(
                        "{mode_text}  \u{00b7}  {} whitelisted apps, {busy} with {total} open connection{}",
                        apps.len(),
                        if total == 1 { "" } else { "s" }
                    ),
                    format!("Phoswire: {mode}, {total} connection{}", if total == 1 { "" } else { "s" }),
                )
            }
        };
        let text = wide(&status);
        unsafe { SetWindowTextW(self.status, text.as_ptr()) };
        self.set_tooltip(&tip);

        // Fill the list only while it can be seen; the tooltip is enough otherwise.
        if !self.shared.visible.load(Ordering::Relaxed) {
            return;
        }
        let empty = Vec::new();
        let apps = match &self.snapshot {
            Some(Snapshot::Ok { apps, .. }) => apps,
            _ => &empty,
        };
        let names = &self.names;
        let mut host = |ip: IpAddr| match names.get(ip) {
            Lookup::Found(name) => name,
            Lookup::Pending => "\u{2026}".into(),
            Lookup::NoName => "\u{2014}".into(),
        };
        self.list.update(apps, show_idle, &mut host);
    }

    fn on_dpi_changed(&mut self, dpi: u32, suggested: &RECT) {
        self.dpi = dpi;
        self.apply_font();
        self.list.set_dpi(dpi);
        unsafe {
            SetWindowPos(
                self.hwnd,
                null_mut(),
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        self.layout();
    }
}

fn copy_tip(dst: &mut [u16; 128], text: &str) {
    let w: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

fn tray_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, IDM_OPEN, w!("&Open Phoswire"));
        AppendMenuW(menu, MF_STRING, IDM_MANAGE, w!("&Manage whitelist\u{2026}"));
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, IDM_EXIT, w!("E&xit tray icon"));
        SetMenuDefaultItem(menu, IDM_OPEN as u32, 0);
        let mut pt: POINT = zeroed();
        GetCursorPos(&mut pt);
        // Without this the menu does not close when clicking elsewhere.
        SetForegroundWindow(hwnd);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, null());
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let loword = |v: usize| v & 0xffff;
    match msg {
        WM_TRAY => {
            match lp as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                    with_app(|a| a.show());
                }
                WM_RBUTTONUP | WM_CONTEXTMENU => tray_menu(hwnd),
                _ => {}
            }
            0
        }
        WM_SHOW => {
            with_app(|a| a.show());
            0
        }
        WM_SNAPSHOT => {
            with_app(|a| a.take_snapshot());
            0
        }
        WM_NAMES => {
            with_app(|a| a.render());
            0
        }
        WM_COMMAND => {
            match loword(wp) {
                IDM_OPEN => {
                    with_app(|a| a.show());
                }
                IDM_MANAGE => manage::open(hwnd),
                IDM_EXIT => {
                    DestroyWindow(hwnd);
                }
                ID_IDLE => {
                    with_app(|a| a.render());
                }
                ID_EXPAND => {
                    with_app(|a| a.list.set_all_collapsed(false));
                }
                ID_COLLAPSE => {
                    with_app(|a| a.list.set_all_collapsed(true));
                }
                _ => {}
            }
            0
        }
        WM_SIZE => {
            with_app(|a| a.layout());
            0
        }
        WM_GETMINMAXINFO => {
            let info = &mut *(lp as *mut MINMAXINFO);
            let dpi = GetDpiForWindow(hwnd).max(96) as i32;
            info.ptMinTrackSize = POINT { x: 640 * dpi / 96, y: 320 * dpi / 96 };
            0
        }
        WM_DPICHANGED => {
            let suggested = &*(lp as *const RECT);
            with_app(|a| a.on_dpi_changed(loword(wp) as u32, suggested));
            0
        }
        WM_ERASEBKGND => {
            let mut rc: RECT = zeroed();
            GetClientRect(hwnd, &mut rc);
            FillRect(wp as HDC, &rc, theme::get().brush);
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            // Match the window background behind the label, the checkbox and
            // the corners of the buttons.
            let hdc = wp as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            let theme = theme::get();
            SetTextColor(hdc, theme.text);
            theme.brush as LRESULT
        }
        WM_NOTIFY => {
            let hdr = &*(lp as *const NMHDR);
            if hdr.idFrom == ID_IDLE && hdr.code == NM_CUSTOMDRAW {
                let cd = &*(lp as *const NMCUSTOMDRAW);
                theme::draw_checkbox(cd)
            } else if hdr.idFrom == ID_LIST && hdr.code == NM_CUSTOMDRAW {
                let cd = &*(lp as *const NMLVCUSTOMDRAW);
                view::custom_draw(cd)
            } else {
                DefWindowProcW(hwnd, msg, wp, lp)
            }
        }
        WM_RETHEME => {
            with_app(|a| a.apply_theme());
            0
        }
        WM_SETTINGCHANGE if theme::is_theme_setting(wp, lp) => {
            PostMessageW(hwnd, WM_RETHEME, 0, 0);
            DefWindowProcW(hwnd, msg, wp, lp)
        }
        WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
            PostMessageW(hwnd, WM_RETHEME, 0, 0);
            DefWindowProcW(hwnd, msg, wp, lp)
        }
        WM_CLOSE => {
            // Closing the window leaves the tray icon; Exit is in its menu.
            with_app(|a| a.hide());
            0
        }
        WM_DESTROY => {
            with_app(|a| a.remove_tray_icon());
            PostQuitMessage(0);
            0
        }
        m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
            with_app(|a| a.add_tray_icon());
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}
