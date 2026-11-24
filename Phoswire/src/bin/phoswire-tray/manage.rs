//! The whitelist window: lists every rule, and lets an administrator delete
//! rules or add programs picked in the usual Windows file dialog.
//!
//! The tray itself never gets administrator rights. "Manage whitelist" in
//! its menu starts a second copy of this program (`phoswire-tray --manage`)
//! through UAC, and only that elevated copy shows this window. It changes the
//! whitelist over the same control pipe as `phoswire` in an elevated
//! terminal, which only Administrators may open: the window cannot do more
//! than the command line, and nothing it shows can be changed from an
//! unelevated program.

use std::cell::RefCell;
use std::mem::{size_of, zeroed};
use std::path::Path;
use std::ptr::{null, null_mut};

use phoswire::config::{self, Rule, Source};
use phoswire::ipc::{self, Reply, Request};
use phoswire::win::{self, wide};
use windows_sys::core::{w, PCWSTR};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::HiDpi::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus, VK_DELETE};
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::theme;

/// Command-line switch that opens this window instead of the tray.
pub const ARG: &str = "--manage";
/// Added when this program restarts itself through UAC, so that a start that
/// still lacks administrator rights reports it rather than trying again.
const RELAUNCHED_ARG: &str = "--elevated";

const CLASS: PCWSTR = w!("PhoswireWhitelistWindow");
const TITLE: &str = "Phoswire \u{2014} whitelist";

const ID_LIST: usize = 200;
const ID_STATUS: usize = 201;
const ID_ADD: usize = 202;
const ID_DELETE: usize = 203;
const TIMER_REFRESH: usize = 1;
/// Picks up rules learned or changed elsewhere while the window is open.
const REFRESH_MS: u32 = 5000;

const WM_RETHEME: u32 = WM_APP + 1;
const WM_REFRESH: u32 = WM_APP + 2;

// Static-control styles (not in the windows-sys features used here).
const SS_LEFTNOWORDWRAP: u32 = 0xc;
const SS_CENTERIMAGE: u32 = 0x200;
const SS_ENDELLIPSIS: u32 = 0x4000;

/// (title, width at 96 dpi)
const COLUMNS: [(&str, i32); 5] =
    [("Program", 190), ("Path", 430), ("Source", 80), ("Added", 90), ("Notes", 220)];

struct Manager {
    hwnd: HWND,
    status: HWND,
    add: HWND,
    delete: HWND,
    list: HWND,
    font: HFONT,
    dpi: u32,
    /// The rules as last read from the service, in the order shown. A row's
    /// `lParam` is its index here.
    rules: Vec<Rule>,
    /// The service's answer the list was built from, to rebuild only on change.
    shown: Option<String>,
    /// Why the service could not be asked, if it could not.
    error: Option<String>,
    /// The outcome of the last add or delete, shown next to the count.
    note: Option<String>,
}

thread_local! {
    static MANAGER: RefCell<Option<Manager>> = const { RefCell::new(None) };
}

/// Runs `f` on the window state, unless it is not set up yet or already in
/// use further up the stack (list-view calls and dialogs send messages back
/// to the window while they run).
fn with_mgr<R>(f: impl FnOnce(&mut Manager) -> R) -> Option<R> {
    MANAGER.with(|m| m.try_borrow_mut().ok().and_then(|mut m| m.as_mut().map(f)))
}

/// From the tray menu: brings up the whitelist window, starting it with
/// administrator rights (Windows asks through UAC) if it is not open yet.
pub fn open(owner: HWND) {
    if let Some(window) = existing_window() {
        bring_up(window);
        return;
    }
    if let Err(e) = launch_elevated(owner) {
        message(owner, &e, MB_ICONERROR);
    }
}

/// `phoswire-tray --manage`: shows the whitelist window until it is closed.
pub fn run(args: &[String]) {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        if !win::is_elevated() {
            if args.iter().any(|a| a == RELAUNCHED_ARG) {
                message(
                    null_mut(),
                    "Managing the whitelist needs administrator rights, and this window was started without them.",
                    MB_ICONERROR,
                );
            } else if let Err(e) = launch_elevated(null_mut()) {
                message(null_mut(), &e, MB_ICONERROR);
            }
            return;
        }
        if let Some(window) = existing_window() {
            bring_up(window);
            return;
        }

        // The file dialog is built on COM and wants a single-threaded apartment.
        CoInitializeEx(null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
        let icc = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);

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
        let dpi = GetDpiForWindow(hwnd).max(96);
        let scale = |v: i32| v * dpi as i32 / 96;
        SetWindowPos(hwnd, null_mut(), 0, 0, scale(1040), scale(560), SWP_NOMOVE | SWP_NOZORDER);

        let child = |class: PCWSTR, text: &str, style: u32, id: usize| {
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
        let status = child(
            w!("STATIC"),
            "Reading the whitelist\u{2026}",
            SS_LEFTNOWORDWRAP | SS_CENTERIMAGE | SS_ENDELLIPSIS,
            ID_STATUS,
        );
        let add = child(w!("BUTTON"), "Add entry\u{2026}", WS_TABSTOP | BS_PUSHBUTTON as u32, ID_ADD);
        let delete = child(w!("BUTTON"), "Delete entry", WS_TABSTOP | BS_PUSHBUTTON as u32, ID_DELETE);
        let list = child(WC_LISTVIEWW, "", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, ID_LIST);
        let ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;
        SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, ex as WPARAM, ex as LPARAM);
        for (i, (title, _)) in COLUMNS.iter().enumerate() {
            let mut text = wide(title);
            let mut col: LVCOLUMNW = zeroed();
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            col.pszText = text.as_mut_ptr();
            col.iSubItem = i as i32;
            SendMessageW(list, LVM_INSERTCOLUMNW, i, &col as *const _ as LPARAM);
        }
        SetWindowSubclass(list, Some(list_subclass), 1, 0);

        let mgr = Manager {
            hwnd,
            status,
            add,
            delete,
            list,
            font: null_mut(),
            dpi,
            rules: Vec::new(),
            shown: None,
            error: None,
            note: None,
        };
        MANAGER.with(|m| *m.borrow_mut() = Some(mgr));
        with_mgr(|m| {
            m.apply_font();
            m.set_column_widths();
            m.apply_theme();
            m.layout();
            m.refresh();
        });
        SetTimer(hwnd, TIMER_REFRESH, REFRESH_MS, None);

        ShowWindow(hwnd, SW_SHOWNORMAL);
        SetForegroundWindow(hwnd);
        SetFocus(list);

        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

/// Starts `phoswire-tray --manage` with administrator rights. Windows asks
/// the user through UAC; declining is not an error.
fn launch_elevated(owner: HWND) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find phoswire-tray.exe: {e}"))?;
    let file = wide(&exe.to_string_lossy());
    let params = wide(&format!("{ARG} {RELAUNCHED_ARG}"));
    unsafe {
        let mut info: SHELLEXECUTEINFOW = zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC;
        info.hwnd = owner;
        info.lpVerb = w!("runas");
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) != 0 {
            return Ok(());
        }
    }
    match win::last_error() {
        ERROR_CANCELLED => Ok(()),
        code => Err(format!("Could not start the whitelist window with administrator rights (error {code}).")),
    }
}

/// The whitelist window already open in this session, if any. Only a window
/// of this very program counts: any program may register the class name.
fn existing_window() -> Option<HWND> {
    let hwnd = unsafe { FindWindowW(CLASS, null()) };
    if hwnd.is_null() {
        return None;
    }
    let mut pid = 0;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    let theirs = win::process_path(pid)?;
    let ours = std::env::current_exe().ok()?;
    config::eq_ignore_case(&theirs, &ours.to_string_lossy()).then_some(hwnd)
}

fn bring_up(hwnd: HWND) {
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        SetForegroundWindow(hwnd);
    }
}

fn message(owner: HWND, text: &str, icon: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    let text = wide(text);
    unsafe { MessageBoxW(owner, text.as_ptr(), w!("Phoswire"), MB_OK | icon) }
}

fn ask(owner: HWND, text: &str) -> bool {
    let text = wide(text);
    let answer =
        unsafe { MessageBoxW(owner, text.as_ptr(), w!("Phoswire"), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) };
    answer == IDYES
}

/// Sends one change to the service; the message of its answer, or why not.
fn change(req: &Request) -> Result<String, String> {
    match ipc::request(req)? {
        Reply::Done { message } => Ok(message),
        Reply::Error { message } => Err(message),
        _ => Err("unexpected answer from the service".into()),
    }
}

impl Manager {
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
            for child in [self.status, self.add, self.delete, self.list] {
                SendMessageW(child, WM_SETFONT, font as WPARAM, 1);
            }
            if !self.font.is_null() {
                DeleteObject(self.font as HGDIOBJ);
            }
            self.font = font;
        }
    }

    fn set_column_widths(&self) {
        for (i, (_, width)) in COLUMNS.iter().enumerate() {
            unsafe { SendMessageW(self.list, LVM_SETCOLUMNWIDTH, i, self.scale(*width) as LPARAM) };
        }
    }

    /// Takes up the light or dark theme Windows asks for now.
    fn apply_theme(&mut self) {
        let theme = theme::reload();
        theme.apply_title_bar(self.hwnd);
        theme.apply_button(self.add);
        theme.apply_button(self.delete);
        unsafe {
            let header = SendMessageW(self.list, LVM_GETHEADER, 0, 0) as HWND;
            let (list_style, header_style) = match theme.control_style() {
                Some(dark) => (dark, w!("DarkMode_ItemsView")),
                None => (w!("Explorer"), null()),
            };
            SetWindowTheme(self.list, list_style, null());
            SetWindowTheme(header, header_style, null());
            SendMessageW(self.list, LVM_SETBKCOLOR, 0, theme.background as LPARAM);
            SendMessageW(self.list, LVM_SETTEXTBKCOLOR, 0, theme.background as LPARAM);
            SendMessageW(self.list, LVM_SETTEXTCOLOR, 0, theme.text as LPARAM);
            RedrawWindow(self.hwnd, null(), null_mut(), RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
        }
    }

    fn layout(&self) {
        unsafe {
            let mut rc: RECT = zeroed();
            GetClientRect(self.hwnd, &mut rc);
            let s = |v| self.scale(v);
            let (margin, bar, button) = (s(10), s(28), s(110));
            let mut x = rc.right - margin - button;
            MoveWindow(self.delete, x, margin, button, bar, 1);
            x -= s(6) + button;
            MoveWindow(self.add, x, margin, button, bar, 1);
            MoveWindow(self.status, margin, margin, (x - s(12) - margin).max(0), bar, 1);
            let top = margin + bar + s(8);
            MoveWindow(self.list, 0, top, rc.right, (rc.bottom - top).max(0), 1);
        }
    }

    /// Reads the whitelist again, and rebuilds the list if it changed.
    fn refresh(&mut self) {
        match ipc::request(&Request::List) {
            Ok(Reply::Rules { rules }) => {
                self.error = None;
                let answer = serde_json::to_string(&rules).unwrap_or_default();
                if self.shown.as_deref() != Some(answer.as_str()) {
                    self.shown = Some(answer);
                    self.rebuild(rules);
                }
            }
            Ok(Reply::Error { message }) => self.lost(message),
            Ok(_) => self.lost("unexpected answer from the service".into()),
            Err(e) => self.lost(e),
        }
        self.update_status();
        self.update_buttons();
    }

    fn lost(&mut self, why: String) {
        self.error = Some(why);
        if self.shown.take().is_some() {
            self.rebuild(Vec::new());
        }
    }

    fn rebuild(&mut self, mut rules: Vec<Rule>) {
        let selected: Vec<String> = self.selected().iter().map(|&i| key(&self.rules[i])).collect();
        rules.sort_by_cached_key(|r| (display_name(r).to_lowercase(), r.path.to_lowercase()));
        self.rules = rules;
        unsafe {
            SendMessageW(self.list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
            let mut first_selected = None;
            for (i, rule) in self.rules.iter().enumerate() {
                let texts = row_texts(rule);
                let mut first = wide(&texts[0]);
                let mut item: LVITEMW = zeroed();
                item.mask = LVIF_TEXT | LVIF_PARAM;
                item.iItem = i as i32;
                item.pszText = first.as_mut_ptr();
                item.lParam = i as isize;
                let index = SendMessageW(self.list, LVM_INSERTITEMW, 0, &item as *const _ as LPARAM) as i32;
                if index < 0 {
                    continue;
                }
                for (col, text) in texts.iter().enumerate().skip(1) {
                    let mut text = wide(text);
                    let mut sub: LVITEMW = zeroed();
                    sub.iSubItem = col as i32;
                    sub.pszText = text.as_mut_ptr();
                    SendMessageW(self.list, LVM_SETITEMTEXTW, index as WPARAM, &sub as *const _ as LPARAM);
                }
                if selected.contains(&key(rule)) {
                    let mut state: LVITEMW = zeroed();
                    state.stateMask = LVIS_SELECTED;
                    state.state = LVIS_SELECTED;
                    SendMessageW(self.list, LVM_SETITEMSTATE, index as WPARAM, &state as *const _ as LPARAM);
                    first_selected.get_or_insert(index);
                }
            }
            if let Some(index) = first_selected {
                SendMessageW(self.list, LVM_ENSUREVISIBLE, index as WPARAM, 0);
            }
            SendMessageW(self.list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.list, null(), 1);
        }
    }

    /// Indexes into `rules` of the selected rows.
    fn selected(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut index = -1i32;
        loop {
            index = unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, index as WPARAM, LVNI_SELECTED as LPARAM) }
                as i32;
            if index < 0 {
                break;
            }
            let mut item: LVITEMW = unsafe { zeroed() };
            item.mask = LVIF_PARAM;
            item.iItem = index;
            unsafe { SendMessageW(self.list, LVM_GETITEMW, 0, &mut item as *mut _ as LPARAM) };
            if let Ok(i) = usize::try_from(item.lParam) {
                if i < self.rules.len() {
                    out.push(i);
                }
            }
        }
        out
    }

    fn selected_rules(&self) -> Vec<Rule> {
        self.selected().into_iter().map(|i| self.rules[i].clone()).collect()
    }

    fn update_status(&self) {
        let text = match (&self.error, &self.note) {
            (Some(e), _) => format!("Not connected: {e}"),
            (None, note) => {
                let n = self.rules.len();
                let count = format!("{n} whitelisted entr{}", if n == 1 { "y" } else { "ies" });
                match note {
                    Some(note) => format!("{count}  \u{00b7}  {note}"),
                    None => count,
                }
            }
        };
        let text = wide(&text);
        unsafe { SetWindowTextW(self.status, text.as_ptr()) };
    }

    fn update_buttons(&self) {
        let connected = self.error.is_none();
        let any = connected && unsafe { SendMessageW(self.list, LVM_GETSELECTEDCOUNT, 0, 0) } > 0;
        unsafe {
            EnableWindow(self.add, connected as i32);
            EnableWindow(self.delete, any as i32);
        }
    }

    fn on_dpi_changed(&mut self, dpi: u32, suggested: &RECT) {
        self.dpi = dpi;
        self.apply_font();
        self.set_column_widths();
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

/// Identifies a rule across refreshes, to keep it selected.
fn key(rule: &Rule) -> String {
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

fn row_texts(rule: &Rule) -> [String; 5] {
    let source = match rule.source {
        Source::Manual => "by hand",
        Source::Learned => "learned",
    };
    let mut notes = Vec::new();
    if rule.inbound {
        notes.push("inbound");
    }
    if config::is_pattern(&rule.path) {
        notes.push("any version");
    } else if rule.exact {
        notes.push("this version only");
    }
    if !win::path_protected(&rule.path) {
        notes.push("unprotected path");
    }
    [display_name(rule), rule.path.clone(), source.into(), age(rule.added), notes.join(", ")]
}

fn age(then: u64) -> String {
    let secs = config::now().saturating_sub(then);
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// Asks the service to remove the selected rules, after confirming.
fn delete_selected() {
    let Some((hwnd, rules)) = with_mgr(|m| (m.hwnd, m.selected_rules())) else { return };
    if rules.is_empty() {
        return;
    }
    let question = match rules.as_slice() {
        [rule] => format!(
            "Remove this entry from the whitelist?\n\n{}\n\nIt will be blocked from the network until it is added again.",
            rule.subject()
        ),
        _ => {
            let mut list: Vec<String> = rules.iter().take(12).map(|r| r.subject()).collect();
            if rules.len() > list.len() {
                list.push(format!("\u{2026} and {} more", rules.len() - list.len()));
            }
            format!(
                "Remove these {} entries from the whitelist?\n\n{}\n\nThey will be blocked from the network until they are added again.",
                rules.len(),
                list.join("\n")
            )
        }
    };
    if !ask(hwnd, &question) {
        return;
    }
    let mut done = Vec::new();
    let mut failed = Vec::new();
    unsafe { SetCursor(LoadCursorW(null_mut(), IDC_WAIT)) };
    for rule in &rules {
        let req = Request::Remove { path: rule.path.clone(), service: rule.service.clone() };
        match change(&req) {
            Ok(message) => done.push(message),
            Err(e) => failed.push(format!("{}: {e}", rule.subject())),
        }
    }
    report(hwnd, done, failed, "removed", "Some entries could not be removed");
}

/// Lets the user pick programs and asks the service to whitelist them.
fn add_programs() {
    let Some(hwnd) = with_mgr(|m| m.hwnd) else { return };
    let picked = pick_programs(hwnd);
    if picked.is_empty() {
        return;
    }
    let mut failed = Vec::new();
    let mut paths = Vec::new();
    for file in picked {
        // The dialog only lists programs, but a name can still be typed in.
        let is_program = Path::new(&file).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"));
        if !is_program {
            failed.push(format!("{file}: only programs (.exe files) can be whitelisted"));
            continue;
        }
        match win::resolve_path(&file) {
            Ok(path) => paths.push(path),
            Err(e) => failed.push(e),
        }
    }

    // Rules trust a path, not a file: say so before trusting one that
    // programs without administrator rights could replace.
    let unprotected: Vec<&String> = paths.iter().filter(|p| !win::path_protected(p)).collect();
    if !unprotected.is_empty() {
        let list: Vec<&str> = unprotected.iter().map(|p| p.as_str()).collect();
        let question = format!(
            "{}\n\n{} in a folder where programs without administrator rights can change files. Phoswire trusts \
             the path, not the file, so anything put in {} place would be let through as well.\n\nWhitelist {} anyway?",
            list.join("\n"),
            if list.len() == 1 { "This program is" } else { "These programs are" },
            if list.len() == 1 { "its" } else { "their" },
            if list.len() == 1 { "it" } else { "them" },
        );
        if !ask(hwnd, &question) {
            paths.retain(|p| win::path_protected(p));
        }
    }

    let mut done = Vec::new();
    unsafe { SetCursor(LoadCursorW(null_mut(), IDC_WAIT)) };
    for path in paths {
        let req = Request::Allow { path: path.clone(), service: None, inbound: false, outbound_only: false, exact: false };
        match change(&req) {
            Ok(message) => done.push(message),
            Err(e) => failed.push(format!("{path}: {e}")),
        }
    }
    report(hwnd, done, failed, "added", "Some programs could not be whitelisted");
}

/// Shows the outcome of a change: in the status line when all went well and
/// the service has nothing more to say, otherwise in a message box.
fn report(hwnd: HWND, done: Vec<String>, failed: Vec<String>, verb: &str, failure: &str) {
    let note = match done.as_slice() {
        [] => None,
        [one] => one.lines().next().map(str::to_string),
        many => Some(format!("{} entries {verb}", many.len())),
    };
    with_mgr(|m| {
        if note.is_some() {
            m.note = note;
        }
        m.refresh();
    });
    // The service adds lines when there is more to know, such as a change
    // that could not be saved.
    let remarks: Vec<&String> = done.iter().filter(|m| m.contains('\n')).collect();
    if !failed.is_empty() {
        message(hwnd, &format!("{failure}:\n\n{}", failed.join("\n\n")), MB_ICONERROR);
    } else if !remarks.is_empty() {
        let text: Vec<&str> = remarks.iter().map(|m| m.as_str()).collect();
        message(hwnd, &text.join("\n\n"), MB_ICONINFORMATION);
    }
}

/// The usual Windows "Open" dialog, showing only programs. Returns the full
/// paths of the files chosen; none if the dialog was cancelled.
fn pick_programs(owner: HWND) -> Vec<String> {
    let mut buf = vec![0u16; 64 * 1024];
    let filter: Vec<u16> = "Programs (*.exe)\0*.exe\0\0".encode_utf16().collect();
    let initial = wide(win::program_files());
    let mut ofn: OPENFILENAMEW = unsafe { zeroed() };
    ofn.lStructSize = size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = buf.as_mut_ptr();
    ofn.nMaxFile = buf.len() as u32;
    ofn.lpstrInitialDir = initial.as_ptr();
    ofn.lpstrTitle = w!("Add programs to the Phoswire whitelist");
    ofn.Flags = OFN_EXPLORER
        | OFN_FILEMUSTEXIST
        | OFN_PATHMUSTEXIST
        | OFN_HIDEREADONLY
        | OFN_NOCHANGEDIR
        | OFN_DONTADDTORECENT
        | OFN_ALLOWMULTISELECT;
    if unsafe { GetOpenFileNameW(&mut ofn) } == 0 {
        let code = unsafe { CommDlgExtendedError() };
        if code == FNERR_BUFFERTOOSMALL {
            message(owner, "Too many files were selected at once; please choose fewer.", MB_ICONWARNING);
        } else if code != 0 {
            message(owner, &format!("The file dialog failed (error {code:#x})."), MB_ICONERROR);
        }
        return Vec::new();
    }
    // One file: its full path. Several: the folder, then each file name.
    let parts: Vec<String> =
        buf.split(|&c| c == 0).take_while(|s| !s.is_empty()).map(String::from_utf16_lossy).collect();
    match parts.as_slice() {
        [] => Vec::new(),
        [one] => vec![one.clone()],
        [dir, files @ ..] => {
            files.iter().map(|f| Path::new(dir).join(f).to_string_lossy().into_owned()).collect()
        }
    }
}

/// Paints the column titles in the dark theme, where the header style would
/// write them in black.
unsafe extern "system" fn list_subclass(
    hwnd: HWND,
    msg: u32,
    wp: WPARAM,
    lp: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if msg == WM_NOTIFY {
        let cd = &*(lp as *const NMCUSTOMDRAW);
        if cd.hdr.code == NM_CUSTOMDRAW && theme::get().dark {
            match cd.dwDrawStage {
                CDDS_PREPAINT => return CDRF_NOTIFYITEMDRAW as LRESULT,
                CDDS_ITEMPREPAINT => {
                    SetTextColor(cd.hdc, theme::DARK_TEXT);
                    return CDRF_DODEFAULT as LRESULT;
                }
                _ => {}
            }
        }
    }
    DefSubclassProc(hwnd, msg, wp, lp)
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let loword = |v: usize| v & 0xffff;
    match msg {
        WM_COMMAND => {
            match loword(wp) {
                ID_ADD => add_programs(),
                ID_DELETE => delete_selected(),
                _ => {}
            }
            0
        }
        WM_NOTIFY => {
            let hdr = &*(lp as *const NMHDR);
            if hdr.idFrom == ID_LIST {
                match hdr.code {
                    LVN_ITEMCHANGED => {
                        with_mgr(|m| m.update_buttons());
                    }
                    LVN_KEYDOWN => {
                        let key = &*(lp as *const NMLVKEYDOWN);
                        if key.wVKey == VK_DELETE {
                            PostMessageW(hwnd, WM_COMMAND, ID_DELETE, 0);
                        }
                    }
                    _ => {}
                }
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
        WM_TIMER if wp == TIMER_REFRESH => {
            if IsIconic(hwnd) == 0 {
                with_mgr(|m| m.refresh());
            }
            0
        }
        WM_ACTIVATE => {
            if loword(wp) as u32 != WA_INACTIVE {
                PostMessageW(hwnd, WM_REFRESH, 0, 0);
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
        WM_REFRESH => {
            with_mgr(|m| m.refresh());
            0
        }
        WM_SIZE => {
            with_mgr(|m| m.layout());
            0
        }
        WM_GETMINMAXINFO => {
            let info = &mut *(lp as *mut MINMAXINFO);
            let dpi = GetDpiForWindow(hwnd).max(96) as i32;
            info.ptMinTrackSize = POINT { x: 560 * dpi / 96, y: 280 * dpi / 96 };
            0
        }
        WM_DPICHANGED => {
            let suggested = &*(lp as *const RECT);
            with_mgr(|m| m.on_dpi_changed(loword(wp) as u32, suggested));
            0
        }
        WM_ERASEBKGND => {
            let mut rc: RECT = zeroed();
            GetClientRect(hwnd, &mut rc);
            FillRect(wp as HDC, &rc, theme::get().brush);
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = wp as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            let theme = theme::get();
            SetTextColor(hdc, theme.text);
            theme.brush as LRESULT
        }
        WM_RETHEME => {
            with_mgr(|m| m.apply_theme());
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
        WM_DESTROY => {
            KillTimer(hwnd, TIMER_REFRESH);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}
