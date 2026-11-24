//! Light and dark: the window follows the app mode chosen in Settings >
//! Personalization > Colors, and switches over when it is changed.
//!
//! Win32 controls have no dark mode of their own. The parts that can be
//! asked for one get it (the title bar, through DWM, and the buttons, list
//! and scroll bars, through the `DarkMode_Explorer` visual styles that ship
//! with Windows); the rest (backgrounds, text colours, the checkbox label)
//! are painted here. With a high-contrast theme on, the system colours are
//! left alone.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

use windows_sys::core::{w, BOOL, PCWSTR};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::HiDpi::OpenThemeDataForDpi;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// Windows 11's dark window background and text.
pub const DARK_BACKGROUND: COLORREF = rgb(0x20, 0x20, 0x20);
pub const DARK_TEXT: COLORREF = rgb(0xf0, 0xf0, 0xf0);
/// Less important text, such as an app's path under its name.
pub const DARK_SECONDARY_TEXT: COLORREF = rgb(0xa8, 0xa8, 0xa8);
/// Behind something the mouse is over.
pub const DARK_HOT: COLORREF = rgb(0x2d, 0x2d, 0x2d);

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

pub struct Theme {
    pub dark: bool,
    pub background: COLORREF,
    pub text: COLORREF,
    /// Solid `background`, for painting the window and its labels.
    pub brush: HBRUSH,
}

impl Theme {
    /// The theme Windows asks apps to use right now.
    pub fn current() -> Theme {
        let dark = apps_use_dark_mode();
        let (background, text) = if dark {
            (DARK_BACKGROUND, DARK_TEXT)
        } else {
            unsafe { (GetSysColor(COLOR_WINDOW), GetSysColor(COLOR_WINDOWTEXT)) }
        };
        Theme { dark, background, text, brush: unsafe { CreateSolidBrush(background) } }
    }

    /// The visual style name for a button, list or scroll bar: dark, or
    /// (`None`) the control's usual one.
    pub fn control_style(&self) -> Option<PCWSTR> {
        self.dark.then_some(w!("DarkMode_Explorer"))
    }

    /// Dark or light title bar (Windows 10 20H1 and later; ignored before).
    pub fn apply_title_bar(&self, hwnd: HWND) {
        let value: BOOL = self.dark as BOOL;
        unsafe {
            DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
                &value as *const BOOL as *const c_void,
                size_of::<BOOL>() as u32,
            );
        }
    }

    /// Gives a button the theme's visual style.
    pub fn apply_button(&self, hwnd: HWND) {
        unsafe { SetWindowTheme(hwnd, self.control_style().unwrap_or(null()), null()) };
    }
}

impl Drop for Theme {
    fn drop(&mut self) {
        unsafe { DeleteObject(self.brush as HGDIOBJ) };
    }
}

/// Whether the "Choose your app mode" setting is Dark. A high-contrast theme
/// brings its own colours, so it counts as not dark.
fn apps_use_dark_mode() -> bool {
    unsafe {
        let mut hc: HIGHCONTRASTW = zeroed();
        hc.cbSize = size_of::<HIGHCONTRASTW>() as u32;
        if SystemParametersInfoW(SPI_GETHIGHCONTRAST, hc.cbSize, &mut hc as *mut _ as *mut c_void, 0) != 0
            && hc.dwFlags & HCF_HIGHCONTRASTON != 0
        {
            return false;
        }
        let mut value: u32 = 1;
        let mut size = size_of::<u32>() as u32;
        let status = RegGetValueW(
            HKEY_CURRENT_USER,
            w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
            w!("AppsUseLightTheme"),
            RRF_RT_REG_DWORD,
            null_mut(),
            &mut value as *mut u32 as *mut c_void,
            &mut size,
        );
        status == ERROR_SUCCESS && value == 0
    }
}

/// Whether a `WM_SETTINGCHANGE` may mean the app mode or contrast changed.
pub fn is_theme_setting(wp: WPARAM, lp: LPARAM) -> bool {
    if wp as u32 == SPI_SETHIGHCONTRAST {
        return true;
    }
    if lp == 0 {
        return false;
    }
    let name = unsafe { phoswire::win::from_wide_ptr(lp as *const u16) };
    name == "ImmersiveColorSet"
}

/// Paints a checkbox for the dark theme, where the themed control would
/// write its label in black whatever colour it is asked for. Answers the
/// checkbox's `NM_CUSTOMDRAW`.
pub fn draw_checkbox(theme: &Theme, cd: &NMCUSTOMDRAW, font: HFONT, dpi: u32) -> LRESULT {
    if !theme.dark {
        return CDRF_DODEFAULT as LRESULT;
    }
    if cd.dwDrawStage != CDDS_PREPAINT {
        return CDRF_DODEFAULT as LRESULT;
    }
    let hwnd = cd.hdr.hwndFrom;
    let hdc = cd.hdc;
    let rc = cd.rc;
    unsafe {
        FillRect(hdc, &rc, theme.brush);

        let checked = SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
        let state = cd.uItemState;
        let mut part_state = if state & CDIS_DISABLED != 0 {
            CBS_UNCHECKEDDISABLED
        } else if state & CDIS_SELECTED != 0 {
            CBS_UNCHECKEDPRESSED
        } else if state & CDIS_HOT != 0 {
            CBS_UNCHECKEDHOT
        } else {
            CBS_UNCHECKEDNORMAL
        };
        if checked {
            part_state += CBS_CHECKEDNORMAL - CBS_UNCHECKEDNORMAL;
        }

        let mut box_size = SIZE { cx: 13 * dpi as i32 / 96, cy: 13 * dpi as i32 / 96 };
        let style = OpenThemeDataForDpi(hwnd, w!("Button"), dpi);
        if style != 0 {
            GetThemePartSize(style, hdc, BP_CHECKBOX, part_state, null(), TS_DRAW, &mut box_size);
        }
        let top = rc.top + (rc.bottom - rc.top - box_size.cy) / 2;
        let glyph = RECT { left: rc.left, top, right: rc.left + box_size.cx, bottom: top + box_size.cy };
        if style != 0 {
            DrawThemeBackground(style, hdc, BP_CHECKBOX, part_state, &glyph, null());
            CloseThemeData(style);
        } else {
            let mut frame = glyph;
            DrawFrameControl(hdc, &mut frame, DFC_BUTTON, DFCS_BUTTONCHECK | if checked { DFCS_CHECKED } else { 0 });
        }

        let len = GetWindowTextLengthW(hwnd);
        let mut text = vec![0u16; len as usize + 1];
        GetWindowTextW(hwnd, text.as_mut_ptr(), len + 1);
        let old_font = SelectObject(hdc, font as HGDIOBJ);
        SetBkMode(hdc, TRANSPARENT as i32);
        SetTextColor(hdc, if state & CDIS_DISABLED != 0 { GetSysColor(COLOR_GRAYTEXT) } else { theme.text });
        let mut label = RECT { left: glyph.right + 4 * dpi as i32 / 96, ..rc };
        let format = DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS;
        DrawTextW(hdc, text.as_ptr(), len, &mut label, format);

        let hide_focus = SendMessageW(hwnd, WM_QUERYUISTATE, 0, 0) as u32 & UISF_HIDEFOCUS != 0;
        if state & CDIS_FOCUS != 0 && !hide_focus {
            let mut focus = label;
            DrawTextW(hdc, text.as_ptr(), len, &mut focus, format | DT_CALCRECT);
            let height = focus.bottom - focus.top;
            focus.top = rc.top + (rc.bottom - rc.top - height) / 2;
            focus.bottom = focus.top + height;
            InflateRect(&mut focus, 1, 1);
            DrawFocusRect(hdc, &focus);
        }
        SelectObject(hdc, old_font);
    }
    CDRF_SKIPDEFAULT as LRESULT
}
