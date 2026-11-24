//! The tray and window icon: a pink neon ring with a soft glow.
//!
//! It is drawn here rather than loaded from a file, at exactly the size
//! Windows asks for, so it stays sharp at every display scale. Icons with an
//! alpha channel let the glow fade into whatever is behind it, light or dark
//! taskbar alike.

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// The bright middle of the tube, where neon looks almost white.
const HOT: [f32; 3] = [255.0, 214.0, 244.0];
/// The tube itself.
const TUBE: [f32; 3] = [255.0, 62.0, 190.0];
/// The light it throws around it.
const GLOW: [f32; 3] = [255.0, 24.0, 160.0];
/// How opaque the glow is right at the tube.
const GLOW_STRENGTH: f32 = 0.75;

/// The large (window, Alt+Tab) and small (title bar, tray) icons.
pub fn pair() -> (HICON, HICON) {
    let dpi = unsafe { GetDpiForSystem() };
    let big = unsafe { GetSystemMetricsForDpi(SM_CXICON, dpi) }.max(32);
    let small = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi) }.max(16);
    // Should Windows fail to make one, the stock shield beats no icon at all.
    let or_shield = |icon: HICON| match icon.is_null() {
        true => unsafe { LoadIconW(null_mut(), IDI_SHIELD) },
        false => icon,
    };
    (or_shield(create(big)), or_shield(create(small)))
}

/// A ring icon `size` pixels square; null if Windows could not make it.
pub fn create(size: i32) -> HICON {
    let pixels = pixels(size as usize);
    unsafe {
        let mut bmi: BITMAPINFO = zeroed();
        bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = size;
        bmi.bmiHeader.biHeight = -size; // top row first
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        let mut bits = null_mut();
        let color = CreateDIBSection(null_mut(), &bmi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if color.is_null() || bits.is_null() {
            return null_mut();
        }
        std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits as *mut u32, pixels.len());
        // With a 32-bit colour bitmap Windows takes transparency from its
        // alpha channel; the mask only has to exist, and be all zeros.
        let row_bytes = (size as usize).div_ceil(16) * 2;
        let zeros = vec![0u8; row_bytes * size as usize];
        let mask = CreateBitmap(size, size, 1, 1, zeros.as_ptr().cast());
        let info = ICONINFO { fIcon: 1, xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
        let icon = CreateIconIndirect(&info);
        DeleteObject(color as HGDIOBJ);
        DeleteObject(mask as HGDIOBJ);
        icon
    }
}

/// The ring as `n`×`n` pixels, top row first, each `0xAARRGGBB` with
/// straight (not premultiplied) alpha, as icons expect.
pub fn pixels(n: usize) -> Vec<u32> {
    let s = n as f32;
    let centre = s / 2.0;
    // Half the tube's thickness, and how far the glow reaches beyond it.
    // Small icons get a bolder tube and less glow, to read at tray size.
    let half = (s * 0.07).max(1.15);
    let spread = s * 0.075;
    // How white the middle of the tube gets: at tray size a white line
    // would read as a second ring, so it only shows in larger icons.
    let heat = ((s - 16.0) / 24.0).clamp(0.25, 1.0);
    // As large as the glow allows without being cut off at the edge.
    let radius = centre - half - 2.0 * spread;
    const SAMPLES: usize = 4;

    let mut out = Vec::with_capacity(n * n);
    for y in 0..n {
        for x in 0..n {
            // Coverage of the tube and of its white-hot middle, sampled on a
            // grid inside the pixel so the edges are smooth.
            let (mut tube, mut hot) = (0.0f32, 0.0f32);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let px = x as f32 + (sx as f32 + 0.5) / SAMPLES as f32;
                    let py = y as f32 + (sy as f32 + 0.5) / SAMPLES as f32;
                    let d = ((px - centre).hypot(py - centre) - radius).abs();
                    if d <= half {
                        tube += 1.0;
                        if d <= half * 0.4 {
                            hot += 1.0;
                        }
                    }
                }
            }
            let total = (SAMPLES * SAMPLES) as f32;
            let (tube, hot) = (tube / total, hot / total);

            let d = ((x as f32 + 0.5 - centre).hypot(y as f32 + 0.5 - centre) - radius).abs();
            let beyond = (d - half).max(0.0) / spread;
            let glow = GLOW_STRENGTH * (-beyond * beyond).exp();

            // The tube over its glow.
            let tube_colour = if tube > 0.0 { mix(TUBE, HOT, heat * hot / tube) } else { TUBE };
            let alpha = tube + glow * (1.0 - tube);
            let pixel = if alpha <= 0.0 {
                0
            } else {
                let channel = |i: usize| {
                    let v = (tube_colour[i] * tube + GLOW[i] * glow * (1.0 - tube)) / alpha;
                    v.round().clamp(0.0, 255.0) as u32
                };
                let a = (alpha * 255.0).round().clamp(0.0, 255.0) as u32;
                a << 24 | channel(0) << 16 | channel(1) << 8 | channel(2)
            };
            out.push(pixel);
        }
    }
    out
}

fn mix(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]
}
