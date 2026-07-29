# overlay

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/overlay.rs` |
| **Lines** | 630 |
| **Cards** | T023-client-capabilities |
| **Role** | Win32 layered overlay manager: GIF support, WDA_EXCLUDEFROMCAPTURE |
| **Unsafe blocks** | 7 |

## Constants

- `WM_UPDATE_IMAGE`: `u32` = `0x0401`
- `WM_SET_OPACITY`: `u32` = `0x0402`
- `WM_MOVE_OVERLAY`: `u32` = `0x0403` — wparam=x, lparam=y (signed i32 packed)
- `WM_RESIZE_OVERLAY`: `u32` = `0x0404` — wparam=w, lparam=h
- `GIF_TIMER_ID`: `usize` = `1`
- `WDA_EXCLUDEFROMCAPTURE`: `u32` = `0x11`

## Types

### struct `OverlayState` (line 30)

### struct `ScreenOverlay` (line 266)

### struct `OverlayManager` (line 545)

### struct `ScreenOverlay` (line 606)

### struct `OverlayManager` (line 617)

## Public API

### `new` (line 274)
```rust
pub fn new() -> Self
```

### `show` (line 296)
```rust
pub fn show(&mut self, image_data: &[u8], opacity: u32)
```

### `show_at` (line 302)
```rust
pub fn show_at(&mut self, image_data: &[u8], opacity: u32,
```
Show overlay at a specific position and size.
win_w / win_h == 0 → fullscreen.

### `close` (line 336)
```rust
pub fn close(&mut self)
```

### `set_opacity` (line 354)
```rust
pub fn set_opacity(&self, percent: u32)
```

### `move_to` (line 364)
```rust
pub fn move_to(&self, x: i32, y: i32)
```
Reposition the overlay window (PostMessage to the window thread).

### `resize_to` (line 374)
```rust
pub fn resize_to(&self, width: u32, height: u32)
```
Resize the overlay window (PostMessage to the window thread).

### `new` (line 550)
```rust
pub fn new() -> Self
```

### `show_region` (line 556)
```rust
pub fn show_region(&mut self, id: &str, image_data: &[u8],
```

### `move_overlay` (line 567)
```rust
pub fn move_overlay(&self, id: &str, x: i32, y: i32)
```

### `resize_overlay` (line 573)
```rust
pub fn resize_overlay(&self, id: &str, w: u32, h: u32)
```

### `close_overlay` (line 579)
```rust
pub fn close_overlay(&mut self, id: &str)
```

### `close_all` (line 586)
```rust
pub fn close_all(&mut self)
```

### `set_opacity` (line 596)
```rust
pub fn set_opacity(&self, id: &str, percent: u32)
```

### `new` (line 608)
```rust
pub fn new() -> Self { ScreenOverlay }
```

### `show` (line 609)
```rust
pub fn show(&mut self, _data: &[u8], _opacity: u32) {}
```

### `show_at` (line 610)
```rust
pub fn show_at(&mut self, _data: &[u8], _opacity: u32, _x: i32, _y: i32, _w: u32, _h: u32) {}
```

### `close` (line 611)
```rust
pub fn close(&mut self) {}
```

### `set_opacity` (line 612)
```rust
pub fn set_opacity(&self, _percent: u32) {}
```

### `move_to` (line 613)
```rust
pub fn move_to(&self, _x: i32, _y: i32) {}
```

### `resize_to` (line 614)
```rust
pub fn resize_to(&self, _w: u32, _h: u32) {}
```

### `new` (line 619)
```rust
pub fn new() -> Self { OverlayManager }
```

### `show_region` (line 620)
```rust
pub fn show_region(&mut self, _id: &str, _data: &[u8], _x: i32, _y: i32, _w: u32, _h: u32, _opacity: u32) {}
```

### `move_overlay` (line 621)
```rust
pub fn move_overlay(&self, _id: &str, _x: i32, _y: i32) {}
```

### `resize_overlay` (line 622)
```rust
pub fn resize_overlay(&self, _id: &str, _w: u32, _h: u32) {}
```

### `close_overlay` (line 623)
```rust
pub fn close_overlay(&mut self, _id: &str) {}
```

### `close_all` (line 624)
```rust
pub fn close_all(&mut self) {}
```

### `set_opacity` (line 625)
```rust
pub fn set_opacity(&self, _id: &str, _percent: u32) {}
```

## Internal Functions

- `wnd_proc` (unsafe) (line 56)
- `blit_frame` (unsafe) — Blit a BGRA frame. dest_w/dest_h = window dimensions to fill. (line 156)
- `paint_black` (unsafe) (line 179)
- `decode_image` — Decode image bytes (JPEG/PNG/BMP/GIF) to BGRA bottom-up frames at screen size. (line 205)
- `to_bgra_bottomup` (line 243)
- `run_overlay_thread` (line 384)

## Key Dependencies

- `use tracing::{info, warn, error};`
- `use super::*;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::Graphics::Gdi::*;`
- `use windows::Win32::System::LibraryLoader::GetModuleHandleW;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use windows::core::PCWSTR;`
- `use image::AnimationDecoder;`
- `use image::GenericImageView;`

## Full Source

```rust
// Win32 layered window overlay.
// Supports fullscreen and positioned/sized overlays.
// Multiple independent overlays managed by OverlayManager.
// WDA_EXCLUDEFROMCAPTURE controlled by OVERLAY_EXCLUDE_CAPTURE env var.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{info, warn, error};

#[cfg(windows)]
mod win {
    use super::*;
    use std::thread;
    use windows::Win32::Foundation::*;
    use windows::Win32::Graphics::Gdi::*;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::PCWSTR;

    // Custom window messages (WM_USER is already defined in windows crate — use raw values)
    const WM_UPDATE_IMAGE:   u32 = 0x0401;
    const WM_SET_OPACITY:    u32 = 0x0402;
    const WM_MOVE_OVERLAY:   u32 = 0x0403;  // wparam=x, lparam=y (signed i32 packed)
    const WM_RESIZE_OVERLAY: u32 = 0x0404;  // wparam=w, lparam=h

    const GIF_TIMER_ID: usize = 1;
    const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

    // Global state shared between the overlay API and the window thread
    struct OverlayState {
        hwnd: Option<HWND>,
        frames: Vec<Vec<u8>>,         // BGRA raw bytes (bottom-up, render-sized)
        frame_delays: Vec<u32>,       // ms per frame
        frame_idx: usize,
        img_width: u32,               // render width (window width)
        img_height: u32,              // render height (window height)
        screen_w: u32,
        screen_h: u32,
        // Window geometry (0 → fullscreen for w/h, 0 for x/y)
        win_x: i32,
        win_y: i32,
        win_w: u32,                   // 0 → screen_w
        win_h: u32,                   // 0 → screen_h
    }

    unsafe impl Send for OverlayState {}

    // Use a thread-local for the Arc because HWND is not Send
    thread_local! {
        static TL_STATE: std::cell::RefCell<Option<Arc<Mutex<OverlayState>>>> =
            std::cell::RefCell::new(None);
    }

    static CLASS_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // Retrieve the OverlayState pointer stored as window user data
        let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Arc<Mutex<OverlayState>>;

        match msg {
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                if !hdc.is_invalid() {
                    if !state_ptr.is_null() {
                        let state = &*state_ptr;
                        if let Ok(s) = state.lock() {
                            if let Some(frame) = s.frames.get(s.frame_idx) {
                                blit_frame(hdc, frame, s.img_width, s.img_height, s.img_width, s.img_height);
                            } else {
                                paint_black(hdc, s.img_width.max(1), s.img_height.max(1));
                            }
                        }
                    }
                    EndPaint(hwnd, &ps);
                }
                LRESULT(0)
            }
            WM_ERASEBKGND => LRESULT(1),
            WM_TIMER => {
                if wparam.0 == GIF_TIMER_ID {
                    if !state_ptr.is_null() {
                        let state = &*state_ptr;
                        if let Ok(mut s) = state.lock() {
                            if !s.frames.is_empty() {
                                s.frame_idx = (s.frame_idx + 1) % s.frames.len();
                                let delay = s.frame_delays.get(s.frame_idx).copied().unwrap_or(100);
                                let delay = delay.max(10);
                                let _ = KillTimer(hwnd, GIF_TIMER_ID);
                                SetTimer(hwnd, GIF_TIMER_ID, delay, None);
                                InvalidateRect(hwnd, None, FALSE);
                            }
                        }
                    }
                }
                LRESULT(0)
            }
            WM_UPDATE_IMAGE => {
                InvalidateRect(hwnd, None, TRUE);
                LRESULT(0)
            }
            _ if msg == WM_SET_OPACITY => {
                let alpha = (wparam.0.min(100) * 255 / 100) as u8;
                SetLayeredWindowAttributes(hwnd, COLORREF(0), alpha, LWA_ALPHA).ok();
                LRESULT(0)
            }
            _ if msg == WM_MOVE_OVERLAY => {
                // wparam = x (i32), lparam = y (i32)
                let new_x = wparam.0 as i32;
                let new_y = lparam.0 as i32;
                SetWindowPos(
                    hwnd, HWND_TOPMOST,
                    new_x, new_y, 0, 0,
                    SWP_NOSIZE | SWP_NOACTIVATE,
                ).ok();
                LRESULT(0)
            }
            _ if msg == WM_RESIZE_OVERLAY => {
                // wparam = width, lparam = height
                let new_w = (wparam.0 as u32).max(1) as i32;
                let new_h = (lparam.0 as u32).max(1) as i32;
                if !state_ptr.is_null() {
                    let state = &*state_ptr;
                    if let Ok(mut s) = state.lock() {
                        s.img_width  = new_w as u32;
                        s.img_height = new_h as u32;
                    }
                }
                SetWindowPos(
                    hwnd, HWND_TOPMOST,
                    0, 0, new_w, new_h,
                    SWP_NOMOVE | SWP_NOACTIVATE,
                ).ok();
                InvalidateRect(hwnd, None, TRUE);
                LRESULT(0)
            }
            WM_CLOSE => {
                let _ = KillTimer(hwnd, GIF_TIMER_ID);
                DestroyWindow(hwnd).ok();
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    /// Blit a BGRA frame. dest_w/dest_h = window dimensions to fill.
    unsafe fn blit_frame(hdc: HDC, frame: &[u8], img_w: u32, img_h: u32, dest_w: u32, dest_h: u32) {
        let bmi_header = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: img_w as i32,
            biHeight: img_h as i32, // positive = bottom-up (already flipped)
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        };
        let bmi = BITMAPINFO { bmiHeader: bmi_header, ..Default::default() };

        StretchDIBits(
            hdc,
            0, 0, dest_w as i32, dest_h as i32,
            0, 0, img_w as i32, img_h as i32,
            Some(frame.as_ptr() as *const _),
            &bmi,
            DIB_RGB_COLORS,
            SRCCOPY,
        );
    }

    unsafe fn paint_black(hdc: HDC, screen_w: u32, screen_h: u32) {
        let black_pixel = [0u8, 0u8, 0u8, 0xffu8];
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: 1,
                biHeight: 1,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        StretchDIBits(
            hdc,
            0, 0, screen_w as i32, screen_h as i32,
            0, 0, 1, 1,
            Some(black_pixel.as_ptr() as *const _),
            &bmi,
            DIB_RGB_COLORS,
            SRCCOPY,
        );
    }

    /// Decode image bytes (JPEG/PNG/BMP/GIF) to BGRA bottom-up frames at screen size.
    fn decode_image(image_data: &[u8], screen_w: u32, screen_h: u32) -> (Vec<Vec<u8>>, Vec<u32>) {
        let mut frames = Vec::new();
        let mut delays = Vec::new();

        // Try animated GIF first
        let is_gif = image_data.starts_with(b"GIF");
        if is_gif {
            use image::AnimationDecoder;
            if let Ok(decoder) = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(image_data)) {
                if let Ok(gif_frames) = decoder.into_frames().collect_frames() {
                    for f in &gif_frames {
                        let (num, den) = f.delay().numer_denom_ms();
                        let delay_ms: u32 = if den > 0 { num / den } else { 100 };
                        let delay_ms = delay_ms.max(10);
                        let img = image::DynamicImage::ImageRgba8(f.clone().into_buffer());
                        let bgra = to_bgra_bottomup(&img, screen_w, screen_h);
                        frames.push(bgra);
                        delays.push(delay_ms);
                    }
                    if !frames.is_empty() {
                        return (frames, delays);
                    }
                }
            }
        }

        // Single frame decode
        if let Ok(img) = image::load_from_memory(image_data) {
            let bgra = to_bgra_bottomup(&img, screen_w, screen_h);
            frames.push(bgra);
            delays.push(100);
        } else {
            error!("overlay: failed to decode image ({} bytes)", image_data.len());
        }

        (frames, delays)
    }

    fn to_bgra_bottomup(img: &image::DynamicImage, screen_w: u32, screen_h: u32) -> Vec<u8> {
        use image::GenericImageView;
        let resized = img.resize_exact(screen_w, screen_h, image::imageops::FilterType::Lanczos3);
        let rgba = resized.to_rgba8();
        let stride = screen_w as usize * 4;
        let height = screen_h as usize;
        let mut bgra = vec![0u8; stride * height];
        // Convert RGBA → BGRA and flip vertically (bottom-up for GDI)
        for row in 0..height {
            let src_row = &rgba.as_raw()[row * stride..(row + 1) * stride];
            let dst_row_idx = height - 1 - row;
            let dst_start = dst_row_idx * stride;
            let dst_row = &mut bgra[dst_start..dst_start + stride];
            for i in 0..screen_w as usize {
                dst_row[i * 4] = src_row[i * 4 + 2]; // B
                dst_row[i * 4 + 1] = src_row[i * 4 + 1]; // G
                dst_row[i * 4 + 2] = src_row[i * 4]; // R
                dst_row[i * 4 + 3] = src_row[i * 4 + 3]; // A
            }
        }
        bgra
    }

    pub struct ScreenOverlay {
        state: Arc<Mutex<OverlayState>>,
        thread_handle: Option<thread::JoinHandle<()>>,
        ready_rx: Option<std::sync::mpsc::Receiver<bool>>,
        close_tx: Option<std::sync::mpsc::Sender<()>>,
    }

    impl ScreenOverlay {
        pub fn new() -> Self {
            ScreenOverlay {
                state: Arc::new(Mutex::new(OverlayState {
                    hwnd: None,
                    frames: Vec::new(),
                    frame_delays: Vec::new(),
                    frame_idx: 0,
                    img_width: 0,
                    img_height: 0,
                    screen_w: 0,
                    screen_h: 0,
                    win_x: 0,
                    win_y: 0,
                    win_w: 0,
                    win_h: 0,
                })),
                thread_handle: None,
                ready_rx: None,
                close_tx: None,
            }
        }

        pub fn show(&mut self, image_data: &[u8], opacity: u32) {
            self.show_at(image_data, opacity, 0, 0, 0, 0);
        }

        /// Show overlay at a specific position and size.
        /// win_w / win_h == 0 → fullscreen.
        pub fn show_at(&mut self, image_data: &[u8], opacity: u32,
                       win_x: i32, win_y: i32, win_w: u32, win_h: u32) {
            // Close existing overlay first
            self.close();

            // Store geometry in state before spawning thread
            if let Ok(mut s) = self.state.lock() {
                s.win_x = win_x;
                s.win_y = win_y;
                s.win_w = win_w;
                s.win_h = win_h;
            }

            let state = self.state.clone();
            let img_bytes = image_data.to_vec();
            let opacity = opacity.min(100);

            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
            let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();

            self.ready_rx = Some(ready_rx);
            self.close_tx = Some(close_tx);

            let handle = thread::spawn(move || {
                run_overlay_thread(state, img_bytes, opacity, ready_tx, close_rx);
            });
            self.thread_handle = Some(handle);

            // Wait for window to be created (up to 5s)
            if let Some(rx) = &self.ready_rx {
                let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
            }
        }

        pub fn close(&mut self) {
            // Signal the window thread to close
            let hwnd = self.state.lock().ok().and_then(|s| s.hwnd);
            if let Some(hwnd) = hwnd {
                unsafe {
                    PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)).ok();
                }
            }
            if let Some(handle) = self.thread_handle.take() {
                let _ = handle.join();
            }
            if let Ok(mut s) = self.state.lock() {
                s.hwnd = None;
                s.frames.clear();
                s.frame_delays.clear();
            }
        }

        pub fn set_opacity(&self, percent: u32) {
            let hwnd = self.state.lock().ok().and_then(|s| s.hwnd);
            if let Some(hwnd) = hwnd {
                unsafe {
                    PostMessageW(hwnd, WM_SET_OPACITY, WPARAM(percent as usize), LPARAM(0)).ok();
                }
            }
        }

        /// Reposition the overlay window (PostMessage to the window thread).
        pub fn move_to(&self, x: i32, y: i32) {
            let hwnd = self.state.lock().ok().and_then(|s| s.hwnd);
            if let Some(hwnd) = hwnd {
                unsafe {
                    PostMessageW(hwnd, WM_MOVE_OVERLAY, WPARAM(x as usize), LPARAM(y as isize)).ok();
                }
            }
        }

        /// Resize the overlay window (PostMessage to the window thread).
        pub fn resize_to(&self, width: u32, height: u32) {
            let hwnd = self.state.lock().ok().and_then(|s| s.hwnd);
            if let Some(hwnd) = hwnd {
                unsafe {
                    PostMessageW(hwnd, WM_RESIZE_OVERLAY, WPARAM(width as usize), LPARAM(height as isize)).ok();
                }
            }
        }
    }

    fn run_overlay_thread(
        state: Arc<Mutex<OverlayState>>,
        image_data: Vec<u8>,
        opacity: u32,
        ready_tx: std::sync::mpsc::Sender<bool>,
        close_rx: std::sync::mpsc::Receiver<()>,
    ) {
        unsafe {
            let screen_w = GetSystemMetrics(SM_CXSCREEN) as u32;
            let screen_h = GetSystemMetrics(SM_CYSCREEN) as u32;

            if screen_w == 0 || screen_h == 0 {
                let _ = ready_tx.send(false);
                return;
            }

            // Read geometry from state (set by show_at before thread spawn)
            let (win_x, win_y, win_w_raw, win_h_raw) = {
                if let Ok(s) = state.lock() {
                    (s.win_x, s.win_y, s.win_w, s.win_h)
                } else {
                    (0, 0, 0u32, 0u32)
                }
            };
            let render_w = if win_w_raw > 0 { win_w_raw } else { screen_w };
            let render_h = if win_h_raw > 0 { win_h_raw } else { screen_h };

            // Decode image at render dimensions
            let (frames, delays) = decode_image(&image_data, render_w, render_h);
            let frame_count = frames.len();

            // Register unique window class
            let counter = CLASS_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let class_name_str = format!("ScreenOverlay_{}\0", counter);
            let class_name_wide: Vec<u16> = class_name_str.encode_utf16().collect();

            let hmodule = GetModuleHandleW(None).unwrap_or_default();
            let hinstance: windows::Win32::Foundation::HINSTANCE = hmodule.into();

            // Store state Arc pointer as raw pointer for use in wndproc
            let state_box = Box::new(state.clone());
            let state_ptr = Box::into_raw(state_box);

            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinstance,
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
                hbrBackground: CreateSolidBrush(COLORREF(0x00000000)),
                lpszClassName: PCWSTR(class_name_wide.as_ptr()),
                ..Default::default()
            };

            if RegisterClassExW(&wc) == 0 {
                error!("RegisterClassExW failed");
                let _ = ready_tx.send(false);
                drop(Box::from_raw(state_ptr));
                return;
            }

            let ex_style = WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
            let style = WS_POPUP | WS_VISIBLE;

            let window_title_wide: Vec<u16> = "ScreenOverlay\0".encode_utf16().collect();
            let hwnd = CreateWindowExW(
                ex_style,
                PCWSTR(class_name_wide.as_ptr()),
                PCWSTR(window_title_wide.as_ptr()),
                style,
                win_x, win_y,
                render_w as i32, render_h as i32,
                None, None,
                hinstance, None,
            );

            if hwnd.0 == 0 {
                error!("CreateWindowExW failed");
                let _ = ready_tx.send(false);
                drop(Box::from_raw(state_ptr));
                return;
            }

            // Store state pointer in window user data
            #[cfg(target_pointer_width = "64")]
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);
            #[cfg(target_pointer_width = "32")]
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as i32);

            // Update state with hwnd and decoded frames
            {
                let mut s = state.lock().unwrap();
                s.hwnd = Some(hwnd);
                s.frames = frames;
                s.frame_delays = delays;
                s.frame_idx = 0;
                s.img_width = render_w;
                s.img_height = render_h;
                s.screen_w = screen_w;
                s.screen_h = screen_h;
            }

            // Set initial alpha
            let alpha = ((opacity.min(100) * 255 / 100) as u8).max(1);
            SetLayeredWindowAttributes(hwnd, COLORREF(0), alpha, LWA_ALPHA).ok();

            // WDA_EXCLUDEFROMCAPTURE if requested
            if std::env::var("OVERLAY_EXCLUDE_CAPTURE").as_deref() == Ok("1") {
                SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(WDA_EXCLUDEFROMCAPTURE)).ok();
                info!("WDA_EXCLUDEFROMCAPTURE enabled");
            }

            // Force topmost at geometry position
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                win_x, win_y, render_w as i32, render_h as i32,
                SWP_NOACTIVATE | SWP_SHOWWINDOW,
            ).ok();

            ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            UpdateWindow(hwnd);

            // Start GIF timer if multiple frames
            if frame_count > 1 {
                let delay = state.lock().ok()
                    .and_then(|s| s.frame_delays.first().copied())
                    .unwrap_or(100)
                    .max(10);
                SetTimer(hwnd, GIF_TIMER_ID, delay, None);
            }

            let _ = ready_tx.send(true);
            info!("Overlay window created: pos=({},{}) size={}x{} frames={}", win_x, win_y, render_w, render_h, frame_count);

            // Message pump
            let mut msg = MSG::default();
            loop {
                let ret = GetMessageW(&mut msg, HWND(0), 0, 0);
                if ret.0 <= 0 {
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Cleanup: recover state pointer and drop it
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Arc<Mutex<OverlayState>>;
            if !ptr.is_null() {
                drop(Box::from_raw(ptr));
            }

            if let Ok(mut s) = state.lock() {
                s.hwnd = None;
            }
        }
    }

    // =========================================================================
    // OverlayManager — manages multiple named ScreenOverlay instances
    // =========================================================================
    pub struct OverlayManager {
        overlays: HashMap<String, ScreenOverlay>,
    }

    impl OverlayManager {
        pub fn new() -> Self {
            OverlayManager {
                overlays: HashMap::new(),
            }
        }

        pub fn show_region(&mut self, id: &str, image_data: &[u8],
                           x: i32, y: i32, w: u32, h: u32, opacity: u32) {
            if let Some(existing) = self.overlays.get_mut(id) {
                existing.close();
            }
            let mut ov = ScreenOverlay::new();
            ov.show_at(image_data, opacity, x, y, w, h);
            self.overlays.insert(id.to_string(), ov);
            info!("OverlayManager.show_region: id={}, pos=({},{}), size={}x{}", id, x, y, w, h);
        }

        pub fn move_overlay(&self, id: &str, x: i32, y: i32) {
            if let Some(ov) = self.overlays.get(id) {
                ov.move_to(x, y);
            }
        }

        pub fn resize_overlay(&self, id: &str, w: u32, h: u32) {
            if let Some(ov) = self.overlays.get(id) {
                ov.resize_to(w, h);
            }
        }

        pub fn close_overlay(&mut self, id: &str) {
            if let Some(mut ov) = self.overlays.remove(id) {
                ov.close();
                info!("OverlayManager.close: id={}", id);
            }
        }

        pub fn close_all(&mut self) {
            let count = self.overlays.len();
            for (_, mut ov) in self.overlays.drain() {
                ov.close();
            }
            if count > 0 {
                info!("OverlayManager.close_all: closed {} overlay(s)", count);
            }
        }

        pub fn set_opacity(&self, id: &str, percent: u32) {
            if let Some(ov) = self.overlays.get(id) {
                ov.set_opacity(percent);
            }
        }
    }
}

#[cfg(not(windows))]
mod win {
    pub struct ScreenOverlay;
    impl ScreenOverlay {
        pub fn new() -> Self { ScreenOverlay }
        pub fn show(&mut self, _data: &[u8], _opacity: u32) {}
        pub fn show_at(&mut self, _data: &[u8], _opacity: u32, _x: i32, _y: i32, _w: u32, _h: u32) {}
        pub fn close(&mut self) {}
        pub fn set_opacity(&self, _percent: u32) {}
        pub fn move_to(&self, _x: i32, _y: i32) {}
        pub fn resize_to(&self, _w: u32, _h: u32) {}
    }

    pub struct OverlayManager;
    impl OverlayManager {
        pub fn new() -> Self { OverlayManager }
        pub fn show_region(&mut self, _id: &str, _data: &[u8], _x: i32, _y: i32, _w: u32, _h: u32, _opacity: u32) {}
        pub fn move_overlay(&self, _id: &str, _x: i32, _y: i32) {}
        pub fn resize_overlay(&self, _id: &str, _w: u32, _h: u32) {}
        pub fn close_overlay(&mut self, _id: &str) {}
        pub fn close_all(&mut self) {}
        pub fn set_opacity(&self, _id: &str, _percent: u32) {}
    }
}

pub use win::ScreenOverlay;
pub use win::OverlayManager;

```