# clipboard

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/clipboard.rs` |
| **Lines** | 116 |
| **Cards** | T023-client-capabilities |
| **Role** | Clipboard monitoring |
| **Unsafe blocks** | 3 |

## Public API

### `get_clipboard` (line 7)
```rust
pub fn get_clipboard() -> String
```
Read Unicode text from the Windows clipboard.

### `set_clipboard` (line 50)
```rust
pub fn set_clipboard(text: &str)
```
Write Unicode text to the Windows clipboard.

### `get_active_window_title` (line 90)
```rust
pub fn get_active_window_title() -> String
```
Get the title of the currently active (foreground) window.

### `md5_hash` (line 113)
```rust
pub fn md5_hash(s: &str) -> String
```
Compute the MD5 hash of a string (for clipboard change detection).

## Key Dependencies

- `use tracing::warn;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::System::DataExchange::*;`
- `use windows::Win32::System::Memory::*;`
- `use windows::Win32::System::Ole::CF_UNICODETEXT;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::System::DataExchange::*;`
- `use windows::Win32::System::Memory::*;`
- `use windows::Win32::System::Ole::CF_UNICODETEXT;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`

## Full Source

```rust
// Windows clipboard: read, write, and monitor for changes.
// Uses Win32 OpenClipboard/GetClipboardData/SetClipboardData.

use tracing::warn;

/// Read Unicode text from the Windows clipboard.
pub fn get_clipboard() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::*;
        use windows::Win32::System::DataExchange::*;
        use windows::Win32::System::Memory::*;
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        unsafe {
            if OpenClipboard(HWND(0)).is_err() {
                return String::new();
            }
            let h = match GetClipboardData(CF_UNICODETEXT.0 as u32) {
                Ok(h) => h,
                Err(_) => {
                    CloseClipboard().ok();
                    return String::new();
                }
            };
            let hglobal = HGLOBAL(h.0 as *mut std::ffi::c_void);
            let raw_ptr = GlobalLock(hglobal);
            if raw_ptr.is_null() {
                CloseClipboard().ok();
                return String::new();
            }
            // Read as null-terminated UTF-16
            let mut len = 0usize;
            let u16_ptr = raw_ptr as *const u16;
            while *u16_ptr.add(len) != 0 {
                len += 1;
            }
            let wide: Vec<u16> = std::slice::from_raw_parts(u16_ptr, len).to_vec();
            let text = String::from_utf16_lossy(&wide).to_string();
            GlobalUnlock(hglobal).ok();
            CloseClipboard().ok();
            text
        }
    }
    #[cfg(not(windows))]
    String::new()
}

/// Write Unicode text to the Windows clipboard.
pub fn set_clipboard(text: &str) {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::*;
        use windows::Win32::System::DataExchange::*;
        use windows::Win32::System::Memory::*;
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        unsafe {
            // Encode as UTF-16 with null terminator
            let mut data: Vec<u16> = text.encode_utf16().collect();
            data.push(0);
            let byte_len = data.len() * 2;

            let h = match GlobalAlloc(GMEM_MOVEABLE, byte_len) {
                Ok(h) => h,
                Err(_) => {
                    warn!("clipboard: GlobalAlloc failed");
                    return;
                }
            };
            let raw_ptr = GlobalLock(h);
            if raw_ptr.is_null() {
                warn!("clipboard: GlobalLock failed");
                return;
            }
            let ptr = raw_ptr as *mut u16;
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            GlobalUnlock(h).ok();

            if OpenClipboard(HWND(0)).is_ok() {
                EmptyClipboard().ok();
                SetClipboardData(CF_UNICODETEXT.0 as u32, HANDLE(h.0 as isize)).ok();
                CloseClipboard().ok();
            }
        }
    }
}

/// Get the title of the currently active (foreground) window.
pub fn get_active_window_title() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::*;
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0 == 0 {
                return String::new();
            }
            let len = GetWindowTextLengthW(hwnd);
            if len <= 0 {
                return String::new();
            }
            let mut buf = vec![0u16; len as usize + 1];
            GetWindowTextW(hwnd, &mut buf);
            String::from_utf16_lossy(&buf[..len as usize]).to_string()
        }
    }
    #[cfg(not(windows))]
    String::new()
}

/// Compute the MD5 hash of a string (for clipboard change detection).
pub fn md5_hash(s: &str) -> String {
    let digest = md5::compute(s.as_bytes());
    format!("{:x}", digest)
}

```