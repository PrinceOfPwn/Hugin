# input_blocker

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/input_blocker.rs` |
| **Lines** | 165 |
| **Cards** | T023-client-capabilities |
| **Role** | WH_KEYBOARD_LL/WH_MOUSE_LL hooks |
| **Unsafe blocks** | 2 |

## Constants

- `LLKHF_INJECTED`: `u32` = `0x10`
- `LLMHF_INJECTED`: `u32` = `0x01`

## Types

### struct `HookState` (line 21)

## Public API

### `block_input` (line 74)
```rust
pub fn block_input(block: bool)
```

### `block_input` (line 162)
```rust
pub fn block_input(_block: bool) {}
```

## Internal Functions

- `keyboard_proc` (unsafe) (line 33)
- `mouse_proc` (unsafe) (line 54)

## Key Dependencies

- `use tracing::{info, warn};`
- `use super::*;`
- `use windows::Win32::Foundation::*;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use windows::Win32::UI::Input::KeyboardAndMouse::*;`

## Full Source

```rust
// WH_KEYBOARD_LL + WH_MOUSE_LL hook-based input blocking.
// Blocks physical input (LLKHF_INJECTED NOT set) while allowing
// synthetic SendInput through (LLKHF_INJECTED IS set).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

#[cfg(windows)]
mod win {
    use super::*;
    use std::thread;
    use windows::Win32::Foundation::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    // LLKHF/LLMHF injected flags
    const LLKHF_INJECTED: u32 = 0x10;
    const LLMHF_INJECTED: u32 = 0x01;

    struct HookState {
        kb_hook: HHOOK,
        mouse_hook: HHOOK,
        thread_id: u32,
    }

    unsafe impl Send for HookState {}

    static HOOK_STATE: std::sync::OnceLock<std::sync::Mutex<Option<HookState>>> =
        std::sync::OnceLock::new();
    static BLOCKING: AtomicBool = AtomicBool::new(false);

    unsafe extern "system" fn keyboard_proc(
        code: i32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if code >= 0 {
            let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
            if (kb.flags.0 & LLKHF_INJECTED) == 0 && BLOCKING.load(Ordering::SeqCst) {
                // Physical keystroke — block it
                return LRESULT(1);
            }
        }
        let state_lock = HOOK_STATE.get_or_init(|| std::sync::Mutex::new(None));
        let kb_hook = state_lock
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.kb_hook))
            .unwrap_or(HHOOK(0));
        CallNextHookEx(kb_hook, code, wparam, lparam)
    }

    unsafe extern "system" fn mouse_proc(
        code: i32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if code >= 0 {
            let ms = &*(lparam.0 as *const MSLLHOOKSTRUCT);
            if (ms.flags & LLMHF_INJECTED) == 0 && BLOCKING.load(Ordering::SeqCst) {
                return LRESULT(1);
            }
        }
        let state_lock = HOOK_STATE.get_or_init(|| std::sync::Mutex::new(None));
        let mouse_hook = state_lock
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.mouse_hook))
            .unwrap_or(HHOOK(0));
        CallNextHookEx(mouse_hook, code, wparam, lparam)
    }

    pub fn block_input(block: bool) {
        let state_lock = HOOK_STATE.get_or_init(|| std::sync::Mutex::new(None));

        if block {
            // Install hooks if not already installed
            let has_hooks = state_lock
                .lock()
                .map(|g| g.is_some())
                .unwrap_or(false);

            if !has_hooks {
                // Spawn dedicated thread for hooks + message pump
                thread::spawn(move || {
                    unsafe {
                        let hmod: windows::Win32::Foundation::HINSTANCE =
                            windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
                                .unwrap_or_default()
                                .into();

                        let kb_hook = SetWindowsHookExW(
                            WH_KEYBOARD_LL,
                            Some(keyboard_proc),
                            hmod,
                            0,
                        )
                        .unwrap_or(HHOOK(0));

                        let mouse_hook = SetWindowsHookExW(
                            WH_MOUSE_LL,
                            Some(mouse_proc),
                            hmod,
                            0,
                        )
                        .unwrap_or(HHOOK(0));

                        let thread_id = windows::Win32::System::Threading::GetCurrentThreadId();

                        {
                            if let Ok(mut g) = state_lock.lock() {
                                *g = Some(HookState { kb_hook, mouse_hook, thread_id });
                            }
                        }

                        info!("Input blocker hooks installed (thread {})", thread_id);

                        // Message pump — required for LL hooks
                        let mut msg = MSG::default();
                        loop {
                            let ret = GetMessageW(&mut msg, HWND(0), 0, 0);
                            if ret.0 <= 0 {
                                break;
                            }
                            TranslateMessage(&msg);
                            DispatchMessageW(&msg);
                        }

                        // Cleanup
                        UnhookWindowsHookEx(kb_hook).ok();
                        UnhookWindowsHookEx(mouse_hook).ok();
                        if let Ok(mut g) = state_lock.lock() {
                            *g = None;
                        }
                        info!("Input blocker hooks removed");
                    }
                });
            }
            BLOCKING.store(true, Ordering::SeqCst);
            info!("Input blocking ENABLED");
        } else {
            BLOCKING.store(false, Ordering::SeqCst);
            info!("Input blocking DISABLED");

            // Optionally tear down hooks to free resources
            let state_opt = state_lock
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.thread_id));
            if let Some(tid) = state_opt {
                unsafe {
                    PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0)).ok();
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod win {
    pub fn block_input(_block: bool) {}
}

pub use win::block_input;

```