# input

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/input.rs` |
| **Lines** | 748 |
| **Cards** | T023-client-capabilities |
| **Role** | Input injection |
| **Unsafe blocks** | 11 |

## Public API

### `vk_from_name` (line 12)
```rust
pub fn vk_from_name(name: &str) -> Option<VIRTUAL_KEY>
```

### `try_post_message_mouse_move` (line 141)
```rust
pub fn try_post_message_mouse_move(screen_x: i32, screen_y: i32) -> bool
```
Try to move the cursor via PostMessage(WM_MOUSEMOVE) to the foreground window.
Returns true if the message was posted successfully.

### `try_post_message_click` (line 161)
```rust
pub fn try_post_message_click(screen_x: i32, screen_y: i32, button: &str) -> bool
```
Try to perform a mouse click via PostMessage to the foreground window.
`button` is "left", "right", or "middle".
Returns true if both down+up messages were posted successfully.

### `move_mouse_normalized` (line 187)
```rust
pub fn move_mouse_normalized(norm_x: i32, norm_y: i32)
```
Move mouse to normalized coordinates (0-65535) using MOUSEEVENTF_ABSOLUTE | VIRTUALDESKTOP.
Fallback chain: SendInput -> SetCursorPos -> PostMessage(WM_MOUSEMOVE).

### `move_mouse_normalized_on_monitor` (line 230)
```rust
pub fn move_mouse_normalized_on_monitor(
```
Move mouse on a specific monitor, converting monitor-local normalized coords
to virtual-desktop-normalized coords.
Fallback chain: SendInput -> SetCursorPos -> PostMessage(WM_MOUSEMOVE).

### `set_natural_mouse` (line 303)
```rust
pub fn set_natural_mouse(enabled: bool)
```
Enable or disable natural mouse movement at runtime.

### `cancel_mouse_move` (line 395)
```rust
pub fn cancel_mouse_move() -> u32
```
Signal cancellation and return a fresh token for the next motion.

### `left_click` (line 567)
```rust
pub fn left_click()
```

### `right_click` (line 578)
```rust
pub fn right_click()
```

### `middle_click` (line 589)
```rust
pub fn middle_click()
```

### `scroll_wheel` (line 601)
```rust
pub fn scroll_wheel(delta: i32)
```

### `type_text` (line 607)
```rust
pub fn type_text(text: &str)
```
Type a string character by character using KEYEVENTF_UNICODE.

### `press_key` (line 617)
```rust
pub fn press_key(key_name: &str)
```
Press a single key or hotkey combo (e.g., "CTRL+C", "F5", "A").

### `move_mouse_normalized` (line 701)
```rust
pub fn move_mouse_normalized(_x: i32, _y: i32) {}
```

### `move_mouse_normalized_on_monitor` (line 702)
```rust
pub fn move_mouse_normalized_on_monitor(
```

### `try_post_message_mouse_move` (line 711)
```rust
pub fn try_post_message_mouse_move(_screen_x: i32, _screen_y: i32) -> bool
```

### `try_post_message_click` (line 714)
```rust
pub fn try_post_message_click(
```

### `cancel_mouse_move` (line 721)
```rust
pub fn cancel_mouse_move() -> u32
```

### `set_natural_mouse` (line 724)
```rust
pub fn set_natural_mouse(_enabled: bool) {}
```

### `left_click` (line 740)
```rust
pub fn left_click() {}
```

### `right_click` (line 741)
```rust
pub fn right_click() {}
```

### `middle_click` (line 742)
```rust
pub fn middle_click() {}
```

### `scroll_wheel` (line 743)
```rust
pub fn scroll_wheel(_delta: i32) {}
```

### `type_text` (line 744)
```rust
pub fn type_text(_text: &str) {}
```

### `press_key` (line 745)
```rust
pub fn press_key(_key: &str) {}
```

## Internal Functions

- `send_inputs` — Send an array of INPUT events via SendInput. (line 76)
- `mouse_input` (line 82)
- `key_input` (line 98)
- `make_lparam` — Pack (x, y) into an LPARAM for PostMessage mouse messages. (line 121)
- `norm_to_pixel_with_bounds` — Convert normalized 0-65535 coords to virtual-desktop pixel coordinates (line 127)
- `issue_move_token` (line 288)
- `token_matches` (line 292)
- `is_natural_enabled` — Returns whether natural (Bézier) mouse movement is currently enabled. (line 298)
- `get_cursor_pos` — Get current cursor position in screen pixels. (line 309)
- `norm_to_pixel` — Convert normalized 0-65535 coords to virtual-desktop pixel coordinates. (line 318)
- `pixel_to_norm` — Convert virtual-desktop pixel coordinates to normalized 0-65535 for SendInput. (line 331)
- `ease_in_out_cubic` — Ease-in-out cubic: slow at start and end, fast in the middle. (line 344)
- `bezier_cubic` — Evaluate a cubic Bézier curve at parameter t. (line 353)
- `rand_f64` — Simple LCG-based pseudo-random float in [0, 1) using a thread-local seed. (line 370)
- `rand_range` — rand in [lo, hi] (line 390)
- `do_click` — Execute a mouse button click by name. (line 559)
- `press_hotkey` (line 648)

## Key Dependencies

- `use windows::Win32::UI::Input::KeyboardAndMouse::*;`
- `use windows::Win32::UI::WindowsAndMessaging::*;`
- `use windows::Win32::Foundation::*;`

## Full Source

```rust
// Win32 SendInput-based mouse and keyboard injection.
// Mirrors the functionality of client_py/input_win.py.

#[cfg(windows)]
pub mod win {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::Win32::Foundation::*;

    // Virtual key map: name → VK code
    pub fn vk_from_name(name: &str) -> Option<VIRTUAL_KEY> {
        let key = name.trim().to_uppercase();
        let vk = match key.as_str() {
            "ENTER" | "RETURN" => VK_RETURN,
            "ESCAPE" | "ESC" => VK_ESCAPE,
            "TAB" => VK_TAB,
            "BACKSPACE" | "BACK" => VK_BACK,
            "DELETE" | "DEL" => VK_DELETE,
            "INSERT" | "INS" => VK_INSERT,
            "SPACE" => VK_SPACE,
            "HOME" => VK_HOME,
            "END" => VK_END,
            "PAGEUP" | "PGUP" | "PAGE_UP" => VK_PRIOR,
            "PAGEDOWN" | "PGDN" | "PAGE_DOWN" => VK_NEXT,
            "UP" => VK_UP,
            "DOWN" => VK_DOWN,
            "LEFT" => VK_LEFT,
            "RIGHT" => VK_RIGHT,
            "F1" => VK_F1, "F2" => VK_F2, "F3" => VK_F3, "F4" => VK_F4,
            "F5" => VK_F5, "F6" => VK_F6, "F7" => VK_F7, "F8" => VK_F8,
            "F9" => VK_F9, "F10" => VK_F10, "F11" => VK_F11, "F12" => VK_F12,
            "CTRL" | "CONTROL" | "LCTRL" => VK_CONTROL,
            "RCTRL" => VK_RCONTROL,
            "SHIFT" | "LSHIFT" => VK_SHIFT,
            "RSHIFT" => VK_RSHIFT,
            "ALT" | "LALT" | "MENU" => VK_MENU,
            "RALT" => VK_RMENU,
            "LWIN" | "WIN" | "WINDOWS" => VK_LWIN,
            "RWIN" => VK_RWIN,
            "APPS" => VK_APPS,
            "CAPSLOCK" | "CAPS_LOCK" | "CAPS" => VK_CAPITAL,
            "NUMLOCK" | "NUM_LOCK" => VK_NUMLOCK,
            "SCROLLLOCK" | "SCROLL_LOCK" => VK_SCROLL,
            "PRINTSCREEN" | "PRTSC" | "PRINT_SCREEN" => VK_SNAPSHOT,
            "PAUSE" | "BREAK" => VK_PAUSE,
            "SLEEP" => VK_SLEEP,
            "NUMPAD0" => VK_NUMPAD0, "NUMPAD1" => VK_NUMPAD1,
            "NUMPAD2" => VK_NUMPAD2, "NUMPAD3" => VK_NUMPAD3,
            "NUMPAD4" => VK_NUMPAD4, "NUMPAD5" => VK_NUMPAD5,
            "NUMPAD6" => VK_NUMPAD6, "NUMPAD7" => VK_NUMPAD7,
            "NUMPAD8" => VK_NUMPAD8, "NUMPAD9" => VK_NUMPAD9,
            "MULTIPLY" => VK_MULTIPLY,
            "ADD" => VK_ADD,
            "SUBTRACT" => VK_SUBTRACT,
            "DECIMAL" => VK_DECIMAL,
            "DIVIDE" => VK_DIVIDE,
            "MEDIA_PLAY_PAUSE" => VK_MEDIA_PLAY_PAUSE,
            "MEDIA_STOP" => VK_MEDIA_STOP,
            "MEDIA_NEXT" => VK_MEDIA_NEXT_TRACK,
            "MEDIA_PREV" => VK_MEDIA_PREV_TRACK,
            "VOLUME_MUTE" => VK_VOLUME_MUTE,
            "VOLUME_UP" => VK_VOLUME_UP,
            "VOLUME_DOWN" => VK_VOLUME_DOWN,
            "BROWSER_BACK" => VK_BROWSER_BACK,
            "BROWSER_FORWARD" => VK_BROWSER_FORWARD,
            "BROWSER_REFRESH" => VK_BROWSER_REFRESH,
            "BROWSER_HOME" => VK_BROWSER_HOME,
            _ => return None,
        };
        Some(vk)
    }

    /// Send an array of INPUT events via SendInput.
    /// Returns the number of events successfully injected (0 means failure).
    fn send_inputs(inputs: &[INPUT]) -> u32 {
        unsafe {
            SendInput(inputs, std::mem::size_of::<INPUT>() as i32)
        }
    }

    fn mouse_input(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: u32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn key_input(vk: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS, scan: u16) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    // ---------------------------------------------------------------------------
    // VM / headless fallback helpers
    // ---------------------------------------------------------------------------

    /// Counter for diagnostic logging of fallback paths (log first 3 only).
    static FALLBACK_LOG_COUNT: AtomicU32 = AtomicU32::new(0);

    /// Pack (x, y) into an LPARAM for PostMessage mouse messages.
    fn make_lparam(x: i32, y: i32) -> LPARAM {
        LPARAM(((y & 0xFFFF) << 16 | (x & 0xFFFF)) as isize)
    }

    /// Convert normalized 0-65535 coords to virtual-desktop pixel coordinates
    /// (same as `norm_to_pixel` but returns the virtual screen bounds too).
    fn norm_to_pixel_with_bounds(norm_x: i32, norm_y: i32) -> (i32, i32, i32, i32, i32, i32) {
        unsafe {
            let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);
            let px = vx + (norm_x as f64 / 65535.0 * (vw - 1) as f64).round() as i32;
            let py = vy + (norm_y as f64 / 65535.0 * (vh - 1) as f64).round() as i32;
            (px, py, vx, vy, vw, vh)
        }
    }

    /// Try to move the cursor via PostMessage(WM_MOUSEMOVE) to the foreground window.
    /// Returns true if the message was posted successfully.
    pub fn try_post_message_mouse_move(screen_x: i32, screen_y: i32) -> bool {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0 == 0 {
                return false;
            }
            let mut rect = RECT::default();
            if GetWindowRect(hwnd, &mut rect).is_err() {
                return false;
            }
            let client_x = screen_x - rect.left;
            let client_y = screen_y - rect.top;
            PostMessageW(hwnd, WM_MOUSEMOVE, WPARAM(0), make_lparam(client_x, client_y))
                .is_ok()
        }
    }

    /// Try to perform a mouse click via PostMessage to the foreground window.
    /// `button` is "left", "right", or "middle".
    /// Returns true if both down+up messages were posted successfully.
    pub fn try_post_message_click(screen_x: i32, screen_y: i32, button: &str) -> bool {
        let (down_msg, up_msg) = match button.to_lowercase().as_str() {
            "right" => (WM_RBUTTONDOWN, WM_RBUTTONUP),
            // middle not commonly supported via PostMessage, use left as default
            _ => (WM_LBUTTONDOWN, WM_LBUTTONUP),
        };
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0 == 0 {
                return false;
            }
            let mut rect = RECT::default();
            if GetWindowRect(hwnd, &mut rect).is_err() {
                return false;
            }
            let client_x = screen_x - rect.left;
            let client_y = screen_y - rect.top;
            let lp = make_lparam(client_x, client_y);
            let ok_down = PostMessageW(hwnd, down_msg, WPARAM(0), lp).is_ok();
            let ok_up = PostMessageW(hwnd, up_msg, WPARAM(0), lp).is_ok();
            ok_down && ok_up
        }
    }

    /// Move mouse to normalized coordinates (0-65535) using MOUSEEVENTF_ABSOLUTE | VIRTUALDESKTOP.
    /// Fallback chain: SendInput -> SetCursorPos -> PostMessage(WM_MOUSEMOVE).
    pub fn move_mouse_normalized(norm_x: i32, norm_y: i32) {
        let inp = mouse_input(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            norm_x,
            norm_y,
            0,
        );
        let result = send_inputs(&[inp]);
        if result > 0 {
            return;
        }

        // Fallback 1: SetCursorPos (works in some headless/VM environments where
        // SendInput's MOUSEEVENTF_ABSOLUTE fails).
        let (px, py, vx, vy, vw, vh) = norm_to_pixel_with_bounds(norm_x, norm_y);
        unsafe {
            if SetCursorPos(px, py).is_ok() {
                let count = FALLBACK_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                if count < 3 {
                    eprintln!(
                        "[input] SendInput failed, SetCursorPos fallback OK ({},{}) vdesk=({},{},{},{})",
                        px, py, vx, vy, vw, vh
                    );
                }
                return;
            }
        }

        // Fallback 2: PostMessage(WM_MOUSEMOVE) to the foreground window.
        if try_post_message_mouse_move(px, py) {
            let count = FALLBACK_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
            if count < 3 {
                eprintln!(
                    "[input] SendInput+SetCursorPos failed, PostMessage fallback OK ({},{})",
                    px, py
                );
            }
        }
    }

    /// Move mouse on a specific monitor, converting monitor-local normalized coords
    /// to virtual-desktop-normalized coords.
    /// Fallback chain: SendInput -> SetCursorPos -> PostMessage(WM_MOUSEMOVE).
    pub fn move_mouse_normalized_on_monitor(
        norm_x: i32,
        norm_y: i32,
        mon_left: i32,
        mon_top: i32,
        mon_w: u32,
        mon_h: u32,
    ) {
        let px = mon_left
            + (norm_x as f64 / 65535.0 * (mon_w as f64 - 1.0).max(0.0)).round() as i32;
        let py = mon_top
            + (norm_y as f64 / 65535.0 * (mon_h as f64 - 1.0).max(0.0)).round() as i32;

        unsafe {
            let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);

            let dx = (((px - vx) as f64 / (vw - 1) as f64) * 65535.0)
                .round()
                .clamp(0.0, 65535.0) as i32;
            let dy = (((py - vy) as f64 / (vh - 1) as f64) * 65535.0)
                .round()
                .clamp(0.0, 65535.0) as i32;

            let inp = mouse_input(
                MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                dx,
                dy,
                0,
            );
            let result = send_inputs(&[inp]);
            if result > 0 {
                return;
            }

            // Fallback 1: SetCursorPos with computed pixel coords
            if SetCursorPos(px, py).is_ok() {
                return;
            }

            // Fallback 2: PostMessage to foreground window
            try_post_message_mouse_move(px, py);
        }
    }

    // ---------------------------------------------------------------------------
    // Natural mouse movement (Bézier curve + ease-in-out cubic + micro-jitter)
    // ---------------------------------------------------------------------------

    /// Incrementing token: newer moves use a higher token and older tasks exit.
    static MOVE_TOKEN: AtomicU32 = AtomicU32::new(0);

    /// Runtime-toggleable flag for natural (Bézier) mouse movement.
    /// Default: ON. Toggled via MOUSE_NATURAL_ON / MOUSE_NATURAL_OFF commands.
    static NATURAL_MOUSE_ENABLED: AtomicBool = AtomicBool::new(true);

    fn issue_move_token() -> u32 {
        MOVE_TOKEN.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
    }

    fn token_matches(token: u32) -> bool {
        MOVE_TOKEN.load(Ordering::Relaxed) == token
    }

    /// Returns whether natural (Bézier) mouse movement is currently enabled.
    /// Toggled in runtime via `set_natural_mouse()`.
    fn is_natural_enabled() -> bool {
        NATURAL_MOUSE_ENABLED.load(Ordering::Relaxed)
    }

    /// Enable or disable natural mouse movement at runtime.
    pub fn set_natural_mouse(enabled: bool) {
        NATURAL_MOUSE_ENABLED.store(enabled, Ordering::Relaxed);
        tracing::info!("Natural mouse: {}", if enabled { "ON" } else { "OFF" });
    }

    /// Get current cursor position in screen pixels.
    fn get_cursor_pos() -> (i32, i32) {
        unsafe {
            let mut pt = POINT::default();
            let _ = GetCursorPos(&mut pt);
            (pt.x, pt.y)
        }
    }

    /// Convert normalized 0-65535 coords to virtual-desktop pixel coordinates.
    fn norm_to_pixel(norm_x: i32, norm_y: i32) -> (i32, i32) {
        unsafe {
            let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);
            let px = vx + (norm_x as f64 / 65535.0 * (vw - 1) as f64) as i32;
            let py = vy + (norm_y as f64 / 65535.0 * (vh - 1) as f64) as i32;
            (px, py)
        }
    }

    /// Convert virtual-desktop pixel coordinates to normalized 0-65535 for SendInput.
    fn pixel_to_norm(px: i32, py: i32) -> (i32, i32) {
        unsafe {
            let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
            let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);
            let nx = ((px - vx) as f64 / (vw - 1) as f64 * 65535.0) as i32;
            let ny = ((py - vy) as f64 / (vh - 1) as f64 * 65535.0) as i32;
            (nx, ny)
        }
    }

    /// Ease-in-out cubic: slow at start and end, fast in the middle.
    fn ease_in_out_cubic(t: f64) -> f64 {
        if t < 0.5 {
            4.0 * t * t * t
        } else {
            1.0 - (-2.0 * t + 2.0_f64).powi(3) / 2.0
        }
    }

    /// Evaluate a cubic Bézier curve at parameter t.
    fn bezier_cubic(
        t: f64,
        p0: (f64, f64), p1: (f64, f64), p2: (f64, f64), p3: (f64, f64),
    ) -> (f64, f64) {
        let mt = 1.0 - t;
        let x = mt.powi(3) * p0.0
              + 3.0 * mt.powi(2) * t * p1.0
              + 3.0 * mt * t.powi(2) * p2.0
              + t.powi(3) * p3.0;
        let y = mt.powi(3) * p0.1
              + 3.0 * mt.powi(2) * t * p1.1
              + 3.0 * mt * t.powi(2) * p2.1
              + t.powi(3) * p3.1;
        (x, y)
    }

    /// Simple LCG-based pseudo-random float in [0, 1) using a thread-local seed.
    fn rand_f64() -> f64 {
        use std::cell::Cell;
        use std::time::{SystemTime, UNIX_EPOCH};
        thread_local! {
            static SEED: Cell<u64> = Cell::new({
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 17))
                    .unwrap_or(12345)
            });
        }
        SEED.with(|s| {
            // LCG constants from Numerical Recipes
            let next = s.get().wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            s.set(next);
            (next >> 11) as f64 / (1u64 << 53) as f64
        })
    }

    /// rand in [lo, hi]
    fn rand_range(lo: f64, hi: f64) -> f64 {
        lo + rand_f64() * (hi - lo)
    }

    /// Signal cancellation and return a fresh token for the next motion.
    pub fn cancel_mouse_move() -> u32 {
        issue_move_token()
    }

    /// Move the mouse from current position to (target_px, target_py) using
    /// a cubic Bézier curve with ease-in-out pacing and micro-jitter.
    ///
    /// This is an async function and must be awaited inside a Tokio runtime.
    /// Uses `tokio::time::sleep` so it does not block the async executor.
    pub async fn move_mouse_natural_pixels(token: u32, target_px: i32, target_py: i32) {
        if !token_matches(token) {
            return;
        }

        let (start_px, start_py) = get_cursor_pos();
        let dx = (target_px - start_px) as f64;
        let dy = (target_py - start_py) as f64;
        let dist = (dx * dx + dy * dy).sqrt();

        // Skip interpolation for very short distances
        if dist < 20.0 {
            let (nx, ny) = pixel_to_norm(target_px, target_py);
            move_mouse_normalized(nx, ny);
            return;
        }

        // Steps: distance/10, clamped to [10, 50]
        let steps = (dist / 10.0).round() as usize;
        let steps = steps.clamp(10, 50);

        // Control point perpendicular offset: 10-30% of distance, random sign
        let perp_scale = rand_range(0.10, 0.30) * dist;
        let (perp_x, perp_y) = if dist > 0.0 {
            (-dy / dist, dx / dist)
        } else {
            (0.0, 0.0)
        };
        let sign1: f64 = if rand_f64() < 0.5 { 1.0 } else { -1.0 };
        let sign2: f64 = if rand_f64() < 0.5 { 1.0 } else { -1.0 };
        let off1 = perp_scale * sign1;
        let off2 = perp_scale * sign2 * rand_range(0.5, 1.0);

        let p0 = (start_px as f64, start_py as f64);
        let p1 = (start_px as f64 + dx / 3.0 + perp_x * off1,
                  start_py as f64 + dy / 3.0 + perp_y * off1);
        let p2 = (start_px as f64 + 2.0 * dx / 3.0 + perp_x * off2,
                  start_py as f64 + 2.0 * dy / 3.0 + perp_y * off2);
        let p3 = (target_px as f64, target_py as f64);

        // Total time: ~50 ms short, ~200 ms cross-screen
        let total_ms = (dist * 0.15).clamp(50.0, 200.0);
        let step_ms = total_ms / steps as f64;

        for i in 0..steps {
            if !token_matches(token) {
                return;
            }

            let t_raw = (i + 1) as f64 / steps as f64;
            let t = ease_in_out_cubic(t_raw);

            let (bx, by) = bezier_cubic(t, p0, p1, p2, p3);

            // Micro-jitter: ±2 px always, ±4 px occasionally (5% chance)
            let (jx, jy) = if i < steps - 1 {
                let mut jx = rand_range(-2.0, 2.0);
                let mut jy = rand_range(-2.0, 2.0);
                if rand_f64() < 0.05 {
                    jx += rand_range(-4.0, 4.0);
                    jy += rand_range(-4.0, 4.0);
                }
                (jx, jy)
            } else {
                // Final step: land exactly on target
                (0.0, 0.0)
            };

            let px = (bx + jx) as i32;
            let py = (by + jy) as i32;
            if !token_matches(token) {
                return;
            }
            let (nx, ny) = pixel_to_norm(px, py);
            move_mouse_normalized(nx, ny);

            // Variable per-step delay: step_ms ± 1 ms
            let delay_ms = (step_ms + rand_range(-1.0, 1.0)).max(1.0);
            tokio::time::sleep(std::time::Duration::from_micros((delay_ms * 1000.0) as u64)).await;
        }

        // Guarantee exact final position
        if !token_matches(token) {
            return;
        }
        let (nx, ny) = pixel_to_norm(target_px, target_py);
        move_mouse_normalized(nx, ny);
    }

    /// Move to normalized coords with natural human-like movement.
    /// Falls back to instant teleport if MOUSE_NATURAL=0 or distance < 20 px.
    pub async fn move_mouse_natural(token: u32, norm_x: i32, norm_y: i32) {
        if !is_natural_enabled() {
            if !token_matches(token) {
                return;
            }
            move_mouse_normalized(norm_x, norm_y);
            return;
        }
        let (target_px, target_py) = norm_to_pixel(norm_x, norm_y);
        move_mouse_natural_pixels(token, target_px, target_py).await;
    }

    /// Move to target with natural movement, optional overshoot, then click.
    /// Overshoot: 30% chance — moves 5-15 px past target, pauses, corrects.
    pub async fn move_mouse_natural_and_click(token: u32, norm_x: i32, norm_y: i32, button: &str) {
        if !is_natural_enabled() {
            if !token_matches(token) {
                return;
            }
            move_mouse_normalized(norm_x, norm_y);
            do_click(button);
            return;
        }

        let (target_px, target_py) = norm_to_pixel(norm_x, norm_y);

        // 30% chance of overshoot
        if rand_f64() < 0.30 {
            let (cx, cy) = get_cursor_pos();
            let ddx = (target_px - cx) as f64;
            let ddy = (target_py - cy) as f64;
            let dist = (ddx * ddx + ddy * ddy).sqrt();
            if dist > 0.0 {
                let over = rand_range(5.0, 15.0);
                let over_px = (target_px as f64 + ddx / dist * over) as i32;
                let over_py = (target_py as f64 + ddy / dist * over) as i32;
                move_mouse_natural_pixels(token, over_px, over_py).await;
                let pause_ms = rand_range(30.0, 80.0);
                tokio::time::sleep(std::time::Duration::from_millis(pause_ms as u64)).await;
                move_mouse_natural_pixels(token, target_px, target_py).await;
            } else {
                move_mouse_natural_pixels(token, target_px, target_py).await;
            }
        } else {
            move_mouse_natural_pixels(token, target_px, target_py).await;
        }

        // Small pre-click pause (5-20 ms)
        let pre_click_ms = rand_range(5.0, 20.0);
        tokio::time::sleep(std::time::Duration::from_millis(pre_click_ms as u64)).await;

        if token_matches(token) {
            do_click(button);
        }
    }

    pub async fn move_mouse_natural_and_scroll(token: u32, norm_x: i32, norm_y: i32, delta: i32) {
        move_mouse_natural(token, norm_x, norm_y).await;
        if token_matches(token) {
            scroll_wheel(delta);
        }
    }

    /// Execute a mouse button click by name.
    fn do_click(button: &str) {
        match button.to_lowercase().as_str() {
            "right" => right_click(),
            "middle" => middle_click(),
            _ => left_click(),
        }
    }

    pub fn left_click() {
        let result = send_inputs(&[
            mouse_input(MOUSEEVENTF_LEFTDOWN, 0, 0, 0),
            mouse_input(MOUSEEVENTF_LEFTUP, 0, 0, 0),
        ]);
        if result == 0 {
            let (cx, cy) = get_cursor_pos();
            try_post_message_click(cx, cy, "left");
        }
    }

    pub fn right_click() {
        let result = send_inputs(&[
            mouse_input(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0),
            mouse_input(MOUSEEVENTF_RIGHTUP, 0, 0, 0),
        ]);
        if result == 0 {
            let (cx, cy) = get_cursor_pos();
            try_post_message_click(cx, cy, "right");
        }
    }

    pub fn middle_click() {
        let result = send_inputs(&[
            mouse_input(MOUSEEVENTF_MIDDLEDOWN, 0, 0, 0),
            mouse_input(MOUSEEVENTF_MIDDLEUP, 0, 0, 0),
        ]);
        if result == 0 {
            // PostMessage middle-click is unreliable; best-effort with left as fallback
            let (cx, cy) = get_cursor_pos();
            try_post_message_click(cx, cy, "left");
        }
    }

    pub fn scroll_wheel(delta: i32) {
        let inp = mouse_input(MOUSEEVENTF_WHEEL, 0, 0, delta as u32);
        send_inputs(&[inp]);
    }

    /// Type a string character by character using KEYEVENTF_UNICODE.
    pub fn type_text(text: &str) {
        for ch in text.chars() {
            let code = ch as u16;
            let down = key_input(VIRTUAL_KEY(0), KEYEVENTF_UNICODE, code);
            let up = key_input(VIRTUAL_KEY(0), KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, code);
            send_inputs(&[down, up]);
        }
    }

    /// Press a single key or hotkey combo (e.g., "CTRL+C", "F5", "A").
    pub fn press_key(key_name: &str) {
        let key = key_name.trim().to_uppercase();
        if key.contains('+') {
            press_hotkey(&key);
            return;
        }

        if let Some(vk) = vk_from_name(&key) {
            let down = key_input(vk, KEYBD_EVENT_FLAGS(0), 0);
            let up = key_input(vk, KEYEVENTF_KEYUP, 0);
            send_inputs(&[down, up]);
            return;
        }

        // Single character — use VkKeyScanW
        if key_name.trim().chars().count() == 1 {
            let ch = key_name.trim().chars().next().unwrap();
            unsafe {
                let raw = VkKeyScanW(ch as u16);
                let low = (raw & 0xFF) as u8;
                if low != 0xFF {
                    let vk = VIRTUAL_KEY(low as u16);
                    send_inputs(&[
                        key_input(vk, KEYBD_EVENT_FLAGS(0), 0),
                        key_input(vk, KEYEVENTF_KEYUP, 0),
                    ]);
                }
            }
        }
    }

    fn press_hotkey(hotkey: &str) {
        let parts: Vec<&str> = hotkey.split('+').collect();
        let mut mods: Vec<VIRTUAL_KEY> = Vec::new();
        let mut main_vk: Option<VIRTUAL_KEY> = None;

        for p in &parts {
            let p = p.trim();
            match p.to_uppercase().as_str() {
                "CTRL" | "CONTROL" | "LCTRL" => mods.push(VK_CONTROL),
                "SHIFT" | "LSHIFT" => mods.push(VK_SHIFT),
                "ALT" | "LALT" => mods.push(VK_MENU),
                "WIN" | "WINDOWS" | "LWIN" => mods.push(VK_LWIN),
                _ => {
                    if let Some(vk) = vk_from_name(p) {
                        main_vk = Some(vk);
                    } else if p.chars().count() == 1 {
                        let ch = p.chars().next().unwrap();
                        unsafe {
                            let raw = VkKeyScanW(ch as u16);
                            let low = (raw & 0xFF) as u8;
                            let high = ((raw >> 8) & 0xFF) as u8;
                            if low != 0xFF {
                                main_vk = Some(VIRTUAL_KEY(low as u16));
                                if high & 1 != 0 { mods.push(VK_SHIFT); }
                                if high & 2 != 0 { mods.push(VK_CONTROL); }
                                if high & 4 != 0 { mods.push(VK_MENU); }
                            }
                        }
                    }
                }
            }
        }

        if let Some(vk) = main_vk {
            // Press modifiers
            let mut inputs: Vec<INPUT> = Vec::new();
            for &m in &mods {
                inputs.push(key_input(m, KEYBD_EVENT_FLAGS(0), 0));
            }
            // Press main key
            inputs.push(key_input(vk, KEYBD_EVENT_FLAGS(0), 0));
            inputs.push(key_input(vk, KEYEVENTF_KEYUP, 0));
            // Release modifiers in reverse
            for &m in mods.iter().rev() {
                inputs.push(key_input(m, KEYEVENTF_KEYUP, 0));
            }
            send_inputs(&inputs);
        }
    }
}

#[cfg(not(windows))]
pub mod win {
    pub fn move_mouse_normalized(_x: i32, _y: i32) {}
    pub fn move_mouse_normalized_on_monitor(
        _nx: i32,
        _ny: i32,
        _ml: i32,
        _mt: i32,
        _mw: u32,
        _mh: u32,
    ) {
    }
    pub fn try_post_message_mouse_move(_screen_x: i32, _screen_y: i32) -> bool {
        false
    }
    pub fn try_post_message_click(
        _screen_x: i32,
        _screen_y: i32,
        _button: &str,
    ) -> bool {
        false
    }
    pub fn cancel_mouse_move() -> u32 {
        0
    }
    pub fn set_natural_mouse(_enabled: bool) {}
    pub async fn move_mouse_natural(_token: u32, _norm_x: i32, _norm_y: i32) {}
    pub async fn move_mouse_natural_and_click(
        _token: u32,
        _norm_x: i32,
        _norm_y: i32,
        _button: &str,
    ) {
    }
    pub async fn move_mouse_natural_and_scroll(
        _token: u32,
        _norm_x: i32,
        _norm_y: i32,
        _delta: i32,
    ) {
    }
    pub fn left_click() {}
    pub fn right_click() {}
    pub fn middle_click() {}
    pub fn scroll_wheel(_delta: i32) {}
    pub fn type_text(_text: &str) {}
    pub fn press_key(_key: &str) {}
}

pub use win::*;

```