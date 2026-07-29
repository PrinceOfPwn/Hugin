# vnc_server

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/vnc_server.rs` |
| **Lines** | 962 |
| **Cards** | T019-networking |
| **Role** | VNC/RFB over WebSocket |
| **Unsafe blocks** | 3 |

## Constants

- `RFB_FRAMEBUFFER_UPDATE`: `u8` = `0`
- `RFB_SET_COLOUR_MAP`: `u8` = `1`
- `RFB_BELL`: `u8` = `2`
- `RFB_SERVER_CUT_TEXT`: `u8` = `3`
- `RFB_SET_PIXEL_FORMAT`: `u8` = `0`
- `RFB_SET_ENCODINGS`: `u8` = `2`
- `RFB_FRAMEBUFFER_UPDATE_REQUEST`: `u8` = `3`
- `RFB_KEY_EVENT`: `u8` = `4`
- `RFB_POINTER_EVENT`: `u8` = `5`
- `RFB_CLIENT_CUT_TEXT`: `u8` = `6`
- `RFB_ENCODING_RAW`: `i32` = `0`
- `RFB_ENCODING_COPYRECT`: `i32` = `1`
- `RFB_ENCODING_TIGHT`: `i32` = `7`

## Types

### struct `VncHandle` (line 54)
Handle returned to the caller. Use it to stop the VNC server
and to feed incoming RFB bytes from the WebSocket.

## Public API

### `feed_rfb_bytes` (line 65)
```rust
pub fn feed_rfb_bytes(&self, data: Vec<u8>)
```
Feed raw RFB bytes received from the server relay into the VNC server.

### `stop` (line 71)
```rust
pub fn stop(&self)
```
Stop the VNC server. The capture loop and input processing loop
will terminate on the next iteration.

### `is_stopped` (line 76)
```rust
pub fn is_stopped(&self) -> bool
```
Returns true if the VNC server has been signaled to stop.

### `start` (line 518)
```rust
pub fn start(
```
Start the VNC server. Returns a VncHandle for feeding incoming RFB
bytes and stopping the server.

`ws_tx` is used to send outgoing binary messages (MSG_VNC_DATA wrapped)
to the WebSocket writer. The caller provides this from the main session's
send channel.

`monitor_index` is the current monitor to capture.
`target_fps` controls the frame rate of VNC updates.

## Internal Functions

- `rfb_protocol_version` — Build the RFB protocol version string. (line 86)
- `rfb_security_types` — Build security types message: only None (type 1). (line 91)
- `rfb_security_result_ok` — Build SecurityResult: OK (0). (line 97)
- `rfb_server_init` — Build the ServerInit message. (line 103)
- `rfb_framebuffer_update_raw` — Build a FramebufferUpdate message containing a single full-screen (line 151)
- `write_compact_size` — Encode a compact-size length as 1–3 bytes (Tight spec §6.6). (line 188)
- `rfb_framebuffer_update_tight_jpeg` — Build a FramebufferUpdate with one rectangle using Tight JPEG sub-type. (line 205)
- `handle_pointer_event` — Parse and handle a PointerEvent (mouse) from the RFB client. (line 240)
- `send_mouse_event` (line 278)
- `keysym_to_vk` — Map an X11/RFB keysym to a Windows virtual key code. (line 333)
- `handle_key_event` — Parse and handle a KeyEvent from the RFB client. (line 416)
- `handle_client_cut_text` — Parse and handle ClientCutText (clipboard paste from viewer). (line 491)
- `send_vnc_data` — Send raw RFB bytes wrapped in MSG_VNC_DATA to the WebSocket. (line 646)
- `send_vnc_diag` — Emit a VNC diagnostic CMD_OUTPUT so the server can relay it to the operator. (line 653)

## Key Dependencies

- `use tokio::sync::mpsc;`
- `use tracing::{debug, info, warn};`
- `use crate::capture;`
- `use crate::protocol::{build_message, MSG_CMD_OUTPUT, MSG_VNC_DATA};`
- `use windows::Win32::UI::Input::KeyboardAndMouse::*;`
- `use windows::Win32::UI::Input::KeyboardAndMouse::*;`

## Full Source

```rust
// Minimal RFB (Remote FrameBuffer) server for VNC tunneling.
//
// This module implements a lightweight RFB server that:
// - Performs the RFB handshake (protocol version, security, ServerInit)
// - Sends FramebufferUpdate messages with Raw encoding
// - Receives PointerEvent, KeyEvent, and ClientCutText from the viewer
// - Translates RFB input events to the local input.rs / clipboard.rs functions
//
// The RFB server does NOT listen on a TCP port. Instead, it sends and receives
// raw RFB bytes wrapped in MSG_VNC_DATA (0x0E) over the existing WebSocket
// connection to the Python server, which relays them to/from the noVNC client.
//
// Architecture:
//   Browser (noVNC) <-WS-> Server (relay) <-WS/MSG_VNC_DATA-> Rust Client (this RFB server)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::capture;
use crate::protocol::{build_message, MSG_CMD_OUTPUT, MSG_VNC_DATA};

// ------------------------------------------------------------------ //
// RFB Protocol Constants
// ------------------------------------------------------------------ //

// RFB message types: server -> client
const RFB_FRAMEBUFFER_UPDATE: u8 = 0;
const RFB_SET_COLOUR_MAP: u8 = 1;
const RFB_BELL: u8 = 2;
const RFB_SERVER_CUT_TEXT: u8 = 3;

// RFB message types: client -> server
const RFB_SET_PIXEL_FORMAT: u8 = 0;
const RFB_SET_ENCODINGS: u8 = 2;
const RFB_FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
const RFB_KEY_EVENT: u8 = 4;
const RFB_POINTER_EVENT: u8 = 5;
const RFB_CLIENT_CUT_TEXT: u8 = 6;

// RFB encoding types
const RFB_ENCODING_RAW: i32 = 0;
#[allow(dead_code)]
const RFB_ENCODING_COPYRECT: i32 = 1;
const RFB_ENCODING_TIGHT: i32 = 7;

// ------------------------------------------------------------------ //
// VNC Server State
// ------------------------------------------------------------------ //

/// Handle returned to the caller. Use it to stop the VNC server
/// and to feed incoming RFB bytes from the WebSocket.
pub struct VncHandle {
    /// Send raw RFB bytes received from the server (originating from noVNC)
    /// into this channel so the VNC server can process them.
    pub rfb_input_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Set to true to signal the VNC server tasks to shut down.
    stop_flag: Arc<AtomicBool>,
}

impl VncHandle {
    /// Feed raw RFB bytes received from the server relay into the VNC server.
    pub fn feed_rfb_bytes(&self, data: Vec<u8>) {
        let _ = self.rfb_input_tx.send(data);
    }

    /// Stop the VNC server. The capture loop and input processing loop
    /// will terminate on the next iteration.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    /// Returns true if the VNC server has been signaled to stop.
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::SeqCst)
    }
}

// ------------------------------------------------------------------ //
// RFB Handshake helpers
// ------------------------------------------------------------------ //

/// Build the RFB protocol version string.
fn rfb_protocol_version() -> Vec<u8> {
    b"RFB 003.008\n".to_vec()
}

/// Build security types message: only None (type 1).
fn rfb_security_types() -> Vec<u8> {
    // [1 byte: number_of_security_types][type1]
    vec![1, 1] // 1 type available: type 1 = None
}

/// Build SecurityResult: OK (0).
fn rfb_security_result_ok() -> Vec<u8> {
    0u32.to_be_bytes().to_vec()
}

/// Build the ServerInit message.
/// Tells the client about framebuffer dimensions and pixel format.
fn rfb_server_init(width: u16, height: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24 + 4 + 16);

    // Framebuffer width and height (2 bytes each, big-endian)
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());

    // PIXEL_FORMAT (16 bytes):
    // bits-per-pixel: 32
    msg.push(32);
    // depth: 24
    msg.push(24);
    // big-endian-flag: 0 (little-endian)
    msg.push(0);
    // true-colour-flag: 1
    msg.push(1);
    // red-max: 255 (big-endian u16)
    msg.extend_from_slice(&255u16.to_be_bytes());
    // green-max: 255
    msg.extend_from_slice(&255u16.to_be_bytes());
    // blue-max: 255
    msg.extend_from_slice(&255u16.to_be_bytes());
    // red-shift: 16 (BGRA -> R is at byte offset 2 = bit 16)
    msg.push(16);
    // green-shift: 8
    msg.push(8);
    // blue-shift: 0
    msg.push(0);
    // padding (3 bytes)
    msg.extend_from_slice(&[0u8; 3]);

    // Desktop name (4-byte length prefix + UTF-8)
    let name = b"Screen Panel VNC";
    msg.extend_from_slice(&(name.len() as u32).to_be_bytes());
    msg.extend_from_slice(name);

    msg
}

// ------------------------------------------------------------------ //
// RFB FramebufferUpdate builder (Raw encoding)
// ------------------------------------------------------------------ //

/// Build a FramebufferUpdate message containing a single full-screen
/// rectangle with Raw encoding.
///
/// The pixel data must be in the format matching the PIXEL_FORMAT from
/// ServerInit: 32bpp, little-endian, BGRX (blue at lowest address).
fn rfb_framebuffer_update_raw(
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    pixel_data: &[u8],
) -> Vec<u8> {
    // Header: [type=0][padding=0][number_of_rectangles=1(u16 BE)]
    // Rectangle: [x(u16)][y(u16)][w(u16)][h(u16)][encoding_type(i32 BE)][pixel_data]
    let num_rects: u16 = 1;
    let header_len = 4 + 12; // 4 bytes update header + 12 bytes rect header
    let total = header_len + pixel_data.len();
    let mut msg = Vec::with_capacity(total);

    // FramebufferUpdate header
    msg.push(RFB_FRAMEBUFFER_UPDATE); // message-type
    msg.push(0); // padding
    msg.extend_from_slice(&num_rects.to_be_bytes());

    // Rectangle header
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&RFB_ENCODING_RAW.to_be_bytes());

    // Pixel data
    msg.extend_from_slice(pixel_data);

    msg
}

// ------------------------------------------------------------------ //
// RFB FramebufferUpdate builder (Tight / JPEG encoding)
// ------------------------------------------------------------------ //

/// Encode a compact-size length as 1–3 bytes (Tight spec §6.6).
fn write_compact_size(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 16384 {
        buf.push(0x80 | (len & 0x7F) as u8);
        buf.push((len >> 7) as u8);
    } else {
        buf.push(0x80 | (len & 0x7F) as u8);
        buf.push(0x80 | ((len >> 7) & 0x7F) as u8);
        buf.push((len >> 14) as u8);
    }
}

/// Build a FramebufferUpdate with one rectangle using Tight JPEG sub-type.
///
/// Control byte 0x90: bits 7–4 = 0x9 → JPEG sub-type.
/// Followed by compact-size length + raw JPEG bytes.
fn rfb_framebuffer_update_tight_jpeg(
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    jpeg_data: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 12 + 1 + 3 + jpeg_data.len());

    // FramebufferUpdate header
    msg.push(RFB_FRAMEBUFFER_UPDATE);
    msg.push(0); // padding
    msg.extend_from_slice(&1u16.to_be_bytes());

    // Rectangle header
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&RFB_ENCODING_TIGHT.to_be_bytes());

    // Tight JPEG payload: control byte + compact-size + JPEG bytes
    msg.push(0x90); // JPEG sub-type
    write_compact_size(&mut msg, jpeg_data.len());
    msg.extend_from_slice(jpeg_data);

    msg
}

// ------------------------------------------------------------------ //
// RFB Input Parsing
// ------------------------------------------------------------------ //

/// Parse and handle a PointerEvent (mouse) from the RFB client.
/// Format: [type=5][button_mask(1)][x_position(u16 BE)][y_position(u16 BE)]
fn handle_pointer_event(data: &[u8], fb_width: u16, fb_height: u16) {
    if data.len() < 5 {
        return;
    }
    let button_mask = data[0];
    let x = u16::from_be_bytes([data[1], data[2]]);
    let y = u16::from_be_bytes([data[3], data[4]]);

    // Convert pixel coords to normalized 0-65535 range
    let norm_x = if fb_width > 0 {
        (x as i32 * 65535) / (fb_width as i32).max(1)
    } else {
        0
    };
    let norm_y = if fb_height > 0 {
        (y as i32 * 65535) / (fb_height as i32).max(1)
    } else {
        0
    };

    // Move mouse to position
    crate::input::move_mouse_normalized(norm_x, norm_y);

    // Handle button presses
    // bit 0: left, bit 1: middle, bit 2: right
    // bits 3-4: scroll up/down
    static LAST_BUTTONS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    let prev = LAST_BUTTONS.swap(button_mask, Ordering::SeqCst);

    let pressed = button_mask & !prev;
    let released = !button_mask & prev;

    // Inject mouse button events using SendInput directly.
    // We need individual down/up events (not click pairs) for VNC.
    #[cfg(windows)]
    {
        use windows::Win32::UI::Input::KeyboardAndMouse::*;

        fn send_mouse_event(flags: MOUSE_EVENT_FLAGS) {
            let inp = INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: 0,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            unsafe {
                SendInput(&[inp], std::mem::size_of::<INPUT>() as i32);
            }
        }

        // Left button
        if pressed & 0x01 != 0 {
            send_mouse_event(MOUSEEVENTF_LEFTDOWN);
        }
        if released & 0x01 != 0 {
            send_mouse_event(MOUSEEVENTF_LEFTUP);
        }

        // Middle button
        if pressed & 0x02 != 0 {
            send_mouse_event(MOUSEEVENTF_MIDDLEDOWN);
        }
        if released & 0x02 != 0 {
            send_mouse_event(MOUSEEVENTF_MIDDLEUP);
        }

        // Right button
        if pressed & 0x04 != 0 {
            send_mouse_event(MOUSEEVENTF_RIGHTDOWN);
        }
        if released & 0x04 != 0 {
            send_mouse_event(MOUSEEVENTF_RIGHTUP);
        }
    }

    // Scroll: button 4 = scroll up, button 5 = scroll down
    if button_mask & 0x08 != 0 {
        crate::input::scroll_wheel(120); // scroll up
    }
    if button_mask & 0x10 != 0 {
        crate::input::scroll_wheel(-120); // scroll down
    }
}

/// Map an X11/RFB keysym to a Windows virtual key code.
/// Covers the most common keysyms used by noVNC.
fn keysym_to_vk(keysym: u32) -> Option<u16> {
    match keysym {
        // Latin-1 printable range (0x20..0x7E) maps directly to VK codes
        // for letters A-Z, digits 0-9, and some symbols.
        0x0020 => Some(0x20), // VK_SPACE
        0x0030..=0x0039 => Some(keysym as u16), // 0-9
        0x0041..=0x005A => Some(keysym as u16), // A-Z (uppercase)
        0x0061..=0x007A => Some((keysym - 0x20) as u16), // a-z -> A-Z

        // Function keys
        0xFFBE => Some(0x70), // F1
        0xFFBF => Some(0x71), // F2
        0xFFC0 => Some(0x72), // F3
        0xFFC1 => Some(0x73), // F4
        0xFFC2 => Some(0x74), // F5
        0xFFC3 => Some(0x75), // F6
        0xFFC4 => Some(0x76), // F7
        0xFFC5 => Some(0x77), // F8
        0xFFC6 => Some(0x78), // F9
        0xFFC7 => Some(0x79), // F10
        0xFFC8 => Some(0x7A), // F11
        0xFFC9 => Some(0x7B), // F12

        // Modifier keys
        0xFFE1 => Some(0xA0), // Shift_L
        0xFFE2 => Some(0xA1), // Shift_R
        0xFFE3 => Some(0xA2), // Control_L
        0xFFE4 => Some(0xA3), // Control_R
        0xFFE9 => Some(0xA4), // Alt_L
        0xFFEA => Some(0xA5), // Alt_R
        0xFFEB => Some(0x5B), // Super_L (Win)
        0xFFEC => Some(0x5C), // Super_R (Win)

        // Navigation
        0xFF08 => Some(0x08), // BackSpace
        0xFF09 => Some(0x09), // Tab
        0xFF0D => Some(0x0D), // Return
        0xFF1B => Some(0x1B), // Escape
        0xFFFF => Some(0x2E), // Delete
        0xFF63 => Some(0x2D), // Insert
        0xFF50 => Some(0x24), // Home
        0xFF57 => Some(0x23), // End
        0xFF55 => Some(0x21), // Page_Up
        0xFF56 => Some(0x22), // Page_Down

        // Arrow keys
        0xFF51 => Some(0x25), // Left
        0xFF52 => Some(0x26), // Up
        0xFF53 => Some(0x27), // Right
        0xFF54 => Some(0x28), // Down

        // Misc
        0xFF14 => Some(0x91), // Scroll_Lock
        0xFF7F => Some(0x90), // Num_Lock
        0xFFE5 => Some(0x14), // Caps_Lock
        0xFF13 => Some(0x13), // Pause
        0xFF61 => Some(0x2C), // Print_Screen

        // Numpad
        0xFFB0 => Some(0x60), // KP_0
        0xFFB1 => Some(0x61), // KP_1
        0xFFB2 => Some(0x62), // KP_2
        0xFFB3 => Some(0x63), // KP_3
        0xFFB4 => Some(0x64), // KP_4
        0xFFB5 => Some(0x65), // KP_5
        0xFFB6 => Some(0x66), // KP_6
        0xFFB7 => Some(0x67), // KP_7
        0xFFB8 => Some(0x68), // KP_8
        0xFFB9 => Some(0x69), // KP_9
        0xFFAA => Some(0x6A), // KP_Multiply
        0xFFAB => Some(0x6B), // KP_Add
        0xFFAD => Some(0x6D), // KP_Subtract
        0xFFAE => Some(0x6E), // KP_Decimal
        0xFFAF => Some(0x6F), // KP_Divide
        0xFF8D => Some(0x0D), // KP_Enter

        // Common symbols using VkKeyScan on Windows
        _ => None,
    }
}

/// Parse and handle a KeyEvent from the RFB client.
/// Format: [type=4][down_flag(1)][padding(2)][key(u32 BE)]
fn handle_key_event(data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    let down = data[0] != 0;
    // data[1..3] = padding
    let keysym = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);

    #[cfg(windows)]
    {
        use windows::Win32::UI::Input::KeyboardAndMouse::*;

        if let Some(vk_code) = keysym_to_vk(keysym) {
            let vk = VIRTUAL_KEY(vk_code);
            let flags = if down {
                KEYBD_EVENT_FLAGS(0)
            } else {
                KEYEVENTF_KEYUP
            };
            let inp = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: vk,
                        wScan: 0,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            unsafe {
                SendInput(&[inp], std::mem::size_of::<INPUT>() as i32);
            }
        } else if down && keysym >= 0x20 && keysym <= 0xFFFF {
            // For unmapped keysyms in the Unicode BMP, use KEYEVENTF_UNICODE
            let scan = keysym as u16;
            let inp_down = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: scan,
                        dwFlags: KEYEVENTF_UNICODE,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let inp_up = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: scan,
                        dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            unsafe {
                SendInput(&[inp_down, inp_up], std::mem::size_of::<INPUT>() as i32);
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (down, keysym);
    }
}

/// Parse and handle ClientCutText (clipboard paste from viewer).
/// Format: [type=6][padding(3)][length(u32 BE)][text(utf-8)]
fn handle_client_cut_text(data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    // data[0..3] = padding
    let length = u32::from_be_bytes([data[3], data[4], data[5], data[6]]) as usize;
    if data.len() < 7 + length {
        return;
    }
    let text = String::from_utf8_lossy(&data[7..7 + length]).to_string();
    crate::clipboard::set_clipboard(&text);
    debug!("VNC ClientCutText: {} chars", text.len());
}

// ------------------------------------------------------------------ //
// VNC Server: start / capture loop / input loop
// ------------------------------------------------------------------ //

/// Start the VNC server. Returns a VncHandle for feeding incoming RFB
/// bytes and stopping the server.
///
/// `ws_tx` is used to send outgoing binary messages (MSG_VNC_DATA wrapped)
/// to the WebSocket writer. The caller provides this from the main session's
/// send channel.
///
/// `monitor_index` is the current monitor to capture.
/// `target_fps` controls the frame rate of VNC updates.
pub fn start(
    ws_tx: mpsc::UnboundedSender<Vec<u8>>,
    monitor_index: u32,
    target_fps: u32,
    jpeg_quality: u8,
) -> VncHandle {
    let (rfb_input_tx, rfb_input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let stop_flag = Arc::new(AtomicBool::new(false));

    let handle = VncHandle {
        rfb_input_tx,
        stop_flag: stop_flag.clone(),
    };

    let stop = stop_flag.clone();
    tokio::spawn(async move {
        vnc_server_task(ws_tx, rfb_input_rx, stop, monitor_index, target_fps, jpeg_quality).await;
    });

    handle
}

/// Main VNC server task. Performs the RFB handshake, then runs
/// capture + input processing loops concurrently.
async fn vnc_server_task(
    ws_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut rfb_input_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    monitor_index: u32,
    target_fps: u32,
    jpeg_quality: u8,
) {
    info!("VNC server starting (monitor={}, fps={})", monitor_index, target_fps);

    // Get screen dimensions for this monitor
    let (_, _, fb_width, fb_height) = crate::sysinfo_collect::get_monitor_rect(monitor_index);
    let fb_w = fb_width as u16;
    let fb_h = fb_height as u16;

    // --- RFB Handshake (server side) ---
    //
    // All steps share `hs_buf` so that bytes arriving in the same TCP
    // segment as a handshake byte are not silently dropped.  After the
    // handshake, `hs_buf` may already contain the first post-handshake
    // messages (e.g. SetEncodings); we hand it directly to the input loop.

    let mut hs_buf: Vec<u8> = Vec::new();

    // Step 1: Send ProtocolVersion
    send_vnc_data(&ws_tx, &rfb_protocol_version());

    // Step 2: Wait for client's ProtocolVersion response (12 bytes)
    let client_proto = match wait_rfb_message(&mut hs_buf, &mut rfb_input_rx, &stop, 12).await {
        Some(data) => data,
        None => {
            warn!("VNC handshake: no client protocol version received");
            return;
        }
    };
    debug!("VNC handshake: client version = {:?}", String::from_utf8_lossy(&client_proto));

    // Step 3: Send security types (None)
    send_vnc_data(&ws_tx, &rfb_security_types());

    // Step 4: Wait for client's security type selection (1 byte)
    match wait_rfb_message(&mut hs_buf, &mut rfb_input_rx, &stop, 1).await {
        Some(_) => {}
        None => { warn!("VNC handshake: no security type response"); return; }
    }

    // Step 5: Send SecurityResult OK
    send_vnc_data(&ws_tx, &rfb_security_result_ok());

    // Step 6: Wait for ClientInit (1 byte: shared-flag)
    match wait_rfb_message(&mut hs_buf, &mut rfb_input_rx, &stop, 1).await {
        Some(_) => {}
        None => { warn!("VNC handshake: no ClientInit received"); return; }
    }

    // Step 7: Send ServerInit
    send_vnc_data(&ws_tx, &rfb_server_init(fb_w, fb_h));
    info!("VNC handshake complete: {}x{}", fb_w, fb_h);

    // --- Post-handshake: run capture and input processing concurrently ---

    // Fix #2: default Tight=true — noVNC always advertises Tight in
    // SetEncodings, so this is safe.  If Fix #1 ever loses SetEncodings
    // we still get compressed frames instead of 8 MB Raw blobs.
    let tight_supported = Arc::new(AtomicBool::new(true));

    // Fix #3: keyframe_requested — set by input loop on incremental=0,
    // causes capture loop to send a frame immediately without waiting.
    let keyframe_requested = Arc::new(AtomicBool::new(true)); // true = send first frame ASAP

    let ws_tx_capture = ws_tx.clone();
    let stop_capture = stop.clone();
    let tight_cap = tight_supported.clone();
    let kf_cap = keyframe_requested.clone();

    // Capture loop: send framebuffer updates at the configured FPS
    let capture_handle = tokio::spawn(async move {
        vnc_capture_loop(ws_tx_capture, stop_capture, monitor_index, fb_w, fb_h, target_fps, jpeg_quality, tight_cap, kf_cap).await;
    });

    // Input loop: starts with any bytes already buffered from the handshake
    // (Fix #1 — prevents SetEncodings / FramebufferUpdateRequest from being dropped).
    let stop_input = stop.clone();
    let tight_inp = tight_supported.clone();
    let kf_inp = keyframe_requested.clone();
    let input_handle = tokio::spawn(async move {
        vnc_input_loop(hs_buf, rfb_input_rx, stop_input, fb_w, fb_h, tight_inp, kf_inp).await;
    });

    // Wait for either to finish
    tokio::select! {
        _ = capture_handle => {
            debug!("VNC capture loop ended");
        }
        _ = input_handle => {
            debug!("VNC input loop ended");
        }
    }

    stop.store(true, Ordering::SeqCst);
    info!("VNC server stopped");
}

/// Send raw RFB bytes wrapped in MSG_VNC_DATA to the WebSocket.
fn send_vnc_data(ws_tx: &mpsc::UnboundedSender<Vec<u8>>, rfb_bytes: &[u8]) {
    let msg = build_message(MSG_VNC_DATA, rfb_bytes);
    let _ = ws_tx.send(msg);
}

/// Emit a VNC diagnostic CMD_OUTPUT so the server can relay it to the operator.
/// The server intercepts requestId="vnc_diag" and broadcasts it as a WS event.
fn send_vnc_diag(
    ws_tx: &mpsc::UnboundedSender<Vec<u8>>,
    encoding: &str,
    fps: f64,
    frame_count: u64,
    bytes_last_frame: usize,
    error: Option<&str>,
) {
    let payload = serde_json::json!({
        "requestId": "vnc_diag",
        "exitCode": 0,
        "stdout": serde_json::json!({
            "encoding": encoding,
            "fps": (fps * 10.0).round() / 10.0,
            "frames": frame_count,
            "bytes_last_frame": bytes_last_frame,
            "error": error,
        }).to_string(),
        "stderr": "",
    });
    if let Ok(json_str) = serde_json::to_vec(&payload) {
        let msg = build_message(MSG_CMD_OUTPUT, &json_str);
        let _ = ws_tx.send(msg);
    }
}

/// Wait until `buf` contains at least `min_bytes`, pulling from `rx` as
/// needed.  Drains exactly `min_bytes` from the front of `buf` and returns
/// them.  Any extra bytes that arrived in the same receive call stay in
/// `buf` so the next caller (or the input loop) can consume them without
/// data loss.
///
/// Returns None only if the stop flag fires, the channel closes, or the
/// 10-second receive timeout elapses.
async fn wait_rfb_message(
    buf: &mut Vec<u8>,
    rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    stop: &AtomicBool,
    min_bytes: usize,
) -> Option<Vec<u8>> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        if buf.len() >= min_bytes {
            let consumed: Vec<u8> = buf.drain(..min_bytes).collect();
            return Some(consumed);
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv()).await {
            Ok(Some(data)) => buf.extend_from_slice(&data),
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

/// Capture loop: captures screen frames and sends RFB FramebufferUpdate
/// messages at the configured FPS.
async fn vnc_capture_loop(
    ws_tx: mpsc::UnboundedSender<Vec<u8>>,
    stop: Arc<AtomicBool>,
    monitor_index: u32,
    fb_width: u16,
    fb_height: u16,
    target_fps: u32,
    jpeg_quality: u8,
    tight_supported: Arc<AtomicBool>,
    keyframe_requested: Arc<AtomicBool>,
) {
    let interval = std::time::Duration::from_secs_f64(1.0 / target_fps.max(1) as f64);
    let mut capturer = capture::ScreenCapturer::new(monitor_index);
    let mut frame_count: u64 = 0;
    #[allow(unused_assignments)]
    let mut last_frame_bytes: usize = 0;
    let started = std::time::Instant::now();

    info!(
        "VNC capture loop started: {}x{} @ {} FPS",
        fb_width, fb_height, target_fps
    );
    // Emit initial diag so the UI shows "starting" immediately
    send_vnc_diag(&ws_tx, "starting", 0.0, 0, 0, None);

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let frame_start = std::time::Instant::now();
        let use_tight = tight_supported.load(Ordering::Relaxed);

        if use_tight {
            // Tight JPEG path: capture directly as JPEG (much lower bandwidth)
            let jpeg_result = tokio::task::block_in_place(|| {
                capture::capture_jpeg(monitor_index, jpeg_quality)
            });
            match jpeg_result {
                Ok(jpeg_data) if !jpeg_data.is_empty() => {
                    // Fix #3: clear keyframe flag — we just sent one
                    keyframe_requested.store(false, Ordering::Relaxed);
                    last_frame_bytes = jpeg_data.len();
                    let update = rfb_framebuffer_update_tight_jpeg(
                        0, 0, fb_width, fb_height, &jpeg_data,
                    );
                    send_vnc_data(&ws_tx, &update);
                    frame_count += 1;
                    let elapsed = started.elapsed().as_secs_f64();
                    let fps = frame_count as f64 / elapsed.max(0.001);
                    if frame_count % 30 == 0 {
                        send_vnc_diag(&ws_tx, "tight", fps, frame_count, last_frame_bytes, None);
                        debug!("VNC Tight JPEG: {} frames, {:.1} fps, {} KB/frame", frame_count, fps, jpeg_data.len() / 1024);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    debug!("VNC Tight capture error: {}", e);
                    send_vnc_diag(&ws_tx, "tight", 0.0, frame_count, 0, Some(&e.to_string()));
                }
            }
        } else {
            // Raw path: send uncompressed BGRX pixels
            let capture_timeout_ms = (interval.as_secs_f64() * 1000.0).clamp(5.0, 50.0) as u32;
            let frame_result = tokio::task::block_in_place(|| {
                capturer.capture_frame_with_timeout(capture_timeout_ms)
            });
            match frame_result {
                Ok(Some(raw_frame)) => {
                    let actual_w = raw_frame.width as u16;
                    let actual_h = raw_frame.height as u16;
                    // Fix #5: skip frames whose dimensions don't match ServerInit to
                    // avoid noVNC drawing outside its canvas (can happen on HiDPI).
                    if actual_w != fb_width || actual_h != fb_height {
                        debug!(
                            "VNC Raw: frame {}x{} != ServerInit {}x{}, skipping",
                            actual_w, actual_h, fb_width, fb_height
                        );
                    } else {
                        let pixel_data = if raw_frame.is_bgra {
                            raw_frame.data
                        } else {
                            let mut bgra = raw_frame.data.clone();
                            for chunk in bgra.chunks_exact_mut(4) {
                                chunk.swap(0, 2);
                            }
                            bgra
                        };
                        // Fix #3: clear keyframe flag
                        keyframe_requested.store(false, Ordering::Relaxed);
                        last_frame_bytes = pixel_data.len();
                        let update = rfb_framebuffer_update_raw(0, 0, fb_width, fb_height, &pixel_data);
                        send_vnc_data(&ws_tx, &update);
                        frame_count += 1;
                        let elapsed = started.elapsed().as_secs_f64();
                        let fps = frame_count as f64 / elapsed.max(0.001);
                        if frame_count % 30 == 0 {
                            send_vnc_diag(&ws_tx, "raw", fps, frame_count, last_frame_bytes, None);
                            debug!("VNC Raw: {} frames, {:.1} fps, {:.1} MB/frame", frame_count, fps, pixel_data.len() as f64 / (1024.0 * 1024.0));
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => debug!("VNC Raw capture error: {}", e),
            }
        }

        let elapsed = frame_start.elapsed();
        // Fix #3: if a keyframe was requested (incremental=0 from noVNC),
        // skip the inter-frame sleep to respond immediately.
        if !keyframe_requested.load(Ordering::Relaxed) && elapsed < interval {
            tokio::time::sleep(interval - elapsed).await;
        }
    }
}

/// Input processing loop: reads RFB client messages and dispatches them
/// to the appropriate input handlers.
///
/// `initial_buf` contains any bytes already received during the handshake
/// that belong to the first post-handshake messages (Fix #1).
async fn vnc_input_loop(
    initial_buf: Vec<u8>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    fb_width: u16,
    fb_height: u16,
    tight_supported: Arc<AtomicBool>,
    keyframe_requested: Arc<AtomicBool>,
) {
    let mut buffer = initial_buf;

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Wait for more data only when the buffer is exhausted
        if buffer.is_empty() {
            match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(Some(data)) => buffer.extend_from_slice(&data),
                Ok(None) => break, // channel closed
                Err(_) => continue, // timeout, check stop flag and loop
            }
        }

        // Process all complete messages in the buffer
        loop {
            if buffer.is_empty() {
                break;
            }

            let msg_type = buffer[0];
            let consumed = match msg_type {
                RFB_SET_PIXEL_FORMAT => {
                    // 20 bytes total: [type(1)][padding(3)][pixel_format(16)]
                    if buffer.len() < 20 {
                        break;
                    }
                    debug!("VNC: SetPixelFormat received (ignored, using server format)");
                    20
                }
                RFB_SET_ENCODINGS => {
                    // [type(1)][padding(1)][number_of_encodings(u16 BE)]
                    // then [encoding_type(i32 BE)] * n
                    if buffer.len() < 4 {
                        break;
                    }
                    let n = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
                    let total = 4 + n * 4;
                    if buffer.len() < total {
                        break;
                    }
                    // Check if Tight encoding (7) is in the list
                    let mut has_tight = false;
                    for i in 0..n {
                        let offset = 4 + i * 4;
                        let enc = i32::from_be_bytes([
                            buffer[offset],
                            buffer[offset + 1],
                            buffer[offset + 2],
                            buffer[offset + 3],
                        ]);
                        if enc == RFB_ENCODING_TIGHT {
                            has_tight = true;
                            break;
                        }
                    }
                    tight_supported.store(has_tight, Ordering::Relaxed);
                    debug!("VNC: SetEncodings ({} types), tight={}", n, has_tight);
                    total
                }
                RFB_FRAMEBUFFER_UPDATE_REQUEST => {
                    // 10 bytes: [type(1)][incremental(1)][x(u16)][y(u16)][w(u16)][h(u16)]
                    if buffer.len() < 10 {
                        break;
                    }
                    // Fix #3: incremental=0 means "send me a full frame NOW".
                    // Signal the capture loop to skip the inter-frame sleep.
                    if buffer[1] == 0 {
                        keyframe_requested.store(true, Ordering::Relaxed);
                        debug!("VNC: non-incremental FramebufferUpdateRequest — triggering keyframe");
                    }
                    10
                }
                RFB_KEY_EVENT => {
                    // 8 bytes: [type(1)][down_flag(1)][padding(2)][key(u32 BE)]
                    if buffer.len() < 8 {
                        break;
                    }
                    tokio::task::block_in_place(|| {
                        handle_key_event(&buffer[1..8]);
                    });
                    8
                }
                RFB_POINTER_EVENT => {
                    // 6 bytes: [type(1)][button_mask(1)][x(u16 BE)][y(u16 BE)]
                    if buffer.len() < 6 {
                        break;
                    }
                    tokio::task::block_in_place(|| {
                        handle_pointer_event(&buffer[1..6], fb_width, fb_height);
                    });
                    6
                }
                RFB_CLIENT_CUT_TEXT => {
                    // [type(1)][padding(3)][length(u32 BE)][text...]
                    if buffer.len() < 8 {
                        break;
                    }
                    let text_len =
                        u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;
                    let total = 8 + text_len;
                    if buffer.len() < total {
                        break;
                    }
                    tokio::task::block_in_place(|| {
                        handle_client_cut_text(&buffer[1..total]);
                    });
                    total
                }
                _ => {
                    warn!("VNC: unknown client message type 0x{:02X}, clearing buffer", msg_type);
                    buffer.clear();
                    break;
                }
            };

            buffer.drain(..consumed);
        }
    }
}

```