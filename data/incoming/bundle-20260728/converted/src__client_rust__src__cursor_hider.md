# cursor_hider

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/cursor_hider.rs` |
| **Lines** | 106 |
| **Cards** | T023-client-capabilities |
| **Role** | System-wide cursor replacement with transparent cursors |
| **Unsafe blocks** | 2 |

## Public API

### `is_hidden` (line 17)
```rust
pub fn is_hidden() -> bool
```

### `hide_cursor` (line 51)
```rust
pub fn hide_cursor()
```

### `show_cursor` (line 81)
```rust
pub fn show_cursor()
```

### `hide_cursor` (line 102)
```rust
pub fn hide_cursor() {}
```

### `show_cursor` (line 103)
```rust
pub fn show_cursor() {}
```

## Key Dependencies

- `use super::HIDDEN;`
- `use windows::Win32::Foundation::HINSTANCE;`
- `use windows::Win32::UI::WindowsAndMessaging::{`

## Full Source

```rust
// Cursor hider — hides the system cursor globally on Windows.
//
// Strategy: replace every standard system cursor with a 32×32 fully
// transparent cursor (AND mask all-1, XOR mask all-0 → every pixel
// shows the background unchanged, effectively invisible).
//
// SetSystemCursor takes ownership of the cursor handle, so we create a
// fresh handle via CreateCursor for each cursor type.
//
// Restore: SystemParametersInfo(SPI_SETCURSORS) reloads cursor defaults
// from the registry, undoing our replacements instantly.

use std::sync::atomic::{AtomicBool, Ordering};

static HIDDEN: AtomicBool = AtomicBool::new(false);

pub fn is_hidden() -> bool {
    HIDDEN.load(Ordering::SeqCst)
}

#[cfg(windows)]
mod win {
    use super::HIDDEN;
    use std::sync::atomic::Ordering;
    use windows::Win32::Foundation::HINSTANCE;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateCursor, SetSystemCursor, SystemParametersInfoW,
        SYSTEM_PARAMETERS_INFO_ACTION, SPIF_SENDCHANGE, SYSTEM_CURSOR_ID,
    };

    // OCR_* cursor IDs — the complete set a user might see
    const CURSOR_IDS: &[u32] = &[
        32512, // OCR_NORMAL   arrow
        32513, // OCR_IBEAM    text caret
        32514, // OCR_WAIT     spinner/hourglass
        32515, // OCR_CROSS    crosshair
        32516, // OCR_UP       resize up
        32642, // OCR_SIZENWSE diagonal resize ↖↘
        32643, // OCR_SIZENESW diagonal resize ↗↙
        32644, // OCR_SIZEWE   horizontal resize ↔
        32645, // OCR_SIZENS   vertical resize ↕
        32646, // OCR_SIZEALL  move ✥
        32648, // OCR_NO       forbidden ⊘
        32649, // OCR_HAND     link pointer 👆
    ];

    // SPI_SETCURSORS = 0x0057 — restores all system cursors from registry
    const SPI_SETCURSORS: SYSTEM_PARAMETERS_INFO_ACTION =
        SYSTEM_PARAMETERS_INFO_ACTION(0x0057);

    pub fn hide_cursor() {
        if HIDDEN.load(Ordering::SeqCst) {
            return;
        }

        // 32×32 transparent cursor: AND=1 → shows background, XOR=0 → no change
        let and_mask = [0xFFu8; 128]; // 32*32/8
        let xor_mask = [0x00u8; 128];

        unsafe {
            for &id in CURSOR_IDS {
                match CreateCursor(
                    HINSTANCE::default(),
                    0, 0, 32, 32,
                    and_mask.as_ptr().cast(),
                    xor_mask.as_ptr().cast(),
                ) {
                    Ok(hcursor) => {
                        // SetSystemCursor consumes the handle on success
                        let _ = SetSystemCursor(hcursor, SYSTEM_CURSOR_ID(id));
                    }
                    Err(e) => tracing::warn!("CreateCursor id={} failed: {}", id, e),
                }
            }
        }

        HIDDEN.store(true, Ordering::SeqCst);
        tracing::info!("System cursor hidden");
    }

    pub fn show_cursor() {
        if !HIDDEN.load(Ordering::SeqCst) {
            return;
        }

        unsafe {
            let _ = SystemParametersInfoW(
                SPI_SETCURSORS,
                0,
                None,
                SPIF_SENDCHANGE,
            );
        }

        HIDDEN.store(false, Ordering::SeqCst);
        tracing::info!("System cursor restored");
    }
}

#[cfg(not(windows))]
mod win {
    pub fn hide_cursor() {}
    pub fn show_cursor() {}
}

pub use win::{hide_cursor, show_cursor};

```