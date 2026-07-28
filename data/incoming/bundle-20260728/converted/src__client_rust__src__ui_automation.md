# ui_automation

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/ui_automation.rs` |
| **Lines** | 311 |
| **Cards** | T023-client-capabilities |
| **Role** | UI element enumeration |
| **Unsafe blocks** | 8 |

## Constants

- `MAX_ELEMENTS`: `usize` = `500`

## Types

### struct `UiElement` (line 10)

### struct `UiElementResult` (line 20)

### struct `TopLevelState` (line 192)

### struct `ChildState` (line 211)

## Public API

### `read_elements` (line 230)
```rust
pub fn read_elements(window_pattern: &str, control_types: &[String]) -> UiElementResult
```

### `read_elements` (line 295)
```rust
pub fn read_elements(_window_pattern: &str, _control_types: &[String]) -> UiElementResult
```

### `read_elements` (line 309)
```rust
pub fn read_elements(window_pattern: &str, control_types: &[String]) -> UiElementResult
```

## Internal Functions

- `get_window_text` (line 46)
- `get_class_name` (line 61)
- `get_control_text` — For Edit/ComboBox/RichEdit: use WM_GETTEXT to get the live text value. (line 74)
- `count_children` (line 104)
- `count_cb` (unsafe) (line 106)
- `compute_level` (line 125)
- `collect_element` (line 141)
- `enum_windows_cb` (unsafe) (line 197)
- `enum_child_cb` (unsafe) (line 217)

## Key Dependencies

- `use super::*;`
- `use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE, FALSE};`
- `use windows::Win32::UI::WindowsAndMessaging::{`
- `use super::*;`

## Full Source

```rust
/// UI element reading via Win32 EnumWindows + EnumChildWindows (MSAA-style).
///
/// Enumerates all top-level windows whose title matches `window_pattern`
/// (case-insensitive substring), then collects their child controls, returning
/// class name, text, handle, and hierarchy information.
///
/// Max 500 elements are returned to avoid flooding the channel.

#[derive(serde::Serialize)]
pub struct UiElement {
    pub hwnd: String,
    pub class_name: String,
    pub text: String,
    pub parent_hwnd: String,
    pub level: u32,
    pub child_count: usize,
}

#[derive(serde::Serialize)]
pub struct UiElementResult {
    pub window_pattern: String,
    pub windows_found: usize,
    pub elements: Vec<UiElement>,
    pub error: Option<String>,
}

const MAX_ELEMENTS: usize = 500;

// ────────────────────────────────────────────────
// Windows implementation
// ────────────────────────────────────────────────

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::sync::Mutex;

    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE, FALSE};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumChildWindows, EnumWindows, GetClassNameW, GetWindowTextLengthW, GetWindowTextW,
        IsWindowVisible, GetParent, SendMessageW, WM_GETTEXT, WM_GETTEXTLENGTH,
    };

    // ── low-level helpers ──────────────────────────────────────────────

    fn get_window_text(hwnd: HWND) -> String {
        unsafe {
            let len = GetWindowTextLengthW(hwnd);
            if len <= 0 {
                return String::new();
            }
            let mut buf: Vec<u16> = vec![0u16; (len + 2) as usize];
            let written = GetWindowTextW(hwnd, &mut buf);
            if written <= 0 {
                return String::new();
            }
            String::from_utf16_lossy(&buf[..written as usize])
        }
    }

    fn get_class_name(hwnd: HWND) -> String {
        unsafe {
            let mut buf: Vec<u16> = vec![0u16; 256];
            let written = GetClassNameW(hwnd, &mut buf);
            if written <= 0 {
                return String::new();
            }
            String::from_utf16_lossy(&buf[..written as usize])
        }
    }

    /// For Edit/ComboBox/RichEdit: use WM_GETTEXT to get the live text value.
    /// Falls back to GetWindowText for all other control classes.
    fn get_control_text(hwnd: HWND, class_name: &str) -> String {
        let use_wm_gettext = class_name.eq_ignore_ascii_case("Edit")
            || class_name.eq_ignore_ascii_case("ComboBox")
            || class_name.to_ascii_lowercase().starts_with("richedit");

        if use_wm_gettext {
            unsafe {
                let len_result = SendMessageW(hwnd, WM_GETTEXTLENGTH, None, None);
                let len = len_result.0 as usize;
                if len == 0 {
                    return String::new();
                }
                let mut buf: Vec<u16> = vec![0u16; len + 2];
                let written = SendMessageW(
                    hwnd,
                    WM_GETTEXT,
                    windows::Win32::Foundation::WPARAM(len + 1),
                    windows::Win32::Foundation::LPARAM(buf.as_mut_ptr() as isize),
                );
                let chars = written.0 as usize;
                if chars == 0 {
                    return String::new();
                }
                String::from_utf16_lossy(&buf[..chars])
            }
        } else {
            get_window_text(hwnd)
        }
    }

    fn count_children(hwnd: HWND) -> usize {
        let counter = Mutex::new(0usize);
        unsafe extern "system" fn count_cb(
            _hwnd: HWND,
            lparam: LPARAM,
        ) -> BOOL {
            let ptr = lparam.0 as *const Mutex<usize>;
            if let Some(m) = ptr.as_ref() {
                if let Ok(mut g) = m.lock() {
                    *g += 1;
                }
            }
            TRUE
        }
        unsafe {
            let ptr = &counter as *const Mutex<usize> as isize;
            let _ = EnumChildWindows(hwnd, Some(count_cb), LPARAM(ptr));
        }
        counter.into_inner().unwrap_or(0)
    }

    fn compute_level(mut hwnd: HWND, stop_at: HWND) -> u32 {
        let mut level = 0u32;
        loop {
            let parent = unsafe { GetParent(hwnd) };
            if parent == stop_at || parent.0 == 0 {
                break;
            }
            level += 1;
            hwnd = parent;
            if level >= 64 {
                break;
            }
        }
        level + 1
    }

    fn collect_element(
        hwnd: HWND,
        parent_hwnd: HWND,
        level: u32,
        type_filter: &[String],
        elements: &mut Vec<UiElement>,
    ) {
        if elements.len() >= MAX_ELEMENTS {
            return;
        }

        if !unsafe { IsWindowVisible(hwnd).as_bool() } {
            return;
        }

        let class_name = get_class_name(hwnd);
        let text = get_control_text(hwnd, &class_name);

        // Skip elements where both class and text are empty
        if class_name.is_empty() && text.is_empty() {
            return;
        }

        // Apply optional class-name filter
        if !type_filter.is_empty()
            && !type_filter
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&class_name))
        {
            return;
        }

        let child_count = count_children(hwnd);
        let parent_str = if parent_hwnd.0 == 0 {
            String::new()
        } else {
            format!("0x{:X}", parent_hwnd.0)
        };

        elements.push(UiElement {
            hwnd: format!("0x{:X}", hwnd.0),
            class_name,
            text,
            parent_hwnd: parent_str,
            level,
            child_count,
        });
    }

    // ── EnumWindows callback data ──────────────────────────────────────

    struct TopLevelState {
        pattern: String,
        matched: Vec<HWND>,
    }

    unsafe extern "system" fn enum_windows_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = &mut *(lparam.0 as *mut TopLevelState);
        if !IsWindowVisible(hwnd).as_bool() {
            return TRUE;
        }
        let title = get_window_text(hwnd).to_lowercase();
        if state.pattern.is_empty() || title.contains(&state.pattern) {
            state.matched.push(hwnd);
        }
        TRUE
    }

    // ── EnumChildWindows callback data ─────────────────────────────────

    struct ChildState<'a> {
        top_hwnd: HWND,
        type_filter: &'a [String],
        elements: &'a mut Vec<UiElement>,
    }

    unsafe extern "system" fn enum_child_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = &mut *(lparam.0 as *mut ChildState<'_>);
        if state.elements.len() >= MAX_ELEMENTS {
            return FALSE;
        }
        let parent = GetParent(hwnd);
        let level = compute_level(hwnd, state.top_hwnd);
        collect_element(hwnd, parent, level, state.type_filter, state.elements);
        TRUE
    }

    // ── Public entry point ──────────────────────────────────────────────

    pub fn read_elements(window_pattern: &str, control_types: &[String]) -> UiElementResult {
        let mut result = UiElementResult {
            window_pattern: window_pattern.to_string(),
            windows_found: 0,
            elements: Vec::new(),
            error: None,
        };

        // Step 1: enumerate top-level windows
        let mut top_state = TopLevelState {
            pattern: window_pattern.to_lowercase(),
            matched: Vec::new(),
        };

        unsafe {
            let ptr = &mut top_state as *mut TopLevelState as isize;
            if let Err(e) = EnumWindows(Some(enum_windows_cb), LPARAM(ptr)) {
                result.error = Some(format!("EnumWindows failed: {e}"));
                return result;
            }
        }

        result.windows_found = top_state.matched.len();

        // Step 2: for each matched top-level window, collect its children
        let mut elements: Vec<UiElement> = Vec::new();

        for top_hwnd in &top_state.matched {
            if elements.len() >= MAX_ELEMENTS {
                break;
            }

            // Include the top-level window itself (level 0)
            collect_element(*top_hwnd, HWND(0), 0, control_types, &mut elements);

            if elements.len() >= MAX_ELEMENTS {
                break;
            }

            let mut child_state = ChildState {
                top_hwnd: *top_hwnd,
                type_filter: control_types,
                elements: &mut elements,
            };

            unsafe {
                let ptr = &mut child_state as *mut ChildState<'_> as isize;
                // Ignore errors (e.g. access denied on protected windows)
                let _ = EnumChildWindows(*top_hwnd, Some(enum_child_cb), LPARAM(ptr));
            }
        }

        result.elements = elements;
        result
    }
}

// ────────────────────────────────────────────────
// Non-Windows stub
// ────────────────────────────────────────────────

#[cfg(not(windows))]
mod win_impl {
    use super::*;

    pub fn read_elements(_window_pattern: &str, _control_types: &[String]) -> UiElementResult {
        UiElementResult {
            window_pattern: String::new(),
            windows_found: 0,
            elements: vec![],
            error: Some("READ_UI_ELEMENTS is only supported on Windows".into()),
        }
    }
}

// ────────────────────────────────────────────────
// Public re-exports
// ────────────────────────────────────────────────

pub fn read_elements(window_pattern: &str, control_types: &[String]) -> UiElementResult {
    win_impl::read_elements(window_pattern, control_types)
}

```