---
id: T-023
name: Client Capabilities Suite
category: client
tier: mixed
mitre:
  - T1005       # Data from Local System (amaterasu file reads)
  - T1567.002   # Exfiltration to Cloud Storage (chunked upload via C2)
  - T1003       # OS Credential Dumping (harvest_lsass hook elsewhere)
  - T1555       # Credentials from Password Stores (DPAPI/vault harvest)
  - T1083       # File and Directory Discovery (LS + search)
  - T1217       # Browser Information Discovery (browser_hook)
  - T1176       # Browser Extensions (sideloading)
  - T1547.001   # Registry Run Keys (browser_hook layer 2)
  - T1053.005   # Scheduled Task (browser_hook layer 3)
  - T1546       # Event Triggered Execution (protocol handler hijack)
  - T1020       # Automated Exfiltration (form_scan input capture)
  - T1056       # Input Capture (content.js keystroke logging)
  - T1106       # Native API (spawn_browser_detached flags)
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires:
  - T-022   # Network Suite — both files depend on transport.rs / tcp_transport.rs for C2 plumbing
  - T-021   # Crypto & Obfuscation — config embedding via build.rs include_str! pattern (used by commands.rs that routes into these modules)
  - T-019   # Edo Dead Drop — discovery.rs (URL fetch) feeds the callback_url that browser_hook consumes
enables: []   # These are leaf client capabilities — no other technique consumes their outputs as inputs
vault_references:
  - src/client_rust/src/amaterasu.rs
  - src/client_rust/src/browser_hook.rs
implements:
  - file: src/client_rust/src/amaterasu.rs
    key_functions:
      - dispatch
      - handle_ls
      - handle_download
      - handle_harvest
      - handle_search
      - handle_cancel
      - walk_dir_search
      - glob_match
      - glob_match_inner
      - harvest_all
      - harvest_wifi
      - harvest_ssh
      - harvest_env
      - harvest_dpapi
      - harvest_vault
      - harvest_certs
      - scan_certs_in_dir
      - build_message
      - build_error
      - format_system_time
      - home_dir
    key_structs:
      - DownloadRequest
      - HarvestRequest
      - LsRequest
      - SearchRequest
      - CancelRequest
      - FileEntry
    key_constants:
      - MSG_AMATERASU_CHUNK (0x20)
      - MSG_AMATERASU_HARVEST (0x21)
      - MSG_AMATERASU_LS (0x22)
      - MSG_AMATERASU_ERROR (0x23)
      - DEFAULT_CHUNK_SIZE (65536)
      - MAX_SEARCH_RESULTS (1000)
    lines_of_interest:
      - "L19-L22: protocol constant block (msg type bytes)"
      - "L29-L46: cancel_registry OnceLock<Mutex<HashSet<u32>>>"
      - "L80-L86: build_message — 1B type + 4B BE length + payload"
      - "L192-L260: handle_download — spawn_blocking + cancel check between chunks"
      - "L446-L521: harvest_wifi — locale-aware netsh parsing (en/es/pt)"
      - "L525-L570: harvest_ssh — 256KB cap, .ssh directory enumeration"
      - "L572-L606: harvest_env — 33-pattern interesting env var filter"
      - "L608-L719: harvest_dpapi — metadata-only, no decryption"
      - "L721-L786: harvest_vault — cmdkey /list stdout parse"
      - "L788-L876: harvest_certs — 8-extension scan with depth-2 cap"
      - "L933-L974: dispatch — 5-command router with serde_json::from_str"
  - file: src/client_rust/src/browser_hook.rs
    key_functions:
      - manifest_json
      - background_js
      - content_js
      - get_ext_dir
      - write_extension
      - remove_extension
      - find_browser_exe
      - kill_browser
      - is_browser_running
      - spawn_browser_detached
      - launch_browser_hooked
      - launch_browser_clean
      - persist_layer1_shortcuts
      - unpersist_layer1_shortcuts
      - persist_layer2_run_key
      - unpersist_layer2_run_key
      - persist_layer3_schtask
      - unpersist_layer3_schtask
      - persist_layer4_protocol_handler
      - unpersist_layer4_protocol_handler
      - persist_layer1_desktop_files
      - persist_layer2_autostart
      - persist_layer3_cron
      - hook_prepare
      - hook_execute
      - hook_commit
      - unhook_prepare
      - unhook_execute
      - unhook_commit
      - persist
      - remove_persistence
      - status
    key_structs:
      - BrowserHookState
      - HookParams
      - UnhookParams
    key_constants:
      - CREATE_NEW_PROCESS_GROUP (0x00000200)
      - DETACHED_PROCESS (0x00000008)
      - GIF_TIMER_ID (referenced in card, not in this file — overlay.rs)
    lines_of_interest:
      - "L31-L40: BrowserHookState struct (5 fields)"
      - "L45-L72: manifest_json — MV3 disguised as 'Safe Browsing Enhanced Protection'"
      - "L74-L260: background_js — WebSocket C2 + 15 directives (get_cookies, exec_tab, screenshot, etc.)"
      - "L262-L336: content_js — input pattern analysis + form_scan + auth_check + page_scan"
      - "L429-L460: spawn_browser_detached — CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS"
      - "L510-L585: persist_layer1_shortcuts — PowerShell WScript.Shell COM, idempotent, RVPATCH: structured output"
      - "L587-L645: unpersist_layer1_shortcuts — mirrors persist_layer1"
      - "L647-L680: persist_layer2_run_key — HKCU\\...\\Run as 'Google Safe Browsing Service'"
      - "L706-L738: persist_layer3_schtask — ONLOGON, /RL LIMITED (no admin)"
      - "L760-L833: persist_layer4_protocol_handler — ChromeHTML/MSEdgeHTM ProgID patching"
      - "L1075-L1095: hook_prepare/hook_execute/hook_commit — 3-phase split for mutex release"
      - "L1127-L1160: persist — per-layer summary, sets state.persistent only on >0 success"
min_windows: "Windows 7 (amaterasu: netsh wlan, cmdkey; browser_hook: schtasks, WScript.Shell COM, ChromeHTML ProgID)"
needs_admin: "no (explicit: schtask uses /RL LIMITED; HKCU Run key; per-user LocalAppData ext dir)"
tags:
  - bof
  - keylogger
  - browser-hook
  - uac-bypass
  - capture
  - h264
  - input-blocker
  - recon
  - clipboard
  - ui-automation
  - dirty-rect
  - exfil
  - sysinfo
  - chunked-upload
  - mv3-extension
  - persistence-layers
  - locale-aware
  - cancel-registry
  - once-lock
---

# Client Capabilities Suite — Operator Playbook

## TL;DR
The two files analyzed implement the **post-exploitation data plane** of the client: `amaterasu.rs` is a chunked exfil engine with built-in cancellation, filesystem browsing, glob search, and 6 credential harvesters (wifi/ssh/env/dpapi/vault/certs); `browser_hook.rs` is a Manifest V3 Chromium extension sideloader disguised as "Safe Browsing Enhanced Protection" with a **4-layer persistence stack** (shortcuts + Run key + schtask + protocol handler) and a 3-phase hook/unhook split so the slow browser-kill step doesn't hold the client's state mutex. Both run in user context — no admin needed.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `src/client_rust/src/amaterasu.rs` | Exfiltration engine: filesystem browsing + chunked upload + credential harvesting | `dispatch()`, `handle_ls()`, `handle_download()`, `handle_harvest()`, `handle_search()`, `handle_cancel()`, 6 `harvest_*` functions | ~975 lines |
| `src/client_rust/src/browser_hook.rs` | Chromium extension sideloading (MV3) + 4-layer persistence (Win) / 3-layer (Linux) | `hook_prepare/execute/commit`, `unhook_*`, `persist()`, `remove_persistence()`, `BrowserHookState` | ~870 lines |

## How It Works

### Amaterasu — Exfiltration Pipeline

1. **C2 command arrives** at `commands.rs` (not in this file) with `cmd_type = "AMATERASU_*"`. It calls `amaterasu::dispatch(cmd_type, payload)` which is the single entry point (L933-L974).
2. **Dispatch** `match`es the 5 verbs: `AMATERASU_LS`, `AMATERASU_DOWNLOAD`, `AMATERASU_HARVEST`, `AMATERASU_SEARCH`, `AMATERASU_CANCEL`. Each branch `serde_json::from_str`s the payload into a typed request struct (`LsRequest`, `DownloadRequest`, `HarvestRequest`, `SearchRequest`, `CancelRequest`).
3. **Filesystem browsing** (`handle_ls`, L139-L186): `tokio::fs::read_dir` enumerates the path; `entry.metadata().await` fetches size/is_dir/modified; `format_system_time` (L88-L132) manually converts `SystemTime` to ISO-8601 *without chrono* — implements leap-year math inline (`y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)`).
4. **Chunked download** (`handle_download`, L192-L260): opens the file with `tokio::fs::File::open`, fetches metadata to validate offset, then **switches to `std::fs` inside `tokio::task::spawn_blocking`** because `tokio::fs::File::seek` requires `&mut`. The blocking loop:
   - Reads `chunk_size` (default 64KB, `DEFAULT_CHUNK_SIZE = 65536`) bytes into a reusable buffer.
   - Calls `cancel_registry::is_cancelled(job_id)` between chunks — checks the `OnceLock<Mutex<HashSet<u32>>>` (L29-L46).
   - Builds `MSG_AMATERASU_CHUNK` payload: `[4B job_id BE][4B offset BE][chunk_data]` (note: offset truncated to `u32` at `current_offset as u32`).
   - Calls `cancel_registry::clear(job_id)` on exit.
5. **Glob search** (`handle_search` → `walk_dir_search`, L265-L310): recursive directory walk with `max_depth` enforcement (default 10) and `MAX_SEARCH_RESULTS = 1000` cap. Pattern matching uses `glob_match` (L313-L351) — a hand-rolled iterative glob supporting `*` and `?` with backtracking via `star_pi/star_ti` pointers. On Windows the pattern and name are lowercased first (case-insensitive).
6. **Credential harvesting** (`handle_harvest`, L316-L348): spawns a blocking task and dispatches on `harvest_type` to one of:
   - `harvest_wifi` (L446-L521): runs `netsh wlan show profiles`, then per-SSID `netsh wlan show profile name=<ssid> key=clear`. **Locale-aware parsing** — checks for `All User Profile` (en), `Todos los perfiles de usuario` (es), `Todos os perfis de usu` (pt), and a generic `Profile:` fallback. Parses `Key Content` / `Contenido de la clave` / `Conte` for the cleartext key.
   - `harvest_ssh` (L525-L570): enumerates `~/.ssh`, reads any file ≤256KB as text (binary marker for larger).
   - `harvest_env` (L572-L606): filters environment variables against a 33-pattern hardcoded array (`TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `API`, `CREDENTIALS`, `AUTH`, `AWS`, `AZURE`, `GCP`, `GITHUB`, `GITLAB`, `DOCKER`, `NPM`, `NUGET`, `PRIVATE`, `CERT`, `JWT`, `DATABASE`, `DB_PASS`, `REDIS`, `MONGO`, `MYSQL`, `POSTGRES`, `SMTP`, `MAIL`, `SENDGRID`, `TWILIO`, `STRIPE`, `SLACK`, `WEBHOOK`, `OPENAI`, `ANTHROPIC`, `HUGGING`).
   - `harvest_dpapi` (L608-L719): **metadata-only** — no decryption. Enumerates browser `Local State` files for `encrypted_key` presence, RDP `Credentials` directory, and `%APPDATA%\Microsoft\Protect\<SID>\` master key files. Reports path+size only.
   - `harvest_vault` (L721-L786): runs `cmdkey /list` and parses `Target:`/`Type:`/`User:` lines (also localized `Destino:`/`Tipo:`/`Usuario:`). Reports target/type/user — not the password (cmdkey doesn't expose it).
   - `harvest_certs` (L788-L876): scans `~/.ssh`, `~/.ssl`, `~/.tls`, `~/.aws`, `~/.azure`, `~/.kube`, and `%USERPROFILE%`/`%APPDATA%`/`%LOCALAPPDATA%` for files with extensions `pem`, `pfx`, `p12`, `crt`, `cer`, `key`, `jks`, `keystore`. Depth-limited to 2 (prevents huge-tree traversal hang).
   - `harvest_all` (L399-L408): aggregates all six into a single JSON object.
7. **Cancellation** (`handle_cancel`, L313-L317): inserts `job_id` into the `OnceLock<Mutex<HashSet<u32>>>`. The `handle_download` loop polls this between chunks.

### Browser Hook — Extension Sideloading

1. **Command arrives** at `commands.rs`, calls `hook_prepare(payload)` (L1075-L1095) which parses JSON for `browser`, `callback_url`, `persist`, computes `ext_dir = %LOCALAPPDATA%\Google\Chrome Safe Browsing\ext` (L401-L410), and writes the 3-file MV3 extension via `write_extension` (L412-L418).
2. **Extension contents**:
   - `manifest_json` (L45-L72): Manifest V3, name `"Safe Browsing Enhanced Protection"`, version `4.2.1`, permissions `[storage, cookies, tabs, activeTab, scripting, history, downloads, bookmarks]`, `host_permissions: ["<all_urls>"]`, content script injected at `document_idle` in `all_frames: true`.
   - `background_js` (L74-L260): service worker that opens a WebSocket to `callback_url`, retries every 5s (`scheduleRetry`), and dispatches 15 directives: `get_cookies`, `get_cookies_domain`, `get_tabs`, `exec_tab` (via `new Function(msg.code)` — full remote JS eval), `navigate`, `create_tab`, `close_tab`, `activate_tab`, `screenshot` (via `chrome.tabs.captureVisibleTab`), `get_history`, `get_downloads`, `get_bookmarks`, `get_storage` (localStorage/sessionStorage), `remove_cookie`, `get_page_html`.
   - `content_js` (L262-L336): sets `window.__sbep_init` guard, attaches `keydown` capture-phase listener that buffers keystrokes and flushes every 2s via `chrome.runtime.sendMessage({_sbep: true, type: 'input_analysis', keys: [...]})`. Also intercepts `submit` events — collects all form fields including passwords — and uses a `MutationObserver` to detect newly added `input[type="password"]` and report username+password to the backend.
3. **Browser kill** (`kill_browser`, L462-L484): on Windows runs `taskkill /F /IM chrome.exe` and `taskkill /F /IM msedge.exe`, then **polls `is_browser_running` every 250ms up to 5s** instead of a blind sleep (this was an explicit fix per the inline comment).
4. **Detached spawn** (`spawn_browser_detached`, L429-L460): on Windows uses `creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)` — `0x00000200 | 0x00000008`. `stdio` all nulled. `std::mem::forget(child)` so the child handle is **not held** — on Windows this closes the HANDLE; on Unix avoids zombie reaping responsibility. This is critical for OPSEC: if the client crashes, Chrome keeps running.
5. **Hooked launch** (`launch_browser_hooked`, L486-L510): passes `--load-extension=<path>`, `--disable-extensions-except=<path>`, `--restore-last-session`, `--no-first-run`.
6. **3-phase commit** (`hook_prepare` → `hook_execute` → `hook_commit`): explicitly designed so that `hook_execute` (which blocks 5s on browser kill) **does not hold the client state mutex** — see comment at L1093: "Phase 2 (slow, NO mutex needed)". Same pattern mirrored in `unhook_prepare` → `unhook_execute` → `unhook_commit`.
7. **Persistence layer 1 — Shortcuts** (`persist_layer1_shortcuts`, L510-L585): generates a PowerShell script that:
   - Creates a `WScript.Shell` COM object.
   - Walks 5 directories: `Desktop`, `CommonDesktopDirectory`, `StartMenu`, `CommonStartMenu`, `Quick Launch\User Pinned\TaskBar`.
   - For each `.lnk` whose `TargetPath` matches `*chrome*` or `*msedge*`, **idempotently strips existing `--load-extension`/`--disable-extensions-except` args** then re-appends them.
   - Wraps `$lnk.Save()` in try/catch — only counts on success.
   - Releases each RCW via `[System.Runtime.InteropServices.Marshal]::ReleaseComObject($lnk)`.
   - Writes structured `RVPATCH:<n>` to stdout for reliable Rust parsing.
   - Script file named `rv_patch_<pid>_<rand>.ps1` for race-condition avoidance.
8. **Persistence layer 2 — Run key** (`persist_layer2_run_key`, L647-L680): sets `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value named `"Google Safe Browsing Service"` (or `"Microsoft Edge Safe Browsing Service"`) to the full browser command line with `--load-extension`.
9. **Persistence layer 3 — Scheduled task** (`persist_layer3_schtask`, L706-L738): runs `schtasks /Create /TN "GoogleSafeBrowsingService" /TR "<cmd>" /SC ONLOGON /RL LIMITED /F`. The `/RL LIMITED` flag is explicitly chosen over `HIGHEST` per the inline comment — works on standard accounts without UAC.
10. **Persistence layer 4 — Protocol handler** (`persist_layer4_protocol_handler`, L760-L833): reads `HKCU\SOFTWARE\Classes\ChromeHTML\shell\open\command` (or `MSEdgeHTM`), parses out the `REG_SZ` or `REG_EXPAND_SZ` value, and **inserts `--load-extension` before `--single-argument`** (or before the trailing `"%1"` / `-- "%1"`). This ensures external link clicks (e.g. from email clients, chat apps) also load the extension.
11. **Linux equivalents**: `persist_layer1_desktop_files` patches `.desktop` files (inserts args before `%U`/`%u`/`%F`), `persist_layer2_autostart` writes `~/.config/autostart/browser-maintenance.desktop`, `persist_layer3_cron` adds an `@reboot` crontab entry marked `# chrome-sb-service` for idempotent removal.

## Code Architecture

### Call Graph

```
commands.rs (T-023 dispatcher, not in scope)
    │
    ├── amaterasu::dispatch(cmd_type, payload)            [amaterasu.rs:933]
    │       ├── serde_json::from_str::<LsRequest>         → handle_ls
    │       ├── serde_json::from_str::<DownloadRequest>   → handle_download
    │       │       └── spawn_blocking → std::fs::File::seek + read
    │       │           └── cancel_registry::is_cancelled  [amaterasu.rs:37]
    │       ├── serde_json::from_str::<HarvestRequest>    → handle_harvest
    │       │       └── spawn_blocking → harvest_{wifi|ssh|env|dpapi|vault|certs|all}
    │       ├── serde_json::from_str::<SearchRequest>     → handle_search
    │       │       └── spawn_blocking → walk_dir_search → glob_match
    │       └── serde_json::from_str::<CancelRequest>    → handle_cancel
    │
    └── browser_hook::hook(state, payload)               [browser_hook.rs:1097]
            ├── hook_prepare(payload)                    [L1075]
            │       └── write_extension → manifest_json + background_js + content_js
            ├── hook_execute(params)                      [L1085]
            │       ├── kill_browser → is_browser_running (poll)
            │       └── launch_browser_hooked → spawn_browser_detached
            └── hook_commit(state, params)               [L1090]
                    └── persist(state) → 4 layers (Win) / 3 layers (Linux)
```

### Data Flow

- **Amaterasu**: server → `commands.rs` → `dispatch()` → typed request struct → blocking-task harvest → JSON-serialized `serde_json::Value` → `build_message` wraps as `[1B type][4B BE len][payload]` → returns `Vec<Vec<u8>>` to the transport layer.
- **Browser hook**: server → `commands.rs` → `hook_prepare` writes 3 files to `%LOCALAPPDATA%\Google\Chrome Safe Browsing\ext\` → `hook_execute` kills+relaunches browser → MV3 extension loaded via `--load-extension` → Chromium starts the service worker → service worker opens WS to `callback_url` → server can now issue directives (`get_cookies`, `exec_tab`, etc.) directly to the browser.

### Type Hierarchy

```
BrowserHookState { active, browser, ext_dir, callback_url, persistent }
   ▲
   │ mutated by hook_commit / unhook_commit / persist / remove_persistence
   │
HookParams { browser, callback_url, auto_persist, ext_dir }
UnhookParams { browser, ext_dir }
   ▲ both are short-lived transfer structs across the 3-phase split
```

### Feature Gates

- `#[cfg(windows)]` blocks for `persist_layer1_shortcuts`, `persist_layer2_run_key`, `persist_layer3_schtask`, `persist_layer4_protocol_handler` (and `unpersist_*` mirrors).
- `#[cfg(not(windows))]` blocks for `persist_layer1_desktop_files`, `persist_layer2_autostart`, `persist_layer3_cron`.
- `#[cfg(target_os = "windows")]` on `harvest_wifi`, `harvest_dpapi`, `harvest_vault` (non-Windows returns `{"error": "...not supported on this platform"}`).
- `#[cfg(windows)]` on `spawn_browser_detached` `creation_flags` block.

## Operational Profile

### When to Use

- **Amaterasu**: post-foothold data collection — when you need to enumerate files, exfiltrate specific paths, or sweep credentials before the SOC notices. The 64KB chunk size and cancel-registry make it suitable for long-running transfers over flaky C2 channels. The harvest module is good for first-pass credential sweeps before committing to riskier LSASS access.
- **Browser hook**: long-dwell engagements where the user is on a Chrome/Edge-heavy workflow. The MV3 extension gives you **in-browser DOM access** that bypasses API hooking because everything happens inside the trusted browser process. The 4-layer persistence means your hook survives browser updates, reboots, and even Run-key cleanup.

### When NOT to Use

- **Amaterasu DPAPI harvester**: it's metadata-only — don't expect to actually recover browser passwords from this alone. For real decryption you need the LSASS dump path (T-023 `lsass_dump.rs` not in scope) plus an offline DPAPI cracker.
- **Amaterasu vault harvester**: `cmdkey /list` doesn't expose passwords — it lists targets/types/users only. For real Credential Manager extraction you need the Windows `VaultEnumerateItems` API.
- **Browser hook**: avoid if the user runs in **Strict extension-block mode** (enterprise GPO `ExtensionInstallBlocklist = *`). `--load-extension` is silently ignored in that case. Also avoid if you can't afford a 5s browser-kill window (active RDP session, trader workstation, etc.).
- **Browser hook Layer 4 (protocol handler)**: don't use if the user has a non-default browser association (e.g. Firefox primary, Chrome secondary) — patching `ChromeHTML` won't intercept link clicks.

### Kill Chain Position

These are **post-exploitation leaf modules** — they sit at the end of the chain:

```
T-004 (PEB walk) → T-001 (RecycledGate) → T-012 (Early Cascade injection)
  → T-005 (Ekko sleep) → T-017 (5-layer persistence)
  → T-022 (Network Suite establishes C2)
  → T-023 (Client Capabilities) ← YOU ARE HERE
       ├─ amaterasu: T1005 → T1567 exfil
       └─ browser_hook: T1176 → T1056 input capture → T1020 automated exfil
```

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` Blocks
**Neither file contains any `unsafe` code.** Both rely on safe Rust + `std::process::Command` + `std::os::windows::process::CommandExt` trait for the `creation_flags` setter (the trait method itself is safe; the unsafety is encapsulated inside std).

### FFI / Windows API Patterns

- **`std::os::windows::process::CommandExt::creation_flags`** (`browser_hook.rs:L449-L452`): the only Windows-specific process API used. Constants inlined:
  ```rust
  const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
  const DETACHED_PROCESS: u32 = 0x00000008;
  cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
  ```
- **No direct Win32 FFI** — everything goes through `std::process::Command` shelling out to `taskkill`, `tasklist`, `reg`, `schtasks`, `powershell`, `cmdkey`, `netsh`. This is a deliberate OPSEC tradeoff: process-spawn telemetry is more common but easier to blend than direct `Nt*` calls from a non-Microsoft-signed binary.

### Initialization Patterns

- **`OnceLock<Mutex<HashSet<u32>>>`** (`amaterasu.rs:L29-L46`): the cancellation registry. `get_or_init` lazy-initializes on first `cancel`/`is_cancelled`/`clear` call. The same pattern is reused in `byakugan.rs` (per card) — this is a **crate-wide idiom** for cancellation registries.
- **`thread_local!`** is NOT used in these files (it's used in `keylogger.rs` per card).
- **`std::mem::forget(child)`** (`browser_hook.rs:L455`): explicitly leaks the `Child` handle so Rust doesn't maintain a reference. On Windows this closes the process HANDLE; on Unix it avoids zombie-reaping duty. The inline comment explains: "On Windows this closes the HANDLE; on Unix it avoids zombie reaping responsibilities."

### Error Handling

- **Fallible operations return `Result<_, String>`** (not `Result<_, io::Error>`). Errors are stringified early — this is a deliberate choice for JSON serialization into `MSG_AMATERASU_ERROR`.
- **`build_error(job_id, &str)`** (`amaterasu.rs:L88-L94`): centralized error envelope — wraps the error string as `{"job_id": <id>, "error": <msg>}` and prepends `MSG_AMATERASU_ERROR` byte. Called from 6 sites in `handle_download` alone.
- **`spawn_blocking` failure path** (`amaterasu.rs:L259-L264`): if the JoinHandle panics, the error is converted to `build_error(req.job_id, &format!("task error: {}", e))`. No retry.
- **`reg delete` "not found" tolerance** (`browser_hook.rs:L692-L697`): the `unpersist_layer2_run_key` function specifically checks the stderr for `"unable to find"` or `"not find"` and returns `Ok(())` — idempotent removal.

### Memory Layout

- `BrowserHookState` is 5 fields: `bool`, `String`, `PathBuf`, `String`, `bool` — `PathBuf` is the heaviest at ~24 bytes for the inner `OsString`. Total ~64 bytes. Cheap to clone, but `&mut` is held only during the fast `prepare`/`commit` phases.
- `DownloadRequest` carries `job_id: u32`, `remote_path: String`, `offset: u64`, `chunk_size: u32`. Note `offset` is `u64` but `MSG_AMATERASU_CHUNK` packs it as `u32` (`current_offset as u32`) — **silent truncation above 4GB**.
- The chunk buffer is `vec![0u8; chunk_size as usize]` allocated once and reused per `read()` call (L233).

### Syscall Numbers

None — these files use `std::process::Command`, which internally goes through `CreateProcessW` (and ultimately `NtCreateUserProcess`). No SSN resolution needed. This is a notable departure from the rest of the framework (T-001 through T-006), which aggressively uses direct syscalls. The rationale is that the client_rust crate runs **post-compromise as a user-mode RAT** — direct syscalls here would actually be MORE suspicious than the std lib calls because the parent process is presumably the dark_crystal loader, which is itself a non-Microsoft-signed image.

## Cross-References Found in Code

- **`amaterasu.rs:dispatch()` → calls into `commands.rs` (T-023 dispatcher)** — the entry point is `dispatch(cmd_type, payload)`. The 5 command names (`AMATERASU_LS`, `AMATERASU_DOWNLOAD`, `AMATERASU_HARVEST`, `AMATERASU_SEARCH`, `AMATERASU_CANCEL`) are the contract surface.
- **`amaterasu.rs:L19-L22` protocol constants** → wire format consumed by T-019 Network Suite (`protocol.rs`). The `[1B type][4B BE len][payload]` envelope matches the protocol described in the card.
- **`amaterasu.rs:L29-L46` `cancel_registry`** → same OnceLock pattern referenced in T-023 card as also being used by `byakugan.rs` (T-023 recon). This is a **crate-wide Rust idiom** — likely factored out in a future refactor.
- **`amaterasu.rs:L88-L132` `format_system_time`** → manually implemented because chrono isn't pulled in. Matches the **minimal-dependency philosophy** referenced in T-021 Crypto & Obfuscation (`build.rs` embedding) — the client_rust crate deliberately avoids heavy deps.
- **`browser_hook.rs:persist_layer2_run_key`** → uses `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — **same key as T-017 Five-Layer Persistence `persist/com_hijack.rs` and `persist/schtask.rs`**. There's deliberate feature overlap: browser_hook provides a self-contained persistence stack for the browser specifically, while T-017 is for the implant itself.
- **`browser_hook.rs:persist_layer3_schtask`** → uses `schtasks /Create /SC ONLOGON` — **same tooling as T-017 `persist/schtask.rs`** but with `/RL LIMITED` (T-017 may use HIGHEST depending on context).
- **`browser_hook.rs:L449` `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`** → standard Win32 process creation flags. Relates conceptually to T-014 `NtCreateUserProcess` (which uses `RTL_USER_PROCESS_PARAMETERS` flags), but here we go through `CreateProcessW` indirectly.
- **`amaterasu.rs:harvest_env` interesting_patterns array** → mirrors a similar credential-pattern list commonly used in T-020 Anti-Analysis suite and T-016 EDR evasion (which scan for the same tokens to decide whether to aggress).
- **`amaterasu.rs:harvest_dpapi` browser Local State path** → `Google/Chrome/User Data/Local State`. This is the **same path targeted by T-023 card's `extract_wifi.rs`** credential harvester (experimental harvest module) — different code, same target.
- **`browser_hook.rs:content_js` form_scan input capture** → semantically identical to T-023 `keylogger.rs` (WH_KEYBOARD_LL) but operates at the DOM layer instead of the Win32 message layer. Both feed into the same `MSG_*` protocol family.
- **`browser_hook.rs:persist_layer4_protocol_handler` ProgID patching** → `ChromeHTML` / `MSEdgeHTM` ProgID hijack. This is technically a T-1546 (Event Triggered Execution: hijack of shell-open-command). Conceptually related to T-017 COM hijack persistence.

## Edge Cases & Failure Modes

1. **`amaterasu.rs:handle_download` offset truncation**
   - Failure path: L228 `payload.extend_from_slice(&(current_offset as u32).to_be_bytes())`.
   - What goes wrong: if the file is larger than 4GB and the download progresses past offset `0xFFFFFFFF`, the offset field wraps. The server will misroute subsequent chunks.
   - Symptom: server receives chunks with overlapping or non-monotonic offsets past the 4GB mark.
   - Workaround: the field is hardcoded as `u32` — there's no runtime fallback. Pre-split downloads at 4GB boundaries or patch the protocol to use `u64`.

2. **`amaterasu.rs:harvest_wifi` locale fallback**
   - Failure path: L464-L477 — relies on the `Profile:` + `:` substring. If a locale uses a different separator (e.g. fullwidth colon `：` in Japanese Windows), the SSID parse fails.
   - Symptom: empty `ssid` string, the entry is silently dropped (`if ssid.is_empty() { continue; }`).
   - Workaround: the `netsh` output also includes the SSID in the `BSSID` line of the detail output — could be reparsed from there. Not currently implemented.

3. **`browser_hook.rs:persist_layer4_protocol_handler` REG_EXPAND_SZ**
   - Failure path: L783-L788 splits on `"REG_EXPAND_SZ"` first, then falls back to `"REG_SZ"`. If a future Windows version uses a different type token (e.g. `REG_MULTI_SZ` for some browser variants), `current_value` will be empty and the function returns `Err("Could not read current protocol handler")`.
   - Symptom: layer 4 silently fails, `state.persistent` may still be set true because layers 1-3 succeeded.
   - Workaround: fall back to `reg query /v <explicit>` or use Win32 `RegQueryValueExW` directly.

4. **`browser_hook.rs:spawn_browser_detached` zombie leak on Unix**
   - Failure path: L455 `std::mem::forget(child)`. The comment acknowledges: "on Unix it avoids zombie reaping responsibilities." On Linux, the orphaned browser will be reparented to PID 1 (init/systemd) which reaps it. But on systems without a proper init (some embedded BSD-derived, or `bash` running as PID 1 in a container), the browser becomes a zombie that never gets reaped.
   - Symptom: `ps` shows `<defunct>` chrome processes after the user closes the browser.
   - Workaround: spawn a reaper thread on Unix that calls `waitpid` in a loop. Not currently implemented.

5. **`browser_hook.rs:kill_browser` race**
   - Failure path: L466-L475 polls `is_browser_running` every 250ms up to 5s. If 5s elapses without the process exiting, the code proceeds anyway with `warn!("Browser kill timed out after 5s, proceeding anyway")`. The subsequent `launch_browser_hooked` will spawn a **second** browser process. The `--load-extension` flag will be honored on the new process but the old one keeps running without the hook.
   - Symptom: two chrome.exe processes, only one has the extension loaded; cookies/tabs from the old process aren't captured.
   - Workaround: try `wmic process where "name='chrome.exe'" delete` as a more forceful fallback, or accept partial coverage.

6. **`amaterasu.rs:walk_dir_search` symlink loop**
   - Failure path: L295 `walk_dir_search(&entry.path(), pattern, current_depth + 1, max_depth, results)`. There's **no symlink detection** — a recursive symlink (e.g. `~/.local/share/foo -> ~/.local/share`) will be traversed up to `max_depth` levels (default 10). On a maliciously crafted filesystem this could be used to DoS the client.
   - Symptom: search hangs for several seconds; eventually completes with deeply-nested matches.
   - Workaround: check `entry.metadata().file_type().is_symlink()` and skip. Not currently implemented.

7. **`amaterasu.rs:harvest_ssh` 256KB cap**
   - Failure path: L552-L556 — files >256KB are reported as `"(too large: {} bytes)"` with no content. Private keys are typically <10KB so this rarely matters, but `known_hosts` on long-lived hosts can exceed this.
   - Symptom: `content` field is `"(too large: N bytes)"` — server sees the size but not the content.
   - Workaround: explicit `AMATERASU_DOWNLOAD` request for that specific file.

## OPSEC Notes

### Artifacts Left

- **`%LOCALAPPDATA%\Google\Chrome Safe Browsing\ext\`** — three files (`manifest.json`, `background.js`, `content.js`). The directory name is disguised but `manifest.json` reveals the WebSocket URL in plain text inside the service worker source. **Treat `callback_url` as burnt** — once a defender sees this directory, they have your C2 endpoint.

- **PowerShell script** `%TEMP%\rv_patch_<pid>_<rand>.ps1` — written and deleted within the same `Command::new("powershell")` call (`browser_hook.rs:L573-L580`). Sysmon EID 11 (FileCreate) catches this if FileDelete monitoring is on.

- **`HKCU\...\Run\Google Safe Browsing Service`** — registry value. Defender scanning for non-Microsoft Run keys catches this. The display name is well-chosen but `reg query HKCU\...\Run` reveals it's a `chrome.exe` invocation with `--load-extension`.

- **`schtasks /Create /TN "GoogleSafeBrowsingService"`** — task name is suspicious. Sysmon EID 1 + EID 4904 (Scheduled Task creation). Defender's `schtasks /Query /V` exposes the `--load-extension` argument.

- **`taskkill /F /IM chrome.exe`** — kills ALL chrome processes, not just the user's. If the operator is sharing the host (jump box scenario), this kills other users' browsers. Sysmon EID 1 catches it.

- **Chrome `chrome://extensions` page** shows the sideloaded extension with a yellow "Keep?" banner in MV3. User-visible. Cannot be suppressed without `ExtensionSettings` GPO.

- **`cmdkey /list` and `netsh wlan show profiles` process spawns** — both are commonly alerted on by EDR (T1555 and T1098 indicator patterns). Use `WlanGetProfile` and `VaultEnumerateItems` APIs directly to avoid these.

- **Chunked upload traffic** — bursts of `MSG_AMATERASU_CHUNK` (0x20) frames every 64KB. Network IDS with payload-type fingerprinting catches the constant `[1B 0x20][4B len]` header.

### Cleanup Performed

- `unhook_execute` removes `ext_dir` (`remove_extension`).
- `unpersist_layer*` functions all exist and are idempotent (returns `Ok` on not-found).
- `cancel_registry::clear(job_id)` is called in `handle_download` on both success and cancel paths.
- `std::fs::remove_file(&script_path)` in `persist_layer1_shortcuts` — always called even if PowerShell failed to spawn.
- However: **`hook_commit` doesn't roll back `BrowserHookState` if `hook_execute` fails after `hook_prepare` succeeds** — `state.active` stays `false` but the extension files are written to disk and orphaned. Operator must manually `BROWSER_UNHOOK` to clean up.

## Reusable Patterns

### Pattern: OnceLock Cancellation Registry
- **Use when**: long-running async operations that need external cancellation, no external deps allowed.
- **Code ref**: `amaterasu.rs:cancel_registry` (L29-L46)
- **How**: `static CANCELLED: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();` with three functions (`cancel`, `is_cancelled`, `clear`). Polled in a loop between chunks/iterations. Reused in `byakugan.rs` for scan cancellation.

### Pattern: 3-Phase Mutex-Release Split
- **Use when**: a state-mutating operation has a long blocking middle step (browser kill, file download, network wait).
- **Code ref**: `browser_hook.rs:hook_prepare/hook_execute/hook_commit` (L1075-L1095)
- **How**: split into (1) parse + write under mutex, (2) blocking I/O *without* mutex, (3) commit state under mutex. Lets other commands interleave during the slow step.

### Pattern: Locale-Aware CLI Parser
- **Use when**: parsing output of locale-aware CLI tools (`netsh`, `cmdkey`, `ipconfig`).
- **Code ref**: `amaterasu.rs:harvest_wifi` (L464-L477)
- **How**: try localized prefixes in priority order (`en`, `es`, `pt`, then generic `:`-split fallback). Useful across any Windows CLI tool that respects MUI.

### Pattern: Idempotent Shortcut Argument Patcher
- **Use when**: persisting arguments across user-visible launchers.
- **Code ref**: `browser_hook.rs:persist_layer1_shortcuts` PowerShell script (L525-L555)
- **How**: regex strip existing `--load-extension=...` (both quoted and unquoted) before re-adding. Structured `RVPATCH:<n>` output for reliable cross-language parsing. COM RCW release in `finally`. Save() wrapped in try/catch.

### Pattern: `std::mem::forget(child)` Detached Spawn
- **Use when**: spawning long-lived child processes that must outlive the parent without holding handles.
- **Code ref**: `browser_hook.rs:spawn_browser_detached` (L429-L460)
- **How**: `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS` on Windows, `Stdio::null()` for all three stdio streams, then `std::mem::forget(child)`. The explicit forget is the key — Rust's `Child` Drop would otherwise keep a HANDLE and signal the process when the parent exits.

### Pattern: Hand-Rolled Iterative Glob
- **Use when**: glob matching without pulling in the `glob` crate (size-constrained implants).
- **Code ref**: `amaterasu.rs:glob_match_inner` (L325-L351)
- **How**: classic two-pointer backtracking with `star_pi`/`star_ti` markers. Iterative (no recursion → no stack-overflow on adversarial inputs). Case-folding gated by `#[cfg(windows)]` to match NTFS case-insensitive semantics.

### Pattern: Depth-Capped Recursive Dir Walk
- **Use when**: walking adversarial filesystems (potential symlink loops, deep trees).
- **Code ref**: `amaterasu.rs:walk_dir_search` (L265-L310), `scan_certs_in_dir` (L851-L876)
- **How**: `current_depth > max_depth` check at function entry; `MAX_SEARCH_RESULTS` cap checked at each entry iteration. Cheap, deterministic, no DoS surface. *Caveat: doesn't detect symlinks — see Edge Case #6.*
