# juubi

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/juubi.rs` |
| **Lines** | 242 |
| **Cards** | T019-networking |
| **Role** | Peer relay network |

## Types

### struct `JuubiState` (line 14)

## Public API

### `new` (line 28)
```rust
pub fn new() -> Self
```

### `build_hello` (line 54)
```rust
pub fn build_hello(&self, client_id: &str) -> Vec<u8>
```

### `handle_auth_challenge` (line 66)
```rust
pub fn handle_auth_challenge(&mut self, nonce: &[u8]) -> Vec<u8>
```

### `handle_peer_list` (line 72)
```rust
pub fn handle_peer_list(&mut self, payload: &[u8])
```

### `handle_open` (line 84)
```rust
pub fn handle_open(&mut self, payload: &[u8]) -> Option<Vec<u8>>
```

### `handle_ack` (line 95)
```rust
pub fn handle_ack(&mut self, payload: &[u8])
```

### `handle_data` (line 103)
```rust
pub fn handle_data(&mut self, payload: &[u8]) -> Option<Vec<u8>>
```

### `handle_failover` (line 116)
```rust
pub fn handle_failover(&mut self, payload: &[u8]) -> Option<Vec<u8>>
```

### `handle_close` (line 133)
```rust
pub fn handle_close(&mut self, payload: &[u8])
```

### `sha256` (line 170)
```rust
pub fn sha256(data: &[u8]) -> [u8; 32]
```

## Internal Functions

- `hmac_sha256` (line 145)

## Key Dependencies

- `use tracing::{info, warn};`
- `use crate::protocol::{`

## Full Source

```rust
// Juubi (十尾) — client-side relay state and HMAC authentication.
//
// Handles the client's participation in server-brokered peer relay:
// announcing relay capability, responding to HMAC-SHA256 auth challenges,
// and managing inbound/outbound relay streams.

use std::collections::HashMap;
use tracing::{info, warn};

use crate::protocol::{
    build_message, MSG_JUUBI_HELLO, MSG_JUUBI_AUTH_RESP,
};

pub struct JuubiState {
    pub enabled: bool,
    pub can_relay: bool,
    pub max_streams: u8,
    pub outbound_streams: HashMap<u32, String>,
    pub inbound_streams: HashMap<u32, Vec<u8>>,
    pub last_peer_list: Vec<serde_json::Value>,
    pub authenticated: bool,
    pub secret_token: Vec<u8>,
    /// Ethereum wallet address derived from JuubiChainState (populated on construction)
    pub wallet_address: String,
}

impl JuubiState {
    pub fn new() -> Self {
        let token = std::env::var("JUUBI_SECRET")
            .unwrap_or_else(|_| "raven-juubi-default".to_string());
        // Derive wallet address from chain state without taking ownership
        let chain = crate::juubi_chain::JuubiChainState::new();
        let wallet_address = chain.wallet_address();
        JuubiState {
            enabled: std::env::var("JUUBI_ENABLED")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            can_relay: std::env::var("JUUBI_CAN_RELAY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            max_streams: std::env::var("JUUBI_MAX_STREAMS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            outbound_streams: HashMap::new(),
            inbound_streams: HashMap::new(),
            last_peer_list: Vec::new(),
            authenticated: false,
            secret_token: token.into_bytes(),
            wallet_address,
        }
    }

    pub fn build_hello(&self, client_id: &str) -> Vec<u8> {
        let payload = serde_json::json!({
            "juubiVersion": 1,
            "canRelay": self.can_relay,
            "maxStreams": self.max_streams,
            "capabilities": ["socks5"],
            "clientId": client_id,
            "walletAddress": self.wallet_address,
        });
        build_message(MSG_JUUBI_HELLO, payload.to_string().as_bytes())
    }

    pub fn handle_auth_challenge(&mut self, nonce: &[u8]) -> Vec<u8> {
        let mac = hmac_sha256(nonce, &self.secret_token);
        info!("Juubi: responding to auth challenge ({} byte nonce)", nonce.len());
        build_message(MSG_JUUBI_AUTH_RESP, &mac)
    }

    pub fn handle_peer_list(&mut self, payload: &[u8]) {
        match serde_json::from_slice::<Vec<serde_json::Value>>(payload) {
            Ok(peers) => {
                info!("Juubi: received peer list with {} entries", peers.len());
                self.last_peer_list = peers;
            }
            Err(e) => {
                warn!("Juubi: failed to parse peer list: {}", e);
            }
        }
    }

    pub fn handle_open(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 4 {
            return None;
        }
        let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let meta = &payload[4..];
        info!("Juubi: stream {} opened (meta {} bytes)", stream_id, meta.len());
        self.inbound_streams.insert(stream_id, Vec::new());
        None
    }

    pub fn handle_ack(&mut self, payload: &[u8]) {
        if payload.len() < 4 {
            return;
        }
        let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        info!("Juubi: stream {} acknowledged", stream_id);
    }

    pub fn handle_data(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 4 {
            return None;
        }
        let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let data = &payload[4..];

        if let Some(buf) = self.inbound_streams.get_mut(&stream_id) {
            buf.extend_from_slice(data);
        }
        None
    }

    pub fn handle_failover(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 8 {
            return None;
        }
        let old_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let new_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        info!("Juubi: failover stream {} → {}", old_id, new_id);

        if let Some(data) = self.inbound_streams.remove(&old_id) {
            self.inbound_streams.insert(new_id, data);
        }
        if let Some(peer) = self.outbound_streams.remove(&old_id) {
            self.outbound_streams.insert(new_id, peer);
        }
        None
    }

    pub fn handle_close(&mut self, payload: &[u8]) {
        if payload.len() < 5 {
            return;
        }
        let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let reason = payload[4];
        info!("Juubi: stream {} closed (reason={})", stream_id, reason);
        self.inbound_streams.remove(&stream_id);
        self.outbound_streams.remove(&stream_id);
    }
}

fn hmac_sha256(data: &[u8], key: &[u8]) -> [u8; 32] {
    let block_size = 64;
    let mut key_padded = vec![0u8; block_size];

    if key.len() > block_size {
        let hash = sha256(key);
        key_padded[..32].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    ipad.extend_from_slice(data);
    let inner_hash = sha256(&ipad);

    opad.extend_from_slice(&inner_hash);
    sha256(&opad)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use std::num::Wrapping;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [Wrapping<u32>; 8] = [
        Wrapping(0x6a09e667), Wrapping(0xbb67ae85), Wrapping(0x3c6ef372), Wrapping(0xa54ff53a),
        Wrapping(0x510e527f), Wrapping(0x9b05688c), Wrapping(0x1f83d9ab), Wrapping(0x5be0cd19),
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [Wrapping(0u32); 64];
        for i in 0..16 {
            w[i] = Wrapping(u32::from_be_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]));
        }
        for i in 16..64 {
            let s0 = (w[i - 15].0.rotate_right(7)) ^ (w[i - 15].0.rotate_right(18)) ^ (w[i - 15].0 >> 3);
            let s1 = (w[i - 2].0.rotate_right(17)) ^ (w[i - 2].0.rotate_right(19)) ^ (w[i - 2].0 >> 10);
            w[i] = w[i - 16] + Wrapping(s0) + w[i - 7] + Wrapping(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = Wrapping(e.0.rotate_right(6) ^ e.0.rotate_right(11) ^ e.0.rotate_right(25));
            let ch = Wrapping((e.0 & f.0) ^ ((!e.0) & g.0));
            let temp1 = hh + s1 + ch + Wrapping(K[i]) + w[i];
            let s0 = Wrapping(a.0.rotate_right(2) ^ a.0.rotate_right(13) ^ a.0.rotate_right(22));
            let maj = Wrapping((a.0 & b.0) ^ (a.0 & c.0) ^ (b.0 & c.0));
            let temp2 = s0 + maj;

            hh = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        h[0] = h[0] + a; h[1] = h[1] + b; h[2] = h[2] + c; h[3] = h[3] + d;
        h[4] = h[4] + e; h[5] = h[5] + f; h[6] = h[6] + g; h[7] = h[7] + hh;
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&h[i].0.to_be_bytes());
    }
    result
}

```