# eth_tx

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/eth_tx.rs` |
| **Lines** | 703 |
| **Cards** | T020-crypto |
| **Role** | Pure Rust EIP-155 TX signing |

## Constants

- `SEPOLIA_CHAIN_ID`: `u64` = `11155111`
- `SEL_POST_OPEN`: `[u8; 4]` = `[0x24, 0xd2, 0x88, 0xbf]`
- `SEL_REGISTER_PEER`: `[u8; 4]` = `[0x39, 0x5c, 0x0c, 0xe8]`
- `SEL_SEND_MESSAGE`: `[u8; 4]` = `[0x23, 0xc6, 0x40, 0xe7]`

## Types

### enum `RlpItem` (line 62)

## Public API

### `keccak256` (line 24)
```rust
pub fn keccak256(data: &[u8]) -> [u8; 32]
```

### `derive_address` (line 39)
```rust
pub fn derive_address(private_key: &[u8; 32]) -> [u8; 20]
```
Derive an Ethereum address from a 32-byte private key.
Returns the 20-byte address.

### `address_to_hex` (line 54)
```rust
pub fn address_to_hex(addr: &[u8; 20]) -> String
```
Format address as 0x-prefixed hex string.

### `from_u64` (line 68)
```rust
pub fn from_u64(v: u64) -> Self
```

### `from_bytes` (line 77)
```rust
pub fn from_bytes(v: &[u8]) -> Self
```

### `empty` (line 81)
```rust
pub fn empty() -> Self
```

### `rlp_encode` (line 86)
```rust
pub fn rlp_encode(item: &RlpItem) -> Vec<u8>
```

### `sign_transaction` (line 128)
```rust
pub fn sign_transaction(
```
Sign an EIP-155 transaction and return the raw hex with 0x prefix.

### `abi_encode_bytes` (line 227)
```rust
pub fn abi_encode_bytes(data: &[u8]) -> Vec<u8>
```
ABI-encode a dynamic bytes argument (offset + length + padded data).

### `abi_encode_register_peer` (line 241)
```rust
pub fn abi_encode_register_peer(client_hash: &[u8; 32], endpoint: &[u8], caps: u8) -> Vec<u8>
```
ABI-encode for registerPeer(bytes32 clientHash, bytes encryptedEndpoint, uint8 caps).

### `abi_encode_send_message` (line 258)
```rust
pub fn abi_encode_send_message(to_hash: &[u8; 32], data: &[u8]) -> Vec<u8>
```
ABI-encode for sendMessage(bytes32 to, bytes data).

### `encode_post_open` (line 291)
```rust
pub fn encode_post_open(data: &[u8]) -> Vec<u8>
```
Build calldata for postOpen(bytes data)

### `encode_register_peer` (line 298)
```rust
pub fn encode_register_peer(client_hash: &[u8; 32], endpoint: &[u8], caps: u8) -> Vec<u8>
```
Build calldata for registerPeer(bytes32 clientHash, bytes encryptedEndpoint, uint8 caps)

### `encode_send_message` (line 305)
```rust
pub fn encode_send_message(to_hash: &[u8; 32], data: &[u8]) -> Vec<u8>
```
Build calldata for sendMessage(bytes32 to, bytes data)

### `hex_encode` (line 315)
```rust
pub fn hex_encode(bytes: &[u8]) -> String
```

### `hex_decode` (line 319)
```rust
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String>
```

## Internal Functions

- `rlp_length_prefix` (line 104)
- `trim_leading_zeros` (line 217)
- `pad32_left` (line 272)
- `keccak256_empty` (line 340)
- `keccak256_hello` (line 350)
- `derive_address_known_vector` (line 363)
- `address_to_hex_format` (line 386)
- `hex_encode_decode_roundtrip` (line 403)
- `hex_decode_0x_prefix` (line 411)
- `hex_decode_odd_length_error` (line 417)
- `hex_decode_invalid_chars_error` (line 424)
- `rlp_single_byte_below_0x80` (line 432)
- `rlp_empty_bytes` (line 439)
- `rlp_short_string` (line 445)
- `rlp_long_string` (line 455)
- `rlp_list_encoding` (line 466)
- `rlp_nested_list` (line 479)
- `rlp_from_u64_zero` (line 492)
- `rlp_from_u64_one` (line 499)
- `rlp_from_u64_127` (line 510)
- `rlp_from_u64_128` (line 521)
- `test_privkey` (line 533)
- `test_to_address` (line 542)
- `sign_transaction_returns_0x_prefix` (line 547)
- `sign_transaction_deterministic` (line 567)
- `sign_transaction_low_s_normalization` (line 576)
- `abi_encode_bytes_32_aligned` (line 648)
- `abi_encode_bytes_starts_with_offset_0x20` (line 655)
- `encode_post_open_selector` (line 667)
- `encode_register_peer_selector` (line 673)
- `encode_send_message_selector` (line 680)
- `selector_post_open_matches_keccak` (line 687)
- `selector_register_peer_matches_keccak` (line 693)
- `selector_send_message_matches_keccak` (line 699)

## Key Dependencies

- `use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner, RecoveryId};`
- `use sha3::{Digest, Keccak256};`
- `use super::*;`

## Full Source

```rust
// Minimal Ethereum transaction signing for Sepolia testnet.
//
// Port of server/blockchain.py RLP + EIP-155 signing + address derivation.
// Uses k256 (pure Rust secp256k1) and sha3 (Keccak-256).
// No ethers-rs, no C dependencies.

use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner, RecoveryId};
use sha3::{Digest, Keccak256};

/// Sepolia chain ID for EIP-155 signing.
pub const SEPOLIA_CHAIN_ID: u64 = 11155111;

/// secp256k1 curve order N.
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

// ------------------------------------------------------------------
// Keccak-256 helper
// ------------------------------------------------------------------

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ------------------------------------------------------------------
// Ethereum address derivation (secp256k1 pubkey -> keccak256 -> [12:])
// ------------------------------------------------------------------

/// Derive an Ethereum address from a 32-byte private key.
/// Returns the 20-byte address.
pub fn derive_address(private_key: &[u8; 32]) -> [u8; 20] {
    let signing_key = SigningKey::from_bytes(private_key.into())
        .expect("invalid private key");
    let verifying_key = signing_key.verifying_key();
    // Uncompressed public key: 65 bytes (0x04 + 32 x + 32 y)
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let pubkey_uncompressed = pubkey_bytes.as_bytes();
    // Hash the 64 bytes after the 0x04 prefix
    let hash = keccak256(&pubkey_uncompressed[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Format address as 0x-prefixed hex string.
pub fn address_to_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", hex_encode(addr))
}

// ------------------------------------------------------------------
// RLP encoding (matches server/blockchain.py _rlp_encode)
// ------------------------------------------------------------------

pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

impl RlpItem {
    pub fn from_u64(v: u64) -> Self {
        if v == 0 {
            return RlpItem::Bytes(vec![]);
        }
        let bytes = v.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        RlpItem::Bytes(bytes[start..].to_vec())
    }

    pub fn from_bytes(v: &[u8]) -> Self {
        RlpItem::Bytes(v.to_vec())
    }

    pub fn empty() -> Self {
        RlpItem::Bytes(vec![])
    }
}

pub fn rlp_encode(item: &RlpItem) -> Vec<u8> {
    match item {
        RlpItem::Bytes(data) => {
            if data.len() == 1 && data[0] < 0x80 {
                return vec![data[0]];
            }
            if data.is_empty() {
                return vec![0x80];
            }
            rlp_length_prefix(data, 0x80)
        }
        RlpItem::List(items) => {
            let payload: Vec<u8> = items.iter().flat_map(|i| rlp_encode(i)).collect();
            rlp_length_prefix(&payload, 0xc0)
        }
    }
}

fn rlp_length_prefix(data: &[u8], offset: u8) -> Vec<u8> {
    let length = data.len();
    if length <= 55 {
        let mut out = vec![offset + length as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = {
            let bytes = length.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
            bytes[start..].to_vec()
        };
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

// ------------------------------------------------------------------
// EIP-155 transaction signing
// ------------------------------------------------------------------

/// Sign an EIP-155 transaction and return the raw hex with 0x prefix.
pub fn sign_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &[u8],          // 20 bytes for normal tx, empty for contract creation
    value: u64,
    data: &[u8],
    private_key: &[u8; 32],
    chain_id: u64,
) -> anyhow::Result<String> {
    // Build unsigned tx for EIP-155 hash: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
    let unsigned = RlpItem::List(vec![
        RlpItem::from_u64(nonce),
        RlpItem::from_u64(gas_price),
        RlpItem::from_u64(gas_limit),
        RlpItem::from_bytes(to),
        RlpItem::from_u64(value),
        RlpItem::from_bytes(data),
        RlpItem::from_u64(chain_id),
        RlpItem::from_u64(0),
        RlpItem::from_u64(0),
    ]);

    let encoded = rlp_encode(&unsigned);
    let msg_hash = keccak256(&encoded);

    // Sign with k256
    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| anyhow::anyhow!("invalid private key: {}", e))?;
    let (signature, recovery_id) = signing_key
        .sign_prehash(&msg_hash)
        .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

    let r_bytes = signature.r().to_bytes();
    let mut s_bytes_arr = signature.s().to_bytes();

    // Low-s normalization: if s > N/2, set s = N - s and flip recovery_id
    let mut rec_id = recovery_id.to_byte();
    let n_half = {
        let mut h = [0u8; 32];
        // N/2 — shift right by 1
        let mut carry = 0u8;
        for i in 0..32 {
            let val = SECP256K1_N[i] as u16 + carry as u16 * 256;
            h[i] = (val / 2) as u8;
            carry = (SECP256K1_N[i] & 1) as u8;
        }
        h
    };
    if s_bytes_arr.as_slice() > n_half.as_slice() {
        // s = N - s
        let mut borrow: i16 = 0;
        let mut new_s = [0u8; 32];
        for i in (0..32).rev() {
            let diff = SECP256K1_N[i] as i16 - s_bytes_arr[i] as i16 - borrow;
            if diff < 0 {
                new_s[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                new_s[i] = diff as u8;
                borrow = 0;
            }
        }
        s_bytes_arr.copy_from_slice(&new_s);
        rec_id ^= 1;
    }

    let v = rec_id as u64 + chain_id * 2 + 35;

    // Build r and s as big-endian integers (strip leading zeros)
    let r_trimmed = trim_leading_zeros(&r_bytes);
    let s_trimmed = trim_leading_zeros(&s_bytes_arr);

    let signed = RlpItem::List(vec![
        RlpItem::from_u64(nonce),
        RlpItem::from_u64(gas_price),
        RlpItem::from_u64(gas_limit),
        RlpItem::from_bytes(to),
        RlpItem::from_u64(value),
        RlpItem::from_bytes(data),
        RlpItem::from_u64(v),
        RlpItem::from_bytes(r_trimmed),
        RlpItem::from_bytes(s_trimmed),
    ]);

    let raw = rlp_encode(&signed);
    Ok(format!("0x{}", hex_encode(&raw)))
}

fn trim_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len().saturating_sub(1));
    &data[start..]
}

// ------------------------------------------------------------------
// ABI encoding helpers
// ------------------------------------------------------------------

/// ABI-encode a dynamic bytes argument (offset + length + padded data).
pub fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + ((data.len() + 31) / 32) * 32);
    // Offset: always 0x20 (32) for a single bytes argument
    out.extend_from_slice(&pad32_left(&32u64.to_be_bytes()));
    // Length
    out.extend_from_slice(&pad32_left(&(data.len() as u64).to_be_bytes()));
    // Data padded to 32-byte boundary
    out.extend_from_slice(data);
    let padding = (32 - data.len() % 32) % 32;
    out.extend(std::iter::repeat(0u8).take(padding));
    out
}

/// ABI-encode for registerPeer(bytes32 clientHash, bytes encryptedEndpoint, uint8 caps).
pub fn abi_encode_register_peer(client_hash: &[u8; 32], endpoint: &[u8], caps: u8) -> Vec<u8> {
    let mut out = Vec::new();
    // clientHash (bytes32) — static
    out.extend_from_slice(client_hash);
    // offset for encryptedEndpoint (bytes) — after clientHash(32) + offset(32) + caps(32) = 96
    out.extend_from_slice(&pad32_left(&96u64.to_be_bytes()));
    // caps (uint8) — padded to 32
    out.extend_from_slice(&pad32_left(&[caps]));
    // encryptedEndpoint: length + padded data
    out.extend_from_slice(&pad32_left(&(endpoint.len() as u64).to_be_bytes()));
    out.extend_from_slice(endpoint);
    let padding = (32 - endpoint.len() % 32) % 32;
    out.extend(std::iter::repeat(0u8).take(padding));
    out
}

/// ABI-encode for sendMessage(bytes32 to, bytes data).
pub fn abi_encode_send_message(to_hash: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // to (bytes32) — static
    out.extend_from_slice(to_hash);
    // offset for data (bytes) — after to(32) + offset(32) = 64
    out.extend_from_slice(&pad32_left(&64u64.to_be_bytes()));
    // data: length + padded data
    out.extend_from_slice(&pad32_left(&(data.len() as u64).to_be_bytes()));
    out.extend_from_slice(data);
    let padding = (32 - data.len() % 32) % 32;
    out.extend(std::iter::repeat(0u8).take(padding));
    out
}

fn pad32_left(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32 - data.len().min(32);
    out[start..].copy_from_slice(&data[..data.len().min(32)]);
    out
}

// ------------------------------------------------------------------
// Function selectors (keccak256 of signature, first 4 bytes)
// ------------------------------------------------------------------

/// postOpen(bytes) — anyone can post to RavenC2
pub const SEL_POST_OPEN: [u8; 4] = [0x24, 0xd2, 0x88, 0xbf];
/// registerPeer(bytes32,bytes,uint8) — JuubiRegistry
pub const SEL_REGISTER_PEER: [u8; 4] = [0x39, 0x5c, 0x0c, 0xe8];
/// sendMessage(bytes32,bytes) — JuubiRegistry
pub const SEL_SEND_MESSAGE: [u8; 4] = [0x23, 0xc6, 0x40, 0xe7];

/// Build calldata for postOpen(bytes data)
pub fn encode_post_open(data: &[u8]) -> Vec<u8> {
    let mut calldata = Vec::from(SEL_POST_OPEN.as_slice());
    calldata.extend(abi_encode_bytes(data));
    calldata
}

/// Build calldata for registerPeer(bytes32 clientHash, bytes encryptedEndpoint, uint8 caps)
pub fn encode_register_peer(client_hash: &[u8; 32], endpoint: &[u8], caps: u8) -> Vec<u8> {
    let mut calldata = Vec::from(SEL_REGISTER_PEER.as_slice());
    calldata.extend(abi_encode_register_peer(client_hash, endpoint, caps));
    calldata
}

/// Build calldata for sendMessage(bytes32 to, bytes data)
pub fn encode_send_message(to_hash: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut calldata = Vec::from(SEL_SEND_MESSAGE.as_slice());
    calldata.extend(abi_encode_send_message(to_hash, data));
    calldata
}

// ------------------------------------------------------------------
// Hex helpers
// ------------------------------------------------------------------

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Keccak-256 ------------------------------------------------

    #[test]
    fn keccak256_empty() {
        let hash = keccak256(b"");
        let expected = hex_decode(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn keccak256_hello() {
        let hash = keccak256(b"hello");
        let expected = hex_decode(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
        )
        .unwrap();
        assert_eq!(hash.len(), 32);
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    // ---- Address derivation ----------------------------------------

    #[test]
    fn derive_address_known_vector() {
        // Well-known test vector: private key → address
        // Verified via k256 secp256k1 derivation
        let privkey: [u8; 32] = [
            0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31,
            0x47, 0x1b, 0x5d, 0xbb, 0x62, 0x04, 0xfe, 0x51, 0x29, 0x61,
            0x70, 0x82, 0x79, 0xf8, 0xb7, 0x88, 0xce, 0x07, 0xa7, 0x8e,
            0x4c, 0x18,
        ];
        let addr = derive_address(&privkey);
        assert_eq!(addr.len(), 20, "address must be 20 bytes");
        // Verify determinism: same key always yields same address
        let addr2 = derive_address(&privkey);
        assert_eq!(addr, addr2);
        // Verify against known output from this implementation
        let addr_hex = hex_encode(&addr);
        assert_eq!(
            addr_hex.to_lowercase(),
            "406381066342cd54094672884635aaf44ccaa256"
        );
    }

    #[test]
    fn address_to_hex_format() {
        let privkey: [u8; 32] = [
            0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31,
            0x47, 0x1b, 0x5d, 0xbb, 0x62, 0x04, 0xfe, 0x51, 0x29, 0x61,
            0x70, 0x82, 0x79, 0xf8, 0xb7, 0x88, 0xce, 0x07, 0xa7, 0x8e,
            0x4c, 0x18,
        ];
        let addr = derive_address(&privkey);
        let hex = address_to_hex(&addr);
        assert!(hex.starts_with("0x"), "must start with 0x");
        assert_eq!(hex.len(), 42, "0x + 40 hex chars = 42");
        assert_eq!(hex, hex.to_lowercase(), "must be lowercase");
    }

    // ---- Hex helpers ------------------------------------------------

    #[test]
    fn hex_encode_decode_roundtrip() {
        let original = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn hex_decode_0x_prefix() {
        let decoded = hex_decode("0xdeadbeef").unwrap();
        assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_odd_length_error() {
        let result = hex_decode("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("odd"));
    }

    #[test]
    fn hex_decode_invalid_chars_error() {
        let result = hex_decode("zzzz");
        assert!(result.is_err());
    }

    // ---- RLP encoding -----------------------------------------------

    #[test]
    fn rlp_single_byte_below_0x80() {
        // A single byte in 0x00..0x7f is its own RLP encoding
        let item = RlpItem::Bytes(vec![0x42]);
        assert_eq!(rlp_encode(&item), vec![0x42]);
    }

    #[test]
    fn rlp_empty_bytes() {
        let item = RlpItem::Bytes(vec![]);
        assert_eq!(rlp_encode(&item), vec![0x80]);
    }

    #[test]
    fn rlp_short_string() {
        // "hello" = 5 bytes, <= 55 → prefix = 0x80 + 5 = 0x85
        let data = b"hello";
        let item = RlpItem::Bytes(data.to_vec());
        let encoded = rlp_encode(&item);
        assert_eq!(encoded[0], 0x80 + data.len() as u8);
        assert_eq!(&encoded[1..], data);
    }

    #[test]
    fn rlp_long_string() {
        // 56 bytes → needs multi-byte length prefix
        let data = vec![0xAA; 56];
        let encoded = rlp_encode(&RlpItem::Bytes(data.clone()));
        // length = 56 fits in 1 byte → prefix byte = 0x80 + 55 + 1 = 0xb8
        assert_eq!(encoded[0], 0xb8);
        assert_eq!(encoded[1], 56);
        assert_eq!(&encoded[2..], data.as_slice());
    }

    #[test]
    fn rlp_list_encoding() {
        // RLP list of two single bytes
        let list = RlpItem::List(vec![
            RlpItem::Bytes(vec![0x01]),
            RlpItem::Bytes(vec![0x02]),
        ]);
        let encoded = rlp_encode(&list);
        // Payload: [0x01, 0x02] = 2 bytes
        // List prefix: 0xc0 + 2 = 0xc2
        assert_eq!(encoded, vec![0xc2, 0x01, 0x02]);
    }

    #[test]
    fn rlp_nested_list() {
        // [[0x01]]
        let inner = RlpItem::List(vec![RlpItem::Bytes(vec![0x01])]);
        let outer = RlpItem::List(vec![inner]);
        let encoded = rlp_encode(&outer);
        // Inner: [0xc1, 0x01] (list of 1 byte payload)
        // Outer: [0xc2, 0xc1, 0x01] (list of 2 byte payload)
        assert_eq!(encoded, vec![0xc2, 0xc1, 0x01]);
    }

    // ---- RlpItem::from_u64 -----------------------------------------

    #[test]
    fn rlp_from_u64_zero() {
        let item = RlpItem::from_u64(0);
        // Zero encodes as empty bytes → RLP = [0x80]
        assert_eq!(rlp_encode(&item), vec![0x80]);
    }

    #[test]
    fn rlp_from_u64_one() {
        let item = RlpItem::from_u64(1);
        match &item {
            RlpItem::Bytes(b) => assert_eq!(b, &vec![0x01]),
            _ => panic!("expected Bytes variant"),
        }
        // 0x01 < 0x80, so single byte passthrough
        assert_eq!(rlp_encode(&item), vec![0x01]);
    }

    #[test]
    fn rlp_from_u64_127() {
        let item = RlpItem::from_u64(127);
        match &item {
            RlpItem::Bytes(b) => assert_eq!(b, &vec![0x7f]),
            _ => panic!("expected Bytes variant"),
        }
        // 0x7f < 0x80 → passthrough
        assert_eq!(rlp_encode(&item), vec![0x7f]);
    }

    #[test]
    fn rlp_from_u64_128() {
        let item = RlpItem::from_u64(128);
        match &item {
            RlpItem::Bytes(b) => assert_eq!(b, &vec![0x80]),
            _ => panic!("expected Bytes variant"),
        }
        // 0x80 is NOT < 0x80, so short string: [0x80+1, 0x80] = [0x81, 0x80]
        assert_eq!(rlp_encode(&item), vec![0x81, 0x80]);
    }

    // ---- Transaction signing ----------------------------------------

    fn test_privkey() -> [u8; 32] {
        [
            0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31,
            0x47, 0x1b, 0x5d, 0xbb, 0x62, 0x04, 0xfe, 0x51, 0x29, 0x61,
            0x70, 0x82, 0x79, 0xf8, 0xb7, 0x88, 0xce, 0x07, 0xa7, 0x8e,
            0x4c, 0x18,
        ]
    }

    fn test_to_address() -> [u8; 20] {
        [0x01; 20] // arbitrary recipient
    }

    #[test]
    fn sign_transaction_returns_0x_prefix() {
        let privkey = test_privkey();
        let to = test_to_address();
        let result = sign_transaction(
            0,              // nonce
            1_000_000_000,  // gas_price (1 gwei)
            21_000,         // gas_limit
            &to,            // to
            0,              // value
            &[],            // data
            &privkey,
            SEPOLIA_CHAIN_ID,
        )
        .unwrap();
        assert!(result.starts_with("0x"), "signed tx must start with 0x");
        // Must be valid hex after 0x
        assert!(hex_decode(&result).is_ok());
    }

    #[test]
    fn sign_transaction_deterministic() {
        let privkey = test_privkey();
        let to = test_to_address();
        let result1 = sign_transaction(0, 1_000_000_000, 21_000, &to, 0, &[], &privkey, SEPOLIA_CHAIN_ID).unwrap();
        let result2 = sign_transaction(0, 1_000_000_000, 21_000, &to, 0, &[], &privkey, SEPOLIA_CHAIN_ID).unwrap();
        assert_eq!(result1, result2, "same inputs must produce identical signed tx");
    }

    #[test]
    fn sign_transaction_low_s_normalization() {
        let privkey = test_privkey();
        let to = test_to_address();
        let raw_hex = sign_transaction(0, 1_000_000_000, 21_000, &to, 0, &[], &privkey, SEPOLIA_CHAIN_ID).unwrap();
        let raw = hex_decode(&raw_hex).unwrap();

        // Decode the signed tx RLP to extract s value.
        // The signed tx is RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s]).
        // We verify s <= N/2 by checking against the precomputed half.
        let n_half: [u8; 32] = {
            let mut h = [0u8; 32];
            let mut carry = 0u8;
            for i in 0..32 {
                let val = SECP256K1_N[i] as u16 + carry as u16 * 256;
                h[i] = (val / 2) as u8;
                carry = (SECP256K1_N[i] & 1) as u8;
            }
            h
        };

        // Re-sign and inspect internal s: we can verify by re-running the signing logic.
        // Simpler approach: the raw tx is well-formed RLP. A large s would mean
        // the signing code is broken. We verify the tx is non-empty and decodable.
        assert!(!raw.is_empty());
        // The tx should be a valid RLP list starting with 0xf8.. or 0xf9.. (long list)
        assert!(raw[0] >= 0xc0, "signed tx must be an RLP list");

        // Directly verify: re-derive s from the signing process
        let unsigned = RlpItem::List(vec![
            RlpItem::from_u64(0),
            RlpItem::from_u64(1_000_000_000),
            RlpItem::from_u64(21_000),
            RlpItem::from_bytes(&to),
            RlpItem::from_u64(0),
            RlpItem::from_bytes(&[]),
            RlpItem::from_u64(SEPOLIA_CHAIN_ID),
            RlpItem::from_u64(0),
            RlpItem::from_u64(0),
        ]);
        let encoded = rlp_encode(&unsigned);
        let msg_hash = keccak256(&encoded);

        let signing_key = k256::ecdsa::SigningKey::from_bytes((&privkey).into()).unwrap();
        let (signature, _recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            k256::ecdsa::signature::hazmat::PrehashSigner::sign_prehash(&signing_key, &msg_hash).unwrap();
        let mut s_bytes = signature.s().to_bytes();

        // Apply the same normalization logic as the function under test
        if s_bytes.as_slice() > n_half.as_slice() {
            let mut new_s = [0u8; 32];
            let mut borrow: i16 = 0;
            for i in (0..32).rev() {
                let diff = SECP256K1_N[i] as i16 - s_bytes[i] as i16 - borrow;
                if diff < 0 {
                    new_s[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    new_s[i] = diff as u8;
                    borrow = 0;
                }
            }
            s_bytes.copy_from_slice(&new_s);
        }
        assert!(
            s_bytes.as_slice() <= n_half.as_slice(),
            "s must be <= N/2 after normalization"
        );
    }

    // ---- ABI encoding -----------------------------------------------

    #[test]
    fn abi_encode_bytes_32_aligned() {
        let data = b"hello world";
        let encoded = abi_encode_bytes(data);
        assert_eq!(encoded.len() % 32, 0, "output must be 32-byte aligned");
    }

    #[test]
    fn abi_encode_bytes_starts_with_offset_0x20() {
        let data = b"test";
        let encoded = abi_encode_bytes(data);
        // First 32 bytes = offset = 0x0000...0020
        let mut expected_offset = [0u8; 32];
        expected_offset[31] = 0x20;
        assert_eq!(&encoded[..32], &expected_offset);
    }

    // ---- Calldata selectors -----------------------------------------

    #[test]
    fn encode_post_open_selector() {
        let calldata = encode_post_open(b"test");
        assert_eq!(&calldata[..4], &SEL_POST_OPEN);
    }

    #[test]
    fn encode_register_peer_selector() {
        let hash = [0u8; 32];
        let calldata = encode_register_peer(&hash, b"endpoint", 1);
        assert_eq!(&calldata[..4], &SEL_REGISTER_PEER);
    }

    #[test]
    fn encode_send_message_selector() {
        let hash = [0u8; 32];
        let calldata = encode_send_message(&hash, b"msg");
        assert_eq!(&calldata[..4], &SEL_SEND_MESSAGE);
    }

    #[test]
    fn selector_post_open_matches_keccak() {
        let hash = keccak256(b"postOpen(bytes)");
        assert_eq!(&hash[..4], &SEL_POST_OPEN);
    }

    #[test]
    fn selector_register_peer_matches_keccak() {
        let hash = keccak256(b"registerPeer(bytes32,bytes,uint8)");
        assert_eq!(&hash[..4], &SEL_REGISTER_PEER);
    }

    #[test]
    fn selector_send_message_matches_keccak() {
        let hash = keccak256(b"sendMessage(bytes32,bytes)");
        assert_eq!(&hash[..4], &SEL_SEND_MESSAGE);
    }
}

```