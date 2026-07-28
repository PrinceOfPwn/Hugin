# eth_tx_signing

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/eth_tx_signing.rs` |
| **Lines** | 40 |

## Constants

- `SEPOLIA_CHAIN_ID`: `u64` = `11155111`

## Types

### enum `RlpItem` (line 37)
RLP encoding (matches server/blockchain.py _rlp_encode)

## Public API

### `keccak256` (line 14)
```rust
pub fn keccak256(data: &[u8]) -> [u8; 32]
```

### `derive_address` (line 25)
```rust
pub fn derive_address(private_key: &[u8; 32]) -> [u8; 20]
```
Derive Ethereum address from 32-byte private key.
secp256k1 pubkey → Keccak-256 → last 20 bytes

## Key Dependencies

- `use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};`
- `use sha3::{Digest, Keccak256};`

## Full Source

```rust
// Source: client_rust/src/eth_tx.rs
// Technique: T020 - Pure Rust Ethereum EIP-155 TX signing
// Tier: A
//
// Minimal Ethereum transaction signing for Sepolia testnet.
// Pure Rust: k256 (secp256k1) + sha3 (Keccak-256). No ethers-rs, no C deps.
// Port of server/blockchain.py RLP + EIP-155 signing.

use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};
use sha3::{Digest, Keccak256};

pub const SEPOLIA_CHAIN_ID: u64 = 11155111;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derive Ethereum address from 32-byte private key.
/// secp256k1 pubkey → Keccak-256 → last 20 bytes
pub fn derive_address(private_key: &[u8; 32]) -> [u8; 20] {
    let signing_key = SigningKey::from_bytes(private_key.into()).expect("invalid key");
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let pubkey_uncompressed = pubkey_bytes.as_bytes();
    let hash = keccak256(&pubkey_uncompressed[1..]);  // skip 0x04 prefix
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// RLP encoding (matches server/blockchain.py _rlp_encode)
pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

```