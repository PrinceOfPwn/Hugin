# crowd — crypto.rs  (✅ C TIER — AES-GCM + zstd, pure crypto utility)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/crypto.rs` |
| **Lines** | 191 |
| **Tier** | A |
| **Cards** | T020-crypto |
| **Role** | AES-256-GCM + zstd pipeline |
| **Unsafe blocks** | 3 |

## Purpose

# crowd — crypto.rs  (✅ C TIER — AES-GCM + zstd, pure crypto utility)

Primitivas criptográficas del dropper.

## AES-GCM (primario — spec)
`aes_gcm_decrypt`: descifrado in-place compatible con el formato del spec.
Key 32B, nonce 12B, tag 16B al final del ciphertext.

## AES-256-CBC (legacy — para payloads pre-existentes)
`decrypt_payload`: backward-compat con el formato anterior (key+IV 16B).

## zstd decompression
`zstd_decompress`: descomprimir buffer post-decrypt.

## SecureZeroMemory
`secure_zero_memory`: write_volatile 0 en toda la región — compiler-proof.

## Types

### struct `SecureVec` (line 148)
A Vec<u8> that is zeroized on drop.

## Public API

### `aes_gcm_decrypt` (line 33)
```rust
pub fn aes_gcm_decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>>
```
AES-256-GCM decrypt.

Formato del input: `nonce(12B) || ciphertext || tag(16B)`.
Compatible con el formato producido por donut con AES-GCM.

### `aes_gcm_decrypt_with_aad` (line 50)
```rust
pub fn aes_gcm_decrypt_with_aad(data: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>>
```
AES-256-GCM decrypt with AAD (Additional Authenticated Data).

### `decrypt_payload` (line 75)
```rust
pub fn decrypt_payload(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>>
```
AES-256-CBC decrypt (legacy format). Key 32B, IV 16B.

### `zstd_decompress` (line 91)
```rust
pub fn zstd_decompress(data: &[u8], out_hint_mb: usize) -> Result<Vec<u8>>
```
Decompress a zstd stream.
`out_hint_mb`: expected output size hint in MB (0 = no hint, max 512MB enforced).

### `zstd_decompress_validated` (line 116)
```rust
pub fn zstd_decompress_validated(data: &[u8], expected_bytes: usize, out_hint_mb: usize) -> Result<Vec<u8>>
```
Decompress a zstd stream and validate the output matches an expected size.
Returns an error if the decompressed size does not match `expected_bytes`.
Useful when the payload header specifies the original size and we need
to ensure integrity post-decompression.

### `decrypt_and_decompress` (line 132)
```rust
pub fn decrypt_and_decompress(
```
AES-GCM decrypt + zstd decompress in sequence.
This is the main Fase 1 step 07 entry point.

The intermediate decrypted buffer is securely zeroed after decompression
to avoid leaving sensitive plaintext in process memory.

### `secure_zero_memory` (line 169)
```rust
pub fn secure_zero_memory(buf: &mut Vec<u8>)
```
Zero out a buffer using `write_volatile` — prevents compiler elision.
Each byte is written individually to ensure all bytes are zeroed.

### `secure_zero_slice` (line 187)
```rust
pub fn secure_zero_slice(buf: &mut [u8])
```
Zero out a raw slice.

## Internal Functions

- `drop` (line 151)
- `deref` (line 158)
- `deref_mut` (line 162)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use aes_gcm::{`
- `use aes::Aes256;`
- `use cbc::Decryptor;`
- `use cbc::cipher::KeyIvInit;`
- `use cbc::cipher::BlockDecryptMut;`

## Full Source

```rust
//! # crowd — crypto.rs  (✅ C TIER — AES-GCM + zstd, pure crypto utility)
//!
//! Primitivas criptográficas del dropper.
//!
//! ## AES-GCM (primario — spec)
//! `aes_gcm_decrypt`: descifrado in-place compatible con el formato del spec.
//! Key 32B, nonce 12B, tag 16B al final del ciphertext.
//!
//! ## AES-256-CBC (legacy — para payloads pre-existentes)
//! `decrypt_payload`: backward-compat con el formato anterior (key+IV 16B).
//!
//! ## zstd decompression
//! `zstd_decompress`: descomprimir buffer post-decrypt.
//!
//! ## SecureZeroMemory
//! `secure_zero_memory`: write_volatile 0 en toda la región — compiler-proof.

#![allow(dead_code)]

use anyhow::{anyhow, Result};

// ── AES-GCM ───────────────────────────────────────────────────────────────────

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};

/// AES-256-GCM decrypt.
///
/// Formato del input: `nonce(12B) || ciphertext || tag(16B)`.
/// Compatible con el formato producido por donut con AES-GCM.
pub fn aes_gcm_decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(anyhow!("AES-GCM: input too short ({} bytes)", data.len()));
    }

    let nonce_bytes = &data[..12];
    let ciphertext  = &data[12..];             // includes tag at the end

    let k     = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let nonce  = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES-GCM decryption failed: {:?}", e))
}

/// AES-256-GCM decrypt with AAD (Additional Authenticated Data).
pub fn aes_gcm_decrypt_with_aad(data: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(anyhow!("AES-GCM+AAD: input too short ({} bytes)", data.len()));
    }

    let nonce_bytes = &data[..12];
    let ciphertext  = &data[12..];

    let k     = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let nonce  = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow!("AES-GCM+AAD decryption failed: {:?}", e))
}

// ── AES-256-CBC (legacy) ──────────────────────────────────────────────────────

use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::KeyIvInit;

type Aes256CbcDec = Decryptor<Aes256>;

/// AES-256-CBC decrypt (legacy format). Key 32B, IV 16B.
pub fn decrypt_payload(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let mut buf = data.to_vec();
    use cbc::cipher::BlockDecryptMut;
    let result = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map(|s| s.to_vec())
        .map_err(|e| anyhow!("AES-256-CBC decryption failed: {:?}", e));
    // Zero the intermediate buffer that held decrypted data regardless of outcome
    secure_zero_memory(&mut buf);
    result
}

// ── zstd ─────────────────────────────────────────────────────────────────────

/// Decompress a zstd stream.
/// `out_hint_mb`: expected output size hint in MB (0 = no hint, max 512MB enforced).
pub fn zstd_decompress(data: &[u8], out_hint_mb: usize) -> Result<Vec<u8>> {
    let capacity = if out_hint_mb > 0 {
        out_hint_mb * 1024 * 1024
    } else {
        data.len().saturating_mul(4).max(1024 * 1024)
    };

    let capacity = capacity.min(512 * 1024 * 1024);

    let mut out = Vec::with_capacity(capacity);
    zstd::stream::copy_decode(std::io::Cursor::new(data), &mut out)
        .map_err(|e| anyhow!("zstd decompress failed: {}", e))?;

    if out.len() > 512 * 1024 * 1024 {
        secure_zero_memory(&mut out);
        return Err(anyhow!("decompressed payload exceeds 512 MB safety limit"));
    }

    Ok(out)
}

/// Decompress a zstd stream and validate the output matches an expected size.
/// Returns an error if the decompressed size does not match `expected_bytes`.
/// Useful when the payload header specifies the original size and we need
/// to ensure integrity post-decompression.
pub fn zstd_decompress_validated(data: &[u8], expected_bytes: usize, out_hint_mb: usize) -> Result<Vec<u8>> {
    let out = zstd_decompress(data, out_hint_mb)?;
    if out.len() != expected_bytes {
        return Err(anyhow!(
            "zstd decompressed size mismatch: got {} bytes, expected {} bytes",
            out.len(), expected_bytes
        ));
    }
    Ok(out)
}

/// AES-GCM decrypt + zstd decompress in sequence.
/// This is the main Fase 1 step 07 entry point.
///
/// The intermediate decrypted buffer is securely zeroed after decompression
/// to avoid leaving sensitive plaintext in process memory.
pub fn decrypt_and_decompress(
    encrypted: &[u8],
    key:       &[u8; 32],
    out_hint_mb: usize,
) -> Result<Vec<u8>> {
    let mut decrypted = aes_gcm_decrypt(encrypted, key)?;
    let result = zstd_decompress(&decrypted, out_hint_mb);
    // Zero the intermediate decrypted buffer — it held sensitive plaintext
    secure_zero_memory(&mut decrypted);
    drop(decrypted);
    result
}

// ── SecureVec ─────────────────────────────────────────────────────────────────

/// A Vec<u8> that is zeroized on drop.
pub struct SecureVec(pub Vec<u8>);

impl Drop for SecureVec {
    fn drop(&mut self) {
        secure_zero_memory(&mut self.0);
    }
}

impl std::ops::Deref for SecureVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::ops::DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

// ── SecureZeroMemory ──────────────────────────────────────────────────────────

/// Zero out a buffer using `write_volatile` — prevents compiler elision.
/// Each byte is written individually to ensure all bytes are zeroed.
pub fn secure_zero_memory(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8) };
    }
    // Also zero any slack capacity
    let len = buf.len();
    let cap = buf.capacity();
    if cap > len {
        unsafe {
            let ptr = buf.as_mut_ptr().add(len);
            for i in 0..(cap - len) {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

/// Zero out a raw slice.
pub fn secure_zero_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8) };
    }
}

```