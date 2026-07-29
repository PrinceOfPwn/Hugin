# crypto

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/crypto.rs` |
| **Lines** | 90 |
| **Cards** | T020-crypto |
| **Role** | AES-256-GCM + zstd pipeline |
| **Unsafe blocks** | 4 |

## Types

### struct `SecureVec` (line 65)
Wrapper de Vec que hace zeroize automáticamente al hacer drop.

## Public API

### `decrypt_payload` (line 11)
```rust
pub fn decrypt_payload(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>>
```
Descifra un payload AES-256-CBC.

IMPORTANTE: El Vec<u8> retornado CONTIENE EL PAYLOAD DESCIFRADO.
Debe ser pasado por `secure_zero_memory()` después de su uso,
o idealmente usar SecureVec.

### `secure_zero_memory` (line 38)
```rust
pub fn secure_zero_memory(buf: &mut [u8])
```

## Internal Functions

- `drop` (line 68)
- `deref` (line 75)
- `deref_mut` (line 81)
- `from` (line 87)

## Key Dependencies

- `use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};`
- `use anyhow::{anyhow, Result};`

## Full Source

```rust
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Descifra un payload AES-256-CBC.
///
/// IMPORTANTE: El Vec<u8> retornado CONTIENE EL PAYLOAD DESCIFRADO.
/// Debe ser pasado por `secure_zero_memory()` después de su uso,
/// o idealmente usar SecureVec.
pub fn decrypt_payload(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if encrypted.is_empty() {
        return Err(anyhow!("Payload cifrado vacío"));
    }

    let key: &[u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("AES key debe tener exactamente 32 bytes"))?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| anyhow!("AES IV debe tener exactamente 16 bytes"))?;

    let mut buf = encrypted.to_vec();
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());

    let decrypted_len = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow!("Error descifrando payload: {:?}", e))?
        .len();

    buf.truncate(decrypted_len);
    Ok(buf)
}

/// Borra seguramente un buffer de memoria.
/// Usa `write_volatile` para que el compilador NO optimice fuera el borrado.
#[inline(never)]
pub fn secure_zero_memory(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    // Doble pasada para asegurar
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0xFF);
        }
    }
    // Tercera pasada con patrón aleatorio
    for (i, b) in buf.iter_mut().enumerate() {
        unsafe {
            std::ptr::write_volatile(b, (i % 256) as u8);
        }
    }
    // Pasada final con ceros
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
}

/// Wrapper de Vec que hace zeroize automáticamente al hacer drop.
pub struct SecureVec(pub Vec<u8>);

impl Drop for SecureVec {
    fn drop(&mut self) {
        secure_zero_memory(&mut self.0);
    }
}

impl std::ops::Deref for SecureVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for SecureVec {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

```