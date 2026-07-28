# wrappers

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/wrappers.rs` |
| **Lines** | 177 |
| **Cards** | T021-patterns |
| **Role** | NT API bindings via windows_targets::link! |

## Constants

- `PROCESS_CREATE_FLAGS_INHERIT_HANDLES`: `u32` = `0x0000_0004`
- `RTL_USER_PROC_PARAMS_NORMALIZED`: `u32` = `0x0000_0001`

## Types

### struct `PS_ATTRIBUTE_LIST` (line 75)

### struct `PS_ATTRIBUTE` (line 81)

### struct `RTL_USER_PROCESS_PARAMETERS` (line 95)

### struct `CURDIR` (line 138)

### struct `RTL_DRIVE_LETTER_CURDIR` (line 144)

### struct `STRING` (line 152)

### struct `LARGE_INTEGER_0` (line 167)

### struct `LARGE_INTEGER_0_0` (line 174)

## Public API

### `InitializeObjectAttributes` (line 54)
```rust
pub fn InitializeObjectAttributes(
```

## Key Dependencies

- `use windows_sys::{`
- `use windows_targets::link;`

## Full Source

```rust
#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::c_void;
use windows_sys::{
    Wdk::Foundation::OBJECT_ATTRIBUTES,
    Win32::Foundation::{HANDLE, UNICODE_STRING},
};
use windows_targets::link;

type NTSTATUS = i32;
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x0000_0004;
pub const RTL_USER_PROC_PARAMS_NORMALIZED: u32 = 0x0000_0001;

link!("ntdll.dll" "system" fn NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: *mut c_void, Buffer: *mut c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: *mut usize) -> NTSTATUS);
link!("ntdll.dll" "system" fn NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: *mut c_void, Buffer: *mut c_void, NumberOfBytesToRead: usize, NumberOfBytesRead: *mut usize) -> NTSTATUS);
link!("ntdll.dll" "system" fn RtlCreateProcessParametersEx(
    ProcessParameters: *mut *mut RTL_USER_PROCESS_PARAMETERS,
    ImagePathName: *mut UNICODE_STRING,
    DllPath: *mut UNICODE_STRING,
    CurrentDirectory: *mut UNICODE_STRING,
    CommandLine: *mut UNICODE_STRING,
    Environment: *mut c_void,
    WindowTitle: *mut UNICODE_STRING,
    DesktopInfo: *mut UNICODE_STRING,
    ShellInfo: *mut UNICODE_STRING,
    RuntimeData: *mut UNICODE_STRING,
    Flags: u32
) -> NTSTATUS);
link!("ntdll.dll" "system" fn NtCreateThreadEx(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    ProcessHandle: HANDLE,
    StartRoutine: *mut c_void,
    Argument: *mut c_void,
    CreateFlags: u32,
    ZeroBits: usize,
    StackSize: usize,
    MaximumStackSize: usize,
    AttributeList: *mut PS_ATTRIBUTE_LIST
) -> NTSTATUS);
link!("ntdll.dll" "system" fn NtCreateProcessEx(
    ProcessHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ParentProcess: HANDLE,
    Flags: u32,
    SectionHandle: HANDLE,
    DebugPort: HANDLE,
    TokenHandle: HANDLE,
    Reserved: u32
) -> NTSTATUS);

pub fn InitializeObjectAttributes(
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    root_directory: HANDLE,
    security_descriptor: *const c_void,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_directory,
        Attributes: attributes,
        ObjectName: object_name,
        SecurityDescriptor: security_descriptor as *const _,
        SecurityQualityOfService: std::ptr::null_mut(),
    }
}

pub const fn NT_SUCCESS(nt_status: NTSTATUS) -> bool {
    nt_status >= 0
}

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    TotalLength: usize,
    Attributes: [PS_ATTRIBUTE; 1],
}

#[repr(C)]
pub struct PS_ATTRIBUTE {
    Attribute: usize,
    Size: usize,
    u: PS_ATTRIBUTE_0,
    ReturnLength: *mut usize,
}

#[repr(C)]
pub union PS_ATTRIBUTE_0 {
    Value: usize,
    ValuePtr: *mut c_void,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: u32,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; 32],
    pub EnvironmentSize: usize,
    pub EnvironmentVersion: usize,
    pub PackageDependencyData: *mut c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectionDllName: UNICODE_STRING,
    pub HeapPartitionName: UNICODE_STRING,
    pub DefaultThreadpoolCpuSetMasks: *mut u64,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
    pub HeapMemoryTypeMask: u32,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    Handle: HANDLE,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    Flags: u16,
    Length: u16,
    TimeStamp: u32,
    pub DosPath: STRING,
}

#[repr(C)]
pub struct STRING {
    Length: u16,
    MaximumLength: u16,
    pub Buffer: *const i8,
}

#[repr(C)]
pub union LARGE_INTEGER {
    Anonymous: LARGE_INTEGER_0,
    u: LARGE_INTEGER_0_0,
    QuadPart: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LARGE_INTEGER_0 {
    LowPart: u32,
    HighPart: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LARGE_INTEGER_0_0 {
    LowPart: u32,
    HighPart: i32,
}

```