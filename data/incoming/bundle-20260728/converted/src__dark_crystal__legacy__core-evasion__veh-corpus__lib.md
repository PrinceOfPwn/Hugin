# lib

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/legacy/core-evasion/veh-corpus/lib.rs` |
| **Lines** | 182 |
| **Cards** | T002-veh-gate |
| **Role** | VEH legacy corpus |
| **Unsafe blocks** | 6 |
| **Feature gates** | verbose_debug |

## Internal Functions

- `test_nt_create_user_process` (line 36)

## Macros

- `debug_println!` (macro_rules, line 170)
- `debug_println!` (macro_rules, line 180)

## Key Dependencies

- `use crate::debug_println;`
- `use crate::hooks::{destroy_hooks, initialize_hooks};`
- `use crate::syscall;`
- `use core::iter::once;`
- `use core::ptr::null_mut;`
- `use winapi::shared::basetsd::ULONG_PTR;`
- `use winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES, UNICODE_STRING};`
- `use winapi::um::handleapi::CloseHandle;`
- `use winapi::um::memoryapi::VirtualAlloc;`
- `use winapi::um::winnt::PROCESS_ALL_ACCESS;`
- `use ntapi::ntpsapi::{`
- `use ntapi::ntrtl::{`

## Full Source

```rust
pub mod def;
pub mod hooks;
pub mod syscall;
pub mod utils;

pub use crate::hooks::set_hw_bp;
pub use crate::syscall::get_ssn_by_name;
pub use crate::utils::dbj2_hash;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use crate::debug_println;
    use crate::hooks::{destroy_hooks, initialize_hooks};
    use crate::syscall;

    use core::iter::once;
    use core::ptr::null_mut;

    use winapi::shared::basetsd::ULONG_PTR;
    use winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES, UNICODE_STRING};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::VirtualAlloc;
    use winapi::um::winnt::PROCESS_ALL_ACCESS;

    use ntapi::ntpsapi::{
        PsCreateInitialState, PS_ATTRIBUTE, PS_ATTRIBUTE_IMAGE_NAME, PS_ATTRIBUTE_LIST,
        PS_CREATE_INFO,
    };
    use ntapi::ntrtl::{
        RtlCreateProcessParametersEx, RtlInitUnicodeString, RTL_USER_PROCESS_PARAMETERS,
    };

    #[test]
    fn test_nt_create_user_process() {
        println!("[*] Program Started");

        // Initialize hooks
        initialize_hooks();

        // Set up UNICODE_STRING for the image path
        let mut image_path: alloc::vec::Vec<u16> = "\\??\\C:\\Windows\\System32\\calc.exe"
            .encode_utf16()
            .chain(once(0))
            .collect();
        let mut nt_image_path: UNICODE_STRING = UNICODE_STRING {
            Length: (image_path.len() as u16 - 1) * 2,
            MaximumLength: image_path.len() as u16 * 2,
            Buffer: image_path.as_mut_ptr(),
        };

        unsafe { RtlInitUnicodeString(&mut nt_image_path, image_path.as_ptr()) };

        // Create the process parameters
        let mut process_parameters: *mut RTL_USER_PROCESS_PARAMETERS = null_mut();
        let status = unsafe {
            RtlCreateProcessParametersEx(
                &mut process_parameters,
                &mut nt_image_path,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                0x01,
            )
        };

        assert_eq!(status, 0, "Failed to create process parameters");

        // Initialize the PS_CREATE_INFO structure
        let mut create_info: PS_CREATE_INFO = unsafe { core::mem::zeroed() };
        create_info.Size = core::mem::size_of::<PS_CREATE_INFO>();
        create_info.State = PsCreateInitialState;

        // Calculate the correct size for the PS_ATTRIBUTE_LIST
        let attribute_list_size =
            core::mem::size_of::<PS_ATTRIBUTE_LIST>() + core::mem::size_of::<PS_ATTRIBUTE>();

        let attribute_list: *mut PS_ATTRIBUTE_LIST = unsafe {
            VirtualAlloc(
                null_mut(),
                attribute_list_size,
                winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
                winapi::um::winnt::PAGE_READWRITE,
            )
        } as *mut PS_ATTRIBUTE_LIST;

        assert!(
            !attribute_list.is_null(),
            "Failed to allocate memory for PS_ATTRIBUTE_LIST"
        );

        // Populate the PS_ATTRIBUTE_LIST
        unsafe {
            (*attribute_list).TotalLength = core::mem::size_of::<PS_ATTRIBUTE_LIST>();
            (*attribute_list).Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
            (*attribute_list).Attributes[0].Size = nt_image_path.Length as usize;
            (*attribute_list).Attributes[0].u.Value = nt_image_path.Buffer as ULONG_PTR;
        }

        let mut process_handle: HANDLE = null_mut();
        let mut thread_handle: HANDLE = null_mut();
        let desired_access = PROCESS_ALL_ACCESS;

        // Call NtCreateUserProcess
        let status = syscall!(
            "NtCreateUserProcess",
            OrgNtCreateUserProcess,
            &mut process_handle,
            &mut thread_handle,
            desired_access,
            desired_access,
            null_mut(),
            null_mut(),
            0,
            0,
            process_parameters,
            &mut create_info,
            attribute_list
        );

        assert_eq!(
            status, 0,
            "Failed to create process with NT STATUS: {:#X}",
            status
        );

        println!("[*] Process created successfully.");

        assert!(
            !process_handle.is_null(),
            "Process handle should not be null"
        );
        assert!(!thread_handle.is_null(), "Thread handle should not be null");

        // Clean up resources
        unsafe {
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
        }

        // Destroy hooks
        destroy_hooks();

        println!("[*] Program Ended");
    }

    pub type OrgNtCreateUserProcess = unsafe extern "system" fn(
        ProcessHandle: *mut HANDLE,
        ThreadHandle: *mut HANDLE,
        ProcessDesiredAccess: u32,
        ThreadDesiredAccess: u32,
        ProcessObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ThreadObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ProcessFlags: u32,
        ThreadFlags: u32,
        ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
        CreateInfo: *mut PS_CREATE_INFO,
        AttributeList: *mut PS_ATTRIBUTE_LIST,
    ) -> i32;
}

#[cfg(feature = "verbose_debug")]
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {{
        if crate::selection_config::verbose_debug() {
            println!($($arg)*);
        }
    }};
}

#[cfg(not(feature = "verbose_debug"))]
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {{}};
}

```