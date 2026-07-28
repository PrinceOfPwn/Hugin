# utils

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/veh/utils.rs` |
| **Lines** | 148 |
| **Cards** | T002-veh-gate |
| **Role** | VEH utilities |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 5 |

## Public API

### `get_nt_headers` `unsafe` (line 16)
```rust
pub unsafe fn get_nt_headers(base_addr: *mut u8) -> *mut ImageNtHeaders
```

### `ldr_module_info` `unsafe` (line 41)
```rust
pub unsafe fn ldr_module_info(module_hash: u32) -> (*mut u8, usize)
```
Finds and returns the base address and size of a module by its hash.

# Arguments
* `module_hash` - The hash of the module name to locate.

Returns a tuple with the base address and the size of the module or (null, 0) if not found.

### `dbj2_hash` (line 101)
```rust
pub fn dbj2_hash(buffer: &[u8]) -> u32
```
Computes the DJB2 hash for the given buffer

### `get_cstr_len` (line 125)
```rust
pub fn get_cstr_len(pointer: *const char) -> usize
```
Calculates the length of a C-style null-terminated string.

### `find_peb` (line 139)
```rust
pub fn find_peb() -> *mut PEB
```

## Internal Functions

- `hash_unicode_djb2` (unsafe) (line 82)

## Key Dependencies

- `use core::arch::asm;`
- `use core::ptr::null_mut;`
- `use super::def::{`

## Full Source

```rust
use core::arch::asm;
use core::ptr::null_mut;

use super::def::{
    ImageDosHeader, ImageNtHeaders, LoaderDataTableEntry, PebLoaderData, IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE, PEB,
};

/// Retrieves the NT headers from the base address of a module.
///
/// # Arguments
/// * `base_addr` - The base address of the module.
///
/// Returns a pointer to `ImageNtHeaders` or null if the headers are invalid.
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_nt_headers(base_addr: *mut u8) -> *mut ImageNtHeaders {
    let dos_header = base_addr as *mut ImageDosHeader;

    // Check if the DOS signature is valid (MZ)
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    // Calculate the address of NT headers
    let nt_headers = (base_addr as isize + (*dos_header).e_lfanew as isize) as *mut ImageNtHeaders;

    // Check if the NT signature is valid (PE\0\0)
    if (*nt_headers).signature != IMAGE_NT_SIGNATURE {
        return null_mut();
    }

    nt_headers
}

/// Finds and returns the base address and size of a module by its hash.
///
/// # Arguments
/// * `module_hash` - The hash of the module name to locate.
///
/// Returns a tuple with the base address and the size of the module or (null, 0) if not found.
pub unsafe fn ldr_module_info(module_hash: u32) -> (*mut u8, usize) {
    let peb = find_peb(); // Retrieve the PEB

    if peb.is_null() {
        return (null_mut(), 0);
    }

    let peb_ldr_data_ptr = (*peb).loader_data as *mut PebLoaderData;
    if peb_ldr_data_ptr.is_null() {
        return (null_mut(), 0);
    }

    // Stop iteration on the list sentinel instead of dereferencing it as a loader entry.
    let head = core::ptr::addr_of_mut!((*peb_ldr_data_ptr).in_load_order_module_list);
    let mut module_list = (*head).flink as *mut LoaderDataTableEntry;

    // Iterate through the list of loaded modules
    while !module_list.is_null() && module_list.cast() != head {
        let dll_buffer_ptr = (*module_list).base_dll_name.buffer;
        let dll_length = (*module_list).base_dll_name.length as usize;

        // Compare the hash of the DLL name with the provided hash
        if !dll_buffer_ptr.is_null() && module_hash == hash_unicode_djb2(dll_buffer_ptr, dll_length)
        {
            let dll_base = (*module_list).dll_base as *const ImageDosHeader;
            let nt_headers = (dll_base as *const u8).offset((*dll_base).e_lfanew as isize)
                as *const ImageNtHeaders;

            // Obtain the size of the module from the OptionalHeader's SizeOfImage
            let size_of_image = (*nt_headers).optional_header.size_of_image as usize;

            return ((*module_list).dll_base as _, size_of_image); // Return the base address and size of the module
        }

        // Move to the next module in the list
        module_list = (*module_list).in_load_order_links.flink as *mut LoaderDataTableEntry;
    }

    (null_mut(), 0)
}

unsafe fn hash_unicode_djb2(buffer: *const u16, length_bytes: usize) -> u32 {
    let mut hsh: u32 = 5381;
    let wide_len = length_bytes / core::mem::size_of::<u16>();
    let wide_slice = core::slice::from_raw_parts(buffer, wide_len);

    for &wide_char in wide_slice {
        let ascii_char = wide_char as u8;

        if ascii_char == 0 {
            continue;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + ascii_char.to_ascii_uppercase() as u32;
    }

    hsh
}

/// Computes the DJB2 hash for the given buffer
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];

        if cur == 0 {
            iter += 1;
            continue;
        }

        if cur >= ('a' as u8) {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    hsh
}

/// Calculates the length of a C-style null-terminated string.
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }

    (tmp - pointer as u64) as _
}

/// Finds and returns the Process Environment Block (PEB)
#[cfg(target_arch = "x86_64")]
pub fn find_peb() -> *mut PEB {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb_ptr
        );
    }
    peb_ptr
}

```