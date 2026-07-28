# sys_trace

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/legacy/core-src-dead/sys_trace.rs` |
| **Lines** | 16 |
| **Cards** | T004-syscall-dispatch |
| **Role** | Syscall tracing (dead code) |
| **Feature gates** | syscall_trace |

## Macros

- `trace_syscall!` (macro_rules, line 2)

## Full Source

```rust
#[macro_export]
macro_rules! trace_syscall {
    ($($arg:tt)*) => {
        #[cfg(feature = "syscall_trace")]
        {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("syscall_trace.log")
            {
                use std::io::Write;
                let _ = writeln!(file, $($arg)*);
            }
        }
    };
}

```