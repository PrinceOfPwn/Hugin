# mod

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/injection/mod.rs` |
| **Lines** | 6 |
| **Cards** | T007-process-injection |
| **Role** | Injection module |
| **Feature gates** | process_reflection, threadless |

## Full Source

```rust
#[cfg(feature = "process_reflection")]
#[path = "../experimental/injection/process_reflection.rs"]
pub mod process_reflection;
#[cfg(feature = "threadless")]
#[path = "../experimental/injection/threadless.rs"]
pub mod threadless;

```