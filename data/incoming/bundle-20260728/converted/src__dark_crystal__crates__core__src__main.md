# main

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/main.rs` |
| **Lines** | 5 |
| **Cards** | T023-client-capabilities |
| **Role** | Entry point, FSM bootstrap |

## Internal Functions

- `main` (line 3)

## Full Source

```rust
#![cfg_attr(not(feature = "verbose_debug"), windows_subsystem = "windows")]

fn main() -> anyhow::Result<()> {
    crystalclearlib::runner::run()
}

```