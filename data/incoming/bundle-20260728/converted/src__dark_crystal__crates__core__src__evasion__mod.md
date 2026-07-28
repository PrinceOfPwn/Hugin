# mod

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/evasion/mod.rs` |
| **Lines** | 10 |
| **Cards** | T009-edr-evasion |
| **Role** | Evasion module |
| **Feature gates** | advanced_stack, byovd, veh_syscalls |

## Full Source

```rust
#[cfg(feature = "advanced_stack")]
#[path = "../experimental/evasion/advanced_stack.rs"]
pub mod advanced_stack;
#[cfg(feature = "byovd")]
#[path = "../experimental/evasion/byovd/mod.rs"]
pub mod byovd;
pub mod stack_spoof;
#[cfg(feature = "veh_syscalls")]
#[path = "../experimental/evasion/veh/mod.rs"]
pub mod veh;

```