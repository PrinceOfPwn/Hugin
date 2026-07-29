# mod

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/evasion/veh/mod.rs` |
| **Lines** | 16 |
| **Cards** | T002-veh-gate |
| **Role** | VEH syscall gate module |

## Public API

### `initialize_veh` (line 8)
```rust
pub fn initialize_veh() -> anyhow::Result<()>
```
Inicializa el sistema VEH para interceptar syscalls.
Debe llamarse UNA VEZ al inicio del proceso, ANTES de cualquier syscall.

### `destroy_veh` (line 14)
```rust
pub fn destroy_veh()
```
Limpia los hooks VEH. Llamar al final si es necesario.

## Full Source

```rust
pub mod def;
pub mod hooks;
pub mod syscall;
pub mod utils;

/// Inicializa el sistema VEH para interceptar syscalls.
/// Debe llamarse UNA VEZ al inicio del proceso, ANTES de cualquier syscall.
pub fn initialize_veh() -> anyhow::Result<()> {
    hooks::initialize_hooks();
    Ok(())
}

/// Limpia los hooks VEH. Llamar al final si es necesario.
pub fn destroy_veh() {
    hooks::destroy_hooks();
}

```