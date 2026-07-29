---
id: T-018
name: Edo Tensei (Polymorphic Resurrection Engine)
category: persistence
tier: S
mitre: T1480.001
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-017, T-022, T-021]
enables: [T-007, T-016, T-005, T-003, T-002, T-001]
vault_references:
  - dark_crystal/crowd/src/edo_tensei.rs
implements:
  - file: dark_crystal/crowd/src/edo_tensei.rs
    key_functions:
      - is_active
      - apply_resurrection
      - apply_generation
      - parse_injection_method
      - apply_evasion_overrides
      - apply_syscall_backend
      - read_generation
      - read_gen_ntfs_ea
      - read_gen_registry
      - read_gen_registry_inner
      - read_gen_env_var
      - read_gen_ads
      - parse_gen_bytes
      - write_generation
      - write_gen_ntfs_ea
      - write_gen_registry
      - write_gen_registry_inner
      - write_gen_env_var
      - write_env_var_persistent
      - write_gen_ads
    key_structs:
      - ChainConfig (imported from crate::chain)
      - InjectionMethod (enum, imported from crate::chain)
      - PersistConfig (imported from crate::persist)
    key_constants:
      - SOUL_EA_NAME
      - SOUL_REG_SUBKEY
      - SOUL_REG_VALUE
      - SOUL_ENV_VAR
      - SOUL_ADS_TARGET
      - SOUL_ADS_STREAM
      - EDO_ENABLED
      - EDO_MAX_GENERATIONS
      - EDO_SOUL_STORAGE
      - EDO_CHAIN_LEN
      - EDO_INJECTION
      - EDO_EVASION
      - EDO_SYSCALL_BACKEND
      - EDO_PERSIST_METHOD
      - EDO_SLEEP_MS
    lines_of_interest:
      - "L1-L25: module docstring describing generation-cycling model and soul storage backends"
      - "L29-L46: re-export of compile-time constants from crate::payload_cfg"
      - "L49-L55: soul storage magic constants (GUID, EA name, ADS stream name, env var name)"
      - "L60-L64: is_active() gate — short-circuits when EDO_ENABLED=false or EDO_CHAIN_LEN=0"
      - "L66-L88: apply_resurrection() — read generation, apply, advance, persist"
      - "L91-L107: apply_generation() — populates ChainConfig fields from parallel arrays"
      - "L110-L133: parse_injection_method() — string→enum mapping for 18 injection variants"
      - "L138-L178: apply_evasion_overrides() — reset-all-then-enable allow-list semantics"
      - "L181-L190: apply_syscall_backend() — selects recycled/veh_gate/hells_gate/direct"
      - "L195-L204: read_generation() dispatch on EDO_SOUL_STORAGE string"
      - "L207-L213: read_gen_ntfs_ea() — delegates to crate::persist::ntfs_ea::read_dropper_ea()"
      - "L216-L253: read_gen_registry_inner() — unsafe FFI RegOpenKeyExW+RegQueryValueExW"
      - "L271-L282: parse_gen_bytes() — accepts 4-byte LE u32 OR ASCII decimal string"
      - "L349-L356: write_gen_env_var() — hybrid: std::env::set_var + persistent registry write"
      - "L359-L386: write_env_var_persistent() — writes REG_SZ to HKCU\\Environment for cross-process survival"
      - "L170-L173: amsi_hbp no-op (always-on via DR0, not toggleable per generation)"
      - "L175: stack_spoof no-op (always-on via hardcoded spoof_caller in chain.rs)"
      - "L177: ppid evasion ID sets cfg.ppid_parent = Some(0) — bug: PID 0 is System Idle Process"
min_windows: Win7
needs_admin: conditional
tags: [polymorphism, resurrection, generation-cycling, soul-storage, allow-list-evasion, behavior-fingerprint]
---

# Edo Tensei — Operator Playbook

## TL;DR
Edo Tensei reads a 4-byte "generation index" from one of four soul-storage backends (NTFS EA, registry, env var, or NTFS ADS), uses it to index into compile-time parallel arrays of injection methods / evasion sets / syscall backends / persistence layers / sleep durations, mutates a `ChainConfig` accordingly, then advances and persists the next index for the next resurrection. It is the behavior-fingerprinting layer that sits on top of T-017 (Five-Layer Persistence): when the persistence monitor restarts the implant after kill, the new generation produces a different IOC footprint. Worth the complexity only when you expect the target SOC to baseline process behavior across executions.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `dark_crystal/crowd/src/edo_tensei.rs` | Single self-contained module: generation index I/O across 4 backends + ChainConfig mutation | `is_active()`, `apply_resurrection(&mut ChainConfig) -> u32`, `parse_injection_method(&str) -> InjectionMethod` | ~12K |

The module is intentionally monolithic — no submodule split for the four soul backends — because each backend is short and the operator wants to read all I/O paths in one file.

## How It Works

1. **Activation gate (L60-L64)**: `is_active()` returns `EDO_ENABLED && EDO_CHAIN_LEN > 0`. Both flags come from `crate::payload_cfg` (compile-time constants injected by `crowd_builder.py`). If the build was compiled without Edo Tensei or with `EDO_CHAIN_LEN=0`, the module is a no-op. The caller in `main.rs` (FSM bootstrap) is expected to check this before calling `apply_resurrection`.

2. **Read generation index (L66, L195-L204)**: `apply_resurrection()` calls `read_generation()`, which dispatches on the compile-time string `EDO_SOUL_STORAGE`:
   - `"ntfs_ea"` → `read_gen_ntfs_ea()` → `crate::persist::ntfs_ea::read_dropper_ea()` (T-017 dependency)
   - `"registry"` → `read_gen_registry()` → unsafe `read_gen_registry_inner()` → `RegOpenKeyExW(HKEY_CURRENT_USER, "Software\\Classes\\CLSID\\{b4bab081-ef08-11e3-848d-b8e856428d4f}\\Config", ..., KEY_READ)` then `RegQueryValueExW` for `REG_DWORD` "Generation"
   - `"env_var"` → `read_gen_env_var()` → `std::env::var("CROWD_GEN").parse::<u32>()` (returns 0 on missing/parse failure)
   - `"ads"` → `read_gen_ads()` → `std::fs::read("C:\\Windows\\System32\\en-US\\kernel32.dll.mui:CrowdGen")` then `parse_gen_bytes()`

3. **Generation wrap (L68)**: `idx = (gen as usize) % EDO_CHAIN_LEN`. If the persisted generation counter exceeds the chain length (e.g., operator bumps `EDO_MAX_GENERATIONS` across builds), this is a safe wrap-around. The modulo-then-index pattern lets the soul-storage value be unbounded while the chain length is fixed.

4. **Apply technique stack (L70 → L91-L107)**: `apply_generation(cfg, idx)` reads five parallel arrays at `[idx]`:
   - `EDO_INJECTION[idx]` → `parse_injection_method()` → `cfg.injection_method`
   - `EDO_SLEEP_MS[idx]` → `cfg.sleep_ms` (only if > 0; preserves default if 0)
   - `EDO_PERSIST_METHOD[idx]` → forces `cfg.persist = true` and sets `cfg.persist_cfg.get_or_insert_with(PersistConfig::default).methods = vec![persist_method.to_string()]`
   - `EDO_EVASION[idx]` → `apply_evasion_overrides()` (comma-separated ID list)
   - `EDO_SYSCALL_BACKEND[idx]` → `apply_syscall_backend()` (mutually exclusive `cfg.veh_syscalls` / `cfg.hells_gate` flags)

5. **Evasion allow-list (L138-L178)**: `apply_evasion_overrides()` first **resets all 11 toggleable evasion flags to false** (`patch_etw`, `anti_vm`, `self_delete`, `stomp_own_header`, `peb_unlink`, `block_handle`, `use_threadless`, `amsi_page_guard`, `hells_gate`, `veh_syscalls`, `byovd_enabled`), then enables only the IDs that appear in the CSV. This is explicit-allow-list semantics — forgetting to list an evasion in a generation's CSV disables it for that generation. Several IDs are **no-ops** (see Edge Cases): `amsi_hbp` (DR0 hardware breakpoint, always on), `stack_spoof` (hardcoded in `chain.rs`), `proxy_dll`/`hypnosis`/`ki_step_over` (injection-mode techniques, not runtime toggles), `arg_spoof` (driven by `decoy_args`/`real_args`), `sleep` (controlled by `EDO_SLEEP_MS` array), `block_dll`/`policy` (applied via PPID setup at process creation).

6. **Syscall backend selection (L181-L190)**: `apply_syscall_backend()` is a 4-way match:
   - `"recycled"` → `veh_syscalls=false; hells_gate=false` (routes to T-001 RecycledGate default)
   - `"veh_gate"` → `veh_syscalls=true; hells_gate=false` (routes to T-003 VEH Gate via HW breakpoint)
   - `"hells_gate"` → `hells_gate=true; veh_syscalls=false` (routes to T-002 SSN resolution cascade)
   - `"direct"` → both false (direct syscalls)

7. **Advance generation (L73-L74)**: `next_gen = if gen + 1 >= EDO_MAX_GENERATIONS { 0 } else { gen + 1 }`. This is the wrap-around for the long-running counter. So if `EDO_MAX_GENERATIONS=12` and `EDO_CHAIN_LEN=3`, the generations seen are 0→1→2→0→1→2→0→1→2→0→1→2→0 (every 4th resurrection wraps). This decouples the IOC fingerprint cycle (`EDO_CHAIN_LEN`) from the absolute generation counter (`EDO_MAX_GENERATIONS`).

8. **Persist next generation (L75 → L287-L386)**: `write_generation(next_gen)` dispatches the same way as read:
   - `ntfs_ea` → `crate::persist::ntfs_ea::store_dropper_ea(&bytes)` (4-byte LE)
   - `registry` → unsafe `write_gen_registry_inner()` → `RegCreateKeyExW` + `RegSetValueExW(REG_DWORD, 4 bytes)`
   - `env_var` → `std::env::set_var("CROWD_GEN", ...)` **AND** `write_env_var_persistent()` which writes `REG_SZ` to `HKCU\Environment` — this is a hybrid backend: env var for in-process access, registry for cross-process survival
   - `ads` → `std::fs::write("C:\\Windows\\System32\\en-US\\kernel32.dll.mui:CrowdGen", gen.to_le_bytes())`

9. **Return value (L86)**: `apply_resurrection()` returns the generation index that was *applied* (not the next one). Callers use this for logging via `crate::mega_dbg!` when `megadebug` feature is enabled.

## Code Architecture

### Call Graph
```
main.rs (FSM bootstrap)
  └─ edo_tensei::is_active()                            [gate]
  └─ edo_tensei::apply_resurrection(&mut ChainConfig)
       ├─ read_generation()
       │    ├─ read_gen_ntfs_ea()    → crate::persist::ntfs_ea::read_dropper_ea()   [T-017]
       │    ├─ read_gen_registry()   → unsafe read_gen_registry_inner()  [winapi FFI]
       │    ├─ read_gen_env_var()    → std::env::var
       │    └─ read_gen_ads()        → std::fs::read + parse_gen_bytes()
       ├─ apply_generation(cfg, idx)
       │    ├─ parse_injection_method()           → mutates cfg.injection_method  [→ T-007 dispatch]
       │    ├─ apply_evasion_overrides()           → mutates 11 cfg.evasion_* flags [→ T-016 dispatch]
       │    └─ apply_syscall_backend()            → mutates cfg.veh_syscalls/hells_gate [→ T-001/T-002/T-003]
       └─ write_generation(next_gen)
            ├─ write_gen_ntfs_ea()  → crate::persist::ntfs_ea::store_dropper_ea()   [T-017]
            ├─ write_gen_registry() → unsafe write_gen_registry_inner()  [winapi FFI]
            ├─ write_gen_env_var()  → std::env::set_var + unsafe write_env_var_persistent() [hybrid]
            └─ write_gen_ads()     → std::fs::write
```

### Data Flow
- **Input**: `&mut ChainConfig` (caller-owned) + 4-byte generation index from soul storage
- **Output**: mutated `ChainConfig` + persisted `next_gen` written back to soul storage
- **Side effects**: NTFS EA mutation, registry mutation, env var mutation, ADS mutation (depending on backend)

### Type Hierarchy
- `ChainConfig` is owned by `crate::chain` (T-022 architecture) and is the central execution plan struct. Edo Tensei is a mutator pattern — it does not own `ChainConfig`, it just patches fields.
- `InjectionMethod` enum (imported from `crate::chain`) has 17 variants reachable from `parse_injection_method()`: `Auto`, `EarlyBird`, `EarlyBirdPpid`, `Hypnosis`, `DirtyVanity`, `Herpaderping`, `Phantom`, `ModuleStomp`, `ProxyDll`, `KiStepOver`, `EarlyCascade`, `MappingInject`, `WaitingThreadHijack`, `NtCreateProcess`, `ReflectivePe`, `PoolParty`, `Overload`.

### Feature Gates
- `#[cfg(feature = "megadebug")]` guards every `crate::mega_dbg!()` call. In release builds these are compiled out, so the module emits zero debug strings.
- `#[allow(dead_code)]` at module level — many functions are only called when a specific `EDO_SOUL_STORAGE` backend is selected at compile time, so unused ones would normally warn.

## Operational Profile

### When to Use
- **Target SOC does behavior baselining** across executions of the same binary (e.g., EDR rule "crowd.exe spawned by services.exe 5x in 30min → alert"). Generation cycling defeats fingerprint rules.
- **Engagement window ≥ 4 hours** — you need at least 2 resurrections to see the polymorphism benefit. Shorter engagements don't justify the soul-storage footprint.
- **Persistence layer is already installed (T-017)** — Edo Tensei is meaningless without a monitor that respawns the process.
- **You can tolerate a small IOCs surface increase** in exchange for behavioral polymorphism (each generation leaves registry/ADS/EA traces).

### When NOT to Use
- **One-shot drops / initial access** — there's no resurrection to cycle, so the polymorphism is wasted weight.
- **Memory-constrained implants** — the parallel arrays and backend dispatch add ~4-8KB to .rdata.
- **Target uses kernel-level ETW-TI on RegOpenKeyExW for HKCU** — the registry soul backend will trip telemetry on every resurrection. Prefer `ntfs_ea` or `ads` backends in that environment.
- **Non-English Windows hosts with the `ads` or `ntfs_ea` backends** — `SOUL_ADS_TARGET = C:\Windows\System32\en-US\kernel32.dll.mui` will not exist on localized systems.

### Kill Chain Position
```
T-017 (Five-Layer Persistence — phantom_restart monitor)
  ↓ respawn trigger
T-018 (Edo Tensei — read generation + apply stack)
  ↓ mutates ChainConfig
T-022 (Architecture — FSM bootstrap reads patched ChainConfig)
  ↓ dispatches to
T-007 (Injection method per gen)
T-016 (Evasion set per gen)
T-001/T-002/T-003 (Syscall backend per gen)
T-005 (Sleep duration per gen)
T-017 (Persist method per gen)
  ↓ implant runs
  ↓ killed/crashes
  ↑ loops back to T-017
```

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` Blocks

1. **`read_gen_registry_inner()` (unsafe fn)** — Lines ~216-253. Calls `winapi::um::winreg::RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey)`. Returns 0 if `status != 0 || hkey.is_null()`. Then `RegQueryValueExW` with `data_type` validation (must be `REG_DWORD`) — this is the right pattern, prevents type-confusion attacks where a maliciously-set value of REG_SZ could be reinterpreted. `RegCloseKey(hkey)` always called (no RAII guard, manual cleanup).

2. **`write_gen_registry_inner(gen: u32)` (unsafe fn)** — Lines ~306-346. `RegCreateKeyExW` with `KEY_WRITE` and `null_mut()` for `lpClass` / `lpSecurityAttributes`. Sets `REG_DWORD` 4-byte value. `disposition` is captured but unused — could indicate whether the key was created vs opened, useful for first-run detection (operator TODO).

3. **`write_env_var_persistent(gen: u32)` (unsafe fn)** — Lines ~359-386. Opens `HKCU\Environment` with `KEY_WRITE`, writes `REG_SZ` UTF-16 wide string. Byte size calculation: `(value_data.len() * 2) as u32` — correct for UTF-16 including null terminator (because `OsStr::encode_wide().chain(Some(0))` already appended the null). This is the cross-process survival mechanism for the `env_var` backend — env vars in the process environment block don't survive process death, so the registry acts as a backing store.

### FFI Patterns
- All FFI uses the `winapi` crate (not `windows-sys` or `windows`). This is the older ecosystem.
- Wide-string construction is uniform: `OsStr::new(...).encode_wide().chain(Some(0)).collect::<Vec<u16>>()` — null-terminated UTF-16. Used 6 times in this file.
- HKEY handle management: raw `winapi::shared::minwindef::HKEY` pointer, `null_mut()` for invalid, `RegCloseKey()` for cleanup. **No Drop guard** — if a panic occurs between open and close, the handle leaks. Operator-modification candidate: wrap in a `HKeyGuard` RAII struct.
- `data.as_ptr()` for byte buffers: `data.as_ptr()` (4-byte u8 slice) in `RegSetValueExW` — type-erased through `*const u8`. The cast `data as *mut u32 as *mut u8` in `read_gen_registry_inner` is the inverse for reads.

### Initialization Patterns
- No `OnceLock` or `LazyCell` — the module is stateless between calls except for the persisted generation in soul storage.
- Compile-time constants `EDO_*` are imported via `pub use crate::payload_cfg::*` — these are injected by `crowd_builder.py` as `pub const` items (probably `&[&str]` for the parallel arrays). They live in `.rdata` and cannot be patched at runtime without write access to that section.

### Memory Layout
- `parse_gen_bytes()` (L271-L282) handles two encodings:
  - 4-byte LE u32 (binary storage — used by `ntfs_ea` and `ads` backends)
  - ASCII decimal string (human-readable storage — used by `env_var` and any manually-inspected registry value)
- This dual encoding is intentional — operators can manually set the generation from PowerShell (`Set-ItemProperty ... -Value "2"` as REG_SZ) or from a binary tool.

### Syscall Numbers
- Not applicable — Edo Tensei makes no direct syscalls. The `apply_syscall_backend()` function only flips boolean flags that downstream modules consume.

### Error Handling
- **Read path**: every `read_gen_*()` returns `0` on any failure (file missing, registry key missing, parse error, FFI error). This is fail-safe — the implant runs with generation 0 (the "default" stack).
- **Write path**: every `write_gen_*()` silently ignores errors via `let _ = ...` or bare FFI calls without status checks. A failed write means the *next* resurrection reads the *current* generation — the implant re-runs the same stack. This is **acceptable for OPSEC** (no crash, no panic) but means the operator can't tell from telemetry whether the cycle is advancing.
- The `read_gen_registry_inner` status check `if status != 0 || hkey.is_null()` is the only path that distinguishes "key doesn't exist" from "value doesn't exist" — and even then it just returns 0.

## Cross-References Found in Code

- `edo_tensei.rs:apply_resurrection()` → calls **T-017** (Five-Layer Persistence) via `crate::persist::ntfs_ea::{read_dropper_ea, store_dropper_ea}` for the `ntfs_ea` soul backend; relies on T-017's `phantom_restart` monitor to respawn the process in the first place
- `edo_tensei.rs:apply_generation()` → mutates `ChainConfig.injection_method` (one of 17 variants) consumed by **T-007** (Process Injection) dispatch in `crate::chain`
- `edo_tensei.rs:apply_generation()` → mutates `ChainConfig.persist_cfg` (PersistConfig) consumed by **T-017** dispatch — Edo Tensei overrides which persistence layer the *new* incarnation installs, so the implant's persistence fingerprint can rotate across resurrections
- `edo_tensei.rs:apply_evasion_overrides()` → mutates `patch_etw`, `anti_vm`, `self_delete`, `stomp_own_header`, `peb_unlink`, `block_handle`, `use_threadless`, `amsi_page_guard`, `hells_gate`, `veh_syscalls`, `byovd_enabled`, `iat_camo_profile`, `hammer_seed`, `ppid_parent` — these are consumed by **T-016** (EDR Evasion Suite) modules
- `edo_tensei.rs:apply_syscall_backend()` → flips `cfg.veh_syscalls` (routes to **T-002** VEH Gate) and `cfg.hells_gate` (routes to **T-003** Hells/Halos/Tartarus Gate) — both-off state routes to **T-001** RecycledGate (default)
- `edo_tensei.rs:apply_generation()` → mutates `cfg.sleep_ms` consumed by **T-005** (Ekko ROP Sleep) dispatcher in `crate::sleep`
- `edo_tensei.rs:apply_evasion_overrides()` `"ppid"` ID → sets `cfg.ppid_parent = Some(0)` — consumed by **T-015** (PPID Spoofing) module in `crate::ppid`
- `edo_tensei.rs` imports `crate::chain::{ChainConfig, InjectionMethod}` — T-022 architecture (chain.rs)
- `edo_tensei.rs` imports `crate::payload_cfg::*` — T-021 patterns (payload_cfg.rs)
- `edo_tensei.rs:apply_evasion_overrides()` `"stack_spoof"` ID comment → references hardcoded `spoof_caller()` in `chain.rs` (**T-016** stack spoofing is process-wide, not generation-aware)

## Edge Cases & Failure Modes

1. **`env_var` backend cross-process survival is broken**
   - **Path**: `read_gen_env_var()` only calls `std::env::var("CROWD_GEN")`. If the parent process was killed before spawning the resurrection, the env var doesn't exist in the new process's environment block — *unless* the new process was started by a shell that read `HKCU\Environment` after `WM_SETTINGCHANGE` broadcast. `write_gen_env_var()` writes to both `std::env` AND `HKCU\Environment`, but `read_gen_env_var()` only reads `std::env`. **Asymmetric.**
   - **Symptom**: After a kill, the new process reads generation 0 (env var not inherited) and the cycle resets silently.
   - **Workaround**: Either implement `read_gen_env_var()` to also check `HKCU\Environment` as fallback, or just use the `registry` backend directly. The hybrid was probably intended to provide an env-var-fast-path with registry-persistence fallback, but the read side never reads the fallback.

2. **`ppid` evasion ID sets `cfg.ppid_parent = Some(0)`**
   - **Path**: `apply_evasion_overrides` `"ppid" => cfg.ppid_parent = Some(0)`.
   - **Symptom**: PID 0 is the System Idle Process. `OpenProcess(PROCESS_CREATE_PROCESS, ...)` on PID 0 returns `STATUS_ACCESS_DENIED` for non-System callers. PPID spoofing silently fails; the spawn falls back to default parent.

3. **Non-English Windows breaks `ads` and `ntfs_ea` backends**
   - **Path**: `SOUL_ADS_TARGET = "C:\\Windows\\System32\\en-US\\kernel32.dll.mui"`. On `de-DE` Windows this path doesn't exist; `std::fs::read` returns `Err`.
   - **Symptom**: `read_gen_ads()` returns 0 on every resurrection. The implant always runs generation 0.
   - **Workaround**: At build time, set `EDO_SOUL_STORAGE="registry"` for international targets, or use `ntfs_ea` with a path-agnostic target (e.g., the user's own `%TEMP%`).

4. **`amsi_hbp` cannot be toggled off per generation**
   - **Path**: `apply_evasion_overrides` `"amsi_hbp" => { /* always active via DR0 */ }` — comment is explicit.
   - **Symptom**: AMSI HBP bypass (T-016) is installed on DR0 hardware breakpoint on every generation. If a generation wants to look AMSI-active for OPSEC reasons, it can't.
   - **Workaround**: None from Edo Tensei — would require restructuring `amsi_hbp.rs` to gate on `cfg.amsi_hbp_enabled` flag (which doesn't exist).

5. **`stack_spoof` is always on, ignoring CSV**
   - **Path**: `"stack_spoof" => { /* always active — hardcoded spoof_caller() in chain.rs */ }`.
   - **Symptom**: Operator listing `"stack_spoof"` in a generation's evasion CSV has no effect — it's on for every generation. The CSV is misleading documentation.
   - **Workaround**: Don't list it. The CSV-only-toggle is a documentation bug.

6. **Write path silently drops errors**
   - **Path**: `let _ = crate::persist::ntfs_ea::store_dropper_ea(&bytes);` — return value discarded.
   - **Symptom**: If `ntfs_ea` write fails (e.g., ACL changed mid-engagement), the next resurrection reads the same generation. No log, no fallback. The implant runs the *same* stack indefinitely — defeats the polymorphism purpose silently.
   - **Workaround**: Add `#[cfg(feature="megadebug")]` logging on write failure.

7. **`EDO_MAX_GENERATIONS` vs `EDO_CHAIN_LEN` confusion**
   - **Path**: `apply_resurrection` computes `idx = gen % EDO_CHAIN_LEN` but writes back `next_gen = (gen + 1 >= EDO_MAX_GENERATIONS) ? 0 : gen + 1`. If operator sets `EDO_MAX_GENERATIONS=4` and `EDO_CHAIN_LEN=3`, the cycle is 0,1,2,0,1,2,3→0 — but `gen=3` would compute `idx = 3 % 3 = 0`, so generations 0 and 3 produce identical stacks. The polymorphism benefit is lost.
   - **Workaround**: Always set `EDO_MAX_GENERATIONS` to a multiple of `EDO_CHAIN_LEN`, or just set them equal.

## OPSEC Notes

**Artifacts left by each soul backend**:
- `ntfs_ea`: EA named `CrowdEdoGenIdx` on `kernel32.dll.mui`. Detectable with `fsutil usn readjournal` or EA-enumeration tools. Survives process kill. Hard to remove (EA APIs are obscure).
- `registry`: `HKCU\Software\Classes\CLSID\{b4bab081-ef08-11e3-848d-b8e856428d4f}\Config\Generation` REG_DWORD. **Visible to any registry-monitoring EDR** (sysmon RegistryEvent). The GUID `b4bab081-...` looks like a COM CLSID, providing some camouflage, but `Config\Generation` subkey naming is suspicious.
- `env_var`: `CROWD_GEN` env var + `HKCU\Environment\CROWD_GEN` REG_SZ. Env var is visible via `procmon -e PROCESS_START` events; HKCU\Environment writes fire sysmon RegistryEvent.
- `ads`: `kernel32.dll.mui:CrowdGen` — ADS on a system file. ADS enumeration (`dir /r`, sysmon FileCreateStreamHash) will flag this immediately.

**Stealth ranking of backends** (best→worst): `ntfs_ea` > `ads` (hidden in plain sight, requires explicit ADS scan) > `registry` (GUID camouflage helps) > `env_var` (most visible).

**Cleanup functions**: None. Edo Tensei has no uninstall path — operators must manually clear soul storage on engagement end. 

**Detection surface from the apply path**: The 17 `InjectionMethod` variants, 11 evasion flags, and 4 syscall backends produce 17 × 2^11 × 4 = 139,264 distinct behavioral profiles. For a chain of length 3, that's 3 profiles seen in sequence — enough to defeat most static fingerprint rules but not enough for ML-based sequence analysis.

## Reusable Patterns

### Pattern: Compile-time Parallel Arrays with Runtime Dispatch
- **Use when**: You need a small bounded set of mutually-exclusive runtime configurations selected by an index known only at runtime, with values known at compile time.
- **Code ref**: `edo_tensei.rs:L29-L46` (constants) + `L91-L107` (apply_generation)
- **How**: Declare `pub const EDO_INJECTION: &[&str] = &["threadless", "early_bird", ...];` in `payload_cfg.rs`, re-export via `pub use`. At runtime, `EDO_INJECTION[idx]` indexes by generation. The compile-time nature means no allocation, no runtime parsing, no string-table indirection — the values are baked into `.rodata`.

### Pattern: Allow-List Evasion Override
- **Use when**: You have a struct with many boolean flag fields and want to set exactly a subset to `true` based on a CSV string, with everything else going to `false`.
- **Code ref**: `edo_tensei.rs:apply_evasion_overrides` (L138-L178)
- **How**: First line `cfg.patch_etw = false; ...` resets all 11 flags, then a `for id in ids { match id { "etw" => cfg.patch_etw = true, ... } }`. This is `O(N)` in flag count, but more importantly it's *explicit* — the operator authoring the CSV can never accidentally inherit a default-on state from the prior generation. Compare with deny-list (set listed flags to false, leave others), which is fragile.

### Pattern: Hybrid Storage Backend (env var + registry)
- **Use when**: You want a fast in-process read with cross-process survival.
- **Code ref**: `edo_tensei.rs:write_gen_env_var` (L349-L356) + `write_env_var_persistent` (L359-L386)
- **How**: On write: `std::env::set_var(name, value)` for in-process access + `RegSetValueExW(HKCU\Environment, ...)` for child-process inheritance via `WM_SETTINGCHANGE`. Note: the read side (`read_gen_env_var`) only reads `std::env::var` — the asymmetry is a bug (see Edge Cases #1).

### Pattern: WinAPI FFI Without RAII (and why you should fix it)
- **Use when**: Calling winapi functions that return handles you must release.
- **Code ref**: `edo_tensei.rs:read_gen_registry_inner` (L216-L253)
- **How**: `let mut hkey: HKEY = null_mut(); RegOpenKeyExW(...); /* work */; RegCloseKey(hkey);`. **Problem**: If the body between open and close panics, the handle leaks. **Fix**: Wrap in a struct `struct RegGuard(HKEY); impl Drop for RegGuard { fn drop(&mut self) { unsafe { RegCloseKey(self.0); } } }` and `let _guard = RegGuard::new(hkey)?;`. Edo Tensei doesn't do this — operator-modification candidate.

### Pattern: Dual-Encoding Parser
- **Use when**: A storage location may contain either binary or text data depending on operator.
- **Code ref**: `edo_tensei.rs:parse_gen_bytes` (L271-L282)
- **How**: `if data.len() == 4 { u32::from_le_bytes(...) } else { std::str::from_utf8(data).ok()?.parse::<u32>() }`. Length-first dispatch means a 4-byte ASCII value like `b"1234"` is interpreted as binary, not decimal. This is acceptable for generation indices (small numbers, 4-byte binary is unambiguous) but would be wrong for variable-length numeric values.
