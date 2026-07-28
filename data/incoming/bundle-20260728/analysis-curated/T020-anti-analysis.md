---
id: T-020
name: Anti-Analysis Suite
category: anti-analysis
tier: mixed
crate: dark_crystal
mitre: [T1497.001, T1497.003, T1027, T1070.004, T1218, T1497]
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-004, T-002]
enables: [T-012, T-017, T-019, T-022]
vault_references:
  - techniques/T020-anti-analysis.md
  - src/dark_crystal/crowd/src/anti_vm.rs
  - src/dark_crystal/crowd/src/hammering.rs
  - src/dark_crystal/crowd/src/iat_camo.rs
  - src/dark_crystal/crowd/src/self_delete.rs
implements:
  - file: crowd/src/anti_vm.rs
    key_functions:
      - run_anti_vm
      - check_all_fsm
      - check_vm
      - check_cpuid
      - check_rdtsc
      - rdtsc_serialized
      - check_core_count
      - check_ram
      - check_mac_prefix
      - get_mac_address
      - check_registry_keys
      - registry_key_exists
      - registry_value_matches
      - check_filesystem_artifacts
      - check_running_processes
      - sleep_indefinitely
    key_structs:
      - MemoryStatusEx
    key_constants:
      - SAMPLES=16
      - THRESHOLD=500
      - interval_24h
    lines_of_interest:
      - "L40-L58: sleep_indefinitely via NtDelayExecution RecycledGate"
      - "L83-L98: check_all_fsm OR-cascade"
      - "L130-L150: check_cpuid hypervisor bit + vendor leaf"
      - "L156-L184: check_rdtsc 16-sample median"
      - "L186-L201: rdtsc_serialized LFENCE+RDTSC asm"
      - "L203-L222: check_core_count CPUID leaf 0xB fallback leaf 1"
      - "L260-L296: get_mac_address GetAdaptersInfo linked list walk"
      - "L298-L345: registry artifact tables"
  - file: crowd/src/hammering.rs
    key_functions:
      - run_fsm
      - hammer
      - sleep_detected
      - fpu_simd_waste
      - sha256_chain
      - registry_deep_walk
      - verify_loaded_modules
    key_structs: []
    key_constants:
      - DEFAULT_ITERATIONS=3_000_000
      - DEFAULT_MIN_ELAPSED_SECS=2
    lines_of_interest:
      - "L36-L66: hammer() five-stage composition"
      - "L82-L98: sleep_detected 24h RecycledGate loop"
      - "L107-L141: fpu_simd_waste x87+SSE2 interleave"
      - "L145-L158: sha256_chain anti-elision"
      - "L162-L176: registry_deep_walk HKLM enumeration"
      - "L180-L186: verify_loaded_modules ntdll_base probe"
  - file: crowd/src/iat_camo.rs
    key_functions:
      - apply_camouflage
      - profile_3::apply
      - profile_4::apply
      - profile_5::apply
    key_structs: []
    key_constants:
      - PROFILE_3_BIT=1
      - PROFILE_4_BIT=2
      - PROFILE_5_BIT=4
      - APPLIED_MASK
      - COINIT_MULTITHREADED=0
      - CERT_STORE_READONLY_FLAG=0x8000
      - CERT_SYSTEM_STORE_CURRENT_USER=0x10000
      - INTERNET_OPEN_TYPE_PRECONFIG=0
    lines_of_interest:
      - "L21-L40: profile_3 gdi32+winmm extern blocks"
      - "L46-L96: profile_4 wininet+crypt32 (UA spoof Mozilla/5.0)"
      - "L102-L152: profile_5 ole32+shell32 COM init/shell path"
      - "L158-L164: APPLIED_MASK Mutex<u8>"
      - "L177-L206: apply_camouflage bitmask dispatch"
  - file: crowd/src/self_delete.rs
    key_functions:
      - delete_self
    key_structs:
      - FILE_DISPOSITION_INFO
      - FILE_RENAME_INFO
    key_constants:
      - ":victor"
      - HEAP_ZERO_MEMORY
      - FileRenameInfo
      - FileDispositionInfo
      - DELETE
      - SYNCHRONIZE
      - FILE_SHARE_READ
      - OPEN_EXISTING
    lines_of_interest:
      - "L34-L41: HeapAlloc variable-length FILE_RENAME_INFO"
      - "L46-L75: closure-based RAII cleanup wrapper"
      - "L77-L92: FILE_RENAME_INFO population (FileNameLength -= 2 for NUL)"
      - "L96-L107: Step1 CreateFileW + SetFileInformationByHandle rename"
      - "L110-L131: Step2 reopen ADS path + delete-on-close"
      - "L138: HeapFree always-free on all return paths"
min_windows: "Windows 7 (NTFS ADS, reg.exe, wmic.exe present); RecycledGate path requires ntdll with valid SSN map"
needs_admin: "no"
tags:
  - anti-vm
  - anti-sandbox
  - api-hammering
  - iat-camouflage
  - self-delete
  - diagnostic-harness
  - cpuid
  - rdtsc
  - ads-rename
  - ml-evasion
---

# Anti-Analysis Suite (T-020) — Operator Playbook

## TL;DR
The Anti-Analysis Suite is a five-pronged pre-execution gauntlet that lets `dark_crystal` decide whether the host is a real operator target or a sandbox/analyst VM before any payload touches memory. CPUID/RDTSC/MAC/registry/process fingerprinting (`anti_vm.rs`) and 3M-iteration FPU+SIMD+SHA-256 wall-clock probing (`hammering.rs`) feed into a "sleep-indefinitely" 24h stall (never exit — exit itself is a tell). `iat_camo.rs` decorates the binary's IAT with benign GDI/wininet/ole32/shell32 imports to look like a desktop app to ML static classifiers, and `self_delete.rs` performs ADS rename + `FileDispositionInfo` unlink-while-running so the on-disk dropper vanishes the moment execution begins.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `crowd/src/anti_vm.rs` | 10-check VM/sandbox fingerprint; FSM hook | `run_anti_vm`, `check_all_fsm`, `check_vm`, 8 individual check fns, `sleep_indefinitely` | ~360 lines |
| `crowd/src/hammering.rs` | FPU/SIMD+SHA-256 anti-acceleration + registry/PEB walk | `run_fsm`, `hammer`, `fpu_simd_waste`, `sha256_chain`, `registry_deep_walk`, `verify_loaded_modules`, `sleep_detected` | ~190 lines |
| `crowd/src/iat_camo.rs` | Benign IAT injection across 3 cumulative profiles | `apply_camouflage`, `profile_3::apply`, `profile_4::apply`, `profile_5::apply` | ~210 lines |
| `crowd/src/self_delete.rs` | NTFS ADS-rename + delete-on-close self-unlink | `delete_self` | ~140 lines |

## How It Works

### 1. Anti-VM — `anti_vm.rs`

The FSM entry `check_all_fsm(&mut ExecutionContext)` (L36) respects `ctx.config.anti_vm` — operators can disable with `--no-anti-vm`. If enabled, eight checks run in an OR-cascade via the `chk!` macro (L46–L62) so the first hit short-circuits:

1. **`check_cpuid()` (L130)** — uses the `raw_cpuid::CpuId` crate to read leaf 1 ECX bit 31 (`has_hypervisor()`) and leaf 0x40000000 hypervisor vendor (`get_hypervisor_info().identify()`). Match list: `KVM`, `VMware`, `HyperV`, `Xen`, `QEMU`, `Unknown(_,_,_)`. Either signal → true.
2. **`check_rdtsc()` (L156)** — runs 16 samples (`SAMPLES = 16`) of `lfence; rdtsc; cpuid; lfence; rdtsc` (`rdtsc_serialized()` at L186), takes the median of the sorted deltas, and flags if > `THRESHOLD = 500` cycles. CPUID inline asm at L171–179 swaps RBX through a temp register because LLVM reserves RBX on x86_64 — `xchg rbx, {tmp:r}` before/after `cpuid`.
3. **`check_core_count()` (L203)** — prefers CPUID leaf 0xB extended topology (`get_extended_topology_info()` with `TopologyType::Core`) and falls back to leaf 1 EBX[23:16] (`max_logical_processor_ids()`). Flag if `< 4`.
4. **`check_ram()` (L224)** — calls `GlobalMemoryStatusEx` (declared as `unsafe extern "system"` at L241) on a stack `MemoryStatusEx` struct (L228, layout matches Win32 `MEMORYSTATUSEX`, 9 fields, 64-bit totals). Flag if `ull_total_phys < 4 GiB`.
5. **`check_mac_prefix()` (L254)** — `get_mac_address()` (L260) walks the linked list returned by `GetAdaptersInfo` (`winapi::um::iphlpapi`) and returns the first 6-byte non-zero MAC. Compared against 9 known OUI prefixes (VBox `08:00:27`, VMware `00:05:69/00:0C:29/00:1C:14/00:50:56`, Parallels `00:1C:42`, Xen `00:16:3E`, Hybrid Analysis `0A:00:27`, QEMU/KVM `52:54:00`).
6. **`check_registry_keys()` (L298)** — combines two tables: 12 known key paths (`HKLM\HARDWARE\ACPI\DSDT\VBOX__`, `HKLM\SOFTWARE\Oracle\...`, `HKLM\SOFTWARE\Wine`, etc.) and 10 value-substring pairs (BIOS version "VMWARE/VBOX/QEMU", SystemBiosDate "06/23/99", SystemInformation "SystemManufacturer=VMWARE"…). Both checkers shell out to `reg.exe query` (L335, L344) — `wmic`/`reg` are LOtL so no imports are added.
7. **`check_filesystem_artifacts()` (L378)** — `fs::metadata(p).is_ok()` against 16 paths including `C:\Windows\system32\drivers\VBoxMouse.sys`, `vmmouse.sys`, `vmhgfs.sys`, `vm3dmp.sys`, `vboxtray.exe`.
8. **`check_running_processes()` (L394)** — spawns `wmic process get name`, lowercases stdout, substring-matches 13 VM-tool process names (`vboxservice.exe`, `vmtoolsd.exe`, `prl_cc.exe`, `qemu-ga.exe`…).

Any hit → `sleep_indefinitely()` (L40). The 24h delay is encoded as `i64 = -(24*60*60*10_000_000)` (negative = relative time, 100-ns units). The loop **prefers** `crate::recycled::recycled2(ssn, gadget, 0 /*Alertable=FALSE*/, &interval as *const i64 as _)` after looking up `NtDelayExecution` via `crate::syscall_map::get_ssn_and_gadget(crate::resolve::compute_hash("NtDelayExecution"))` — i.e. goes through **RecycledGate (T-001)** and **PEB Walker + DJB2 (T-004)**. Falls back to `std::thread::sleep(86400s)` if the syscall map is unavailable. Function returns `-> !` (never).

### 2. API Hammering — `hammering.rs`

`hammer(seed, iters, min_secs)` (L46) runs five stages:

1. **`fpu_simd_waste(seed, iters) -> f64` (L107)** — 3,000,000-iteration loop (default `DEFAULT_ITERATIONS = 3_000_000`). Body: `acc.mul_add(1.000_001, 0.000_001)` (compiles to x87/SSE `fma`); every 64 iters `(acc.sin().abs() + 0.001).sqrt()` (forces x87 `FSIN` + `FSQRT`); every iteration two `mul_add` ops on `xmm_a/xmm_b` (`[f64;2]`) → `MULPD/ADDPD`; every 256 iters cross-mixes `acc` into `xmm_b` to defeat dead-code elimination. Returns `acc + xmm_a[0] + xmm_a[1]` so the caller keeps the value live.
2. **`sha256_chain(seed, 100_000)` (L145)** — iteratively hashes a 32-byte buffer (`seed.to_le_bytes()` + `seed.wrapping_mul(0x9e37_79b9).to_le_bytes()`), with `i.to_le_bytes()` appended every 25,000 iters to perturb length and prevent identical-hash short-circuits.
3. **`registry_deep_walk()` (L162)** — `winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(...)` over three hives (`...\Uninstall`, `...\Windows NT\CurrentVersion`, `SYSTEM\CurrentControlSet\Services`) and `enum_keys().take(30)` enumeration to force kernel-mode registry driver calls.
4. **`verify_loaded_modules()` (L180)** — `let (base, _) = crate::resolve::ntdll_base_and_name_hashes();` (PEB walker, **T-004**) — if `base.is_null()`, the environment is broken → `sleep_detected()`.
5. Clock-acceleration check: `start.elapsed()` compared to `Duration::from_secs(min_secs)` (default 2s). Sandboxes complete sub-500ms; real hardware takes 2–4s. If short → `sleep_detected()` (L82), a copy of `sleep_indefinitely` kept local for self-containment.

FSM hook is `run_fsm(&mut ExecutionContext)` (L26) — same logic but bails out (returns `false`) instead of sleeping, so the FSM can transition to `BailOut`. Honors `ctx.config.hammer_seed == 0` as skip-flag, and falls back to defaults when `hammer_iters == 0` or `hammer_min_secs == 0`.

### 3. IAT Camouflage — `iat_camo.rs`

`apply_camouflage(profile: usize)` (L177) is the public entry. Profile bits:
- `PROFILE_3_BIT = 1 << 0` (gdi32 + winmm)
- `PROFILE_4_BIT = 1 << 1` (wininet + crypt32)
- `PROFILE_5_BIT = 1 << 2` (ole32 + shell32)

Profiles are **cumulative** — `5` requests `PROFILE_3_BIT | PROFILE_4_BIT | PROFILE_5_BIT`. The static `APPLIED_MASK: Mutex<u8>` (L158) tracks which tiers already ran; each profile body only fires when its bit is requested *and* unset, then sets the bit. Mutex poisoning is explicitly handled (`Err(poisoned) => poisoned.into_inner()` L191) — never panics.

Per-profile payloads (each uses Rust `#[link(name = "...")] extern "system"` blocks so the linker adds the import even though the calls are no-ops):

- **`profile_3::apply`** (L21) — `GetDeviceCaps(NULL, 0)` + `timeGetTime()`. Pulls `gdi32.dll` + `winmm.dll` into IAT.
- **`profile_4::apply`** (L46) — `InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG=0, NULL, NULL, 0)` then immediate `InternetCloseHandle` (no traffic), plus `CertOpenStore(provider=9, dwFlags=0x0001_8000 = CERT_SYSTEM_STORE_CURRENT_USER(0x10000) | CERT_STORE_READONLY_FLAG(0x8000), pvPara="My\0")` then `CertCloseStore`. Pulls `wininet.dll` + `crypt32.dll`.
- **`profile_5::apply`** (L102) — `CoInitializeEx(NULL, COINIT_MULTITHREADED=0)`, then `SHGetFolderPathW(NULL, CSIDL_DESKTOP=0, NULL, 0, &mut [0u16; 260])`, then `CoUninitialize()` if HRESULT ≥ 0. Pulls `ole32.dll` + `shell32.dll`.

Effect: a static ML classifier scanning the binary's IAT sees a benign desktop-app import profile (multimedia, internet, cert, COM, shell) instead of the sparse `ntdll`-only set typical of droppers.

### 4. Self-Deletion — `self_delete.rs`

`delete_self() -> anyhow::Result<()>` (L28) executes a four-step NTFS trick:

1. **Allocate rename buffer** (L34): `len = size_of::<FILE_RENAME_INFO>() + stream_wide.len() * 2`. `HeapAlloc(GetProcessHeap()?, HEAP_ZERO_MEMORY, len)` — variable-length because `FILE_RENAME_INFO.FileName` is a flexible array. Null-check at L38.
2. **Populate rename info** (L51): `delete_file.DeleteFile = true.into()`, `(*rename_info).FileNameLength = (stream_wide.len() * 2) - 2` (subtracts trailing-NUL bytes per Win32 convention), `copy_nonoverlapping(stream_wide.as_ptr(), (*rename_info).FileName.as_mut_ptr(), stream_wide.len())`.
3. **Step 1 — Rename primary stream to ADS `:victor`** (L62): `CreateFileW(PCWSTR(full_path.as_ptr()), DELETE.0 | SYNCHRONIZE.0, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None)`, then `SetFileInformationByHandle(h, FileRenameInfo, rename_info as *const c_void, len as u32)`. Closes handle.
4. **Step 2 — Mark delete-on-close on the ADS path** (L91): builds `format!("{}:{}", path_str, "victor")`, reopens with `DELETE | SYNCHRONIZE`, calls `SetFileInformationByHandle(h2, FileDispositionInfo, &delete_file, size_of_val(&delete_file))`. When `h2` closes, NTFS unlinks the stream — but since the primary stream was renamed to `:victor`, there is no remaining named stream reachable via the original path.

A closure `(|| -> anyhow::Result<()> { ... })()` at L46 wraps steps 2–4 so that the outer `HeapFree(heap, HEAP_FLAGS(0), rename_info)` at L138 runs on **every** return path (success, error from `SetFileInformationByHandle`, error from `CreateFileW`). The `let _ =` on `HeapFree` discards the boolean return — fire-and-forget cleanup.

The file disappears from disk while the process is still running, defeating volume-shadow-copy forensics and post-execution disk scanners.

## Code Architecture

### Call graph

```
fsm::ExecutionContext ──┐
                        ├──> anti_vm::check_all_fsm ─┐
                        │                             │
                        ├──> hammering::run_fsm ──────┤
                        │                             ▼
                        │                    sleep_indefinitely / sleep_detected
                        │                             │
                        │                             ├── crate::syscall_map::get_ssn_and_gadget  ──► T-002/T-004
                        │                             ├── crate::resolve::compute_hash         ──► T-004
                        │                             └── crate::recycled::recycled2           ──► T-001
                        │
                        ├──> iat_camo::apply_camouflage (no syscall path — pure Win32 FFI)
                        │
                        └──> self_delete::delete_self (pure Win32 FFI, no syscalls)
```

### Data flow

- `anti_vm` and `hammering` both **gate** on `crate::fsm::ExecutionContext` config fields (`anti_vm: bool`, `hammer_seed: u32`, `hammer_iters: u32`, `hammer_min_secs: u64`). The FSM decides whether to bail or sleep.
- The 24h sleep loop is a shared semantic — duplicated in `anti_vm::sleep_indefinitely` and `hammering::sleep_detected`. The duplication is intentional (`hammering.rs` docstring says "Exists here so hammering.rs is self-contained"), so each module can be lifted standalone.
- `iat_camo` and `self_delete` are leaf modules — no dependency on syscall infrastructure or FSM context.
- `hammering::verify_loaded_modules` consumes `crate::resolve::ntdll_base_and_name_hashes()` — a tuple `(base, name_hash)` — to validate that PEB walking succeeded.

### Type hierarchy

- `MemoryStatusEx` (`anti_vm.rs` L228) — `#[repr(C)]`, 9 fields, mirrors `MEMORYSTATUSEX`.
- `FILE_RENAME_INFO` + `FILE_DISPOSITION_INFO` (`self_delete.rs`) — imported from `windows::Win32::Storage::FileSystem`.
- `IP_ADAPTER_INFO` (`anti_vm.rs` via `winapi::um::iptypes`) — external.
- No traits, no enums of note — the suite is deliberately flat, FFI-heavy, and panic-free.

### Feature gates

- `#![allow(dead_code)]` on `anti_vm.rs`, `hammering.rs`, `iat_camo.rs` — the modules are compiled even when not invoked; this is intentional so `iat_camo`'s `#[link]` extern blocks always decorate the IAT.
- `hammering.rs` honors runtime config flags (`hammer_seed == 0` skips) rather than `cfg` features.
- The card references `crowd/src/diagnostic.rs` as compiled only under `--features diagnostic` — not present in source provided.

## Operational Profile

### When to Use

- **Any engagement where the dropper lands cold and unscored.** `run_anti_vm` + `hammer` should be the first two FSM phases before any payload staging.
- **ML-classifier-protected front-ends** (Defender, CrowdStrike static ML) — `iat_camo` profile 4 or 5 should be the *first* code the linker sees; the `extern "system"` blocks add imports at link time even if `apply_camouflage` is never called at runtime. (Operator's trick: leave `apply_camouflage` uncalled — the IAT deception persists.)
- **Long-running RAT beacons** — `self_delete::delete_self` should fire immediately after the secondary stage is staged to memory, so disk forensics find no dropper.
- **Sandbox-evading red certs** where the goal is to pass an automated detonation report card.

### When NOT to Use

- **Target is a known physical laptop/desktop owned by a specific user** — `anti_vm` will return clean (good), but `hammer`'s 2-4s CPU burn is audible to EDR telemetry (`NtQuerySystemInformation` CPU usage counters).
- **Engagement requires Win10-on-Win11-HyperV dev boxes** — `check_cpuid` will see `HyperV` and stall. Disable with `--no-anti-vm` or extend the match list.
- **EDR with behavioral sandbox that flags `reg.exe` / `wmic.exe` child processes** — `check_registry_keys` and `check_running_processes` shell out via `Command::new("reg")` / `Command::new("wmic")`. This is loud. Replace with `NtQueryKey`/`NtEnumerateKey` (RecycledGate) and `NtQuerySystemInformation(SystemProcessInformation)` before using on hardened targets.
- **Sting operations / honeytoken files** — `delete_self` obliterates the dropper before analysts can grab it. Disable for engagement evidence preservation.
- **Cloud instance where you specifically want to detect cloud** — `check_ram` will trip on a 2GB t3.small; that's by design.

### Kill Chain Position

```
T-004 (PEB walk) ─► T-001 (RecycledGate) ─► T-002/T-003 (syscall map resolve)
                                              │
                                              ▼
                                          T-020 (this suite)
                                          ├── anti_vm      ◄── pre-execution gauntlet
                                          ├── hammering    ◄── pre-execution gauntlet
                                          └── iat_camo     ◄── link-time / startup
                                              │
                                              ▼
                                          T-012 (Early Cascade)  ─► T-005 (Ekko sleep) ─► T-017 (persistence)
                                              │
                                              ▼
                                          T-019 (Edo Dead Drop) — final C2 channel
                                          │
                                          ▼
                                          self_delete  ◄── post-staging cleanup (runs concurrently with main payload)
```

T-020 sits *after* syscall infrastructure is initialized (it depends on `recycled2`) but *before* any injection/persistence code runs. `iat_camo` is link-time and effectively pre-phase-0. `self_delete` runs *after* stage-2 is staged in memory and *before* the dropper exits.

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` blocks

- **`anti_vm.rs::sleep_indefinitely` (L44-L56)** — one unsafe block: looks up SSN+gadget, calls `recycled2(ssn, gadget, 0, &interval as *const i64 as _)`. Casts `&i64` to `*const c_void`-compatible; no handle ownership. Fallback `std::thread::sleep` is safe-Rust.
- **`anti_vm.rs::check_rdtsc` (L171-L179)** — inline `core::arch::asm!` block: `xchg rbx, {tmp:r}`; `xor eax, eax`; `cpuid`; `xchg rbx, {tmp:r}`. Clobbers `eax`, `ecx`, `edx`, `tmp` (reg). `options(nostack)` — no stack frame. RBX is callee-saved on x86_64 MSVC/SysV so it must be preserved around `cpuid`.
- **`anti_vm.rs::rdtsc_serialized` (L188-L201)** — two asm blocks: `lfence` with `options(nostack, nomem)` and `rdtsc` writing `eax`+`edx`. Combined via `((hi as u64) << 32) | (lo as u64)`.
- **`anti_vm.rs::check_ram` (L241-L258)** — `unsafe extern "system" { fn GlobalMemoryStatusEx(...) -> i32; }` declaration + call on `&mut ms`. No handle, no cleanup.
- **`anti_vm.rs::get_mac_address` (L260-L296)** — `unsafe` block wraps `GetAdaptersInfo(std::ptr::null_mut(), &mut buf_len)` for size query, then `GetAdaptersInfo(adapter_ptr, &mut buf_len)` for data. Walks linked list via `cur = info.Next`. Dereferences `*mut IP_ADAPTER_INFO` raw pointer — no RAII; the `Vec<u8>` buffer owns the memory and frees on drop.
- **`iat_camo.rs::profile_3/4/5::apply`** — each `unsafe` block calls Win32 FFI with mostly null handles. `profile_4` checks `h.is_null()` before `InternetCloseHandle`. `profile_5` tracks HRESULT sign before `CoUninitialize` to avoid unbalanced uninit.
- **`self_delete.rs::delete_self` (L28-L140)** — single outer `unsafe` block. `HeapAlloc` returns raw `*mut FILE_RENAME_INFO`; cast inside the closure. `CreateFileW` returns `HANDLE` owned by `Result`; `CloseHandle` called on both success and error paths. The closure captures `rename_info` by mutable reference; the outer `HeapFree(heap, HEAP_FLAGS(0), Some(rename_info as *const c_void))` at L138 is unconditional.

### FFI patterns

- `anti_vm.rs` uses raw `unsafe extern "system" fn` declarations (no `windows_targets::link!`) — direct libc-style linkage.
- `iat_camo.rs` uses `#[link(name = "...")] extern "system" { fn ... }` blocks — Rust-native declaration that pulls in the import library at link time. The block is *inside* a child module so the namespacing is `profile_4::InternetOpenA` etc., avoiding collisions with `windows` crate bindings.
- `self_delete.rs` uses `windows::Win32::{Foundation, Storage::FileSystem, System::Memory}` paths via the `windows` crate — RAII `Result<HANDLE>` returns from `CreateFileW`, `?` propagates errors.
- `hammering.rs` uses `winreg::RegKey::predef(HKEY_LOCAL_MACHINE)` — safe-Rust wrapper around `RegOpenKeyExW`. No unsafe.

### Memory layout

- `MemoryStatusEx` (`anti_vm.rs` L228) is `#[repr(C)]`, 9 fields, `dw_length: u32` set to `size_of::<MemoryStatusEx>() as u32` before the call — required by Win32 to identify struct version.
- `FILE_RENAME_INFO` allocation (`self_delete.rs` L34): `size_of::<FILE_RENAME_INFO>() + stream_wide.len() * size_of::<u16>()`. The +N bytes extend past the `FileName: [u16; 1]` flexible array. `FileNameLength = (stream_wide.len() * 2) - 2` — the -2 strips the trailing NUL because Win32 expects length in bytes excluding terminator. The `copy_nonoverlapping` copies `stream_wide.len()` elements including the NUL — this is fine because the buffer was sized for that.

### Initialization patterns

- `iat_camo.rs::APPLIED_MASK: Mutex<u8> = Mutex::new(0)` — static-once guard. Poisoning handled gracefully (`into_inner()`).
- `hammering.rs::verify_loaded_modules` calls `crate::resolve::ntdll_base_and_name_hashes()` — this is itself backed by a OnceLock in `resolve.rs` (T-004) per the vault manifest. So the PEB walk happens once, lazily, on first anti-analysis call.
- `anti_vm.rs` — no statics. Each check is a pure function. The 24h interval is recomputed each call to `sleep_indefinitely` — cheap.

### Error handling

- `anti_vm.rs` — all checks return `false` on error (`GlobalMemoryStatusEx == 0`, `GetAdaptersInfo != 0`, `Command::output().is_err()`). The dropper **fails open** — assumes clean on internal error. This is a deliberate trade-off: better to proceed into a slightly-suspicious environment than to false-positive and stall on a real target.
- `hammering.rs` — `run_fsm` returns `bool` (true = clean); the wrapper `hammer()` sleeps forever on detection. The `sha256_chain` return is discarded (`let _ =`).
- `iat_camo.rs` — no `Result`, no panics. Mutex poisoning unwrapped via `into_inner()`.
- `self_delete.rs` — `anyhow::Result<()>` propagated via `?`. Closure captures errors so `HeapFree` always runs. The only unrecoverable error is `HeapAlloc` returning null (returns `Err`).

### Syscall numbers — how resolved

The 24h sleep path in both `anti_vm::sleep_indefinitely` (L50) and `hammering::sleep_detected` (L86) uses the **identical** resolution pattern:

```rust
crate::syscall_map::get_ssn_and_gadget(
    crate::resolve::compute_hash("NtDelayExecution")
)
```

- `crate::resolve::compute_hash` (T-004) — DJB2 hash of the ASCII syscall name. Constants live in `crate::resolve` and `crate::syscall_map`.
- `crate::syscall_map::get_ssn_and_gadget(hash)` (T-002/T-004) — returns `Option<(u16, usize)>` where `u16` is the SSN and `usize` is the gadget address inside `ntdll.dll`'s `.text` (RecycledGate's indirect syscall trampoline).
- The guard `if gadget != 0` skips the syscall path if the gadget couldn't be resolved (e.g., unhooked ntdll) and falls through to `std::thread::sleep` — safe-Rust fallback.

## Cross-References Found in Code

- `anti_vm.rs:38` → calls **T-001 RecycledGate** via `crate::recycled::recycled2(ssn, gadget, 0, &interval as *const i64 as _)` — indirect syscall execution of `NtDelayExecution`.
- `anti_vm.rs:50` → calls **T-004 PEB Walker + DJB2** via `crate::resolve::compute_hash("NtDelayExecution")`.
- `anti_vm.rs:49` → calls **T-002/T-003 Syscall Dispatch (SSN Map)** via `crate::syscall_map::get_ssn_and_gadget(...)`.
- `anti_vm.rs:60` → calls **T-022 Architecture (FSM)** via `ctx: &mut crate::fsm::ExecutionContext` — `ctx.config.anti_vm` field.
- `hammering.rs:60` → calls **T-001 RecycledGate** via `crate::recycled::recycled2` (in `sleep_detected`).
- `hammering.rs:60` → calls **T-004** via `crate::resolve::compute_hash` and `crate::resolve::ntdll_base_and_name_hashes()`.
- `hammering.rs:26` → calls **T-022** via `crate::fsm::ExecutionContext` with `hammer_seed`, `hammer_iters`, `hammer_min_secs` config fields.
- `self_delete.rs:1-22` → comment block explicitly attributes the technique to "killaofking/crates/core/src/experimental/self_deletion.rs" (lineage reference, not a T-XXX).
- `iat_camo.rs` — no cross-references to other T-XXX. Pure link-time FFI.
- `anti_vm.rs:5` → `use crate::mega_dbg!` — debug logging macro, plausibly part of **T-022 Architecture** debug subsystem.

- `crowd/src/kaguya.rs` (T-020 card section 5) — LOtL inventory, expected to use `crate::resolve` and RecycledGate per card.
- `crowd/src/winhttp_dl.rs` (T-020 card section 6) — WinHTTP staged download with `NtVecBuf` owner; uses `winhttp` bindings, no ntdll path.
- `crowd/src/diagnostic.rs` (T-020 card section "Diagnostic Integration Test Harness") — `DiagReport`, `TestCategory`, marker-event verification; compiled only under `--features diagnostic`.

## Edge Cases & Failure Modes

1. **`check_rdtsc` on a CPU without TSC.** Code path: `check_rdtsc` (L156) calls `cpuid.get_feature_info().map_or(true, |f| !f.has_tsc())` → returns `false` ("clean"). The check is silently skipped. **Symptom**: never triggers on ancient hardware. **Workaround**: none needed — TSC has been baseline since Pentium 4.
2. **`get_mac_address` on a host with only virtual adapters (loopback, Tunnel adapters).** Code path: walks the linked list at `anti_vm.rs:285-294`, but skips `mac.iter().any(|&b| b != 0) == false` entries. **Symptom**: returns `None`, `check_mac_prefix` returns `false`. **Risk**: a VMware VM with only the `vmxnet3` adapter but zeroed MAC would be missed. **Workaround**: extend the loop to also probe `info.Type` for IF_TYPE_ETHERNET.
3. **`wmic.exe` not present on Win11 22H2+.** Code path: `check_running_processes` (L394) `Command::new("wmic").output()` returns `Err`, the `.unwrap_or(false)` swallows it and returns `false`. **Symptom**: VM process check silently disabled. **Workaround**: replace with `NtQuerySystemInformation(SystemProcessInformation)` via RecycledGate.
4. **`reg.exe` blocked by AppLocker / WDAC.** Code path: `registry_key_exists` returns `false` for every key. **Symptom**: registry artifact checks completely disabled. **Workaround**: use `winreg` (as `hammering.rs::registry_deep_walk` already does) or RecycledGate-backed `NtOpenKey`/`NtQueryValueKey`.
5. **`self_delete` on FAT32 / ExFAT volume.** Code path: `SetFileInformationByHandle(FileRenameInfo, ":victor")` returns `Err` — ADS unsupported on FAT. **Symptom**: `delete_self` returns `Err(...)`, file remains. **Workaround**: stage the dropper on an NTFS-reparse-point path, or use `Win32::DeleteFileW` after process exit via `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`.
6. **`self_delete` while the binary is mapped via `NtCreateSection(SEC_IMAGE)`.** Code path: `CreateFileW` with `DELETE | SYNCHRONIZE` may fail with `STATUS_SHARING_VIOLATION` if AV has the file open for scan. **Symptom**: step 1 returns `Err`. **Workaround**: retry loop with `Sleep`; fall back to `FILE_FLAG_DELETE_ON_CLOSE` on the original `CreateFileW`.
7. **`iat_camo` profile 5 called when COM is already initialized on the calling thread.** Code path: `CoInitializeEx(NULL, 0)` returns `S_FALSE (1)`; `should_uninitialize = hr >= 0` is true → `CoUninitialize()` runs and tears down the *previous* initializer's COM. **Symptom**: COM state corruption in caller. **Workaround**: only call `profile_5::apply` from a thread you control, not from the FSM dispatcher thread.
8. **`hammer` on a system with `hammer_iters` set very high (e.g., 100M).** Code path: `fpu_simd_waste` runs to completion; total wall-clock >> 2s; check passes. **Symptom**: dropper appears to hang for 30+ seconds — might trigger EDR's "long-running unsigned binary" heuristic. **Workaround**: cap iters at 3M.
9. **`anti_vm::sleep_indefinitely` when `syscall_map` not yet initialized.** Code path: `get_ssn_and_gadget(...)` returns `None`; the `if let Some(...)` skips; falls through to `std::thread::sleep(86400)`. **Symptom**: dropper sleeps 24h via Win32 (visible to ETW TI `ThreadSet`/`ThreadWake`) instead of via direct `NtDelayExecution` (invisible). **Workaround**: ensure `crate::resolve::init()` runs before `run_anti_vm`.

## OPSEC Notes

**Artifacts left (loud):**

- `anti_vm.rs::check_running_processes` spawns `wmic.exe` (Sysmon EID 1 process creation, EID 3 network if wmic queries remote — local here).
- `anti_vm.rs::check_registry_keys` / `registry_key_exists` / `registry_value_matches` spawn `reg.exe` once per key/value (~22 spawns worst case). Sysmon EID 1.
- `iat_camo.rs` profile 4 — `InternetOpenA("Mozilla/5.0")` may briefly show in WinINet's session list (EID 4 `WinINet` ETW).
- `self_delete.rs` — `HeapAlloc(GetProcessHeap)` and `CreateFileW` on the dropper path are visible via `Sysmon EID 11 (FileCreate)` for the ADS stream `:victor` if Sysmon's ProcessCreate+FileDelete rule is configured.

**Artifacts minimized (silent):**

- `anti_vm.rs::sleep_indefinitely` and `hammering.rs::sleep_detected` use **RecycledGate indirect syscalls** — no `ntdll.dll!NtDelayExecution` appears on the call stack, only the gadget address. ETW TI `ThreadSet` still fires (kernel sees the wait) but the user-mode caller is the ntdll gadget, not the dropper.
- `iat_camo.rs` profile 3 + 5 — `GetDeviceCaps(NULL,0)`, `timeGetTime`, `SHGetFolderPathW` are no-ops from a network/IO perspective.
- `self_delete` — final file unlink is silent because NTFS handles it on handle close, no `DeleteFileW` API call.

**Cleanup:**

- `self_delete.rs` IS the cleanup. The dropper file vanishes mid-execution. The only residual is the `:victor` ADS — but since the file is gone, the ADS is gone too.
- `iat_camo.rs` — no artifacts to clean; FFI calls return immediately.
- `anti_vm.rs` / `hammering.rs` — no on-disk cleanup needed. The 24h sleep is by design (an analyst who memory-dumps at hour 23 sees a benign-looking stalled process).

**Telemetry detections to watch:**

- EDR with `reg.exe` child-of-unsigned-binary rule → high-confidence alert. **Mitigation**: variant 1 above.
- EDR with `wmic.exe` parent not `winmgmt.exe` → high-confidence alert. **Mitigation**: variant 1.
- Volume Shadow Copy running between stage-1 and `self_delete` execution → snapshot contains the dropper. **Mitigation**: run `self_delete` *before* any other stage-2 staging; or run `vssadmin delete shadows` (loud, requires admin).

## Reusable Patterns

### Pattern: Fails-Open Anti-Analysis Check
- **Use when**: any pre-execution fingerprinting where a false positive (stall on a real target) is worse than a false negative (proceed in a sandbox).
- **Code ref**: `anti_vm.rs::check_ram()` L258 — `if GlobalMemoryStatusEx(...) == 0 { return false; }`
- **How**: every check returns `false` (assumed clean) when its own API call fails. The OR-cascade in `check_vm` (L122-L130) then short-circuits to `false` only when *all* checks pass. Operators who want strict mode can flip the fallback to `true`.

### Pattern: Sleep-Never-Exit Detection Response
- **Use when**: any sandbox-evading pre-flight check where the goal is to outlast the sandbox's wait window without revealing that detection fired.
- **Code ref**: `anti_vm.rs::sleep_indefinitely()` L40-L58, `hammering.rs::sleep_detected()` L82-L98
- **How**: function returns `-> !` (diverges). Loop body prefers RecycledGate-syscalled `NtDelayExecution` (negative i64 = relative 100-ns interval), falls back to `std::thread::sleep(86400)`. Never calls `ExitProcess` — process stays alive and "looks busy" to the sandbox.

### Pattern: Bitmask Idempotent Profile Application
- **Use when**: invoking the same setup code multiple times should be a no-op after the first invocation (COM init, IAT profile, etc.).
- **Code ref**: `iat_camo.rs::APPLIED_MASK` L158, `apply_camouflage` L177-L206
- **How**: `static APPLIED_MASK: Mutex<u8> = Mutex::new(0)`. Each tier has a bit (`PROFILE_3_BIT`, etc.). Request mask is `requested & bit != 0 && *applied & bit == 0`. Mutex poisoning handled via `into_inner()` — never panics.

### Pattern: RAII Closure for Heap Buffer
- **Use when**: a heap-allocated variable-length struct must be freed on every return path including early `?` errors.
- **Code ref**: `self_delete.rs::delete_self` L46-L138
- **How**: `let result = (|| -> Result<()> { ... })(); let _ = HeapFree(heap, HEAP_FLAGS(0), Some(ptr)); result`. The closure captures `rename_info` by ref; any `?` inside the closure propagates out, then `HeapFree` runs unconditionally. Equivalent to a `Drop` guard without defining a new type.

### Pattern: Asm-Safe CPUID on x86_64
- **Use when**: inline `cpuid` in Rust on x86_64 — LLVM reserves `RBX` (the frame pointer on MSVC, PIC base on SysV) so naive `cpuid` clobbers it.
- **Code ref**: `anti_vm.rs::check_rdtsc` L171-L179
- **How**: `xchg rbx, {tmp:r}` before and after `cpuid` swaps RBX with a temporary register; the `tmp` is declared `out(reg) _` so the compiler picks a free GPR. `options(nostack)` because no stack spills.

### Pattern: TSC-Serialized Timing Probe
- **Use when**: benchmarking cycles-per-instruction without reordering or speculation polluting the measurement.
- **Code ref**: `anti_vm.rs::rdtsc_serialized` L186-L201
- **How**: `lfence` (serializing) before `rdtsc` to drain prior instructions; `rdtsc` writes EDX:EAX. The `nomem` option lets the compiler reorder around it but the `lfence` itself is the serialization barrier. Combined with `cpuid` (also serializing) between two `rdtsc_serialized` calls, the delta is the cost of `cpuid` plus VM-exit overhead — used to fingerprint hypervisors at L156-L184.
