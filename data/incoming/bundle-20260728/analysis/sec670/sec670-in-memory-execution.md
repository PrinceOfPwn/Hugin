---
id: RTO-sec670-persistence-die-another-day
name: SEC670.4 — Persistence: Die Another Day
source: SANS SEC670 / Red Teaming Tools: Developing Windows Implants
category: persistence
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-016, T-017, T-018, T-019, T-020, T-009, T-007, T-013, T-021]
tags: [persistence, fileless-malware, registry-run, appinit-dlls, appcert-dlls, binary-patching, in-memory-execution, dropper-opsec, memory-forensics, autostart, runonce]
---

# SEC670.4 — Persistence: Die Another Day — Training Reference

## TL;DR
SEC670.4 is the persistence module from SANS's red team tool development course. It frames the fileless-vs-on-disk tradeoff, then walks through classic autostart primitives (Run/RunOnce keys, AppInit/AppCert DLLs), binary patching (in-memory and on-disk), and introductory material for services, port monitors, IFEO, and WMI event subscriptions. Compared to the vault's T-017 Five-Layer Persistence Suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist), this training is foundational — useful for operators needing the *why* behind persistence decisions, but operationally superseded by the vault's modern, resilient primitives.

## Key Concepts

1. **Fileless Execution = No Disk Backing**
   Code running in RAM without a corresponding file on disk — "fileless malware." The training emphasizes this is the ideal initial-access state: no static signatures, nothing to hash, no analyst-recoverable artifact (without a memory dump). Cross-ref: vault's reflective PE loader (T-013), module stomping (T-016), and PE stomping primitives all implement fileless execution variants that go beyond what the training describes.

2. **The Reboot Problem — Volatility Kills Persistence**
   RAM flushes on reboot. Pure in-memory presence dies with the host. SEC670 frames the entire persistence problem around surviving reboot: you must drop *something* to disk (or firmware/BIOS) or accept loss of access. The vault's T-017 PhantomPersist + 30-minute resilience monitor explicitly solves this by monitoring persistence health and self-healing — a layer SEC670 does not cover.

3. **"One is None, Two is One"**
   Persistence redundancy principle: a single persistence mechanism is effectively zero because it can be burned or fail silently. Operators should layer at least two mechanisms. Vault operationalizes this in T-017's 5-layer suite and T-018 Edo Tensei's polymorphic technique-stack resurrection (which resurrects burned persistence techniques automatically).

4. **Strategic Drop Locations**
   When dropping to disk, target folders with high file density (e.g., System32 with 4,200+ entries) to blend in. Avoid first/last position in directory listings. Match filename prefix patterns and modification dates of surrounding files. Don't drop in Desktop/Documents/Downloads. Requires elevated context for System32 placement.

5. **In-Memory Patching vs. On-Disk Patching**
   In-memory patching is volatile but OPSEC-clean (no disk artifacts, flushes on reboot, scoped to one process). On-disk patching is persistent and cascading (affects every process that loads the patched module post-reboot) but high-risk for system stability. Patching `ntdll.dll` on disk affects the loader itself — extremely dangerous. Vault's T-016 includes NTDLL unhooking and AMSI/ETW patching primitives that are in-memory scoped; SEC670's on-disk patching guidance is **not** in the vault and represents a divergence in tradecraft philosophy (the vault favors in-memory evasion to avoid SFC/Tamper Protection issues).

6. **Run Key = Most-Used Persistence Primitive**
   MITRE T1547.001. Used by APT28, APT30, DarkComet, Emotet, FIN7, Gazer, Lazarus. `HKCU\...\CurrentVersion\Run` (no elevation required, fires on user logon) and `HKLM\...\CurrentVersion\Run` (requires Admin, fires at boot). Vault's T-017 schtask layer is the modern equivalent — scheduled tasks are stealthier than Run keys in modern EDR telemetry.

7. **RunOnce vs. Run**
   `RunOnce`/`RunOnceEx` deletes the value after execution. Useful for staging (downloader fires once, pulls second-stage persistence) but does not survive a reboot cycle on its own. `HKLM\...\RunOnce` runs as Admin.

8. **AppInit_DLLs — Global DLL Injection via User32**
   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` — set `LoadAppInit_DLLs=1` (REG_DWORD) and `AppInit_DLLs` (REG_SZ, comma-separated paths). Every new process linked against `user32.dll` loads the listed DLLs. 64-bit and 32-bit (Wow6432Node) variants exist. Used by APT39, CherryPicker, T9000. MITRE T1546.010. Critical OPSEC: must use a global mutex to prevent infinite process-spawn loops if the DLL calls `CreateProcess`.

9. **AppCert DLLs — CreateProcess Hook**
   `HKLM\SYSTEM\CurrentControlSet\Current\Session Manager\AppCertDlls`. Loaded into any process that calls `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogin`, `CreateProcessWithToken`, or `WinExec`. Requires DLL exporting `CreateProcessNotify`. Requires reboot to take effect. Used by Honeybee, PUNCHBUGGY. MITRE T1546.009. Easily detected by Sysinternals Autoruns — high noise.

10. **Memory Forensics Threat**
    Volatility, PE-sieve (Hasherzade), Moneta (forrest-orr) are live memory scanners that can detect injected/unbacked regions. MDSec Nighthawk reportedly bypassed Moneta. The training notes that EDR cannot scan all process memory constantly due to perf cost — targeted scanning is the norm. Vault's T-005 Ekko ROP Sleep (encrypts implant in place during sleep) and T-016 stack/PE stomping are direct countermeasures to PE-sieve/Moneta-style scanning.

## Operational Techniques

### In-Memory Execution (Fileless)

- **What**: Execute shellcode or PE images in RAM without file backing on disk
- **When to use**: Initial access, post-exploitation actions, any scenario where leaving disk artifacts is unacceptable
- **How**:
  1. Acquire payload (network-delivered, in-packet, embedded)
  2. Allocate RWX (or RW→RX) memory in target process
  3. Copy/move shellcode or reflectively load PE
  4. Create thread or use APC/callback/fiber to trigger execution
  5. Optionally wipe headers post-load to reduce memory scanner signal
- **Vault link**: T-013 (Remaining Methods) covers reflective PE loader, callback exec, fiber exec, mapping inject, module stomping. T-007 Pool Party / Threadless provide stealthier fileless execution than basic VirtualAlloc+CreateThread. The vault's implementations are S/A-tier vs. SEC670's conceptual treatment.
- **Tool/code**: Vault `pe_loader.rs`, `callback_exec.rs`, `fiber_exec.rs`
- **OPSEC**: Memory scanners (PE-sieve, Moneta) will eventually catch unbacked regions. Use module stomping or MEM_IMAGE-backed phantom stubs (T-006) to give regions a backing image.

### Strategic Dropping to Disk

- **What**: Drop a minimal persistence/downloader binary to a well-chosen filesystem location
- **When to use**: Surviving reboot when no in-memory persistence vector is viable; required for long-term foothold on high-value targets
- **How**:
  1. Conduct host survey: enumerate folders with write access, file counts, modification date patterns
  2. Pick folder with high file density (System32 ideal — 4,200+ entries, requires Admin)
  3. Choose filename that blends with neighbors (match starting letter prefix patterns)
  4. Match modification timestamps of surrounding files (avoid being the only current-year file in an old folder)
  5. Drop a *minimal* capability — only what is needed to re-establish access; not your full toolset
  6. Do not place in Desktop/Documents/Downloads (unless Desktop is heavily cluttered)
- **Vault link**: Vault's T-017 PhantomPersist explicitly tracks persistence health and resurrects burned entries — SEC670 does not cover resilience monitoring. T-019 Edo Dead Drop (autonomous C2 via Google Translate/blockchain/steganography) provides a fallback channel if the on-disk persistence is discovered.
- **Tool/code**: None specific; host-survey enumeration via standard Win32 APIs
- **OPSEC**: AV/EDR will eventually scan the file. Cloud-based AV may submit unknown binaries to vendor cloud for analysis. Use Themida, Skrull (Process Ghosting-based anti-copy DRM, see [github.com/aaaddress1/Skrull](https://github.com/aaaddress1/Skrull)), or vault's T-021 string obfuscation proc macro + AES-GCM/zstd payload encryption to limit static analysis exposure. Drop only a stub, never your full capability.

### In-Memory Binary Patching

- **What**: Modify bytes of an in-memory module image to change function behavior (e.g., AMSI bypass, ETW patch, AV hook disabling)
- **When to use**: Bypassing AMSI/ETW, disabling AV scanning functions, changing EDR hook behavior in a single process
- **How**:
  1. Inject into or attach to target process
  2. Walk PEB → find loaded module list → locate target DLL base
  3. Find image base by scanning for `\x4d\x5a\x90\x00` (MZ + NOP + null) to reduce false positives
  4. Parse PE headers → locate target function via Export Address Table
  5. `VirtualProtect` to RW → patch with `ret`/`xor eax,eax; ret`/custom stub → restore to RX
  6. Common targets: `AmsiScanBuffer`, `AmsiScanString` in `amsi.dll`; `EtwEventWrite` in `ntdll.dll`
- **Vault link**: T-016 EDR Evasion Suite implements AMSI patching (both direct and via HW breakpoints — `amsi_hbp.rs`), ETW muffling (`etw.rs`), and NTDLL unhook (`ntdll_unhook_inject.rs`, `ntdll_unhook.rs`). The vault's AMSI HW breakpoint bypass (`T-016 amsi_hbp.rs`) is **more advanced** than SEC670's byte-patching approach — it avoids memory modifications entirely by trapping on AMSI function execution.
- **Tool/code**: `amsi_hbp.rs`, `amsi_page_guard.rs`, `etw.rs`, `ntdll_unhook_inject.rs`
- **OPSEC**: In-memory patches do not survive reboot (good for stealth, bad for persistence). EDR with cross-process memory scanning may detect patched pages. HW BP bypass leaves no memory signature.

### On-Disk Binary Patching

- **What**: Modify a binary file on disk to change behavior persistently across reboots
- **When to use**: Persistent evasion (every process loading the patched DLL post-reboot is affected); whitelisting self-insertion
- **How**:
  1. Acquire write access to target file (System32 requires Admin + may trip SFC/Tamper Protection)
  2. Read original bytes (always preserve for rollback)
  3. Apply patch to disk bytes
  4. Trigger reload (reboot required for ntdll; restart for AV/EDR binaries)
- **Vault link**: Vault does **not** implement on-disk binary patching. This is a deliberate divergence — on-disk patching of system files trips Windows Resource Protection (WRP/SFC), triggers EDR file-write telemetry, and risks system instability. The vault favors in-memory unhooking (T-016) which is OPSEC-safer. SEC670's guidance to "avoid patching critical system DLLs unless dire need" is sound but the vault goes further by avoiding it entirely.
- **Tool/code**: None in vault
- **OPSEC**: High risk. SFC will restore patched system files. EDR file-write telemetry on System32 contents is heavily monitored. System stability at risk if `ntdll.dll` is patched incorrectly — cascading failures across all processes on next boot.

### Registry Run Key Persistence

- **What**: Add a value to `HKCU\...\CurrentVersion\Run` or `HKLM\...\CurrentVersion\Run` to execute a binary on user logon or system boot
- **When to use**: Quick, reliable, low-effort persistence when OPSEC concerns are secondary
- **How**:
  1. Choose hive: HKCU (no elevation, fires on logon) or HKLM (Admin, fires at boot)
  2. Add REG_SZ value: name = arbitrary, data = full path to binary + args
  3. Binary will execute next logon/boot
- **Vault link**: T-017 persistence suite does **not** use Run keys directly — it uses schtask (scheduled task), COM hijack, NTFS EA, TLS callback, and PhantomPersist. Schtasks are stealthier than Run keys in modern EDR telemetry because schtasks generate less prominent process-tree events than Run-key-spawned binaries. SEC670's Run key is the legacy fallback. **For operations where Run key is needed for compatibility, it is not in the vault and must be implemented ad hoc.**
- **Tool/code**: Standard `RegSetValueEx` via Win32
- **OPSEC**: Trivially detected by Autoruns, every EDR monitors Run keys. MITRE T1547.001 is one of the most-telemetry-covered persistence techniques.

### RunOnce Key Staging

- **What**: Add a value to `...\RunOnce` or `...\RunOnceEx` for one-time execution on next logon/boot
- **When to use**: Staging downloader that pulls a more stealthy persistence mechanism post-reboot
- **How**:
  1. Add REG_SZ value to `HKLM\...\RunOnce` (Admin, runs at boot) or `HKCU\...\RunOnce` (user logon)
  2. Value data = path to downloader/stager binary
  3. After execution, Windows automatically deletes the value
  4. Downloader establishes the actual (stealthier) persistence mechanism
- **Vault link**: Not directly implemented. T-017 schtask layer can be configured as a one-shot trigger (`/SC ONCE`) which serves the same purpose with less telemetry exposure. Vault's approach is preferred.
- **Tool/code**: `RegSetValueEx`
- **OPSEC**: Lower artifact persistence (auto-deleted) but the one-shot execution itself is heavily monitored. Better than Run key for ephemeral staging.

### AppInit_DLLs Global Injection

- **What**: Force every new user32-linked process to load a specified DLL via registry configuration
- **When to use**: Broad DLL injection across all GUI processes without per-process injection operations
- **How**:
  1. Escalate to local Admin (HKLM write required)
  2. Set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` (REG_SZ) = comma-separated DLL paths
  3. Set `LoadAppInit_DLLs` (REG_DWORD) = 1
  4. For 32-bit targets, also set under `Wow6432Node\...\Windows`
  5. **Critical**: DLL must check a global mutex before any `CreateProcess` call to prevent infinite loop (DLL → CreateProcess → new process loads DLL → CreateProcess → ...)
  6. Next process creation linked against user32.dll loads the DLL
- **Vault link**: Not implemented in vault. The vault's T-007 Pool Party / T-012 Early Cascade provide process injection without the global injection footprint of AppInit. AppInit is also MITRE T1546.010 — heavily monitored. Vault's choice to omit reflects modern OPSEC reality.
- **Tool/code**: `RegSetValueExA`
- **OPSEC**: Detected by Autoruns. Affects every GUI process — extremely noisy. AppInit DLLs are also flagged by many EDRs as a known persistence vector. The infinite-loop footgun is real and operators must handle it.

### AppCert DLLs (CreateProcess Hook)

- **What**: Register DLLs to be loaded into any process calling CreateProcess-family APIs
- **When to use**: Hooking process creation across the system for monitoring or interception
- **How**:
  1. Escalate to local Admin
  2. Add DLL path under `HKLM\SYSTEM\CurrentControlSet\Current\Session Manager\AppCertDlls`
  3. DLL must export `CreateProcessNotify` function
  4. **Reboot required** for changes to take effect
  5. On next boot, any process calling `CreateProcess`/`CreateProcessAsUser`/`CreateProcessWithLogin`/`CreateProcessWithToken`/`WinExec` will load the DLL
- **Vault link**: Not implemented. Vault's process-creation interception needs are handled via T-016 handle blocking (`block_handle.rs`) and direct syscall invocation rather than registry-based DLL injection.
- **Tool/code**: `RegSetValueExA`, standard DLL with `CreateProcessNotify` export
- **OPSEC**: Reboot requirement is a non-starter for live operations. Detected by Autoruns. MITRE T1546.009. Used by Honeybee and PUNCHBUGGY historically.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| Volatility | Memory dump analysis framework | Operator threat — IR/sandbox can extract implant from RAM dump |
| PE-sieve (Hasherzade) | Live process scanner for injected/unbacked memory | Detects most injection methods; vault's Ekko ROP Sleep (T-005) and module stomping (T-016) counter it |
| Moneta (forrest-orr) | User-mode Windows memory analysis | Reportedly bypassed by MDSec Nighthawk; vault's stomping primitives achieve similar |
| Autoruns (Sysinternals) | Autostart location enumeration | Detects Run/RunOnce/AppInit/AppCert instantly; vault's schtask/COM hijack/NTFS EA layers are stealthier |
| Themida (Oreans) | Commercial PE protector/packer | Annoys reverse engineers; doesn't bypass AV/EDR behavioral detection |
| Skrull (github.com/aaaddress1/Skrull) | Malware DRM via Process Ghosting | Anti-copy launchers; broken when submitted to cloud AV. Vault's T-009 Process Ghosting is the underlying technique |
| `RegSetValueEx` | Win32 API for registry value creation | Heavily monitored by EDR for persistence paths |
| `LoadAppInitDlls` (Kernel32 import) | Trigger for AppInit DLL loading | Called by user32.dll on every process init |
| `MZ\x90\x00` (`\x4d\x5a\x90\x00`) | PE image signature for in-memory scanning | More specific than `MZ` alone; reduces false positives |
| EternalBlue / DoublePulsar | Historical fileless exploit example | SMB kernel-mode backdoor, never touched disk |
| Red Balloon Security HDD challenge | Hardware persistence research | Firmware-level implants beyond software EDR reach |

## Gaps & Extensions

### What the vault covers that SEC670 does not
- **Resilience monitoring** (T-017 PhantomPersist): 30-minute health check loop that re-establishes burned persistence. SEC670 only covers the "two is one" principle in the abstract; the vault implements it.
- **Polymorphic persistence resurrection** (T-018 Edo Tensei): Automatically rotates between persistence techniques as they are discovered/burned. SEC670 has no equivalent.
- **Autonomous dead-drop C2** (T-019 Edo Dead Drop): Google Translate/blockchain/steganography channels for when primary C2 is lost. SEC670 assumes traditional callback model.
- **Modern persistence layers** (T-017): COM hijack, NTFS Extended Attributes, TLS callbacks, scheduled tasks — all stealthier than Run/AppInit/AppCert that SEC670 emphasizes.
- **Advanced AMSI bypass** (T-016): HW breakpoint-based AMSI bypass — no memory modification, no signature. SEC670 only covers byte-patch approach.
- **Ekko ROP Sleep** (T-005): Encrypts implant memory during sleep to defeat PE-sieve/Moneta. SEC670 acknowledges memory forensics as a threat but offers no countermeasure.
- **Process Ghosting implementation** (T-009): SEC670 references Skrull (which uses Process Ghosting) but does not teach the technique itself.
- **BYOVD** (T-018 vault): Bring-your-own-vulnerable-driver for kernel operations — extends well beyond the firmware persistence mention in SEC670.

### What SEC670 covers that the vault does not
- **On-disk binary patching tradecraft**: The vault deliberately avoids this (correctly, for OPSEC reasons), but SEC670's discussion of the cascading effect, system stability risks, and rollback considerations is operationally useful context for understanding *why* the vault avoids it.
- **AppInit_DLLs and AppCert DLLs**: Not in vault. While noisy, they are operationally simple and useful in legacy or low-EDR environments. Operators targeting OT/ICS or older Windows builds may still find these viable.
- **Run/RunOnce keys**: Not in vault (vault uses schtask instead). Operators need Run key for engagements where schtasks are heavily monitored or where Run key is more compatible with target environment.
- **Strategic drop-location heuristics**: The vault does not codify rules about file-count density, prefix-matching, or timestamp-matching for drop locations. SEC670's heuristics are operationally useful and should be adopted as operator tradecraft even when using vault primitives.
- **Memory forensics tooling landscape**: SEC670's naming of PE-sieve, Moneta, and Volatility as the primary threats gives operators a concrete list of what to defeat. The vault's techniques counter these but do not explicitly name them.
- **Firmware/BIOS persistence**: Mentioned only conceptually by SEC670 (Red Balloon HDD challenge, BadUSB). The vault does not address firmware-level persistence at all — this is a true gap if targeting hardware-resident footholds.
- **Skrull-style anti-copy DRM**: The vault's T-009 Process Ghosting does not implement the anti-copy property that Skrull adds. This is a unique SEC670 insight worth borrowing.

### Supersession notes
- SEC670's in-memory execution treatment is **superseded** by vault T-007/T-012/T-013 injection primitives — operators should use vault implementations.
- SEC670's in-memory patching for AMSI is **superseded** by T-016's HW breakpoint bypass — strictly better OPSEC.
- SEC670's Run key persistence is **not superseded** but is **de-emphasized** — vault's schtask layer is stealthier, but Run key remains a valid fallback.
- SEC670's on-disk patching is **deliberately not implemented** in the vault due to OPSEC concerns; vault stance is the correct one for modern EDR'd environments.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Fileless execution concept | T-013 Remaining Injection (PE loader, mapping, callback, fiber) | Vault provides operational implementations of fileless execution; SEC670 only defines the concept |
| Reflective DLL Injection (mentioned) | T-013 `pe_loader.rs` (reflective PE loader) | Vault implements; SEC670 defers to Section 5 |
| EternalBlue/DoublePulsar examples | (none directly) | Historical examples; vault does not cover kernel exploitation |
| Memory forensics threat (PE-sieve, Moneta) | T-005 Ekko ROP Sleep, T-016 PE stomping/module stomping | Vault primitives are direct countermeasures; SEC670 names the threat |
| Strategic disk drop heuristics | T-017 PhantomPersist | Vault handles resilience; SEC670 handles initial placement strategy — complementary |
| Skrull anti-copy DRM via Process Ghosting | T-009 Process Ghosting | Vault implements the ghosting primitive but not the anti-copy DRM property |
| Themida packer reference | T-021 AES-GCM+zstd, T-021 string obf proc macro | Vault uses compile-time obfuscation + crypto instead of runtime packers — different tradecraft philosophy |
| In-memory AMSI patching (byte patch) | T-016 `amsi_hbp.rs` (HW breakpoint bypass), `amsi_page_guard.rs` | Vault strictly superior — no memory modification signature |
| In-memory ETW patching | T-016 `etw.rs` (ETW muffling) | Vault implements the equivalent |
| On-disk binary patching | (none) | Vault deliberately omits; SEC670 covers as tradecraft context |
| Registry Run key (T1547.001) | T-017 schtask layer | Vault uses scheduled tasks instead; Run key not implemented |
| Registry RunOnce key | T-017 schtask (`/SC ONCE` configuration) | Vault's schtask layer can serve the same staging role |
| AppInit_DLLs (T1546.010) | (none) | Not in vault; SEC670-only; useful for legacy/low-EDR environments |
| AppCert DLLs (T1546.009) | (none) | Not in vault; SEC670-only; high OPSEC cost, reboot requirement |
| "One is none, two is one" principle | T-017 5-layer suite, T-018 Edo Tensei | Vault operationalizes the principle; SEC670 states it |
| Reboot volatility problem | T-017 PhantomPersist + 30-min monitor | Vault explicitly solves; SEC670 describes the problem |
| NTDLL on-disk patching warning | T-016 `ntdll_unhook_inject.rs`, `ntdll_unhook.rs` (in-memory unhook) | Vault's in-memory unhook achieves the goal without the OPSEC/stability risks SEC670 warns about |
| APT references (APT28, APT30, Emotet, FIN7, Lazarus, APT39, T9000, Honeybee, PUNCHBUGGY) | (none directly) | Threat-actor tradecraft references; vault does not catalog APT usage |