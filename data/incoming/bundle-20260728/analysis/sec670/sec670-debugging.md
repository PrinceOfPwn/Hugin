---
id: RTO-sec670-wmi-persistence
name: WMI Event Subscriptions & Persistence Bootcamp
source: Red Team Ops / SANS SEC670
category: persistence
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T017, T023, T021]
tags: [wmi, persistence, event-subscription, appinit-dlls, ifeo, silentprocessexit, services, wql, com, sysmon-evasion, system-escalation]
---

# WMI Event Subscriptions & Persistence Bootcamp — Training Reference

## TL;DR
SEC670 Section 4 covers Windows persistence tradecraft with a deep dive on WMI event subscriptions as an autonomous SYSTEM-privileged trigger mechanism. The module also reviews registry-based persistence (SilentProcessExit, IFEO, AppInit_DLLs) and service hiding, then consolidates them via four bootcamp labs. The vault's T-017 covers five persistence layers but **does not implement WMI event subscriptions, AppInit_DLLs, or service hiding** — these are significant gaps to fill.

## Key Concepts

1. **WMI as attack substrate**
   WMI is the Windows instrumentation layer exposing CIM-standard classes (Win32_Process, Win32_Service, Win32_Registry, etc.) consumable from C++ or PowerShell via COM. Operators care because WMI persists data across reboots in the repository (`%SystemRoot%\System32\wbem\Repository`), accepts method invocations (Win32_Process.Create), and runs event consumers as **SYSTEM** — giving both persistence and LPE in one primitive. Not covered in the vault; T-023 only implements WMI execution as a recon primitive.

2. **Intrinsic vs Extrinsic WMI events**
   Intrinsic events (`__InstanceCreationEvent`, `__InstanceModificationEvent`) fire on changes to objects in the WMI repository and **require polling** via `WITHIN <seconds>`. Extrinsic events (e.g. `RegistryKeyChangeEvent`) fire from non-repository sources and do not need polling. Choosing intrinsic means accepting the polling-interval noise; extrinsic is cleaner but the available providers are limited.

3. **WQL (Windows Query Language)**
   SQL-subset used to write Data, Event, or Schema queries. Event queries use `WITHIN` to set the polling interval; `TargetInstance ISA` filters the class; `TargetInstance.Name` filters the instance. Schema queries use `meta_class` and only support `SELECT *`.

4. **Event Filter → Consumer → Binding triad**
   Persistence requires three WMI objects in `root\subscription`:
   - `__EventFilter` — the WQL query
   - `__EventConsumer` subclass — one of `ActiveScriptEventConsumer`, `CommandLineEventConsumer`, `LogFileEventConsumer`, `NTEventLogEventConsumer`, `SMTPEventConsumer`
   - `__FilterToConsumerBinding` — links the two

   The `CommandLineEventConsumer` is the operator-default: instantiates a process when the filter matches, runs as SYSTEM.

5. **Sysmon detection surface**
   Sysmon (with default WMI config) emits `WmiEventConsumer`, `WmiEventFilter`, and `WmiFilterConsumerBinding` events. The technique is **loud against mature EDR/Sysmon** — operators must weigh detection risk vs. the SYSTEM-escalation payoff. Mitigation requires either disabling/tampering Sysmon or running only during windows where WMI telemetry is unmonitored.

6. **Registry persistence primitives (review)**
   - **SilentProcessExit** (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`) — can monitor process exit and trigger actions; useful for protecting footholds.
   - **IFEO** (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`) — `Debugger` value hijacks target binary launch.
   - **AppInit_DLLs** — loads a DLL into any process loading user32.dll; OPSEC-tricky because it can create infinite loops (e.g. when payload itself loads user32).

7. **Service hiding**
   Post-installation stealth via Win32 Service Control Manager API manipulation to remove a service from standard enumeration without breaking its execution. The lab deliberately leaves the specific technique open but emphasizes using "proper Win32 APIs" rather than registry tricks.

8. **Bootcamp composition pattern**
   The four labs (NotInService → InitToWinit → OhMyWMI → CustomShell) form a progression: single-mechanism persistence → multi-mechanism "baby implant" with recon, injection, persistence, and logging. This mirrors the vault's `dark_crystal/crowd` FSM architecture but is implemented in C/C++ rather than Rust.

## Operational Techniques

### WMI Permanent Event Subscription
- **What**: Persistence + LPE primitive that triggers a binary on a WMI-defined condition, executing as SYSTEM.
- **When to use**: Engagement requiring foothold survival across reboot **and** elevation from Admin → SYSTEM. Strong fit when WMI telemetry is unmonitored by the target's stack.
- **How**:
  1. Author the WQL event query. Example (notepad creation, 5s polling):
     ```sql
     SELECT * FROM __InstanceCreationEvent WITHIN 5
     WHERE TargetInstance ISA "Win32_Process"
       AND TargetInstance.Name = "notepad.exe"
     ```
  2. Create the `__EventFilter` instance in `root\subscription` namespace.
  3. Create a `CommandLineEventConsumer` with `ExecutablePath` and `CommandLineTemplate` properties pointing to your payload (`C:\evil.exe`).
  4. Create a `__FilterToConsumerBinding` linking filter and consumer.
  5. Validate with `Get-WmiObject __EventFilter -Namespace root\subscription` (and equivalent for consumer + binding).
- **Vault link**: **T-017 Five-Layer Persistence** — gap. Vault implements COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist but **no WMI subscription layer**. Adding a `wmi_subscription.rs` to `dark_crystal/crowd/src/persist/` would round out the persistence stack. T-017's resilience monitor concept maps directly onto WMI's `__InstanceDeletionEvent` for self-healing.
- **Tool/code**:
  ```powershell
  Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" `
    -Arguments @{ Name='Consumer'; ExecutablePath='C:\evil.exe'; CommandLineTemplate='C:\evil.exe' }
  ```
- **OPSEC**: High. Sysmon WMI events fire by default. Mitigations: (a) choose a benign-looking filter target (system uptime triggers, low-frequency process), (b) prefer `ActiveScriptEventConsumer` with obfuscated JS/VBScript, (c) bind during a window when target SIEM is not ingesting Sysmon Event ID 19/20/21, (d) clean filter/consumer/binding on engagement exit.

### WMI Query Testing (PowerShell)
- **What**: Rapid WQL prototyping via `Get-WmiObject` before committing to compiled C++.
- **When to use**: Always — iterating WQL in compiled code is wasteful.
- **How**:
  ```powershell
  Get-WmiObject -Query "select * from Win32_Process where name='notepad.exe'"
  Get-WmiObject -Query "select * from win32_ntlogevent where eventcode=4625 and logfile='security' and message like '%alice%'"
  ```
  Trigger logon-failure events for testing with:
  ```
  smbclient \\#{target}\C$ -U alice badpassword
  ```
- **Vault link**: No direct vault equivalent — T-023 has `byakugan.rs` recon but no WMI query helper. Pattern worth porting as a `wmi_query` BOF.
- **OPSEC**: Get-WmiObject logs via WMI-Activity/Operational; use direct COM `IWbemServices::ExecQuery` from native code in production.

### Registry-Based Persistence (SilentProcessExit / IFEO)
- **What**: Hijack process exit or launch via registry keys to trigger attacker payloads.
- **When to use**: When WMI is monitored but registry telemetry is not; SilentProcessExit also serves as a **watchdog** for your foothold (detecting when your process dies).
- **How**:
  - **SilentProcessExit**: Configure `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<your_process>` with `ReportingMode` and `MonitorProcess` values to trigger actions on exit.
  - **IFEO**: Set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>.exe\Debugger` to your binary path — every launch of `<target>.exe` instead invokes your binary with the original command line.
- **Vault link**: **T-017 Five-Layer Persistence** — gap. Vault's persistence layers don't include SilentProcessExit or IFEO. Both should be added as `silentprocessexit.rs` and `ifeo.rs` modules in `dark_crystal/crowd/src/persist/`. SilentProcessExit especially complements T-017's PhantomPersist resilience monitor.
- **Tool/code**: Standard Win32 registry APIs (`RegCreateKeyExW`, `RegSetValueExW`).
- **OPSEC**: IFEO Debugger is trivially detected by any registry-diffing tool; reserve for short-foothold scenarios. SilentProcessExit is less commonly monitored but generates Event Log 4688/sx events when triggered.

### AppInit_DLLs Persistence
- **What**: Force any user32-loading process to load your DLL.
- **When to use**: When you want broad DLL injection across many processes without per-process injection code.
- **How**: Create/set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` (REG_SZ) to your DLL path and `LoadAppInit_DLLs` (REG_DWORD) to `1`. Payload DLL must **not** unconditionally load user32 itself or you recurse infinitely.
- **Vault link**: **T-017** gap. Vault has no AppInit module. Should be added — combines naturally with T-021's proxy DLL pattern (`proxy_dll.rs`) to give the loaded DLL a stable EAT facade.
- **Tool/code**: Standard registry APIs; payload DLL must be a real DLL with valid `DllMain`.
- **OPSEC**: AppInit is heavily monitored by EDR (SentinelOne, CrowdStrike flag it). Mitigation: use only as a tertiary persistence layer; pair with T-016's Block-DLL policy to filter which processes actually load it (less reliable). Avoid msfvenom DLLs — they recurse.

### Service Hiding (NotInService lab)
- **What**: Install a service then make it invisible to standard enumeration.
- **When to use**: Persistent service presence without `sc query`/`services.msc` visibility.
- **How**: Use Win32 Service Control Manager APIs (`OpenSCManager`, `CreateService`, `ChangeServiceConfig`) to set the service config in a way that excludes it from default enumeration. The lab is deliberately open-ended — common operator approaches include setting `SERVICE_CONFIG_DESCRIPTION` to empty/null and adjusting service type flags. The training emphasizes **Win32 API route over direct registry patching**.
- **Vault link**: **T-017** gap — no service-based persistence layer. T-017's `schtask.rs` is the closest analog (scheduled task persistence). A `service.rs` module would complement schtask as two SCM-derived primitives.
- **Tool/code**: `advapi32!OpenSCManagerW`, `CreateServiceW`, `ChangeServiceConfig2W`.
- **OPSEC**: Even hidden services generate Service Control Manager event 7036/7040. Pair with T-016's telemetry muffling or stop the service during recon windows.

### Custom Baby Implant (CustomShell lab)
- **What**: Capstone — combine recon, injection, persistence, and logging into one binary.
- **When to use**: Engagement entry point when a full framework (vault's `dark_crystal`) is not warranted.
- **How**: Lab is intentionally open. Required features: full recon, process injection, reboot persistence, log file generation. The vault's `client_rust` is the production-grade realization of this exact lab spec.
- **Vault link**: **T-023 Client Capabilities** is the complete implementation. The lab is essentially a C/C++ re-implementation of what the vault already provides in Rust: `byakugan.rs` (recon), `injection/*` (injection), `persist/*` (persistence), `amaterasu.rs` (exfil/log).
- **OPSEC**: Don't ship a monolithic binary if a modular one is feasible. The vault's feature-gated build (`dark_crystal/crowd` Cargo features) is the correct operator pattern — compile only what the engagement needs.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `Get-WmiObject -Query "<WQL>"` | WQL prototyping | Logs to WMI-Activity/Operational |
| `Get-WmiObject __EventFilter -Namespace root\subscription` | Enumerate installed filters | Recon footprint |
| `Get-WmiObject __EventConsumer -Namespace root\subscription` | Enumerate installed consumers | Recon footprint |
| `Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription` | Enumerate bindings | Recon footprint |
| `Set-WmiInstance -Class CommandLineEventConsumer` | Register consumer via PS | Loud; prefer native COM in production |
| `smbclient \\\\target\\C$ -U alice badpassword` | Generate 4625 events for query testing | Generates auth telemetry |
| `OpenSCManager` / `CreateService` / `ChangeServiceConfig2` | Service install + hide | Generates SCM events 7036/7040 |
| `RegCreateKeyExW` / `RegSetValueExW` | Registry persistence (AppInit/IFEO/SilentProcessExit) | Heavily monitored by EDR |
| Sysmon EIDs 19/20/21 | WMI filter/consumer/binding detection | Operators must assume on |
| WQL `WITHIN <sec>` | Polling interval for intrinsic events | Lower = more CPU/telemetry noise |

## Gaps & Extensions

### Training covers; vault does not
- **WMI permanent event subscriptions** — the single biggest gap. T-017 has five persistence layers, none of which use WMI. This is a high-value addition because WMI subscription uniquely provides **both persistence AND SYSTEM-level execution context** in one primitive.
- **SilentProcessExit** — particularly valuable as a self-healing watchdog for protecting other persistence. Would complement T-017's PhantomPersist resilience monitor.
- **IFEO Debugger** — classic persistence not in vault.
- **AppInit_DLLs** — DLL-load-based persistence; pairs naturally with T-016's `proxy_dll.rs`.
- **Service hiding** — vault's T-017 has schtask persistence but no service-layer primitive.

### Vault covers; training does not
- **NTFS EA persistence** (T-017) — vault-only; SEC670 doesn't touch alternate data streams/EA.
- **TLS callback persistence** (T-017) — vault-only advanced primitive.
- **COM hijack** (T-017) — SEC670's WMI section overlaps conceptually (both COM-based) but the vault's COM hijack is a distinct layer.
- **PhantomPersist + resilience monitor** (T-017) — the vault's self-healing persistence architecture is absent from SEC670.
- **Edo Tensei / Edo Dead Drop** (T-018, T-019) — polymorphic resurrection and autonomous C2 well beyond SEC670 scope.
- **Five-layer composition** — vault composes multiple persistence layers with resilience; SEC670 treats them in isolation.

### Net new modules to add to vault
Based on this training material, the vault should grow:
1. `dark_crystal/crowd/src/persist/wmi_subscription.rs` — `__EventFilter` + `CommandLineEventConsumer` + `__FilterToConsumerBinding` installer via direct COM (avoid Set-WmiInstance).
2. `dark_crystal/crowd/src/persist/silentprocessexit.rs` — registry-based watchdog; tie into T-017's resilience monitor.
3. `dark_crystal/crowd/src/persist/ifeo.rs` — IFEO Debugger hijack.
4. `dark_crystal/crowd/src/persist/appinit.rs` — AppInit_DLLs with T-021 proxy DLL integration.
5. `dark_crystal/crowd/src/persist/service.rs` — SCM-based persistence with hide-via-config.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| WMI permanent event subscription | T-017 Five-Layer Persistence | **Gap** — vault has no WMI layer; add as 6th persistence layer |
| WMI execution as recon | T-023 Client Capabilities (`wmi_exec.rs`) | Vault has WMI exec but only for recon, not persistence |
| CommandLineEventConsumer → SYSTEM exec | T-021 Crypto & Obfuscation (UAC bypass) | Both achieve elevation; WMI subscription is more reliable post-reboot |
| Registry persistence (SilentProcessExit/IFEO) | T-017 Five-Layer Persistence | **Gap** — vault's COM hijack, NTFS EA, schtask, TLS, PhantomPersist don't include registry-value-based hijacks |
| AppInit_DLLs | T-016 EDR Evasion Suite (`proxy_dll.rs`) | Complementary — vault has proxy DLL infrastructure; missing the AppInit trigger |
| Service hiding (NotInService lab) | T-017 Five-Layer Persistence (`schtask.rs`) | Adjacent — vault uses schtask not services; service layer is a missing primitive |
| CustomShell baby implant | T-023 Client Capabilities | Vault is the production realization of this lab spec |
| Sysmon WMI detection (EID 19/20/21) | T-016 EDR Evasion Suite | Vault covers telemetry muffling broadly; specific WMI Sysmon evasion not detailed |
| WQL `WITHIN` polling | T-020 Anti-Analysis Suite | No direct relation; polling generates CPU noise visible to defenders |
| Bootcamp FSM pattern | T-022 Architecture (Crowd FSM) | Vault's 10-state FSM is the production-grade analog of SEC670's "baby implant" progression |
| IFEO Debugger → binary hijack | T-009 Process Ghosting / T-010 Herpaderping | All achieve execution-via-filesystem-manipulation; IFEO is simpler but noisier |

---

**Operator note**: The SEC670 WMI section is dated in its detection model — modern EDRs (CrowdStrike, SentinelOne, Elastic) now natively flag WMI subscription creation without requiring Sysmon. Treat WMI subscriptions as **high-OPSEC-cost** persistence reserved for engagements where you have confirmed the target stack lacks WMI telemetry, or pair with active EDR evasion (T-016 BYOVD or NTDLL unhook) before installing the subscription. The SYSTEM-context payoff is real but the detection risk is no longer "overlooked by defenders" as the 2024 course material suggests.