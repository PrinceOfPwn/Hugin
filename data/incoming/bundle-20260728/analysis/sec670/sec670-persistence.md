---
id: RTO-persistence-mechanisms
name: Persistence Mechanisms — Services, Port Monitors, IFEO
source: Red Team Ops / SEC670 (SANS)
category: persistence
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T017-persistence-suite, T018-edo-tensei, T019-edo-dead-drop]
tags: [persistence, services, scm, sddl, port-monitor, ifeo, silent-process-exit, registry, win32-api, system-privileges, red-team, sec670]
---

# Persistence Mechanisms — Training Reference

## TL;DR
SEC670 Section 4 ("Persistence: Die Another Day") covers three classic Windows persistence vectors — **services**, **port monitors**, and **Image File Execution Options (IFEO)** — together with the tradecraft to **hide** those primitives (SDDL-based DACL manipulation for services, `System32` placement for port monitors, and silent registry key insertion for IFEO). All three vectors are absent from the vault's T-017 Five-Layer Persistence suite (which uses COM hijack / NTFS EA / schtask / TLS callback / PhantomPersist), making this module a complementary extension that broadens the persistence arsenal rather than overlapping it.

## Key Concepts

1. **Service Control Manager (SCM) as a persistence substrate**
   The SCM governs service lifecycle, restart actions, and failure semantics. Operators can either **create** a new service (`CreateService`) or **modify** an existing one via `ImagePath` / `binPath` / `FailureCommand`. The `SERVICE_FAILURE_ACTIONS` struct (set with `ChangeServiceConfig2` + `SERVICE_CONFIG_FAILURE_ACTIONS`) is the cleanest primitive: a failed service will trigger `lpCommand` via `CreateProcess` under the service's identity (often SYSTEM). No new artifacts beyond a config change.
   *Vault link*: T-017 covers schtask persistence but not SCM-based persistence. SCM is a distinct persistence substrate worth integrating.

2. **Service "failure" semantics are operator-controlled**
   A service is deemed failed when it (a) terminates without sending `SERVICE_STOPPED`, or (b) returns a non-`ERROR_SUCCESS` `Win32ExitCode` in `SERVICE_STATUS`. This means an operator-controlled service can deliberately fail (or appear to) to fire the `FailureCommand` — useful for re-triggering on demand without rebooting.

3. **SDDL (Security Descriptor Definition Language) for service hiding**
   Service hiding is achieved by manipulating the service's security descriptor via SDDL strings — no kernel driver, no hooking. By denying `DC`, `LC`, `WP`, `DT`, `SD` to interactive users, service users, and built-in admins, the service becomes invisible to `sc.exe`, `Get-Service`, and similar enumerators. SDDL syntax: `O:owner G:group D:(dacl_flags)(ace_strings) S:(sacl_flags)(ace_strings)`.

4. **Port Monitors as SYSTEM-backed persistence**
   Print Spooler (`spoolsv.exe`, runs as SYSTEM) loads DLLs registered under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>\Driver`. The DLL **must** reside in `C:\Windows\System32`. Two installation paths: manual registry edit (requires reboot) or `AddMonitor` API (immediate, no reboot). Both require local admin.

5. **IFEO — `Debugger` value**
   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<TargetExe>\Debugger` redirects execution of `<TargetExe>` to whatever binary the operator specifies. Classic primitive for hijacking frequently-launched binaries (e.g., `userinit.exe`, `taskmgr.exe`, third-party autostart apps).

6. **IFEO — Silent Process Exit**
   A second IFEO variant. Set `GlobalFlag = 0x200` (`FLG_MONITOR_SILENT_PROCESS_EXIT`) on the target image and register a `MonitorProcess` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<ProcessName>`. Fires the monitor process when the watched process exits — opposite trigger condition vs. `Debugger` (start vs. exit).

7. **Admin / SYSTEM is the floor for all three techniques**
   Each technique requires writing to `HKLM` registry hives or `C:\Windows\System32`. Pre-requisite is local admin (port monitor, IFEO) or existing privileged service context (creating a new service). Operators must chain a privilege escalation primitive first — the vault's T-017 escalation path (slui.exe / CMSTP UAC bypass) is the natural precursor.

## Operational Techniques

### 1. Service Persistence via FailureCommand
- **What**: Set `lpCommand` in `SERVICE_FAILURE_ACTIONS` on a (new or existing) service so that SCM launches an arbitrary command when the service fails.
- **When to use**: Already SYSTEM/Admin on host; want a re-fireable persistence trigger that survives reboots and doesn't need a new executable in autostart chains.
- **How**:
  1. `OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE)` → SCM handle.
  2. `CreateService(...)` with `lpBinaryPathName` pointing to operator binary; `SERVICE_AUTO_START`, `SERVICE_ERROR_NORMAL`.
  3. Zero out `SERVICE_FAILURE_ACTIONSA sfa;`
  4. `sfa.dwResetPeriod = INFINITE;`
  5. `sfa.lpRebootMsg = "";` (empty string suppresses reboot toast; `NULL` keeps default).
  6. `sfa.lpCommand = "cmd.exe /c <operator command>";` (or a `ping C2` beacon).
  7. `sfa.cActions = 0; sfa.lpsaActions = NULL;`
  8. `ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);`
  9. Trigger by terminating the service without sending `SERVICE_STOPPED`, or by returning non-zero `Win32ExitCode` from `ServiceMain`.
- **Vault link**: T-017 (schtask persistence is the closest analog — both re-fire triggers but FailureCommand executes under SCM context, not Task Scheduler).
- **Tool/code**: `sc.exe failure <svc> cmd= "..."`, `ChangeServiceConfig2A`, `SecureZeroMemory`.
- **OPSEC**: Adds/changes one service. New service is visible via `sc query`, `Get-Service`, `services.msc` until hidden (see below). Event IDs 7036/7034 (service stop/crash) and 7000 (service start failure) fire on every failure-trigger cycle — disable these in the C2 malleable profile if the host has SIEM forwarding.

### 2. Hide a Service via SDDL
- **What**: Rewrite the service's security descriptor to deny list/read/delete to interactive users, service users, and built-in admins.
- **When to use**: After installing the persistence service; want it to disappear from `sc.exe`, `Get-Service`, `services.msc`.
- **How** (manual, Joshua Wright's real-world SDDL string):
  ```
  sc.exe sdset <SvcName> D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
  ```
  - Deny ACEs (`D;;DCLCWPDTSD;;;`) for `IU` (interactive user), `SU` (service logon user), `BA` (built-in admins): block delete / list children / write property / delete tree / standard delete.
  - Allow ACEs (`A;;...`) for `SY` (LocalSystem) and `BA` retain operational rights.
  - SACL audits failure access for `WD` (Everyone) — useful as a tripwire mask, not strictly needed for hiding.
- **Restore (cleanup)**:
  ```
  sc.exe sdset <SvcName> D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
  ```
- **How (programmatic)**:
  1. `GetNamedSecurityInfoA(pObjectName=<svc>, ObjectType=SE_SERVICE, SecInfo=OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION, ...)` — retrieve current SD.
  2. Build `EXPLICIT_ACCESS_A[]` entries with `TRUSTEE_A` per `ACCESS_MODE = DENY_ACCESS` for `IU`/`SU`/`BA` and `GRANT_ACCESS` for `SY`/`BA`.
  3. `SetEntriesInAcW(...)` to merge into a new ACL.
  4. `SetNamedSecurityInfoA(pObjectName=<svc>, ObjectType=SE_SERVICE, SecInfo=DACL_SECURITY_INFORMATION, pDacl=<new>)`.
  - Headers: `securitybaseapi.h`, `aclapi.h`.
- **Vault link**: T-017 does not currently cover service hiding. Vault's block-handle / PEB-unlink patterns (T-016) hide processes; SDDL hides services — analogous primitive, different object class. Could be ported to the vault as a new persistence-layer tradecraft.
- **Tool/code**: `sc.exe sdshow`, `sc.exe sdset`, `GetNamedSecurityInfoA`, `SetNamedSecurityInfoA`, `SetEntriesInAcl`, `EXPLICIT_ACCESS_A`, `TRUSTEE_A`, `ConvertSecurityDescriptorToStringSecurityDescriptor` / `ConvertStringSecurityDescriptorToSecurityDescriptor`.
- **OPSEC**: Forensic defenders with SYSTEM can still enumerate hidden services via direct registry reads of `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` or by querying SCM with `SERVICE_ENUMERATE_ALL` and bypassing DACL by impersonating SYSTEM. Don't rely on SDDL alone — pair with a renamed service binary and impersonated service description.

### 3. Port Monitor Persistence (Registry)
- **What**: Drop a DLL into `C:\Windows\System32` and register it under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>` with `Driver = <dllname.dll>`. Spooler loads it as SYSTEM on next boot.
- **When to use**: Long-dwell engagement where a reboot is expected (scheduled corporate reboot, Windows Update patch Tuesday).
- **How**:
  1. `MoveFileEx` / `CopyFile` payload DLL into `C:\Windows\System32\<name>.dll`. **Path is enforced** — System32 is the only allowed location.
  2. Create registry key `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>`.
  3. Add REG_SZ value `Driver = <name>.dll` (filename only, not full path).
  4. Wait for `spoolsv.exe` restart (reboot or `net stop spooler && net start spooler`).
  5. DLL's `DllMain` (or exported monitor entrypoints like `InitializeMonitor`, `OpenPort`) executes in `spoolsv.exe` context as SYSTEM.
- **Vault link**: T-017 does not currently cover port monitor persistence. Different from COM hijack (T-017) — port monitor is a kernel-bridged DLL load, not an in-process COM server swap.
- **Tool/code**: `reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<Name> /v Driver /t REG_SZ /d <name>.dll`, `regedit.exe`.
- **OPSEC**: Print Spooler has had a long abuse history (PrintNightmare). EDRs with spooler-specific telemetry (e.g., Sysmon Event ID 7 image-load for `spoolsv.exe`) will catch unsigned / untrusted DLL loads. Sign the payload DLL, prefer a known-good proxy DLL pattern (cf. T-016 proxy DLL). The registry key itself is a IOC — defender baseline scan for new `Print\Monitors` subkeys is common.

### 4. Port Monitor Persistence (AddMonitor API)
- **What**: Same outcome as the registry method but installed via the `AddMonitor` Win32 API — no reboot required, takes effect immediately on next spoolsv.exe load (often on-the-fly).
- **When to use**: Live engagement where rebooting the host is not viable; need persistence to land before user's next login.
- **How**:
  1. Ensure payload DLL is in `C:\Windows\System32`.
  2. Configure `MONITOR_INFO_2`:
     - `pName = "Sauron"` (or arbitrary).
     - `pEnvironment = "Windows x64"` (must match target arch — `Windows NT x86` for 32-bit).
     - `pDLLName = "NotEvil.dll"` (DLL filename, must be System32-resident).
  3. `AddMonitor(NULL, 2, (LPBYTE)&mInfo2);` — `Level` must be 2.
  4. Spooler loads DLL immediately (no reboot).
- **Vault link**: Not in T-017. Could be added as a programmatic counterpart to the registry variant.
- **Tool/code**: `AddMonitor` (winspool.h), `MONITOR_INFO_2`, winspool.lib / `AddMonitorW`.
- **OPSEC**: Generates the same registry artifact as the manual method plus the immediate spoolsv image-load event. EDR signature on `AddMonitor` calls from non-spooler-UI processes is increasingly common — call from a process that legitimately touches spooler subsystem if possible.

### 5. IFEO — `Debugger` Persistence
- **What**: Set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<TargetExe>\Debugger = "<operator binary> <args>"`. Whenever `<TargetExe>` is launched, Windows launches the Debugger binary instead with `<TargetExe>`'s command line appended.
- **When to use**: Want to fire payload on user/system invocation of a known frequently-run binary (e.g., `userinit.exe`, `sethc.exe`, `utilman.exe`, `taskmgr.exe`, or a third-party autostart binary).
- **How** (manual):
  ```
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<TargetExe>" /v Debugger /t REG_SZ /d "C:\Path\To\implant.exe"
  ```
  (Programmatic): `RegOpenKeyExA` → `RegCreateKeyExA` → `RegSetValueExA` with `REG_SZ` type.
- **Vault link**: T-017 currently uses COM hijack / NTFS EA / schtask / TLS callback / PhantomPersist — IFEO is a natural sixth layer. Worth integrating into T-017's resilience monitor pattern.
- **Tool/code**: `reg.exe add`, `RegOpenKeyExA`, `RegCreateKeyExA`, `RegSetValueExA`. Sysinternals `Process Explorer → Options → Replace Task Manager` is the same primitive (legitimate use case).
- **OPSEC**: `Debugger` value under `Image File Execution Options` is a known IoC; many EDRs flag writes to it. The target executable **does not launch** — only the debugger runs — which is visible in Event Tracing and Procmon. Pick a target binary that exists in the user's natural workflow but isn't critical (avoid `userinit.exe` if it breaks logon — pick a third-party autostart app instead). Cleanup: delete the `Debugger` value before exfil.

### 6. IFEO — Silent Process Exit Persistence
- **What**: Configure Windows to invoke a `MonitorProcess` when a watched image exits cleanly (without `TerminateProcess`). Useful when the operator wants payload to fire on process termination rather than on process start.
- **When to use**: Target process exits at predictable times (e.g., `outlook.exe` closing, logoff cascade). Payload re-execution on user shutdown of a long-running app.
- **How** (manual):
  ```
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<TargetExe>" /v GlobalFlag /t REG_DWORD /d 512
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<TargetExe>" /v ReportingMode /t REG_DWORD /d 1
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<TargetExe>" /v MonitorProcess /d "C:\Path\To\implant.exe"
  ```
  - `GlobalFlag = 0x200` (`FLG_MONITOR_SILENT_PROCESS_EXIT`).
  - `ReportingMode`: `1` = launch monitor process. Other bits: `2` = enable notification, `4` = enable dump generation.
  - Programmatic: `gflags.exe` GUI / `GflagsX` (Pavel Yosifovich, https://github.com/zodiacon) — silent exit tab is under the Image tab in GflagsX.
- **Vault link**: Not in T-017. Complement to T-017's TLS callback (which fires on process load) — silent exit fires on process unload. The two together cover both ends of a target process' lifecycle.
- **Tool/code**: `reg.exe add`, `gflags.exe` (Windows SDK path: `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`), `GflagsX`. Programmatic via standard Registry APIs.
- **OPSEC**: Less noisy than `Debugger` — the target binary still launches and runs normally. Trigger is the silent exit event (process exits without `TerminateProcess`), so an operator that knows the user workflow can predict firing. Event 4660 (handle to object deleted) and SilentProcessExit telemetry from WerFault.exe can be signatured. Cleanup: delete the `SilentProcessExit\<TargetExe>` subkey and clear the `GlobalFlag` value.

## Tool & Tradecraft Reference

| Tool / Command / API | Purpose | OPSEC Notes |
|---|---|---|
| `sc.exe` (sdshow, sdset, failure, config, create) | Service enumeration, security descriptor read/write, failure config | DACL modifications show in `Security` event log with 4670 (permissions changed). |
| `ChangeServiceConfig2A` (`SERVICE_CONFIG_FAILURE_ACTIONS`) | Set `lpCommand` for service-failure trigger | Event ID 7034 (service crashed) on trigger fire. |
| `SERVICE_FAILURE_ACTIONSA` struct | Failure-action descriptor | `dwResetPeriod = INFINITE` keeps failure count persistent. |
| SDDL string: `D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)...` | Hide service from `IU`/`SU`/`BA` | Bypassable by SYSTEM-impersonating scanner; pairs with binary impersonation. |
| `GetNamedSecurityInfoA` / `SetNamedSecurityInfoA` | Programmatic SD read/write for `SE_SERVICE` objects | Same DACL behavior as `sc.exe sdset`. |
| `SetEntriesInAcl` + `EXPLICIT_ACCESS_A` | Build merged ACL with deny+allow ACEs | Must precede `SetNamedSecurityInfo` call. |
| `reg.exe add` for `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<Name>` | Port monitor registration | Registry-only method requires reboot; spooler starts DLL on next spoolsv cycle. |
| `AddMonitor` / `MONITOR_INFO_2` | Programmatic port monitor install | No reboot; immediate load; `Level` must be 2; `pEnvironment` must match target arch (`Windows x64`). |
| `C:\Windows\System32\<payload>.dll` | Required DLL location for port monitor | System32 writes are EDR-relevant; consider proxy DLL pattern (cf. T-016). |
| `reg.exe add` for `Image File Execution Options\<TargetExe>\Debugger` | IFEO Debugger persistence | EDR-flagged write; target process does NOT launch — only Debugger does. |
| `reg.exe add` for `GlobalFlag = 0x200` + `SilentProcessExit\<TargetExe>\{ReportingMode=1, MonitorProcess=<path>}` | IFEO Silent Process Exit persistence | Target binary launches normally; fires on natural exit; Event 4660 telemetry. |
| `gflags.exe` (`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`) | Sysinternals GUI for GlobalFlag + SilentProcessExit | SDK binary — operating with it on-target is itself an IOC if executed from non-standard context. |
| `GflagsX` (Pavel Yosifovich, https://github.com/zodiacon) | Modern gflags alternative | Public tool; presence on target unusual outside dev context. |
| `RegOpenKeyExA` / `RegCreateKeyExA` / `RegSetValueExA` | Programmatic IFEO/Port Monitor/Service registry edits | Use direct registry writes over `reg.exe` for tradecraft consistency and OPSEC. |
| `services.msc` / `Get-Service` / `sc query` | Defender/operator enumeration surface — all blind to SDDL-hidden services | Don't rely on these for hide-checking; use `reg query HKLM\SYSTEM\CurrentControlSet\Services` directly. |

## Gaps & Extensions

### What the vault covers that this training does NOT
- **T-017 Five-Layer Persistence Suite**: COM hijack, NTFS Extended Attributes, scheduled tasks (different from services), TLS callbacks, PhantomPersist + 30-minute resilience monitor — none of these are mentioned in SEC670 Section 4. The vault's schtask layer is the closest overlap but uses a different scheduler subsystem.
- **T-018 Edo Tensei**: Polymorphic resurrection engine — automatically reconstitutes a randomized persistence stack after cleanup. SEC670 has no equivalent dynamic / re-randomization tradecraft.
- **T-019 Edo Dead Drop**: Autonomous C2 via Google Translate / Ethereum Sepolia / steganography. SEC670's persistence triggers fire on local system events only; no dead-drop / autonomous re-contact path.
- **T-016 EDR Evasion Suite**: The training notes treat persistence as a registry / SCM config exercise and do not address EDR hooks, AMSI/ETW, stack spoofing, etc. Operators using SEC670 primitives in isolation will leave telemetry; pair with T-016 techniques for any modern engagement.

### What this training covers that the vault does NOT
- **SCM-based persistence** (services + `SERVICE_FAILURE_ACTIONS` + `ChangeServiceConfig2`) — completely absent from the vault. The vault's persistence layers do not leverage the Service Control Manager.
- **SDDL service hiding** — no equivalent primitive in the vault. The vault's process-hiding (PEB unlink, block-handle) does not extend to services. This is a high-value addition for persistence-layer stealth.
- **Port Monitor persistence** (registry and `AddMonitor` API variants) — absent. Distinct from any existing T-017 layer.
- **IFEO persistence** — both `Debugger` and `SilentProcessExit` variants are absent. These are the only primitives in either source that fire on **process termination** (SilentProcessExit), complementing T-017's TLS callback (which fires on process load).
- **`gflags.exe` / `GflagsX` tradecraft** — utility-focused operational tooling not mentioned in the vault.

### Recommended vault extensions
1. **New card T-024 SCM Persistence**: Cover `CreateService`, `ChangeServiceConfig2` with `SERVICE_FAILURE_ACTIONS`, the "deliberate-fail" trigger pattern.
2. **Extend T-017 with SDDL hiding tradecraft**: Pull the Joshua Wright SDDL string and the `GetNamedSecurityInfoA`/`SetNamedSecurityInfoA`/`SetEntriesInAcl` programmatic path into the persistence-layer stealth section.
3. **New card T-025 Port Monitor Persistence**: Both registry and `AddMonitor` variants.
4. **Extend T-017 with IFEO layers**: Both `Debugger` (start trigger) and `SilentProcessExit` (exit trigger) — gives the persistence suite both load-side and unload-side triggers, complementing TLS callback's load-side trigger.
5. **Operational guidance**: Make IFEO `SilentProcessExit` the recommended variant over `Debugger` for stealth (target binary runs normally — better OPSEC).

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `CreateService` / `ChangeServiceConfig2` / `SERVICE_FAILURE_ACTIONS` | (no vault card — recommended T-024) | Vault lacks SCM-based persistence entirely. SEC670 is the canonical reference. |
| Service hiding via SDDL (`sc.exe sdset` + `GetNamedSecurityInfoA`/`SetNamedSecurityInfoA`) | T-016 (block-handle, PEB unlink for processes) | Vault hides processes; SEC670 hides services. Analogous primitive, different object class. Vault extension recommended. |
| Port Monitor registry method (`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`) | (no vault card — recommended T-025) | Vault persistence suite has no spooler-backed layer. |
| Port Monitor API method (`AddMonitor` / `MONITOR_INFO_2`) | (no vault card) | Programmatic counterpart to the registry method. |
| IFEO `Debugger` value | T-017 (schtask persistence layer is closest analog) | Both are autostart triggers but IFEO hijacks a binary launch, schtask is scheduler-driven. Vault extension recommended. |
| IFEO `SilentProcessExit` (`GlobalFlag=0x200`, `MonitorProcess`) | T-017 TLS callback (process-load trigger) | TLS callback fires on load; SilentProcessExit fires on unload. Complementary pair covering both ends of target process lifecycle. |
| `gflags.exe` / `GflagsX` GUI tradecraft | (no vault equivalent) | Vault has no GUI tradecraft for IFEO configuration. |
| Privilege prerequisite (Admin / SYSTEM) | T-017 escalation path (slui.exe / CMSTP UAC bypass — `src/escalation/uac.rs`, `src/experimental/harvest/uac_cmstp.rs`) | SEC670 assumes privileges; vault provides the escalation primitive to satisfy that precondition. |
| `CreateProcess` invocation by SCM (`lpCommand`) | T-014 `NtCreateUserProcess` direct | Different process-creation path: SCM-internal `CreateProcess` vs. operator-direct `NtCreateUserProcess`. |
| Service binary on disk in System32 / DLL payload in System32 | T-016 proxy DLL / T-013 self-deletion (ADS) | Proxy DLL pattern from T-016 is the correct OPSEC wrapper for both port monitor DLLs and service binaries dropped to System32. |
| Cleanup / unhide commands (e.g., `sc.exe sdset <svc> D:(A;;...;;SY)...`) | T-017 resilience monitor (auto-cleanup-aware) | Vault has the cleanup-as-first-class-citizen mindset; SEC670's restore SDDL string is one example artifact in that discipline. |
| Service failure as re-trigger | T-018 Edo Tensei (polymorphic resurrection) | Edo Tensei auto-resurrects the persistence stack on cleanup; SEC670's failure-action re-triggers on service crash. Both are re-fire patterns but at different abstraction layers (stack vs. single service). |