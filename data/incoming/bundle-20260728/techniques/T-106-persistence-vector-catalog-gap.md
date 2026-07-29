---
id: T-106
name: Persistence Vector Catalog Gap
category: persistence
tier: S
crate: none
source_file: none
mitre: T1546
mitre_secondary: [T1547.001, T1546.010, T1546.009, T1546.012, T1546.003, T1547.010]
tags: [persistence, run-key, appinit, appcert, ifeo, wmi, port-monitor, service-acl, catalog, vector-coverage]
origin: atlas-synthesis
member_notes: ['lgtm:gap-run-key-persistence', 'lgtm:gap-appinit-appcert-ifeo-wmi-persistence', 'lgtm:persistence-suite-coverage-gap', 'lgtm:cross-source-persistence-tradecraft-convergence', 'lgtm:weak-service-acl-persistence']
---

# Persistence Vector Catalog Gap — Expanding the Persistence Surface Beyond T-017's Five Layers

## Summary

The HUGIN vault's T-017 documents five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but the Windows persistence surface extends significantly further. This card catalogs seven additional persistence vectors absent from T-017's enumeration: Run/RunOnce registry keys, AppInit_DLLs, AppCert DLLs, IFEO Debugger values, WMI Event Subscriptions, Port Monitor DLLs, and weak service ACL replacement. Each vector abuses an administrative or debugging feature by redirecting a code path the operating system executes on a scheduled or trigger-based event. All require elevated privileges (Admin or SYSTEM) for HKLM modification, and each has distinct trigger semantics (boot, logon, process-event, scheduled) and detection footprints that operators select among based on the target environment's monitoring profile.

## Mechanism

1. **Run / RunOnce Registry Keys**:
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — executes the registered command at every user logon (system-wide).
   - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — executes at logon for the current user.
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` — executes once at next logon, then the entry is automatically deleted by the shell (`explorer.exe`).
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx` — extended RunOnce with flags for wait and error handling.
   The `Run` key is the most commonly used persistence vector in Windows. The shell (`explorer.exe`) reads these keys during logon via `RegisterApplicationRestart` / shell initialization and executes each value's command string.

2. **AppInit_DLLs**:
   - Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` — semicolon-separated list of DLL paths.
   - Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` — DWORD value (1 to enable, 0 to disable).
   - When `LoadAppInit_DLLs` is set to 1, every process that loads `user32.dll` also loads every DLL listed in `AppInit_DLLs`. The loader (`LdrpInitializeProcess` → `LdrpCodeAuthzCheck` → `LdrpLoadDll` for AppInit) performs this injection during `user32.dll` initialization.
   - On x64 Windows, a separate `AppInit_DLLs` key exists under `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` for 32-bit processes.

3. **AppCert DLLs**:
   - Registry path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` — contains values where each value name is a DLL path and the value data is the DLL filename.
   - DLLs listed here are loaded into any process that uses the `CreateProcess` API family via `AppCertFix` in `kernelbase.dll`. The mechanism attaches to process creation events similarly to IFEO but at a different layer.

4. **IFEO Debugger Values** (overlaps with T-105):
   - Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>\Debugger`
   - When `<target.exe>` is launched, the loader starts the `Debugger` binary instead, passing the original target's path as an argument.
   - Also supports `SilentProcessExit` subkey with `ReportingMode` and `MonitorProcess` values for exit-triggered persistence.

5. **WMI Event Subscriptions**:
   - Namespace: `root\subscription`
   - Three components: `__EventFilter` (defines the trigger condition via WQL query), `__EventConsumer` (defines the action — `CommandLineEventConsumer` for command execution, `ActiveScriptEventConsumer` for script execution), and `__FilterToConsumerBinding` (links filter to consumer).
   - The WMI provider service (`wmiprvse.exe`) evaluates filters and invokes consumers when conditions are met. A common trigger: `SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'` — fires every 5 seconds when any new process is created.
   - WMI subscriptions survive reboot because they are stored in the WMI repository (`%SystemRoot%\System32\wbem\Repository`), a persistent CIM database.

6. **Port Monitor DLLs** (overlaps with T-105):
   - Registry path: `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver`
   - The Print Spooler service (`spoolsv.exe`) loads the named DLL at service start via `LoadLibraryEx`. The DLL must export `InitializePrintMonitor2` and runs as `NT AUTHORITY\SYSTEM`.

7. **Weak Service ACL Replacement**:
   - The operator enumerates services via `OpenSCManager` / `EnumServicesStatusEx` and reads each service's security descriptor via `QueryServiceObjectSecurity` / `sc.exe sdshow <service>`.
   - If the service's DACL grants `SERVICE_CHANGE_CONFIG` (or equivalent write permission) to a group the operator belongs to (e.g., `Authenticated Users`, `Users`), the operator modifies the service binary path via `ChangeServiceConfig` with `SERVICE_CHANGE_CONFIG` → `lpBinaryPathName` pointing to the implant.
   - Alternatively, the operator uses `sc.exe sdset <service> <new_sddl>` to replace the security descriptor, then modifies the binary path.
   - The implant executes when the service is started (manually, on boot if `SERVICE_AUTO_START`, or on trigger if `SERVICE_TRIGGER_START`).

## OS Internals Context

The Windows persistence surface spans multiple OS subsystems. The shell (`explorer.exe`) reads Run/RunOnce keys during its initialization sequence (`SHCreateShellWindow` → shell startup processing). The PE loader (`LdrpInitializeProcess` in `ntdll.dll`) checks IFEO keys in `BasepCheckForRelaunch` (in `kernelbase.dll`) and loads AppInit_DLLs during `user32.dll` initialization via `LdrpCodeAuthzCheck` → `LdrpLoadAppInitDlls`. The `AppCertDlls` mechanism is invoked from `CreateProcessInternalW` in `kernelbase.dll` when the `BasepIsProcessAllowed` check triggers AppCert DLL loading.

The WMI infrastructure is implemented by the WMI service (`wmiprvse.exe`, hosted in `svchost.exe`) and the CIM Object Manager (`CIMOM`). Event filters are evaluated by the `__EventProvider` infrastructure, which polls for `__InstanceCreationEvent`, `__InstanceModificationEvent`, and `__InstanceDeletionEvent` at the interval specified in the WQL `WITHIN` clause. When a filter matches, the consumer is invoked: `CommandLineEventConsumer` calls `CreateProcess` with the `CommandLineTemplate` property, and `ActiveScriptEventConsumer` executes a script via the Windows Script Host (`wscript.exe`).

Service security descriptors are stored in the SCM database (`%SystemRoot%\System32\config\SYSTEM` registry hive, under `HKLM\SYSTEM\CurrentControlSet\Services\<service>\Security`). The DACL controls who can start, stop, and modify the service. The `SERVICE_CHANGE_CONFIG` access right (value 0x0002) allows modification of the binary path, start type, and display name via `ChangeServiceConfig`.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN persistence module (`dark_crystal/crowd/src/persist/`) implements COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist. The vault also has separate atlas-expansion cards for some individual vectors (T-034 for IFEO, T-035 for Port Monitor, T-037 for WMI, T-038 for AppInit_DLLs, T-036 for service-based persistence, T-040 for service failure actions). This card serves as the unified catalog reference. A full implementation for each vector would require: (1) Run/RunOnce: `RegSetValueExA` on the Run key with the implant path; (2) AppInit_DLLs: `RegSetValueExA` on `AppInit_DLLs` and `LoadAppInit_DLLs`; (3) AppCertDlls: `RegSetValueExA` under the `AppCertDlls` key; (4) IFEO: documented in T-105; (5) WMI: COM calls to `IWbemServices::PutInstance` for `__EventFilter`, `CommandLineEventConsumer`, and `__FilterToConsumerBinding`; (6) Port Monitor: documented in T-105; (7) Weak Service ACL: `OpenSCManager` → `OpenService` → `QueryServiceObjectSecurity` → DACL analysis → `ChangeServiceConfig`.

## Why It Matters

The vault's T-017 currently lists only five persistence layers, leaving operators without documented options for seven additional vectors that represent standard red-team tradecraft. The convergence pattern across multiple SEC670 modules confirms that the persistence surface extends well beyond the five T-017 layers and that operators select among vectors based on trigger type (boot vs. logon vs. process-event vs. scheduled), required privilege (HKLM vs. HKCU), and detection footprint (registry write vs. WMI repository modification vs. service config change). This card provides the unified catalog that operators reference when selecting persistence vectors for a specific engagement environment, with explicit trigger, privilege, and detection attributes per vector.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 12/13 (RegistryEvent) captures Run key, AppInit_DLLs, AppCertDlls, IFEO, and Port Monitor registry writes. Sysmon Event ID 19 (WmiFilter), Event ID 20 (WmiConsumer), and Event ID 21 (WmiFilterConsumerBinding) capture WMI event subscription creation. Sysmon Event ID 4 (ServiceConfig) captures service configuration changes. EDR products monitor HKLM Run key writes, AppInit_DLLs modifications, and WMI subscription creation as high-confidence persistence indicators.
- **Bypass options**: For Run keys, writing to `HKCU\Run` avoids HKLM access requirements but only triggers for the current user. For WMI, using `ActiveScriptEventConsumer` with obfuscated VBScript/JScript avoids plaintext command strings. For weak service ACLs, modifying a service that is already configured for auto-start minimizes configuration changes.
- **Residual artifacts**: Run keys leave registry entries visible via `autorunsc` (Sysinternals). AppInit_DLLs leaves a DLL loaded in every user32 process — visible in `Process Explorer` module lists. WMI subscriptions are visible via `wmic.exe path __filter_to_consumer_binding` or `Get-WmiObject` in PowerShell. Port Monitors are visible in the Print Management MMC snap-in. Service ACL changes are visible via `sc.exe sdshow`.

## Related Techniques

- **T-017 Five-Layer Persistence** — the persistence suite this card expands with additional vectors
- **T-034 IFEO GlobalFlag and SilentProcessExit** — dedicated card for IFEO persistence
- **T-035 Port Monitor Persistence via Print Spooler** — dedicated card for Port Monitor persistence
- **T-036 Windows Service-Based Persistence** — dedicated card for service-based persistence
- **T-037 WMI Permanent Event Subscription Persistence** — dedicated card for WMI event subscription persistence
- **T-038 AppInit_DLLs Registry Persistence** — dedicated card for AppInit_DLLs persistence
- **T-044 Service-Based Local Privilege Escalation** — service enumeration for weak ACLs that enables the weak service ACL persistence vector

## References

- Atlas material: atlas-post-exploit-part6 (units 1, 2, 5, 6, 9), atlas-post-exploit-part7 (units 1, 6, 9, 18, 21, 27, 36), atlas-post-exploit-part12 (units 1, 24, 31, 39), atlas-recon-part7 (unit 17), atlas-methodology-part8 (units 16-20, 22, 24)
- MITRE ATT&CK: T1546 (Event Triggered Execution) — https://attack.mitre.org/techniques/T1546
- LGTM notes: lgtm:gap-run-key-persistence, lgtm:gap-appinit-appcert-ifeo-wmi-persistence, lgtm:persistence-suite-coverage-gap, lgtm:cross-source-persistence-tradecraft-convergence, lgtm:weak-service-acl-persistence

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Individual persistence vectors have dedicated atlas Expansion cards (T-034 through T-038) with additional detail.