---
id: T-105
name: IFEO Debugger and Port Monitor DLL Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.012
mitre_secondary: [T1547.010]
tags: [ifeo, port-monitor, persistence, debugger-value, print-spooler, registry, autostart, event-driven, addmonitor, spoolsv]
origin: atlas-synthesis
member_notes: ['lgtm:coverage-gap-persistence-layer-ifoe-portmon-wmi', 'lgtm:ifoe-and-port-monitor-persistence-coverage', 'lgtm:ifeo-and-port-monitor-coverage', 'lgtm:persistence-layer-cross-source-convergence']
---

# IFEO Debugger and Port Monitor DLL Persistence — Two Event-Driven Autostart Mechanisms via Registry and Print Spooler

## Summary

Image File Execution Options (IFEO) Debugger persistence and Port Monitor DLL persistence are two registry-driven autostart mechanisms that trigger on legitimate system events rather than scheduled timers. IFEO persistence writes a `Debugger` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` that redirects process launch into an attacker-specified binary — when the target executable is launched, Windows reads the IFEO key and starts the debugger binary instead, passing the original command line as an argument. Port Monitor persistence installs a DLL via the `AddMonitor()` API into `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver`, which the Print Spooler service (`spoolsv.exe`) loads at spooler initialization. Both require Administrator privileges for HKLM modification and are file-less in the registry-write sense, though both require a DLL or executable on disk to serve as the payload.

## Mechanism

1. **IFEO Debugger persistence** (SEC670 Lab 4.3 'IFEOPersist'):

2. The operator creates or opens the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` via `RegCreateKeyExA` or `NtCreateKey`. The `<target.exe>` is the name of a legitimate executable that the operator expects to be launched by a user or the system (e.g., `userinit.exe`, `sethc.exe`, `magnifier.exe`, `notepad.exe`).

3. The operator writes a string value named `Debugger` under this key. The value data is the full path to the attacker's binary (e.g., `C:\Windows\Temp\implant.exe`). When any process attempts to launch `<target.exe>`, the Windows image loader (`LdrpInitializeProcess` → `DbgUiRemoteBreakin` path) checks the IFEO registry key before creating the process. If a `Debugger` value exists, the loader launches the debugger binary instead, appending the original target's path and command line as arguments: `C:\Windows\Temp\implant.exe <original_target_path> <original_args>`.

4. The attacker's binary receives the original target's path as a command-line argument and can either execute the payload directly or chain: execute the payload, then launch the original target executable transparently to avoid user suspicion.

5. **Port Monitor persistence**:

6. The operator installs a custom Port Monitor DLL by calling the `AddMonitor()` API (exported by `winspool.drv` / `spoolss.dll`):
   ```c
   AddMonitor(NULL, MONITOR_INFO_2, &monitorInfo);
   ```
   The `MONITOR_INFO_2` structure contains:
   - `pName` — monitor name (arbitrary string, e.g., "MaliciousMonitor")
   - `pEnvironment` — "Windows x64" or "Windows NT x86"
   - `pDLLName` — filename of the monitor DLL (e.g., "evilmon.dll")

7. `AddMonitor()` writes the monitor configuration to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<monitor_name>\Driver` with the DLL name as the value. It also creates subkeys for monitor configuration under the `Monitors` key.

8. The Print Spooler service (`spoolsv.exe`) loads all registered Port Monitor DLLs at service initialization via `LoadLibrary` / `LoadLibraryEx`. The spooler calls the monitor DLL's `InitializePrintMonitor2` (or `InitializePrintMonitor` on older systems) export, which receives a function pointer table for spooler callbacks. The attacker's DLL implements this export to gain execution in the context of the spooler service (running as `NT AUTHORITY\SYSTEM`).

9. The monitor DLL can also implement the `Monitor2` structure's function pointers (`pfnOpenPort`, `pfnStartDocPort`, `pfnWritePort`, etc.) to maintain a legitimate monitor facade while executing payload code in `InitializePrintMonitor2` or during port operations.

## OS Internals Context

The IFEO mechanism is implemented in the Windows image loader. When `CreateProcess` / `NtCreateUserProcess` is called, the loader (`LdrpInitializeProcess` in `ntdll.dll`) checks `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<ApplicationName>` for a `Debugger` value. This check occurs in `BasepCheckForRelaunch` (in `kernel32.dll` / `kernelbase.dll`) before the process is created. If the `Debugger` value is present, `BasepCheckForRelaunch` modifies the `CreateProcess` parameters to launch the debugger binary with the original target's path appended. The original target is not launched — the debugger is expected to launch it if desired.

IFEO also supports additional values: `GlobalFlag` (controls heap debugging, verifier, and other debug options), `DebuggerFlags` (bitmask controlling debugger behavior), and `MitigationOptions` / `MitigationAuditOptions` (process mitigation policies). The `SilentProcessExit` subkey under IFEO (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\SilentProcessExit`) supports `ReportingMode` and `MonitorProcess` values that trigger actions when the target process exits — this is documented separately in T-034.

The Print Spooler service (`spoolsv.exe`) is hosted in a generic `svchost.exe` instance grouped with the `Spooler` service group. At service start (`ServiceMain` in `spoolss.dll`), the spooler enumerates `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` subkeys and calls `LoadLibraryEx` on each monitor's `Driver` value. The `MONITOR2` structure (or `MONITOR_INFO_2` for registration) defines 25+ function pointers that the spooler calls for port operations. The `InitializePrintMonitor2` export receives a `LPMONITORINIT` structure containing callbacks for the spooler to communicate back to the monitor DLL.

The Port Monitor DLL runs in the `spoolsv.exe` process, which runs as `NT AUTHORITY\SYSTEM`. Code executing in `InitializePrintMonitor2` has full system-level privileges and access to the spooler's handles, memory, and network connections.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN persistence module (`dark_crystal/crowd/src/persist/`) implements COM hijack (`com_hijack.rs`), NTFS EA (`ntfs_ea.rs`), scheduled task (`schtask.rs`), TLS callback (`tls_cb.rs`), and PhantomPersist (`phantom_restart.rs`), but does not include IFEO or Port Monitor persistence. An IFEO implementation would need: (1) a function that calls `RegCreateKeyExA` to create `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>`, (2) a call to `RegSetValueExA` to write the `Debugger` string value with the implant path, and (3) cleanup logic that deletes the registry key on uninstall. A Port Monitor implementation would need: (1) a DLL project that exports `InitializePrintMonitor2` returning a populated `MONITOR2` structure, (2) a call to `AddMonitor()` or direct registry writes to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver`, and (3) cleanup via `DeleteMonitor()` or registry deletion.

## Why It Matters

T-017 documents five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but does not include IFEO or Port Monitor as persistence vectors. Both are canonical, well-documented Windows persistence primitives with distinct trigger semantics and detection footprints. IFEO is event-driven (triggers on process launch) rather than time-driven (triggers on schedule), making it unpredictable in timing but reliable in execution — the operator knows the payload will execute when the target process is launched, which can be socially engineered or triggered by normal user activity. Port Monitor persistence leverages a system service that auto-starts and runs as SYSTEM, providing reliable, high-privilege execution on every spooler restart (which occurs on reboot or service restart). Both fill gaps in the persistence surface that T-017 does not cover.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 12 (RegistryEvent ObjectCreateKey) and Event ID 13 (RegistryEvent ValueSet) capture IFEO `Debugger` value writes and Port Monitor `Driver` value writes. Sysmon Event ID 7 (ImageLoad) captures the Port Monitor DLL being loaded by `spoolsv.exe`. EDR products that monitor IFEO registry paths generate alerts on `Debugger` value creation. Windows Defender ATP's advanced hunting queries flag IFEO and Port Monitor modifications as persistence techniques.
- **Bypass options**: For IFEO, target executables that are commonly launched (e.g., `notepad.exe`, `calc.exe`) reduce the anomaly of the trigger event. For Port Monitor, using a DLL name that matches a legitimate monitor (e.g., blending with `Local Monitor`, `Standard TCP/IP Port Monitor`, `WSD Port Monitor`) reduces visual detection in the Print Management console.
- **Residual artifacts**: IFEO leaves a registry key under `Image File Execution Options\<target.exe>` with a `Debugger` value. Port Monitor leaves a registry key under `Print\Monitors\<name>\Driver` and a loaded DLL handle in `spoolsv.exe` visible via `Process Explorer` module list. The payload DLL or executable on disk.

## Related Techniques

- **T-017 Five-Layer Persistence** — persistence suite that does not include IFEO or Port Monitor layers
- **T-034 IFEO GlobalFlag and SilentProcessExit** — related IFEO persistence via SilentProcessExit monitor (T-105 covers the Debugger value specifically)
- **T-035 Port Monitor Persistence via Print Spooler** — dedicated card for Port Monitor persistence (T-105 combines IFEO and Port Monitor from the SEC670 curriculum perspective)

## References

- Atlas material: atlas-methodology-part8 (units 16-20, 22, 24), atlas-methodology-part9 (units 20-22, 24-26, 28-30), atlas-post-exploit-part1 (units 13, 34, 35), atlas-post-exploit-part12 (units 1, 24, 31, 39)
- MITRE ATT&CK: T1546.012 (Event Triggered Execution: Image File Execution Options Debugger) — https://attack.mitre.org/techniques/T1546/012
- LGTM notes: lgtm:coverage-gap-persistence-layer-ifoe-portmon-wmi, lgtm:ifoe-and-port-monitor-persistence-coverage, lgtm:ifeo-and-port-monitor-coverage, lgtm:persistence-layer-cross-source-convergence

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.