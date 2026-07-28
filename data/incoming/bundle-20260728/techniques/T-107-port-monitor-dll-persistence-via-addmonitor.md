---
id: T-107
name: Port Monitor DLL Persistence via AddMonitor
category: persistence
tier: A
crate: none
source_file: none
mitre: T1547.010
tags: [persistence, port-monitor, addmonitor, print-spooler, system-privilege, registry, dll-loading, winspool]
origin: atlas-synthesis
member_notes: ['lgtm:port-monitor-persistence-gap', 'lgtm:port-monitor-persistence-coverage']
---

# Port Monitor DLL Persistence via AddMonitor — SYSTEM-Privilege Persistence via Print Spooler

## Summary

The AddMonitor API from winspool.drv registers a custom DLL as a port monitor that the print spooler service (spoolsv.exe) loads at service startup, providing SYSTEM-privilege persistence that triggers on boot rather than user logon. The monitor entry persists in the registry under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors with the DLL path, and the spooler service loads it on every restart. This mechanism differs from logon-triggered persistence because it executes under the print spooler's SYSTEM context and blends with legitimate printer driver installation activity. The AddMonitor call requires SeLoadDriverPrivilege, making it accessible only from an elevated context.

## Mechanism

1. The operator obtains SeLoadDriverPrivilege through token adjustment or prior privilege escalation. AddMonitor validates the caller's token for this privilege before creating the registry entry.
2. A custom DLL is crafted implementing the port monitor interface. The DLL must export InitializePrintMonitor (for legacy monitors) or InitializePrintMonitor2 (for version 2 monitors), returning a MONITOR_INFO structure containing function pointers for the monitor's print job operations.
3. The operator calls AddMonitor with a MONITOR_INFO_2 structure containing three fields: pName (the monitor's display name), pEnvironment (target environment string such as "Windows x64" or "Windows NT x86"), and pDLLName (the filename of the DLL to load).
4. AddMonitor internally invokes an RPC to the spooler service, which creates a registry subkey under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName> with the Driver value set to the DLL filename.
5. The print spooler service (spoolsv.exe) loads the registered DLL during its next initialization sequence via LoadLibrary. The DLL executes within the spoolsv.exe process, which runs as NT AUTHORITY\SYSTEM.
6. The registry entry persists across reboots. Each time the spooler service starts — typically at boot via its SERVICE_AUTO_START configuration — the DLL is loaded, re-executing the monitor's initialization routine.
7. The loaded DLL performs arbitrary actions within its InitializePrintMonitor callback: spawning threads, loading additional payloads, or establishing C2 channels. The callback must return a valid MONITOR structure to avoid spooler error logging.
8. To remove the persistence, the operator calls DeleteMonitor or deletes the registry subkey and the DLL file from disk.

## OS Internals Context

The print spooler service (spoolsv.exe) hosts all print-related components and runs as a SYSTEM-privilege process managed by the Service Control Manager. Port monitors occupy the lowest layer of the Windows print architecture, acting as the interface between the spooler and physical or virtual print devices. When spoolsv.exe initializes, it enumerates the HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors registry key and loads each registered monitor DLL.

The MONITOR_INFO_2 structure used by AddMonitor contains three string fields. The pDLLName field specifies only the filename — not a full path — and the spooler resolves it against the %SystemRoot%\System32\spool\DRIVERS\x64\ (or x86) directory. This path resolution behavior means the operator's DLL must be placed in the spool driver directory or a directory on the system DLL search path. Alternatively, the operator can write the registry entry directly via RegCreateKeyExW, specifying a full path in the Driver value, bypassing AddMonitor's path resolution.

The AddMonitor function is exported by winspool.drv (the print spooler client DLL) and internally invokes an RPC to the spooler service to perform the registration. The spooler validates the caller's token for SeLoadDriverPrivilege before creating the registry entry. This privilege check makes AddMonitor a privileged operation distinct from typical registry writes — even an administrator with write access to the Print\Monitors key cannot use AddMonitor without SeLoadDriverPrivilege. Direct registry writes bypass this check but require separate SeTakeOwnershipPrivilege or SeRestorePrivilege to modify the ACL-protected registry key.

The registry structure under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors stores each monitor as a subkey. Default monitors present on a standard installation include Local Port, Standard TCP/IP Port, USB Port Monitor, and WSD Port Monitor. A new monitor subkey with a Driver value pointing to the attacker's DLL appears alongside these legitimate entries. The spooler does not verify the digital signature of port monitor DLLs on default Windows configurations, though Secure Boot with Code Integrity may enforce signing requirements on locked-down systems.

The spooler's LoadLibrary call for each monitor DLL occurs early in spoolsv.exe's initialization, before the spooler processes any print jobs. This timing means the malicious DLL's code runs before any user-mode print-related activity, providing a clean execution window. The DLL remains loaded for the lifetime of the spooler process.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would call AddMonitorW via FFI, passing a MONITOR_INFO_2W structure with the monitor name, environment string, and DLL filename. The DLL payload would export InitializePrintMonitor2, performing its malicious work in the callback before returning a minimal MONITOR structure to avoid spooler error logging. The DLL should be written to the spool driver directory or the registry entry should be created directly via RegCreateKeyExW with a full path in the Driver value. On cleanup, DeleteMonitor or manual registry deletion removes the persistence entry, and the DLL file is shredded from disk.

## Why It Matters

Port monitor persistence provides SYSTEM-privilege execution that triggers at service start rather than user logon, making it suitable for server targets where user sessions are infrequent. The mechanism blends with legitimate printer driver installation activity and persists across reboots via a registry key that is less commonly monitored than Run keys or scheduled tasks. T-017's five-layer persistence suite covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits this print spooler vector entirely.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 7 (image load) captures spoolsv.exe loading unexpected DLLs from the spool driver directory or arbitrary paths. Registry monitoring on HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors detects new monitor subkey creation. The Microsoft-Windows-PrintService/Operational ETW channel logs port monitor registration and load operations. Autoruns enumerates port monitor entries in its Print Monitor DLLs category.
- **Bypass options**: Naming the monitor and DLL to mimic legitimate entries (e.g., using a manufacturer-prefixed name or a generic-sounding port description) reduces visual anomaly during manual review. Placing the DLL in the standard spool driver directory avoids path-based suspicion. Direct registry writes bypass the AddMonitor privilege check if the operator has taken ownership of the registry key.
- **Residual artifacts**: The registry subkey under Print\Monitors persists until removed via DeleteMonitor or manual deletion. The DLL file on disk remains at the dropped path. The spooler service logs monitor load failures to the System event log if the DLL does not export the required interface.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-107 fills the port monitor persistence gap absent from T-017's suite of COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist
- **T-035 Port Monitor Persistence via Print Spooler** — existing vault card covering the same MITRE technique from the same operational angle

## References

- Atlas material: atlas-exploit-dev-part10.md, atlas-exploit-dev-part19.md
- MITRE ATT&CK: T1547.010 — https://attack.mitre.org/techniques/T1547/010/
- LGTM notes: lgtm:port-monitor-persistence-gap, lgtm:port-monitor-persistence-coverage

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.