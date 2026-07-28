---
id: T-115
name: SilentProcessExit Registry Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.012
tags: [persistence, silent-process-exit, registry, ifeo, globalflag, process-termination, event-driven]
origin: atlas-synthesis
member_notes: [lgtm:silent-process-exit-persistence, lgtm:ifeo-persistence-coverage-gap]
---

# SilentProcessExit Registry Persistence — Process-Termination-Triggered Execution

## Summary

SilentProcessExit is a registry-driven persistence mechanism that triggers configurable follow-up actions when a monitored process terminates. It exploits the Windows Error Reporting (WER) infrastructure's silent process exit monitoring feature, originally designed to capture diagnostic data when processes exit unexpectedly. An operator configures the GlobalFlag value under the Image File Execution Options (IFEO) registry key for a target binary to enable silent process exit monitoring, then sets the ReportingMode and MonitorProcess values under the SilentProcessExit registry key to specify that a follow-up process should launch when the target exits. The primary detection surface is registry writes to the IFEO and SilentProcessExit key trees, which are monitored by Sysmon and EDR rules.

## Mechanism

1. Identify a target binary that the victim process will execute and terminate normally — common choices include notepad.exe, svchost.exe, or any legitimate binary that runs transiently.
2. Open `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target_binary>` and set the `GlobalFlag` value (REG_DWORD) to `0x200` (`FLG_MONITOR_SILENT_PROCESS_EXIT`). This flag enables the silent process exit monitoring infrastructure for the specified binary.
3. Create the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target_binary>`.
4. Under the SilentProcessExit\<target_binary> key, set `ReportingMode` (REG_DWORD) to `0x1` (`LAUNCH_MONITOR_PROCESS`). Other valid values include `0x2` (`SET_EVENT`) and `0x4` (`CREATE_DUMP`), and these can be combined via bitwise OR.
5. Under the same key, set `MonitorProcess` (REG_SZ) to the full path of the payload to execute — for example, `C:\Users\Public\payload.exe` or a PowerShell one-liner wrapper.
6. When the target binary runs and subsequently exits, the Windows Error Reporting service detects the termination, reads the SilentProcessExit registry configuration, and launches the MonitorProcess executable.
7. The launched process inherits the security context of the process that triggered the monitoring — if the target binary ran as SYSTEM (e.g., a service-hosted binary), the payload executes at SYSTEM integrity.

## OS Internals Context

The SilentProcessExit mechanism is part of the Windows Error Reporting (WER) infrastructure, implemented in werkernel.dll and dispatched through the kernel's process exit notification path. When a process exits, the kernel raises a process exit notification via `PsSetCreateProcessNotifyRoutine`. If the exiting process has the `FLG_MONITOR_SILENT_PROCESS_EXIT` flag (0x200) set in its IFEO GlobalFlag value, the WER infrastructure reads the corresponding SilentProcessExit registry key and performs the configured actions.

The `GlobalFlag` value is a 32-bit bitmask stored under `IFEO\<binary>\GlobalFlag`. The flag `FLG_MONITOR_SILENT_PROCESS_EXIT` (0x200) is distinct from `FLG_APPLICATION_PAGE_HEAP` (0x40000) and the IFEO `Debugger` value (which triggers on process launch). When this flag is set, the kernel's process exit path calls into the silent process exit monitoring code, which reads configuration from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<binary>`.

The `ReportingMode` bitmask determines the action: bit 0 (0x1) launches the `MonitorProcess` value as a new process, bit 1 (0x2) signals an event, and bit 2 (0x4) creates a minidump. The `MonitorProcess` value is a REG_SZ containing the command line to execute.

This mechanism is paired with the IFEO Debugger value, which triggers on process launch rather than exit. The `Debugger` value under `IFEO\<binary>\Debugger` causes the system to launch the specified debugger instead of the target binary. Together, the Debugger value (launch trigger) and SilentProcessExit (exit trigger) provide complementary coverage — an operator can execute on both process start and process termination.

The IFEO GlobalFlag value is read by the kernel during process creation (`NtCreateUserProcess` → `PspAllocateProcess` → `PspSetupUserProcessImage`), while the SilentProcessExit configuration is read during process termination. This means the GlobalFlag must be set before the target process starts — setting it after the process is already running does not trigger monitoring for that instance.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would write the three registry values (`GlobalFlag`, `ReportingMode`, `MonitorProcess`) using `RegCreateKeyExW`/`RegSetValueExW` or the NT registry APIs (`NtCreateKey`/`NtSetValueKey`). The `edo_tensei.rs` module in dark_crystal/crowd/src/ demonstrates registry-based soul storage using `RegCreateKeyExW`/`RegSetValueExW` under `HKCU\Software\Classes\CLSID\{...}\Config`, which could serve as a code pattern for the SilentProcessExit registry writes under HKLM. The implementation would need to handle the HKLM elevation requirement — either running from a high-integrity context or using SeTakeOwnershipPrivilege to modify the IFEO keys.

## Why It Matters

SilentProcessExit fills the event-driven persistence gap that T-017's five-layer suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not cover. While scheduled tasks trigger on time and COM hijacks trigger on CLSID activation, SilentProcessExit triggers on process termination — a different trigger surface. This is operationally complementary to IFEO Debugger persistence (which triggers on launch), and the shared GlobalFlag enablement makes the two variants naturally paired for launch-and-exit coverage. SEC670 Lab 4.3 (IFEOPersisto) documents both variants as a single lab exercise, reflecting their operational coupling.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 (Registry Value Set) captures writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*` and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\GlobalFlag`. Sysmon Event ID 12 (RegistryEvent Object) captures key creation. EDR products with registry monitoring rules alert on writes to the SilentProcessExit key tree.
- **Bypass options**: Using NT registry APIs (`NtCreateKey`/`NtSetValueKey`) instead of the Win32 `Reg*` APIs avoids the user-mode RPC path that some EDRs hook. Writing the values from a SYSTEM-integrity process avoids UAC elevation prompts for HKLM writes.
- **Residual artifacts**: The three registry values persist until manually removed. The launched `MonitorProcess` binary creates a new process with a parent of the silent process exit monitor service (typically WerFault.exe or a WER-related svchost instance), which is an anomalous parent-child relationship that process lineage monitoring can detect.

## Related Techniques

- **T-017 Five-Layer Persistence** — SilentProcessExit fills the event-driven termination trigger gap not covered by the five persistence layers in T-017's suite.

## References

- Atlas material: atlas-post-exploit-part13.md, atlas-post-exploit-part17.md
- MITRE ATT&CK: T1546.012 (https://attack.mitre.org/techniques/T1546/012)
- LGTM notes: lgtm:silent-process-exit-persistence, lgtm:ifeo-persistence-coverage-gap
- Public references: SEC670 Lab 4.3 IFEOPersisto

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.