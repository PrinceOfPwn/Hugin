---
id: T-GAP-2016
title: "Native Application (NT_main) Execution Surface"
category: "anti-analysis"
tier: "B"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: native-application-nt-main-entry
member_notes: ['lgtm:native-application-execution-surface', 'lgtm:native-application-entry-point']
---

## Summary
Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Two notes (one gap, one emerging-tradecraft) both surface the native Windows application entry signature as a distinct execution mode currently undocumented in the vault.

## Evidence
- lgtm:native-application-execution-surface: See original note for details.
- lgtm:native-application-entry-point: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
