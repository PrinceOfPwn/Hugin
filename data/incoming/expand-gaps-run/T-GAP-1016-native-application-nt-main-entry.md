---
id: T-GAP-1016
title: "Native Application (NT_main) Execution Surface"
tier: "B"
category: "anti-analysis"
---

# Native Application (NT_main) Execution Surface

## Description
Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


## Rationale
Two notes (one gap, one emerging-tradecraft) both surface the native Windows application entry signature as a distinct execution mode currently undocumented in the vault.

## References
- lgtm:native-application-execution-surface
- lgtm:native-application-entry-point
