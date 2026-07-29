---
id: T-15816
title: "Native Application (NT_main) Execution Surface"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "native-application-nt-main-entry"
member_notes: ["lgtm:native-application-execution-surface", "lgtm:native-application-entry-point"]
---

## Summary
This card covers the research gap identified as Native Application (NT_main) Execution Surface. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


## Evidence
- lgtm:native-application-execution-surface: Identified gap in the research corpus.
- lgtm:native-application-entry-point: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-017: Related technique identified in gap analysis.
- T-020: Related technique identified in gap analysis.

## References
- To be added.
