---
id: T-216
title: "Native Application (NT_main) Execution Surface"
category: anti-analysis
tier: B
tags: ['research-gap', 'native-application-nt-main-entry']
mitre: []
origin: glm-expand-cluster
source_cluster: native-application-nt-main-entry
member_notes: ['lgtm:native-application-execution-surface', 'lgtm:native-application-entry-point']
---

## Summary

This technique card addresses the research gap identified in cluster `native-application-nt-main-entry`.
Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


## Technical Deep Dive

Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


Technical anchor points:
```
NTSTATUS NTAPI NT_main(int argc, char* argv[]) — entry point invoked before Win32 subsystem; HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute registration
```

## Evidence

- **lgtm:native-application-execution-surface**: Extracted as a foundational reference note for this cluster.
- **lgtm:native-application-entry-point**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-017: Relates to the foundational mechanisms discussed in this gap.
- T-020: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `native-application-nt-main-entry`
- Generated as part of batch processing to fill identified research gaps.
