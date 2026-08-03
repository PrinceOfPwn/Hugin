---
id: T-228
title: "Native Application (NT_main) Execution Surface"
category: anti-analysis
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: native-application-nt-main-entry
member_notes: ["lgtm:native-application-execution-surface", "lgtm:native-application-entry-point"]
---

## Summary
This technique covers Native Application (NT_main) Execution Surface, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// NTSTATUS NTAPI NT_main(int argc, char* argv[]) — entry point invoked before Win32 subsystem; HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute registration
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:native-application-execution-surface: Contributed insights into the specific mechanism.
- Note lgtm:native-application-entry-point: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.
- T-020: Relates conceptually based on evidence.

## References
- Internal vault documentation on Native Application (NT_main) Execution Surface
