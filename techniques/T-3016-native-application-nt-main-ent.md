---
id: T-3016
title: "Native Application (NT_main) Execution Surface"
category: anti-analysis
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: native-application-nt-main-entry
member_notes: ['lgtm:native-application-execution-surface', 'lgtm:native-application-entry-point']
---
## Summary

This technique card covers Native Application (NT_main) Execution Surface. It details mechanisms required to implement or understand native-application-nt-main-entry operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the native Windows application execution mode: entry signature `NTSTATUS NTAPI NT_main(int argc, char* argv[])`, distinct from the Win32 main / WinMainCRTStartup. Native applications run before the Win32 subsystem is fully initialized — they are invoked via the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image registered as a known DLL. They have no subsystem import binding; must call only ntdll exports. Operations: registry access via NtCreateKey/NtSetValueKey, file I/O via NtCreateFile, no kernel32/kernelbase. Useful for early-boot persistence (Boot Execute via HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute), SurvivableProtectedProcess launchers, and minimal recon droppers that avoid the Win32 API surface EDRs monitor.



```c
// Example for Native Application (NT_main) Execution Surface
// Implementation specific to native-application-nt-main-entry
void execute_native_application_nt_main_entry() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:native-application-execution-surface`: Referenced in internal atlas batches as a core component of native-application-nt-main-entry.
- `lgtm:native-application-entry-point`: Referenced in internal atlas batches as a core component of native-application-nt-main-entry.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Native Application (NT_main) Execution Surface
