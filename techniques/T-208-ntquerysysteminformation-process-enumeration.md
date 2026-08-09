---
id: T-208
title: "NtQuerySystemInformation Process Enumeration"
category: patterns
tier: A
tags: ['research-gap', 'native-process-enumeration-ntquerysysteminformation']
mitre: []
origin: glm-expand-cluster
source_cluster: native-process-enumeration-ntquerysysteminformation
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---

## Summary

This technique card addresses the research gap identified in cluster `native-process-enumeration-ntquerysysteminformation`.
Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.


## Technical Deep Dive

Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.


Technical anchor points:
```
NtQuerySystemInformation(SystemProcessInformation = class 5) → SYSTEM_PROCESS_INFORMATION.NextEntryOffset walk; STATUS_INFO_LENGTH_MISMATCH two-pass allocation
```

## Evidence

- **lgtm:native-process-enumeration-coverage**: Extracted as a foundational reference note for this cluster.
- **lgtm:undocumented-native-api-process-enum**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-007: Relates to the foundational mechanisms discussed in this gap.
- T-020: Relates to the foundational mechanisms discussed in this gap.
- T-023: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `native-process-enumeration-ntquerysysteminformation`
- Generated as part of batch processing to fill identified research gaps.
