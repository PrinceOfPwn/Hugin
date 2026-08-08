---
id: T-GAP-2008
title: "NtQuerySystemInformation Process Enumeration"
category: "discovery"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: native-process-enumeration-ntquerysysteminformation
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---

## Summary
Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Two coverage-gap notes both identify NtQuerySystemInformation with SystemProcessInformation as the evasion-friendly enumeration path distinct from Win32 toolhelp32.

## Evidence
- lgtm:native-process-enumeration-coverage: See original note for details.
- lgtm:undocumented-native-api-process-enum: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
