---
id: T-1008
title: "NtQuerySystemInformation Process Enumeration"
category: patterns
tier: A
tags: [research-gap, patterns]
mitre: []
origin: glm-expand-cluster
source_cluster: native-process-enumeration-ntquerysysteminformation
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---

## Summary
Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278).

## Technical Deep Dive
The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.

### Technical Anchor
NtQuerySystemInformation(SystemProcessInformation = class 5) → SYSTEM_PROCESS_INFORMATION.NextEntryOffset walk; STATUS_INFO_LENGTH_MISMATCH two-pass allocation

## Evidence
- `lgtm:native-process-enumeration-coverage`: Contributed evidence for this cluster.
- `lgtm:undocumented-native-api-process-enum`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-007: Related technique identified during clustering.
- T-020: Related technique identified during clustering.
- T-023: Related technique identified during clustering.

## References
- Internal cluster analysis
