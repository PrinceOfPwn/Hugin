---
id: T-1588
title: "NtQuerySystemInformation Process Enumeration"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "native-process-enumeration-ntquerysysteminformation"
member_notes: ["lgtm:native-process-enumeration-coverage", "lgtm:undocumented-native-api-process-enum"]
---

## Summary
This card covers the research gap identified as NtQuerySystemInformation Process Enumeration. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.


## Evidence
- lgtm:native-process-enumeration-coverage: Identified gap in the research corpus.
- lgtm:undocumented-native-api-process-enum: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-007: Related technique identified in gap analysis.
- T-020: Related technique identified in gap analysis.
- T-023: Related technique identified in gap analysis.

## References
- To be added.
