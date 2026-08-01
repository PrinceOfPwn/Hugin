---
id: T-1583
title: "NtQuerySystemInformation Process Enumeration"
category: discovery
tier: A
tags: [native, process, enumeration, ntquerysysteminformation]
mitre: []
origin: glm-expand-cluster
source_cluster: native-process-enumeration-ntquerysysteminformation
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---

## Summary
Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.

## Technical Deep Dive
Two coverage-gap notes both identify NtQuerySystemInformation with SystemProcessInformation as the evasion-friendly enumeration path distinct from Win32 toolhelp32.

Key technical anchor: NtQuerySystemInformation(SystemProcessInformation = class 5) → SYSTEM_PROCESS_INFORMATION.NextEntryOffset walk; STATUS_INFO_LENGTH_MISMATCH two-pass allocation

## Evidence
- lgtm:native-process-enumeration-coverage: Highlights the gap or observation related to this tradecraft.
- lgtm:undocumented-native-api-process-enum: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-007 - related to NtQuerySystemInformation Process Enumeration
- T-020 - related to NtQuerySystemInformation Process Enumeration
- T-023 - related to NtQuerySystemInformation Process Enumeration

## References
- Refer to internal research note native-process-enumeration-ntquerysysteminformation for preliminary data.
