---
id: T-GAP-1008
title: "NtQuerySystemInformation Process Enumeration"
tier: "A"
category: "discovery"
---

# NtQuerySystemInformation Process Enumeration

## Description
Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.


## Rationale
Two coverage-gap notes both identify NtQuerySystemInformation with SystemProcessInformation as the evasion-friendly enumeration path distinct from Win32 toolhelp32.

## References
- lgtm:native-process-enumeration-coverage
- lgtm:undocumented-native-api-process-enum
