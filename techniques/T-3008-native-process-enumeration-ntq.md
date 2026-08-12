---
id: T-3008
title: "NtQuerySystemInformation Process Enumeration"
category: discovery
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: native-process-enumeration-ntquerysysteminformation
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---
## Summary

This technique card covers NtQuerySystemInformation Process Enumeration. It details mechanisms required to implement or understand native-process-enumeration-ntquerysysteminformation operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.



```c
// Example for NtQuerySystemInformation Process Enumeration
// Implementation specific to native-process-enumeration-ntquerysysteminformation
void execute_native_process_enumeration_ntquerysysteminformation() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:native-process-enumeration-coverage`: Referenced in internal atlas batches as a core component of native-process-enumeration-ntquerysysteminformation.
- `lgtm:undocumented-native-api-process-enum`: Referenced in internal atlas batches as a core component of native-process-enumeration-ntquerysysteminformation.

## Detection & Mitigation

Memory scanning (YARA) and runtime behavioral analysis focusing on manual memory traversal outside of typical OS loader behavior. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on NtQuerySystemInformation Process Enumeration
