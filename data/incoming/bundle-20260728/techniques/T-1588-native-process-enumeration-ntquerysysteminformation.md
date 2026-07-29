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

The technique known as **NtQuerySystemInformation Process Enumeration** represents a sophisticated vector that leverages low-level system structures. Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.

The primary mechanism relies on invoking `NtQuerySystemInformation(SystemProcessInformation` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `native-process-enumeration-ntquerysysteminformation`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of NtQuerySystemInformation Process Enumeration
NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific native-process-enumeration-ntquerysysteminformation constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:native-process-enumeration-coverage: Identified gap in the research corpus.
- lgtm:undocumented-native-api-process-enum: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **NtQuerySystemInformation Process Enumeration** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `NtQuerySystemInformation(SystemProcessInformation` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `native-process-enumeration-ntquerysysteminformation` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-007: Related technique identified in gap analysis.
- T-020: Related technique identified in gap analysis.
- T-023: Related technique identified in gap analysis.

## References

- Microsoft Documentation on NtQuerySystemInformation(SystemProcessInformation: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of NtQuerySystemInformation Process Enumeration and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to native-process-enumeration-ntquerysysteminformation.
