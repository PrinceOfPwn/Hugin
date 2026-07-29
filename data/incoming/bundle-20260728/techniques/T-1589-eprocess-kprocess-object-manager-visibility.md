---
id: T-1589
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "eprocess-kprocess-object-manager-visibility"
member_notes: ["lgtm:eprocess-kprocess-split-concept"]
---

## Summary
This card covers the research gap identified as EPROCESS / KPROCESS Object-Manager Visibility Split. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **EPROCESS / KPROCESS Object-Manager Visibility Split** represents a sophisticated vector that leverages low-level system structures. Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.

The primary mechanism relies on invoking `_KPROCESS.DirectoryTableBase` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `eprocess-kprocess-object-manager-visibility`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of EPROCESS / KPROCESS Object-Manager Visibility Split
NTSTATUS status = _KPROCESS.DirectoryTableBase(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific eprocess-kprocess-object-manager-visibility constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:eprocess-kprocess-split-concept: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **EPROCESS / KPROCESS Object-Manager Visibility Split** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `_KPROCESS.DirectoryTableBase` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `eprocess-kprocess-object-manager-visibility` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-014: Related technique identified in gap analysis.
- T-015: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on _KPROCESS.DirectoryTableBase: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of EPROCESS / KPROCESS Object-Manager Visibility Split and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to eprocess-kprocess-object-manager-visibility.
