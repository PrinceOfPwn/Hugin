---
id: T-15811
title: "Handle Table Entry Structure and Protect-from-Close Flag"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "handle-table-entry-protect-from-close"
member_notes: ["lgtm:handle-table-entry-internals"]
---

## Summary
This card covers the research gap identified as Handle Table Entry Structure and Protect-from-Close Flag. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Handle Table Entry Structure and Protect-from-Close Flag** represents a sophisticated vector that leverages low-level system structures. Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).

The primary mechanism relies on invoking `NtSetInformationObject(ObjectHandleFlagInformation)` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `handle-table-entry-protect-from-close`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Handle Table Entry Structure and Protect-from-Close Flag
NTSTATUS status = NtSetInformationObject(ObjectHandleFlagInformation)(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific handle-table-entry-protect-from-close constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:handle-table-entry-internals: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Handle Table Entry Structure and Protect-from-Close Flag** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `NtSetInformationObject(ObjectHandleFlagInformation)` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `handle-table-entry-protect-from-close` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-013: Related technique identified in gap analysis.
- T-015: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on NtSetInformationObject(ObjectHandleFlagInformation): https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Handle Table Entry Structure and Protect-from-Close Flag and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to handle-table-entry-protect-from-close.
