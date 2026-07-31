---
id: T-1585
title: "Handle Table Entry Structure and Protect-from-Close Flag"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: handle-table-entry-protect-from-close
member_notes: ['lgtm:handle-table-entry-internals']
---

## Summary
This technique covers the concepts surrounding Handle Table Entry Structure and Protect-from-Close Flag. It represents a synthesized view of the identified research gap `handle-table-entry-protect-from-close` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).

At a deeper API level, this involves understanding the specific structures and offsets associated with handle-table-entry-protect-from-close. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `handle-table-entry-protect-from-close`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `handle-table-entry-protect-from-close`
- Synthesized Coverage Gap Documentation