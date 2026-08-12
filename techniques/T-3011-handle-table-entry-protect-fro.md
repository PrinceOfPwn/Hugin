---
id: T-3011
title: "Handle Table Entry Structure and Protect-from-Close Flag"
category: exploit-primitive
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: handle-table-entry-protect-from-close
member_notes: ['lgtm:handle-table-entry-internals']
---
## Summary

This technique card covers Handle Table Entry Structure and Protect-from-Close Flag. It details mechanisms required to implement or understand handle-table-entry-protect-from-close operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).



```c
// Example for Handle Table Entry Structure and Protect-from-Close Flag
// Implementation specific to handle-table-entry-protect-from-close
void execute_handle_table_entry_protect_from_close() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:handle-table-entry-internals`: Referenced in internal atlas batches as a core component of handle-table-entry-protect-from-close.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Handle Table Entry Structure and Protect-from-Close Flag
