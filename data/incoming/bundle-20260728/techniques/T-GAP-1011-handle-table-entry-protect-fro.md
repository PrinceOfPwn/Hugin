---
id: T-GAP-1011
name: "Handle Table Entry Structure and Protect-from-Close Flag"
category: exploit-primitive
tier: B
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:handle-table-entry-internals"]
---

# Handle Table Entry Structure and Protect-from-Close Flag

## Summary

Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).


## Mechanism

NtSetInformationObject(ObjectHandleFlagInformation) → OBJECT_HANDLE_FLAG_INFORMATION.ProtectFromClose = 0x2 → NtClose returns STATUS_HANDLE_NOT_CLOSABLE

## Rationale

Single coverage-gap note documenting a kernel object internals topic that recurs across T-013/T-015/T-016; concept card supporting handle-protection tradecraft.

## Related To

T-013, T-015, T-016
