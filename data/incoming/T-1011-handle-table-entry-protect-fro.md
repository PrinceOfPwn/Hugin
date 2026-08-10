---
id: T-1011
title: "Handle Table Entry Structure and Protect-from-Close Flag"
category: patterns
tier: B
tags: [research-gap, patterns]
mitre: []
origin: glm-expand-cluster
source_cluster: handle-table-entry-protect-from-close
member_notes: ['lgtm:handle-table-entry-internals']
---

## Summary
Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }).

## Technical Deep Dive
Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).

### Technical Anchor
NtSetInformationObject(ObjectHandleFlagInformation) → OBJECT_HANDLE_FLAG_INFORMATION.ProtectFromClose = 0x2 → NtClose returns STATUS_HANDLE_NOT_CLOSABLE

## Evidence
- `lgtm:handle-table-entry-internals`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-013: Related technique identified during clustering.
- T-015: Related technique identified during clustering.
- T-016: Related technique identified during clustering.

## References
- Internal cluster analysis
