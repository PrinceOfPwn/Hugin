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
Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).


## Evidence
- lgtm:handle-table-entry-internals: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-013: Related technique identified in gap analysis.
- T-015: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References
- To be added.
