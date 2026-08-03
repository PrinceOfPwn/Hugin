---
id: T-225
title: "Handle Table Entry Structure and Protect-from-Close Flag"
category: patterns
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: handle-table-entry-protect-from-close
member_notes: ["lgtm:handle-table-entry-internals"]
---

## Summary
This technique covers Handle Table Entry Structure and Protect-from-Close Flag, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// NtSetInformationObject(ObjectHandleFlagInformation) → OBJECT_HANDLE_FLAG_INFORMATION.ProtectFromClose = 0x2 → NtClose returns STATUS_HANDLE_NOT_CLOSABLE
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:handle-table-entry-internals: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-013: Relates conceptually based on evidence.
- T-015: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on Handle Table Entry Structure and Protect-from-Close Flag
