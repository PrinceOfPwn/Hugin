---
id: T-141
title: "Handle Table Entry Structure and Protect-from-Close Flag"
category: exploit-primitive
tier: B
tags: ['handle-table-entry-protect-from-close']
mitre: ["T-013","T-015","T-016"]
origin: glm-expand-cluster
source_cluster: handle-table-entry-protect-from-close
member_notes: ["lgtm:handle-table-entry-internals"]
---
## Summary

This technique covers Handle Table Entry Structure and Protect-from-Close Flag. It addresses a gap in knowledge for red-team operations related to exploit-primitive.

## Technical Deep Dive

Documents the kernel HANDLE_TABLE_ENTRY structure: a 64-bit ObjectPointer field (low bits used as flags: OBJ_PROTECT_CLOSE = bit 0, OBJ_INHERIT = bit 1, OBJ_AUDIT_OBJECT_CLOSE = bit 2), and the AccessMask (GrantedAccess) packed into the upper 32 bits. The Protect-from-close and Audit-on-close flags are set via NtSetInformationObject(ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION { Inherit = 0x1, ProtectFromClose = 0x2 }). Operations include NtQueryObject and NtSetInformationObject. Setting ProtectFromClose on a privileged handle (e.g., a thread token or PPL-protected process handle) causes NtClose to return STATUS_HANDLE_NOT_CLOSABLE, which denies defensive scanners the ability to strip the implant's access. Pairs with T-013 (waiting thread hijack requiring retained thread handles) and T-015 (token manipulation).


Technical anchor details:
```text
NtSetInformationObject(ObjectHandleFlagInformation) → OBJECT_HANDLE_FLAG_INFORMATION.ProtectFromClose = 0x2 → NtClose returns STATUS_HANDLE_NOT_CLOSABLE
```

## Evidence

- lgtm:handle-table-entry-internals: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-013: Related technique for extended operations.
- T-015: Related technique for extended operations.
- T-016: Related technique for extended operations.

## References

- Internal Vault References
