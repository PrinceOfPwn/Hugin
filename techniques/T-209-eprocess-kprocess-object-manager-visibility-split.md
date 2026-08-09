---
id: T-209
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: patterns
tier: B
tags: ['research-gap', 'eprocess-kprocess-object-manager-visibility']
mitre: []
origin: glm-expand-cluster
source_cluster: eprocess-kprocess-object-manager-visibility
member_notes: ['lgtm:eprocess-kprocess-split-concept']
---

## Summary

This technique card addresses the research gap identified in cluster `eprocess-kprocess-object-manager-visibility`.
Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.


## Technical Deep Dive

Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.


Technical anchor points:
```
_KPROCESS.DirectoryTableBase (CR3) at offset 0x028, ThreadListHead at 0x030, ReadyListHead at 0x038 inside EPROCESS.Pcb
```

## Evidence

- **lgtm:eprocess-kprocess-split-concept**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-014: Relates to the foundational mechanisms discussed in this gap.
- T-015: Relates to the foundational mechanisms discussed in this gap.
- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `eprocess-kprocess-object-manager-visibility`
- Generated as part of batch processing to fill identified research gaps.
