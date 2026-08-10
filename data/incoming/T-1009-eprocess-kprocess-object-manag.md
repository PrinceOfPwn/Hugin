---
id: T-1009
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: patterns
tier: B
tags: [research-gap, patterns]
mitre: []
origin: glm-expand-cluster
source_cluster: eprocess-kprocess-object-manager-visibility
member_notes: ['lgtm:eprocess-kprocess-split-concept']
---

## Summary
Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation.

## Technical Deep Dive
This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.

### Technical Anchor
_KPROCESS.DirectoryTableBase (CR3) at offset 0x028, ThreadListHead at 0x030, ReadyListHead at 0x038 inside EPROCESS.Pcb

## Evidence
- `lgtm:eprocess-kprocess-split-concept`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-014: Related technique identified during clustering.
- T-015: Related technique identified during clustering.
- T-016: Related technique identified during clustering.

## References
- Internal cluster analysis
