---
id: T-1589
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "eprocess-kprocess-object-manager-visibility"
member_notes: ["lgtm:eprocess-kprocess-split-concept"]
---

## Summary
This card covers the research gap identified as EPROCESS / KPROCESS Object-Manager Visibility Split. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.


## Evidence
- lgtm:eprocess-kprocess-split-concept: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-014: Related technique identified in gap analysis.
- T-015: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References
- To be added.
