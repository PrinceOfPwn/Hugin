---
id: T-010
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: discovery
tier: B
tags: ["gap", "research"]
mitre: []
origin: manual-gap-extraction
source_cluster: eprocess-kprocess-object-manager-visibility
member_notes: ["lgtm:eprocess-kprocess-split-concept"]
---

## Summary

Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.


## Technical Deep Dive

Single concept note documenting a Windows internals distinction that recurs across T-014/T-015/T-016; prerequisite for understanding handle-vs-kernel-only fields.

Technical Anchor: _KPROCESS.DirectoryTableBase (CR3) at offset 0x028, ThreadListHead at 0x030, ReadyListHead at 0x038 inside EPROCESS.Pcb

## Evidence

- lgtm:eprocess-kprocess-split-concept

## Detection & Mitigation

To be documented.

## Related Techniques

- T-014
- T-015
- T-016

## References

- Internal research vault
