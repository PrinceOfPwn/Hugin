---
id: T-GAP-1009
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
tier: "B"
category: "discovery"
---

# EPROCESS / KPROCESS Object-Manager Visibility Split

## Description
Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.


## Rationale
Single concept note documenting a Windows internals distinction that recurs across T-014/T-015/T-016; prerequisite for understanding handle-vs-kernel-only fields.

## References
- lgtm:eprocess-kprocess-split-concept
