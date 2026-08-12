---
id: T-3009
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: discovery
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: eprocess-kprocess-object-manager-visibility
member_notes: ['lgtm:eprocess-kprocess-split-concept']
---
## Summary

This technique card covers EPROCESS / KPROCESS Object-Manager Visibility Split. It details mechanisms required to implement or understand eprocess-kprocess-object-manager-visibility operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.



```c
// Example for EPROCESS / KPROCESS Object-Manager Visibility Split
// Implementation specific to eprocess-kprocess-object-manager-visibility
void execute_eprocess_kprocess_object_manager_visibility() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:eprocess-kprocess-split-concept`: Referenced in internal atlas batches as a core component of eprocess-kprocess-object-manager-visibility.

## Detection & Mitigation

Memory scanning (YARA) and runtime behavioral analysis focusing on manual memory traversal outside of typical OS loader behavior. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on EPROCESS / KPROCESS Object-Manager Visibility Split
