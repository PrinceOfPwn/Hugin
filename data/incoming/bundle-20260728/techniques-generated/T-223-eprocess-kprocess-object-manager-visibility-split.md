---
id: T-223
title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
category: patterns
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: eprocess-kprocess-object-manager-visibility
member_notes: ["lgtm:eprocess-kprocess-split-concept"]
---

## Summary
This technique covers EPROCESS / KPROCESS Object-Manager Visibility Split, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the kernel object split: EPROCESS is partially exposed via the Object Manager (HandleTable, ImageFileName, UniqueProcessId, Pcb) while _KPROCESS — the embedded head of EPROCESS — holds DirectoryTableBase (CR3 at offset 0x028 on x64), ThreadListHead (offset 0x030), ReadyListHead (offset 0x038), and Affinity (offset 0x040) and is strictly kernel-only. User-mode code cannot read _KPROCESS directly; any technique that requires CR3 pivoting or thread-list walking must obtain a kernel handle or read through NtQuerySystemInformation. This split underpins why T-014 (NtCreateUserProcess) does not expose affinity or page-table root to the caller, and why forensic scanners pivot through EPROCESS→Pcb→ThreadListHead to detect PEB-unlinked modules.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// _KPROCESS.DirectoryTableBase (CR3) at offset 0x028, ThreadListHead at 0x030, ReadyListHead at 0x038 inside EPROCESS.Pcb
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:eprocess-kprocess-split-concept: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-014: Relates conceptually based on evidence.
- T-015: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on EPROCESS / KPROCESS Object-Manager Visibility Split
