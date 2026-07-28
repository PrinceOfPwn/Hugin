# Cluster Spec — T-060: DKOM Process Hiding via ActiveProcessLinks Unlinking

- **T-NNN ID**: `T-060`
- **Canonical name**: DKOM Process Hiding via ActiveProcessLinks Unlinking
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, kernel-mode technique, high barrier to entry, deprecated due to EDR monitoring.
- **would_relate_to**: ['T-016', 'T-013']

## Consolidated Description

Direct Kernel Object Manipulation (DKOM) process hiding via unlinking process from _EPROCESS.ActiveProcessLinks. Unlinked process invisible to all documented enumeration APIs. Requires kernel-mode access or vulnerable driver; distinct from PEB unlink. Complex anti-detection technique with high privilege requirement.

## Member LGTM Notes (1)

### Note 1: Kernel DKOM Process Hiding via ActiveProcessLinks Unlinking
- id: `lgtm:dkom-process-hiding`
- origin: atlas-post-exploit-part2
- would_relate_to: ['T-016', 'T-013']
- tags: ['dkom', 'kernel', 'process-hiding', 'activeprocesslinks', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part2
**Would relate to:** T-016, T-013
**Source units:** unit 5, unit 33, unit 34, unit 35

SEC670 dedicates multiple units to the _EPROCESS structure and DKOM attacks that unlink a process from the ActiveProcessLinks doubly-linked list to hide it from every documented enumeration API. The vault currently documents PEB unlink (T-016) as a user-mode hiding primitive but has no kernel-mode DKOM counterpart. A standalone T-NNN card would document the kernel-mode write requirement, the specific LIST_ENTRY manipulation, the PsActiveProcessHead walk that enumeration APIs perform, and the detection-via-handle-table-comparison technique.

---
Use `id: T-060`, canonical name above, and `member_notes: ['lgtm:dkom-process-hiding']`.
Cross-reference `would_relate_to`: ['T-016', 'T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.