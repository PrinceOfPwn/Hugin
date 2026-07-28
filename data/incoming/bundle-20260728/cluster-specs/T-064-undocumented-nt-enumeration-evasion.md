# Cluster Spec — T-064: Undocumented NT Enumeration as Syscall-Level Evasion Primitive

- **T-NNN ID**: `T-064`
- **Canonical name**: Undocumented NT Enumeration as Syscall-Level Evasion Primitive
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: low — Singleton; overlaps with syscall-based discovery; mostly legacy (modern EDR hooks syscalls).
- **would_relate_to**: ['T-016', 'T-023', 'T-004']

## Consolidated Description

Direct NT syscall enumeration via NtQuerySystemInformation as evasion primitive bypassing Win32-layer hooks on documented APIs. Requires knowledge of NT API semantics and response structure parsing; direct syscall usage avoids userland interception.

## Member LGTM Notes (1)

### Note 1: Undocumented NT Enumeration as Evasion Primitive
- id: `lgtm:undocumented-nt-enum-evasion-primitive`
- origin: atlas-enumeration-part1
- would_relate_to: ['T-016', 'T-023', 'T-004']
- tags: ['nt-api', 'evasion', 'recon', 'undocumented', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-enumeration-part1
**Would relate to:** T-016, T-023, T-004
**Source units:** unit 13

SEC670 explicitly frames NtQuerySystemInformation as an undocumented alternative to EnumProcesses, WTSEnumerateProcessesEx, and CreateToolhelp32Snapshot for process enumeration. This positions direct NT enumeration as an evasion primitive that bypasses Win32-layer hooks and ETW providers tied to documented APIs. The vault has no card for direct-NT recon primitives, though T-016 (EDR Evasion Suite) covers the broader evasion space. A dedicated card could capture NT-API-based enumeration patterns as a distinct capability.

---
Use `id: T-064`, canonical name above, and `member_notes: ['lgtm:undocumented-nt-enum-evasion-primitive']`.
Cross-reference `would_relate_to`: ['T-016', 'T-023', 'T-004'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.