# Cluster Spec — T-074: Sywshipers3: Random Syscall Dispatch via EGH

- **T-NNN ID**: `T-074`
- **Canonical name**: Sywshipers3: Random Syscall Dispatch via EGH
- **Proposed category**: `syscalls`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, narrow applicability (detection evasion), less-documented than SSN-based approaches.
- **would_relate_to**: ['T-001', 'T-002', 'T-003', 'T-006']

## Consolidated Description

Sywshipers3 is a syscall-detection bypass tool using EGG-hunter style stubs and random syscall jumps in Wow64 and x64. Distinguishes itself from deterministic SSN-based dispatch by using randomization to evade signature-based detection of specific syscall numbers. Focuses on evasion through indirection rather than architecture manipulation.

## Member LGTM Notes (1)

### Note 1: Random Syscall Dispatch via Sywshipers3 (EGH-based)
- id: `lgtm:sywshipers3-random-syscall-dispatch`
- origin: atlas-edr-evasion-part3
- would_relate_to: ['T-001', 'T-002', 'T-003', 'T-006']
- tags: ['syscall', 'ssn', 'randomization', 'sywshipers', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part3
**Would relate to:** T-001, T-002, T-003, T-006
**Source units:** unit 13

SEC670 surfaces Sywshipers3 as a syscall-detection bypass tool that uses EGGs (egg-hunter style stubs) and direct syscall jumps to random syscall numbers, in both Wow64 and x64. This is operationally distinct from HUGIN's T-001 (RecycledGate indirect via ntdll gadget), T-002 (Hells/Halo's/Tartarus SSN sort cascade), and T-003 (VEH HW-breakpoint dispatch) — Sywshipers3 deliberately randomizes which syscall SSN is invoked per call to defeat static pattern matching on syscall sequences. A dedicated T-NNN for randomized SSN dispatch would document this alternative dispatch philosophy.

---
Use `id: T-074`, canonical name above, and `member_notes: ['lgtm:sywshipers3-random-syscall-dispatch']`.
Cross-reference `would_relate_to`: ['T-001', 'T-002', 'T-003', 'T-006'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.