# Cluster Spec — T-075: Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)

- **T-NNN ID**: `T-075`
- **Canonical name**: Memory Forensics Tooling Awareness (Volatility, PE-sieve, Moneta)
- **Proposed category**: `anti-analysis`
- **Proposed tier**: `A`
- **Priority**: high — Two convergence notes; cross-cutting defensive awareness that constrains every evasion technique in the vault.
- **would_relate_to**: ['T-007', 'T-013', 'T-016']

## Consolidated Description

Documents the three memory forensics tools an operator must assume are in use: Volatility (vol.py, the reference framework — scans for DTB, walks EPROCESS list, PEB module lists, VAD tree, handles), PE-sieve (hashes the .text section of every loaded module and compares against on-disk counterparts to find hooked/hollowed DLLs), and Moneta (scans for PAGE_EXECUTE_READWRITE pages with no corresponding mapped file in the VAD — catches PIC shellcode and module stomping). The operational consequence: "being in memory is not a get out of jail free card" — T-007 injection and T-016 unhook must consider detection by these scanners, not just by EDR hooks. Specific evasion responses: hash-mismatch hiding via T-016 fresh-copy unhook (defeats PE-sieve), VAD-backed allocation via NtMapViewOfSection of a legitimate DLL (defeats Moneta).


## Member LGTM Notes (2)

### Note 1: Memory Forensics Tooling Awareness Coverage Gap
- id: `lgtm:memory-forensics-tooling-coverage-gap`
- origin: atlas-edr-evasion-part1
- would_relate_to: ['T-007', 'T-013', 'T-016']
- tags: ['memory-forensics', 'pe-sieve', 'volatility', 'moneta', 'coverage-gap', 'detection']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-007, T-013, T-016
**Source units:** unit 23, unit 24, unit 25, unit 32

SEC670 explicitly names Volatility, PE-sieve, and Moneta as the defensive memory-forensics stack an operator must assume is in use, and frames the 'being in memory is not a get out of jail free card' constraint. The vault's evasion cards (T-016) describe evasion techniques but do not document which specific scanner heuristics each technique defeats. Cross-cutting metadata linking each evasion to its memory-scanner counter-evasion would close this gap.

### Note 2: Memory Forensics Tool Coverage Gap
- id: `lgtm:memory-forensics-defense-landscape`
- origin: atlas-edr-evasion-part4
- would_relate_to: ['T-007', 'T-016']
- tags: ['memory-forensics', 'defense', 'pe-sieve', 'moneta', 'volatility', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part4
**Would relate to:** T-007, T-016
**Source units:** unit 1, unit 9

SEC670 documents three memory forensics tools (Volatility, PE-sieve, Moneta) as defensive capabilities that detect in-memory implants despite fileless techniques. The vault's technique cards document injection and evasion methods but do not currently document the specific defensive tools operators must evade. Documenting PE-sieve's per-process scanning model and Moneta's user-mode analysis approach would help operators understand the threat landscape for T-007 and T-016 techniques.

---
Use `id: T-075`, canonical name above, and `member_notes: ['lgtm:memory-forensics-tooling-coverage-gap', 'lgtm:memory-forensics-defense-landscape']`.
Cross-reference `would_relate_to`: ['T-007', 'T-013', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.