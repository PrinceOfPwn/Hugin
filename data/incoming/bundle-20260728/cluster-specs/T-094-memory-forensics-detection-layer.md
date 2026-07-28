# Cluster Spec — T-094: Memory Forensics Detection Layer (PE-sieve, Moneta, Volatility)

- **T-NNN ID**: `T-094`
- **Canonical name**: Memory Forensics Detection Layer (PE-sieve, Moneta, Volatility)
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: high — Cross-source convergence across SEC670 and Huntress Labs; surfaces detection surface for 6 existing injection / evasion cards
- **would_relate_to**: ['T-007', 'T-008', 'T-011', 'T-013', 'T-016', 'T-003']

## Consolidated Description

PE-sieve (Hasherzade), Moneta (forrest-orr), and Volatility (Volatility Foundation) detect in-memory implants even when on-disk AV does not, by scanning process address spaces for unbacked executable regions, hollowed modules, suspicious PE header anomalies, IAT mismatches, and RWX permissions inconsistent with the original image. The vault's detection narrative narrows to kernel callbacks and ETW; the gap leaves operators without a model of how memory scanners fingerprint module stomping (T-007), Threadless injection (T-008), and NTDLL unhooking (T-016). PE-sieve specifically walks the PEB Loader list (PEB->Ldr->InLoadOrderModuleList) and cross-checks each entry against the on-disk image via MEMORY_BASIC_INFORMATION, flagging modules where ImageBase mismatches or MZ / PE headers indicate shadow copies; Moneta targets unbacked RWX / EXECUTE_READWRITE memory in a more generic fashion.


## Member LGTM Notes (2)

### Note 1: Memory Forensics Tooling as Detection Layer
- id: `lgtm:memory-forensics-tooling`
- origin: atlas-post-exploit-part5
- would_relate_to: ['T-003', 'T-007', 'T-016']
- tags: ['memory-forensics', 'pe-sieve', 'moneta', 'volatility', 'detection', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part5
**Would relate to:** T-003, T-007, T-016
**Source units:** unit 18

SEC670 names PE-sieve (Hasherzade), Moneta (forrest-orr), and Volatility (Volatility Foundation) as third-party memory forensics tools that detect in-memory implants even when on-disk AV does not. The vault's detection narrative is heavily weighted toward ETW-TI, kernel callbacks, and Sysmon. PE-sieve and Moneta in particular operate on VAD and module-vs-disk comparison heuristics that are a distinct detection surface. A concept node exists for them here, but cross-cutting detection guidance across T-003, T-007, T-016 referencing these specific tools is absent from the vault.

### Note 2: PE-sieve Heuristics vs Vault Injection Methods Cross-Reference
- id: `lgtm:convergence-pe-sieve-vs-vault-injection`
- origin: atlas-recon-part2
- would_relate_to: ['T-007', 'T-008', 'T-011', 'T-013', 'T-016']
- tags: ['pe-sieve', 'memory-scan', 'injection-evasion', 'cross-source', 'convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part2
**Would relate to:** T-007, T-008, T-011, T-013, T-016
**Source units:** unit 11

SEC670 cites PE-sieve and Huntress Labs as state-of-the-art memory scanners; the vault documents multiple injection methods (T-007 module stomping, module overloading, section mapping; T-008 Threadless; T-011 Dirty Vanity; T-013 mapping injection) that specifically aim to evade the unbacked-executable heuristic PE-sieve applies. The convergence between SEC670's defender-side scanner presentation and the vault's attacker-side injection coverage deserves explicit cross-referencing in the graph.

---
Use `id: T-094`, canonical name above, and `member_notes: ['lgtm:memory-forensics-tooling', 'lgtm:convergence-pe-sieve-vs-vault-injection']`.
Cross-reference `would_relate_to`: ['T-007', 'T-008', 'T-011', 'T-013', 'T-016', 'T-003'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.