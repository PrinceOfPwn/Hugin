# Cluster Spec — T-056: PE-sieve Detection Mechanics Against Injection Techniques

- **T-NNN ID**: `T-056`
- **Canonical name**: PE-sieve Detection Mechanics Against Injection Techniques
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: low — Singleton defensive knowledge, complements offensive techniques with detection insights.
- **would_relate_to**: ['T-007', 'T-008', 'T-013']

## Consolidated Description

PE-sieve is a state-of-the-art community-driven tool for identifying malicious activity against T-007 (reflective injection), T-013 (process hollowing, manual mapping, stomped modules). Defensive knowledge documenting detection mechanisms against vault techniques.

## Member LGTM Notes (2)

### Note 1: PE-sieve Detection Mechanics Against Injection Techniques
- id: `lgtm:pe-sieve-detection-coverage`
- origin: atlas-recon-part6
- would_relate_to: ['T-007', 'T-008', 'T-013']
- tags: ['pe-sieve', 'detection', 'memory-scan', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-recon-part6
**Would relate to:** T-007, T-008, T-013
**Source units:** unit 36

SEC670 identifies PE-sieve as a community-driven state-of-the-art tool for identifying malicious activity, alongside profit-driven products like Huntress Labs. The vault documents many injection techniques (T-007 through T-013) but does not document how PE-sieve specifically detects each — its hollowed-process detection, module stomp detection, and unbacked executable heuristics follow distinct algorithms that operators must understand to evade. A dedicated concept node per technique card on PE-sieve detection mechanics would close this gap.

### Note 2: Defensive Memory Scanner Coverage (PE-sieve Class)
- id: `lgtm:pe-sieve-detection-tool-card`
- origin: atlas-edr-evasion-part6
- would_relate_to: ['T-007', 'T-013', 'T-016']
- tags: ['pe-sieve', 'moneta', 'defensive-tool', 'memory-scanner', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part6
**Would relate to:** T-007, T-013, T-016
**Source units:** unit 12, unit 23

SEC670 units 12 and 23 reference PE-sieve as the canonical defender-side tool for detecting manually mapped, hollowed, and stomped modules — the exact effects produced by T-013 and T-007. The vault's detection insights are written from first-principle indicators (unbacked memory, VAD analysis) but do not name specific defender tools an operator will encounter. A dedicated card cataloguing defender-side scanners (PE-sieve, Moneta, Hunt-Sleeping-Beacons, hollows_hunter) with their specific detection algorithms would let operators pre-test techniques against real tools.

---
Use `id: T-056`, canonical name above, and `member_notes: ['lgtm:pe-sieve-detection-coverage', 'lgtm:pe-sieve-detection-tool-card']`.
Cross-reference `would_relate_to`: ['T-007', 'T-008', 'T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.