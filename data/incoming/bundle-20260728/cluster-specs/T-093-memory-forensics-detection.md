# Cluster Spec — T-093: Memory Forensics Tooling (Volatility, PE-sieve, Moneta)

- **T-NNN ID**: `T-093`
- **Canonical name**: Memory Forensics Tooling (Volatility, PE-sieve, Moneta)
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: high — 4 member notes from independent batches, named defensive tools that define the post-capture detection surface
- **would_relate_to**: ['T-007', 'T-008', 'T-013', 'T-016', 'T-020', 'T-005']

## Consolidated Description

SEC670 explicitly names Volatility, PE-sieve, and Moneta as the memory forensics suite defenders use to identify in-memory and fileless execution artifacts. PE-sieve (hasherezade) scans a process's memory for PE images, compares in-memory headers against on-disk counterparts, and flags unmapped/scraped/hollowed images by comparing the .text section bytes in memory against the file on disk. Volatility performs full-memory analysis of EPROCESS blocks, VAD (Virtual Address Descriptor) trees, and PEB structures to identify injected code, hollowed processes, and unbacked executable regions. Moneta scans for unbacked executable memory (VirtualAlloc'd without a file backing) and suspicious RWX regions. SEC670 explicitly identifies memory forensics as the defensive counter to in-memory execution (citing WannaCry and EternalBlue). The vault's T-016, T-013, and T-007 document EDR evasion from the product perspective (ETW-TI, kernel callbacks, hooks) but do not reference these standalone forensic tools. This gap matters because an operator who defeats the EDR's runtime monitoring can still be caught by a post-capture memory forensic scan.


## Member LGTM Notes (4)

### Note 1: PE-sieve as Defensive Reference Tool
- id: `lgtm:pe-sieve-as-detection-reference`
- origin: atlas-methodology-part9
- would_relate_to: ['T-007', 'T-008', 'T-013']
- tags: ['detection', 'pe-sieve', 'memory-scan', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part9
**Would relate to:** T-007, T-008, T-013
**Source units:** unit 3

SEC670 Unit 3 names PE-sieve as a community-driven defensive tool for detecting injected implants. The vault currently documents detection from the EDR perspective (ETW-TI, kernel callbacks, userland hooks) but does not reference standalone open-source scanners that operators and defenders run independently of EDR. A detection concept node for PE-sieve is added here; a future LGTM consideration is whether the vault's detection sections should systematically cross-reference open-source scanner capabilities alongside EDR telemetry.

### Note 2: Memory Forensics as Documented Counter to In-Memory Execution
- id: `lgtm:memory-forensics-as-fileless-counter`
- origin: atlas-post-exploit-part1
- would_relate_to: ['T-013']
- tags: ['memory-forensics', 'fileless', 'detection', 'coverage-gap']

**Kind:** cross-source-convergence
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-013
**Source units:** unit 26

SEC670 explicitly identifies memory forensics as the defensive counter to in-memory and fileless execution (WannaCry and EternalBlue cited as examples). The vault's T-013 covers remaining injection methods including in-memory execution but does not surface the unbacked-executable memory-scan heuristic as a documented defense. The convergence between SEC670's framing and the vault's injection coverage indicates the vault should add cross-cutting detection metadata on memory-scan signatures.

### Note 3: Memory Forensics Scanner Coverage Gap
- id: `lgtm:memory-forensics-detection-coverage`
- origin: atlas-post-exploit-part11
- would_relate_to: ['T-020', 'T-016', 'T-005']
- tags: ['volatility', 'pe-sieve', 'moneta', 'memory-forensics', 'detection', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part11
**Would relate to:** T-020, T-016, T-005
**Source units:** unit 11, unit 12, unit 13

T-020 (Anti-Analysis Suite) and T-016 (EDR Evasion) do not currently document the specific memory forensics tools that detect in-memory techniques: Volatility, PE-sieve, and Moneta. SEC670 explicitly names these three tools as the detection surface for fileless implants. Each has different detection heuristics (full-process analysis vs. PE module mismatch detection vs. unbacked executable memory) and bypassing them requires distinct tradecraft from bypassing EDR userland hooks. The vault would benefit from documenting these scanners as named adversaries.

### Note 4: Memory Forensics Tooling (Volatility/PE-sieve/Moneta) Detection Coverage Gap
- id: `lgtm:gap-memory-forensics-detection-coverage`
- origin: atlas-post-exploit-part14
- would_relate_to: ['T-007', 'T-016', 'T-013']
- tags: ['memory-forensics', 'detection', 'coverage-gap', 'volatility', 'pe-sieve', 'moneta']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part14
**Would relate to:** T-007, T-016, T-013
**Source units:** unit 30, unit 29

SEC670 explicitly names Volatility, PE-sieve, and Moneta as the memory forensics suite defenders use to identify injection and PE stomping artifacts. The vault's T-007, T-016, and T-013 technique cards do not currently document how these specific tools identify each technique's artifacts. Cross-cutting detection metadata — which scanner catches which technique by what heuristic — would substantially improve the vault's tradecraft-vs-detection navigability.

---
Use `id: T-093`, canonical name above, and `member_notes: ['lgtm:pe-sieve-as-detection-reference', 'lgtm:memory-forensics-as-fileless-counter', 'lgtm:memory-forensics-detection-coverage', 'lgtm:gap-memory-forensics-detection-coverage']`.
Cross-reference `would_relate_to`: ['T-007', 'T-008', 'T-013', 'T-016', 'T-020', 'T-005'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.