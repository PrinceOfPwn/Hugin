# Cluster Spec — T-101: PE-sieve as Defensive Validation Scanner

- **T-NNN ID**: `T-101`
- **Canonical name**: PE-sieve as Defensive Validation Scanner
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: medium — 2 member notes from different batches; closes validation-tooling gap for 4 injection/evasion cards.
- **would_relate_to**: ['T-007', 'T-008', 'T-013', 'T-016']

## Consolidated Description

SEC670 Lab 1.1 dedicates a unit to PE-sieve (hasherezade's open-source memory
scanner) as the canonical defensive validation tool for injection detection.
PE-sieve walks the loaded module list via
NtQueryInformationProcess(ProcessMappedInformation), then for each module
compares the in-memory image against the on-disk PE file (byte-diff hash
over .text section, IAT mismatch detection, hollowed process detection via
PEB->Ldr entry mismatch against actual loaded base). Detection surfaces:
classic DLL injection (extra module in PEB but not on disk), process
hollowing (PEB->Ldr entry matches on-disk file but in-memory image differs),
reflective DLL injection (no PEB entry but executable memory region with PE
headers). Operators should run PE-sieve /imp /hooks /threads against their
own implants during testing to verify evasion claims. The card should
document the specific PE-sieve command-line matrix and the resulting report
sections.


## Member LGTM Notes (2)

### Note 1: Defensive Memory Scanner Coverage Gap
- id: `lgtm:pe-sieve-and-memory-scanner-coverage-gap`
- origin: atlas-exploit-dev-part7
- would_relate_to: ['T-007', 'T-013', 'T-008', 'T-016']
- tags: ['pe-sieve', 'memory-scanner', 'detection-heuristic', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part7
**Would relate to:** T-007, T-013, T-008, T-016
**Source units:** unit 37

SEC670 names PE-sieve alongside Sysinternals (ProcMon, Sysmon) and Huntress Labs as part of the defensive tool landscape. The vault's detection insights reference 'memory scan' as an indicator source but do not document what specifically constitutes a memory scanner's signature: unbacked VadS nodes, .text-section byte divergence from disk, floating PE headers, or modified export tables. A concept node describing the PE-sieve detection heuristic would sharpen the bypass rationale fields on multiple injection cards.

### Note 2: PE-sieve as Defensive Validation Tool
- id: `lgtm:pe-sieve-defensive-validation`
- origin: atlas-labs-part1
- would_relate_to: ['T-007', 'T-013', 'T-016']
- tags: ['pe-sieve', 'memory-scan', 'defensive-validation', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-labs-part1
**Would relate to:** T-007, T-013, T-016
**Source units:** unit 29

Unit 29 dedicates Lab 1.1 to PE-sieve as a defensive scanner that catches injection methods. The vault documents 14+ injection techniques in T-007 and T-013 but does not document the defensive tooling an operator should run during development to validate which techniques leave memory artifacts. PE-sieve, Moneta, and HollowsHunter form a class of free defensive scanners operators use pre-engagement to verify evasion claims; this deserves a cross-cutting concept reference or dedicated validation-tradecraft note in the vault.

---
Use `id: T-101`, canonical name above, and `member_notes: ['lgtm:pe-sieve-and-memory-scanner-coverage-gap', 'lgtm:pe-sieve-defensive-validation']`.
Cross-reference `would_relate_to`: ['T-007', 'T-008', 'T-013', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.