# Cluster Spec — T-096: Binary Patching as Standalone Offensive Capability

- **T-NNN ID**: `T-096`
- **Canonical name**: Binary Patching as Standalone Offensive Capability
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: medium — Two convergence notes flag this as currently fragmented across T-016/T-017/T-020; consolidating to a unified card.
- **would_relate_to**: ['T-016', 'T-017', 'T-020']

## Consolidated Description

Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.


## Member LGTM Notes (2)

### Note 1: Binary Patching as a Standalone Offensive Capability
- id: `lgtm:binary-patching-as-standalone-capability`
- origin: atlas-binary-analysis-part4
- would_relate_to: ['T-016']
- tags: ['binary-patching', 'pe-editing', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-016
**Source units:** unit 40

SEC670 lists binary patching ('modifying binaries to achieve results') as a discrete capability in the Red Team Tools module. The vault references patching implicitly inside T-016 (NTDLL unhook, AMSI patch, ETW patch) but does not document binary patching as a general technique covering CFG bitmap editing, hot-patching live PE images in memory, modifying EAT entries to redirect function resolution, or stripping security cookie checks. A general binary-patching concept would tie the existing patching references together.

### Note 2: Binary Patching — Memory vs Disk Modification
- id: `lgtm:binary-patching-as-distinct-technique`
- origin: atlas-binary-analysis-part7
- would_relate_to: ['T-016', 'T-017', 'T-020']
- tags: ['binary-patching', 'ntdll', 'edr-hooking', 'cross-source-convergence', 'persistence']

**Kind:** cross-source-convergence
**Origin:** atlas-binary-analysis-part7
**Would relate to:** T-016, T-017, T-020
**Source units:** unit 20, unit 21, unit 22

The SANS material treats binary patching as a distinct operational concept: modifying binaries on disk or in memory to change execution behavior. It explicitly discusses patching NTDLL, patching secondary/tertiary DLLs that NTDLL loads, and notes that AV/EDR solutions themselves use in-memory binary patching as their hooking mechanism. The vault's T-016 (NTDLL unhook) is a specific instance of this broader pattern. The SANS framing suggests binary patching deserves recognition as a cross-cutting technique that connects EDR evasion (T-016), persistence (patching DLLs for stable hooks), and IAT camouflage (T-020).

---
Use `id: T-096`, canonical name above, and `member_notes: ['lgtm:binary-patching-as-standalone-capability', 'lgtm:binary-patching-as-distinct-technique']`.
Cross-reference `would_relate_to`: ['T-016', 'T-017', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.