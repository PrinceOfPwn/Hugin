# Cluster Spec — T-098: Custom Loader Development and Unhook→Bypass→C2 Callback Arc

- **T-NNN ID**: `T-098`
- **Canonical name**: Custom Loader Development and Unhook→Bypass→C2 Callback Arc
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes documenting an integrated operational arc that spans loader, evasion, and C2
- **would_relate_to**: ['T-016', 'T-022', 'T-013']

## Consolidated Description

SEC670 Section 5 (units 27–29, 32–37) sequences custom loader development, ntdll unhooking, AV/EDR bypass, AMSI patching, and C2 callback establishment as a single training arc. The loader is the initial execution vehicle — a custom PE that manually maps and executes the implant payload (manual PE loader: NtCreateFile → NtReadFile → parse PE headers → NtAllocateVirtualMemory → copy sections → resolve imports via NtAllocateVirtualMemory + LdrLoadDll → fix relocations → DllMain(ATTACH)). This sequencing mirrors the operational reality: the loader must establish execution (manual mapping), defeat runtime monitoring (unhook ntdll, patch amsi.dll!AmsiScanBuffer), and then establish C2 callback registration before the implant can phone home. The vault's dark_crystal crate contains loader infrastructure but T-016 does not document the full arc from loader development through C2 callback as an integrated discipline.


## Member LGTM Notes (2)

### Note 1: Loader → Unhook → AV/EDR Bypass → C2 Callback Tradecraft Sequence
- id: `lgtm:cross-source-convergence-custom-loader-to-callback-arc`
- origin: atlas-methodology-part8
- would_relate_to: ['T-016', 'T-022']
- tags: ['tradecraft-sequence', 'cross-source-convergence', 'loader', 'evasion', 'c2']

**Kind:** cross-source-convergence
**Origin:** atlas-methodology-part8
**Would relate to:** T-016, T-022
**Source units:** unit 27, unit 28, unit 29

SEC670 Section 5 (units 27, 28, 29) sequences custom loader development, ntdll unhooking, AV/EDR bypass, AMSI patching, and C2 callback establishment as a single training arc. This sequencing mirrors the dark_crystal crate's phase runner structure (T-022 architecture overview) and the evasion chain builder in the xptool. The convergence across SEC670 and the vault architecture indicates a strong tradecraft consensus on the operational order of these primitives — loader first, then in-process evasion, then callback — that the vault could surface explicitly as a canonical chain rather than leaving it implicit in the phase runner.

### Note 2: Custom Loader Development as a Tradecraft Area
- id: `lgtm:custom-loader-development-tradecraft`
- origin: atlas-methodology-part9
- would_relate_to: ['T-016', 'T-013']
- tags: ['loader', 'dropper', 'tradecraft', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part9
**Would relate to:** T-016, T-013
**Source units:** unit 32, unit 34, unit 35, unit 36, unit 37

SEC670 Section 5 opens with 'Custom Loaders' as a dedicated module, treating loader development as a discipline distinct from evasion or C2. The vault's dark_crystal crate contains loader infrastructure (src/loader/mod.rs, src/transport.rs, src/runner.rs multi-phase runner) but does not have a dedicated technique card for the loader construct itself — T-022 (architecture) is the closest reference. A loader-focused card would document staging, payload acquisition (embedded vs remote), phase sequencing, and integration points for evasion modules.

---
Use `id: T-098`, canonical name above, and `member_notes: ['lgtm:cross-source-convergence-custom-loader-to-callback-arc', 'lgtm:custom-loader-development-tradecraft']`.
Cross-reference `would_relate_to`: ['T-016', 'T-022', 'T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.