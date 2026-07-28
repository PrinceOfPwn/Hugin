# Cluster Spec — T-095: NTDLL Unhook Method Typology and Restore Sequence

- **T-NNN ID**: `T-095`
- **Canonical name**: NTDLL Unhook Method Typology and Restore Sequence
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: high — Three convergence notes identify this as a discrete technique currently buried inside T-016; promoting to its own card surfaces the variant choice.
- **would_relate_to**: ['T-016']

## Consolidated Description

Documents the three canonical NTDLL unhook variants and their concrete API sequences. (1) Byte-level prologue patch: per-function search-and-replace of the EDR's trampoline bytes with the original Nt* prologue (the inverse of the inline-hook byte forensics pattern). (2) Fresh-copy file mapping: CreateFileA(L"\\??\\C:\\Windows\\System32\\ntdll.dll") → CreateFileMapping(PAGE_READONLY | SEC_IMAGE) → MapViewOfFile → walk IMAGE_NT_HEADERS to locate .text section → memcpy the clean .text over the hooked .text in the loaded ntdll. (3) Per-function stub restore via RtlPcToFileHeader + the on-disk ntdll .text RVA. All three are partial: kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallback) continue to observe operations after userland hooks are removed, so unhooking must be paired with operations that do not trigger callbacks. The fresh-copy variant is operationally preferred because it does not require per-function signature knowledge.


## Member LGTM Notes (3)

### Note 1: NTDLL Restore via On-Disk File Mapping — Explicit API Sequence
- id: `lgtm:coverage-gap-ntdll-restore-api-sequence`
- origin: atlas-binary-analysis-part1
- would_relate_to: ['T-016']
- tags: ['ntdll', 'unhook', 'file-mapping', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part1
**Would relate to:** T-016
**Source units:** unit 8

Unit 8 documents the exact CreateFileA → CreateFileMapping → MapViewOfFile → NtHeader lookup → .text memcpy sequence for restoring a fresh ntdll. The vault's ntdll_unhook_inject.rs and ntdll_unhook.rs implement the technique, but the source alone does not surface why this specific sequence (rather than copying from another process, or KnownDlls) is operationally preferred: it requires no cross-process handle, no SCM interaction, and uses only on-disk bytes that match the running build. A short operational note attached to T-016 documenting the alternative NTDLL restore sources (on-disk vs KnownDlls vs suspended-process injection) and their tradeoffs would close this gap.

### Note 2: NTDLL Unhook Convergence Across Three Variants
- id: `lgtm:cross-source-ntdll-unhook-convergence`
- origin: atlas-edr-evasion-part3
- would_relate_to: ['T-016']
- tags: ['ntdll', 'unhook', 'fresh-copy', 'suspended-copy', 'convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-edr-evasion-part3
**Would relate to:** T-016
**Source units:** unit 4, unit 5, unit 6, unit 7, unit 8, unit 9, unit 10

SEC670 dedicates an entire module to NTDLL unhooking and enumerates three distinct variants — byte-level prologue patch (per-function), fresh-copy file mapping (whole .text from disk), and suspended-copy snapshot (whole .text from a CREATE_SUSPENDED child). HUGIN's T-016 documents NTDLL unhook via suspended process (dark_crystal/src/experimental/evasion/ntdll_unhook.rs) but does not surface the file-mapping variant as a documented alternative. The convergence indicates strong tradecraft consensus that the suspended-copy path is the operational default — worth surfacing in the vault as a variant selector.

### Note 3: NTDLL Unhook Method Typology
- id: `lgtm:cross-source-unhook-method-typology`
- origin: atlas-edr-evasion-part5
- would_relate_to: ['T-016']
- tags: ['unhook', 'ntdll', 'typology', 'cross-source-convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-edr-evasion-part5
**Would relate to:** T-016
**Source units:** unit 24, unit 25, unit 26, unit 27, unit 28

SEC670 units 24–28 enumerate three distinct unhook methods with concrete API sequences: byte-level patch (search-and-replace), Fresh Copy (file-mapping restore of entire .text section), and Suspended Copy (clean process spawn to harvest syscall table). The vault's T-016 card documents NTDLL unhook but the source-code-centric view does not surface the three-method typology as a decision tree (detection surface vs. operational cost vs. robustness). Surfacing this typology in the card would help operators select the unhook variant appropriate to the target EDR's telemetry posture.

---
Use `id: T-095`, canonical name above, and `member_notes: ['lgtm:coverage-gap-ntdll-restore-api-sequence', 'lgtm:cross-source-ntdll-unhook-convergence', 'lgtm:cross-source-unhook-method-typology']`.
Cross-reference `would_relate_to`: ['T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.