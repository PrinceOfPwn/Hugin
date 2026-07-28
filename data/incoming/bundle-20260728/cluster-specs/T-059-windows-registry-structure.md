# Cluster Spec — T-059: Windows Registry Internal Structure and Link Semantics

- **T-NNN ID**: `T-059`
- **Canonical name**: Windows Registry Internal Structure and Link Semantics
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: low — Singleton structural knowledge, foundational but pure conceptual rather than technique.
- **would_relate_to**: ['T-017']

## Consolidated Description

Windows registry merged-view and link semantics: per-user classes override machine-wide ones; HKCC entirely linked to HKLM. Structural knowledge underpinning COM hijack persistence (T-017) but not a discrete offensive technique.

## Member LGTM Notes (1)

### Note 1: Windows Registry Internal Structure and Link Semantics
- id: `lgtm:windows-registry-internals-deep-dive`
- origin: atlas-recon-part6
- would_relate_to: ['T-017']
- tags: ['registry', 'hkcr', 'hkcc', 'com-hijack', 'persistence', 'windows-internals']

**Kind:** proposed-technique
**Origin:** atlas-recon-part6
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19

SEC670 dedicates multiple slides to the merged-view and link semantics of HKCR, HKCU, and HKCC, explaining that per-user classes override machine-wide ones and that HKCC is entirely linked to HKLM. This structural knowledge underpins COM hijack persistence (T-017) and per-user persistence generally, but is not surfaced as a concept area in the vault. A dedicated concept cluster on registry link semantics would improve navigation for operators implementing per-user persistence.

---
Use `id: T-059`, canonical name above, and `member_notes: ['lgtm:windows-registry-internals-deep-dive']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.