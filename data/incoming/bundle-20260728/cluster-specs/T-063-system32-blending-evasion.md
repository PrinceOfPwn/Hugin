# Cluster Spec — T-063: System32 Folder Blending as File-Based Hiding Technique

- **T-NNN ID**: `T-063`
- **Canonical name**: System32 Folder Blending as File-Based Hiding Technique
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: low — Singleton with behavioral/statistical focus; low technical sophistication.
- **would_relate_to**: ['T-017', 'T-020']

## Consolidated Description

System32 blending via statistical hiding: place payloads among 4,200+ existing files, select middle-listing position, match filename conventions, align timestamps. Evasion through visual/statistical obscuration rather than technical hiding. Reliant on defender workflow (manual inspection) rather than technical controls.

## Member LGTM Notes (1)

### Note 1: System32 Folder Blending as Evasion Technique
- id: `lgtm:system32-blending-evasion`
- origin: atlas-edr-evasion-part1
- would_relate_to: ['T-017', 'T-020']
- tags: ['blending', 'system32', 'filename-masquerade', 'timestamp-alignment', 'evasion']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-017, T-020
**Source units:** unit 33, unit 34

SEC670 documents a concrete strategy for file-based blending: place payloads in System32 (4,200+ files to hide among), choose a middle-listing position, match filename conventions of surrounding entries, and align timestamps. The vault's persistence card (T-017) covers persistence locations but not this file-system blending tradecraft as a distinct evasion step. Worth its own treatment because it composes with persistence and is reusable.

---
Use `id: T-063`, canonical name above, and `member_notes: ['lgtm:system32-blending-evasion']`.
Cross-reference `would_relate_to`: ['T-017', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.