# Cluster Spec — T-054: Executive Object Types as Telemetry Taxonomy

- **T-NNN ID**: `T-054`
- **Canonical name**: Executive Object Types as Telemetry Taxonomy
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: low — Singleton structural knowledge, pure conceptual rather than offensive capability.
- **would_relate_to**: ['T-007', 'T-016', 'T-015']

## Consolidated Description

Executive object types (Process, Thread, Section, Token, Mutex, Key, Desktop) with per-type auditing enable understanding of detection surface. Structural knowledge underpinning detection mechanics rather than offensive technique.

## Member LGTM Notes (1)

### Note 1: Executive Object Types as a Telemetry Taxonomy
- id: `lgtm:executive-object-types-as-telemetry-surface`
- origin: atlas-methodology-part1
- would_relate_to: ['T-007', 'T-016', 'T-015']
- tags: ['windows-internals', 'object-types', 'auditing', 'detection', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part1
**Would relate to:** T-007, T-016, T-015
**Source units:** unit 38

Unit 38 tabulates executive object types (Process, Thread, Section, Token, Mutex, Key, Desktop) and notes that object-access auditing is gated per object type. The vault currently treats detection concepts inline per technique card. A cross-cutting concept card mapping object types to the Event IDs 4656/4663/4658/4660 access masks they emit would give operators a single reference for which kernel-level handle operations are auditable per object class, enabling more precise EDR-evasion planning around which object types to touch.

---
Use `id: T-054`, canonical name above, and `member_notes: ['lgtm:executive-object-types-as-telemetry-surface']`.
Cross-reference `would_relate_to`: ['T-007', 'T-016', 'T-015'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.