# Cluster Spec — T-072: PE Injection: Additional Image Loading (Non-Hollowing)

- **T-NNN ID**: `T-072`
- **Canonical name**: PE Injection: Additional Image Loading (Non-Hollowing)
- **Proposed category**: `process-injection`
- **Proposed tier**: `B`
- **Priority**: low — Singleton variant of process injection, overlaps with T-013 injection methods.
- **would_relate_to**: ['T-013']

## Consolidated Description

PE Injection as distinct from process hollowing: an additional PE image loaded into target process without removing original executable. Preserves original process integrity while adding new code section. Distinct operational profile from hollowing; original binary still observable, different memory footprint.

## Member LGTM Notes (1)

### Note 1: PE Injection (Additional Image, Non-Hollowing)
- id: `lgtm:pe-injection-additional-image-card`
- origin: atlas-exploit-dev-part19
- would_relate_to: ['T-013']
- tags: ['injection', 'pe-injection', 'non-hollowing', 'additive-injection']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-013
**Source units:** unit 14

SEC670 documents PE Injection as a distinct technique from process hollowing: an additional PE image is loaded into the target process without removing the original. The vault's T-013 lists 'Hollowing' but does not explicitly distinguish this additive variant. PE Injection has different detection characteristics (two PE images in the process, no unmap of the original) and different operational tradeoffs (the original process image remains functional). A dedicated technique card or sub-entry would clarify the distinction.

---
Use `id: T-072`, canonical name above, and `member_notes: ['lgtm:pe-injection-additional-image-card']`.
Cross-reference `would_relate_to`: ['T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.