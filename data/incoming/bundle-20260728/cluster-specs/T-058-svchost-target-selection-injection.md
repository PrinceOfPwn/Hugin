# Cluster Spec — T-058: svchost Shared vs Isolated Service Hosting as Injection Target Selection

- **T-NNN ID**: `T-058`
- **Canonical name**: svchost Shared vs Isolated Service Hosting as Injection Target Selection
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: low — Singleton targeting guidance, operational methodology rather than discrete technique.
- **would_relate_to**: ['T-007', 'T-013']

## Consolidated Description

svchost shared vs isolated service hosting distinction is operationally relevant for injection target selection. Shared services share address space and crash fate; isolated services have dedicated svchost. Targeting shared svchost risks collateral damage. Operational guidance for technique selection rather than standalone technique.

## Member LGTM Notes (1)

### Note 1: svchost Shared vs Isolated Service Hosting as Injection Target Selection Criterion
- id: `lgtm:svchost-hosting-model-target-selection`
- origin: atlas-methodology-part3
- would_relate_to: ['T-007', 'T-013']
- tags: ['svchost', 'services', 'target-selection', 'injection', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part3
**Would relate to:** T-007, T-013
**Source units:** unit 19

SEC670 distinguishes shared services (multiple services in one svchost, share address space, shared crash fate) from isolated services (dedicated svchost). This distinction is operationally relevant when selecting a process injection host: targeting a shared svchost group risks destabilizing unrelated co-tenant services. The vault does not have a technique card or selection criterion for choosing injection targets based on service hosting model. Would merit either a new technique card or selection metadata on T-007.

---
Use `id: T-058`, canonical name above, and `member_notes: ['lgtm:svchost-hosting-model-target-selection']`.
Cross-reference `would_relate_to`: ['T-007', 'T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.