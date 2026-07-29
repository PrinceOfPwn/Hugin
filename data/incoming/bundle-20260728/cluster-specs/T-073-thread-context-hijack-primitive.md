# Cluster Spec — T-073: Thread Context Hijack via CONTEXT Structure Modification

- **T-NNN ID**: `T-073`
- **Canonical name**: Thread Context Hijack via CONTEXT Structure Modification
- **Proposed category**: `process-injection`
- **Proposed tier**: `B`
- **Priority**: low — Singleton with focused applicability; overlaps with T-013 Remaining Methods.
- **would_relate_to**: ['T-005', 'T-013', 'T-012']

## Consolidated Description

Thread hijacking via direct CONTEXT structure modification using GetThreadContext/SetThreadContext. Operators modify Rip field to redirect thread execution to attacker code. Provides low-footprint code-execution primitive modifying running thread's execution flow. Requires appropriate handle access.

## Member LGTM Notes (1)

### Note 1: CONTEXT-Based Thread Hijack as Standalone Primitive
- id: `lgtm:proposed-thread-context-hijack-primitive`
- origin: atlas-binary-analysis-part9
- would_relate_to: ['T-005', 'T-013', 'T-012']
- tags: ['context', 'thread-hijack', 'primitive', 'injection']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part9
**Would relate to:** T-005, T-013, T-012
**Source units:** unit 20, unit 21, unit 22

SEC670 establishes thread hijacking as the act of modifying a thread's CONTEXT structure (specifically the Rip field) rather than thread state or priority. T-013 bundles thread hijack under 'Remaining Methods' alongside hollowing, mapping, and module stomping. The CONTEXT-modification primitive is reusable beyond WaitingThread — it underlies thread hijack in sacrificial suspended processes, Ekko ROP sleep's frame restoration, and Early Cascade's pre-LdrInitializeThunk APC dispatch. Elevating CONTEXT hijack to its own concept node or sub-card would clarify which injection methods share the primitive versus those that use APCs or section mapping.

---
Use `id: T-073`, canonical name above, and `member_notes: ['lgtm:proposed-thread-context-hijack-primitive']`.
Cross-reference `would_relate_to`: ['T-005', 'T-013', 'T-012'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.