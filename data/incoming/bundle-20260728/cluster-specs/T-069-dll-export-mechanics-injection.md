# Cluster Spec — T-069: DLL Export Mechanics as Injection Prerequisite

- **T-NNN ID**: `T-069`
- **Canonical name**: DLL Export Mechanics as Injection Prerequisite
- **Proposed category**: `process-injection`
- **Proposed tier**: `C`
- **Priority**: low — Singleton prerequisite knowledge, foundational but not standalone offensive capability.
- **would_relate_to**: ['T-013']

## Consolidated Description

DLL construction with exported functions is a direct enabler of process injection. Export table construction is prerequisite knowledge for callback injection and other T-013 methods but not a standalone technique.

## Member LGTM Notes (1)

### Note 1: DLL Export Mechanics as Injection Prerequisite
- id: `lgtm:dll-export-for-injection-surface`
- origin: atlas-exploit-dev-part14
- would_relate_to: ['T-013']
- tags: ['dll', 'export', 'declspec', 'injection', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part14
**Would relate to:** T-013
**Source units:** unit 24, unit 25, unit 26, unit 27, unit 28, unit 29, unit 30, unit 31

SEC670 presents DLL construction with exported functions as a direct enabler of process injection, noting that DLLs are great for injecting into processes. The vault's T-013 covers callback and fiber-based injection but does not have a dedicated technique card for reflective DLL injection or DLL injection via exported function invocation. This would merit a T-NNN card documenting the export-method choice (__declspec vs .def file vs EXTERN_C) and how it affects loader-side resolution.

---
Use `id: T-069`, canonical name above, and `member_notes: ['lgtm:dll-export-for-injection-surface']`.
Cross-reference `would_relate_to`: ['T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.