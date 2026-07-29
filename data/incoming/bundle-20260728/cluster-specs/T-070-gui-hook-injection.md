# Cluster Spec — T-070: GUI Application Hook Injection via SetWindowsHookEx

- **T-NNN ID**: `T-070`
- **Canonical name**: GUI Application Hook Injection via SetWindowsHookEx
- **Proposed category**: `process-injection`
- **Proposed tier**: `B`
- **Priority**: low — Singleton with GUI-specific applicability; narrower operational window than core injection.
- **would_relate_to**: ['T-013', 'T-007']

## Consolidated Description

GUI application hook injection via SetWindowsHookEx to inject DLLs into processes that message-pump. Distinct from CreateRemoteThread-based injection; callback-based hook dispatch provides dedicated API surface for GUI targets. Requires message-loop presence in target; conditional on GUI application characteristics.

## Member LGTM Notes (1)

### Note 1: GUI Application Hook Injection as a Distinct Injection Variant
- id: `lgtm:gui-application-hook-injection-distinction`
- origin: atlas-binary-analysis-part4
- would_relate_to: ['T-013', 'T-007']
- tags: ['setwindowshookex', 'gui-injection', 'dll-injection', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-013, T-007
**Source units:** unit 26, unit 27, unit 28

SEC670 explicitly identifies SetWindowsHookEx as the API for injecting DLLs into GUI applications specifically, distinct from CreateRemoteThread-based injection. The vault's T-013 remaining methods lists callback, fiber, Early Bird, PE loader, etc. but does not surface SetWindowsHookEx as a named variant. The mechanism (forced DLL load on the next GUI message processing) produces a different module-load pattern than CreateRemoteThread injection and has different detection characteristics.

---
Use `id: T-070`, canonical name above, and `member_notes: ['lgtm:gui-application-hook-injection-distinction']`.
Cross-reference `would_relate_to`: ['T-013', 'T-007'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.