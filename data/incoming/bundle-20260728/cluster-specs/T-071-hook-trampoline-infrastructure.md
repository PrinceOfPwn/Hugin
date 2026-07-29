# Cluster Spec — T-071: Hook Trampoline Infrastructure for Non-Reentrant Hooks

- **T-NNN ID**: `T-071`
- **Canonical name**: Hook Trampoline Infrastructure for Non-Reentrant Hooks
- **Proposed category**: `process-injection`
- **Proposed tier**: `B`
- **Priority**: low — Singleton infrastructure primitive; secondary to primary injection techniques.
- **would_relate_to**: ['T-016', 'T-013']

## Consolidated Description

Hook trampoline infrastructure for implementing non-reentrant inline hooks. Trampolines preserve original function prologue bytes and jump back past the hook, preventing infinite loop. Distinguishes reentrancy handling from hook placement. Enables both offensive (implant hooks) and defensive (unhooking) operations.

## Member LGTM Notes (1)

### Note 1: Hook Trampoline as Standalone Primitive
- id: `lgtm:proposed-trampoline-infrastructure`
- origin: atlas-edr-evasion-part5
- would_relate_to: ['T-016', 'T-013']
- tags: ['trampoline', 'hooking', 'infrastructure', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part5
**Would relate to:** T-016, T-013
**Source units:** unit 22, unit 23

SEC670 units 22 and 23 cover trampolines as the infrastructure that makes inline hooks non-reentrant: a stub that executes the displaced original bytes and jumps back to the original function past the hook. The vault's T-016 EDR Evasion Suite covers unhooking but does not document the trampoline pattern as a primitive the implant itself might use for its own hooking needs (e.g., IAT camouflage, argument spoofing, KiUserException StepOver interactions all benefit from trampoline infrastructure). A standalone T-NNN for trampoline construction — preserving displaced instruction semantics under variable-length x86 decoding — would unify several existing card internals.

---
Use `id: T-071`, canonical name above, and `member_notes: ['lgtm:proposed-trampoline-infrastructure']`.
Cross-reference `would_relate_to`: ['T-016', 'T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.