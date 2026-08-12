---
id: T-3002
title: "Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue"
category: edr-evasion
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: inline-hook-byte-forensics-hot-patch
member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']
---
## Summary

This technique card covers Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue. It details mechanisms required to implement or understand inline-hook-byte-forensics-hot-patch operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.



```c
// Example for Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue
// Implementation specific to inline-hook-byte-forensics-hot-patch
void execute_inline_hook_byte_forensics_hot_patch() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:inline-hook-byte-forensics`: Referenced in internal atlas batches as a core component of inline-hook-byte-forensics-hot-patch.
- `lgtm:32-bit-hot-patch-prologue-coverage`: Referenced in internal atlas batches as a core component of inline-hook-byte-forensics-hot-patch.

## Detection & Mitigation

Routine verification of in-memory `.text` sections of core DLLs (e.g., `ntdll.dll`) against their on-disk counterparts to identify inline hooks (JMP/E9 instructions). Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue
