---
id: T-202
title: "Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue"
category: edr-evasion
tier: A
tags: ['research-gap', 'inline-hook-byte-forensics-hot-patch']
mitre: []
origin: glm-expand-cluster
source_cluster: inline-hook-byte-forensics-hot-patch
member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']
---

## Summary

This technique card addresses the research gap identified in cluster `inline-hook-byte-forensics-hot-patch`.
Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.


## Technical Deep Dive

Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.


Technical anchor points:
```
32-bit hot-patch prologue: `MOV EDI, EDI` (8B FF) at function start + 5-NOP pad (90 90 90 90 90) preceding function; 64-bit trampoline bytes `48 B8 <imm64> FF E0`
```

## Evidence

- **lgtm:inline-hook-byte-forensics**: Extracted as a foundational reference note for this cluster.
- **lgtm:32-bit-hot-patch-prologue-coverage**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `inline-hook-byte-forensics-hot-patch`
- Generated as part of batch processing to fill identified research gaps.
