---
id: T-GAP-2002
title: "Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue"
category: "edr-evasion"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: inline-hook-byte-forensics-hot-patch
member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']
---

## Summary
Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Two coverage gaps describe the same EDR inline-hook byte patterns and the 32-bit hot-patch prologue that enables them; both are diagnostics for detecting hooks and unhooking correctly.

## Evidence
- lgtm:inline-hook-byte-forensics: See original note for details.
- lgtm:32-bit-hot-patch-prologue-coverage: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
