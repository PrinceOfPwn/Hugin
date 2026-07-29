---
id: T-1582
title: "Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "inline-hook-byte-forensics-hot-patch"
member_notes: ["lgtm:inline-hook-byte-forensics", "lgtm:32-bit-hot-patch-prologue-coverage"]
---

## Summary
This card covers the research gap identified as Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.


## Evidence
- lgtm:inline-hook-byte-forensics: Identified gap in the research corpus.
- lgtm:32-bit-hot-patch-prologue-coverage: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References
- To be added.
