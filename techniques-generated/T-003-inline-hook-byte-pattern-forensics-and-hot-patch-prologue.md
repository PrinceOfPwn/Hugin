---
id: T-003
title: "Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue"
category: edr-evasion
tier: A
tags: ["gap", "research"]
mitre: []
origin: manual-gap-extraction
source_cluster: inline-hook-byte-forensics-hot-patch
member_notes: ["lgtm:inline-hook-byte-forensics", "lgtm:32-bit-hot-patch-prologue-coverage"]
---

## Summary

Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.


## Technical Deep Dive

Two coverage gaps describe the same EDR inline-hook byte patterns and the 32-bit hot-patch prologue that enables them; both are diagnostics for detecting hooks and unhooking correctly.

Technical Anchor: 32-bit hot-patch prologue: `MOV EDI, EDI` (8B FF) at function start + 5-NOP pad (90 90 90 90 90) preceding function; 64-bit trampoline bytes `48 B8 <imm64> FF E0`

## Evidence

- lgtm:inline-hook-byte-forensics
- lgtm:32-bit-hot-patch-prologue-coverage

## Detection & Mitigation

To be documented.

## Related Techniques

- T-016

## References

- Internal research vault
