---
id: T-GAP-2003
title: "x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs"
category: "syscalls"
tier: "B"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: x64-abi-syscall-stub-construction
member_notes: ['lgtm:x64-calling-convention-stub-constraint', 'lgtm:x64-abi-syscall-stub-construction', 'lgtm:cross-source-convergence-shadow-store-and-rop']
---

## Summary
Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Three notes (two coverage gaps, one convergence) all describe the x64 calling convention — RCX/RDX/R8/R9 + stack, 32-byte shadow store at RSP+0..RSP+20h — as the structural constraint on syscall stub construction and ROP frame layout.

## Evidence
- lgtm:x64-calling-convention-stub-constraint: See original note for details.
- lgtm:x64-abi-syscall-stub-construction: See original note for details.
- lgtm:cross-source-convergence-shadow-store-and-rop: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
