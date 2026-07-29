---
id: T-1583
title: "x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "x64-abi-syscall-stub-construction"
member_notes: ["lgtm:x64-calling-convention-stub-constraint", "lgtm:x64-abi-syscall-stub-construction", "lgtm:cross-source-convergence-shadow-store-and-rop"]
---

## Summary
This card covers the research gap identified as x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.


## Evidence
- lgtm:x64-calling-convention-stub-constraint: Identified gap in the research corpus.
- lgtm:x64-abi-syscall-stub-construction: Identified gap in the research corpus.
- lgtm:cross-source-convergence-shadow-store-and-rop: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-003: Related technique identified in gap analysis.
- T-005: Related technique identified in gap analysis.
- T-006: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References
- To be added.
