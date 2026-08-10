---
id: T-1003
title: "x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs"
category: syscalls
tier: B
tags: [research-gap, syscalls]
mitre: []
origin: glm-expand-cluster
source_cluster: x64-abi-syscall-stub-construction
member_notes: ['lgtm:x64-calling-convention-stub-constraint', 'lgtm:x64-abi-syscall-stub-construction', 'lgtm:cross-source-convergence-shadow-store-and-rop']
---

## Summary
Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into.

## Technical Deep Dive
Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.

### Technical Anchor
32-byte shadow store at RSP+0..RSP+20h (8 × 8 bytes); RCX/RDX/R8/R9 first four args, RAX for syscall number

## Evidence
- `lgtm:x64-calling-convention-stub-constraint`: Contributed evidence for this cluster.
- `lgtm:x64-abi-syscall-stub-construction`: Contributed evidence for this cluster.
- `lgtm:cross-source-convergence-shadow-store-and-rop`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-001: Related technique identified during clustering.
- T-002: Related technique identified during clustering.
- T-003: Related technique identified during clustering.
- T-005: Related technique identified during clustering.
- T-006: Related technique identified during clustering.
- T-016: Related technique identified during clustering.

## References
- Internal cluster analysis
