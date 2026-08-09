---
id: T-203
title: "x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs"
category: syscalls
tier: B
tags: ['research-gap', 'x64-abi-syscall-stub-construction']
mitre: []
origin: glm-expand-cluster
source_cluster: x64-abi-syscall-stub-construction
member_notes: ['lgtm:x64-calling-convention-stub-constraint', 'lgtm:x64-abi-syscall-stub-construction', 'lgtm:cross-source-convergence-shadow-store-and-rop']
---

## Summary

This technique card addresses the research gap identified in cluster `x64-abi-syscall-stub-construction`.
Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.


## Technical Deep Dive

Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.


Technical anchor points:
```
32-byte shadow store at RSP+0..RSP+20h (8 × 8 bytes); RCX/RDX/R8/R9 first four args, RAX for syscall number
```

## Evidence

- **lgtm:x64-calling-convention-stub-constraint**: Extracted as a foundational reference note for this cluster.
- **lgtm:x64-abi-syscall-stub-construction**: Extracted as a foundational reference note for this cluster.
- **lgtm:cross-source-convergence-shadow-store-and-rop**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-001: Relates to the foundational mechanisms discussed in this gap.
- T-002: Relates to the foundational mechanisms discussed in this gap.
- T-003: Relates to the foundational mechanisms discussed in this gap.
- T-005: Relates to the foundational mechanisms discussed in this gap.
- T-006: Relates to the foundational mechanisms discussed in this gap.
- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `x64-abi-syscall-stub-construction`
- Generated as part of batch processing to fill identified research gaps.
