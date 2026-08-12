---
id: T-3003
title: "x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs"
category: syscalls
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: x64-abi-syscall-stub-construction
member_notes: ['lgtm:x64-calling-convention-stub-constraint', 'lgtm:x64-abi-syscall-stub-construction', 'lgtm:cross-source-convergence-shadow-store-and-rop']
---
## Summary

This technique card covers x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs. It details mechanisms required to implement or understand x64-abi-syscall-stub-construction operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.



```c
// Example for x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs
// Implementation specific to x64-abi-syscall-stub-construction
void execute_x64_abi_syscall_stub_construction() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:x64-calling-convention-stub-constraint`: Referenced in internal atlas batches as a core component of x64-abi-syscall-stub-construction.
- `lgtm:x64-abi-syscall-stub-construction`: Referenced in internal atlas batches as a core component of x64-abi-syscall-stub-construction.
- `lgtm:cross-source-convergence-shadow-store-and-rop`: Referenced in internal atlas batches as a core component of x64-abi-syscall-stub-construction.

## Detection & Mitigation

Detection relies on monitoring call stacks (e.g. via ETW-Ti) for indirect syscall patterns or anomalous RIP values outside ntdll.dll module boundaries. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs
