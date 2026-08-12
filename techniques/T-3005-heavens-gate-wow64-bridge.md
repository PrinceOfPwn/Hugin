---
id: T-3005
title: "Heaven's Gate 32→64-bit WOW64 Syscall Bridge"
category: syscalls
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: heavens-gate-wow64-bridge
member_notes: ['lgtm:vault-gap-heavens-gate']
---
## Summary

This technique card covers Heaven's Gate 32→64-bit WOW64 Syscall Bridge. It details mechanisms required to implement or understand heavens-gate-wow64-bridge operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.



```c
// Example for Heaven's Gate 32→64-bit WOW64 Syscall Bridge
// Implementation specific to heavens-gate-wow64-bridge
void execute_heavens_gate_wow64_bridge() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:vault-gap-heavens-gate`: Referenced in internal atlas batches as a core component of heavens-gate-wow64-bridge.

## Detection & Mitigation

Detection relies on monitoring call stacks (e.g. via ETW-Ti) for indirect syscall patterns or anomalous RIP values outside ntdll.dll module boundaries. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Heaven's Gate 32→64-bit WOW64 Syscall Bridge
