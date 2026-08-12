---
id: T-3006
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: syswhispers3-reference-tooling
member_notes: ['lgtm:vault-gap-syswhispers3-tooling']
---
## Summary

This technique card covers SysWhispers3 as Reference SSN-Stub Generator. It details mechanisms required to implement or understand syswhispers3-reference-tooling operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.



```c
// Example for SysWhispers3 as Reference SSN-Stub Generator
// Implementation specific to syswhispers3-reference-tooling
void execute_syswhispers3_reference_tooling() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:vault-gap-syswhispers3-tooling`: Referenced in internal atlas batches as a core component of syswhispers3-reference-tooling.

## Detection & Mitigation

Detection relies on monitoring call stacks (e.g. via ETW-Ti) for indirect syscall patterns or anomalous RIP values outside ntdll.dll module boundaries. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on SysWhispers3 as Reference SSN-Stub Generator
