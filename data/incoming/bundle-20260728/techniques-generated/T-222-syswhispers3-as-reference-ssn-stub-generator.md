---
id: T-222
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: syswhispers3-reference-tooling
member_notes: ["lgtm:vault-gap-syswhispers3-tooling"]
---

## Summary
This technique covers SysWhispers3 as Reference SSN-Stub Generator, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// SysWhispers3 stub modes: WoW64, egg-hunter (`@__Nt` egg pattern), direct `syscall` in user stub, indirect `jmp` into ntdll `syscall; ret` gadget
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:vault-gap-syswhispers3-tooling: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-001: Relates conceptually based on evidence.
- T-002: Relates conceptually based on evidence.
- T-006: Relates conceptually based on evidence.

## References
- Internal vault documentation on SysWhispers3 as Reference SSN-Stub Generator
