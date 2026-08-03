---
id: T-201
title: "Heaven's Gate 32→64-bit WOW64 Syscall Bridge"
category: syscalls
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: heavens-gate-wow64-bridge
member_notes: ["lgtm:vault-gap-heavens-gate"]
---

## Summary
This technique covers Heaven's Gate 32→64-bit WOW64 Syscall Bridge, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// Far jump via segment selector 0x33 (64-bit CS) through ntdll.Wow64Transition → wow64cpu.dll TurboDispatch; FAR RET to switch CS register
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:vault-gap-heavens-gate: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-001: Relates conceptually based on evidence.
- T-002: Relates conceptually based on evidence.

## References
- Internal vault documentation on Heaven's Gate 32→64-bit WOW64 Syscall Bridge
