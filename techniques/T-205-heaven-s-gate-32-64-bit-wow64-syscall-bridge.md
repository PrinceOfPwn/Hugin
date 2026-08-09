---
id: T-205
title: "Heaven's Gate 32→64-bit WOW64 Syscall Bridge"
category: syscalls
tier: A
tags: ['research-gap', 'heavens-gate-wow64-bridge']
mitre: []
origin: glm-expand-cluster
source_cluster: heavens-gate-wow64-bridge
member_notes: ['lgtm:vault-gap-heavens-gate']
---

## Summary

This technique card addresses the research gap identified in cluster `heavens-gate-wow64-bridge`.
Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.


## Technical Deep Dive

Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.


Technical anchor points:
```
Far jump via segment selector 0x33 (64-bit CS) through ntdll.Wow64Transition → wow64cpu.dll TurboDispatch; FAR RET to switch CS register
```

## Evidence

- **lgtm:vault-gap-heavens-gate**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-001: Relates to the foundational mechanisms discussed in this gap.
- T-002: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `heavens-gate-wow64-bridge`
- Generated as part of batch processing to fill identified research gaps.
