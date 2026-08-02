---
id: T-905
title: "Heaven's Gate 32→64-bit WOW64 Syscall Bridge"
category: syscalls
tier: A
tags: [generated, manual]
mitre: []
origin: manual-expand-cluster
source_cluster: heavens-gate-wow64-bridge
member_notes: ['lgtm:vault-gap-heavens-gate']
---

## Summary
Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump in...

## Technical Deep Dive
Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.


## Evidence
- lgtm:vault-gap-heavens-gate

## Detection & Mitigation
- Standard monitoring and detection.

## Related Techniques
- N/A

## References
- N/A
