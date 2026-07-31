---
id: T-1577
title: "Heaven's Gate 32→64-bit WOW64 Syscall Bridge"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: heavens-gate-wow64-bridge
member_notes: ['lgtm:vault-gap-heavens-gate']
---

## Summary
This technique covers the concepts surrounding Heaven's Gate 32→64-bit WOW64 Syscall Bridge. It represents a synthesized view of the identified research gap `heavens-gate-wow64-bridge` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.

At a deeper API level, this involves understanding the specific structures and offsets associated with heavens-gate-wow64-bridge. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `heavens-gate-wow64-bridge`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `heavens-gate-wow64-bridge`
- Synthesized Coverage Gap Documentation