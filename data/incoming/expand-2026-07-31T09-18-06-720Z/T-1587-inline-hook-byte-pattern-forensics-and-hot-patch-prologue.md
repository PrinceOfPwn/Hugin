---
id: T-1587
title: "Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: inline-hook-byte-forensics-hot-patch
member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']
---

## Summary
This technique covers the concepts surrounding Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue. It represents a synthesized view of the identified research gap `inline-hook-byte-forensics-hot-patch` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.

At a deeper API level, this involves understanding the specific structures and offsets associated with inline-hook-byte-forensics-hot-patch. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `inline-hook-byte-forensics-hot-patch`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `inline-hook-byte-forensics-hot-patch`
- Synthesized Coverage Gap Documentation