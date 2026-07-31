---
id: T-1593
title: "SEC670 Convergence on Injection and Evasion Tradecraft"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: sec670-injection-evasion-convergence
member_notes: ['lgtm:sec670-cross-source-convergence']
---

## Summary
This technique covers the concepts surrounding SEC670 Convergence on Injection and Evasion Tradecraft. It represents a synthesized view of the identified research gap `sec670-injection-evasion-convergence` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
Multiple SEC670 labs converge on the same injection and evasion technique
space as the vault's T-007/T-013/T-016: Call_DirectInjection (direct syscall
injection, mirrors T-001/T-007), APCInjection (APC queue injection, mirrors
T-007 APC variant), ThreadHijacker (thread context RIP overwrite, mirrors
T-014), ClassicDLLInjection (LoadLibrary via CreateRemoteThread, mirrors
T-007 baseline), The Loader (manual PE loader, mirrors T-013 RDI),
UnhookTheHook (NTDLL .text section overwrite from clean on-disk copy,
mirrors T-016), AMSI No More (AmsiScanBuffer patching, mirrors T-016). The
convergence validates the vault's technique categorization but suggests the
vault could document lab-to-technique mapping as a pedagogic bridge. The
card should be a cross-reference table linking each SEC670 lab exercise to
its corresponding T-NNN card.

At a deeper API level, this involves understanding the specific structures and offsets associated with sec670-injection-evasion-convergence. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `sec670-injection-evasion-convergence`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `sec670-injection-evasion-convergence`
- Synthesized Coverage Gap Documentation