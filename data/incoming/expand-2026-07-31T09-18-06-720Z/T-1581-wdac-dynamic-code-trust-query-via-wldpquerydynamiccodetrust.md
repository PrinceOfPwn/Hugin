---
id: T-1581
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: wdac-dynamic-code-trust-query
member_notes: ['lgtm:coverage-gap-wdac-dynamic-code-trust-query']
---

## Summary
This technique covers the concepts surrounding WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust. It represents a synthesized view of the identified research gap `wdac-dynamic-code-trust-query` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.

At a deeper API level, this involves understanding the specific structures and offsets associated with wdac-dynamic-code-trust-query. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `wdac-dynamic-code-trust-query`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `wdac-dynamic-code-trust-query`
- Synthesized Coverage Gap Documentation