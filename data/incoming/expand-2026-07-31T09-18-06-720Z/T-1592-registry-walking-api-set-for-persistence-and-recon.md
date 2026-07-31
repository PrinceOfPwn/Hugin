---
id: T-1592
title: "Registry Walking API Set for Persistence and Recon"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: registry-walking-api-set
member_notes: ['lgtm:registry-api-enumeration-primitives']
---

## Summary
This technique covers the concepts surrounding Registry Walking API Set for Persistence and Recon. It represents a synthesized view of the identified research gap `registry-walking-api-set` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).

At a deeper API level, this involves understanding the specific structures and offsets associated with registry-walking-api-set. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `registry-walking-api-set`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `registry-walking-api-set`
- Synthesized Coverage Gap Documentation