---
id: T-3017
title: "Registry Walking API Set for Persistence and Recon"
category: discovery
tier: C
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: registry-walking-api-set
member_notes: ['lgtm:registry-api-enumeration-primitives']
---
## Summary

This technique card covers Registry Walking API Set for Persistence and Recon. It details mechanisms required to implement or understand registry-walking-api-set operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).



```c
// Example for Registry Walking API Set for Persistence and Recon
// Implementation specific to registry-walking-api-set
void execute_registry_walking_api_set() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:registry-api-enumeration-primitives`: Referenced in internal atlas batches as a core component of registry-walking-api-set.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Registry Walking API Set for Persistence and Recon
