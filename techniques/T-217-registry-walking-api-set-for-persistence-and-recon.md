---
id: T-217
title: "Registry Walking API Set for Persistence and Recon"
category: patterns
tier: C
tags: ['research-gap', 'registry-walking-api-set']
mitre: []
origin: glm-expand-cluster
source_cluster: registry-walking-api-set
member_notes: ['lgtm:registry-api-enumeration-primitives']
---

## Summary

This technique card addresses the research gap identified in cluster `registry-walking-api-set`.
Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).


## Technical Deep Dive

Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).


Technical anchor points:
```
RegQueryInfoKey + RegEnumValue/RegEnumKeyEx two-pass pattern; ERROR_INSUFFICIENT_BUFFER (0x7A) signals buffer sizing
```

## Evidence

- **lgtm:registry-api-enumeration-primitives**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-017: Relates to the foundational mechanisms discussed in this gap.
- T-023: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `registry-walking-api-set`
- Generated as part of batch processing to fill identified research gaps.
