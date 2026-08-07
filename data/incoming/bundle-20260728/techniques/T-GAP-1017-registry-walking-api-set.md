---
id: T-GAP-1017
name: "Registry Walking API Set for Persistence and Recon"
category: discovery
tier: C
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:registry-api-enumeration-primitives"]
---

# Registry Walking API Set for Persistence and Recon

## Summary

Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).


## Mechanism

RegQueryInfoKey + RegEnumValue/RegEnumKeyEx two-pass pattern; ERROR_INSUFFICIENT_BUFFER (0x7A) signals buffer sizing

## Rationale

Single coverage-gap note documenting the complete registry-walking Win32 API set as a foundational primitive underlying T-017 persistence and T-023 recon.

## Related To

T-017, T-023
