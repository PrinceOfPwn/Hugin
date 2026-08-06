---
id: T-018
title: "Registry Walking API Set for Persistence and Recon"
category: discovery
tier: C
tags: [gap-card]
mitre: []
origin: manual-script
source_cluster: registry-walking-api-set
member_notes: ["lgtm:registry-api-enumeration-primitives"]
---

## Summary

Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).


## Technical Deep Dive

Single coverage-gap note documenting the complete registry-walking Win32 API set as a foundational primitive underlying T-017 persistence and T-023 recon.

## Evidence

- lgtm:registry-api-enumeration-primitives

## Detection & Mitigation

N/A

## Related Techniques

N/A

## References

N/A
