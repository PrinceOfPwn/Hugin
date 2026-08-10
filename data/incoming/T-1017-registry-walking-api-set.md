---
id: T-1017
title: "Registry Walking API Set for Persistence and Recon"
category: patterns
tier: C
tags: [research-gap, patterns]
mitre: []
origin: glm-expand-cluster
source_cluster: registry-walking-api-set
member_notes: ['lgtm:registry-api-enumeration-primitives']
---

## Summary
Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration.

## Technical Deep Dive
Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).

### Technical Anchor
RegQueryInfoKey + RegEnumValue/RegEnumKeyEx two-pass pattern; ERROR_INSUFFICIENT_BUFFER (0x7A) signals buffer sizing

## Evidence
- `lgtm:registry-api-enumeration-primitives`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-017: Related technique identified during clustering.
- T-023: Related technique identified during clustering.

## References
- Internal cluster analysis
