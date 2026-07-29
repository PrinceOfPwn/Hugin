---
id: T-15817
title: "Registry Walking API Set for Persistence and Recon"
category: "edr-evasion"
tier: "C"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "registry-walking-api-set"
member_notes: ["lgtm:registry-api-enumeration-primitives"]
---

## Summary
This card covers the research gap identified as Registry Walking API Set for Persistence and Recon. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).


## Evidence
- lgtm:registry-api-enumeration-primitives: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-017: Related technique identified in gap analysis.
- T-023: Related technique identified in gap analysis.

## References
- To be added.
