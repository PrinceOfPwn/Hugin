---
id: T-GAP-2017
title: "Registry Walking API Set for Persistence and Recon"
category: "discovery"
tier: "C"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: registry-walking-api-set
member_notes: ['lgtm:registry-api-enumeration-primitives']
---

## Summary
Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Single coverage-gap note documenting the complete registry-walking Win32 API set as a foundational primitive underlying T-017 persistence and T-023 recon.

## Evidence
- lgtm:registry-api-enumeration-primitives: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
