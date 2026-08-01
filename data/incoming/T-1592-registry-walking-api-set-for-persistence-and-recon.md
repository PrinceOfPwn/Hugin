---
id: T-1592
title: "Registry Walking API Set for Persistence and Recon"
category: discovery
tier: C
tags: [registry, walking, api, set]
mitre: []
origin: glm-expand-cluster
source_cluster: registry-walking-api-set
member_notes: ['lgtm:registry-api-enumeration-primitives']
---

## Summary
Documents the complete registry-walking Win32 API set: RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &hKey), RegQueryValueExW(hKey, valueName, NULL, &type, buffer, &size), RegEnumValue(hKey, index, valueName, &nameLen, NULL, &type, data, &dataLen), RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, NULL, NULL). The two-pass buffer-size pattern (call with NULL buffer → ERROR_MORE_DATA/ERROR_INSUFFICIENT_BUFFER → allocate → retry) underlies all registry enumeration. Pairs with T-017 persistence enumeration (walking Run keys, Image File Execution Options, AppInit_DLLs, AppCertDlls) and T-023 recon (registry-based discovery).

## Technical Deep Dive
Single coverage-gap note documenting the complete registry-walking Win32 API set as a foundational primitive underlying T-017 persistence and T-023 recon.

Key technical anchor: RegQueryInfoKey + RegEnumValue/RegEnumKeyEx two-pass pattern; ERROR_INSUFFICIENT_BUFFER (0x7A) signals buffer sizing

## Evidence
- lgtm:registry-api-enumeration-primitives: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-017 - related to Registry Walking API Set for Persistence and Recon
- T-023 - related to Registry Walking API Set for Persistence and Recon

## References
- Refer to internal research note registry-walking-api-set for preliminary data.
