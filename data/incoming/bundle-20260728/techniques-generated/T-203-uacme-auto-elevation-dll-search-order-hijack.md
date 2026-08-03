---
id: T-203
title: "UACMe Auto-Elevation DLL Search-Order Hijack"
category: patterns
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: uacme-dll-search-order-hijack
member_notes: ["lgtm:uacme-dll-search-order-hijack"]
---

## Summary
This technique covers UACMe Auto-Elevation DLL Search-Order Hijack, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the UACMe FusionScanDirectory technique for auto-elevation DLL search-order hijack. The target is a binary in %SystemRoot%\System32\ that has the autoElevate manifest flag (slui.exe, dccw.exe, eventvwr.exe exemplars). The hijack enumerates the application's directory for plantable DLL names using FindFirstFile/FindNextFile (RtlSecureZeroMemory'd WIN32_FIND_DATA buffer), drops a malicious DLL with a matching name into a writable adjacent path, then triggers the auto-elevated binary which loads the malicious DLL via the default search order (application directory first). Distinct from COM hijack (T-021) which manipulates CLSID registry entries.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// FusionScanDirectory() from UACMe — auto-elevated binary (autoElevate=true manifest) + FindFirstFile/FindNextFile enumeration of plantable DLL names
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:uacme-dll-search-order-hijack: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-021: Relates conceptually based on evidence.
- T-023: Relates conceptually based on evidence.

## References
- Internal vault documentation on UACMe Auto-Elevation DLL Search-Order Hijack
