---
id: T-214
title: "Registry Hive Operational Map"
category: patterns
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: registry-hive-operational-map
member_notes: ["lgtm:coverage-registry-hive-operational-map"]
---

## Summary
This technique covers Registry Hive Operational Map, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
SEC670 dedicates 10 units to enumerating the six registry hives with operational implications: HKU\.DEFAULT and HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID> for user SID discovery (ProfileImagePath value), HKLM\SAM for local account hashes (encrypted, requires SYSTEM token to read via RegSaveKeyEx or RegReadValue; typically read offline via secretsdump.py after RegSaveKey), HKLM\SECURITY for cached domain creds (NL$ keys under HKLM\SECURITY\Cache, 16-byte NLKM + cached domain hashes), HKLM\SYSTEM\CurrentControlSet\Services for driver / service inventory, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall for installed products (DisplayName, DisplayVersion, UninstallString), HKCU\Software for user-installed apps and config. The vault lacks a navigable operational map tying each hive to specific recon / persistence primitives; a reference card should enumerate the hive paths, the SYSTEM-token requirement, and the typical secrets dump pipeline (reg save -> secretsdump.py -> Mimikatz).


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID> ProfileImagePath value + HKLM\SECURITY\Cache\NL$ keys for cached domain credentials
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:coverage-registry-hive-operational-map: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.
- T-023: Relates conceptually based on evidence.

## References
- Internal vault documentation on Registry Hive Operational Map
