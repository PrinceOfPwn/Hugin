---
id: T-231
title: "Defender Exclusion Path Abuse for Payload Staging"
category: edr-evasion
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: defender-exclusion-path-abuse
member_notes: ["lgtm:defender-exclusion-path-abuse-as-evasion"]
---

## Summary
This technique covers Defender Exclusion Path Abuse for Payload Staging, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents Set-MpPreference -ExclusionPath as a simple administrative route to keep payloads out of scanning scope. The exclusion persists in registry under HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths (MpEnableDefaults = 1 flag enables policy). Requires local Administrator privileges — pairs naturally with T-017 persistence (post-privilege-escalation) and T-021 client capability (defender enumeration). The vault's T-016 evasion suite covers AMSI, ETW, hooks, and policy enforcement but does not document this simple administrative lever. Detection: defender event logs (Operational channel, event ID 5007 "configuration changed") and MpCmdRun -RestoreDefaults countermeasure.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// Set-MpPreference -ExclusionPath → HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths registry persistence
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:defender-exclusion-path-abuse-as-evasion: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-016: Relates conceptually based on evidence.
- T-017: Relates conceptually based on evidence.

## References
- Internal vault documentation on Defender Exclusion Path Abuse for Payload Staging
