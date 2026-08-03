---
id: T-237
title: "Registry Persistence Write Blending via OS Read-Timing Windows"
category: persistence
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: registry-write-blending-timing-tradecraft
member_notes: ["lgtm:registry-blending-timing-tradecraft"]
---

## Summary
This technique covers Registry Persistence Write Blending via OS Read-Timing Windows, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
SEC670 identifies four registry-read timing windows during which an OS component reads specific keys: initial boot (smss.exe reads HKLM\SYSTEM\Setup for boot execution order), kernel boot (kernel reads HKLM\SYSTEM\CurrentControlSet for driver loading), logon (winlogon.exe reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit), and app startup. Continuous-polling applications (OneDrive, Teams) read their own keys repeatedly. An operator can blend persistence writes into these windows so a value-write event correlates with expected OS behavior, reducing EDR signal-to-noise and avoiding heuristic flag-on-write alerts. The vault's T-017 does not document this timing tradecraft layer; the card should map the four windows to specific keys and to the OS component performing the read.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// winlogon.exe read of HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit at logon phase, providing write-blend window for persistence value
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:registry-blending-timing-tradecraft: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.

## References
- Internal vault documentation on Registry Persistence Write Blending via OS Read-Timing Windows
