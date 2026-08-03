---
id: T-236
title: "Persistence Risk-Benefit Decision Framework"
category: persistence
tier: C
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: persistence-risk-decision-framework
member_notes: ["lgtm:persistence-risk-decision-framework"]
---

## Summary
This technique covers Persistence Risk-Benefit Decision Framework, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
SEC670 frames persistence as a bounded decision: not every engagement requires persistence, the chosen method depends on target sensitivity and dwell-time budget, and the operator should select the least risky method available. Decision factors include detection surface (e.g., schtask XML triggers ETW Microsoft-Windows-ScheduledTask, IFEO Debugger produces ImageLoad events under Microsoft-Windows-Kernel-Image), survivability across reboot / logout / user switch, and required privileges (admin vs SYSTEM vs user-only). T-017 enumerates the suite layers without a decision framework that an operator can use to triage which layer fits a specific engagement profile; a methodology card should map each T-017 layer to detection surface, privilege requirement, and dwell-time profile.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// Decision matrix: ETW providers Microsoft-Windows-ScheduledTask (for schtask layer) and Microsoft-Windows-Kernel-Image (for IFEO Debugger layer) vs privilege requirement vs reboot-survivable flag
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:persistence-risk-decision-framework: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.

## References
- Internal vault documentation on Persistence Risk-Benefit Decision Framework
