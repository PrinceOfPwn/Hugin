---
id: T-230
title: "VX-Underground AV Artifacts Catalog as EDR Hook Reference"
category: edr-evasion
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: vx-underground-av-artifacts-catalog
member_notes: ["lgtm:vx-underground-av-artifacts-catalog"]
---

## Summary
This technique covers VX-Underground AV Artifacts Catalog as EDR Hook Reference, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the VX-Underground "AntiVirus Artifacts" whitepaper series (first, second, third editions) as the canonical catalog enumerating which Nt* APIs each EDR vendor hooks and in which module (ntdll.dll vs win32u.dll vs kernelbase.dll). The vault's T-016 unhook documentation is implicitly vendor-agnostic; this reference card surfaces vendor-specific hook inventories so an operator targeting a known EDR (e.g., CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) can pre-compute which Nt* stubs need restoration and which are clean. Cross-references to the inline-hook byte-forensics card for runtime verification.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// VX-Underground AV Artifacts whitepaper series enumerating per-vendor Nt* hook inventories across ntdll.dll / win32u.dll / kernelbase.dll
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:vx-underground-av-artifacts-catalog: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-001: Relates conceptually based on evidence.
- T-002: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on VX-Underground AV Artifacts Catalog as EDR Hook Reference
