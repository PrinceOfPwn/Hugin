---
id: T-202
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: edr-evasion
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: wdac-dynamic-code-trust-query
member_notes: ["lgtm:coverage-gap-wdac-dynamic-code-trust-query"]
---

## Summary
This technique covers WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// WldpQueryDynamicCodeTrust(base, size) → returns trust verdict for candidate executable region under WDAC/CIG enforcement
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:coverage-gap-wdac-dynamic-code-trust-query: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust
