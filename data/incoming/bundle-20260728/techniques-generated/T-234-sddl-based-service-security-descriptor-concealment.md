---
id: T-234
title: "SDDL-Based Service Security Descriptor Concealment"
category: edr-evasion
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: sddl-service-concealment
member_notes: ["lgtm:cross-source-convergence-sddl-service-hiding"]
---

## Summary
This technique covers SDDL-Based Service Security Descriptor Concealment, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
sc.exe sdset allows an operator to rewrite a service's DACL using Security Descriptor Definition Language (SDDL), stripping query permissions so that subsequent sc.exe qc / query / EnumServicesStatus / EnumDependentServices calls from non-impersonated contexts return ERROR_ACCESS_DENIED. SEC670 frames this as operationally distinct from kernel-driver-based PspCidTable process hiding or PEB unlinking because it works from any integrity level, only against service enumeration (not active execution), and complements rather than replaces binary-based service persistence. The vault's T-016/T-017 should document the SDDL syntax: D:(D;;0x4;;;WD) to deny SERVICE_QUERY_STATUS and D:(D;;0x20;;;WD) to deny SERVICE_QUERY_CONFIG to Everyone, plus the sc.exe command `sc sdset <svc> <SDDL>`.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// sc.exe sdset <service> D:(D;;0x4;;;WD)(D;;0x20;;;WD) stripping SERVICE_QUERY_STATUS (0x4) and SERVICE_QUERY_CONFIG (0x20) rights from Everyone (WD) SID
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:cross-source-convergence-sddl-service-hiding: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on SDDL-Based Service Security Descriptor Concealment
