---
id: T-213
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: edr-evasion
tier: A
tags: ['research-gap', 'wdac-dynamic-code-trust-query']
mitre: []
origin: glm-expand-cluster
source_cluster: wdac-dynamic-code-trust-query
member_notes: ['lgtm:coverage-gap-wdac-dynamic-code-trust-query']
---

## Summary

This technique card addresses the research gap identified in cluster `wdac-dynamic-code-trust-query`.
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


## Technical Deep Dive

Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


Technical anchor points:
```
WldpQueryDynamicCodeTrust(base, size) → returns trust verdict for candidate executable region under WDAC/CIG enforcement
```

## Evidence

- **lgtm:coverage-gap-wdac-dynamic-code-trust-query**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `wdac-dynamic-code-trust-query`
- Generated as part of batch processing to fill identified research gaps.
