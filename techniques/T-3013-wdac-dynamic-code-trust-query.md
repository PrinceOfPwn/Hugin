---
id: T-3013
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: edr-evasion
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: wdac-dynamic-code-trust-query
member_notes: ['lgtm:coverage-gap-wdac-dynamic-code-trust-query']
---
## Summary

This technique card covers WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust. It details mechanisms required to implement or understand wdac-dynamic-code-trust-query operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.



```c
// Example for WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust
// Implementation specific to wdac-dynamic-code-trust-query
void execute_wdac_dynamic_code_trust_query() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:coverage-gap-wdac-dynamic-code-trust-query`: Referenced in internal atlas batches as a core component of wdac-dynamic-code-trust-query.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust
