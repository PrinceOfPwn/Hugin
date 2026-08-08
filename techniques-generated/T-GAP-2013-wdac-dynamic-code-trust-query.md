---
id: T-GAP-2013
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: "edr-evasion"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: wdac-dynamic-code-trust-query
member_notes: ['lgtm:coverage-gap-wdac-dynamic-code-trust-query']
---

## Summary
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Single coverage-gap note documenting a specific WLDP API for pre-checking CIG/WDAC enforcement; not in T-001..T-074.

## Evidence
- lgtm:coverage-gap-wdac-dynamic-code-trust-query: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
