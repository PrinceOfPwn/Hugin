---
id: T-15813
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "wdac-dynamic-code-trust-query"
member_notes: ["lgtm:coverage-gap-wdac-dynamic-code-trust-query"]
---

## Summary
This card covers the research gap identified as WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


## Evidence
- lgtm:coverage-gap-wdac-dynamic-code-trust-query: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References
- To be added.
