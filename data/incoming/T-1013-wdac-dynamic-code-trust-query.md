---
id: T-1013
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: edr-evasion
tier: A
tags: [research-gap, edr-evasion]
mitre: []
origin: glm-expand-cluster
source_cluster: wdac-dynamic-code-trust-query
member_notes: ['lgtm:coverage-gap-wdac-dynamic-code-trust-query']
---

## Summary
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination.

## Technical Deep Dive
The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.

### Technical Anchor
WldpQueryDynamicCodeTrust(base, size) → returns trust verdict for candidate executable region under WDAC/CIG enforcement

## Evidence
- `lgtm:coverage-gap-wdac-dynamic-code-trust-query`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-016: Related technique identified during clustering.

## References
- Internal cluster analysis
