---
id: T-GAP-1013
name: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:coverage-gap-wdac-dynamic-code-trust-query"]
---

# WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust

## Summary

Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


## Mechanism

WldpQueryDynamicCodeTrust(base, size) → returns trust verdict for candidate executable region under WDAC/CIG enforcement

## Rationale

Single coverage-gap note documenting a specific WLDP API for pre-checking CIG/WDAC enforcement; not in T-001..T-074.

## Related To

T-016
