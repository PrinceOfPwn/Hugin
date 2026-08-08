---
id: T-GAP-1013
title: "WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust"
tier: "A"
category: "edr-evasion"
---

# WDAC Dynamic Code Trust Query via WldpQueryDynamicCodeTrust

## Description
Documents WldpQueryDynamicCodeTrust as the user-mode query for Windows Defender Application Control (WDAC) dynamic-code trust — the API an implant uses to check whether a candidate payload region (e.g., RWX memory about to be executed) would survive Code Integrity Guard (CIG) enforcement before committing the allocation. Without this check, an implant attempting module stomping or shellcode-to-PIC transition on a WDAC-enforced process triggers a CiInitializeSigned policy violation and process termination. The query takes the candidate base address and returns a trust verdict; pairs with WLDP API set wldp.dll. Distinct from WldpIsClassApproved / WldpQueryDynamicCodeTrust — the latter is the runtime check, the former is policy enumeration.


## Rationale
Single coverage-gap note documenting a specific WLDP API for pre-checking CIG/WDAC enforcement; not in T-001..T-074.

## References
- lgtm:coverage-gap-wdac-dynamic-code-trust-query
