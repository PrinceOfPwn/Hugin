---
id: T-GAP-2021
title: "UACMe Auto-Elevation DLL Search-Order Hijack"
category: "privesc"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: uacme-dll-search-order-hijack
member_notes: ['lgtm:uacme-dll-search-order-hijack']
---

## Summary
Documents the UACMe FusionScanDirectory technique for auto-elevation DLL search-order hijack. The target is a binary in %SystemRoot%\System32\ that has the autoElevate manifest flag (slui.exe, dccw.exe, eventvwr.exe exemplars). The hijack enumerates the application's directory for plantable DLL names using FindFirstFile/FindNextFile (RtlSecureZeroMemory'd WIN32_FIND_DATA buffer), drops a malicious DLL with a matching name into a writable adjacent path, then triggers the auto-elevated binary which loads the malicious DLL via the default search order (application directory first). Distinct from COM hijack (T-021) which manipulates CLSID registry entries.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Single convergence note documenting the UACMe FusionScanDirectory search-order hijack as a discrete UAC-bypass primitive; named tooling reference.

## Evidence
- lgtm:uacme-dll-search-order-hijack: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
