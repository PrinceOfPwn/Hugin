---
id: T-921
title: "UACMe Auto-Elevation DLL Search-Order Hijack"
category: patterns
tier: A
tags: [generated, manual]
mitre: []
origin: manual-expand-cluster
source_cluster: uacme-dll-search-order-hijack
member_notes: ['lgtm:uacme-dll-search-order-hijack']
---

## Summary
Documents the UACMe FusionScanDirectory technique for auto-elevation DLL search-order hijack.

## Technical Deep Dive
Documents the UACMe FusionScanDirectory technique for auto-elevation DLL search-order hijack. The target is a binary in %SystemRoot%\System32\ that has the autoElevate manifest flag (slui.exe, dccw.exe, eventvwr.exe exemplars). The hijack enumerates the application's directory for plantable DLL names using FindFirstFile/FindNextFile (RtlSecureZeroMemory'd WIN32_FIND_DATA buffer), drops a malicious DLL with a matching name into a writable adjacent path, then triggers the auto-elevated binary which loads the malicious DLL via the default search order (application directory first). Distinct from COM hijack (T-021) which manipulates CLSID registry entries.


## Evidence
- lgtm:uacme-dll-search-order-hijack

## Detection & Mitigation
- Standard monitoring and detection.

## Related Techniques
- N/A

## References
- N/A
