---
id: T-GAP-1021
name: "UACMe Auto-Elevation DLL Search-Order Hijack"
category: privesc
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:uacme-dll-search-order-hijack"]
---

# UACMe Auto-Elevation DLL Search-Order Hijack

## Summary

Documents the UACMe FusionScanDirectory technique for auto-elevation DLL search-order hijack. The target is a binary in %SystemRoot%\System32\ that has the autoElevate manifest flag (slui.exe, dccw.exe, eventvwr.exe exemplars). The hijack enumerates the application's directory for plantable DLL names using FindFirstFile/FindNextFile (RtlSecureZeroMemory'd WIN32_FIND_DATA buffer), drops a malicious DLL with a matching name into a writable adjacent path, then triggers the auto-elevated binary which loads the malicious DLL via the default search order (application directory first). Distinct from COM hijack (T-021) which manipulates CLSID registry entries.


## Mechanism

FusionScanDirectory() from UACMe — auto-elevated binary (autoElevate=true manifest) + FindFirstFile/FindNextFile enumeration of plantable DLL names

## Rationale

Single convergence note documenting the UACMe FusionScanDirectory search-order hijack as a discrete UAC-bypass primitive; named tooling reference.

## Related To

T-021, T-023
