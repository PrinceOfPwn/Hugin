# Cluster Spec — T-080: Host Recon Surface Catalog (Registry, WMI, KUSER, SDDL, sc.exe)

- **T-NNN ID**: `T-080`
- **Canonical name**: Host Recon Surface Catalog (Registry, WMI, KUSER, SDDL, sc.exe)
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Two member notes with cross-source consensus; consolidates 6+ recon surfaces into one navigable catalog
- **would_relate_to**: ['T-023']

## Consolidated Description

SEC670 recon material forms a host recon surface catalog: registry hives (HKU ProfileList for user SID discovery via ProfileImagePath, HKLM SAM for local account hashes, HKLM SECURITY for cached domain creds under HKLM\SECURITY\Cache, HKLM SYSTEM CurrentControlSet for service / driver inventory, HKLM SOFTWARE Microsoft Windows CurrentVersion Uninstall for installed products, HKCU Software for user-installed apps), WMI Win32 provider classes (Win32_Process, Win32_Service, Win32_Registry, Win32_OperatingSystem, Win32_NetworkAdapterConfiguration), KUSER_SHARED_DATA direct read, ProfileList for SID enumeration, sc.exe security descriptors for service ACL mapping via sc.exe sdshow. The API selection consensus: GetAdapterAddresses vs GetNumberOfInterfaces vs GetIpStatistics distinction; CreateToolhelp32Snapshot vs WTSEnumerateProcesses vs WMI Win32_Process for process enumeration; each pair maps to a different signal / detail trade-off.


## Member LGTM Notes (2)

### Note 1: Host Recon Surface Catalog for Implant Developers
- id: `lgtm:host-recon-surface-catalog-gap`
- origin: atlas-recon-part3
- would_relate_to: ['T-023']
- tags: ['recon', 'coverage-gap', 'sysinfo', 'wmi', 'registry', 'catalog']

**Kind:** coverage-gap
**Origin:** atlas-recon-part3
**Would relate to:** T-023
**Source units:** unit 4, unit 9, unit 15, unit 20, unit 23, unit 18

The on-theme portions of this batch — registry hives, WMI Win32 Provider classes, KUSER_SHARED_DATA, ProfileList, sc.exe security descriptors — form a recon surface catalog: the specific Windows data sources an implant queries for situational awareness. T-023 mentions 'recon' generically but does not enumerate these sources, their detection profiles, or their evasion characteristics. A dedicated catalog would help operators pick recon primitives matching their evasion posture.

### Note 2: Recon API Selection Consensus Across SEC670 and CRTO
- id: `lgtm:cross-source-recon-api-selection-consensus`
- origin: atlas-recon-part6
- would_relate_to: ['T-023']
- tags: ['recon', 'api-selection', 'opsec', 'convergence', 'sec670', 'crto']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part6
**Would relate to:** T-023
**Source units:** unit 10, unit 11, unit 12, unit 21, unit 32

Both SEC670 (GetAdapterAddresses vs GetNumberOfInterfaces vs GetIpStatistics distinction; CreateToolhelp32Snapshot vs WTSEnumerateProcesses vs WMI Win32_Process) and CRTO (PowerView cmdlet selection based on OPSEC) converge on the principle that recon API selection is consequential — different APIs return different fields, hit different log sources, and have different noise profiles. The vault currently treats T-023 recon as a single bucket; surfacing this selection tradeoff would help operators choose APIs deliberately rather than by default.

---
Use `id: T-080`, canonical name above, and `member_notes: ['lgtm:host-recon-surface-catalog-gap', 'lgtm:cross-source-recon-api-selection-consensus']`.
Cross-reference `would_relate_to`: ['T-023'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.