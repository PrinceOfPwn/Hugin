---
id: T-099
name: Disk Artifact Placement and DRM Protection
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1027
mitre_secondary: [T1036]
tags: [disk-artifact, placement-tradecraft, drm-protection, artifact-protection, opsec, pe-protection, binary-spoofing, drop-location]
origin: atlas-synthesis
member_notes: ['lgtm:disk-placement-tradecraft', 'lgtm:implant-drm-protection']
---

# Disk Artifact Placement and DRM Protection Tradecraft — Strategic On-Disk Binary Hardening

## Summary

Strategic on-disk artifact placement and DRM-based integrity protection form a two-part discipline for managing risk when persistence-dropped or stage-downloaded binaries must reside on disk. Placement heuristics govern which directory — Desktop, Documents, Downloads, Pictures, Temp, AppData, Program Files, SysWOW64, System32, OneDrive — minimizes detection attention by blending with legitimate file noise, while DRM techniques (IPRIP-protected PE structures, self-signed code signing, PIMAGE_LOAD_CONFIG_DIRECTORY integrity check entries) prevent static analysis and signature matching by AV engines. The primary detection surface is filesystem monitoring via Sysmon FileCreate events and on-access AV scanning of new files in high-scrutiny directories. Together these techniques address the operational gap between T-017's persistence mechanisms that create disk-resident artifacts and T-020's anti-analysis capabilities that do not cover placement strategy.

## Mechanism

1. The operator selects a drop directory based on the target environment's file noise profile. Each location carries distinct risk and signal characteristics that determine its suitability:

2. **User-profile directories (Desktop, Documents, Downloads, Pictures)** — user-writable without elevation, common for legitimate application drops. However, EDR file-create rules commonly flag executable files (.exe, .dll, .sys) appearing in user-profile paths. Downloads is subject to Mark of the Web (MOTW) enforcement on Windows 10+, which applies SmartScreen, AppLocker, and Attack Surface Reduction (ASR) restrictions to browser-downloaded binaries. Files placed via non-browser channels (direct file write, SMB copy) do not receive a MOTW alternate data stream unless explicitly applied.

3. **Temp (%TEMP%)** — high file churn provides blending, but EDRs commonly flag executable drops in Temp as a heuristic. The directory is cleaned by Storage Sense and Disk Cleanup on schedules, making it unreliable for long-term persistence.

4. **AppData (Local/Roaming)** — large directory trees with hundreds of legitimate application subfolders. Executable noise is high — Discord, Microsoft Teams, Chrome updater, VS Code update services all drop executables here. Blending is strong because EDRs cannot practically alert on every executable in AppData without generating excessive false positives.

5. **Program Files / Program Files (x86)** — requires elevation to write. Executables here are expected to be signed and installed via MSI or package managers. Unsigned or non-installed binaries stand out against the signed baseline. EDRs that enforce code integrity for Program Files will flag unsigned executables.

6. **SysWOW64 / System32** — highest AV scrutiny. Any non-Microsoft-signed binary in System32 is immediately flagged by most EDR products. Placement here requires either signed binary proxying, DLL stomping, or an already-present legitimate binary to overwrite. The detection cost is near-certain; the blending benefit is zero unless the binary is renamed to match a known system component.

7. **OneDrive** — if OneDrive sync is active, files placed in a synced folder are automatically uploaded to the user's Microsoft account cloud storage. This creates an unintended exfiltration channel: the implant binary leaves cloud-side forensic artifacts accessible via Microsoft Graph API, and the binary may sync to other devices the user is signed into. The operational risk of OneDrive placement is bidirectional — it can exfiltrate the implant off-host but also introduces cloud-side detection surfaces.

8. The operator applies the "not first, not last" heuristic: the dropped binary should not be the newest or oldest file in the directory listing. Timeline analysis tools (KAPE, Velociraptor, KAPE) sort by creation timestamp and flag temporal outliers. The binary's creation timestamp should fall within the existing cluster of neighboring files.

9. When drop-to-disk is unavoidable and the binary will be scanned by AV signatures, the operator applies DRM-based integrity protection. The Skrull PoC implant demonstrates three approaches:

10. **IPRIP-protected PE**: Windows DRM infrastructure includes support for marking PE files as IPRIP (Intellectual Property Rights Information Protection) protected. The PE binary's `IMAGE_LOAD_CONFIG_DIRECTORY` is populated with integrity check entries declaring a protected code section. AV engines that respect these integrity annotations defer or skip static analysis of the protected sections to avoid violating DRM constraints.

11. **Self-signed code signing**: The operator generates a self-signed code-signing certificate, installs it in the local machine's Trusted Root Certification Authorities or Trusted Publishers certificate store, and signs the dropped binary using `signtool sign` or the programmatic `SignerSignEx` API. The binary appears signed in Windows Explorer file properties and passes basic `WinVerifyTrust` signature presence checks, though it fails chain validation on systems where the self-signed root is not installed.

12. **PIMAGE_LOAD_CONFIG_DIRECTORY integrity fields**: The load config directory (DataDirectory index 10 in the PE optional header) contains fields including `SecurityDirectory` (RVA and size of a `WIN_CERTIFICATE` structure embedded in the PE file). By crafting these fields with valid-looking but non-standard values, the operator creates a PE that claims to have integrity protections, causing some scanners to treat the binary as protected content and skip deep analysis.

## OS Internals Context

The `IMAGE_LOAD_CONFIG_DIRECTORY` (32-bit: `IMAGE_LOAD_CONFIG_DIRECTORY32`, 64-bit: `IMAGE_LOAD_CONFIG_DIRECTORY64`) is defined in `winnt.h` and loaded by the Windows PE loader when the `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` (index 10) data directory entry in the optional header is non-zero. The structure contains fields for Control Flow Guard (`GuardCFCheckFunctionPointer`, `GuardCFDispatchFunctionPointer`, `GuardCFFunctionTable`, `GuardCFFunctionCount`), SafeSEH (`SEHandlerTable`, `SEHandlerCount` for 32-bit), and security-related cookie initialization (`SecurityCookie`). The `SecurityDirectory` field points to a `WIN_CERTIFICATE` structure embedded at the end of the PE file, which contains the Authenticode signature blob when the binary is signed.

The Mark of the Web is implemented as an NTFS Alternate Data Stream named `Zone.Identifier` attached to the downloaded file. The stream contains INI-formatted text with a `ZoneId` value: 1 (Local Intranet), 2 (Trusted Sites), 3 (Internet), 4 (Restricted Sites). When the shell or the kernel encounters a file with `ZoneId=3` or `ZoneId=4` and the user attempts execution, Windows invokes SmartScreen reputation checking, AppLocker policy evaluation, and ASR rule processing. The `Zone.Identifier` ADS is applied by Zone-aware applications (Internet Explorer, Edge, Chrome, Outlook, Explorer via SMB copy) through the `IAttachmentExecute` COM interface, which calls `IAttachmentExecute::Save()` internally. Files created via `CreateFile` / `NtCreateFile` directly do not receive a `Zone.Identifier` ADS.

The Windows Media DRM (IPRIP) infrastructure uses the `WMDRM` (Windows Media Digital Rights Management) subsystem, which is implemented in `drmv2clt.dll`, `drmv2prot.dll`, and kernel-mode components. The PE-level protection annotations that the Skrull implant leverages are part of the binary's load config directory and the `WIN_CERTIFICATE` structure, which the Windows loader processes during `LdrpMapDllNtFileName` → `LdrpMapViewOfSection`. Some AV products that check for DRM-protected content read the load config directory and skip scanning of sections marked as protected to avoid interfering with DRM enforcement.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would need three components. First, a directory selection function that queries `SHGetKnownFolderPath` for `FOLDERID_Desktop`, `FOLDERID_Documents`, `FOLDERID_Downloads`, `FOLDERID_LocalAppData`, and `FOLDERID_RoamingAppData`, then enumerates existing files via `FindFirstFileW` / `FindNextFileW` to calculate timestamp distributions and select a path where the dropped binary's creation time blends with the existing cluster. Second, a PE post-processing function that parses the target PE's `IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS` → `IMAGE_OPTIONAL_HEADER` → `DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]`, validates the `IMAGE_LOAD_CONFIG_DIRECTORY` structure, and populates `SecurityDirectory` and integrity-related fields with crafted values. Third, a MOTW stripping function that deletes the `Zone.Identifier` ADS via `DeleteFileW` with the path `filename:Zone.Identifier:$DATA` or via `NtDeleteFile` on the ADS path.

## Why It Matters

T-017 documents persistence mechanisms that drop binaries to disk (COM hijack proxy DLL, NTFS EA payload, schtask-triggered binary) and T-020 covers self-deletion and IAT camouflage, but neither card addresses the operational decision of where to place the dropped artifact or how to harden it against on-access scanning. This gap leaves operators without guidance on directory selection risk profiles or binary integrity protection options when disk-resident persistence is unavoidable. The placement heuristics and DRM techniques documented here close that gap, providing the tradecraft layer that makes disk-based persistence survivable in environments with active AV and EDR scanning.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 11 (FileCreate) and Event ID 15 (FileCreateStreamHash) capture file creation including full path and first hash of file content. Sysmon Event ID 7 (ImageLoad) captures module loads. NTFS USN Journal records all file creation events at the volume level and is queryable via `FSCTL_READ_USN_JOURNAL`. EDR products with on-access scanning intercept `NtCreateFile` / `NtOpenFile` with `FILE_EXECUTE` access. Windows Defender's real-time protection scans new files on write via its mini-filter driver.
- **Bypass options**: Place the binary in a directory with high legitimate executable churn (AppData\Local subdirectories) to blend file-create events. Use a filename matching the directory's naming convention (e.g., `update.exe` in a subfolder named after a known application). Strip the `Zone.Identifier` ADS to avoid SmartScreen and ASR evaluation. Apply self-signed code signing to pass basic signature presence checks. Populate `IMAGE_LOAD_CONFIG_DIRECTORY` integrity fields to defer scanners that respect protected content annotations.
- **Residual artifacts**: The dropped binary on disk. Self-signed certificate in the Trusted Root or Trusted Publishers certificate store if installed. NTFS creation timestamps that may not align with neighboring files despite blending efforts. OneDrive sync logs and cloud-side copies if placed in a synced folder. USN Journal entries persisting past file deletion.

## Related Techniques

- **T-017 Five-Layer Persistence** — persistence mechanisms that create disk-resident artifacts requiring placement strategy
- **T-020 Anti-Analysis Suite** — self-deletion and IAT camouflage for reducing on-disk forensic footprint
- **T-039 On-Disk Binary Patching** — binary patching for persistence that benefits from placement heuristics

## References

- Atlas material: atlas-post-exploit-part5 (units 15, 16, 23, 24, 26, 27)
- MITRE ATT&CK: T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027
- LGTM notes: lgtm:disk-placement-tradecraft, lgtm:implant-drm-protection

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.