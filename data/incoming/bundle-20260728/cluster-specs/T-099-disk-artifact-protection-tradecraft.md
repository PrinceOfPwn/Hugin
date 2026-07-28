# Cluster Spec — T-099: Disk Artifact Placement and DRM Protection Tradecraft

- **T-NNN ID**: `T-099`
- **Canonical name**: Disk Artifact Placement and DRM Protection Tradecraft
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: medium — Two member notes; fills an operational-tradecraft gap around disk-resident artifacts
- **would_relate_to**: ['T-017', 'T-020']

## Consolidated Description

SEC670 devotes material to strategic on-disk drop placement — Desktop, Documents, Downloads, Pictures, Temp, AppData, Program Files, SysWow64, System32, OneDrive — with explicit risk / signal trade-offs (e.g., System32 raises AV scrutiny, AppData blends with legitimate app noise, OneDrive sync can exfiltrate the implant off-host). For integrity protection when drop-to-disk is unavoidable, SEC670 references the PoC Skrull implant using Windows DRM techniques (IPRIP-protected PE, code signing with self-signed certs, or PIMAGE_LOAD_CONFIG_DIRECTORY integrity check entries) to prevent static analysis by AV signatures or reverse-engineering. Together these form a disk-artifact-protection discipline the vault lacks: a card should map each placement location to detection attention, and document the DRM techniques available to harden the dropped binary.


## Member LGTM Notes (2)

### Note 1: Disk Drop Placement Heuristics
- id: `lgtm:disk-placement-tradecraft`
- origin: atlas-post-exploit-part5
- would_relate_to: ['T-017', 'T-020']
- tags: ['opsec', 'disk-artifact', 'tradecraft', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part5
**Would relate to:** T-017, T-020
**Source units:** unit 15, unit 16, unit 23, unit 24, unit 27

SEC670 devotes material to strategic selection of on-disk drop locations (Desktop, Documents, Downloads, Pictures, Temp, AppData, Program Files, SysWow64, System32, OneDrive) with the explicit heuristic of 'blending in' and not being the first or last file in a directory listing. The vault's T-020 Anti-Analysis Suite covers self-deletion and IAT camouflage but does not document disk-placement tradecraft for persistence-dropped binaries. This is operational knowledge that does not exist in source code.

### Note 2: Implant DRM for Artifact Protection
- id: `lgtm:implant-drm-protection`
- origin: atlas-post-exploit-part5
- would_relate_to: ['T-020', 'T-017']
- tags: ['drm', 'artifact-protection', 'emerging-tradecraft', 'opsec']

**Kind:** emerging-tradecraft
**Origin:** atlas-post-exploit-part5
**Would relate to:** T-020, T-017
**Source units:** unit 26

SEC670 references the PoC Skrull implant as an example of using Digital Rights Management (DRM) techniques to protect an implant's integrity when dropped to disk, framed under the 'Protecting Yourself' module. The vault has no technique card covering DRM-style protection of on-disk artifacts. This is an emerging tradecraft direction worth tracking as EDR products increasingly scan dropped binaries.

---
Use `id: T-099`, canonical name above, and `member_notes: ['lgtm:disk-placement-tradecraft', 'lgtm:implant-drm-protection']`.
Cross-reference `would_relate_to`: ['T-017', 'T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.