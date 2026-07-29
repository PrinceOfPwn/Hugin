# Cluster Spec — T-116: UAC Bypass Discovery Methodology and Tradecraft

- **T-NNN ID**: `T-116`
- **Canonical name**: UAC Bypass Discovery Methodology and Tradecraft
- **Proposed category**: `privesc`
- **Proposed tier**: `A`
- **Priority**: high — Three member notes with cross-source convergence; adds methodology depth to existing T-021
- **would_relate_to**: ['T-021', 'T-023']

## Consolidated Description

SEC670 Lab 3.7 documents a discovery methodology: enumerate System32 binaries, extract PE manifests via mt.exe or by parsing RT_MANIFEST resource (type 24), find autoElevate="true" attribute, run under Process Monitor to capture COM handler loading, find an attacker-controllable handler path via registry hijack, then trigger the autoElevate binary to execute the COM handler at elevated integrity. UACMe (hfire_f0x) provides the canonical reference implementation index numbering 80+ bypasses. The vault's T-021 / T-023 document CMSTP bypass as a finished technique but lack the discovery methodology and the cross-source pattern of: autoElevate manifest + COM InprocServer32 / LocalServer32 registry value pointing to attacker DLL + triggering binary (computerdefaults.exe, sdclt.exe, fodhelper.exe, eventvwr.exe). A consolidated card should document the manifest parsing step (autoElevate attribute location), the COM hijack step (HKCU\Software\Classes\CLSID\{<GUID>}\InprocServer32), and the trigger binaries.


## Member LGTM Notes (3)

### Note 1: UAC Bypass Discovery Methodology Coverage Gap
- id: `lgtm:gap-uac-bypass-research-methodology`
- origin: atlas-privesc-part1
- would_relate_to: ['T-021']
- tags: ['uac', 'uac-bypass', 'research-methodology', 'coverage-gap', 'process-monitor']

**Kind:** coverage-gap
**Origin:** atlas-privesc-part1
**Would relate to:** T-021
**Source units:** unit 9, unit 13

T-021 documents the CMSTP UAC bypass as a finished technique, but SEC670 Lab 3.7 documents the broader discovery methodology: enumerate System32 binaries, extract manifests, find autoElevate=true, run under Process Monitor, find an attacker-writable interaction, weaponize. The vault lacks coverage of this discovery pipeline — operators get one bypass but not the methodology for finding new ones when CMSTP is detected or patched. Coverage gap because the operational knowledge (how to research a new bypass) is missing alongside the technique itself.

### Note 2: UAC Bypass Tradecraft Cross-Source Convergence
- id: `lgtm:cross-source-convergence-uac-tradecraft`
- origin: atlas-privesc-part2
- would_relate_to: ['T-021', 'T-023']
- tags: ['cross-source-convergence', 'uac', 'autoelevate', 'fusion', 'uacme', 'tradecraft-model']

**Kind:** cross-source-convergence
**Origin:** atlas-privesc-part2
**Would relate to:** T-021, T-023
**Source units:** unit 17, unit 18, unit 19, unit 20, unit 21, unit 22, unit 23, unit 24, unit 25, unit 26, unit 31, unit 32

SEC670's treatment of UAC (units 17–27, 31–32) converges with the vault's existing T-021 and T-023 UAC bypass implementations on the same conceptual model: autoElevate manifests as the gatekeeper, Fusion as the parsing subsystem, the UACMe project as the canonical reference corpus, and elevation-prompt color coding as the trust indicator. The convergence indicates strong tradecraft consensus: any operator working in this space encounters the same autoElevate+Fusion+UACMe mental model across SANS, the source corpus, and the broader red-team community. Surfacing this convergence in the graph would help operators recognize that the vault's CMSTP bypass is one instance of a broader technique family the material systematically documents.

### Note 3: UAC Bypass Research Methodology Across Courses
- id: `lgtm:uac-bypass-research-methodology-convergence`
- origin: atlas-privesc-part3
- would_relate_to: ['T-021', 'T-023']
- tags: ['uac', 'autoelevate', 'fusion', 'uacme', 'process-monitor', 'convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-privesc-part3
**Would relate to:** T-021, T-023
**Source units:** unit 19, unit 20, unit 21, unit 22, unit 23, unit 24, unit 25, unit 26, unit 30

SEC670's UAC bypass module (Fusion manifest parsing, Process Monitor behavior analysis, UACMe project integration) converges with the UAC bypass already documented under T-021 and T-023. The training material adds the discovery methodology (FusionScanDirectory/FusionScanFiles/FusionCheckFile) and the lab workflow (find autoElevate binaries, observe with ProcMon, weaponize) — operational knowledge that source code alone does not surface.

---
Use `id: T-116`, canonical name above, and `member_notes: ['lgtm:gap-uac-bypass-research-methodology', 'lgtm:cross-source-convergence-uac-tradecraft', 'lgtm:uac-bypass-research-methodology-convergence']`.
Cross-reference `would_relate_to`: ['T-021', 'T-023'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.