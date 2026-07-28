# Cluster Spec — T-051: VERSIONINFO Resource Impersonation for Binary Spoofing

- **T-NNN ID**: `T-051`
- **Canonical name**: VERSIONINFO Resource Impersonation for Binary Spoofing
- **Proposed category**: `anti-analysis`
- **Proposed tier**: `B`
- **Priority**: low — Singleton anti-analysis technique, basic metadata spoofing, limited detection evasion value.
- **would_relate_to**: ['T-020']

## Consolidated Description

VERSIONINFO resource impersonation via binary resources: CompanyName, FileDescription, OriginalFilename, ProductVersion set to mimic legitimate applications (Google Chrome, Windows components). Static analysis tools display spoofed metadata, deceiving manual inspection and heuristic analysis. Resource-based impersonation survives compilation and binary modification.

## Member LGTM Notes (1)

### Note 1: VERSIONINFO Resource Impersonation
- id: `lgtm:binary-versioninfo-impersonation`
- origin: atlas-binary-analysis-part8
- would_relate_to: ['T-020']
- tags: ['versioninfo', 'metadata-spoofing', 'anti-analysis', 'resource-section', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part8
**Would relate to:** T-020
**Source units:** unit 39

The MalDev Academy metadata.src unit shows a VERSIONINFO resource block impersonating Google Chrome (CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, ProductVersion=112.0.5615.86). This is a distinct anti-analysis technique — embedding spoofed version metadata in the PE resource section to bypass heuristics that check binary metadata against known-good vendor signatures. The vault's T-020 Anti-Analysis Suite covers IAT camouflage and self-deletion but does not surface resource-section metadata spoofing as a documented technique.

---
Use `id: T-051`, canonical name above, and `member_notes: ['lgtm:binary-versioninfo-impersonation']`.
Cross-reference `would_relate_to`: ['T-020'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.