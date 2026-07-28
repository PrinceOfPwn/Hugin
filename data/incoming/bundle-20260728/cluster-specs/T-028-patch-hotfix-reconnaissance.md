# Cluster Spec — T-028: Patch and Hotfix Status Enumeration

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-028`
- **Canonical name**: Patch and Hotfix Status Enumeration
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: medium — 2 member notes, distinct from general host survey, tactical value for exploit planning.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-020', 'T-023']

## Consolidated Description (from clustering)

Patch status reconnaissance via hotfix enumeration through Get-HotFix PowerShell, WMI qfe list, or Windows Update Agent APIs. Results inform exploit viability (which kernel vulnerabilities remain unpatched) and guide technique escalation. Determines whether specific kernel-mode exploits or ETW bypasses are available; directly informs operational planning.

## Member LGTM Notes (2)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Patch and Hotfix Reconnaissance for Exploit Viability
- **id**: `lgtm:patch-recon-for-exploit-selection`
- **origin**: atlas-methodology-part2
- **source_units**: ['unit 28', 'unit 30', 'unit 33']
- **would_relate_to**: ['T-023']
- **tags**: ['recon', 'patch-enumeration', 'wua', 'exploit-selection', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part2
**Would relate to:** T-023
**Source units:** unit 28, unit 30, unit 33

The material covers using WUA APIs and service-pack/hotfix enumeration to determine which vulnerabilities remain unpatched, directly informing exploit and LPE technique selection. The vault's T-023 (Client Capabilities) includes recon and sysinfo collection but does not document a dedicated patch-status reconnaissance capability that feeds into exploit selection. This would merit its own treatment since patch status determines whether kernel-touching techniques (T-016 BYOVD, T-013 remaining injection) are viable on a given target.

### Note 2: Patch / Hotfix Inventory as a Standalone Capability
- **id**: `lgtm:patch-status-inventory-card`
- **origin**: atlas-recon-part1
- **source_units**: ['unit 27', 'unit 28', 'unit 29', 'unit 32', 'unit 33', 'unit 34']
- **would_relate_to**: ['T-020', 'T-023']
- **tags**: ['patch-status', 'hotfix', 'wua', 'wmi', 'exploit-selection', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-recon-part1
**Would relate to:** T-020, T-023
**Source units:** unit 27, unit 28, unit 29, unit 32, unit 33, unit 34

SEC670 covers hotfix enumeration via three distinct paths (Get-HotFix cmdlet, wmic qfe list, WUA COM APIs) and frames the result as a precondition for exploit selection and for reasoning about kernel-callback/ETW differences across builds. The vault does not currently document patch-status enumeration as a distinct capability; it appears implicitly inside Kaguya's LOtL inventory (T-020) and is not surfaced as an independent recon primitive that gates T-013/T-016 kernel-touching techniques.

---

## Your Task

Produce the technique card for **T-028** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-028` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-020', 'T-023'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:patch-recon-for-exploit-selection', 'lgtm:patch-status-inventory-card']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.