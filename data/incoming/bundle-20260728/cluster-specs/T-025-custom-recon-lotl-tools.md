# Cluster Spec — T-025: Custom Recon Tooling via LotL API Reimplementation

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-025`
- **Canonical name**: Custom Recon Tooling via LotL API Reimplementation
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: medium — Singleton, clear LotL evasion value, reimplementation of common tools.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-023', 'T-020']

## Consolidated Description (from clustering)

Custom reconnaissance tooling via Win32 API reimplementation: ipconfig via GetAdaptersInfo/GetAdaptersAddresses, arp via GetIpNetTable, netstat via GetTcpTable/GetUdpTable. Produces identical output without shelling out to cmd.exe/PowerShell, evading command-line monitoring. API-based approach provides functional equivalence and EDR evasion; reduces operational footprint.

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Custom Recon Tooling via LotL Reimplementation (ipconfig/arp/netstat)
- **id**: `lgtm:custom-recon-tooling-lotl-reimplementation`
- **origin**: atlas-exploit-dev-part18
- **source_units**: ['unit 28', 'unit 29', 'unit 30']
- **would_relate_to**: ['T-023', 'T-020']
- **tags**: ['recon', 'lotl', 'reimplementation', 'sysmon-evasion', 'no-child-process', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part18
**Would relate to:** T-023, T-020
**Source units:** unit 28, unit 29, unit 30

SEC670 Units 28-30 task students with reimplementing ipconfig, arp, and netstat using Win32 APIs rather than shelling out to the system binaries. This is a distinct tradecraft — building LotL-equivalent recon tools that produce the same data as the system utilities but execute as a single implant binary with no child processes, evading parent-child process correlation and command-line logging. The vault's T-023 covers recon as a category but does not document reimplemented-LotL recon tools as a defensive-evasion primitive distinct from shelling out.

---

## Your Task

Produce the technique card for **T-025** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-025` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-023', 'T-020'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:custom-recon-tooling-lotl-reimplementation']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.