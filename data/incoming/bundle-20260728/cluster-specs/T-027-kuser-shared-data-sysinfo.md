# Cluster Spec — T-027: KUSER_SHARED_DATA: Direct-Read System Information Primitive

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-027`
- **Canonical name**: KUSER_SHARED_DATA: Direct-Read System Information Primitive
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, detection-free enumeration primitive, bypasses syscall-based EDR hooks.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-023', 'T-016', 'T-020']

## Consolidated Description (from clustering)

KUSER_SHARED_DATA is a fixed-VA kernel-mapped page (0x7FFE0000 on x64) readable without API calls, providing NT runtime information (OS version, NtSystemRoot, NtTimerResolution, TickCount, InterruptTime). Bypasses userland hooks and syscall monitoring. Direct-page-read approach used as bonus sysinfo target alongside documented APIs; reduces EDR hook surface.

## Member LGTM Notes (2)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: KUSER_SHARED_DATA as Detection-Free System Info Source
- **id**: `lgtm:kuser-shared-data-info-source`
- **origin**: atlas-binary-analysis-part2
- **source_units**: ['unit 21', 'unit 22', 'unit 23']
- **would_relate_to**: ['T-004', 'T-020']
- **tags**: ['kuser-shared-data', 'info-source', 'evasion', 'kernel', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part2
**Would relate to:** T-004, T-020
**Source units:** unit 21, unit 22, unit 23

SEC670 dedicates explicit material to KUSER_SHARED_DATA at VA 0x7FFE0000 — a fixed-VA kernel-mapped page readable without any API call. The vault's T-004 (PEB Walker) documents module resolution via the PEB, but the KUSER_SHARED_DATA page is a distinct info source for system values (page size, tick count, processor counts, system time, NtSystemRoot) that does not require touching the PEB or any ntdll export. This warrants a standalone concept node — and arguably a small T-NNN card — because it is a reusable, detection-resistant primitive distinct from PEB walking.

### Note 2: KUSER_SHARED_DATA Direct-Read Sysinfo Primitive
- **id**: `lgtm:kuser-shared-data-sysinfo-primitive`
- **origin**: atlas-recon-part3
- **source_units**: ['unit 15', 'unit 16']
- **would_relate_to**: ['T-023', 'T-016']
- **tags**: ['kuser-shared-data', 'sysinfo', 'anti-edr', 'direct-read', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-recon-part3
**Would relate to:** T-023, T-016
**Source units:** unit 15, unit 16

SEC670 cites KUSER_SHARED_DATA as a BONUS sysinfo target alongside GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo. The vault's T-023 lists sysinfo collection but does not document the direct-page-read approach that bypasses syscall-based EDR hooks entirely. This merits its own treatment as a stealth sysinfo primitive distinct from the API-call family.

---

## Your Task

Produce the technique card for **T-027** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-027` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-023', 'T-016', 'T-020'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:kuser-shared-data-info-source', 'lgtm:kuser-shared-data-sysinfo-primitive']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.