# Cluster Spec — T-031: WldpQueryDynamicCodeTrust: Device Guard Dynamic Code Trust Check

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-031`
- **Canonical name**: WldpQueryDynamicCodeTrust: Device Guard Dynamic Code Trust Check
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, distinct policy-querying primitive, enables adaptive tradecraft selection.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-016', 'T-013', 'T-006']

## Consolidated Description (from clustering)

WldpQueryDynamicCodeTrust is a user-mode query API exposing Device Guard policy check for dynamically-generated or in-memory code. Implants use this as pre-flight check before executing injected code, hollowed modules, or manually-loaded binaries. Returns policy decision without triggering execution; enables adaptive technique selection.

## Member LGTM Notes (2)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: WldpQueryDynamicCodeTrust as Pre-Flight Check
- **id**: `lgtm:wldp-dynamic-code-trust-query`
- **origin**: atlas-exploit-dev-part16
- **source_units**: ['unit 13']
- **would_relate_to**: ['T-016', 'T-013']
- **tags**: ['wdac', 'acg', 'dynamic-code', 'policy-query', 'pre-flight']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part16
**Would relate to:** T-016, T-013
**Source units:** unit 13

Unit 13 surfaces WldpQueryDynamicCodeTrust — the API Device Guard exposes for querying whether in-memory dynamic code is trusted by policy before execution. This is a distinct operational capability: a pre-flight check that lets an implant determine whether ACG/WDAC will block shellcode execution before committing to the allocation. The vault documents ACG/WDAC as a bypass target in T-016 but not the query-side primitive that lets an operator branch on policy state without triggering a block. The query itself is observable but is far cheaper than a failed NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE) under ACG.

### Note 2: WldpQueryDynamicCodeTrust as Documented EDR Mechanism
- **id**: `lgtm:wldp-dynamic-code-trust-edr-mechanism`
- **origin**: atlas-exploit-dev-part6
- **source_units**: ['unit 19', 'unit 20']
- **would_relate_to**: ['T-006', 'T-016', 'T-013']
- **tags**: ['wdac', 'device-guard', 'code-integrity', 'wldp', 'edr-mechanism', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part6
**Would relate to:** T-006, T-016, T-013
**Source units:** unit 19, unit 20

Units 19 and 20 surface WldpQueryDynamicCodeTrust — the user-mode query into Device Guard's dynamic-code-trust policy that determines whether in-memory code is allowed to execute under WDAC. The vault's T-016 EDR evasion suite lists ACG and CIG policy among its capabilities and T-006 documents MEM_IMAGE-backed stubs, but neither documents the specific kernel-side code-integrity decision API that these techniques are designed to satisfy or evade. Documenting WldpQueryDynamicCodeTrust as a named defensive mechanism in the graph (with its mutual-exclusion _When_ contract on fileHandle vs. baseImage) would give operators a concrete reference point for understanding why MEM_IMAGE-backed execution is operationally necessary under strict WDAC, not merely a stylistic choice.

---

## Your Task

Produce the technique card for **T-031** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-031` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-016', 'T-013', 'T-006'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:wldp-dynamic-code-trust-query', 'lgtm:wldp-dynamic-code-trust-edr-mechanism']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.