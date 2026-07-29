# Cluster Spec — T-046: Manual PE Loader and Reflective DLL Injection (sRDI)

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-046`
- **Canonical name**: Manual PE Loader and Reflective DLL Injection (sRDI)
- **Proposed category**: `process-injection`
- **Proposed tier**: `A`
- **Priority**: high — 3 member notes, substantial SEC670 coverage, key infrastructure for manual code loading.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-013', 'T-007']

## Consolidated Description (from clustering)

Manual PE loader for x64 executables with MZ header validation, section traversal, data directory processing, import/export table construction, base relocations, and entry-point dispatch. sRDI (Shellcode Reflective DLL) is position-independent loader variant providing custom helpers (GetProcAddressR). Bypasses userland APIs entirely with fine-grained relocation control.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Shellcode Reflective DLL Injection (sRDI) as Standalone Technique
- **id**: `lgtm:srdi-as-distinct-technique`
- **origin**: atlas-exploit-dev-part11
- **source_units**: ['unit 3', 'unit 4', 'unit 5']
- **would_relate_to**: ['T-013', 'T-007']
- **tags**: ['srdi', 'reflective-loading', 'shellcode', 'pe-loader', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part11
**Would relate to:** T-013, T-007
**Source units:** unit 3, unit 4, unit 5

SEC670 units 3-5 treat sRDI as a distinct capability from RDI: the loader itself is position-independent shellcode that does not require the target DLL to be compiled with RDI support, and exposes custom helpers like GetProcAddressR. The vault folds reflective loading into T-013's 'PE Loader' line, but sRDI's shellcode-form loader, bootstrap+user-data layout, and GetProcAddressR export resolution constitute a separately documented tradecraft that would merit its own card or a dedicated subsection.

### Note 2: Standalone Manual PE Loader Technique Card
- **id**: `lgtm:proposed-manual-pe-loader-technique-card`
- **origin**: atlas-exploit-dev-part20
- **source_units**: ['unit 5', 'unit 6', 'unit 7', 'unit 11', 'unit 21']
- **would_relate_to**: ['T-013', 'T-007']
- **tags**: ['pe-loader', 'manual-mapping', 'relocations', 'iat', 'eat', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part20
**Would relate to:** T-013, T-007
**Source units:** unit 5, unit 6, unit 7, unit 11, unit 21

SEC670 spends substantial material on the manual x64 PE loader implementation — MZ/Machine validation, header traversal, data directory processing, IAT/EAT construction, base relocations, and entry-point dispatch. The vault currently folds PE loading into T-013 ('Remaining Methods' — including PE Loader) and the framework's pe_analyzer2 template, but does not elevate manual PE loading to its own T-NNN card. Given the depth of OS-loader behavior an operator must replicate (relocations, imports, TLS callbacks, exception directory), this would merit a dedicated technique card with the loader responsibilities enumerated as discrete sub-capabilities.

### Note 3: Manual PE Image Loading (Reflective Loader Primitives)
- **id**: `lgtm:proposed-technique-manual-pe-loading`
- **origin**: atlas-exploit-dev-part5
- **source_units**: ['unit 31']
- **would_relate_to**: ['T-007', 'T-013']
- **tags**: ['proposed-technique', 'reflective-loading', 'manual-map', 'pe-loader', 'in-memory']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part5
**Would relate to:** T-007, T-013
**Source units:** unit 31

Unit 31 lists 'manually load an image into memory' as a distinct last-resort capability. The vault's T-007 process-injection card covers reflective PE loading as one entry in a list of 14 methods but does not elevate the standalone capability — manually loading a DLL/EXE into the current process without the loader — as its own card. This primitive is reusable beyond injection: it underpins in-memory execution of plugins, reflective DLL imports, and self-contained staging. A dedicated card would surface the capability distinct from its injection-method usage.

---

## Your Task

Produce the technique card for **T-046** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-046` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-013', 'T-007'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:srdi-as-distinct-technique', 'lgtm:proposed-manual-pe-loader-technique-card', 'lgtm:proposed-technique-manual-pe-loading']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.