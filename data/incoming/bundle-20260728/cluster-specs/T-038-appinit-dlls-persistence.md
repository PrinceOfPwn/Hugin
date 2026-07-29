# Cluster Spec — T-038: AppInit_DLLs Registry Persistence

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-038`
- **Canonical name**: AppInit_DLLs Registry Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: medium — 3 member notes, clear user32-conditional tradecraft, registry-resident mechanism distinct from T-017 layers.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017', 'T-013']

## Consolidated Description (from clustering)

AppInit_DLLs persistence via registry-resident HKCU/HKLM entry. DLLs loaded into all User32.dll-linked processes. Gated on LoadAppInit_DLLs registry value (admin required). Distinct from AppCert and RunOnce; user32-conditional loading profile differs from other registry persistence.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: AppInit_DLLs as a Standalone Persistence Technique Card
- **id**: `lgtm:appinit-dlls-persistence-card`
- **origin**: atlas-edr-evasion-part6
- **source_units**: ['unit 14']
- **would_relate_to**: ['T-017', 'T-016']
- **tags**: ['appinit', 'persistence', 'registry', 'user32', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part6
**Would relate to:** T-017, T-016
**Source units:** unit 14

SEC670 unit 14 names AppInit as the correct technique for processes linked against User32.dll, distinct from AppCert and RunOnce. The vault's T-017 five-layer persistence suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not include AppInit_DLLs, despite it being a classic User32-graph-wide injection and persistence vector with its own registry semantics, AppInit_Dlls bypass mitigation via LoadAppInit_DLLs=0, and a distinct process-scope profile. Worth a dedicated T-NNN card or an explicit addition to T-017.

### Note 2: AppInit_DLLs Registry Persistence
- **id**: `lgtm:proposed-appinit-dlls-persistence-card`
- **origin**: atlas-exploit-dev-part24
- **source_units**: ['unit 22']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'appinit-dlls', 'registry', 'user32', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part24
**Would relate to:** T-017
**Source units:** unit 22

SEC670 Lab 4.5 'InitToWinInit' (Unit 22) instructs students to create the AppInit_DLLs key and load a malicious DLL into every user32-linked process. This is a distinct persistence primitive from the five layers currently in T-017: it is registry-resident, user32-conditional, and carries a documented recursion hazard ('infinite loading situations'). The vault would benefit from a dedicated technique entry covering its trigger conditions, recursion pitfalls, and modern-Windows applicability (LoadAppInit_DLLs=0 by default on recent builds).

### Note 3: AppInit_DLLs as Standalone Persistence Technique
- **id**: `lgtm:proposed-appinit-dlls-persistence`
- **origin**: atlas-misc-part1
- **source_units**: ['unit 5', 'unit 6', 'unit 8', 'unit 9']
- **would_relate_to**: ['T-017', 'T-013']
- **tags**: ['persistence', 'appinit-dlls', 'registry', 'coverage-gap', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017, T-013
**Source units:** unit 5, unit 6, unit 8, unit 9

SEC670 documents AppInit_DLLs across multiple units (5, 6, 8, 9) as a registry-driven DLL injection persistence mechanism with specific requirements: User32.dll linking of targets, LoadAppInit_DLLs gate, admin privileges, and infinite-loop avoidance. The vault's T-017 persistence suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not include AppInit_DLLs. Given the material's repeated emphasis and the technique's historical use by APT39, CherryPicker, and T9000, this would merit its own T-NNN card or an extension to T-017.

---

## Your Task

Produce the technique card for **T-038** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-038` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017', 'T-013'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:appinit-dlls-persistence-card', 'lgtm:proposed-appinit-dlls-persistence-card', 'lgtm:proposed-appinit-dlls-persistence']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.