# Cluster Spec — T-050: Manual GetProcAddress Implementation via Export Table Walking

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-050`
- **Canonical name**: Manual GetProcAddress Implementation via Export Table Walking
- **Proposed category**: `syscalls`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, distinct evasion primitive for import resolution, complements PEB-walker.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-001', 'T-004', 'T-006']

## Consolidated Description (from clustering)

Manual GetProcAddress implementation via direct export table walking using kernel32's IMAGE_EXPORT_DIRECTORY. Developers manually traverse AddressOfNames, AddressOfNameOrdinals, and AddressOfFunctions to resolve function addresses without calling Win32 API. Enables import-hiding and reduces EDR hook surface.

## Member LGTM Notes (2)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Manual Reimplementation of LoadLibrary/GetProcAddress
- **id**: `lgtm:manual-loader-api-reimplementation`
- **origin**: atlas-exploit-dev-part17
- **source_units**: ['unit 25', 'unit 28']
- **would_relate_to**: ['T-004', 'T-013', 'T-016']
- **tags**: ['manual-loader', 'peb-walk', 'import-hiding', 'loader-evasion', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part17
**Would relate to:** T-004, T-013, T-016
**Source units:** unit 25, unit 28

The material explicitly flags that future modules cover manually implementing LoadLibrary and GetProcAddress to further hide imports beyond what explicit linking alone achieves. This is the conceptual bridge between T-004 (PEB Walker for module resolution) and a full custom loader that performs section mapping, import resolution, and relocation processing without touching the loader API surface. The vault has pieces (PEB walker, reflective PE loader in T-013) but no dedicated card for the manual LdrLoadDll-equivalent routine that avoids the monitored API trampoline entirely.

### Note 2: Manual GetProcAddress Implementation as Standalone Primitive
- **id**: `lgtm:manual-getprocaddress-as-standalone-primitive`
- **origin**: atlas-exploit-dev-part8
- **source_units**: ['unit 38', 'unit 39', 'unit 40']
- **would_relate_to**: ['T-001', 'T-004', 'T-006']
- **tags**: ['api-resolution', 'exports', 'rva', 'getprocaddress', 'primitive']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part8
**Would relate to:** T-001, T-004, T-006
**Source units:** unit 38, unit 39, unit 40

The material dedicates substantial space to walking kernel32.dll's IMAGE_EXPORT_DIRECTORY via AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions, including hex-dump analysis of the real kernel32 export table. The vault currently covers PEB-walker-based module resolution (T-004) but does not have a dedicated card for the function-level export resolution that follows — the step that turns 'module base in PEB' into 'arbitrary function pointer without calling GetProcAddress'. This is a reusable primitive across T-001 (syscall stub location), T-004 (general API resolution), and T-006 (phantom stub construction).

---

## Your Task

Produce the technique card for **T-050** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-050` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-001', 'T-004', 'T-006'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:manual-loader-api-reimplementation', 'lgtm:manual-getprocaddress-as-standalone-primitive']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.