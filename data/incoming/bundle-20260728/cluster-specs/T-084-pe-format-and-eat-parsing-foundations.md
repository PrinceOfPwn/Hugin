# Cluster Spec — T-084: PE Format and EAT Parsing Foundations

- **T-NNN ID**: `T-084`
- **Canonical name**: PE Format and EAT Parsing Foundations
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: high — 3+ member notes spanning multiple atlas batches all flag the same foundational prerequisite gap; concept card that unblocks four existing T-NNN cards.
- **would_relate_to**: ['T-004', 'T-007', 'T-008', 'T-013']

## Consolidated Description

The vault lacks a reference card documenting the PE binary format as a navigable
concept layer, despite T-004 (PEB Walker), T-007, T-008, and T-013 all depending
on PE anatomy. Required coverage spans IMAGE_DOS_HEADER.e_lfanew at offset 0x3C
→ IMAGE_NT_HEADERS → IMAGE_FILE_HEADER → IMAGE_OPTIONAL_HEADER64 →
IMAGE_DATA_DIRECTORY[16] (EXPORT=0, IMPORT=1, RESOURCE=2, RELOC=5). Specific
traversal targets include IMAGE_EXPORT_DIRECTORY (NumberOfNames /
AddressOfNames / AddressOfNameOrdinals triple-pointer walk for
GetProcAddress-equivalent resolution) and IMAGE_IMPORT_DESCRIPTOR's
OriginalFirstThunk / FirstThunk IAT/INT double-chain. The card should also
document WinDbg dx and dt commands against live modules for RVA-to-VA
arithmetic and dumpbin /exports as a static-analysis counterpart.


## Member LGTM Notes (3)

### Note 1: PE Format and EAT Parsing Foundations
- id: `lgtm:coverage-gap-pe-format-foundations`
- origin: atlas-exploit-dev-part22
- would_relate_to: ['T-004', 'T-007', 'T-008']
- tags: ['pe-format', 'eat', 'foundational', 'coverage-gap', 'concept-node']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part22
**Would relate to:** T-004, T-007, T-008
**Source units:** unit 1, unit 2, unit 3, unit 4, unit 5, unit 6, unit 27

Multiple SEC670 units cover IMAGE_DOS_HEADER, e_lfanew, dumpbin /exports, and the role of PE parsing in loaders and API resolution. T-004 (PEB Walker) and T-007 (injection) implicitly rely on this knowledge but the vault lacks a foundational concept node explaining the PE on-disk format vs in-memory format distinction, the EAT traversal algorithm, and how dumpbin output maps to the structures the implant code reads. Operators new to the vault would benefit from this scaffold.

### Note 2: PE Format Parsing as Foundation Knowledge
- id: `lgtm:pe-format-parser-coverage`
- origin: atlas-exploit-dev-part8
- would_relate_to: ['T-004', 'T-007', 'T-013']
- tags: ['pe', 'parsing', 'coverage-gap', 'windows-internals']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part8
**Would relate to:** T-004, T-007, T-013
**Source units:** unit 24, unit 25, unit 27, unit 31, unit 33, unit 35

The material treats PE format anatomy (IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DATA_DIRECTORY, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR) as the prerequisite for injection, persistence, API resolution, and loader development. The vault references pe.rs in T-007's role column and has PE-parsing templates in the framework, but there is no concept-level treatment of the parsing sequence and field semantics a reader needs to understand why the parsing logic looks the way it does. A dedicated concept cluster for PE format would anchor multiple cards.

### Note 3: WinDbg-Based PE Structure Introspection as Foundational Tradecraft
- id: `lgtm:windbg-pe-structure-introspection`
- origin: atlas-exploit-dev-part9
- would_relate_to: ['T-004']
- tags: ['pe', 'windbg', 'debugging', 'peb-walker', 'foundational-tradecraft', 'cross-source-convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-exploit-dev-part9
**Would relate to:** T-004
**Source units:** unit 1, unit 2, unit 3, unit 4, unit 6, unit 7

Multiple SEC670 units demonstrate WinDbg dx and dt commands for live inspection of IMAGE_DATA_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, and RVA-to-absolute-address arithmetic against loaded modules. MalDev Academy and CRTO cover the same PE parsing theory but the WinDbg hands-on approach is unique to SEC670 — it gives operators a verifiable way to validate that their PEB walker is reading the correct structures before committing to code. The vault documents T-004 (PEB Walker) at the implementation level but does not document the debugger-side verification workflow that lets an operator confirm their struct offsets and field interpretations match the live OS layout. This is foundational tradecraft worth surfacing as cross-cutting material.

---
Use `id: T-084`, canonical name above, and `member_notes: ['lgtm:coverage-gap-pe-format-foundations', 'lgtm:pe-format-parser-coverage', 'lgtm:windbg-pe-structure-introspection']`.
Cross-reference `would_relate_to`: ['T-004', 'T-007', 'T-008', 'T-013'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.