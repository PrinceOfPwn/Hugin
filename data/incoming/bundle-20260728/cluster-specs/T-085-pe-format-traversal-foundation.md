# Cluster Spec — T-085: PE Format Header Traversal as Foundational Primitive

- **T-NNN ID**: `T-085`
- **Canonical name**: PE Format Header Traversal as Foundational Primitive
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: high — Five convergence notes name this as the prerequisite for nine other T-NNN cards; filling this gap unblocks navigation across half the vault.
- **would_relate_to**: ['T-002', 'T-004', 'T-006', 'T-007', 'T-008', 'T-013', 'T-016', 'T-017', 'T-009', 'T-010']

## Consolidated Description

A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.


## Member LGTM Notes (5)

### Note 1: PE Format Header Traversal as Cross-Cutting Foundation
- id: `lgtm:pe-format-traversal-foundations`
- origin: atlas-binary-analysis-part3
- would_relate_to: ['T-004', 'T-006', 'T-007', 'T-013', 'T-009', 'T-010']
- tags: ['pe-format', 'header-parsing', 'module-resolution', 'cross-cutting']

**Kind:** cross-source-convergence
**Origin:** atlas-binary-analysis-part3
**Would relate to:** T-004, T-006, T-007, T-013, T-009, T-010
**Source units:** unit 23, unit 24, unit 25, unit 26, unit 27, unit 28, unit 29, unit 30, unit 31, unit 32, unit 33, unit 34, unit 35, unit 36, unit 37, unit 38, unit 39, unit 40

The SANS SEC670 material dedicates roughly 18 units (23-40) to PE format structure: IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DATA_DIRECTORY. These structures underpin at least five vault cards (T-004 PEB Walker, T-006 Phantom Stubs, T-007 Process Injection, T-013 PE Loader, T-009/T-010 process creation techniques) but the vault has no dedicated concept node explaining the e_lfanew → IMAGE_NT_HEADERS → IMAGE_OPTIONAL_HEADER → DataDirectory traversal path. This convergence signals the path is load-bearing across multiple cards and merits a graph-level concept entry.

### Note 2: PE Parsing as a Foundational Utility Across T-NNNs
- id: `lgtm:pe-parsing-foundational-utility`
- origin: atlas-binary-analysis-part5
- would_relate_to: ['T-002', 'T-004', 'T-013', 'T-016', 'T-017']
- tags: ['pe-parsing', 'shared-utility', 'cross-source-convergence', 'foundational']

**Kind:** cross-source-convergence
**Origin:** atlas-binary-analysis-part5
**Would relate to:** T-002, T-004, T-013, T-016, T-017
**Source units:** unit 2, unit 3, unit 6, unit 12, unit 15, unit 16, unit 20, unit 23, unit 26

Multiple SEC670 units in this batch (2, 3, 6, 12, 15, 16, 20, 23, 26) converge on PE file anatomy — DOS stub, COFF, Optional Header, section headers, RVAs, DataDirectory, export/import directories — as the foundational structural knowledge required by T-004 (PEB Walker), T-002 (Hell's Gate SSN resolution), T-013 (RDI), T-016 (NTDLL unhook / IAT manipulation), and T-017 (persistence involving module/DLL manipulation). The vault documents these techniques individually but does not currently surface PE parsing itself as a shared utility node in the graph. A 'PE parsing' concept anchored to multiple T-NNNs would improve navigation and make the shared prerequisite explicit.

### Note 3: PE Format Parsing as Foundational Technique Area
- id: `lgtm:pe-format-parsing-foundation`
- origin: atlas-binary-analysis-part7
- would_relate_to: ['T-004', 'T-007', 'T-013']
- tags: ['pe-format', 'coverage-gap', 'foundational', 'export-resolution', 'import-parsing']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part7
**Would relate to:** T-004, T-007, T-013
**Source units:** unit 3, unit 5, unit 6, unit 7, unit 8, unit 9, unit 18, unit 24

The SANS material dedicates substantial coverage to PE format internals — IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, Optional Header fields, DataDirectory entries, IMAGE_EXPORT_DIRECTORY with its three parallel RVA arrays, and IMAGE_IMPORT_DESCRIPTOR. The vault references PE parsing in T-004 (PEB Walker), T-007 (pe.rs), and T-013 (PE Loader) but does not have a dedicated card documenting the PE parsing primitives that multiple techniques depend on. The export directory resolution algorithm (walk AddressOfNames, index into AddressOfNameOrdinals, use ordinal to index AddressOfFunctions) is described in enough detail in the SANS material to warrant its own concept cluster.

### Note 4: PE Parsing Primitives as Standalone Capability
- id: `lgtm:pe-parsing-primitives-coverage`
- origin: atlas-binary-analysis-part8
- would_relate_to: ['T-004', 'T-013', 'T-016']
- tags: ['pe-format', 'pe-parsing', 'coverage-gap', 'primitive']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part8
**Would relate to:** T-004, T-013, T-016
**Source units:** unit 10, unit 11, unit 12, unit 15, unit 16, unit 17, unit 18, unit 31, unit 32, unit 33, unit 34, unit 35, unit 36

Multiple SEC670 units cover PE format fundamentals (IMAGE_DOS_HEADER, e_lfanew, IMAGE_OPTIONAL_HEADER magic, AddressOfEntryPoint) and Lab 3.1 GetFunctionAddress explicitly walks a PE file to resolve a function address. The vault references PE parsing inside T-004 PEB Walker and T-007 process injection but does not have a dedicated card documenting the PE header walking sequence (DOS -> NT -> Optional -> DataDirectory[Export] -> export name table -> export ordinal -> function RVA). A standalone card would consolidate this reusable primitive.

### Note 5: PE Parsing as Documented Prerequisite for SSN Resolution and Export Hijack
- id: `lgtm:coverage-gap-pe-parsing-prerequisite`
- origin: atlas-binary-analysis-part9
- would_relate_to: ['T-002', 'T-004', 'T-008', 'T-013']
- tags: ['pe-parsing', 'coverage-gap', 'prerequisite-knowledge', 'image-parsing']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part9
**Would relate to:** T-002, T-004, T-008, T-013
**Source units:** unit 11, unit 12, unit 13, unit 14, unit 15, unit 16, unit 17, unit 18, unit 19, unit 25, unit 26

Multiple SEC670 units cover the IMAGE_DOS_HEADER (e_magic, e_lfanew at 0x3C), IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+, AddressOfEntryPoint, DataDirectory), and the Lab 3.1 GetFunctionAddress exercise for parsing export tables. The vault documents T-002 (Hells Gate SSN resolution) and T-008 (Threadless export hijack) without a concept node that captures the prerequisite PE-walk primitive a reader needs. Adding a PE-parse concept cluster would make T-002 and T-008 navigable to readers without prior Windows internals background.

---
Use `id: T-085`, canonical name above, and `member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']`.
Cross-reference `would_relate_to`: ['T-002', 'T-004', 'T-006', 'T-007', 'T-008', 'T-013', 'T-016', 'T-017', 'T-009', 'T-010'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.