# Cluster Spec — T-090: PE Format Internals — MZ Header, DOS Stub, Section Layout

- **T-NNN ID**: `T-090`
- **Canonical name**: PE Format Internals — MZ Header, DOS Stub, Section Layout
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: medium — Two member notes from different batches; concept node but foundational prerequisite for module stomping, reflective loading, and PE manipulation.
- **would_relate_to**: ['T-006', 'T-013', 'T-016', 'T-007']

## Consolidated Description

SEC670 introduces the PE file format at a bird's-eye level — MZ header (IMAGE_DOS_HEADER),
DOS stub, e_lfanew offset (at 0x3C in IMAGE_DOS_HEADER) to IMAGE_NT_HEADERS, COFF file
header (IMAGE_FILE_HEADER), Optional Header (IMAGE_OPTIONAL_HEADER), section headers
(IMAGE_SECTION_HEADER array), and image pages. The .text section holds executable code;
.rdata holds read-only data including the Export Directory (whose RVA is in
IMAGE_DIRECTORY_ENTRY_EXPORT of the DataDirectory array). This structural layout is
the foundation for module stomping (T-006, overwriting a loaded module's .text section),
function stomping (overwriting specific export function bytes), and reflective loading
(T-013, manual PE mapping). A concept card should document the field-by-field layout
of IMAGE_DOS_HEADER (e_magic 'MZ', e_lfanew at 0x3C), IMAGE_NT_HEADERS (Signature
'PE\0\0', FileHeader, OptionalHeader), the DataDirectory[16] array, and the section
header fields (VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics).


## Member LGTM Notes (2)

### Note 1: PE Section Layout as Foundation for Stomping Techniques
- id: `lgtm:pe-section-manipulation-foundations`
- origin: atlas-exploit-dev-part17
- would_relate_to: ['T-006', 'T-013', 'T-016']
- tags: ['pe-format', 'sections', 'stomping', 'module-overload', 'coverage-gap', 'foundations']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part17
**Would relate to:** T-006, T-013, T-016
**Source units:** unit 13, unit 15, unit 16

The material's PE format coverage (DOS stub, COFF, Optional Header, .text/.rdata section layout, Export Directory RVA placement in .rdata) is the structural foundation for module stomping, function stomping, PE header stomping, and module overloading in T-013 and T-016. The vault documents these techniques operationally but does not surface the underlying PE layout knowledge a reader needs to understand why stomping the .text section of a loaded module preserves the VAD entry, why export RVAs in .rdata must remain consistent, or why header stomping affects heuristic scanners differently than section stomping.

### Note 2: PE Format Internals Coverage Gap
- id: `lgtm:gap-pe-format-internals-coverage`
- origin: atlas-exploit-dev-part21
- would_relate_to: ['T-007', 'T-013']
- tags: ['pe-format', 'coverage-gap', 'pe-parsing', 'image-dos-header']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part21
**Would relate to:** T-007, T-013
**Source units:** unit 39, unit 40

SEC670 Units 39-40 introduce the PE file format at a bird's-eye level — MZ header, DOS stub, e_lfanew offset to NT headers, section headers, image pages — and define IMAGE_DOS_HEADER field-by-field. The vault's pe.rs performs PE header parsing for injection and module-stomping techniques, but the vault does not currently document the PE format structures (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, IMAGE_EXPORT_DIRECTORY) as standalone concept nodes. Operators who need to extend or debug PE parsing would benefit from a reference card on these structures in the graph.

---
Use `id: T-090`, canonical name above, and `member_notes: ['lgtm:pe-section-manipulation-foundations', 'lgtm:gap-pe-format-internals-coverage']`.
Cross-reference `would_relate_to`: ['T-006', 'T-013', 'T-016', 'T-007'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.