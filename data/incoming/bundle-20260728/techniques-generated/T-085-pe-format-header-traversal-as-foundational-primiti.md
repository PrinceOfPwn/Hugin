---
id: T-085
name: PE Format Header Traversal as Foundational Primitive
category: discovery
tier: C
crate: dark_crystal
source_file: dark_crystal/crates/core/src/pe.rs, dark_crystal/crowd/src/etw.rs, dark_crystal/crowd/src/herpaderping.rs
mitre: T1082
tags: [pe-format, header-traversal, e-lfanew, image-dos-header, image-nt-headers, rva-arithmetic, cross-cutting-primitive, foundational]
origin: atlas-synthesis
member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']
---

# PE Format Header Traversal as Foundational Primitive — The e_lfanew Navigation Chain

## Summary

PE format header traversal is the offset-arithmetic sequence that navigates from the MZ signature at the start of a PE binary through the layered header structure to reach specific data directories, section tables, and export/import structures. The canonical path — IMAGE_DOS_HEADER.e_lfanew (offset 0x3C) → IMAGE_NT_HEADERS64 (Signature "PE\0\0") → IMAGE_FILE_HEADER → IMAGE_OPTIONAL_HEADER64 → IMAGE_DATA_DIRECTORY[16] — is the load-bearing prerequisite for at least nine HUGIN technique cards spanning syscall SSN resolution, process injection, module stomping, reflective loading, EDR evasion, and persistence. This card documents the traversal path as a cross-cutting primitive, the specific offsets at each stage, and how different techniques consume different subsets of the same navigation chain.

## Mechanism

1. Begin at the module or file base address. Read the WORD at offset 0x00 and validate it equals 0x5A4D ("MZ"). This is the IMAGE_DOS_HEADER.e_magic field.

2. Read the DWORD at offset 0x3C. This is IMAGE_DOS_HEADER.e_lfanew — the file offset (or RVA, for a loaded module) to the IMAGE_NT_HEADERS64 structure. This field bridges the DOS-era header to the PE header.

3. Navigate to base + e_lfanew. Read the DWORD at offset 0x00 and validate it equals 0x00004550 ("PE\0\0"). This is IMAGE_NT_HEADERS64.Signature.

4. IMAGE_FILE_HEADER begins at e_lfanew + 0x04 (immediately after the 4-byte signature). Key fields: Machine at +0x00 (WORD, 0x8664 for AMD64), NumberOfSections at +0x02 (WORD, count of section headers), SizeOfOptionalHeader at +0x10 (WORD, size of the optional header that follows), Characteristics at +0x12 (WORD, bit flags including IMAGE_FILE_DLL 0x2000).

5. IMAGE_OPTIONAL_HEADER64 begins at e_lfanew + 0x18 (4 + 20). Key fields: Magic at +0x00 (WORD, 0x20B for PE32+), AddressOfEntryPoint at +0x10 (DWORD RVA), ImageBase at +0x18 (QWORD), SectionAlignment at +0x20 (DWORD), SizeOfImage at +0x38 (DWORD).

6. The DataDirectory array begins at e_lfanew + 0x18 + 0x70 = e_lfanew + 0x88. Each entry is 8 bytes (VirtualAddress DWORD + Size DWORD). Index 0 (export) is at e_lfanew + 0x88. Index 1 (import) at +0x90. Index 5 (basereloc) at +0xB0. Index 9 (TLS) at +0xD0. Index 12 (IAT) at +0xE8.

7. Section headers begin immediately after the optional header, at e_lfanew + 0x18 + SizeOfOptionalHeader. Each IMAGE_SECTION_HEADER is 40 bytes. Critical fields: Name at +0x00 (8 bytes), VirtualAddress at +0x0C (DWORD RVA), SizeOfRawData at +0x10 (DWORD), PointerToRawData at +0x14 (DWORD file offset), Characteristics at +0x24 (DWORD flags).

8. For export table access: read DataDirectory[0].VirtualAddress at offset 0x88 from the NT headers. Add module base to get the IMAGE_EXPORT_DIRECTORY pointer. The export directory at +0x00 contains NumberOfFunctions, at +0x14 NumberOfNames, at +0x1C AddressOfFunctions, at +0x20 AddressOfNames, at +0x24 AddressOfNameOrdinals.

9. For import table access: read DataDirectory[1].VirtualAddress at offset 0x90. Add module base to get the IMAGE_IMPORT_DESCRIPTOR array. Each descriptor is 20 bytes: OriginalFirstThunk at +0x00, TimeDateStamp at +0x04, ForwarderChain at +0x08, Name at +0x0C (RVA to DLL name string), FirstThunk at +0x10.

10. For relocation table access: read DataDirectory[5].VirtualAddress. The relocation table consists of IMAGE_BASE_RELOCATION blocks, each with VirtualAddress (DWORD) and SizeOfBlock (DWORD) at its head, followed by an array of WORD entries where the high 4 bits encode the relocation type and the low 12 bits encode the page-relative offset.

## OS Internals Context

The e_lfanew field is the single most critical offset in the PE format. It exists because the DOS header must remain at offset 0x00 for legacy compatibility — the BIOS and DOS loader check for "MZ" at the file start — but the PE headers can begin at a variable offset determined by the DOS stub size. The DOS stub is a real-mode program of variable length, so e_lfanew at offset 0x3C stores the actual location of the PE headers as a file offset.

For loaded modules in memory, the same traversal applies except that all offsets become RVAs (relative virtual addresses) from the module's DllBase. The loader maps the file using SectionAlignment granularity, so section data at PointerToRawData in the file appears at VirtualAddress in memory. The e_lfanew value remains valid as an RVA because the PE headers are always mapped at the start of the image.

Different HUGIN techniques consume different subsets of this traversal:

- **T-002 (Hell's Gate)**: Traverses to DataDirectory[0] to locate ntdll's export table, then walks AddressOfNames to find Nt* function names and reads the corresponding stub bytes to extract SSNs.
- **T-004 (PEB Walker)**: Full traversal from gs:[0x60] → PEB → Ldr → InLoadOrderModuleList to find ntdll base, then e_lfanew → NT headers → DataDirectory[0] → export table walk with DJB2 hashing.
- **T-006 (Phantom Stubs)**: Traverses section headers to locate .text sections of legitimate modules for installing MEM_IMAGE-backed stubs.
- **T-009/T-010 (Process Ghosting/Herpaderping)**: Traverses to AddressOfEntryPoint (e_lfanew + 0x28) to determine the entry point RVA for thread creation in the target process.
- **T-016 (NTDLL Unhook)**: Traverses to the .text section of ntdll to locate the region needing restoration from a known-good copy.
- **T-017 (Persistence)**: COM hijack and proxy DLL techniques require parsing import tables and export tables of target DLLs.

The raw-offset approach used in etw.rs reads DataDirectory[0] at offset 0x88 from the NT headers base, bypassing structured IMAGE_NT_HEADERS64 access. This offset is computed as: 4 (signature) + 20 (file header) + 0x70 (optional header fixed fields before DataDirectory) = 0x88. On 32-bit systems, IMAGE_OPTIONAL_HEADER32 has different sizing, and the DataDirectory offset would be 0x60 from the NT headers base instead.

## Key Implementation Details

Three HUGIN source files implement PE header traversal with different levels of abstraction:

**dark_crystal/crates/core/src/pe.rs** — The `PE::new` constructor implements the full structured traversal: reads IMAGE_DOS_HEADER, validates e_magic against IMAGE_DOS_SIGNATURE, reads e_lfanew, validates IMAGE_NT_HEADERS64.Signature against IMAGE_NT_SIGNATURE, computes section header pointer as `nt_header + size_of::<IMAGE_NT_HEADERS64>()`, and extracts five DataDirectory entries (TLS, IMPORT, EXPORT, EXCEPTION, BASERELOC) using indexed access into `OptionalHeader.DataDirectory[]`. The `PE` struct stores these as named fields for subsequent use by `fixing_iat`, `realoc_image`, `fixing_memory`, and `export_function_address`.

**dark_crystal/crowd/src/etw.rs** — The `resolve_export_by_hash` function implements raw-offset traversal: reads MZ at base+0x00, e_lfanew at base+0x3C, export RVA at NT+0x88, then manually dereferences IMAGE_EXPORT_DIRECTORY fields at offsets +0x18, +0x1C, +0x20, +0x24. This approach avoids all typed PE structures and uses only raw pointer arithmetic, reducing the binary's type metadata footprint.

**dark_crystal/crowd/src/herpaderping.rs** — The `parse_entry_point` function implements a minimal traversal: reads e_lfanew at offset 0x3C, computes entry point offset as `e_lfanew + 4 + 20 + 16` (signature + file header + offset of AddressOfEntryPoint in optional header), and reads the DWORD RVA. The `query_image_base` function reads PEB.ImageBaseAddress at offset 0x10 (x64) from the PEB pointer obtained via NtQueryInformationProcess.

## Why It Matters

The PE header traversal chain is the single most cross-cutting primitive in the HUGIN vault. Nine technique cards — T-002, T-004, T-006, T-007, T-008, T-013, T-016, T-017, and T-009/T-010 — all depend on navigating the same e_lfanew → NT headers → DataDirectory path, yet the vault has no dedicated reference that makes this shared prerequisite explicit. Readers without prior Windows internals background encounter the traversal logic embedded inside each technique's implementation and must reverse-engineer the offset arithmetic from context. A standalone card documenting the traversal sequence, the specific offsets, and which techniques consume which subsets fills a navigation gap that blocks readers from reaching half the vault.

## Detection Considerations

- **Telemetry sources**: PE header traversal from in-memory module bases produces no kernel or ETW telemetry — it is pure user-mode pointer arithmetic on mapped pages. PE header traversal from file buffers produces no loader events. EDR scanners may detect PE parsing through heuristic patterns: MZ validation followed by e_lfanew read followed by PE signature validation, particularly when performed on memory regions not registered as loaded modules.
- **Bypass options**: Raw-offset traversal (as in etw.rs) avoids typed structure imports. Performing traversal from within stomped module .text sections blends with loader activity. The herpaderping.rs minimal traversal reads only the entry point offset, reducing the heuristic signature.
- **Residual artifacts**: None directly. The traversal reads existing in-memory structures without modifying them. Subsequent techniques that modify structures based on traversal results (stomping, unhooking) produce the detectable artifacts.

## Related Techniques

- **T-002 Hell's Gate** — SSN resolution requires PE header traversal to DataDirectory[0] to locate ntdll's export table and read Nt* stub bytes
- **T-004 PEB Walker** — Module resolution via PEB depends on the e_lfanew → NT headers → DataDirectory traversal chain for export resolution
- **T-007 Process Injection** — pe.rs implements the full PE traversal chain supporting injection techniques that manipulate loaded module images
- **T-013 Remaining Injection Methods** — PE loader and module stomping require section-level PE traversal including section header iteration and Characteristics interpretation
- **T-009 Process Ghosting** — Process creation from image sections requires PE entry point parsing via the e_lfanew → AddressOfEntryPoint traversal

## References

- Atlas material: atlas-binary-analysis-part3.md, atlas-binary-analysis-part5.md, atlas-binary-analysis-part7.md, atlas-binary-analysis-part8.md, atlas-binary-analysis-part9.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:pe-format-traversal-foundations, lgtm:pe-parsing-foundational-utility, lgtm:pe-format-parsing-foundation, lgtm:pe-parsing-primitives-coverage, lgtm:coverage-gap-pe-parsing-prerequisite
- Public references: SEC670 Units 23-40 (PE format header traversal sequence), Lab 3.1 GetFunctionAddress (export table walk exercise)

## Source Reference

- `dark_crystal/crates/core/src/pe.rs` — `PE::new()` constructor (full structured PE header traversal)
- `dark_crystal/crowd/src/etw.rs` — `resolve_export_by_hash()` function (raw-offset PE header traversal)
- `dark_crystal/crowd/src/herpaderping.rs` — `parse_entry_point()` function (minimal traversal to AddressOfEntryPoint), `query_image_base()` function (PEB.ImageBaseAddress read)