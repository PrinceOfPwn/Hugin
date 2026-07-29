---
id: T-084
name: PE Format and EAT Parsing Foundations
category: discovery
tier: C
crate: dark_crystal
source_file: dark_crystal/crates/core/src/pe.rs
mitre: T1082
tags: [pe-format, dos-header, nt-headers, optional-header, data-directory, iat-parsing, windbg-verification, dumpbin, foundational]
origin: atlas-synthesis
member_notes: ['lgtm:coverage-gap-pe-format-foundations', 'lgtm:pe-format-parser-coverage', 'lgtm:windbg-pe-structure-introspection']
---

# PE Format and EAT Parsing Foundations — Structural Anatomy of the Portable Executable Format

## Summary

The Portable Executable (PE) format is the binary container specification governing all Windows executables, DLLs, and kernel drivers. Understanding its structural anatomy — the layered sequence of headers from IMAGE_DOS_HEADER through IMAGE_NT_HEADERS64 to section tables and data directories — is a prerequisite for every technique in the HUGIN vault that manipulates loaded modules, resolves exports, stomps sections, or implements reflective loading. This card documents the field-level PE layout, the on-disk versus in-memory format distinction, the Export Address Table (EAT) traversal algorithm, and the WinDbg and dumpbin verification workflows that let operators validate struct offsets and field interpretations against live OS layout before committing to implementation code.

## Mechanism

1. The PE file begins with IMAGE_DOS_HEADER at offset 0x00. The field e_magic at offset 0x00 contains 0x5A4D ("MZ"). The field e_lfanew at offset 0x3C is a DWORD containing the file offset to IMAGE_NT_HEADERS64.

2. Between IMAGE_DOS_HEADER and IMAGE_NT_HEADERS64 sits the DOS stub — a small real-mode program that prints "This program cannot be run in DOS mode" when executed under DOS. This region is variable-length and is skipped by following e_lfanew.

3. IMAGE_NT_HEADERS64 begins at the file offset specified by e_lfanew. The Signature field at offset 0x00 contains 0x00004550 ("PE\0\0"). Immediately following is IMAGE_FILE_HEADER (20 bytes) containing NumberOfSections (offset 0x02, WORD), Characteristics (offset 0x12, WORD, where bit 0x2000 indicates a DLL).

4. IMAGE_OPTIONAL_HEADER64 follows IMAGE_FILE_HEADER. The Magic field at offset 0x00 contains 0x20B for PE32+ (64-bit) or 0x10B for PE32 (32-bit). AddressOfEntryPoint at offset 0x10 is the RVA of the entry point function. ImageBase at offset 0x18 is the preferred load address. SizeOfImage at offset 0x38 is the total virtual size of the mapped image. SectionAlignment and FileAlignment at offsets 0x20 and 0x24 govern RVA-to-file-offset translation.

5. The DataDirectory array begins at offset 0x70 in IMAGE_OPTIONAL_HEADER64. It contains 16 IMAGE_DATA_DIRECTORY entries, each 8 bytes (VirtualAddress DWORD + Size DWORD). Key indices: 0 = IMAGE_DIRECTORY_ENTRY_EXPORT (export table, in .rdata), 1 = IMAGE_DIRECTORY_ENTRY_IMPORT (import descriptor table, in .rdata), 2 = IMAGE_DIRECTORY_ENTRY_RESOURCE (resource tree, in .rsrc), 5 = IMAGE_DIRECTORY_ENTRY_BASERELOC (relocation table, in .reloc), 9 = IMAGE_DIRECTORY_ENTRY_TLS (TLS directory, in .rdata), 12 = IMAGE_DIRECTORY_ENTRY_IAT (Import Address Table, in .rdata for loaded images).

6. Section headers (IMAGE_SECTION_HEADER array) follow immediately after IMAGE_OPTIONAL_HEADER64. Each entry is 40 bytes containing Name (8 bytes), VirtualAddress (DWORD, RVA where section is loaded), SizeOfRawData (DWORD, size in file), PointerToRawData (DWORD, file offset of section data), and Characteristics (DWORD, flags including IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE).

7. The EAT traversal for GetProcAddress-equivalent resolution: navigate to IMAGE_EXPORT_DIRECTORY via DataDirectory[0]. Read NumberOfNames, AddressOfNames, AddressOfNameOrdinals, and AddressOfFunctions. Walk AddressOfNames to find the target name, read the parallel ordinal from AddressOfNameOrdinals, and index into AddressOfFunctions to get the function RVA.

8. The IAT/INT double-chain for import resolution: IMAGE_IMPORT_DESCRIPTOR contains OriginalFirstThunk (RVA to INT — Import Name Table, preserved post-load) and FirstThunk (RVA to IAT — Import Address Table, overwritten by the loader with resolved addresses). Both chains contain IMAGE_THUNK_DATA64 entries where the high bit set indicates ordinal import and the low bits contain the ordinal; otherwise the value is an RVA to IMAGE_IMPORT_BY_NAME.

9. On-disk format uses file offsets and PointerToRawData for locating section data. In-memory format uses RVAs and VirtualAddress for the same purpose. The conversion from file offset to RVA requires iterating section headers to find which section contains the file offset, then computing rva = section.VirtualAddress + (fileOffset - section.PointerToRawData).

## OS Internals Context

The PE loader (ntdll!LdrpMapDllNtFileName → LdrpMapDll → LdrpProcessRelocationBlock → LdrpSnapIAT) reads the on-disk PE format and constructs the in-memory image. During loading, the loader allocates a virtual region of SizeOfImage bytes, copies section data from PointerToRawData to VirtualAddress, applies base relocations from the .reloc directory, and resolves imports by walking IMAGE_IMPORT_DESCRIPTOR chains and overwriting FirstThunk entries with resolved function addresses.

The EAT resides in .rdata and consists of the IMAGE_EXPORT_DIRECTORY header followed by three arrays. The arrays use RVAs relative to the module base. When a module is loaded, the loader does not modify export table entries — they remain RVAs. Code resolving exports must add the module's actual base address to convert RVAs to virtual addresses.

The on-disk versus in-memory distinction matters for techniques that parse PE files from buffers (reflective loading, process herpaderping) versus techniques that parse already-loaded modules (export resolution, module stomping). File-offset parsing uses PointerToRawData; in-memory parsing uses VirtualAddress. The pe.rs implementation in HUGIN handles both modes — the `PE::new` constructor parses from a file buffer using file offsets, then `prepare()` maps sections into memory using VirtualAddress for the destination.

WinDbg provides commands for verifying PE structure layouts against live modules. The `dt IMAGE_NT_HEADERS64` command displays the structure definition. The `dx` command enables data inspection of arbitrary expressions. The `!dh` extension command dumps PE headers for a loaded module. Operators can use `dd module_base+0x3C L1` to read e_lfanew, then `dt IMAGE_NT_HEADERS64 module_base+<e_lfanew_value>` to validate the NT headers layout matches their code's struct offsets.

The `dumpbin /exports module.dll` command provides a static-analysis counterpart showing the export table contents — function names, ordinals, and RVAs — that an implant's export-walking code should produce when run against the same module.

## Key Implementation Details

**dark_crystal/crates/core/src/pe.rs** implements comprehensive PE format parsing. The `PE::new` constructor validates IMAGE_DOS_HEADER (e_magic check against IMAGE_DOS_SIGNATURE), reads e_lfanew, validates IMAGE_NT_HEADERS64 (Signature check against IMAGE_NT_SIGNATURE), parses section headers as an array immediately following the optional header, and extracts five DataDirectory entries: TLS (index 9), IMPORT (index 1), EXPORT (index 0), EXCEPTION (index 3), and BASERELOC (index 5). The `is_dll` field is computed by checking `FileHeader.Characteristics & IMAGE_FILE_DLL`.

The `fixing_iat` method walks IMAGE_IMPORT_DESCRIPTOR entries from the import directory, reading OriginalFirstThunk and FirstThunk for each descriptor. It resolves imports by ordinal (checking IMAGE_ORDINAL_FLAG64) and by name (reading IMAGE_IMPORT_BY_NAME structures), using `LoadLibraryA` and `GetProcAddress` for resolution and writing resolved addresses into FirstThunk entries.

The `realoc_image` method walks IMAGE_BASE_RELOCATION blocks, processing BASE_RELOCATION_ENTRY entries with types including IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_LOW, and IMAGE_REL_BASED_ABSOLUTE.

The `fixing_memory` method iterates section headers and maps Characteristics flags to memory protection constants — PAGE_EXECUTE_READWRITE for execute+read+write, PAGE_EXECUTE_READ for execute+read, PAGE_READONLY for read-only — applying them via VirtualProtect.

## Why It Matters

The vault documents T-004 (PEB Walker), T-007 (Process Injection), T-008 (Threadless Injection), and T-013 (PE Loader) as separate technique cards, but all four assume working knowledge of PE format anatomy. Operators extending or debugging PE parsing logic in pe.rs need a reference that explains why the parsing sequence reads e_lfanew at 0x3C, why section headers follow the optional header, and how DataDirectory indices map to the structures each technique manipulates. The WinDbg verification workflow documented here is unique to SEC670 and gives operators a way to confirm that struct offsets in their code match the live OS layout before deployment.

## Detection Considerations

- **Telemetry sources**: PE format parsing itself is not directly telemetered. The loader's PE parsing generates Kernel-Image ETW events, but manual parsing from buffers or in-memory structures produces no such telemetry. EDR memory scanners may flag PE parsing code through heuristic detection of sequential header validation patterns (MZ check, PE signature check, DataDirectory reads).
- **Bypass options**: Raw-offset parsing (as in etw.rs) avoids importing PE structure types. Hash-based export resolution eliminates function name strings. Parsing PE structures from within already-loaded module memory blends with legitimate loader activity.
- **Residual artifacts**: Parsed PE structures in heap allocations, particularly IMAGE_NT_HEADERS64 and section header arrays, are detectable by memory scanners scanning for PE header patterns outside of legitimate module mappings.

## Related Techniques

- **T-004 PEB Walker** — Depends on PE format parsing to locate and traverse module export tables via the PEB InLoadOrderModuleList
- **T-007 Process Injection** — pe.rs PE parsing implementation supports injection techniques that manipulate loaded module images and section properties
- **T-013 Remaining Injection Methods** — PE loader and reflective loading require complete PE format traversal including sections, imports, relocations, TLS callbacks, and exception tables
- **T-008 Threadless Injection** — Export table structure knowledge is prerequisite for modifying AddressOfFunctions entries during export hijack

## References

- Atlas material: atlas-exploit-dev-part22.md, atlas-exploit-dev-part8.md, atlas-exploit-dev-part9.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:coverage-gap-pe-format-foundations, lgtm:pe-format-parser-coverage, lgtm:windbg-pe-structure-introspection
- Public references: SEC670 Units 1-7 (PE format anatomy), Units 24-27 (dumpbin and WinDbg dx/dt verification), Unit 33 (IAT/INT double-chain)

## Source Reference

- `dark_crystal/crates/core/src/pe.rs` — `PE::new()` constructor (full PE format parsing chain), `fixing_iat()` (IMAGE_IMPORT_DESCRIPTOR walk), `realoc_image()` (relocation processing), `fixing_memory()` (section protection mapping), `export_function_address()` (EAT traversal)