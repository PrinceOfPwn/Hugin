<!-- BEGIN CARD T-083 -->
---
id: T-083
name: PE Export Directory Traversal for API Resolution
category: discovery
tier: B
crate: dark_crystal
source_file: dark_crystal/crates/core/src/pe.rs, dark_crystal/crowd/src/etw.rs
mitre: T1027.007
tags: [pe-format, export-resolution, eat-traversal, djb2-hash, getprocaddress, api-resolution, module-resolution, peb-walker]
origin: atlas-synthesis
member_notes: ['lgtm:cross-source-pe-export-resolution-convergence', 'lgtm:getprocaddress-implementation-as-resolution-primitive']
---

# PE Export Directory Traversal for API Resolution — Manual Export Table Walk to Resolve Function Pointers

## Summary

PE export directory traversal is the algorithmic process of walking a loaded module's IMAGE_EXPORT_DIRECTORY structure to resolve function addresses by name or ordinal, replicating the functionality of GetProcAddress without calling the Win32 API directly. The technique reads three parallel arrays — AddressOfNames (DWORD RVA array of name string pointers), AddressOfNameOrdinals (WORD array mapping name index to function index), and AddressOfFunctions (DWORD RVA array of function entry points) — to locate a target export and compute its virtual address by adding the module base. Operators use this primitive to resolve Nt* functions for direct syscall dispatch, to locate export addresses for stomping or hijacking, and to build self-contained loaders that avoid IAT entries traceable by EDR. The primary detection surface is the absence of GetProcAddress in the import table combined with the presence of manual export-table parsing logic in memory.

## Mechanism

1. Obtain the base address of the target module. For the PEB Walker approach (T-004), this involves reading gs:[0x60] on x64 to locate the PEB, traversing PEB → Ldr → InLoadOrderModuleList to find the target module (e.g., ntdll.dll), and extracting its DllBase field.

2. Read the IMAGE_DOS_HEADER at the module base. Validate e_magic equals 0x5A4D ("MZ"). Read e_lfanew at offset 0x3C — a DWORD RVA pointing to the IMAGE_NT_HEADERS64 structure.

3. Navigate to IMAGE_NT_HEADERS64 at base + e_lfanew. Validate Signature equals 0x00004550 ("PE\0\0").

4. Read the IMAGE_DATA_DIRECTORY array from the Optional Header. The export directory entry is at index 0 (IMAGE_DIRECTORY_ENTRY_EXPORT). Its VirtualAddress field is an RVA to the IMAGE_EXPORT_DIRECTORY structure, typically located in the .rdata section.

5. Read IMAGE_EXPORT_DIRECTORY at base + export_rva. Critical fields: NumberOfNames (count of named exports), NumberOfFunctions (total exports including unnamed), AddressOfNames (RVA to DWORD array of name string RVAs), AddressOfNameOrdinals (RVA to WORD array of ordinal indices), AddressOfFunctions (RVA to DWORD array of function RVAs), Base (ordinal base value subtracted from ordinal to get array index).

6. For export-by-name resolution: iterate the AddressOfNames array (NumberOfNames entries). For each entry, read the DWORD RVA, add the module base to get the name string address, and compare the name string against the target function name. On match, read the parallel entry from AddressOfNameOrdinals at the same index — this WORD value is the index into AddressOfFunctions.

7. For hash-based resolution (DJB2): instead of string comparison, compute a hash of each export name string as it is read. The DJB2 algorithm initializes h = 5381 and iterates h = (h << 5) + h + byte for each byte. Compare the computed hash against a pre-calculated target hash. This avoids embedding function name strings in the implant binary.

8. For export-by-ordinal resolution: subtract the IMAGE_EXPORT_DIRECTORY.Base value from the ordinal to get the array index, then index directly into AddressOfFunctions. Validate the index is within [0, NumberOfFunctions).

9. Read the DWORD RVA from AddressOfFunctions at the computed index. Add the module base address to convert the RVA to a virtual address. This is the resolved function pointer.

10. Check for forwarder entries: if the resolved RVA falls within the export directory's range (export_rva to export_rva + export_size), the entry is a forwarder RVA pointing to a "module.function" string rather than a function body. Parse the forwarder string, resolve the referenced module and function, and return that address instead.

## OS Internals Context

The IMAGE_EXPORT_DIRECTORY structure (defined in winnt.h) is the PE mechanism that makes GetProcAddress functional. The three parallel arrays represent different views of the same export table: AddressOfNames provides name strings for by-name lookup, AddressOfNameOrdinals translates name indices to function indices (necessary because named and unnamed exports occupy different positions in AddressOfFunctions), and AddressOfFunctions holds the actual function RVAs.

The parallel array design exists because PE exports support both named and unnamed (ordinal-only) exports. AddressOfFunctions has NumberOfFunctions entries indexed by ordinal-minus-Base. AddressOfNames and AddressOfNameOrdinals both have NumberOfNames entries and are parallel: for index i, AddressOfNames[i] gives the name RVA and AddressOfNameOrdinals[i] gives the corresponding function array index. A named export at ordinal 5 with Base=1 would have AddressOfNameOrdinals[i] = 4 (5 minus 1), so AddressOfFunctions[4] yields its RVA.

The export directory resides in .rdata because it contains read-only data — pointer arrays and name strings. Section-level memory protections (PAGE_READONLY on .rdata) mean the export arrays are readable but not writable. Techniques that modify AddressOfFunctions entries (T-008 Threadless injection) must first change page protections via NtProtectVirtualMemory.

The DataDirectory[0] entry in IMAGE_OPTIONAL_HEADER64 is at offset 0x70 from the start of the optional header, or equivalently at offset 0x88 from the start of IMAGE_NT_HEADERS64 (4 bytes signature plus 20 bytes file header plus 0x70 optional header fixed fields). This offset 0x88 appears in raw-offset implementations that bypass structured PE parsing, as seen in the HUGIN etw.rs code.

Forwarder entries are a PE feature where an export RVA points within the export directory itself rather than into .text. The linker writes a string such as "NTDLL.NtCreateFile" at that RVA, and GetProcAddress follows the forwarder to resolve the target in the referenced module. Manual implementations must handle this case to avoid returning a pointer to a string instead of a function body.

## Key Implementation Details

The HUGIN source implements PE export directory traversal in two locations with different approaches:

**dark_crystal/crates/core/src/pe.rs** — The `export_function_address` method on the `PE` struct performs structured export resolution using typed IMAGE_EXPORT_DIRECTORY pointers and `from_raw_parts` slices. It supports both export-by-ordinal (parsing the target export string as a u32, validating against Base and NumberOfFunctions) and export-by-name (linear scan of AddressOfNames with CStr string comparison). The function reads `self.export_data.VirtualAddress` from the pre-parsed DataDirectory entry and constructs three slices: names as `*const u32`, functions as `*const u32`, ordinals as `*const u16`. The name comparison uses `CStr::from_ptr` and `to_str()` for safe string handling. The function returns the resolved address as `address + functions[ordinal] as usize`, where address is the loaded PE base.

**dark_crystal/crowd/src/etw.rs** — The `resolve_export_by_hash` function implements raw-offset export traversal without typed PE structures. It reads e_lfanew at offset 0x3C, navigates to the NT headers, reads the export directory RVA at offset 0x88 (DataDirectory[0] in IMAGE_NT_HEADERS64), then manually dereferences IMAGE_EXPORT_DIRECTORY fields at their documented offsets: NumberOfNames at +0x18, AddressOfFunctions at +0x1C, AddressOfNames at +0x20, AddressOfNameOrdinals at +0x24. Name matching uses DJB2 hashing with pre-calculated hash constants (e.g., `HASH_ETW_EVENT_WRITE = 0x24A8D022` for "EtwEventWrite"). The hash constants are computed offline and embedded in the binary, eliminating function name strings from the compiled output.

The DJB2 implementation in etw.rs uses `h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(byte as u32)` with initial value 5381, matching the standard DJB2 variant used across the HUGIN codebase.

## Why It Matters

This technique is the shared primitive underlying three existing HUGIN cards. T-004 (PEB Walker) uses export traversal with DJB2 hashing to resolve Nt* functions for syscall dispatch without calling GetProcAddress. T-006 (Phantom Stubs) relies on locating legitimate exports when installing phantom stubs alongside real module exports. T-008 (Threadless Injection) must understand the AddressOfFunctions array to modify export entries for export hijack. Without a dedicated card documenting the export table walk algorithm, the vault forces readers to reverse-engineer the mechanism from three separate technique implementations that each assume prior knowledge of the IMAGE_EXPORT_DIRECTORY structure. The algorithm also handles edge cases — forwarder entries, ordinal-only exports, and base offsets — that individual technique cards do not re-explain.

## Detection Considerations

- **Telemetry sources**: GetProcAddress calls generate loader-mediated telemetry through the Kernel-Image ETW provider. Manual export table walks bypass this entirely, producing no loader events. EDR memory scanners can detect export-walking code through heuristic pattern matching — sequential DWORD reads at IMAGE_EXPORT_DIRECTORY field offsets, particularly when combined with DJB2 hash constants embedded in the binary.
- **Bypass options**: DJB2 hashing eliminates function name strings from the binary, preventing static string analysis from identifying resolved functions. Raw-offset traversal (as in etw.rs) avoids importing PE structure types that might appear in debug symbols or RTTI metadata. Executing the traversal from within a stomped module's .text section blends with legitimate loader activity.
- **Residual artifacts**: The absence of GetProcAddress from the IAT when the binary calls NT functions is a static indicator. Memory-resolved function pointers that point into ntdll's .text section at known Nt* export offsets are detectable through cross-referencing resolved addresses against the module's export table.

## Related Techniques

- **T-004 PEB Walker** — Uses PE export directory traversal with DJB2 hashing to resolve Nt* functions from ntdll via the PEB InLoadOrderModuleList
- **T-006 Phantom Stubs** — Relies on export table knowledge to locate legitimate exports when installing MEM_IMAGE-backed syscall stubs
- **T-008 Threadless Injection** — Modifies AddressOfFunctions entries for export hijack, requiring understanding of the parallel ordinal/function array relationship

## References

- Atlas material: atlas-exploit-dev-part2.md, atlas-exploit-dev-part18.md
- MITRE ATT&CK: T1027.007 — https://attack.mitre.org/techniques/T1027/007
- LGTM notes: lgtm:cross-source-pe-export-resolution-convergence, lgtm:getprocaddress-implementation-as-resolution-primitive
- Public references: SEC670 Units 23-32 (PE export resolution sequence), Unit 40 (GetProcAddress reimplementation)

## Source Reference

- `dark_crystal/crates/core/src/pe.rs` — `export_function_address()` method (structured export resolution by name and ordinal)
- `dark_crystal/crowd/src/etw.rs` — `resolve_export_by_hash()` function (raw-offset export resolution with DJB2 hashing)
<!-- END CARD T-083 -->

<!-- BEGIN CARD T-084 -->
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
<!-- END CARD T-084 -->

<!-- BEGIN CARD T-085 -->
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
<!-- END CARD T-085 -->

<!-- BEGIN CARD T-086 -->
---
id: T-086
name: Process Enumeration API Trade-off Matrix
category: discovery
tier: A
crate: none
mitre: T1057
tags: [process-enum, enumprocesses, toolhelp32-snapshot, wts-enumerate, ntquerysysteminfo, api-tradeoff, syscall-dispatch, recon]
origin: atlas-synthesis
member_notes: ['lgtm:process-enumeration-api-tradeoffs', 'lgtm:convergence-process-enum-api-tradeoffs', 'lgtm:coverage-gap-process-enumeration-variants', 'lgtm:ntquerysysteminformation-recon-via-syscall']
---

# Process Enumeration API Trade-off Matrix — Selecting the Right Process Discovery Primitive

## Summary

Windows exposes four distinct APIs for process enumeration, each with different metadata depth, session visibility, telemetry profiles, and hook susceptibility. The three documented Win32 APIs — K32EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcessesEx — provide decreasing simplicity for increasing detail and remote capability. NtQuerySystemInformation with SystemProcessInformation (class 5) is the undocumented alternative that returns a linked list of SYSTEM_PROCESS_INFORMATION structures including thread data, CPU times, and image base addresses, bypassing userland hooks in ntdll when called via direct or indirect syscall. The HUGIN vault documents syscall dispatch mechanisms (T-001 through T-004) but does not currently map which recon-class Nt* calls pair with which dispatch mechanism within the same implant. This card bridges that gap by documenting the enumeration API matrix and the operational trade-offs that govern API selection.

## Mechanism

1. **K32EnumProcesses / EnumProcessModules** (psapi.dll): Takes a DWORD array pointer and array size, returns the number of PIDs written. Provides a flat PID list with no parent-child relationship, no process paths, and no session information. The simplest API to call but the least informative. Requires a second pass with EnumProcessModules and GetModuleFileNameEx to obtain executable names. Access is mediated through psapi.dll which forwards to NtQuerySystemInformation internally.

2. **CreateToolhelp32Snapshot** (kernel32.dll): Call with TH32CS_SNAPPROCESS (0x00000002) to create a snapshot of all processes. Returns a snapshot handle that must be closed with CloseHandle. Iterate with Process32FirstW / Process32NextW, which fill PROCESSENTRY32W structures containing th32ProcessID (DWORD), th32ParentProcessID (DWORD), szExeFile (WCHAR[MAX_PATH]), cntThreads (DWORD), and th32ModuleID. The snapshot is point-in-time and may be stale by the time it is consumed. The kernel allocates a handle for the snapshot, which is observable through handle table monitoring.

3. **WTSEnumerateProcessesEx** (wtsapi32.dll): Takes a WTS server handle (WTS_CURRENT_SERVER_HANDLE for local), a level parameter (1 for WTS_PROCESS_INFO, 0 for WTS_PROCESS_INFO_EX), and returns an array. WTS_PROCESS_INFO contains pProcessId, pSessionId, pProcessName, pUserSid. WTS_PROCESS_INFO_EX adds numberOfThreads, pageFaultCount, handleCount, peakWorkingSet, workingSetSize, peakPagedPool, pagedPoolUsage, peakNonPagedPool, nonPagedPoolUsage, pagefileUsage, peakPagefileUsage, privatePageCount. Supports remote server enumeration via WTSOpenServerW. Requires the caller to be a member of the local Administrators group for cross-session visibility. Must free the returned buffer with WTSFreeMemory.

4. **NtQuerySystemInformation** (ntdll.dll, syscall): Call with SystemProcessInformation (class 5). The returned buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures connected via NextEntryOffset (ULONG at offset 0x00). A value of 0 in NextEntryOffset indicates the last entry. Each structure contains: NumberOfThreads (offset 0x04),CreateTime (offset 0x10), UserTime (offset 0x20), KernelTime (offset 0x28), ImageName (UNICODE_STRING at offset 0x38), BasePriority (offset 0x48), UniqueProcessId (HANDLE/ULONG_PTR at offset 0x50), InheritedFromUniqueProcessId (offset 0x58), HandleCount (offset 0x60), SessionId (offset 0x68), PeakVirtualSize/VirtualSize (offset 0x70/0x78), PeakWorkingSetSize/WorkingSetSize (offset 0x90/0x98), and an array of SYSTEM_THREAD_INFORMATION entries starting at offset 0x80 (before UniqueProcessId on some layouts; structure offsets vary by Windows version and should be validated). When called via direct or indirect syscall (T-001 RecycledGate, T-002 Hell's Gate), this API bypasses userland hooks in ntdll's .text section.

## OS Internals Context

All four APIs ultimately query the same kernel data — the active process list rooted at a global list head in ntoskrnl, traversed via EPROCESS.ActiveProcessLinks (a LIST_ENTRY at a version-dependent offset in the EPROCESS structure). The differences lie in how the data is filtered, formatted, and delivered to user mode.

K32EnumProcesses internally calls NtQuerySystemInformation(SystemProcessInformation) and extracts only the PID field from each returned structure. The overhead of the full structure copy is incurred even though only PIDs are returned. CreateToolhelp32Snapshot creates a kernel snapshot object (not a copy — it takes a reference count on the process list state) and iterates it via the Toolhelp driver. The snapshot handle appears in the calling process's handle table and can be detected by EDR via NtQueryInformationProcess or handle table enumeration.

WTSEnumerateProcessesEx routes through the TermSrv (Terminal Services) service via RPC, which in turn calls NtQuerySystemInformation. The RPC layer adds network visibility (the call can target remote servers) but also adds RPC telemetry that the other APIs do not produce. The service requires the caller to have SE_DEBUG_PRIVILEGE or be a local admin for cross-session results.

NtQuerySystemInformation is the raw syscall path. When dispatched via indirect syscall (T-001 RecycledGate), the call originates from a gadget in ntdll's .text section, making the return address appear legitimate. The syscall number for NtQuerySystemInformation is resolved through the same SSN resolution cascade (T-002) used for write-class syscalls like NtAllocateVirtualMemory and NtProtectVirtualMemory. This means a single implant can use the same dispatch infrastructure for both injection operations and recon operations.

The SYSTEM_PROCESS_INFORMATION structure is not documented in the Windows Driver Kit (WDK) headers. Structure offsets vary between Windows versions. Operators using this API must maintain version-specific offset tables or dynamically validate offsets at runtime by parsing the structure against known sentinel values (e.g., UniqueProcessId for the current process equals the value returned by GetCurrentProcessId).

## Key Implementation Details

**No current implementation in the HUGIN source.** The provided source files do not implement any of the four process enumeration APIs. The broader HUGIN codebase references process enumeration in `src/client_rust/src/sysinfo_collect.rs` (system info collection) and `src/client_rust/src/byakugan.rs` (network recon), but these files were not available for verification.

An implementation would select the enumeration API based on operational requirements: for injection target selection where parent-child relationships matter, CreateToolhelp32Snapshot provides the th32ParentProcessID field needed to find spawned child processes. For cross-session injection (T-047), WTSEnumerateProcessesEx provides session IDs. For stealth-constrained operations where the implant already has indirect syscall infrastructure, NtQuerySystemInformation via RecycledGate avoids all Win32 API calls and produces no handle table entries.

## Why It Matters

The vault documents syscall dispatch (T-001 through T-004) and injection techniques (T-007 through T-015) as separate capabilities, but does not connect them to the recon surface that precedes injection. An operator selecting an injection target needs process metadata — PID, parent PID, session ID, image path — and the API chosen to obtain that metadata has its own detection profile. Using CreateToolhelp32Snapshot inside an implant that performs injection via indirect syscall creates an asymmetry: the injection is hook-free but the recon is hookable. Documenting which enumeration APIs pair with which dispatch mechanisms closes this tradecraft gap and lets operators select the lowest-telemetry enumeration path that meets their detail requirement.

## Detection Considerations

- **Telemetry sources**: CreateToolhelp32Snapshot generates a kernel snapshot handle visible via handle table enumeration and the Kernel-Process ETW provider (Microsoft-Windows-Kernel-Process, Event ID 4 for handle creation). K32EnumProcesses generates no direct ETW but calls NtQuerySystemInformation which is hookable in ntdll. WTSEnumerateProcessesEx generates RPC traffic to the TermSrv service, detectable via RPC ETW providers. NtQuerySystemInformation called via direct syscall bypasses ntdll hooks entirely; called via indirect syscall (RecycledGate), the return address appears to originate from ntdll .text.
- **Bypass options**: NtQuerySystemInformation via indirect syscall eliminates userland hooks and produces no handle table entries. The same SSN resolution cascade used for injection syscalls resolves the NtQuerySystemInformation SSN. The caller can filter results to extract only needed fields, reducing the data footprint.
- **Residual artifacts**: CreateToolhelp32Snapshot leaves a snapshot handle in the handle table until CloseHandle is called. WTSEnumerateProcessesEx leaves RPC binding handles. NtQuerySystemInformation leaves no handles — only an allocation for the output buffer that must be freed via NtFreeVirtualMemory.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall dispatch mechanism that can route NtQuerySystemInformation calls through ntdll gadgets, bypassing userland hooks
- **T-002 Hell's Gate** — SSN resolution cascade resolves the NtQuerySystemInformation syscall number alongside write-class syscalls
- **T-023 Client Capabilities** — Recon module uses process enumeration for injection target selection and situational awareness
- **T-007 Process Injection** — Process enumeration informs injection target selection based on process metadata including parent PID and session ID

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part4.md, atlas-recon-part5.md, atlas-recon-part7.md
- MITRE ATT&CK: T1057 — https://attack.mitre.org/techniques/T1057
- LGTM notes: lgtm:process-enumeration-api-tradeoffs, lgtm:convergence-process-enum-api-tradeoffs, lgtm:coverage-gap-process-enumeration-variants, lgtm:ntquerysysteminformation-recon-via-syscall
- Public references: SEC670 Units 15, 39-40 (process enumeration API comparison), Units 12-14 (NtQuerySystemInformation recon via syscall)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-086 -->

<!-- BEGIN CARD T-087 -->
---
id: T-087
name: Win32 Enumeration API Taxonomy and Primitive Selection
category: discovery
tier: A
crate: none
mitre: T1082
tags: [enumeration, win32-api, com-enumeration, process-enum, service-enum, task-scheduler, peb-walker, api-taxonomy, discovery]
origin: atlas-synthesis
member_notes: ['lgtm:recon-api-taxonomy-coverage', 'lgtm:sec670-maldev-recon-convergence', 'lgtm:enumeration-primitives-coverage', 'lgtm:toolhelp-vs-peb-walker-divergence']
---

# Win32 Enumeration API Taxonomy and Primitive Selection — Discovery Surface Across Object Types

## Summary

Windows exposes a fragmented surface of enumeration APIs across Win32, COM, and NT syscall boundaries, each with different return types, access mask requirements, and EDR visibility profiles. SEC670 systematically catalogs these primitives across processes (CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcessesEx), users and groups (NetUserEnum, NetLocalGroupEnum), services (EnumServicesStatusEx), scheduled tasks (ITaskScheduler COM), and network interfaces (GetAdaptersAddresses). The HUGIN vault's T-004 (PEB Walker) deliberately avoids all Win32 enumeration patterns by walking the PEB via gs:[0x60] for module resolution — an in-process memory traversal that produces no kernel telemetry. This card documents the full enumeration taxonomy, the detection surface for each primitive, and the PEB-walker alternative as the evasion path for operators who need enumeration without the observability of Win32 API calls.

## Mechanism

1. **Process enumeration**: Three documented APIs plus one undocumented. CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) produces a snapshot handle and PROCESSENTRY32W structures with parent PID. K32EnumProcesses produces a flat PID array. WTSEnumerateProcessesEx produces session-aware results with SID and full process path. NtQuerySystemInformation(SystemProcessInformation) produces the raw kernel linked list with thread data and image base (see T-086 for the full trade-off matrix).

2. **User and group enumeration**: NetUserEnum (netapi32.dll) takes level parameter (0-4) controlling detail depth — level 0 returns username only, level 3 returns USER_INFO_3 with privilege and home directory data. NetLocalGroupEnum enumerates local groups with level 0-1. NetGroupEnum enumerates global groups. All require the caller to have appropriate access and produce network traffic to the Netlogon or SAM RPC interfaces. Active Directory enumeration via LDAP (adsi) or System.DirectoryServices namespaces provides domain-wide user, group, and computer data through the DirectoryEntry class bound to LDAP://RootDSE.

3. **Service enumeration**: EnumServicesStatusEx (advapi32.dll) takes an SC manager handle (from OpenSCManager), a service type filter, a service state filter, and a level parameter (SC_STATUS_PROCESS_INFO returns SERVICE_STATUS_PROCESS with PID, service type, current state, and process ID). Requires SC_MANAGER_ENUMERATE_SERVICE access on the SCM database. The SCM RPC interface is monitored by EDR via the Service Control Manager ETW provider (Microsoft-Windows-Service Control Manager, Event ID 4 for service enumeration queries). An alternative path is EnumDependentServicesW which enumerates services dependent on a specific service handle.

4. **Scheduled task enumeration**: The ITaskScheduler COM interface (CLSID 0x148BD52A) provides IScheduledTasksFolder with EnumTasks returning an IEnumWorkItems enumerator. Each task is an ITask COM object exposing task name, status, trigger, and action data. Alternatively, the XML-based Task Scheduler 2.0 API (ITaskService, CLSID 0x0F87369F) provides folder enumeration via ITaskFolder::GetTasks. The COM activation is observable via the Microsoft-Windows-DistributedCOM ETW provider.

5. **Network interface enumeration**: GetAdaptersAddresses (iphlpapi.dll) returns IP_ADAPTER_ADDRESSES linked list with adapter name, friendly name, IP addresses (unicast, anycast, multicast), DNS suffixes, and gateway addresses. Takes Family (AF_UNSPEC for both IPv4 and IPv6), Flags (GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_DNS_SERVER), and BufferSize parameters. The underlying NDIS and TCP/IP driver interfaces can also be queried via NtDeviceIoControlFile to the AFD (Ancillary Function Driver) and TCP device objects, bypassing iphlpapi.dll hooks.

6. **PEB-walker alternative (evasion path)**: Instead of calling any Win32 enumeration API, walk the PEB via gs:[0x60] (x64) or fs:[0x30] (x86) to access PEB → Ldr → InLoadOrderModuleList for loaded module enumeration. This is pure in-process memory traversal — no kernel calls, no handle creation, no RPC traffic, no ETW events. The HUGIN T-004 implementation uses DJB2 hashing to resolve module and function names without string literals. The trade-off: PEB walking only enumerates loaded modules in the current process, not system-wide processes, services, or tasks.

## OS Internals Context

The enumeration API surface maps to three layers of the Windows architecture. Win32 APIs (kernel32, advapi32, netapi32, iphlpapi) are user-mode wrappers that route to NT syscalls, RPC calls, or device IOCTLs. COM interfaces (ITaskScheduler, ITaskService) activate through the Service Control Manager or DCOM service, generating RPC traffic visible to network monitoring. NT-direct APIs (NtQuerySystemInformation, NtQueryDirectoryObject) bypass the Win32 layer and talk directly to the executive through syscalls.

The detection divergence between Toolhelp and PEB walking is structural. CreateToolhelp32Snapshot calls NtCreateSection and NtQuerySystemInformation internally, creating a kernel snapshot object that appears in the process handle table. The Kernel-Process ETW provider fires Event ID 4 (handle creation) when the snapshot handle is created. EDR products monitoring handle table growth or specific handle type creation detect this enumeration activity.

PEB walking reads gs:[0x60] to locate the PEB, then traverses the Ldr.InLoadOrderModuleList — a doubly-linked list of LDR_DATA_TABLE_ENTRY structures each containing a BaseDllName (UNICODE_STRING) and DllBase (PVOID) field. This traversal touches only already-mapped memory pages in the current process address space. No kernel transitions occur, no handles are created, no ETW providers fire. The detection surface is limited to memory scanning heuristics that look for code reading PEB-relative offsets in a sequential pattern.

The ITaskScheduler COM interface routes through RPC to the Schedule service (schedsvc.dll hosted in svchost.exe). The RPC call binds to the scheduled tasks endpoint and is visible in RPC ETW providers. The Task Scheduler 2.0 ITaskService interface similarly activates via DCOM, generating DistributedCOM ETW events with the CLSID of the Task Scheduler class.

## Key Implementation Details

**No current implementation in the HUGIN source** for the full enumeration taxonomy. The PEB-walker alternative is implemented in `dark_crystal/crowd/src/etw.rs` via the `resolve_export_by_hash` function, which reads the module base and walks its export table. The broader HUGIN codebase references enumeration in `src/client_rust/src/byakugan.rs` (network recon including ARP, TCP, AD enum) and `src/client_rust/src/sysinfo_collect.rs` (system info collection), but these files were not available for verification.

The PEB-walker implementation in etw.rs reads MZ at the module base, e_lfanew at offset 0x3C, and navigates to the export directory via raw offset arithmetic. This same code pattern serves as the evasion alternative to calling EnumProcessModules or EnumServicesStatusEx — by resolving function addresses through in-memory PE traversal rather than Win32 API calls.

## Why It Matters

The vault documents T-023 (Client Capabilities) recon and T-004 (PEB Walker) as separate techniques, but does not explain why PEB walking is the preferred enumeration path or what detections it sidesteps. An operator choosing between CreateToolhelp32Snapshot and NtQuerySystemInformation for process enumeration, or between ITaskScheduler COM and registry parsing for task enumeration, needs to understand the telemetry profile of each option. The cross-source convergence between SEC670 and MalDev Academy on this taxonomy — both present the same three process enumeration APIs with the same trade-off matrix — indicates strong tradecraft consensus that warrants a dedicated discovery card.

## Detection Considerations

- **Telemetry sources**: CreateToolhelp32Snapshot generates Kernel-Process ETW Event ID 4 for handle creation. EnumServicesStatusEx generates Service Control Manager ETW events. NetUserEnum generates SAM RPC traffic. ITaskScheduler COM activation generates DistributedCOM ETW events. GetAdaptersAddresses calls through iphlpapi.dll which is hookable in userland. PEB walking generates no ETW events, no handle table entries, and no RPC traffic.
- **Bypass options**: PEB walking for module enumeration eliminates all Win32 API telemetry. NtQuerySystemInformation via indirect syscall eliminates userland hooks for process enumeration. Registry parsing for scheduled tasks (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache) avoids ITaskScheduler COM activation. Direct NT device IOCTLs to the TCP driver bypass iphlpapi.dll hooks for network interface enumeration.
- **Residual artifacts**: CreateToolhelp32Snapshot leaves a snapshot handle. WTSEnumerateProcessesEx leaves RPC binding handles. ITaskScheduler leaves COM references. PEB walking leaves no artifacts.

## Related Techniques

- **T-004 PEB Walker** — Deliberately avoids Win32 enumeration APIs by walking the PEB for module resolution, sidestepping all ETW telemetry and handle table artifacts
- **T-023 Client Capabilities** — Recon module (byakugan.rs) implements enumeration capabilities that should align with the API taxonomy and telemetry profiles documented here
- **T-017 Persistence Suite** — Persistence techniques interact with SCM, scheduled tasks, and COM interfaces whose enumeration primitives are documented in this taxonomy

## References

- Atlas material: atlas-enumeration-part1.md, atlas-enumeration-part2.md, atlas-exploit-dev-part16.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:recon-api-taxonomy-coverage, lgtm:sec670-maldev-recon-convergence, lgtm:enumeration-primitives-coverage, lgtm:toolhelp-vs-peb-walker-divergence
- Public references: SEC670 (enumeration API taxonomy across processes, users, groups, services, tasks, network interfaces), MalDev Academy (enumeration API selection), CRTO (recon tradecraft)

## Source Reference

No current implementation for the full enumeration taxonomy. The PEB-walker alternative is implemented in `dark_crystal/crowd/src/etw.rs` (`resolve_export_by_hash` function). See atlas material for the complete API matrix.
<!-- END CARD T-087 -->

<!-- BEGIN CARD T-088 -->
---
id: T-088
name: Windows Object Manager as Foundational Reference Card
category: discovery
tier: C
crate: none
mitre: T1082
tags: [object-manager, object-header, handle-table, acl, executive-objects, kernel-objects, foundational-concept]
origin: atlas-synthesis
member_notes: ['lgtm:windows-object-manager-foundational-concept', 'lgtm:windows-object-manager-foundation', 'lgtm:windows-object-manager-foundations-card']
---

# Windows Object Manager as Foundational Reference Card — Executive Object Model, Handle Tables, and ACL Gating

## Summary

The Windows Object Manager is the executive subsystem that standardizes object creation, naming, handle management, and security across all kernel object types — Process, Thread, File, Token, Event, Mutant, Section, Key, and 4000+ registered types. Every cross-process and cross-thread operation in the HUGIN vault — injection via handle ops (T-007), PPID spoofing and handle manipulation (T-014/T-015), handle blocking (T-016), PE loading via Section objects (T-013), and PEB walking (T-004) — depends on the Object Manager's handle table and ACL-gated access model. This card documents the executive object schema, the per-process handle table, the ObpCreateHandle flow, and why PEB walking avoids the handle table entirely.

## Mechanism

1. **Object type registration**: The kernel registers object types during boot via ObCreateObjectType. Each type (PsProcessType, IoFileObjectType, ExEventObjectType, etc.) has a OBJECT_TYPE_INITIALIZER structure specifying default pool type, valid access mask, and callbacks: OpenProcedure, CloseProcedure, DeleteProcedure, ParseProcedure, SecurityProcedure, QueryNameProcedure. Windows 10 maintains 70+ executive object types; the full type list is queryable via NtQueryObject(ObjectAllInformation).

2. **Object structure**: Every executive object consists of an OBJECT_HEADER preceding the object body. The header contains TypeIndex (UCHAR, index into ObpTypeObjectTypeTable), and optional sub-headers located via offsets in OBJECT_HEADER: NameInfoOffset (pointer to OBJECT_HEADER_NAME_INFO containing the object's name and directory), SecurityDescriptorOffset (pointer to OBJECT_HEADER_SECURITY_DESCRIPTOR), QuotaInfoOffset (pointer to OBJECT_HEADER_QUOTA_INFO). The object body follows immediately after the header and its optional sub-headers.

3. **Handle creation flow**: When a user-mode thread calls a Create* or Open* API (CreateProcess, OpenProcess, CreateFile, etc.), the call routes to the corresponding Nt* syscall, which calls ObCreateObject to allocate the object body and header from pool memory, then ObpCreateHandle to insert the object into the per-process handle table and return a handle value to user mode.

4. **ACL check during handle creation**: ObpCreateHandle calls SeAccessCheck against the object's security descriptor (referenced via SecurityDescriptorOffset in OBJECT_HEADER). The check evaluates the caller's token (primary or impersonation) against the object's DACL. If the DACL does not grant the requested access right to the caller's SID, ObpCreateHandle returns STATUS_ACCESS_DENIED and no handle is created. This is the kernel-level enforcement that handle blocking (T-016) manipulates.

5. **Per-process handle table**: Each EPROCESS contains a HandleTable field (PHANDLE_TABLE) pointing to the process's handle table structure. The handle table uses a three-level scheme: the top level contains pointers to mid-level tables, each mid-level table contains pointers to low-level tables, and each low-level table contains HANDLE_TABLE_ENTRY structures (8 bytes each on x64) containing the object pointer (with bits reserved for granted access and attributes) and a granted access mask. The global handle table (PspCidTable) stores Process and Thread objects by PID/TID for system-wide lookup.

6. **Handle value encoding**: The handle value returned to user mode is an index into the process handle table, multiplied by 4 (for tag bits). The kernel uses the handle value to index into the handle table, retrieve the HANDLE_TABLE_ENTRY, extract the object pointer, and validate the granted access mask against the operation being performed.

7. **NtQueryObject(ObjectAllInformation)**: Returns a buffer containing the count of object types, followed by an array of OBJECT_TYPE_INFORMATION structures (one per type) containing TypeName (UNICODE_STRING), TotalNumberOfObjects, TotalNumberOfHandles, TotalPagedPoolUsage, TotalNonPagedPoolUsage, and type-specific information. This provides the complete Object Manager view from user mode without kernel debugging.

## OS Internals Context

The distinction between executive objects, kernel objects, USER objects, and GDI objects is structural. Executive objects are managed by the Object Manager and use the OBJECT_HEADER schema — Process, Thread, File, Token, Event, Mutant, Section, Key, Desktop, and others. Kernel objects are internal structures not exposed through the Object Manager (e.g., DEVICE_NODE, DRIVER_OBJECT). USER objects (windows, menus, cursors) and GDI objects (bitmaps, brushes, DCs) are managed by win32k.sys through a separate handle table (the shared USER/GDI handle table in the session's SessionId space) and do not have OBJECT_HEADER structures.

The handle table's three-level design supports up to 16 million handles per process (2^24 entries in the low level). Each HANDLE_TABLE_ENTRY contains the object pointer in its upper bits, with the low bits encoding GrantedAccess (25 bits) and handle attributes (inherit, audit on close, protect from close). The GrantedAccess bits are set at handle creation time from the requested access mask after the ACL check, and are checked on every subsequent operation through the handle.

The ObpCreateHandle flow for process creation (NtCreateUserProcess, used by T-014) involves: allocating EPROCESS and KPROCESS structures via ObCreateObject, setting up the address space via MmCreatePeb, creating the Section object for the image, inserting the Process object into PspCidTable (the global handle table indexed by PID), and inserting a handle into the parent process's handle table. The parent's handle to the new process carries the access rights granted by the ACL check — typically PROCESS_ALL_ACCESS if the parent has SE_DEBUG_PRIVILEGE.

Section objects (used by T-013 PE Loader and T-007 mapping injection) are executive objects backed by the Memory Manager's section/subsection structures. NtCreateSection creates a Section object with a control area pointing to either a file object (for image and data files) or to committed page table entries (for pagefile-backed sections). The Section object's ACL determines which processes can map it via NtMapViewOfSection.

PEB walking (T-004) avoids the Object Manager entirely. The PEB is located via the TEB (gs:[0x30] on x64 points to the TEB, TEB.ProcessEnvironmentBlock at offset 0x60 points to the PEB). The PEB is already mapped in the current process's address space — it is not an object with an OBJECT_HEADER, and accessing it requires no handle and triggers no ACL check. The Ldr.InLoadOrderModuleList within the PEB contains pointers to LDR_DATA_TABLE_ENTRY structures, each with a DllBase field pointing to the module's mapped image. Reading these pointers is pure memory dereference with no kernel transition.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents a foundational Windows internals concept that underpins multiple HUGIN techniques. The Object Manager structures and handle table mechanics are not directly implemented in Rust source code — they are kernel structures that HUGIN techniques interact with through NT syscalls.

An implementation leveraging Object Manager knowledge would use NtQueryObject(ObjectAllInformation) to enumerate object types and NtQueryDirectoryObject to enumerate named objects in the Object Manager namespace (rooted at "\"). The per-process handle table can be enumerated via NtQuerySystemInformation(SystemExtendedHandleInformation) to discover handles held by other processes, which is relevant for handle hijacking operations.

The `dark_crystal/crowd/src/herpaderping.rs` implementation interacts with the Object Manager when calling NtCreateSection (creating a Section object), NtOpenFile (creating a File object handle), NtCreateProcessEx (creating a Process object), and NtCreateThreadEx (creating a Thread object). Each of these calls passes through ObpCreateHandle and the ACL check. The PROCESS_ALL_ACCESS constant (0x001FFFFF) used in herpaderping.rs reflects the full access mask granted on process objects.

## Why It Matters

The vault documents handle blocking (T-016), PPID spoofing (T-015), injection via handle ops (T-007), PE loading via Section objects (T-013), and PEB walking (T-004) as independent techniques, but all of them operate within the Object Manager's framework. Operators who understand why handle-based detection fires, why PEB walking avoids the handle table, and why Section objects mediate mapping injection can trace technique success or failure to the kernel's ACL check rather than guessing at API behavior. A reference card for the Object Manager lets readers reach the technique cards with the prerequisite mental model already in place.

## Detection Considerations

- **Telemetry sources**: Handle creation generates Object Manager ETW events (Microsoft-Windows-Kernel-Object, Event ID 1 for handle creation). Process and Thread object creation generates Kernel-Process ETW events. NtQueryObject and NtQueryDirectoryObject calls are hookable in ntdll. Handle table enumeration via NtQuerySystemInformation(SystemHandleInformation) is a reconnaissance indicator monitored by EDR.
- **Bypass options**: PEB walking avoids all handle creation and ACL checks by reading in-process memory directly. Direct syscalls (T-001, T-002) bypass userland hooks on Nt* APIs that create objects. Object creation with minimal access masks reduces the footprint of granted access bits.
- **Residual artifacts**: Every executive object created through ObpCreateHandle leaves an entry in the creating process's handle table until the handle is closed. Section objects persist until all views are unmapped and the handle is closed. Process and Thread objects persist in PspCidTable until termination.

## Related Techniques

- **T-004 PEB Walker** — PEB walking avoids the Object Manager handle table entirely by reading in-process memory structures through TEB → PEB → Ldr traversal
- **T-007 Process Injection** — Injection techniques create and manipulate Section, Process, and Thread objects through the Object Manager handle creation and ACL check flow
- **T-016 EDR Evasion Suite** — Handle blocking manipulates Object Manager security descriptors and ACLs to deny external process handle access
- **T-015 PPID Spoofing** — Parent PID spoofing manipulates process object creation through the Object Manager handle flow via NtCreateUserProcess

## References

- Atlas material: atlas-methodology-part1.md, atlas-methodology-part2.md, atlas-methodology-part5.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:windows-object-manager-foundational-concept, lgtm:windows-object-manager-foundation, lgtm:windows-object-manager-foundations-card
- Public references: SEC670 Units 33, 35-39 (Object Manager, executive objects, handle tables, ACL gating)

## Source Reference

No current implementation. See atlas material and MITRE reference for Object Manager concepts. The `dark_crystal/crowd/src/herpaderping.rs` implementation interacts with Object Manager structures through NtCreateSection, NtCreateProcessEx, and NtCreateThreadEx syscalls.
<!-- END CARD T-088 -->

<!-- BEGIN CARD T-089 -->
---
id: T-089
name: WMI as Dual-Use Recon and Persistence Channel
category: discovery
tier: A
crate: none
mitre: T1047
mitre_secondary: [T1546.003]
tags: [wmi, com-interfaces, iwbeanservices, recon, persistence, dual-use, event-subscription, root-subscription, win32-classes]
origin: atlas-synthesis
member_notes: ['lgtm:cross-source-wmi-convergence', 'lgtm:cross-source-wmi-recon-persistence-convergence']
---

# WMI as Dual-Use Recon and Persistence Channel — Single COM Session for Enumeration and Permanent Event Subscription

## Summary

Windows Management Instrumentation (WMI) is the single Windows management substrate that supports both host reconnaissance (read queries via IWbemServices::ExecQuery on standard namespaces) and persistence (write operations via permanent event subscriptions in the root\subscription namespace) using the same COM interfaces. An operator can enumerate processes, services, and registry data via Win32_* class queries and establish persistence via __EventFilter/__EventConsumer/__FilterToConsumerBinding binding — all within a single IWbemServices COM session obtained through CoCreateInstance(CLSID_WbemLocator) → IWbemLocator::ConnectServer. The HUGIN vault's T-023 recon card and T-017 persistence card both miss this dual-use nature, which means the same COM channel serves both operational phases without reconnection or reconfiguration.

## Mechanism

1. **COM initialization**: Call CoInitializeEx(NULL, COINIT_MULTITHREADED) to initialize the COM apartment, then CoInitializeSecurity to set the authentication level (RPC_C_AUTHN_LEVEL_PKT_PRIVACY for encrypted traffic) and impersonation level (RPC_C_IMP_LEVEL_IMPERSONATE).

2. **Locator creation**: Call CoCreateInstance with CLSID_WbemLocator (0x4590F811-1D3A-11D0-891F-00AA004B2E24) and IID_IWbemLocator to obtain an IWbemLocator interface pointer.

3. **Namespace connection for recon**: Call IWbemLocator::ConnectServer with bstrNamespace = L"ROOT\\CIMV2" to connect to the standard CIM namespace. This returns an IWbemServices pointer for querying management data. For registry enumeration, connect to L"ROOT\\DEFAULT" and use the StdRegProv class.

4. **Recon queries via ExecQuery**: Call IWbemServices::ExecQuery with WQL query strings: "SELECT * FROM Win32_Process" returns process information including Name, ProcessId, CommandLine, ExecutablePath. "SELECT * FROM Win32_Service" returns service name, state, start mode, and path. "SELECT * FROM Win32_Registry" or the StdRegProv provider returns registry key values. The query results come back as an IEnumWbemClassObject enumerator, and each object's properties are accessed via IWbemClassObject::Get with property names like "ProcessId", "Name", "ExecutablePath".

5. **Namespace connection for persistence**: Using the same IWbemLocator instance, call ConnectServer with bstrNamespace = L"ROOT\\SUBSCRIPTION" to connect to the subscription namespace. This returns a separate IWbemServices pointer for persistence operations. The root\subscription namespace hosts __EventFilter, __EventConsumer, and __FilterToConsumerBinding classes.

6. **Persistence via permanent event subscription**: Create instances of three classes in root\subscription:
   - __EventFilter: Defines the trigger condition via the Query property (WQL query, e.g., "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12").
   - __EventConsumer (typically ActiveScriptEventConsumer or CommandLineEventConsumer): Defines the action. CommandLineEventConsumer has an ExecutablePath and CommandLineTemplate property. ActiveScriptEventConsumer has a ScriptText property for VBScript/JScript execution.
   - __FilterToConsumerBinding: Links the filter to the consumer via the Filter and Consumer properties (references to the __EventFilter and __EventConsumer instances).

7. **Writing persistence instances**: Call IWbemServices::PutInstance on each class instance (filter, consumer, binding). The PutInstance method with WBEM_FLAG_CREATE_OR_UPDATE creates the instances in the WMI repository (located at %SystemRoot%\System32\wbem\Repository). These instances persist across reboots and execute the consumer action whenever the filter condition triggers.

8. **Cleanup of recon session**: The IWbemServices pointer for root\cimv2 can be released after recon queries complete. The IWbemServices pointer for root\subscription must remain valid only during PutInstance calls — the persistence instances survive in the repository independently of the COM session.

## OS Internals Context

WMI is implemented by the Windows Management Instrumentation service (WmiSvc, hosted in a svchost.exe process under the NetworkService account). The service exposes DCOM interfaces that client processes access through the COM activation framework. When ConnectServer is called, the COM runtime marshals the call to the WMI service via RPC, which in turn accesses the CIMOM (Common Information Model Object Manager) to resolve the namespace and return an IWbemServices proxy.

The root\cimv2 namespace is the default repository for system management data. Win32_* provider classes are implemented by provider DLLs loaded by the WMI service on demand. Win32_Process is backed by the WmiPerfClass provider that queries the kernel process list. Win32_Service is backed by the SCM provider that queries the Service Control Manager. These providers execute in the WMI service process, not in the caller's process — the caller receives serialized results via DCOM marshaling.

The root\subscription namespace is special: it is not backed by dynamic providers but by the WMI event delivery subsystem. Permanent event subscriptions are stored in the CIM repository database (a compound file stored on disk). The WMI service polls for event triggers at the interval specified in the __EventFilter.Query (the WITHIN clause). When the trigger fires, the service instantiates the __EventConsumer and executes its action. CommandLineEventConsumer spawns a process under the WMI service's security context (NetworkService by default, or LocalSystem if the service runs under that account).

The dual-use nature arises because the same COM activation path — CoCreateInstance → IWbemLocator → ConnectServer → IWbemServices — serves both the read path (ExecQuery on root\cimv2) and the write path (PutInstance on root\subscription). The only difference is the namespace string passed to ConnectServer and the method called on the returned IWbemServices pointer. An EDR monitoring IWbemServices method calls would need to distinguish between ExecQuery (recon) and PutInstance (persistence) calls — both use the same RPC interface and service endpoint.

The CRTO course surfaces WMI via Get-Domain / Get-DomainController PowerShell cmdlets, which wrap WMI/CIM calls under the hood. These cmdlets query Win32_* classes through the System.Management.ManagementObjectSearcher class, which internally uses the same IWbemServices::ExecQuery path.

## Key Implementation Details

**No current implementation in the HUGIN source.** The provided source files do not implement WMI operations. The broader HUGIN file manifest references `src/experimental/harvest/wmi_exec.rs` with role "WMI execution," but this file was not available for verification.

An implementation would require the `windows` crate's COM bindings for IWbemLocator, IWbemServices, IWbemClassObject, and IEnumWbemClassObject. The Rust code would use `CoInitializeEx` and `CoCreateInstance` via the `windows::Win32::System::Com` module, then call `ConnectServer` and `ExecQuery` through the `windows::Win32::System::Wmi` module if available, or through manual COM vtable invocation via `Interface::vtable()`.

For the persistence path, the implementation would use `IWbemServices::GetObject` to obtain class objects for __EventFilter, CommandLineEventConsumer, and __FilterToConsumerBinding, spawn instances via `IWbemClassObject::SpawnInstance`, set properties via `IWbemClassObject::Put`, and commit via `IWbemServices::PutInstance`.

## Why It Matters

The vault splits WMI across T-023 (recon) and T-017 (persistence), and T-037 (WMI permanent event subscription persistence) documents the persistence mechanism in isolation. The operational coupling — that the same COM channel, the same CLSID_WbemLocator activation, and the same IWbemServices interface serve both recon and persistence — is not surfaced anywhere. An operator who establishes an IWbemServices session for recon can reuse that session's IWbemLocator to connect to root\subscription and write persistence instances without a second COM activation. This eliminates a second DCOM binding event that would otherwise be observable by EDR. Documenting the dual-use nature makes this operational efficiency explicit.

## Detection Considerations

- **Telemetry sources**: COM activation of CLSID_WbemLocator generates DistributedCOM ETW events (Microsoft-Windows-DistributedCOM, Event ID 4 for DCOM activation). IWbemServices::ExecQuery calls generate Microsoft-Windows-WMI Activity ETW events. PutInstance calls on root\subscription are logged in the WMI repository and are queryable via `Get-WmiObject -Namespace root\subscription -Class __EventFilter`. The WMI service logs permanent subscription creation in the Event Log under Microsoft-Windows-WMI-Activity/Operational.
- **Bypass options**: Using direct DCOM instead of the COM moniker path reduces string artifacts. Connecting to root\subscription with the same IWbemLocator used for root\cimv2 recon avoids a second DCOM activation event. CommandLineEventConsumer with a benign-looking ExecutablePath blends with legitimate WMI-triggered processes. ActiveScriptEventConsumer with obfuscated script text avoids static analysis of the payload.
- **Residual artifacts**: __EventFilter, __EventConsumer, and __FilterToConsumerBinding instances persist in the CIM repository database at %SystemRoot%\System32\wbem\Repository. These are queryable via PowerShell `Get-WmiObject -Namespace root\subscription -List` and are a standard persistence detection target. The spawned consumer process appears as a child of the WMI service host (svchost.exe).

## Related Techniques

- **T-023 Client Capabilities** — Recon module could leverage WMI Win32_* classes for host enumeration via the same COM session used for persistence
- **T-017 Persistence Suite** — WMI permanent event subscription persistence in root\subscription uses the same IWbemServices COM channel as WMI recon queries

## References

- Atlas material: atlas-recon-part3.md, atlas-recon-part5.md
- MITRE ATT&CK: T1047 — https://attack.mitre.org/techniques/T1047
- LGTM notes: lgtm:cross-source-wmi-convergence, lgtm:cross-source-wmi-recon-persistence-convergence
- Public references: SEC670 Book 2 Units 19-24 (WMI recon via Win32_* classes), SEC670 Book 4 (WMI persistence via __EventFilter/__EventConsumer), CRTO (Get-Domain / Get-DomainController WMI wrappers)

## Source Reference

No current implementation in the provided source files. The file manifest references `src/experimental/harvest/wmi_exec.rs` with role "WMI execution" but the file was not available for verification. See atlas material and MITRE reference for public WMI tooling.
<!-- END CARD T-089 -->

<!-- BEGIN CARD T-090 -->
---
id: T-090
name: PE Format Internals — MZ Header, DOS Stub, Section Layout
category: discovery
tier: C
crate: dark_crystal
source_file: dark_crystal/crates/core/src/pe.rs, dark_crystal/crowd/src/herpaderping.rs
mitre: T1082
tags: [pe-format, mz-header, dos-stub, section-headers, text-section, rdata-section, stomping-foundation, section-layout, image-section-header]
origin: atlas-synthesis
member_notes: ['lgtm:pe-section-manipulation-foundations', 'lgtm:gap-pe-format-internals-coverage']
---

# PE Format Internals — MZ Header, DOS Stub, Section Layout — Structural Foundation for Stomping and Reflective Loading

## Summary

The PE binary format arranges executable content into named sections — .text for executable code, .rdata for read-only data including the export directory, .data for mutable global data, .reloc for base relocations, and .rsrc for resources — each with a section header specifying its virtual address, raw data size, file offset, and memory protection characteristics. This section layout is the structural foundation for module stomping (overwriting a loaded module's .text section while preserving its VAD entry), function stomping (overwriting specific export function bytes), PE header stomping, and reflective loading (manual section mapping with relocation and IAT fixing). Understanding why stomping .text preserves VAD entries, why export RVAs in .rdata must remain consistent, and how section characteristics map to memory protections is prerequisite for the stomping and loading techniques in T-006, T-013, and T-016.

## Mechanism

1. **MZ header (IMAGE_DOS_HEADER)**: The first 64 bytes of every PE binary. The structure begins with e_magic at offset 0x00 (WORD, 0x5A4D for "MZ"). The critical field e_lfanew at offset 0x3C (LONG) holds the file offset to the IMAGE_NT_HEADERS structure. The remaining fields (e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res[4], e_oemid, e_oeminfo, e_res2[10]) are DOS-era metadata largely ignored by the PE loader.

2. **DOS stub**: The variable-length region between IMAGE_DOS_HEADER (offset 0x40) and IMAGE_NT_HEADERS (offset e_lfanew). Contains a minimal real-mode program that typically prints "This program cannot be run in DOS mode" and exits. The stub is padded to align the PE headers. The PE loader skips this region entirely by following e_lfanew.

3. **IMAGE_NT_HEADERS64**: Begins at offset e_lfanew. Contains Signature (DWORD, "PE\0\0" = 0x00004550), followed by IMAGE_FILE_HEADER (20 bytes) and IMAGE_OPTIONAL_HEADER64 (variable size, 0xF0 bytes for PE32+ on modern Windows).

4. **Section header array**: Begins immediately after IMAGE_OPTIONAL_HEADER64, at offset e_lfanew + 0x18 + SizeOfOptionalHeader. Contains NumberOfSections entries, each 40 bytes (IMAGE_SECTION_HEADER). The array is sorted by VirtualAddress in loaded images.

5. **.text section layout**: The section containing executable code. Its IMAGE_SECTION_HEADER fields: Name = ".text\0\0\0" (8 bytes, null-padded), VirtualAddress = RVA where the section is loaded in memory, SizeOfRawData = size of the section in the file (aligned to FileAlignment), PointerToRawData = file offset of the section data, Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE (typically 0x60000020). In memory, the loader applies PAGE_EXECUTE_READ protection to this section.

6. **.rdata section layout**: The section containing read-only data — export directory, import descriptors, IAT, string constants, and relocation data. Characteristics typically include IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA (0x40000040). The loader applies PAGE_READONLY protection. The export directory's RVA (from DataDirectory[0]) points into this section.

7. **Section-to-memory-protection mapping**: The loader maps IMAGE_SECTION_HEADER.Characteristics flags to VirtualProtect constants: IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_READ → PAGE_EXECUTE_READ; + IMAGE_SCN_MEM_WRITE → PAGE_EXECUTE_READWRITE; IMAGE_SCN_MEM_READ + IMAGE_SCN_MEM_WRITE → PAGE_READWRITE; IMAGE_SCN_MEM_READ only → PAGE_READONLY. Techniques that stomp sections must match or exceed the original protection to write and then restore appropriate protections.

8. **VAD entry preservation during stomping**: When a module is loaded by the loader, the Memory Manager creates a Virtual Address Descriptor (VAD) entry describing the mapped section. The VAD entry records the section's base address, size, and backing section object. Module stomping overwrites the .text section's content via NtProtectVirtualMemory (to make it writable) and NtWriteVirtualMemory or memcpy, but does not unmap or remap the section. The VAD entry remains valid because the section object and its mapping are unchanged — only the content bytes differ. This is why stomped modules appear as legitimate loaded modules in process memory listings.

9. **Export RVA consistency in .rdata**: The export directory and its three arrays (AddressOfNames, AddressOfNameOrdinals, AddressOfFunctions) contain RVAs relative to the module base. These RVAs must remain valid after stomping — if .rdata content is modified, the RVA arithmetic still works because the module base is unchanged. However, if an export function in .text is stomped, the RVA in AddressOfFunctions still points to the same offset in .text — the code at that offset is now the stomped content. Threadless injection (T-008) relies on this: it modifies AddressOfFunctions to redirect export calls to injected code, and the original .text content remains undisturbed at the original RVA.

## OS Internals Context

The PE section layout reflects the format's heritage from COFF (Common Object File Format). Each section represents a contiguous block of memory with uniform characteristics — execute, read, write permissions — that the loader translates into page-level protections via NtProtectVirtualMemory. The section granularity (typically 4KB or 64KB aligned) matches the processor's page size, allowing the Memory Manager to apply different protections to different sections of the same image.

The VAD (Virtual Address Descriptor) is the kernel structure tracking virtual memory regions in a process. For mapped images (loaded via NtMapViewOfSection from a SEC_IMAGE section), the VAD entry is a SUBSECTION_VAD type that records the backing section object pointer, the view's starting VA, and the committed range. When an EDR scans process memory via NtQueryVirtualMemory or NtReadVirtualMemory, the VAD entry indicates the region is a MEM_IMAGE mapping backed by a named file — the module's file path. Stomping the .text content does not change the VAD type or the backing file path, which is why stomped modules pass memory-scan heuristics that check for MEM_IMAGE-backed regions.

The .rdata section's role as the export directory container creates a dependency: export resolution code reads RVAs from .rdata to locate function addresses in .text. If .rdata is modified (e.g., by PE header stomping that overwrites the headers region), export resolution against the stomped module may fail. PE header stomping (T-016) typically stomps the DOS header and NT headers but leaves .rdata intact to maintain export resolution capability for the stomped module's own exports.

The DOS stub is an artifact of backward compatibility with DOS. The Windows loader does not execute it — it validates e_magic, reads e_lfanew, and jumps directly to the PE headers. The stub's only modern purpose is to provide a user-friendly error message when a PE binary is executed under DOS. Some packers and protectors use the DOS stub region for additional data or code, but the standard Windows stub is approximately 64 bytes of real-mode instructions followed by the "This program cannot be run in DOS mode" message string.

## Key Implementation Details

**dark_crystal/crates/core/src/pe.rs** implements section-level PE parsing. The `PE::new` constructor reads IMAGE_DOS_HEADER (validating e_magic against IMAGE_DOS_SIGNATURE and e_lfanew for validity), navigates to IMAGE_NT_HEADERS64 (validating Signature against IMAGE_NT_SIGNATURE), and computes the section header pointer as `nt_header + size_of::<IMAGE_NT_HEADERS64>()`. The `PE` struct stores the section_header pointer for use by subsequent methods.

The `prepare` method maps sections from file to memory: iterates NumberOfSections entries, reads each section's VirtualAddress, PointerToRawData, and SizeOfRawData, and uses `std::ptr::copy_nonoverlapping` to copy section data from the file buffer to the allocated memory region at the section's VirtualAddress offset.

The `fixing_memory` method maps section Characteristics flags to VirtualProtect constants using a match expression: IMAGE_SCN_MEM_EXECUTE + READ + WRITE → PAGE_EXECUTE_READWRITE; EXECUTE + READ → PAGE_EXECUTE_READ; READ + WRITE → PAGE_READWRITE; READ only → PAGE_READONLY. It calls VirtualProtect on each section at its VirtualAddress offset.

**dark_crystal/crowd/src/herpaderping.rs** implements minimal PE structure reading. The `parse_entry_point` function validates the MZ header (checking buffer length and reading e_lfanew at offset 0x3C), computes the entry point offset as `e_lfanew + 4 + 20 + 16` (signature + file header + offset of AddressOfEntryPoint in optional header), and reads the DWORD RVA. This is the minimal PE header traversal needed to locate the entry point for thread creation in the herpaderped process.

## Why It Matters

The vault documents module stomping (T-006), PE loading (T-013), and PE header stomping (T-016) as operational techniques but does not surface the underlying section layout knowledge that explains why these techniques work. Operators who stomp a .text section need to understand that the VAD entry remains valid because the section mapping is not disturbed — only the content changes. Operators who perform export hijack need to understand that .rdata RVAs remain consistent because the module base is unchanged. Operators who stomp PE headers need to understand that .rdata must remain intact for export resolution to continue functioning against the stomped module. Without a dedicated card for section layout and its stomping implications, these operational constraints are implicit in the technique implementations but not documented for the reader.

## Detection Considerations

- **Telemetry sources**: Module stomping produces no loader events because the module remains mapped via the original VAD entry. EDR memory scanners detect stomped modules by comparing the in-memory .text content against the on-disk file content — if they differ, the section has been modified. PE-sieve and Moneta are tools that perform this comparison by mapping the original file and diffing section contents.
- **Bypass options**: Stomping with content that matches the hash of the original section reduces diff-based detection. Module overloading (loading a new PE into an existing module's space) avoids the diff problem entirely because the original file no longer matches. Function stomping (overwriting a single export function) produces a smaller diff that may fall below scanner thresholds.
- **Residual artifacts**: Stomped .text sections have content that does not match the backing file on disk. NtProtectVirtualMemory calls to make .text writable appear in handle-based telemetry if the EDR hooks NtProtectVirtualMemory. The modified .text section may have different entropy or instruction patterns from the original, detectable by heuristic scanners.

## Related Techniques

- **T-006 Phantom Stubs** — Module stomping overwrites a loaded module's .text section while preserving the VAD entry, relying on the section layout and protection mapping documented here
- **T-013 Remaining Injection Methods** — Module stomping, function stomping, and PE header stomping all depend on section layout knowledge including VirtualAddress, SizeOfRawData, and Characteristics fields
- **T-016 EDR Evasion Suite** — PE header stomping and NTDLL unhooking manipulate .text section bytes of loaded modules, requiring understanding of section protections and VAD preservation
- **T-007 Process Injection** — pe.rs PE parsing implementation reads section headers for section-aware injection techniques including mapping and stomping

## References

- Atlas material: atlas-exploit-dev-part17.md, atlas-exploit-dev-part21.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:pe-section-manipulation-foundations, lgtm:gap-pe-format-internals-coverage
- Public references: SEC670 Units 13, 15-16 (PE section layout, stomping foundations), Units 39-40 (IMAGE_DOS_HEADER field-by-field definition)

## Source Reference

- `dark_crystal/crates/core/src/pe.rs` — `PE::new()` constructor (section header parsing), `prepare()` method (section mapping from file to memory), `fixing_memory()` method (section Characteristics to VirtualProtect mapping)
- `dark_crystal/crowd/src/herpaderping.rs` — `parse_entry_point()` function (MZ header validation and e_lfanew → AddressOfEntryPoint traversal)
<!-- END CARD T-090 -->