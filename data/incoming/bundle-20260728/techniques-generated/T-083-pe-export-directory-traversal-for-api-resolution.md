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