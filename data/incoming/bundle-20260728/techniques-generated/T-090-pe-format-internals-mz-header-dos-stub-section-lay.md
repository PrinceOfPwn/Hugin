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