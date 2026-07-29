---
id: T-046
name: Manual PE Loader and Reflective DLL Injection (sRDI)
category: process-injection
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/pe_loader.rs
mitre: T1620
mitre_secondary: [T1055]
tags: [manual-pe-loader, reflective-loading, srdi, in-memory-execution, base-relocations, iat-resolution, tls-callbacks, peb-invisible, position-independent]
origin: atlas-synthesis
member_notes: ['lgtm:srdi-as-distinct-technique', 'lgtm:proposed-manual-pe-loader-technique-card', 'lgtm:proposed-technique-manual-pe-loading']
---

# Manual PE Loader and Reflective DLL Injection (sRDI) — In-Memory Image Execution Without the OS Loader

## Summary

A manual PE loader replicates the Windows loader's responsibilities — header validation, section mapping, base relocations, import table resolution, TLS callback execution, and entry-point dispatch — to execute a DLL or EXE directly from memory without calling LoadLibrary and without the image ever existing on disk. Reflective DLL Injection (RDI) is the DLL-specific form: the source DLL is manually mapped into the target's virtual address space so its full path is never written and the operator becomes, in the SEC670 material's phrasing, "the system loader." Shellcode Reflective DLL Injection (sRDI), credited in the material to Nick Landers (monoxgas), converts the loader itself into position-independent shellcode, which removes the requirement that the target DLL be compiled with RDI support and adds custom helpers such as GetProcAddressR. Operators use this capability to pull a PE image down over a C2 channel and execute it with no disk footprint and no entry in the PEB loader lists. The training material does not document a detection surface for the technique itself; its documented stealth properties are the absence of a file path and absence from loaded-module enumeration.

## Mechanism

1. Obtain the raw PE bytes — read from a staging buffer, downloaded over a socket, or embedded — and validate the file format: bytes at offset 0x00 must equal "MZ" (0x4D 0x5A).
2. Follow the DOS header's e_lfanew field (offset 0x3C) to the NT headers and validate the architecture: FileHeader.Machine must indicate x64 (IMAGE_FILE_MACHINE_AMD64, 0x8664). The SEC670 implementation slide lists the struct sequence as PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS64, PIMAGE_FILE_HEADER, PIMAGE_OPTIONAL_HEADER, PIMAGE_SECTION_HEADER.
3. Allocate the destination image buffer with size OptionalHeader.SizeOfImage. The RDI walk-through in the material lists a prior step of allocating a heap buffer from the file size to stage the raw bytes before mapping.
4. Copy the headers (OptionalHeader.SizeOfHeader bytes) to the destination base, then walk the section table and copy each section from PointerToRawData in the source to base+VirtualAddress in the destination, using SizeOfRawData.
5. Compute the relocation delta as (actual load base − OptionalHeader.ImageBase). If the delta is nonzero and the base relocation data directory (IMAGE_DIRECTORY_ENTRY_BASERELOC) is present, walk the IMAGE_BASE_RELOCATION blocks and apply fixups — for x64 images the dominant type is IMAGE_REL_BASED_DIR64, a 64-bit additive fixup.
6. Process the import data directory (IMAGE_DIRECTORY_ENTRY_IMPORT): for each IMAGE_IMPORT_DESCRIPTOR, load the dependency DLL and resolve every thunk — by hint/name through the dependency's export address table, or by ordinal — writing the resolved virtual address into the FirstThunk array (the IAT). The material describes this phase as "build the tables; IAT, EAT, etc."
7. Process the export directory (IMAGE_DIRECTORY_ENTRY_EXPORT) so the loaded module's own exports remain resolvable after mapping. sRDI exposes this as GetProcAddressR, a custom export-resolution helper that operates on the manually mapped image.
8. Apply per-section memory permissions derived from each section's characteristics. The material describes sRDI as "a complete PE loader supporting section permissions and TLS callbacks."
9. If the TLS directory (IMAGE_DIRECTORY_ENTRY_TLS) is present, invoke every callback in the IMAGE_TLS_DIRECTORY AddressOfCallBacks array before transferring control to the entry point.
10. Register the exception directory (.pdata RUNTIME_FUNCTION entries) so x64 structured exception handling can unwind through the mapped image — the clustering notes list the exception directory alongside relocations, imports, and TLS as OS-loader behavior the operator must replicate.
11. Dispatch to OptionalHeader.AddressOfEntryPoint. For a DLL, call DllMain with DLL_PROCESS_ATTACH ("Call DllMain and return" in the RDI walk-through); the material distinguishes DllMain versus EXE entry-point signatures, since an EXE entry expects no instance handle argument.

For the sRDI form, the loader executes first as position-independent shellcode. The material gives the on-memory layout as Bootstrap, RDI (the loader shellcode), Existing DLL (the unmodified target DLL bytes), and User-Data. The bootstrap locates the embedded DLL and transfers control to the loader shellcode, which performs steps 3 through 11 against that embedded image. Because the loader is position-independent and the target DLL is carried as raw bytes, the target DLL does not need to have been compiled with RDI support — this is the property the material identifies as sRDI's second "twist" over RDI.

## OS Internals Context

In the standard load path, LoadLibrary reaches ntdll's LdrLoadDll, the kernel creates a section object with NtCreateSection(SEC_IMAGE) backed by the file on disk, maps a view with NtMapViewOfSection, and ntdll's loader snaps the IAT, invokes TLS initializers, and inserts an LDR_DATA_TABLE_ENTRY into the three PEB loader lists — InLoadOrderModuleList, InMemoryOrderModuleList, and InInitializationOrderModuleList. A manual loader performs the user-mode half of that work itself and deliberately skips the last step: no LDR_DATA_TABLE_ENTRY is ever allocated or linked, so the module is absent from all three lists. The HUGIN T-013 card documents the consequence: the loaded module is invisible to NtQueryInformationProcess module queries and to toolhelp32 enumeration (Module32First/Module32Next).

The memory-type distinction matters at the VAD level. A legitimate DLL load produces MEM_IMAGE pages backed by a named file; a manual loader copies the image into privately allocated memory (the material's RDI walk-through allocates a heap buffer and then a SizeOfImage buffer), producing MEM_PRIVATE pages with no file backing. This is the inverse of Module Overloading (T-013), which goes through NtCreateSection(SEC_IMAGE) against a legitimate signed DLL precisely to obtain MEM_IMAGE backing. The manual loader trades that backing for total independence from the on-disk image.

The relocation format the loader must parse is a sequence of IMAGE_BASE_RELOCATION blocks, each carrying a page VirtualAddress and SizeOfBlock followed by 16-bit entries whose high nibble is the relocation type and whose low 12 bits are the offset within the page. On x64 the dominant type is IMAGE_REL_BASED_DIR64 (type 10), which adds the full 64-bit delta to the targeted qword; T-013's Vectored Overloading entry documents the same handler set (DIR64 and HIGHLOW). If the destination buffer happens to land at the PE's preferred ImageBase, the delta is zero and this phase is skipped — the "Apply Fixups if needed" phrasing in the material.

Import resolution must reproduce LdrpSnapThunk behavior: the Import Lookup Table supplies either a hint/name pair (resolved by walking the dependency's EAT — the AddressOfFunctions, AddressOfNames, and AddressOfNameOrdinals arrays) or an ordinal (IMAGE_ORDINAL_FLAG64 set), and the resulting function address is written into the IAT in place. sRDI's GetProcAddressR performs this same EAT walk against the manually mapped module itself, which is what makes the loaded DLL's exports usable without any loader-registered module handle.

Two loader contracts are frequently missed and are both flagged in the source material. First, TLS callbacks: the OS loader invokes the AddressOfCallBacks array with reason DLL_PROCESS_ATTACH before the entry point runs, and a manual loader must do the same or payloads that initialize state in TLS callbacks will malfunction. Second, the exception directory: on x64, SEH unwind metadata lives in .pdata as RUNTIME_FUNCTION entries, and without registering them (RtlAddFunctionTable in the Win32 contract) an exception raised inside the manually mapped image cannot be unwound. Position independence in the sRDI form means the loader shellcode contains no absolute virtual addresses — all data access is RIP-relative or computed from a runtime-derived base — which is what allows the combined bootstrap+loader+DLL blob to execute at any address after delivery by an arbitrary injection primitive.

## Key Implementation Details

The implementing file `dark_crystal/crowd/src/pe_loader.rs` was not included in this input set, so function-level verification of the loader internals is not possible from the provided source. Its existence and role are confirmed by three converging sources: the vault file manifest (role: "Reflective PE loader"), the T-013 card ("Full manual PE mapping: headers, sections, relocations, imports, TLS callbacks; module never appears in PEB; handles both EXE and DLL entry points"), and the call sites in the included `dark_crystal/crowd/src/chain.rs`.

What the included source does verify is the dispatch plumbing. In `chain.rs`, `InjectionMethod::ReflectivePe` is defined with the comment "Reflective PE: manual PE mapping in-process without LoadLibrary." In both `run()` and `run_with_shellcode()`, the ReflectivePe arm validates the MZ header (`payload[0] != 0x4D || payload[1] != 0x5A` returns an error reading "ReflectivePe requires PE payload (MZ header)"), installs a stack-spoof frame via `crate::stack_spoof::spoof_caller()`, and invokes `crate::pe_loader::PE::run(payload.clone())`. The `inject_fsm` path defers ReflectivePe to `run()` via its catch-all match arm. A separate `reflective_pe: bool` toggle in `ChainConfig` also routes PE payloads through `pe_loader::PE::run` in the default Auto chain, ahead of the Process Ghosting (≥35 MB) and Module Overloading fallback paths. `payload_cfg.rs` carries the auto-generated `REFLECTIVE_PE: bool` compile-time constant, and `edo_tensei.rs` maps the generation strings "reflective_pe" and "pe_loader" onto `InjectionMethod::ReflectivePe`.

No sRDI-form implementation — position-independent loader shellcode, bootstrap+user-data layout, or a GetProcAddressR helper — is verified anywhere in the included source. The HUGIN implementation is the RDI-style in-process loader: it maps a PE into the current process's address space and dispatches its entry point, matching the loader form the SEC670 material describes under "Implementation — Inside own process."

## Why It Matters

T-013 folds reflective PE loading into a single line of an eight-technique card, which undersells the surface area: the clustering notes from three independent atlas batches each argue the loader is a standalone primitive with discrete sub-capabilities (validation, mapping, relocations, IAT/EAT, TLS, exception directory, entry dispatch). It is also reusable beyond injection — SEC670 unit 31 lists "manually load an image into memory" as a last-resort capability for in-memory plugin execution and staging, and the material's stated motivation is pulling a PE over a socket and executing it with nothing on disk. Unlike Module Overloading or Module Stomping, which borrow MEM_IMAGE backing from a legitimate signed DLL, the manual loader needs no sacrificial module and never touches LoadLibrary, and unlike most injection methods it handles EXE payloads as well as DLLs. The sRDI variant additionally removes the compile-time coupling between loader and payload, which is the operational gap that justified treating it as separately documented tradecraft.

## Detection Considerations

The training material does not discuss detection for this technique. What the material documents is the technique's artifact-avoidance profile, stated from the operator side: RDI manually maps the source DLL so "the full path of the DLL will not be written," making it stealthier than path-based loading, and the loader assumes the system loader's role so LoadLibrary is never called for the payload image. The HUGIN T-013 card documents the second evasion property: the loaded module never appears in the PEB, leaving it invisible to NtQueryInformationProcess and toolhelp32 enumeration.

Residual artifacts, as documented in the material: the loaded image resides in buffers the loader allocated (a heap staging buffer sized from the file, then a destination buffer of OptionalHeader.SizeOfImage), and the raw DLL bytes persist in memory alongside the mapped copy in the sRDI layout (Bootstrap + RDI + Existing DLL + User-Data). No ETW providers, Sysmon event IDs, or memory-scan heuristics for this technique are named in the material; no operator-side bypass measures beyond the technique's inherent design are described.

## Related Techniques

- **T-013 Additional Injection Methods** — contains the one-line "Reflective PE Loader" entry this card expands; its Vectored Overloading entry is the contrasting approach, applying DIR64/HIGHLOW relocations over a SEC_IMAGE-backed signed DLL rather than into private memory.
- **T-007 Pool Party Injection** — a remote execution primitive for shellcode payloads; the manual loader is the complementary stage executed after such delivery when the staged payload is a full PE rather than raw position-independent code.

## References

- Atlas material: atlas-exploit-dev-part11.md, atlas-exploit-dev-part20.md, atlas-exploit-dev-part5.md
- MITRE ATT&CK: T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- LGTM notes: lgtm:srdi-as-distinct-technique, lgtm:proposed-manual-pe-loader-technique-card, lgtm:proposed-technique-manual-pe-loading
- Public references: Nick Landers (monoxgas), sRDI — named in atlas-exploit-dev-part11 as the author of Shellcode Reflective DLL Injection

## Source Reference

`dark_crystal/crowd/src/pe_loader.rs` — implementing file (not included in this input set; capabilities as documented in T-013). Verified call sites in included source: `dark_crystal/crowd/src/chain.rs` — `InjectionMethod::ReflectivePe` arms in `run()` and `run_with_shellcode()` calling `crate::pe_loader::PE::run(payload.clone())`, plus the `reflective_pe` toggle in `ChainConfig`; `dark_crystal/crowd/src/payload_cfg.rs` — `REFLECTIVE_PE` compile-time constant; `dark_crystal/crowd/src/edo_tensei.rs` — `parse_injection_method` mapping "reflective_pe"/"pe_loader" to `InjectionMethod::ReflectivePe`.