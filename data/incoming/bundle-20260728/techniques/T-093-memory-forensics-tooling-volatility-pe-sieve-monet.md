---
id: T-093
name: Memory Forensics Tooling Volatility PE-sieve Moneta
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1055]
tags: [memory-forensics, volatility, pe-sieve, moneta, detection-surface, fileless-execution, unbacked-memory, vad-tree, memory-scan]
origin: atlas-synthesis
member_notes: [lgtm:pe-sieve-as-detection-reference, lgtm:memory-forensics-as-fileless-counter, lgtm:memory-forensics-detection-coverage, lgtm:gap-memory-forensics-detection-coverage]
---

# Memory Forensics Tooling (Volatility, PE-sieve, Moneta) — Post-Capture Detection Surface for In-Memory Implants

## Summary

Volatility, PE-sieve, and Moneta are three open-source memory forensics tools that detect in-memory and fileless execution artifacts independent of any installed EDR product. SEC670 explicitly identifies these tools as the defensive counter to fileless execution, citing WannaCry and EternalBlue as canonical examples where memory forensics succeeded where on-disk AV failed. Each tool applies a distinct detection heuristic: Volatility performs full-process analysis of EPROCESS blocks, VAD trees, and PEB structures from a captured memory image; PE-sieve scans a live process's address space for PE images and compares in-memory headers and .text section bytes against on-disk counterparts; Moneta scans for unbacked executable memory (VirtualAlloc'd regions without file backing) and suspicious RWX permission patterns. The vault's injection and evasion cards document techniques that bypass EDR runtime monitoring (ETW-TI, kernel callbacks, userland hooks) but do not address the post-capture detection surface that these three scanners define. An operator who defeats the EDR's runtime monitoring can still be caught by a post-capture memory forensic scan performed by a defender who acquires a process memory dump or a full-system memory image.

## Mechanism

1. **Volatility** — The defender acquires a full-system memory image (via a hypervisor snapshot, a crash dump, or a tool like winpmem). Volatility parses the kernel's `EPROCESS` list to enumerate all processes, including hidden or unlinked processes that DKOM techniques may have removed from the active list. For each process, Volatility walks the VAD (Virtual Address Descriptor) tree to identify all committed memory regions and their protection flags. VAD entries with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_READ` protection that lack a corresponding `FILE_OBJECT` backing store indicate unbacked executable regions — the signature of shellcode or a manually mapped PE. Volatility also reads the PEB of each process and cross-references the `PEB->Ldr->InLoadOrderModuleList` against the VAD tree to identify modules present in memory but absent from the loader list, or modules whose on-disk file does not match the in-memory image.

2. **PE-sieve** — The defender runs PE-sieve against a live process or a process memory dump. PE-sieve enumerates all memory regions in the target process and identifies those that contain PE headers (the MZ magic at the region start). For each identified PE image, PE-sieve extracts the in-memory headers and section bytes, then locates the corresponding on-disk file (using the path from `PEB->Ldr` entries or from VAD `FILE_OBJECT` references). PE-sieve compares the in-memory `.text` section bytes against the on-disk `.text` section bytes. Mismatches indicate that the module has been patched, hollowed, or stomped. PE-sieve also flags memory regions that contain a valid PE image but have no corresponding entry in the PEB loader list — the signature of a manually mapped (reflectively loaded) DLL or shellcode that was not loaded through the standard loader. The tool classifies findings as: hollowed (in-memory image differs from on-disk), unmapped (present in memory but not in PEB loader list), or replaced (on-disk file changed since the module was loaded).

3. **Moneta** — The defender runs Moneta against a live process. Moneta scans all committed memory regions and applies a filter for executable protection flags (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`). For each executable region, Moneta checks whether the region is backed by a file on disk (via `GetMappedFileName` or `NtQueryVirtualMemory` with `MemoryMappedFileNameInformation`). Regions with executable protection that are not backed by a file are flagged as suspicious — these correspond to `VirtualAlloc` allocations used for shellcode execution or manually mapped PE images. Moneta also flags regions with `PAGE_EXECUTE_READWRITE` protection specifically, as legitimate modules typically have `PAGE_EXECUTE_READ` (write-protected after loading) rather than writable-and-executable. The tool produces a list of suspicious memory addresses, their sizes, protection flags, and backing file status.

## OS Internals Context

The VAD tree is a kernel data structure that tracks the virtual address space layout of each process. Each `MMVAD` node describes a range of virtual addresses with attributes including starting virtual address, ending virtual address, protection flags, and a pointer to the `FILE_OBJECT` for mapped files. The VAD tree is the kernel's authoritative record of what memory regions exist in a process and how they were created. Volatility reads VAD entries from the kernel's `EPROCESS->VadRoot` field in the memory image. A `VirtualAlloc`-based allocation creates a VAD entry with no `FILE_OBJECT` — the absence of a file backing store is the detection signal. A `NtCreateSection` + `NtMapViewOfSection` call with `SEC_IMAGE` creates a VAD entry with a `FILE_OBJECT` pointing to the section's backing file — this appears as a legitimate mapped module.

The PEB loader list (`PEB->Ldr->InLoadOrderModuleList`) is a doubly-linked list of `LDR_DATA_TABLE_ENTRY` structures, one per loaded module. Each entry contains the module's base address, size, full path, and timestamps. PE-sieve walks this list to build an inventory of modules that the process's loader has registered. A manually mapped PE (loaded via `RtlImageNtHeader` and manual section copying, as in the vault's reflective loader) does not appear in this list — the absence is the detection signal. Module stomping (overwriting a legitimate module's .text section) produces a PEB loader entry that matches a valid module path, but the in-memory .text bytes differ from the on-disk .text bytes — the mismatch is the detection signal.

The `MEMORY_BASIC_INFORMATION` structure (28 bytes on x64) returned by `VirtualQuery` contains `AllocationProtect`, `State`, `Protect`, and `Type` fields. The `Type` field distinguishes `MEM_IMAGE` (mapped from a section backed by a file), `MEM_MAPPED` (mapped from a section backed by the pagefile or a non-image file), and `MEM_PRIVATE` (committed via `VirtualAlloc`). Moneta uses this structure to identify `MEM_PRIVATE` regions with executable protection — the combination indicates shellcode or a manually mapped PE that was not loaded through the section object mechanism.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the defensive detection surface against which the vault's offensive techniques are measured.

The HUGIN source implements several techniques that specifically target the heuristics these tools apply. The `pe_header_stomp.rs` file in `dark_crystal/crates/core/src/experimental/` zeroes the MZ/PE headers and section table of a mapped PE image, preventing PE-sieve from locating and parsing the in-memory PE. The `ghost.rs` file in `dark_crystal/crowd/src/` creates a process backed by a `SEC_IMAGE` section, producing a VAD entry with a `FILE_OBJECT` reference that appears legitimate to Volatility's VAD analysis. The `ki_step_over.rs` file bypasses EDR inline hooks without modifying ntdll's .text section, avoiding the in-memory versus on-disk .text mismatch that PE-sieve detects. These implementations demonstrate operational awareness of the memory forensics detection surface, but the vault does not document the scanner capabilities that motivate these countermeasures.

## Why It Matters

The vault's detection narrative is weighted toward EDR runtime telemetry: ETW-TI providers, kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallback`), and userland inline hooks. These represent the real-time detection surface. Memory forensics tools represent a fundamentally different detection surface: post-capture, offline analysis that operates on a memory image or process dump after the operator's techniques have already executed. An operator who successfully bypasses all EDR runtime monitoring can still be identified by a defender who captures a memory image and runs Volatility, PE-sieve, or Moneta against it. SEC670 treats this as a first-class detection category, and the vault's evasion cards should document which scanner catches which technique by what heuristic to enable operators to select countermeasures that address both surfaces.

## Detection Considerations

- **Telemetry sources**: Volatility operates on captured memory images (hypervisor snapshots, crash dumps, winpmem captures). PE-sieve operates on live process memory or process dumps. Moneta operates on live process memory. None of these tools generate ETW events or trigger kernel callbacks — they are offline or passive scanners that the EDR does not observe.
- **Bypass options**: PE header stomping defeats PE-sieve's PE-image identification. `SEC_IMAGE` section mapping defeats Moneta's unbacked-executable heuristic. PEB loader list registration (via `LdrLoadDll` or manual list insertion) defeats PE-sieve's unmapped-module detection. Sleep-time encryption (T-005 Ekko ROP Sleep) encrypts the .text section during sleep windows, making a captured memory image during sleep show encrypted bytes that do not match any known module pattern.
- **Residual artifacts**: VAD tree entries persist for the lifetime of the process and cannot be removed without kernel-level DKOM. PEB loader list entries persist until explicitly unlinked. `MEMORY_BASIC_INFORMATION` `Type` and `Protect` fields are kernel-managed and cannot be spoofed from user mode.

## Related Techniques

- **T-007 Pool Party** — Thread pool injection creates unbacked executable regions that Moneta detects via MEMORY_BASIC_INFORMATION Type=MEM_PRIVATE with executable protection
- **T-008 Threadless** — Export hijack modifies in-memory module .text bytes, detectable by PE-sieve's module-versus-disk comparison
- **T-013 Remaining Methods** — Process hollowing and mapping injection produce artifacts detectable by Volatility VAD tree analysis and PEB loader list cross-referencing
- **T-016 EDR Evasion Suite** — NTDLL unhooking restores .text bytes from a fresh copy, but PE-sieve can detect the restoration if the tool compares against a cached hash of the original .text
- **T-020 Anti-Analysis Suite** — Anti-VM and API hammering techniques do not address post-capture memory forensic scanning
- **T-005 Ekko ROP Sleep** — ROP-based PE encryption during sleep produces temporarily encrypted .text that a Volatility memory snapshot captured during the sleep window would show as non-matching bytes

## References

- Atlas material: atlas-methodology-part9, atlas-post-exploit-part1, atlas-post-exploit-part11, atlas-post-exploit-part14
- MITRE ATT&CK: T1518.001 (https://attack.mitre.org/techniques/T1518/001)
- LGTM notes: lgtm:pe-sieve-as-detection-reference, lgtm:memory-forensics-as-fileless-counter, lgtm:memory-forensics-detection-coverage, lgtm:gap-memory-forensics-detection-coverage
- Public references: PE-sieve (hasherezade), Volatility (Volatility Foundation), Moneta (forrest-orr)

## Source Reference

No current implementation. See atlas material and public tool repositories for scanner capabilities. HUGIN source files `pe_header_stomp.rs`, `ghost.rs`, and `ki_step_over.rs` implement countermeasures against specific scanner heuristics documented in this card.