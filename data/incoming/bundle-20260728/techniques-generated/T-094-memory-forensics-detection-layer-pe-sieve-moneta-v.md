---
id: T-094
name: Memory Forensics Detection Layer PE-sieve Moneta Volatility
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1055]
tags: [memory-forensics, pe-sieve, moneta, volatility, vad-tree, peb-loader, unbacked-memory, detection-layer, huntress, cross-reference]
origin: atlas-synthesis
member_notes: [lgtm:memory-forensics-tooling, lgtm:convergence-pe-sieve-vs-vault-injection]
---

# Memory Forensics Detection Layer (PE-sieve, Moneta, Volatility) — Scanner Heuristics Cross-Referenced to Injection Methods

## Summary

PE-sieve (Hasherzade), Moneta (forrest-orr), and Volatility (Volatility Foundation) detect in-memory implants through distinct heuristics that target different Windows data structures and memory properties. PE-sieve walks the PEB Loader list and cross-checks each `LDR_DATA_TABLE_ENTRY` against the on-disk image via `MEMORY_BASIC_INFORMATION`, flagging modules where the `ImageBase` mismatches or the MZ/PE headers indicate shadow copies or stomped .text sections. Moneta targets unbacked `PAGE_EXECUTE_READWRITE` and `PAGE_EXECUTE_READ` regions in a generic scan that does not depend on PE header presence. Volatility performs full-memory-image analysis of `EPROCESS` blocks, VAD trees, and PEB structures to identify injected code, hollowed processes, and unbacked executable regions from a captured snapshot. The vault documents multiple injection methods that specifically aim to evade these heuristics — module stomping (T-007) produces a PEB loader entry that matches a valid module, Threadless injection (T-008) modifies export function bytes within a legitimately loaded module, and Dirty Vanity (T-011) creates a reflected process copy. The convergence between SEC670's defender-side scanner presentation and the vault's attacker-side injection coverage indicates that operators must model these specific tools as named adversaries, not merely as generic "memory scanning."

## Mechanism

1. **PE-sieve module-walk detection** — PE-sieve enumerates the target process's PEB by reading `PEB->Ldr->InLoadOrderModuleList`. For each `LDR_DATA_TABLE_ENTRY`, it extracts the `DllBase` (module base address), `SizeOfImage` (module size), and `FullDllName` (on-disk path). It then calls `VirtualQuery` on the `DllBase` to obtain a `MEMORY_BASIC_INFORMATION` structure. The `Type` field must be `MEM_IMAGE` for a legitimately loaded module. If `Type` is `MEM_PRIVATE`, the region was allocated via `VirtualAlloc` and manually populated — the signature of a reflectively loaded DLL that was inserted into the PEB loader list without a corresponding section object. PE-sieve then reads the in-memory PE headers at `DllBase`, extracts the `.text` section RVA and size from the `IMAGE_SECTION_HEADER`, and reads the on-disk `.text` bytes from `FullDllName`. A byte-by-byte comparison of in-memory `.text` against on-disk `.text` reveals module stomping (the .text was overwritten with different code) or hooking (individual bytes patched for inline hooks).

2. **PE-sieve unbacked-region detection** — PE-sieve scans all committed memory regions in the process via `VirtualQuery` walks. For each region with executable protection (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`), PE-sieve checks whether the region contains a valid MZ header. If a valid PE image is found in a region that is not listed in the PEB loader list, PE-sieve flags it as an unmapped module — the signature of a manually mapped PE or large shellcode block that was not registered with the loader.

3. **Moneta unbacked-executable scan** — Moneta walks the process's virtual address space via `VirtualQuery`. For each committed region, it checks the `Protect` field for executable flags and the `Type` field for backing status. Regions with `Type == MEM_PRIVATE` and executable protection are flagged as suspicious — these correspond to `VirtualAlloc` allocations used for shellcode. Regions with `Type == MEM_IMAGE` and `PAGE_EXECUTE_READWRITE` protection are flagged as anomalous — legitimate modules are typically `PAGE_EXECUTE_READ` after the loader applies write-protect. Moneta does not require a valid PE header to flag a region, making it effective against headerless shellcode and PE-header-stomped images.

4. **Volatility VAD tree analysis** — Volatility reads the `EPROCESS->VadRoot` field from the kernel's process record in the memory image. Each `MMVAD` node describes a virtual address range with `StartingVa`, `EndingVa`, protection flags (`u.VadFlags.Protection`), and a `Subsection` pointer to the `FILE_OBJECT` for file-backed mappings. Volatility flags VAD nodes with `PAGE_EXECUTE_READWRITE` protection and no `Subsection` (no `FILE_OBJECT`) as unbacked executable regions. It also cross-references the VAD tree against the PEB loader list to identify modules present in the VAD but absent from the loader list, or modules whose VAD protection flags indicate `PAGE_EXECUTE_READWRITE` when they should be `PAGE_EXECUTE_READ`.

## OS Internals Context

The PEB Loader list is anchored at `PEB->Ldr->InLoadOrderModuleList`, a `LIST_ENTRY` doubly-linked list. Each node is a `LDR_DATA_TABLE_ENTRY` (also accessible via `InMemoryOrderModuleList` and `InInitializationOrderModuleList` in the same structure). The `LDR_DATA_TABLE_ENTRY` on x64 contains `InLoadOrderLinks` (16 bytes), `InMemoryOrderLinks` (16 bytes), `InInitializationOrderLinks` (16 bytes), `DllBase` (8 bytes), `EntryPoint` (8 bytes), `SizeOfImage` (4 bytes + 4 padding), `FullDllName` (16 bytes, UNICODE_STRING), `BaseDllName` (16 bytes, UNICODE_STRING), followed by flags, load count, and timestamp fields. The total structure size is approximately 0x98 bytes on x64.

When a module is loaded via `LdrLoadDll`, the loader creates a section object (`NtCreateSection` with `SEC_IMAGE`), maps it via `NtMapViewOfSection`, and inserts a `LDR_DATA_TABLE_ENTRY` into all three loader lists. The VAD entry for the mapped region has `Type == MEM_IMAGE` and the `Subsection` pointer references the `FILE_OBJECT` for the DLL file. A manually mapped PE that calls `VirtualAlloc` and copies sections manually creates a `MEM_PRIVATE` VAD entry with no `Subsection` — the absence is what Moneta and Volatility detect. A manually mapped PE that uses `NtCreateSection` + `NtMapViewOfSection` with `SEC_IMAGE` creates a `MEM_IMAGE` VAD entry with a `Subsection`, but the PEB loader list does not contain an entry for it — PE-sieve detects this as an unmapped module.

Module stomping (T-007) overwrites the `.text` section of a legitimately loaded module. The VAD entry remains `MEM_IMAGE` with a valid `Subsection`, and the PEB loader list contains the entry. PE-sieve's in-memory versus on-disk `.text` comparison detects the byte mismatch. The countermeasure is PE header stomping (zeroing the MZ/PE headers), which prevents PE-sieve from locating the `.text` section RVA — but Moneta still flags the region as `PAGE_EXECUTE_READWRITE` if the protection was not reset to `PAGE_EXECUTE_READ` after writing.

Threadless injection (T-008) modifies bytes within an export function of a loaded module. The modified bytes are within the module's `.text` section. PE-sieve's `.text` comparison detects the mismatch if the modified bytes fall within the `.text` section range. The countermeasure in Threadless is that the modification is small (a trampoline jump) and the original bytes are restored after execution — but during the execution window, the `.text` mismatch is detectable.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the defensive detection layer against which the vault's injection methods are measured.

The HUGIN source implements countermeasures against specific scanner heuristics. The `pe_header_stomp.rs` file in `dark_crystal/crates/core/src/experimental/` zeroes the PE headers (MZ magic, DOS stub, NT headers, section table) of a mapped image, preventing PE-sieve from extracting the `.text` section RVA. The function `stomp_own_pe_header` reads the `SizeOfHeaders` field from the `IMAGE_OPTIONAL_HEADER` and zeroes that many bytes from the image base. The `stomp_self_header` function uses `gs:[0x60]` to locate the PEB, reads `PEB->ImageBaseAddress` at offset 0x10, calls `VirtualProtect` to make the header region writable, then zeroes it. This defeats PE-sieve's header-based identification but does not defeat Moneta's executable-protection-based scan.

The `ghost.rs` file in `dark_crystal/crowd/src/` implements Process Ghosting, which creates a process backed by a `SEC_IMAGE` section. The resulting VAD entry has `Type == MEM_IMAGE` and a valid `Subsection` pointer, making it appear as a legitimately loaded module to Volatility's VAD analysis. The file was delete-pending before the payload was written, so the on-disk file does not exist for PE-sieve to compare against — but PE-sieve can still flag the module as anomalous if it has no corresponding `FILE_OBJECT` at scan time.

## Why It Matters

The vault documents injection methods that specifically target the unbacked-executable heuristic. Module stomping (T-007) produces a PEB loader entry backed by `MEM_IMAGE`. Threadless injection (T-008) modifies bytes within an existing module's `.text`. Dirty Vanity (T-011) creates a reflected process copy. These techniques are designed against specific scanner heuristics, but the vault does not document which scanner catches which technique by what mechanism. This card provides the cross-reference that enables operators to select injection methods based on the expected forensic tooling on the target, not merely on the EDR product.

## Detection Considerations

- **Telemetry sources**: PE-sieve operates on live process memory or dumps. Moneta operates on live process memory. Volatility operates on full-system memory images. None generate ETW events. Huntress Labs deploys PE-sieve-based scanning at scale across endpoints, making it a realistic adversary on Huntress-managed targets.
- **Bypass options**: PE header stomping defeats PE-sieve's header-based identification. `SEC_IMAGE` section mapping defeats Moneta's unbacked-executable heuristic. PEB loader list registration defeats PE-sieve's unmapped-module detection. `.text` byte restoration after execution defeats PE-sieve's in-memory versus on-disk comparison (used by Threadless injection's self-restoring trampoline).
- **Residual artifacts**: VAD tree entries are kernel-managed and persist for process lifetime. PEB loader list entries persist until unlinked. `MEMORY_BASIC_INFORMATION` fields (`Type`, `Protect`) are kernel-managed and cannot be spoofed from user mode. A memory image captured during a sleep window (when Ekko ROP Sleep has encrypted `.text`) shows non-matching bytes, but a capture during the active window shows the decrypted `.text`.

## Related Techniques

- **T-007 Pool Party** — Thread pool injection creates unbacked executable regions that PE-sieve flags via MEMORY_BASIC_INFORMATION Type=MEM_PRIVATE with executable protection
- **T-008 Threadless** — Export function byte modification within a loaded module is detectable by PE-sieve's in-memory versus on-disk .text comparison during the execution window
- **T-011 Dirty Vanity** — Process reflection via RtlCreateProcessReflection creates a cloned process whose memory state Volatility can diff against the parent to identify reflected implants
- **T-013 Remaining Methods** — Module stomping and mapping injection produce artifacts that PE-sieve detects via PEB->Ldr->InLoadOrderModuleList cross-referencing and .text byte comparison
- **T-016 EDR Evasion Suite** — NTDLL unhooking restores .text bytes from a fresh copy, but PE-sieve can detect the restoration if the tool maintains a baseline hash of the original .text
- **T-003 VEH Syscall Gate** — VEH-based syscall dispatch does not create unbacked executable memory, reducing Moneta's detection surface relative to VirtualAlloc-based stub methods

## References

- Atlas material: atlas-post-exploit-part5, atlas-recon-part2
- MITRE ATT&CK: T1518.001 (https://attack.mitre.org/techniques/T1518/001)
- LGTM notes: lgtm:memory-forensics-tooling, lgtm:convergence-pe-sieve-vs-vault-injection
- Public references: PE-sieve (hasherezade), Moneta (forrest-orr), Volatility (Volatility Foundation), Huntress Labs

## Source Reference

No current implementation. See atlas material and public tool repositories. HUGIN source files `dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` and `dark_crystal/crowd/src/ghost.rs` implement countermeasures against specific scanner heuristics documented in this card.