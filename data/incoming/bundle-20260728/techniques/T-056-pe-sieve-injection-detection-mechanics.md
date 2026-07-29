---
id: T-056
name: PE-sieve Injection Detection Mechanics
category: discovery
tier: B
crate: none
source_file: none
mitre: T1055
mitre_secondary: [T1518.001]
tags: [pe-sieve, memory-scanner, detection, process-injection, hollowed-modules, unbacked-memory, moneta, defensive-tools, memory-forensics, evasion-planning]
origin: atlas-synthesis
member_notes: ['lgtm:pe-sieve-detection-coverage', 'lgtm:pe-sieve-detection-tool-card']
---

# PE-sieve Injection Detection Mechanics — Memory Scanner Evasion Reference

## Summary

PE-sieve is a community-driven memory scanner that detects process injection artifacts by comparing in-memory PE images against their on-disk counterparts and by scanning for unbacked executable memory regions. The tool operates by opening target process handles, walking the PEB module list, reading in-memory PE headers via `NtReadVirtualMemory`, and comparing them against the on-disk PE file to identify hollowed or stomped modules. It also enumerates all `MEM_COMMIT` pages with execute protection and checks whether each page is backed by a mapped image file, flagging `MEM_PRIVATE` executable regions as manually mapped PE images. PE-sieve and similar tools — Moneta, Hunt-Sleeping-Beacons, and hollows_hunter — represent the defender-side detection surface that operators must understand to evade when deploying injection techniques from T-007 and T-013.

## Mechanism

1. PE-sieve enumerates all running processes via `NtQuerySystemInformation(SystemProcessInformation)`, obtaining a list of PIDs and process names.

2. For each target process, PE-sieve calls `NtQueryInformationProcess(ProcessBasicInformation)` to retrieve the `PEB` address. This requires `PROCESS_QUERY_INFORMATION` (0x00010000) access on the target process handle.

3. PE-sieve reads the PEB structure via `NtReadVirtualMemory`, then follows `PEB->Ldr->InLoadOrderModuleList` to walk the loaded module list. For each `LDR_DATA_TABLE_ENTRY`, it reads the `DllBase`, `FullDllName`, and `BaseDllName` fields.

4. For each module, PE-sieve reads the in-memory PE headers starting at `DllBase`: the `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS` (including the `OptionalHeader` and the section table), and the export directory if present.

5. PE-sieve resolves the module's on-disk file path from `FullDllName` and reads the on-disk PE file. It parses the on-disk headers and section data.

6. PE-sieve compares the in-memory PE headers against the on-disk headers. If the `IMAGE_DOS_HEADER`, `IMAGE_FILE_HEADER`, `IMAGE_OPTIONAL_HEADER`, or section headers differ between the in-memory image and the on-disk file, the module is flagged as "hollowed" — indicating that the process's module has been replaced with different content.

7. PE-sieve then scans the entire virtual address space of the target process. For each virtual address range, it calls `NtQueryVirtualMemory(MemoryBasicInformation)` to retrieve the `State`, `Protect`, and `Type` fields of the `MEMORY_BASIC_INFORMATION` structure.

8. Ranges with `State == MEM_COMMIT` (0x1000) and `Protect` including `PAGE_EXECUTE` (0x10), `PAGE_EXECUTE_READ` (0x20), or `PAGE_EXECUTE_READWRITE` (0x40) are flagged as executable regions.

9. For each executable region, PE-sieve checks the `Type` field. `MEM_IMAGE` (0x1000000) indicates the region is backed by a mapped image file. `MEM_PRIVATE` (0x20000) indicates the region is allocated from the process's private pages and has no file backing.

10. `MEM_PRIVATE` executable regions are flagged as "unbacked executable memory" — a primary indicator of manually mapped shellcode or PE images. PE-sieve attempts to parse PE headers at the start of these regions to identify whether the unbacked memory contains a mapped DLL.

11. For stomped modules — where a legitimate module's `.text` section has been overwritten with different code — PE-sieve compares the in-memory `.text` section content against the on-disk `.text` section content. If the `.text` section differs but the headers match, the module is flagged as "stomped."

12. PE-sieve reports results per process, categorizing each anomaly as: hollowed module, unbacked executable region, stomped module, or impersonated module (where the PEB module name does not match the file at the resolved path).

13. Moneta operates with a similar but narrower algorithm: it focuses specifically on `MEM_PRIVATE` executable pages and RWX regions, using `NtQueryVirtualMemory(MemoryMappedFilenameInformation)` to determine whether a page is file-backed. Moneta does not perform in-memory vs on-disk PE comparison, making it faster but less comprehensive than PE-sieve for hollowed-module detection.

14. Hunt-Sleeping-Beacons takes a different approach: it enumerates threads via `NtQuerySystemInformation(SystemProcessInformation)` with `ThreadInformation` class, identifies threads in `Waiting` state (which includes threads waiting on timers — the sleep mechanism used by beacons), and checks whether each thread's `StartAddress` points into `MEM_PRIVATE` memory. A sleeping thread with a start address in unbacked memory is flagged as a potential beacon.

15. hollows_hunter is a companion tool to PE-sieve that focuses specifically on the hollowed-module detection algorithm, scanning for modules where the in-memory image differs from the on-disk file. It provides deeper analysis of the specific bytes that differ between in-memory and on-disk images.

## OS Internals Context

The `MEMORY_BASIC_INFORMATION` structure returned by `NtQueryVirtualMemory` contains the `Type` field, which distinguishes between `MEM_IMAGE` (0x1000000, backed by a mapped image section), `MEM_MAPPED` (0x40000, backed by a mapped data section), and `MEM_PRIVATE` (0x20000, allocated from the process page file with no file backing). The VAD (Virtual Address Descriptor) tree in the kernel maintains the backing-store information for each virtual address range — `MEM_IMAGE` regions have a `Subsection` pointer in their VAD entry that references the `CONTROL_AREA` and `SEGMENT` objects describing the mapped file. `MEM_PRIVATE` regions have no `Subsection` pointer.

When `NtMapViewOfSection` maps a section created from a file object, the resulting VAD entry carries the `MEM_IMAGE` or `MEM_MAPPED` type depending on the section's `AllocationAttribute` flags. `SEC_IMAGE` (0x1000000) in the section attributes produces `MEM_IMAGE` pages; `SEC_COMMIT` without `SEC_IMAGE` produces `MEM_MAPPED` or `MEM_PRIVATE` pages. This distinction is what PE-sieve and Moneta exploit: manually mapped PE images created via `NtCreateSection` with `SEC_COMMIT` and then copied into the section view without proper `SEC_IMAGE` attributes produce `MEM_PRIVATE` pages that scanners flag as anomalies.

Module stomping — where the `.text` section of a legitimate `MEM_IMAGE` module is overwritten with shellcode — produces a different detection surface. The pages remain `MEM_IMAGE` because the VAD tree is not modified, but the content of the `.text` section no longer matches the on-disk file. PE-sieve detects this by reading the in-memory `.text` section and comparing it against the on-disk `.text` section at the same RVA. The comparison uses a hash or byte-by-byte comparison of the `.text` section content.

The `LDR_DATA_TABLE_ENTRY` structure contains `HashLinks` for the `BaseDllName` hash table used by `LdrGetDllHandleByName`. When a module is unlinked from the PEB (T-016 PEB unlink), the `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList` links are removed, but the `DllBase` memory is not freed. PE-sieve can detect orphaned `MEM_IMAGE` regions — where the VAD indicates a mapped image file but the module does not appear in the PEB module list — as an indicator of PEB unlinking.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `dark_crystal/crowd` crate's `block_handle.rs` implements `NtSetSecurityObject` to apply a custom DACL that denies `PROCESS_ALL_ACCESS` (0x1FFFFF) to Everyone (S-1-1-0) and allows it only for SYSTEM (S-1-5-18). This prevents PE-sieve and similar scanners from obtaining the process handle needed to read memory, because `NtOpenProcess` returns `STATUS_ACCESS_DENIED` when the DACL denies the requested access. The security descriptor is constructed in a 256-byte raw buffer as a self-relative `SECURITY_DESCRIPTOR` with `SE_DACL_PRESENT` (0x0004) and `SE_SELF_RELATIVE` (0x8000) control flags, containing a DACL with two ACEs: `ACCESS_DENIED_ACE_TYPE` (0x01) for Everyone and `ACCESS_ALLOWED_ACE_TYPE` (0x00) for SYSTEM. This is a mitigation against PE-sieve scanning but does not implement PE-sieve's detection mechanics.

## Why It Matters

PE-sieve represents the most widely deployed community-driven memory scanner for detecting process injection artifacts. Operators who deploy techniques from T-007 (Pool Party, Threadless, Process Ghosting) and T-013 (process hollowing, module stomping, manual mapping) will encounter PE-sieve during engagements, particularly in environments where commercial EDR is supplemented by threat hunting tooling. Understanding the specific detection algorithms — header comparison for hollowing, `MEM_PRIVATE` scanning for manual mapping, `.text` section comparison for stomping, and thread start address analysis for sleeping beacons — allows operators to choose injection variants that minimize the specific indicators each tool searches for.

## Detection Considerations

- **Telemetry sources**: PE-sieve does not use ETW, kernel callbacks, or real-time monitoring. It operates as a batch scanner that opens process handles and reads memory via `NtReadVirtualMemory`. Its presence is detectable through `NtOpenProcess` calls that request `PROCESS_QUERY_INFORMATION` or `PROCESS_VM_READ` access on many processes in rapid succession, which generates Sysmon Event ID 10 (ProcessAccess) events and may trigger EDR behavioral rules for mass process access. PE-sieve's own process has a distinctive import table containing `NtReadVirtualMemory`, `NtQueryInformationProcess`, `NtQueryVirtualMemory`, and `NtQuerySystemInformation` from `ntdll.dll`.
- **Bypass options**: `block_handle.rs` (T-016) denies `PROCESS_ALL_ACCESS` to external processes via DACL modification, preventing PE-sieve from opening the target process handle. Thread pool injection (T-007 Pool Party) executes code via existing thread pool worker threads, avoiding creation of new `MEM_PRIVATE` executable regions. Module stomping with header preservation — overwriting only the `.text` section while keeping PE headers intact — avoids the hollowed-module heuristic but remains detectable via `.text` section comparison. Reflective DLL injection into `MEM_IMAGE` regions of existing modules avoids the `MEM_PRIVATE` flag. Threadless injection (T-008) avoids creating new threads, evading Hunt-Sleeping-Beacons.
- **Residual artifacts**: PE-sieve generates console output and optional JSON/XML reports listing flagged processes and anomaly types. The scanner process itself is visible in the process list with its import table. Scanning activity generates `NtReadVirtualMemory` calls visible to EDR telemetry. The `block_handle.rs` DACL modification generates Event 4670 ("Permissions on an object were changed") if SACL auditing is enabled on the target process.

## Related Techniques

- **T-007 Pool Party / Process Injection** — PE-sieve detects unbacked executable memory from manual mapping and module stomping; thread pool injection avoids creating new `MEM_PRIVATE` regions.
- **T-008 Threadless Injection** — threadless injection avoids new thread creation, evading Hunt-Sleeping-Beacons' thread start address analysis, though the hijacked export's replaced code may still be detected by `.text` section comparison.
- **T-013 Remaining Injection Methods** — process hollowing, module stomping, and manual mapping are PE-sieve's primary detection targets; each variant has a distinct detection algorithm that operators must account for.

## References

- Atlas material: atlas-recon-part6.md, atlas-edr-evasion-part6.md
- MITRE ATT&CK: T1055 — https://attack.mitre.org/techniques/T1055/
- LGTM notes: lgtm:pe-sieve-detection-coverage, lgtm:pe-sieve-detection-tool-card
- Public references: PE-sieve (hasherezade), Moneta, Hunt-Sleeping-Beacons, hollows_hunter

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.