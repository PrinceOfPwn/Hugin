---
id: T-075
name: Memory Forensics Tooling Awareness
category: anti-analysis
tier: A
crate: none
source_file: none
mitre: T1518.001
tags: [memory-forensics, volatility, pe-sieve, moneta, detection-awareness, vad-scanning, hash-mismatch, rwx-detection, evasion-constraint, defensive-tools]
origin: atlas-synthesis
member_notes: [lgtm:memory-forensics-tooling-coverage-gap, lgtm:memory-forensics-defense-landscape]
---

# Memory Forensics Tooling Awareness — Understanding the Defensive Memory Scanner Landscape

## Summary

SEC670 identifies three memory forensics tools that constrain every in-memory evasion technique: Volatility, PE-sieve, and Moneta. Volatility performs kernel-level analysis by locating the Directory Table Base (CR3) and walking EPROCESS, PEB module lists, VAD tree, and handle tables. PE-sieve operates in user mode by hashing the .text section of each loaded module and comparing against on-disk counterparts to detect hooks, hollowing, and stomping. Moneta scans for PAGE_EXECUTE_READWRITE memory pages with no corresponding VAD file mapping, catching unbacked executable allocations including PIC shellcode and manually mapped payloads. The operational consequence — "being in memory is not a get out of jail free card" — means T-007 injection methods and T-016 evasion techniques must account for detection by these scanners, not just by EDR kernel callbacks and user-mode hooks.

## Mechanism

1. Volatility acquires a memory image (via live acquisition tools such as winpmem, or via crash dumps) and identifies the DTB (CR3 value) for each process by scanning for the DirectoryTableBase field stored in the EPROCESS structure. It then walks the ActiveProcessLinks doubly-linked list to enumerate all processes.
2. For each process, Volatility reads the PEB (via the PEB pointer in EPROCESS at a known offset) and walks the InLoadOrderModuleList, InMemoryOrderModuleList, and InInitializationOrderModuleList to enumerate loaded DLLs. Discrepancies between these three lists reveal PEB unlinking — a module present in the VAD but absent from the PEB module lists indicates active evasion (T-016 PEB unlink).
3. Volatility walks the VAD tree rooted at the VadRoot field in EPROCESS to reconstruct the process virtual memory layout. Each VAD node (MMVAD_SHORT or MMVAD_LONG) describes a virtual address range, its protection flags (MM_PROTECT_MASK), and whether it is backed by a file (the Subsection pointer links to a ControlArea, which links to a FileObject). Unbacked executable regions are flagged for investigation.
4. Volatility dumps process handles via the HandleTable in EPROCESS, revealing open handles to other processes, tokens, sections, or threads that indicate injection or token manipulation activity.
5. PE-sieve runs in user mode (or attaches to a target process) and enumerates loaded modules via the PEB's InLoadOrderModuleList. For each module, it reads the .text section from memory and computes a hash of the in-memory bytes.
6. PE-sieve reads the corresponding on-disk file (using the module's FullDllName from the LDR_DATA_TABLE_ENTRY), locates its .text section using the PE section headers, and computes a hash of the on-disk bytes. If the in-memory hash differs from the on-disk hash, the module is flagged as modified — indicating inline hooks, module stomping, or process hollowing.
7. PE-sieve also scans for modules present in the VAD (file-backed MEM_IMAGE regions) but absent from the PEB module lists. These "unlinked" modules indicate PEB unlinking or manually mapped DLLs that were loaded outside the normal loader path.
8. Moneta operates in user mode and scans the virtual address space of a target process by calling NtQueryVirtualMemory (MemoryWorkingSetEx or MemoryBasicInformation class) for each page range. It identifies pages with PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY protection that have no file backing — the AllocationProtect and Type fields indicate MEM_PRIVATE with no associated Section object.
9. Moneta flags these unbacked executable regions as suspicious. They typically contain PIC shellcode allocated via VirtualAlloc/NtAllocateVirtualMemory, manually mapped payloads loaded through NtCreateSection + NtMapViewOfSection of a transient section (created with SEC_COMMIT and no file handle), or module-stomped code that was allocated privately rather than mapped from a legitimate file.

## OS Internals Context

The EPROCESS structure (kernel mode, size approximately 0x800 bytes on Windows 10 x64) contains VadRoot (an MM_AVL_TABLE root pointing to the VAD tree), ActiveProcessLinks (a LIST_ENTRY connecting all EPROCESS structures), ThreadListHead, and HandleTable (pointer to the EX_HANDLE_TABLE structure). Volatility's ability to walk these structures comes from having a kernel memory image — it operates at a level below EDR's user-mode hooks and does not trigger any ntdll/kernel32 API monitoring.

The VAD entries are of type MMVAD (with MMVAD_SHORT for simple allocations and MMVAD_LONG for file-backed or extended entries). Each MMVAD has a Subsection pointer that links to the CONTROL_AREA structure, which in turn links to the FILE_OBJECT — this is the chain that Volatility and Moneta follow to determine whether a memory region is backed by a file. A VirtualAlloc allocation creates a VAD entry with no Subsection (Type = MEM_PRIVATE), while NtMapViewOfSection of a file-backed section creates a VAD entry with a Subsection chain pointing to the file.

The PEB (user mode, accessible via gs:[0x60] on x64) contains the Ldr field pointing to the PEB_LDR_DATA structure. The three module lists in PEB_LDR_DATA (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList) are traversed via LDR_DATA_TABLE_ENTRY structures. When an operator unlinks a module from the PEB (T-016 PEB unlink), the module's LDR_DATA_TABLE_ENTRY is removed from all three lists, but the section mapping remains in the VAD with its file backing intact. Volatility detects this by cross-referencing VAD file-backed regions against PEB module lists.

PE-sieve's hash comparison leverages the fact that the Windows loader maps a DLL's sections into memory according to the section headers in the PE file. For a legitimate system DLL with a preferred base address (no relocations applied to .text), the in-memory .text bytes should be byte-identical to the on-disk .text bytes. Any deviation — inline hooks (jmp or call instructions patched at function prologues), module stomping (entire .text overwritten with shellcode), or process hollowing (entire image replaced) — produces a hash mismatch that PE-sieve flags.

Moneta's detection of unbacked RWX pages targets the Windows memory protection model. NtAllocateVirtualMemory creates VAD entries with Type = MEM_PRIVATE and no Subsection pointer. A region allocated as PAGE_EXECUTE_READWRITE with MEM_PRIVATE type is a strong indicator of shellcode. In contrast, NtMapViewOfSection of a file-backed section creates VAD entries with Type = MEM_IMAGE, backed by a FileObject via the Subsection → ControlArea chain. Moneta does not flag these regions, which is why mapping shellcode through a legitimate DLL section defeats Moneta's detection.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate's evasion modules (src/evasion/, src/ntdll_unhook_inject.rs, src/peb_unlink.rs, src/experimental/evasion/advanced_stack.rs) implement evasion techniques that must account for these scanners, but do not implement detection of or counter-detection against Volatility, PE-sieve, or Moneta. An implementation would consist of a pre-deployment self-scan module that enumerates the process's own VAD tree and PEB module lists, identifies unbacked RWX regions and hash-mismatched modules, and either remediates them (by converting allocations to file-backed mappings via NtMapViewOfSection of a legitimate DLL, or by restoring original .text bytes via fresh-copy unhook) or reports them as detection risks before executing payloads.

## Why It Matters

Every evasion technique in the vault operates against a dual threat model: EDR hooks and kernel callbacks (which monitor API calls and process creation), and memory forensics scanners (which perform direct memory inspection outside the EDR hook infrastructure). A technique that bypasses EDR hooks but leaves unbacked RWX pages or hash-mismatched modules is detectable by memory scanners that operate through a different detection axis. SEC670 explicitly frames this as a constraint on all in-memory operations — "being in memory is not a get out of jail free card" — making this awareness card a cross-cutting prerequisite for every injection and evasion technique in the vault.

## Detection Considerations

- **Telemetry sources**: Volatility acquires memory images via tools like winpmem (which loads a temporary kernel driver) or LiveKD; PE-sieve and Moneta run as standalone user-mode executables that query virtual memory via NtQueryVirtualMemory. These tools do not rely on ETW, kernel callbacks, or Sysmon — they perform direct memory inspection after-the-fact.
- **Bypass options**: To defeat PE-sieve, use a fresh-copy unhook (T-016) that replaces ntdll.dll .text with bytes read from the on-disk file (C:\Windows\System32
tdll.dll), making the in-memory hash match the on-disk hash. To defeat Moneta, allocate shellcode in a region backed by a file mapping — use NtCreateSection on a legitimate DLL from System32, NtMapViewOfSection to map it into the process, then overwrite the mapped content with shellcode. The VAD entry will show MEM_IMAGE with a file backing via the Subsection → ControlArea chain, and Moneta will not flag the region. To defeat Volatility's PEB cross-referencing, ensure that mapped DLLs remain in the PEB module lists (do not unlink them), since PEB unlinking creates the discrepancy that Volatility detects.
- **Residual artifacts**: Volatility's acquisition tools (winpmem driver) create a temporary device object visible in the object namespace. PE-sieve and Moneta are standalone executables that appear in the process list and can be detected by process name scanning. An implant can detect these tools by checking for their process names (pe-sieve.exe, Moneta.exe, vol.py) or by scanning for their characteristic NtQueryVirtualMemory call patterns.

## Related Techniques

- **T-007 Process Injection Suite** — Injection techniques must account for VAD-backed allocation to evade Moneta and hash-matched modules to evade PE-sieve
- **T-013 Remaining Injection Methods** — Module stomping and function stomping produce .text hash mismatches detectable by PE-sieve
- **T-016 EDR Evasion Suite** — PEB unlinking is detected by Volatility's VAD-to-PEB cross-referencing; NTDLL fresh-copy unhook defeats PE-sieve hash comparison

## References

- Atlas material: atlas-edr-evasion-part1.md (units 23, 24, 25, 32), atlas-edr-evasion-part4.md (units 1, 9)
- MITRE ATT&CK: T1518.001 — https://attack.mitre.org/techniques/T1518/001/
- LGTM notes: lgtm:memory-forensics-tooling-coverage-gap, lgtm:memory-forensics-defense-landscape
- Public references: Volatility 3 (volatilityfoundation), PE-sieve (hasherezade), Moneta (Fox-IT)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling (Volatility 3, PE-sieve by hasherezade, Moneta by Fox-IT).