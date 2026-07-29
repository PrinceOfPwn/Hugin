---
id: T-101
name: PE-sieve as Defensive Validation Scanner
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1055
tags: [pe-sieve, memory-scanner, defensive-validation, detection-heuristic, injection-detection, moneta, hollows-hunter, vad, byte-diff]
origin: atlas-synthesis
member_notes: ['lgtm:pe-sieve-and-memory-scanner-coverage-gap', 'lgtm:pe-sieve-defensive-validation']
---

# PE-sieve as Defensive Validation Scanner — Validating Injection Evasion Against Memory Forensics

## Summary

PE-sieve is an open-source memory scanner (developed by hasherezade) that detects injected code by comparing in-memory PE images against their on-disk counterparts. It walks the loaded module list via `NtQueryInformationProcess` with the `ProcessMappedInformation` class, then for each module performs a byte-diff hash over the `.text` section, checks for IAT mismatches, and detects hollowed processes by comparing PEB `Ldr` entry base addresses against actual loaded image bases. Operators should run PE-sieve with `/imp /hooks /threads` flags against their own implants during development to verify evasion claims before deployment. The scanner represents the class of free defensive tools — alongside Moneta and HollowsHunter — that operators use pre-engagement to validate injection and evasion techniques.

## Mechanism

1. PE-sieve enumerates processes using the standard Windows toolhelp (`CreateToolhelp32Snapshot` / `Process32First` / `Process32Next`) or by accepting a target PID via the `/pid` command-line flag.

2. For the target process, PE-sieve walks the loaded module list. On modern Windows, this uses `NtQueryInformationProcess` with `ProcessMappedInformation` (class 24, available on Windows 8.1+) to retrieve the full set of mapped sections including their backing file paths, commit state, and protection flags. As a fallback, it walks `PEB->Ldr->InLoadOrderModuleList` directly.

3. For each loaded module, PE-sieve performs three categories of comparison:

4. **`.text` section byte-diff**: PE-sieve reads the on-disk PE file's `.text` section (identified via `IMAGE_SCN_CNT_CODE` flag in the section header) and compares it byte-for-byte against the in-memory `.text` section at the module's base address. Any divergence is flagged as a hook, patch, or inline modification. The comparison uses a hash-based approach: both on-disk and in-memory sections are hashed with a fast non-cryptographic hash, and if the hashes differ, a full byte-diff scan identifies the exact modified regions.

5. **IAT mismatch detection**: PE-sieve parses the Import Address Table (`DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]`) from both the on-disk and in-memory copies. If the IAT entries (which contain resolved function pointers in memory but RVAs to import descriptors on disk) have been modified — for example by IAT hooking — the mismatch is reported.

6. **Hollowed process detection**: PE-sieve compares the `PEB->Ldr` entry's `DllBase` field against the actual base address of the mapped section returned by `NtQueryInformationProcess`. If the PEB says `notepad.exe` is loaded at `0x400000` but the actual mapped image is at `0x7FF70000` with different content, the process is flagged as hollowed.

7. **Unbacked executable region detection**: PE-sieve scans the process's VAD (Virtual Address Descriptor) tree for `PAGE_EXECUTE*` regions that have no backing file (no `MappedFilePath` in the `MEMORY_MAPPED_FILE_NAME` returned by `NtQueryVirtualMemory`). These regions are flagged as potential shellcode allocation sites — classic `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` injection leaves a private `MEM_COMMIT` `PAGE_EXECUTE_READWRITE` region with no file backing.

8. **Reflective DLL injection detection**: If a memory region contains valid PE headers (`MZ` / `PE\0\0` signature) but has no corresponding `PEB->Ldr` entry (the module was loaded manually, not via `LdrLoadDll`), PE-sieve flags it as a reflectively loaded DLL.

9. The report output (XML or text format) categorizes findings by severity: suspicious (modified `.text`, mismatched IAT), malicious (unbacked executable, hollowed process, floating PE headers), and informational (hooks that match known EDR patterns).

## OS Internals Context

The `NtQueryInformationProcess` function with `ProcessMappedInformation` (PROCESS_INFORMATION_CLASS value 24) returns an array of `MEMORY_MAPPED_FILE_NAME` or similar structures that describe each mapped section in the process address space. This is distinct from walking the PEB loader list (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`) because the PEB only tracks modules loaded via the legitimate loader (`LdrLoadDll` → `LdrpMapDll` → `NtMapViewOfSection`). Modules loaded via manual mapping (reflective DLL injection, module stomping, section mapping injection) do not appear in the PEB loader list.

The VAD (Virtual Address Descriptor) tree is a kernel-mode data structure maintained by the memory manager that describes every virtual address range in a process. Each VAD entry records the starting virtual address, region size, protection flags (`PAGE_EXECUTE`, `PAGE_READWRITE`, etc.), commit state (`MEM_COMMIT` vs `MEM_RESERVE`), and — for mapped sections — the backing `SectionObject` pointer. The `NtQueryVirtualMemory` function with `MemoryMappedFilenameInformation` (class 2) returns the backing file path for mapped sections. Private committed memory (allocated via `NtAllocateVirtualMemory` without a section object) has no backing file — this is the signature PE-sieve uses to detect classic shellcode injection.

The `IMAGE_LOAD_CONFIG_DIRECTORY` contains a `SecurityDirectory` field that points to a `WIN_CERTIFICATE` structure. PE-sieve reads this to determine whether the on-disk binary has an Authenticode signature and whether the in-memory signature matches.

PE-sieve's `/hooks` flag specifically scans ntdll for inline hooks by comparing the in-memory `.text` section against the on-disk copy. The `/threads` flag enumerates threads via `NtQuerySystemInformation` with `SystemProcessInformation` and checks each thread's start address against known module ranges — threads starting at unbacked addresses are flagged as potentially hijacked.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents PE-sieve as an external validation tool. The HUGIN source files `dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` and `dark_crystal/crowd/src/func_stomp.rs` reference PE-sieve in comments as a bypass target — `pe_header_stomp.rs` zeroes PE headers specifically to defeat PE-sieve's floating-PE-header detection, and `func_stomp.rs` documents that function stomping defeats PE-sieve's `.text` byte-diff because the stomped copy resides in a MEM_IMAGE region that PE-sieve expects to match its on-disk counterpart. Neither file implements PE-sieve itself; both implement techniques designed to bypass it.

## Why It Matters

The vault documents 14+ injection techniques in T-007 and T-013 and 13 EDR evasion techniques in T-016, but does not document the defensive tooling an operator should run during development to validate which techniques leave memory artifacts. PE-sieve, Moneta, and HollowsHunter form a class of free defensive scanners that operators use pre-engagement to verify evasion claims. Without running these tools, an operator cannot know whether module stomping, PE header stomping, or threadless injection actually evades memory scanning in practice. The PE-sieve command-line matrix (`/imp` for imports, `/hooks` for ntdll hook detection, `/threads` for thread start address validation) provides the specific validation surfaces operators should test against.

## Detection Considerations

- **Telemetry sources**: PE-sieve itself is a user-mode tool that uses `NtQueryInformationProcess`, `NtQueryVirtualMemory`, and `NtReadVirtualMemory` — all of which are detectable by an EDR that hooks these NT functions. Running PE-sieve in a target environment will generate process-open and memory-read events.
- **Bypass options**: Module stomping places shellcode in a MEM_IMAGE-backed region that PE-sieve expects to match its on-disk file. PE header stomping removes the `MZ` / `PE\0\0` signature so PE-sieve cannot parse the in-memory image. Function stomping overwrites only the body of a single export, and if the on-disk file has a different export body, PE-sieve's `.text` byte-diff will flag the mismatch — but if the stomped DLL is a shadow copy (module overloading), the mismatch is expected.
- **Residual artifacts**: PE-sieve generates report files (XML/text) on disk. The process itself appears in process listings. `NtReadVirtualMemory` calls to the target process are logged by EDRs that monitor cross-process memory access.

## Related Techniques

- **T-007 Pool Party and Process Injection Suite** — injection techniques that PE-sieve validates for memory artifacts
- **T-008 Threadless Injection** — export hijack technique designed to evade PE-sieve's `.text` diff by residing in MEM_IMAGE-backed memory
- **T-013 Remaining Injection Methods** — additional injection methods validated by PE-sieve including module stomping and PE header stomping
- **T-016 EDR Evasion Suite** — ntdll unhooking and PE stomping techniques validated by PE-sieve's `/hooks` flag

## References

- Atlas material: atlas-exploit-dev-part7 (unit 37), atlas-labs-part1 (unit 29)
- MITRE ATT&CK: T1055 (Process Injection) — https://attack.mitre.org/techniques/T1055
- LGTM notes: lgtm:pe-sieve-and-memory-scanner-coverage-gap, lgtm:pe-sieve-defensive-validation

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. `dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` and `dark_crystal/crowd/src/func_stomp.rs` reference PE-sieve in comments as a bypass target but do not implement the scanner itself.