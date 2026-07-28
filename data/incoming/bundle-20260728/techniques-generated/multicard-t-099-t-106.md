<!-- BEGIN CARD T-099 -->
---
id: T-099
name: Disk Artifact Placement and DRM Protection
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1027
mitre_secondary: [T1036]
tags: [disk-artifact, placement-tradecraft, drm-protection, artifact-protection, opsec, pe-protection, binary-spoofing, drop-location]
origin: atlas-synthesis
member_notes: ['lgtm:disk-placement-tradecraft', 'lgtm:implant-drm-protection']
---

# Disk Artifact Placement and DRM Protection Tradecraft — Strategic On-Disk Binary Hardening

## Summary

Strategic on-disk artifact placement and DRM-based integrity protection form a two-part discipline for managing risk when persistence-dropped or stage-downloaded binaries must reside on disk. Placement heuristics govern which directory — Desktop, Documents, Downloads, Pictures, Temp, AppData, Program Files, SysWOW64, System32, OneDrive — minimizes detection attention by blending with legitimate file noise, while DRM techniques (IPRIP-protected PE structures, self-signed code signing, PIMAGE_LOAD_CONFIG_DIRECTORY integrity check entries) prevent static analysis and signature matching by AV engines. The primary detection surface is filesystem monitoring via Sysmon FileCreate events and on-access AV scanning of new files in high-scrutiny directories. Together these techniques address the operational gap between T-017's persistence mechanisms that create disk-resident artifacts and T-020's anti-analysis capabilities that do not cover placement strategy.

## Mechanism

1. The operator selects a drop directory based on the target environment's file noise profile. Each location carries distinct risk and signal characteristics that determine its suitability:

2. **User-profile directories (Desktop, Documents, Downloads, Pictures)** — user-writable without elevation, common for legitimate application drops. However, EDR file-create rules commonly flag executable files (.exe, .dll, .sys) appearing in user-profile paths. Downloads is subject to Mark of the Web (MOTW) enforcement on Windows 10+, which applies SmartScreen, AppLocker, and Attack Surface Reduction (ASR) restrictions to browser-downloaded binaries. Files placed via non-browser channels (direct file write, SMB copy) do not receive a MOTW alternate data stream unless explicitly applied.

3. **Temp (%TEMP%)** — high file churn provides blending, but EDRs commonly flag executable drops in Temp as a heuristic. The directory is cleaned by Storage Sense and Disk Cleanup on schedules, making it unreliable for long-term persistence.

4. **AppData (Local/Roaming)** — large directory trees with hundreds of legitimate application subfolders. Executable noise is high — Discord, Microsoft Teams, Chrome updater, VS Code update services all drop executables here. Blending is strong because EDRs cannot practically alert on every executable in AppData without generating excessive false positives.

5. **Program Files / Program Files (x86)** — requires elevation to write. Executables here are expected to be signed and installed via MSI or package managers. Unsigned or non-installed binaries stand out against the signed baseline. EDRs that enforce code integrity for Program Files will flag unsigned executables.

6. **SysWOW64 / System32** — highest AV scrutiny. Any non-Microsoft-signed binary in System32 is immediately flagged by most EDR products. Placement here requires either signed binary proxying, DLL stomping, or an already-present legitimate binary to overwrite. The detection cost is near-certain; the blending benefit is zero unless the binary is renamed to match a known system component.

7. **OneDrive** — if OneDrive sync is active, files placed in a synced folder are automatically uploaded to the user's Microsoft account cloud storage. This creates an unintended exfiltration channel: the implant binary leaves cloud-side forensic artifacts accessible via Microsoft Graph API, and the binary may sync to other devices the user is signed into. The operational risk of OneDrive placement is bidirectional — it can exfiltrate the implant off-host but also introduces cloud-side detection surfaces.

8. The operator applies the "not first, not last" heuristic: the dropped binary should not be the newest or oldest file in the directory listing. Timeline analysis tools (KAPE, Velociraptor, KAPE) sort by creation timestamp and flag temporal outliers. The binary's creation timestamp should fall within the existing cluster of neighboring files.

9. When drop-to-disk is unavoidable and the binary will be scanned by AV signatures, the operator applies DRM-based integrity protection. The Skrull PoC implant demonstrates three approaches:

10. **IPRIP-protected PE**: Windows DRM infrastructure includes support for marking PE files as IPRIP (Intellectual Property Rights Information Protection) protected. The PE binary's `IMAGE_LOAD_CONFIG_DIRECTORY` is populated with integrity check entries declaring a protected code section. AV engines that respect these integrity annotations defer or skip static analysis of the protected sections to avoid violating DRM constraints.

11. **Self-signed code signing**: The operator generates a self-signed code-signing certificate, installs it in the local machine's Trusted Root Certification Authorities or Trusted Publishers certificate store, and signs the dropped binary using `signtool sign` or the programmatic `SignerSignEx` API. The binary appears signed in Windows Explorer file properties and passes basic `WinVerifyTrust` signature presence checks, though it fails chain validation on systems where the self-signed root is not installed.

12. **PIMAGE_LOAD_CONFIG_DIRECTORY integrity fields**: The load config directory (DataDirectory index 10 in the PE optional header) contains fields including `SecurityDirectory` (RVA and size of a `WIN_CERTIFICATE` structure embedded in the PE file). By crafting these fields with valid-looking but non-standard values, the operator creates a PE that claims to have integrity protections, causing some scanners to treat the binary as protected content and skip deep analysis.

## OS Internals Context

The `IMAGE_LOAD_CONFIG_DIRECTORY` (32-bit: `IMAGE_LOAD_CONFIG_DIRECTORY32`, 64-bit: `IMAGE_LOAD_CONFIG_DIRECTORY64`) is defined in `winnt.h` and loaded by the Windows PE loader when the `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` (index 10) data directory entry in the optional header is non-zero. The structure contains fields for Control Flow Guard (`GuardCFCheckFunctionPointer`, `GuardCFDispatchFunctionPointer`, `GuardCFFunctionTable`, `GuardCFFunctionCount`), SafeSEH (`SEHandlerTable`, `SEHandlerCount` for 32-bit), and security-related cookie initialization (`SecurityCookie`). The `SecurityDirectory` field points to a `WIN_CERTIFICATE` structure embedded at the end of the PE file, which contains the Authenticode signature blob when the binary is signed.

The Mark of the Web is implemented as an NTFS Alternate Data Stream named `Zone.Identifier` attached to the downloaded file. The stream contains INI-formatted text with a `ZoneId` value: 1 (Local Intranet), 2 (Trusted Sites), 3 (Internet), 4 (Restricted Sites). When the shell or the kernel encounters a file with `ZoneId=3` or `ZoneId=4` and the user attempts execution, Windows invokes SmartScreen reputation checking, AppLocker policy evaluation, and ASR rule processing. The `Zone.Identifier` ADS is applied by Zone-aware applications (Internet Explorer, Edge, Chrome, Outlook, Explorer via SMB copy) through the `IAttachmentExecute` COM interface, which calls `IAttachmentExecute::Save()` internally. Files created via `CreateFile` / `NtCreateFile` directly do not receive a `Zone.Identifier` ADS.

The Windows Media DRM (IPRIP) infrastructure uses the `WMDRM` (Windows Media Digital Rights Management) subsystem, which is implemented in `drmv2clt.dll`, `drmv2prot.dll`, and kernel-mode components. The PE-level protection annotations that the Skrull implant leverages are part of the binary's load config directory and the `WIN_CERTIFICATE` structure, which the Windows loader processes during `LdrpMapDllNtFileName` → `LdrpMapViewOfSection`. Some AV products that check for DRM-protected content read the load config directory and skip scanning of sections marked as protected to avoid interfering with DRM enforcement.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would need three components. First, a directory selection function that queries `SHGetKnownFolderPath` for `FOLDERID_Desktop`, `FOLDERID_Documents`, `FOLDERID_Downloads`, `FOLDERID_LocalAppData`, and `FOLDERID_RoamingAppData`, then enumerates existing files via `FindFirstFileW` / `FindNextFileW` to calculate timestamp distributions and select a path where the dropped binary's creation time blends with the existing cluster. Second, a PE post-processing function that parses the target PE's `IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS` → `IMAGE_OPTIONAL_HEADER` → `DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]`, validates the `IMAGE_LOAD_CONFIG_DIRECTORY` structure, and populates `SecurityDirectory` and integrity-related fields with crafted values. Third, a MOTW stripping function that deletes the `Zone.Identifier` ADS via `DeleteFileW` with the path `filename:Zone.Identifier:$DATA` or via `NtDeleteFile` on the ADS path.

## Why It Matters

T-017 documents persistence mechanisms that drop binaries to disk (COM hijack proxy DLL, NTFS EA payload, schtask-triggered binary) and T-020 covers self-deletion and IAT camouflage, but neither card addresses the operational decision of where to place the dropped artifact or how to harden it against on-access scanning. This gap leaves operators without guidance on directory selection risk profiles or binary integrity protection options when disk-resident persistence is unavoidable. The placement heuristics and DRM techniques documented here close that gap, providing the tradecraft layer that makes disk-based persistence survivable in environments with active AV and EDR scanning.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 11 (FileCreate) and Event ID 15 (FileCreateStreamHash) capture file creation including full path and first hash of file content. Sysmon Event ID 7 (ImageLoad) captures module loads. NTFS USN Journal records all file creation events at the volume level and is queryable via `FSCTL_READ_USN_JOURNAL`. EDR products with on-access scanning intercept `NtCreateFile` / `NtOpenFile` with `FILE_EXECUTE` access. Windows Defender's real-time protection scans new files on write via its mini-filter driver.
- **Bypass options**: Place the binary in a directory with high legitimate executable churn (AppData\Local subdirectories) to blend file-create events. Use a filename matching the directory's naming convention (e.g., `update.exe` in a subfolder named after a known application). Strip the `Zone.Identifier` ADS to avoid SmartScreen and ASR evaluation. Apply self-signed code signing to pass basic signature presence checks. Populate `IMAGE_LOAD_CONFIG_DIRECTORY` integrity fields to defer scanners that respect protected content annotations.
- **Residual artifacts**: The dropped binary on disk. Self-signed certificate in the Trusted Root or Trusted Publishers certificate store if installed. NTFS creation timestamps that may not align with neighboring files despite blending efforts. OneDrive sync logs and cloud-side copies if placed in a synced folder. USN Journal entries persisting past file deletion.

## Related Techniques

- **T-017 Five-Layer Persistence** — persistence mechanisms that create disk-resident artifacts requiring placement strategy
- **T-020 Anti-Analysis Suite** — self-deletion and IAT camouflage for reducing on-disk forensic footprint
- **T-039 On-Disk Binary Patching** — binary patching for persistence that benefits from placement heuristics

## References

- Atlas material: atlas-post-exploit-part5 (units 15, 16, 23, 24, 26, 27)
- MITRE ATT&CK: T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027
- LGTM notes: lgtm:disk-placement-tradecraft, lgtm:implant-drm-protection

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-099 -->

<!-- BEGIN CARD T-100 -->
---
id: T-100
name: Inline Hook Byte-Pattern Forensics and Hot-Patch
category: edr-evasion
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/hells_gate.rs
mitre: T1055
tags: [inline-hook, byte-pattern, forensics, hot-patch, mov-edi-edi, hook-detection, unhooking, x86, x64, ntdll]
origin: atlas-synthesis
member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']
---

# Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue — Recognizing EDR Hook Signatures Before Unhooking

## Summary

Inline hook byte-pattern forensics is the discipline of recognizing the exact byte sequences EDR products write into ntdll syscall stubs when installing inline hooks, enabling an operator to enumerate which functions are hooked before deciding what to unhook. On x64, EDRs typically install a 15-byte trampoline consisting of `MOV rax, imm64` (`48 B8` followed by an 8-byte absolute address) and `JMP rax` (`FF E0`), using RAX as the intermediate register because x64 lacks a direct 8-byte immediate JMP instruction. On x86 (Wow64), EDRs exploit the `MOV EDI, EDI` hot-patch prologue and the five-NOP padding that precedes 32-bit exported functions: the 2-byte hot-patch slot is overwritten with a 2-byte short jump back into the 5-NOP pad, and the pad itself is patched with a 5-byte `JMP rel32` into the trampoline. The detection surface is minimal — reading ntdll stub bytes is a local memory read that does not trigger ETW or kernel callbacks.

## Mechanism

1. The operator enumerates all `Nt*` exports from ntdll by walking the PE export directory. The export directory is located via `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` in the optional header. `AddressOfNames`, `AddressOfNameOrdinals`, and `AddressOfFunctions` arrays provide name-to-address mapping.

2. For each `Nt*` export, the operator reads the first bytes of the stub to classify it as clean or hooked:

3. **64-bit clean stub detection**: A clean 64-bit syscall stub begins with the canonical 8-byte sequence `4C 8B D1 B8 XX XX 00 00` — `MOV r10, rcx` (`4C 8B D1`) followed by `MOV eax, imm32` (`B8` + 4-byte SSN). The high 2 bytes of the SSN immediate are `00 00` because syscall numbers are always less than 0x10000.

4. **64-bit hook detection**: If the first byte is `0xE9` (`JMP rel32`), the stub has been hooked with a 5-byte relative jump. Some EDRs use a 15-byte absolute trampoline instead: `MOV rax, <8-byte-address>` (`48 B8` + 8 bytes) followed by `JMP rax` (`FF E0`). The operator checks for the `48 B8` prefix to identify this hook variant. RAX is the intermediate register because x64 has no `JMP imm64` instruction — the architecture cannot encode an 8-byte immediate in a JMP opcode. The closest alternative, `JMP [rip+0]` (`FF 25 00 00 00 00`), is 6 bytes but requires a memory dereference and is less commonly used by EDRs.

5. **32-bit clean stub detection (Wow64)**: A clean 32-bit syscall stub begins with `MOV EDI, EDI` (`8B FF`), a 2-byte NOP-equivalent instruction that Microsoft placed at the start of all 32-bit exported functions as a hot-patch slot. This is followed by the function body. The 5 bytes preceding the function entry point (in the preceding function's padding or in inter-function alignment) are filled with `CC CC CC CC CC` (five INT 3 / NOP-equivalent padding bytes).

6. **32-bit hook detection (Wow64)**: The EDR overwrites the 2-byte hot-patch slot (`MOV EDI, EDI` at bytes [0..2]) with a 2-byte short jump (`EB FC` or similar) that jumps backward into the 5-byte NOP pad preceding the function. The EDR then overwrites the 5-NOP pad with a 5-byte `JMP rel32` (`E9` + 4-byte relative offset) that jumps into the EDR's trampoline. This technique preserves the original function body — only the hot-patch slot and preceding pad are modified — which means unhooking requires restoring both the 5-NOP pad and the `MOV EDI, EDI` prologue. Restoring only one leaves the function in a corrupted state.

7. The operator catalogs each hooked function, the hook variant (5-byte JMP, 15-byte absolute trampoline, or 32-bit hot-patch hijack), and the original bytes that must be restored during unhooking.

8. Before unhooking, the operator validates that the hook is an EDR hook and not a legitimate Microsoft patch (e.g., CVE hot-patches). Microsoft hot-patches use a different mechanism and should not be reverted.

## OS Internals Context

The `MOV EDI, EDI` hot-patch prologue is a design decision from the Windows XP SP2 / Windows Server 2003 SP1 era. Microsoft instructed compiler teams to insert a 2-byte `MOV EDI, EDI` instruction at the start of every exported function and pad 5 bytes before the function with `CC` (INT 3) instructions. This creates a 7-byte patch zone: the 5-byte pad can hold a `JMP rel32` instruction, and the 2-byte `MOV EDI, EDI` can be patched to a 2-byte short jump (`EB FC`) that jumps backward into the pad. This allows runtime patching of a function's execution flow without modifying the function body itself — the original instructions remain intact, and the patch can be atomically applied or reverted by swapping 2 bytes at the function entry.

On x64, the hot-patch prologue was abandoned because the 15-byte trampoline (`MOV rax, imm64; JMP rax`) is too large to fit in a hot-patch zone, and the architecture's RIP-relative addressing makes relative jumps more practical. EDRs on x64 typically overwrite the first 5 bytes of the stub with a `JMP rel32` or use a 14-byte `MOV rax, imm64; JMP rax` trampoline that overwrites the entire prologue.

The ntdll syscall stub layout on x64 is: `MOV r10, rcx` (2 bytes, `4C 8B D1`) — moves the Win32 API parameter from RCX to R10 because the syscall instruction uses RCX for the return address in the kernel. Then `MOV eax, imm32` (5 bytes, `B8 XX XX 00 00`) — loads the syscall service number (SSN) into EAX. Then `syscall` (2 bytes, `0F 05`) — transitions to kernel mode. Then `ret` (1 byte, `C3`). Total: 10 bytes minimum. SSN assignment is sequential by RVA order of the `Nt*` exports, which the Hell's Gate / Halo's Gate / Tartarus Gate SSN resolution cascade exploits.

## Key Implementation Details

The HUGIN source file `dark_crystal/crowd/src/hells_gate.rs` implements a simplified form of byte-pattern forensics for hook detection. Two functions are relevant:

- **`is_hooked(addr: *const u8) -> bool`**: Checks if the first byte at `addr` is `0xE9` (`JMP_REL32`). This is a single-byte check that detects the 5-byte relative jump hook variant on x64 but does not detect the 15-byte `MOV rax, imm64; JMP rax` trampoline variant (which begins with `48 B8`, not `E9`).

- **`read_ssn_from_stub(addr: *const u8) -> Option<u16>`**: Checks for the clean 64-bit stub prefix `4C 8B D1 B8` (`CLEAN_STUB_PREFIX`) and verifies the high 2 bytes of the SSN immediate are `00 00`. Returns `None` if the stub does not match, indicating a hook is present. This function implements the clean-stub recognition half of the forensics but does not classify the hook variant.

The implementation does not cover 32-bit (Wow64) hook detection. All functions in `hells_gate.rs` are gated on `#[cfg(target_arch = "x86_64")]` — the 32-bit variants return null or empty results. The `MOV EDI, EDI` hot-patch prologue, 5-NOP pad inspection, and 2-byte short jump detection are not implemented. An operator needing full 32-bit forensics would need to add a parallel implementation that checks the `8B FF` prologue and scans the preceding 5 bytes for a `JMP rel32` opcode.

## Why It Matters

T-016 documents the ntdll unhook operation but is implicitly x64-centric and does not document the byte-pattern fingerprints that identify hooked stubs before unhooking. This pre-unhook enumeration step has operational value: an operator who knows exactly which functions an EDR has hooked can selectively unhook only the functions needed for the current operation, reducing the detection surface of the unhook itself. The 32-bit hot-patch prologue protocol is critical because unhooking on Wow64 requires restoring both the 5-NOP pad and the `MOV EDI, EDI` prologue — restoring only one leaves the function corrupted and will cause crashes when the function is called.

## Detection Considerations

- **Telemetry sources**: Reading ntdll stub bytes is a local memory read via the process's own virtual address space. It does not trigger `NtReadVirtualMemory` (which is a cross-process API) or any ETW-TI event. No kernel callback fires for reading memory within the same process. Memory-scan heuristics that compare in-memory ntdll bytes against on-disk ntdll (e.g., PE-sieve's `.text` section diff) detect the hooks themselves, not the act of reading them.
- **Bypass options**: The byte-pattern read is inherently stealthy. The operator should avoid using `NtReadVirtualMemory` or `VirtualQuery` for the read — direct pointer dereference (`*(addr as *const u8)`) is sufficient and generates no system call.
- **Residual artifacts**: None from the forensics step itself. The subsequent unhooking operation (restoring original bytes) modifies ntdll `.text` section, which is detectable by PE-sieve, Moneta, and HollowsHunter via disk-versus-memory byte comparison.

## Related Techniques

- **T-016 EDR Evasion Suite** — ntdll unhook operation that this forensics step precedes; unhooking restores original bytes identified by these patterns
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution cascade that uses `is_hooked` and `read_ssn_from_stub` to detect and bypass hooked stubs

## References

- Atlas material: atlas-edr-evasion-part3 (units 1, 2, 3), atlas-edr-evasion-part2 (units 39, 40)
- MITRE ATT&CK: T1055 (Process Injection) — https://attack.mitre.org/techniques/T1055
- LGTM notes: lgtm:inline-hook-byte-forensics, lgtm:32-bit-hot-patch-prologue-coverage

## Source Reference

`dark_crystal/crowd/src/hells_gate.rs` — `is_hooked()` (line ~120) and `read_ssn_from_stub()` (line ~130) implement simplified 64-bit-only hook detection via byte-pattern checks. 32-bit hot-patch prologue forensics is not implemented.
<!-- END CARD T-100 -->

<!-- BEGIN CARD T-101 -->
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
<!-- END CARD T-101 -->

<!-- BEGIN CARD T-102 -->
---
id: T-102
name: Position-Independent C Shellcode Build Pipeline
category: exploit-primitive
tier: A
crate: none
source_file: none
mitre: T1027
tags: [shellcode, pic, position-independent, build-config, visual-studio, crt-free, intrinsics, compiler-settings, no-entry-point]
origin: atlas-synthesis
member_notes: ['lgtm:pic-shellcode-build-config-coverage', 'lgtm:pic-c-shellcode-build-pipeline', 'lgtm:pic-c-shellcode-tradecraft', 'lgtm:gap-shellcode-position-independence-discipline']
---

# Position-Independent C Shellcode Build Pipeline and Discipline — Producing Raw PIC Bytes from C Source

## Summary

Position-independent C shellcode is produced by compiling standard C source code with a specific Visual Studio linker and compiler configuration that strips all CRT dependencies, fixed entry points, and absolute address references, yielding a raw blob of position-independent machine code. The build pipeline requires `/GS-` (no stack canary), `/NODEFAULTLIB` (no CRT linkage), `/SUBSYSTEM:NATIVE` (no Windows subsystem binding), `/NOENTRY` (no default entry), a custom `/ENTRY:` specification, `/SDL-` (no security checks), and `/MT` (static CRT, which is then excluded by `/NODEFAULTLIB`). The authoring discipline mandates avoiding the heap (no `malloc`/`new`), avoiding external references (no imports resolved by the loader), and avoiding the `.data`/`.rdata` sections (using stack-allocated constants or runtime-resolved strings instead). Compiler intrinsics (`__readgsqword`, `__readmsr`, `#pragma intrinsic` for `memset`/`strcmp`/`__movsb`) replace their CRT-wrapped equivalents.

## Mechanism

1. The operator creates a C source file with a custom entry point function. The entry point is specified via the `/ENTRY:function_name` linker flag. The function signature is `void entry(void)` — no parameters, no return value. The function must not return to the caller (it should call `ExitProcess` or terminate via a `jmp` to a known address).

2. The build configuration is set in Visual Studio project properties or directly in the `cl.exe` / `link.exe` command line:

3. **`/GS-`**: Disables the `/GS` buffer security check. The `/GS` flag inserts a stack canary (`__security_cookie`) check at function entry and exit. When enabled, the compiler generates a call to `__security_init_cookie` and references to the `__security_cookie` global variable, which lives in the `.data` section. This creates an absolute address reference that breaks position independence.

4. **`/NODEFAULTLIB`**: Instructs the linker to ignore all default library directives (`/DEFAULTLIB:` entries embedded in the CRT object files). Without this flag, the linker attempts to resolve `mainCRTStartup` and pulls in the entire CRT initialization chain, which depends on fixed IAT entries and the `.data` section.

5. **`/SUBSYSTEM:NATIVE`**: Marks the PE subsystem as `IMAGE_SUBSYSTEM_NATIVE_BOOT` (value 3) or `IMAGE_SUBSYSTEM_NATIVE` (value 16). This prevents the Windows loader from treating the binary as a Win32 application and avoids subsystem-specific initialization. When the shellcode is extracted from the PE and injected into a remote process, the subsystem field is irrelevant, but during build time it prevents the linker from adding Win32 startup code.

6. **`/NOENTRY`**: Tells the linker that the image has no standard entry point and should not generate `_main` or `mainCRTStartup` references. Combined with `/ENTRY:custom_entry`, this gives full control over the execution start point.

7. **`/SDL-`**: Disables Security Development Lifecycle checks — no `/GS`, no control flow guard, no safe exception handlers. These checks generate metadata in the `.rdata` section and `IMAGE_LOAD_CONFIG_DIRECTORY` entries that create absolute references.

8. **No C++ exceptions**: Exceptions require CRT runtime support (`__CxxFrameHandler`, `_CxxThrowException`) and generate unwind data in the `.pdata` section. The code must be compiled with `/EHs-` or simply authored in C rather than C++.

9. The source code must adhere to position-independence discipline:

10. **No heap allocation**: `malloc`, `calloc`, `new`, and `LocalAlloc` all resolve to external imports (either CRT wrappers or direct Win32 calls). The shellcode cannot rely on the loader resolving imports. Memory must come from stack allocation (local variables), inline buffer allocation via `alloca`/`_alloca` (which compiles to a `SUB RSP, imm` instruction — position independent), or manual calls to `NtAllocateVirtualMemory` after the shellcode has manually resolved the function pointer.

11. **No external references**: The shellcode cannot use any import that the PE loader would resolve via the IAT. All API calls must be manually resolved: the shellcode walks the PEB to find `ntdll.dll`, parses its export table, and resolves `Nt*` functions by DJB2 hash matching. From `ntdll`, the shellcode can resolve `LdrLoadDll` to load additional modules and `LdrGetProcedureAddress` to resolve their exports.

12. **No `.data` section references**: String literals and global variables placed in `.data` or `.rdata` are accessed via RIP-relative addresses that are fixed at link time. When the shellcode is extracted and placed at an arbitrary address, these references point to the wrong memory. The discipline requires stack-allocated string construction:
    ```c
    char str[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
    ```
    This compiles to `MOV` instructions that build the string on the stack byte-by-byte, which is position independent.

13. **Compiler intrinsics**: The `#pragma intrinsic` directive instructs the compiler to emit inline code for functions that are normally CRT library calls. `#pragma intrinsic(memset, strcmp, memcpy, __movsb)` generates inline `REP STOSB`, `REP MOVSB`, and comparison loops instead of calls to the CRT. The `<intrin.h>` header provides access to compiler intrinsics like `__readgsqword` (reads from `GS:` segment — used to access the PEB on x64), `__readmsr` (reads model-specific register), `__readcr2`, `__writecr3`, and other privileged operations.

14. After compilation, the raw shellcode bytes are extracted from the `.text` section of the produced PE. The `.text` section's `VirtualAddress` and `SizeOfRawData` fields in the section header identify the offset and size of the position-independent code blob. The operator copies these bytes into the encoding format required by the delivery mechanism (IPv4/IPv6/MAC/UUID/words encoding as documented in T-021).

## OS Internals Context

The Windows PE loader (`LdrpMapDllNtFileName` → `LdrpMapViewOfSection` → `LdrpProcessRelocationDirectory` → `LdrpProcessImportDirectory`) performs base relocation and IAT resolution when loading a PE. Position-independent shellcode must function correctly without any of these loader services. The PE's base relocation table (`DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]`) contains entries that the loader patches when the image loads at a non-preferred base address. Position-independent code avoids the need for relocation by using only RIP-relative addressing (x64) or call/pop instruction sequences (x86) to determine the current instruction pointer.

The PEB (Process Environment Block) is accessed on x64 via `GS:[0x60]` (the `gs` segment base is set to the TEB, and `TEB.ProcessEnvironmentBlock` is at offset 0x60 on x64, 0x30 on x86). The `__readgsqword(0x60)` intrinsic returns the PEB address. From the PEB, `PEB.Ldr` (offset 0x18 on x64) points to the `PEB_LDR_DATA` structure, whose `InLoadOrderModuleList` (offset 0x10) / `InMemoryOrderModuleList` (offset 0x20) doubly-linked lists enumerate all loaded modules. Each `LDR_DATA_TABLE_ENTRY` contains `DllBase`, `BaseDllName` (UNICODE_STRING), and `FullDllName`. The shellcode walks this list to find `ntdll.dll` by hash comparison, then parses its export directory to resolve `Nt*` functions by name hash.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN shellcode is Rust-based and uses a different toolchain (`rustc` with `panic=abort`, `#![no_std]`, custom linker scripts). The Visual Studio C build pipeline documented here produces raw PIC blobs for embedding in Rust-based payloads (e.g., donut-style loaders or specific shellcode snippets that must be authored in C for compatibility with existing tooling or for access to compiler intrinsics not available in Rust). An implementation in the HUGIN context would be a build script (`build.rs`) that invokes `cl.exe` with the documented flags against a C source file, extracts the `.text` section via PE parsing, and embeds the resulting byte blob via `include_bytes!` or `include_str!` with runtime hex decoding.

## Why It Matters

The vault's T-021 (Crypto & Obfuscation) covers shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) and T-016 covers PE stomping, but neither documents the build pipeline that produces the raw position-independent shellcode blob in the first place. This build pipeline is a prerequisite for every shellcode-encoding technique in T-021 — encoded shellcode that internally uses the heap, references the `.data` section, or relies on CRT initialization will fail when injected into a cross-process context where the loader does not process relocations or resolve imports. The discipline of avoiding these dependencies is the difference between shellcode that works reliably across injection contexts and shellcode that crashes silently.

## Detection Considerations

- **Telemetry sources**: The build pipeline itself runs on the operator's development machine, not the target. No target-side telemetry is generated. The resulting shellcode blob's detection surface depends on the encoding and injection technique used to deliver it.
- **Bypass options**: The shellcode should use manual PEB walking and DJB2 hash-based API resolution (as documented in T-004 PEB Walker) to avoid generating an IAT that reveals intended API usage. Stack-allocated string constants avoid `.rdata` references that static analysis tools use to fingerprint shellcode purpose.
- **Residual artifacts**: The compiled PE file on the development machine. The `.text` section extraction leaves a PE with a `.text` section that contains the shellcode — this PE itself may be flagged by AV if left on disk. The raw extracted `.bin` blob is not a valid PE and will not be scanned by PE-aware AV, but may be detected by byte-pattern signature matching.

## Related Techniques

- **T-013 Remaining Injection Methods** — injection techniques that consume the raw shellcode bytes produced by this pipeline
- **T-020 Anti-Analysis Suite** — IAT camouflage and self-deletion that apply to the final payload, not the shellcode build
- **T-021 Crypto & Obfuscation** — shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) that encode the raw bytes produced by this pipeline
- **T-016 EDR Evasion Suite** — PE stomping technique that receives the compiled shellcode as payload

## References

- Atlas material: atlas-exploit-dev-part1 (unit 17), atlas-exploit-dev-part13 (units 25, 27, 28, 29, 30, 33, 34, 38), atlas-exploit-dev-part19 (units 31, 32, 33, 34, 37, 40), atlas-exploit-dev-part20 (units 1, 2)
- MITRE ATT&CK: T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027
- LGTM notes: lgtm:pic-shellcode-build-config-coverage, lgtm:pic-c-shellcode-build-pipeline, lgtm:pic-c-shellcode-tradecraft, lgtm:gap-shellcode-position-independence-discipline

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-102 -->

<!-- BEGIN CARD T-103 -->
---
id: T-103
name: WinINet vs WinHTTP for C2 Transport
category: networking
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/winhttp_dl.rs
mitre: T1071.001
tags: [wininet, winhttp, c2-transport, http, proxy, cookie, cache, api-selection, ie-cache, user-agent]
origin: atlas-synthesis
member_notes: ['lgtm:wininet-vs-winhttp-c2', 'lgtm:wininet-vs-winhttp-transport-choice']
---

# WinINet vs WinHTTP for C2 Transport — API Family Selection for HTTP C2 Channels

## Summary

WinINet (`wininet.dll`) and WinHTTP (`winhttp.dll`) are two distinct Windows API families for HTTP communication, each with different monitoring profiles, dependency footprints, and capability sets. WinINet is the higher-level API with built-in IE cache, cookie persistence, and proxy inheritance from the system's Internet Explorer settings; WinHTTP is the lighter API designed for server-side and non-interactive HTTP with explicit proxy configuration. The HUGIN source implements WinHTTP in `winhttp_dl.rs` for staged payload download, dynamically loading `winhttp.dll` via `LoadLibraryA` to avoid static IAT detection. The selection between the two API families determines the EDR telemetry surface (WinINet hooks are common, WinHTTP hooks less so but increasing), proxy handling behavior, and whether cache artifacts are left on disk.

## Mechanism

1. **WinINet API sequence** (documented in SEC670 as the canonical HTTP C2 session pattern):
   - `InternetOpen(lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags)` — creates a session handle. The `lpszAgent` parameter sets the User-Agent string. `dwAccessType` determines proxy behavior: `INTERNET_OPEN_TYPE_PRECONFIG` inherits IE proxy settings, `INTERNET_OPEN_TYPE_DIRECT` bypasses proxies.
   - `InternetConnect(hSession, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext)` — creates a server connection handle. `dwService` is set to `INTERNET_SERVICE_HTTP` for HTTP or `INTERNET_SERVICE_FTP` for FTP.
   - `HttpOpenRequest(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext)` — creates a request handle. `lpszVerb` is "GET" or "POST". `dwFlags` can include `INTERNET_FLAG_SECURE` for HTTPS, `INTERNET_FLAG_NO_CACHE_WRITE` to suppress caching.
   - `HttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)` — transmits the request. Headers and body are sent here.
   - `InternetReadFile(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)` — reads the response body in chunks.

2. **WinHTTP API sequence** (implemented in HUGIN's `winhttp_dl.rs`):
   - `WinHttpOpen(pszUserAgent, dwAccessType, pszProxyName, pszProxyBypass, dwFlags)` — creates a session handle. The HUGIN implementation uses User-Agent `"Microsoft-CryptoAPI/10.0"` to masquerade as Windows Update traffic.
   - `WinHttpConnect(hSession, pszServerName, nServerPort, dwReserved)` — creates a connection handle.
   - `WinHttpOpenRequest(hConnect, pszVerb, pszObjectName, pszVersion, pszReferrer, ppwszAcceptTypes, dwFlags)` — creates a request handle. The HUGIN implementation uses `WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE`.
   - `WinHttpSendRequest(hRequest, pszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext)` — sends the request.
   - `WinHttpReceiveResponse(hRequest, lpReserved)` — waits for the response headers.
   - `WinHttpQueryDataAvailable(hRequest, lpdwBytesAvailable)` — checks how much response data is available.
   - `WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwBytesRead)` — reads response body in chunks.

3. The HUGIN `winhttp_dl.rs` implementation dynamically resolves all WinHTTP function pointers at runtime via `LoadLibraryA("winhttp.dll")` and `GetProcAddress`. This avoids static IAT entries for WinHTTP functions, defeating IAT-based detection that flags processes importing `winhttp.dll`.

4. The implementation validates each downloaded chunk's SHA-256 hash against a pre-computed manifest, aborting on mismatch. Downloaded data is assembled into an `NtVecBuf` that attempts large-page allocation via `NtAllocateVirtualMemory` with `MEM_LARGE_PAGES` when `SeLockMemoryPrivilege` is available, falling back to a standard `Vec<u8>`.

## OS Internals Context

WinINet (`wininet.dll`) is implemented on top of WinHTTP internally but adds a caching layer, cookie management, and proxy auto-configuration (PAC) script evaluation. The IE cache is stored in the `%LOCALAPPDATA%\Microsoft\Windows\INetCache` directory structure, with cache entries indexed by URL hash in the `index.dat` file. When `InternetReadFile` reads a response, WinINet may serve cached content if the cache entry has not expired (controlled by HTTP `Cache-Control` and `Expires` headers). This caching behavior can cause a C2 implant to receive stale responses if the cache is not explicitly bypassed with `INTERNET_FLAG_NO_CACHE_WRITE` or `INTERNET_FLAG_RELOAD` flags.

WinHTTP (`winhttp.dll`) does not implement a cache. Every request goes to the network (or proxy). WinHTTP's proxy configuration is set via `WinHttpOpen` parameters or `WinHttpSetOption` with `WINHTTP_OPTION_PROXY` — it does not inherit IE proxy settings unless the application explicitly queries IE configuration via `WinHttpGetIEProxyConfigurationForCurrentUser` (available on Windows 8.1+). WinHTTP is used by Windows Update (`wuaueng.dll`), Windows Defender (`MsMpEng.exe`), and other system services — traffic using the `Microsoft-CryptoAPI/10.0` User-Agent blends with legitimate Windows Update client traffic.

Both APIs ultimately use `Winsock` (via `ws2_32.dll`) for TCP transport. The kernel-level network stack (AFD driver, TCP/IP driver) is shared. ETW providers for HTTP traffic include `Microsoft-Windows-WinINet` (WinINet) and `Microsoft-Windows-WinHTTP` (WinHTTP) — these providers emit events for request/response cycles including URL, status code, and byte counts. An EDR that subscribes to either ETW provider can monitor all HTTP traffic through that API family.

## Key Implementation Details

The HUGIN source file `dark_crystal/crowd/src/winhttp_dl.rs` implements the WinHTTP transport. Key implementation choices:

- **Dynamic loading**: The `load_winhttp()` function uses `LoadLibraryA("winhttp.dll")` and `GetProcAddress` to resolve all WinHTTP function pointers at runtime. The `WinHttpFns` struct holds 8 function pointers (`open`, `connect`, `open_request`, `send`, `recv_response`, `query_avail`, `read`, `close`). This avoids static IAT entries for WinHTTP.
- **User-Agent camouflage**: `pszUserAgent` is set to `"Microsoft-CryptoAPI/10.0"`, matching the User-Agent used by Windows Update client. This blends C2 traffic with legitimate Windows Update polling.
- **HTTPS enforcement**: `WinHttpOpenRequest` is called with `WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE`, enforcing TLS and disabling proxy caching.
- **Chunked download with hash validation**: Data is read in 1MB chunks (`CHUNK_SIZE = 1024 * 1024`). Each chunk's SHA-256 is validated against a pre-computed hash manifest. Mismatch causes silent abort.
- **Large-page allocation**: The `try_large_page_alloc_and_copy` function attempts `NtAllocateVirtualMemory` with `MEM_LARGE_PAGES` to store the downloaded payload in a large-page region, falling back to a standard `Vec<u8>` if `SeLockMemoryPrivilege` is not available or large pages are unsupported.

No WinINet implementation exists in the HUGIN source. The vault's `winhttp_dl.rs` comment explicitly notes "no WinINet — menor footprint" as a design choice.

## Why It Matters

The vault's T-022 networking suite documents WinHTTP-based download but does not surface WinINet as an alternative or document the operational trade-offs between the two API families. The distinction matters operationally: WinINet's IE proxy inheritance simplifies C2 in environments where the target uses a corporate proxy (no manual proxy configuration needed), but WinINet's cache artifacts leave forensic evidence in `INetCache`. WinHTTP's explicit proxy configuration requires the operator to discover and configure proxy settings, but produces no cache artifacts. EDRs that hook WinINet (common — most EDRs monitor browser-relevant APIs) will intercept WinINet C2 traffic; WinHTTP hooks are less common but increasing as EDR vendors recognize WinHTTP's use in non-interactive HTTP C2.

## Detection Considerations

- **Telemetry sources**: ETW provider `Microsoft-Windows-WinINet` emits events for WinINet HTTP traffic. ETW provider `Microsoft-Windows-WinHTTP` emits events for WinHTTP traffic. Sysmon Event ID 22 (DNS) and network connection events capture the underlying TCP connections regardless of API family. EDR products may hook `WinHttpSendRequest` / `InternetConnect` / `HttpSendRequest` via inline hooks in the respective DLL's export table.
- **Bypass options**: Dynamic loading via `LoadLibraryA` + `GetProcAddress` avoids static IAT detection. Using a User-Agent matching legitimate system traffic (e.g., `"Microsoft-CryptoAPI/10.0"`) blends with Windows Update. HTTPS enforcement prevents plaintext network inspection. Domain fronting or CDN-backed C2 infrastructure makes the TCP destination appear legitimate.
- **Residual artifacts**: WinINet leaves cache entries in `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` and cookie files. WinHTTP leaves no filesystem artifacts. Both APIs generate TCP connection records in the system's network stack. Proxy configuration changes (if `WinHttpSetOption` is used) may be logged by proxy-aware EDRs.

## Related Techniques

- **T-022 Network Suite** — networking card that documents WinHTTP download, SOCKS5, HVNC, malleable C2, and multi-chain vault
- **T-065 Certificate Pinning for C2 TLS Transport** — TLS certificate validation for the HTTPS transport layer

## References

- Atlas material: atlas-exploit-dev-part12 (units 39, 40), atlas-exploit-dev-part20 (units 22, 23)
- MITRE ATT&CK: T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001
- LGTM notes: lgtm:wininet-vs-winhttp-c2, lgtm:wininet-vs-winhttp-transport-choice

## Source Reference

`dark_crystal/crowd/src/winhttp_dl.rs` — `winhttp_download()` function (full WinHTTP API sequence: `WinHttpOpen` → `WinHttpConnect` → `WinHttpOpenRequest` → `WinHttpSendRequest` → `WinHttpReceiveResponse` → `WinHttpQueryDataAvailable` → `WinHttpReadData`). Dynamic loading via `load_winhttp()` using `LoadLibraryA` + `GetProcAddress`.
<!-- END CARD T-103 -->

<!-- BEGIN CARD T-104 -->
---
id: T-104
name: Malleable C2 Profile and P2P Listener Convergence
category: networking
tier: A
crate: client_rust
source_file: none
mitre: T1071.001
tags: [malleable-c2, p2p, cobalt-strike, beacon, smb, tcp, c2-matrix, traffic-shaping, profile, peer-relay]
origin: atlas-synthesis
member_notes: ['lgtm:cross-source-malleable-c2-convergence', 'lgtm:cross-source-c2-protocol-convergence']
---

# Malleable C2 Profile and P2P Listener Convergence — Traffic Shaping and Peer-to-Peer C2 Chaining

## Summary

Malleable C2 profiles are configuration files that shape HTTP beacon traffic to blend with legitimate web application patterns, controlling User-Agent, URI paths, HTTP headers, GET/POST staging, and jitter timing. The CRTO curriculum documents Cobalt Strike's `.profile` files as the canonical implementation, and the HUGIN vault implements a malleable C2 profile engine in `client_rust/src/henge.rs`. CRTO also documents P2P listener chaining where Beacons communicate over TCP listeners and SMB named pipe listeners, allowing an isolated beacon without direct HTTP egress to chain through an intermediate beacon that has network access. The HUGIN vault implements peer relay networking in `juubi.rs`, multi-chain vault in `rikudo.rs`, and SOCKS5 proxy in `kamui.rs`. The convergence between CRTO's operational framing and the vault's implementation confirms malleable profiles and P2P chaining as the standard multi-protocol C2 architecture.

## Mechanism

1. **Malleable C2 profile configuration**: A malleable profile defines HTTP transaction properties for each beacon communication type. The profile syntax controls:
   - **User-Agent**: The `User-Agent` header value, typically set to match a common browser string (e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`).
   - **URI structure**: The request URI and any sub-URI paths for staging, task retrieval, and result posting. URIs are designed to match the target environment's expected web application paths (e.g., `/api/v2/reports`, `/images/thumbnails`).
   - **HTTP headers**: Custom headers that carry beacon data. The profile can specify that the beacon ID is encoded in a `Cookie` header, `X-Forwarded-For` header, or custom header name.
   - **GET/POST staging**: Whether the initial beacon stage download uses GET (metadata in URI) or POST (metadata in body). The profile specifies the `http-get` and `http-post` blocks with distinct URI, header, and body parameter configurations.
   - **Jitter**: Random variation in beacon check-in interval (e.g., 10% jitter on a 60-second cycle means check-ins occur between 54 and 66 seconds apart) to avoid fixed-interval detection by network behavioral analytics.
   - **Data transformation**: The profile can specify Base64, XOR, or custom encoding for beacon payloads embedded in HTTP traffic.

2. **HTTP beacon egress**: The beacon polls its C2 server at the configured interval with jitter. Each poll is an HTTP(S) request whose appearance is fully controlled by the malleable profile. The server responds with tasking (commands to execute) or an empty response (no tasks).

3. **TCP P2P listener**: A beacon that has established HTTP egress can open a TCP listener on a port. Other beacons on the same internal network that cannot reach the internet connect to this TCP listener. The TCP listener beacon acts as a relay: it receives tasking from the HTTP C2 server and forwards it over the TCP connection to the chained beacon. Results flow back in reverse.

4. **SMB named pipe P2P listener**: An alternative to TCP, the SMB listener creates a named pipe (e.g., `\\.\pipe\msagent_011`). Beacons connect to this pipe via `CreateFile("\\\\target\\pipe\\msagent_011")` and exchange data over the pipe. SMB P2P is useful in environments where TCP connections between hosts are blocked by host-based firewalls but SMB (port 445) is allowed for file sharing.

5. **C2 Matrix**: The full set of transport options forms a matrix:
   - **HTTP(S)**: Direct egress via HTTP or HTTPS to a C2 server. Subject to network proxy, IDS, and web filtering.
   - **DNS**: Beaconing via DNS queries (A, TXT, AAAA records). Slow bandwidth but effective in environments where only DNS is allowed outbound.
   - **TCP**: P2P relay between beacons on the internal network.
   - **SMB**: P2P relay via named pipes over the SMB protocol.

6. **P2P chain topology**: In a segmented network, the topology might be: Internet-facing beacon (HTTP egress) ← TCP listener → Internal beacon A ← SMB listener → Isolated beacon B. Tasking flows: C2 server → HTTP → Internet beacon → TCP → Internal beacon A → SMB → Isolated beacon B. Results flow in reverse. Each hop must support the beacon protocol.

## OS Internals Context

Named pipes in Windows are implemented by theNamed Pipe File System driver (`npfs.sys`). A named pipe server creates a pipe via `CreateNamedPipeW` (which calls `NtCreateNamedPipeFile`), and a client connects via `CreateFileW` with the pipe path format `\\server\pipe\pipename`. The SMB redirector (`mrxsmb.sys` / `mrxsmb20.sys`) transparently routes named pipe access to remote hosts over SMB (port 445). When a beacon connects to `\\target\pipe\msagent_011`, the SMB redirector establishes an SMB session with the target host and opens the named pipe. Data written to the pipe via `WriteFile` / `NtWriteFile` is transmitted over the SMB session, and data read via `ReadFile` / `NtReadFile` is received from the SMB session.

TCP listeners use the Winsock API (`WSASocket` / `bind` / `listen` / `accept`). The underlying kernel transport is the TCP/IP driver (`tcpip.sys`). TCP connections between hosts on the same subnet do not traverse a proxy or gateway — they are direct Layer 3 connections subject only to host-based firewall rules (Windows Filtering Platform, `netsh advfirewall`).

The HUGIN vault's `henge.rs` (listed in the file manifest as the malleable C2 profile engine under T-022) implements the profile parsing and HTTP traffic shaping. The `juubi.rs` peer relay module and `rikudo.rs` multi-chain vault implement the P2P chaining topology. The `kamui.rs` SOCKS5 proxy provides additional transport flexibility for relayed connections. These source files were not provided for verification in this batch — the file manifest listing serves as the reference.

## Key Implementation Details

The HUGIN vault file manifest references the following implementation files under `client_rust/`:
- `src/henge.rs` — listed as "Malleable C2 profile engine" mapped to T-022 (Network Suite). This file was not provided for source verification in this batch. The implementation is expected to parse malleable profile configuration (User-Agent, URI, headers, jitter) and shape HTTP request/response cycles accordingly.
- `src/juubi.rs` — listed as "Peer relay network" mapped to T-022. Implements the P2P relay topology.
- `src/juubi_chain.rs` — listed as "Peer relay chain management" mapped to T-022. Manages multi-hop relay chains.
- `src/rikudo.rs` — listed as "Multi-chain vault" mapped to T-022. Implements the multi-protocol C2 matrix (HTTP, TCP, SMB).
- `src/kamui.rs` — listed as "SOCKS5 proxy" mapped to T-022. Provides SOCKS5 proxy capability for relayed traffic.
- `src/http_poll_transport.rs` — listed as "HTTP long-poll transport" mapped to T-022. Implements HTTP long-polling for beacon check-in.

These files were not provided for verification. The cluster spec confirms convergence between CRTO's operational framing (malleable profiles, P2P listeners, C2 matrix) and the vault's implementation architecture.

## Why It Matters

The convergence between CRTO operational tradecraft and the HUGIN vault implementation confirms that malleable C2 profiles and P2P listener chaining are the standard C2 architecture for multi-protocol command and control. The P2P chaining capability is operationally significant because it allows a beacon that cannot egress directly (e.g., on an isolated subnet behind network segmentation) to chain through an intermediate beacon that has HTTP egress, using the SMB or TCP listener as the transport. Without P2P chaining, operators would need to establish independent C2 channels for every beacon, increasing the network footprint and detection surface. The malleable profile capability is the baseline for HTTP C2 traffic shaping — without it, beacon HTTP traffic has fixed URIs and headers that are trivially detected by network IDS signatures.

## Detection Considerations

- **Telemetry sources**: HTTP C2 traffic is monitored by network IDS/IPS (Snort, Suricata, Zeek), web proxies (Zscaler, BlueCoat), and EDR network inspection modules. DNS-based C2 is monitored by DNS analytics (RSA NetWitness, Cisco Umbrella). SMB named pipe connections are logged by Sysmon Event ID 17 (NamedPipeCreated) and Event ID 18 (NamedPipeConnected). TCP P2P connections between internal hosts may be detected by network flow analysis (fixed-interval connections, unusual port usage).
- **Bypass options**: Malleable profiles shape HTTP traffic to match legitimate web application patterns, defeating signature-based IDS. Jitter randomization defeats fixed-interval beaconing detection. SMB named pipe P2P uses the standard SMB protocol on port 445, which is expected traffic in enterprise environments. TCP P2P can use standard ports (80, 443, 8080) to blend with HTTP traffic.
- **Residual artifacts**: HTTP C2 leaves server-side access logs and proxy cache entries. SMB named pipe P2P leaves named pipe handles (visible via `GetNamedPipeInfo` / `NtQueryInformationFile` with `FilePipeInformation`). TCP connections leave socket entries visible in `netstat` and `GetExtendedTcpTable`.

## Related Techniques

- **T-022 Network Suite** — vault networking card implementing malleable C2 (henge.rs), peer relay (juubi.rs), multi-chain vault (rikudo.rs), and SOCKS5 proxy (kamui.rs)
- **T-033 Named Pipes for C2 Communication** — named pipe IPC mechanism used by SMB P2P listeners

## References

- Atlas material: atlas-post-exploit-part15 (unit 37), atlas-post-exploit-part16 (units 2, 6, 8)
- MITRE ATT&CK: T1071.001 (Web Protocols) — https://attack.mitre.org/techniques/T1071/001
- LGTM notes: lgtm:cross-source-malleable-c2-convergence, lgtm:cross-source-c2-protocol-convergence

## Source Reference

`client_rust/src/henge.rs` (malleable C2 engine), `client_rust/src/juubi.rs` (peer relay), `client_rust/src/rikudo.rs` (multi-chain vault), `client_rust/src/kamui.rs` (SOCKS5 proxy) — listed in vault file manifest mapped to T-022 but not provided for source verification in this batch.
<!-- END CARD T-104 -->

<!-- BEGIN CARD T-105 -->
---
id: T-105
name: IFEO Debugger and Port Monitor DLL Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.012
mitre_secondary: [T1547.010]
tags: [ifeo, port-monitor, persistence, debugger-value, print-spooler, registry, autostart, event-driven, addmonitor, spoolsv]
origin: atlas-synthesis
member_notes: ['lgtm:coverage-gap-persistence-layer-ifoe-portmon-wmi', 'lgtm:ifoe-and-port-monitor-persistence-coverage', 'lgtm:ifeo-and-port-monitor-coverage', 'lgtm:persistence-layer-cross-source-convergence']
---

# IFEO Debugger and Port Monitor DLL Persistence — Two Event-Driven Autostart Mechanisms via Registry and Print Spooler

## Summary

Image File Execution Options (IFEO) Debugger persistence and Port Monitor DLL persistence are two registry-driven autostart mechanisms that trigger on legitimate system events rather than scheduled timers. IFEO persistence writes a `Debugger` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` that redirects process launch into an attacker-specified binary — when the target executable is launched, Windows reads the IFEO key and starts the debugger binary instead, passing the original command line as an argument. Port Monitor persistence installs a DLL via the `AddMonitor()` API into `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver`, which the Print Spooler service (`spoolsv.exe`) loads at spooler initialization. Both require Administrator privileges for HKLM modification and are file-less in the registry-write sense, though both require a DLL or executable on disk to serve as the payload.

## Mechanism

1. **IFEO Debugger persistence** (SEC670 Lab 4.3 'IFEOPersist'):

2. The operator creates or opens the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` via `RegCreateKeyExA` or `NtCreateKey`. The `<target.exe>` is the name of a legitimate executable that the operator expects to be launched by a user or the system (e.g., `userinit.exe`, `sethc.exe`, `magnifier.exe`, `notepad.exe`).

3. The operator writes a string value named `Debugger` under this key. The value data is the full path to the attacker's binary (e.g., `C:\Windows\Temp\implant.exe`). When any process attempts to launch `<target.exe>`, the Windows image loader (`LdrpInitializeProcess` → `DbgUiRemoteBreakin` path) checks the IFEO registry key before creating the process. If a `Debugger` value exists, the loader launches the debugger binary instead, appending the original target's path and command line as arguments: `C:\Windows\Temp\implant.exe <original_target_path> <original_args>`.

4. The attacker's binary receives the original target's path as a command-line argument and can either execute the payload directly or chain: execute the payload, then launch the original target executable transparently to avoid user suspicion.

5. **Port Monitor persistence**:

6. The operator installs a custom Port Monitor DLL by calling the `AddMonitor()` API (exported by `winspool.drv` / `spoolss.dll`):
   ```c
   AddMonitor(NULL, MONITOR_INFO_2, &monitorInfo);
   ```
   The `MONITOR_INFO_2` structure contains:
   - `pName` — monitor name (arbitrary string, e.g., "MaliciousMonitor")
   - `pEnvironment` — "Windows x64" or "Windows NT x86"
   - `pDLLName` — filename of the monitor DLL (e.g., "evilmon.dll")

7. `AddMonitor()` writes the monitor configuration to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<monitor_name>\Driver` with the DLL name as the value. It also creates subkeys for monitor configuration under the `Monitors` key.

8. The Print Spooler service (`spoolsv.exe`) loads all registered Port Monitor DLLs at service initialization via `LoadLibrary` / `LoadLibraryEx`. The spooler calls the monitor DLL's `InitializePrintMonitor2` (or `InitializePrintMonitor` on older systems) export, which receives a function pointer table for spooler callbacks. The attacker's DLL implements this export to gain execution in the context of the spooler service (running as `NT AUTHORITY\SYSTEM`).

9. The monitor DLL can also implement the `Monitor2` structure's function pointers (`pfnOpenPort`, `pfnStartDocPort`, `pfnWritePort`, etc.) to maintain a legitimate monitor facade while executing payload code in `InitializePrintMonitor2` or during port operations.

## OS Internals Context

The IFEO mechanism is implemented in the Windows image loader. When `CreateProcess` / `NtCreateUserProcess` is called, the loader (`LdrpInitializeProcess` in `ntdll.dll`) checks `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<ApplicationName>` for a `Debugger` value. This check occurs in `BasepCheckForRelaunch` (in `kernel32.dll` / `kernelbase.dll`) before the process is created. If the `Debugger` value is present, `BasepCheckForRelaunch` modifies the `CreateProcess` parameters to launch the debugger binary with the original target's path appended. The original target is not launched — the debugger is expected to launch it if desired.

IFEO also supports additional values: `GlobalFlag` (controls heap debugging, verifier, and other debug options), `DebuggerFlags` (bitmask controlling debugger behavior), and `MitigationOptions` / `MitigationAuditOptions` (process mitigation policies). The `SilentProcessExit` subkey under IFEO (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\SilentProcessExit`) supports `ReportingMode` and `MonitorProcess` values that trigger actions when the target process exits — this is documented separately in T-034.

The Print Spooler service (`spoolsv.exe`) is hosted in a generic `svchost.exe` instance grouped with the `Spooler` service group. At service start (`ServiceMain` in `spoolss.dll`), the spooler enumerates `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` subkeys and calls `LoadLibraryEx` on each monitor's `Driver` value. The `MONITOR2` structure (or `MONITOR_INFO_2` for registration) defines 25+ function pointers that the spooler calls for port operations. The `InitializePrintMonitor2` export receives a `LPMONITORINIT` structure containing callbacks for the spooler to communicate back to the monitor DLL.

The Port Monitor DLL runs in the `spoolsv.exe` process, which runs as `NT AUTHORITY\SYSTEM`. Code executing in `InitializePrintMonitor2` has full system-level privileges and access to the spooler's handles, memory, and network connections.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN persistence module (`dark_crystal/crowd/src/persist/`) implements COM hijack (`com_hijack.rs`), NTFS EA (`ntfs_ea.rs`), scheduled task (`schtask.rs`), TLS callback (`tls_cb.rs`), and PhantomPersist (`phantom_restart.rs`), but does not include IFEO or Port Monitor persistence. An IFEO implementation would need: (1) a function that calls `RegCreateKeyExA` to create `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>`, (2) a call to `RegSetValueExA` to write the `Debugger` string value with the implant path, and (3) cleanup logic that deletes the registry key on uninstall. A Port Monitor implementation would need: (1) a DLL project that exports `InitializePrintMonitor2` returning a populated `MONITOR2` structure, (2) a call to `AddMonitor()` or direct registry writes to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver`, and (3) cleanup via `DeleteMonitor()` or registry deletion.

## Why It Matters

T-017 documents five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but does not include IFEO or Port Monitor as persistence vectors. Both are canonical, well-documented Windows persistence primitives with distinct trigger semantics and detection footprints. IFEO is event-driven (triggers on process launch) rather than time-driven (triggers on schedule), making it unpredictable in timing but reliable in execution — the operator knows the payload will execute when the target process is launched, which can be socially engineered or triggered by normal user activity. Port Monitor persistence leverages a system service that auto-starts and runs as SYSTEM, providing reliable, high-privilege execution on every spooler restart (which occurs on reboot or service restart). Both fill gaps in the persistence surface that T-017 does not cover.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 12 (RegistryEvent ObjectCreateKey) and Event ID 13 (RegistryEvent ValueSet) capture IFEO `Debugger` value writes and Port Monitor `Driver` value writes. Sysmon Event ID 7 (ImageLoad) captures the Port Monitor DLL being loaded by `spoolsv.exe`. EDR products that monitor IFEO registry paths generate alerts on `Debugger` value creation. Windows Defender ATP's advanced hunting queries flag IFEO and Port Monitor modifications as persistence techniques.
- **Bypass options**: For IFEO, target executables that are commonly launched (e.g., `notepad.exe`, `calc.exe`) reduce the anomaly of the trigger event. For Port Monitor, using a DLL name that matches a legitimate monitor (e.g., blending with `Local Monitor`, `Standard TCP/IP Port Monitor`, `WSD Port Monitor`) reduces visual detection in the Print Management console.
- **Residual artifacts**: IFEO leaves a registry key under `Image File Execution Options\<target.exe>` with a `Debugger` value. Port Monitor leaves a registry key under `Print\Monitors\<name>\Driver` and a loaded DLL handle in `spoolsv.exe` visible via `Process Explorer` module list. The payload DLL or executable on disk.

## Related Techniques

- **T-017 Five-Layer Persistence** — persistence suite that does not include IFEO or Port Monitor layers
- **T-034 IFEO GlobalFlag and SilentProcessExit** — related IFEO persistence via SilentProcessExit monitor (T-105 covers the Debugger value specifically)
- **T-035 Port Monitor Persistence via Print Spooler** — dedicated card for Port Monitor persistence (T-105 combines IFEO and Port Monitor from the SEC670 curriculum perspective)

## References

- Atlas material: atlas-methodology-part8 (units 16-20, 22, 24), atlas-methodology-part9 (units 20-22, 24-26, 28-30), atlas-post-exploit-part1 (units 13, 34, 35), atlas-post-exploit-part12 (units 1, 24, 31, 39)
- MITRE ATT&CK: T1546.012 (Event Triggered Execution: Image File Execution Options Debugger) — https://attack.mitre.org/techniques/T1546/012
- LGTM notes: lgtm:coverage-gap-persistence-layer-ifoe-portmon-wmi, lgtm:ifoe-and-port-monitor-persistence-coverage, lgtm:ifeo-and-port-monitor-coverage, lgtm:persistence-layer-cross-source-convergence

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-105 -->

<!-- BEGIN CARD T-106 -->
---
id: T-106
name: Persistence Vector Catalog Gap
category: persistence
tier: S
crate: none
source_file: none
mitre: T1546
mitre_secondary: [T1547.001, T1546.010, T1546.009, T1546.012, T1546.003, T1547.010]
tags: [persistence, run-key, appinit, appcert, ifeo, wmi, port-monitor, service-acl, catalog, vector-coverage]
origin: atlas-synthesis
member_notes: ['lgtm:gap-run-key-persistence', 'lgtm:gap-appinit-appcert-ifeo-wmi-persistence', 'lgtm:persistence-suite-coverage-gap', 'lgtm:cross-source-persistence-tradecraft-convergence', 'lgtm:weak-service-acl-persistence']
---

# Persistence Vector Catalog Gap — Expanding the Persistence Surface Beyond T-017's Five Layers

## Summary

The HUGIN vault's T-017 documents five persistence layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but the Windows persistence surface extends significantly further. This card catalogs seven additional persistence vectors absent from T-017's enumeration: Run/RunOnce registry keys, AppInit_DLLs, AppCert DLLs, IFEO Debugger values, WMI Event Subscriptions, Port Monitor DLLs, and weak service ACL replacement. Each vector abuses an administrative or debugging feature by redirecting a code path the operating system executes on a scheduled or trigger-based event. All require elevated privileges (Admin or SYSTEM) for HKLM modification, and each has distinct trigger semantics (boot, logon, process-event, scheduled) and detection footprints that operators select among based on the target environment's monitoring profile.

## Mechanism

1. **Run / RunOnce Registry Keys**:
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — executes the registered command at every user logon (system-wide).
   - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — executes at logon for the current user.
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` — executes once at next logon, then the entry is automatically deleted by the shell (`explorer.exe`).
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx` — extended RunOnce with flags for wait and error handling.
   The `Run` key is the most commonly used persistence vector in Windows. The shell (`explorer.exe`) reads these keys during logon via `RegisterApplicationRestart` / shell initialization and executes each value's command string.

2. **AppInit_DLLs**:
   - Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` — semicolon-separated list of DLL paths.
   - Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` — DWORD value (1 to enable, 0 to disable).
   - When `LoadAppInit_DLLs` is set to 1, every process that loads `user32.dll` also loads every DLL listed in `AppInit_DLLs`. The loader (`LdrpInitializeProcess` → `LdrpCodeAuthzCheck` → `LdrpLoadDll` for AppInit) performs this injection during `user32.dll` initialization.
   - On x64 Windows, a separate `AppInit_DLLs` key exists under `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` for 32-bit processes.

3. **AppCert DLLs**:
   - Registry path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` — contains values where each value name is a DLL path and the value data is the DLL filename.
   - DLLs listed here are loaded into any process that uses the `CreateProcess` API family via `AppCertFix` in `kernelbase.dll`. The mechanism attaches to process creation events similarly to IFEO but at a different layer.

4. **IFEO Debugger Values** (overlaps with T-105):
   - Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>\Debugger`
   - When `<target.exe>` is launched, the loader starts the `Debugger` binary instead, passing the original target's path as an argument.
   - Also supports `SilentProcessExit` subkey with `ReportingMode` and `MonitorProcess` values for exit-triggered persistence.

5. **WMI Event Subscriptions**:
   - Namespace: `root\subscription`
   - Three components: `__EventFilter` (defines the trigger condition via WQL query), `__EventConsumer` (defines the action — `CommandLineEventConsumer` for command execution, `ActiveScriptEventConsumer` for script execution), and `__FilterToConsumerBinding` (links filter to consumer).
   - The WMI provider service (`wmiprvse.exe`) evaluates filters and invokes consumers when conditions are met. A common trigger: `SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'` — fires every 5 seconds when any new process is created.
   - WMI subscriptions survive reboot because they are stored in the WMI repository (`%SystemRoot%\System32\wbem\Repository`), a persistent CIM database.

6. **Port Monitor DLLs** (overlaps with T-105):
   - Registry path: `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver`
   - The Print Spooler service (`spoolsv.exe`) loads the named DLL at service start via `LoadLibraryEx`. The DLL must export `InitializePrintMonitor2` and runs as `NT AUTHORITY\SYSTEM`.

7. **Weak Service ACL Replacement**:
   - The operator enumerates services via `OpenSCManager` / `EnumServicesStatusEx` and reads each service's security descriptor via `QueryServiceObjectSecurity` / `sc.exe sdshow <service>`.
   - If the service's DACL grants `SERVICE_CHANGE_CONFIG` (or equivalent write permission) to a group the operator belongs to (e.g., `Authenticated Users`, `Users`), the operator modifies the service binary path via `ChangeServiceConfig` with `SERVICE_CHANGE_CONFIG` → `lpBinaryPathName` pointing to the implant.
   - Alternatively, the operator uses `sc.exe sdset <service> <new_sddl>` to replace the security descriptor, then modifies the binary path.
   - The implant executes when the service is started (manually, on boot if `SERVICE_AUTO_START`, or on trigger if `SERVICE_TRIGGER_START`).

## OS Internals Context

The Windows persistence surface spans multiple OS subsystems. The shell (`explorer.exe`) reads Run/RunOnce keys during its initialization sequence (`SHCreateShellWindow` → shell startup processing). The PE loader (`LdrpInitializeProcess` in `ntdll.dll`) checks IFEO keys in `BasepCheckForRelaunch` (in `kernelbase.dll`) and loads AppInit_DLLs during `user32.dll` initialization via `LdrpCodeAuthzCheck` → `LdrpLoadAppInitDlls`. The `AppCertDlls` mechanism is invoked from `CreateProcessInternalW` in `kernelbase.dll` when the `BasepIsProcessAllowed` check triggers AppCert DLL loading.

The WMI infrastructure is implemented by the WMI service (`wmiprvse.exe`, hosted in `svchost.exe`) and the CIM Object Manager (`CIMOM`). Event filters are evaluated by the `__EventProvider` infrastructure, which polls for `__InstanceCreationEvent`, `__InstanceModificationEvent`, and `__InstanceDeletionEvent` at the interval specified in the WQL `WITHIN` clause. When a filter matches, the consumer is invoked: `CommandLineEventConsumer` calls `CreateProcess` with the `CommandLineTemplate` property, and `ActiveScriptEventConsumer` executes a script via the Windows Script Host (`wscript.exe`).

Service security descriptors are stored in the SCM database (`%SystemRoot%\System32\config\SYSTEM` registry hive, under `HKLM\SYSTEM\CurrentControlSet\Services\<service>\Security`). The DACL controls who can start, stop, and modify the service. The `SERVICE_CHANGE_CONFIG` access right (value 0x0002) allows modification of the binary path, start type, and display name via `ChangeServiceConfig`.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN persistence module (`dark_crystal/crowd/src/persist/`) implements COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist. The vault also has separate atlas-expansion cards for some individual vectors (T-034 for IFEO, T-035 for Port Monitor, T-037 for WMI, T-038 for AppInit_DLLs, T-036 for service-based persistence, T-040 for service failure actions). This card serves as the unified catalog reference. A full implementation for each vector would require: (1) Run/RunOnce: `RegSetValueExA` on the Run key with the implant path; (2) AppInit_DLLs: `RegSetValueExA` on `AppInit_DLLs` and `LoadAppInit_DLLs`; (3) AppCertDlls: `RegSetValueExA` under the `AppCertDlls` key; (4) IFEO: documented in T-105; (5) WMI: COM calls to `IWbemServices::PutInstance` for `__EventFilter`, `CommandLineEventConsumer`, and `__FilterToConsumerBinding`; (6) Port Monitor: documented in T-105; (7) Weak Service ACL: `OpenSCManager` → `OpenService` → `QueryServiceObjectSecurity` → DACL analysis → `ChangeServiceConfig`.

## Why It Matters

The vault's T-017 currently lists only five persistence layers, leaving operators without documented options for seven additional vectors that represent standard red-team tradecraft. The convergence pattern across multiple SEC670 modules confirms that the persistence surface extends well beyond the five T-017 layers and that operators select among vectors based on trigger type (boot vs. logon vs. process-event vs. scheduled), required privilege (HKLM vs. HKCU), and detection footprint (registry write vs. WMI repository modification vs. service config change). This card provides the unified catalog that operators reference when selecting persistence vectors for a specific engagement environment, with explicit trigger, privilege, and detection attributes per vector.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 12/13 (RegistryEvent) captures Run key, AppInit_DLLs, AppCertDlls, IFEO, and Port Monitor registry writes. Sysmon Event ID 19 (WmiFilter), Event ID 20 (WmiConsumer), and Event ID 21 (WmiFilterConsumerBinding) capture WMI event subscription creation. Sysmon Event ID 4 (ServiceConfig) captures service configuration changes. EDR products monitor HKLM Run key writes, AppInit_DLLs modifications, and WMI subscription creation as high-confidence persistence indicators.
- **Bypass options**: For Run keys, writing to `HKCU\Run` avoids HKLM access requirements but only triggers for the current user. For WMI, using `ActiveScriptEventConsumer` with obfuscated VBScript/JScript avoids plaintext command strings. For weak service ACLs, modifying a service that is already configured for auto-start minimizes configuration changes.
- **Residual artifacts**: Run keys leave registry entries visible via `autorunsc` (Sysinternals). AppInit_DLLs leaves a DLL loaded in every user32 process — visible in `Process Explorer` module lists. WMI subscriptions are visible via `wmic.exe path __filter_to_consumer_binding` or `Get-WmiObject` in PowerShell. Port Monitors are visible in the Print Management MMC snap-in. Service ACL changes are visible via `sc.exe sdshow`.

## Related Techniques

- **T-017 Five-Layer Persistence** — the persistence suite this card expands with additional vectors
- **T-034 IFEO GlobalFlag and SilentProcessExit** — dedicated card for IFEO persistence
- **T-035 Port Monitor Persistence via Print Spooler** — dedicated card for Port Monitor persistence
- **T-036 Windows Service-Based Persistence** — dedicated card for service-based persistence
- **T-037 WMI Permanent Event Subscription Persistence** — dedicated card for WMI event subscription persistence
- **T-038 AppInit_DLLs Registry Persistence** — dedicated card for AppInit_DLLs persistence
- **T-044 Service-Based Local Privilege Escalation** — service enumeration for weak ACLs that enables the weak service ACL persistence vector

## References

- Atlas material: atlas-post-exploit-part6 (units 1, 2, 5, 6, 9), atlas-post-exploit-part7 (units 1, 6, 9, 18, 21, 27, 36), atlas-post-exploit-part12 (units 1, 24, 31, 39), atlas-recon-part7 (unit 17), atlas-methodology-part8 (units 16-20, 22, 24)
- MITRE ATT&CK: T1546 (Event Triggered Execution) — https://attack.mitre.org/techniques/T1546
- LGTM notes: lgtm:gap-run-key-persistence, lgtm:gap-appinit-appcert-ifeo-wmi-persistence, lgtm:persistence-suite-coverage-gap, lgtm:cross-source-persistence-tradecraft-convergence, lgtm:weak-service-acl-persistence

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Individual persistence vectors have dedicated atlas Expansion cards (T-034 through T-038) with additional detail.
<!-- END CARD T-106 -->