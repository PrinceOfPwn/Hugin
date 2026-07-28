## Synthesis Summary

The batch maps to T-004 (PEB Walker — PE parsing for function address resolution), T-013 (Remaining Injection Methods — thread context hijacking primitives), T-015 (PPID Spoofing — PROC_THREAD_ATTRIBUTE_LIST parent attribution), T-016 (EDR Evasion Suite — AMSI function patching via in-memory patching and IAT walking), and T-020 (Anti-Analysis Suite — binary metadata/version-info impersonation). The SANS SEC670 material covers PE format fundamentals (IMAGE_DOS_HEADER with e_magic=4D 5A and e_lfanew at offset 0x3C; IMAGE_OPTIONAL_HEADER magic values 0x10B for PE32 vs 0x20B for PE32+; AddressOfEntryPoint as the program entry point), the CONTEXT structure layout with DWORD64 register slots (R11–R15, Rip) that thread hijacking modifies, the PROC_THREAD_ATTRIBUTE_LIST structure used to change parent process attribution, and in-memory patching mechanics (IAT walking, MZ signature scanning, patching AmsiScanBuffer/AmsiScanString) where disk is not modified so changes do not persist across reboots. The gap the source fills: explains the PE parsing primitives that underlie manual function resolution (T-004), the CONTEXT structure manipulation that makes thread hijacking work (T-013), the STARTUPINFOEX attribute list mechanics behind PPID spoofing (T-015), and the in-memory patching workflow for AMSI bypass (T-016) — knowledge that source code alone does not surface. Several units (CreateFile return values, HRESULT macros, error code enumerations, MIB_IPSTATS, HKEY/HINSTANCE/HRSRC handle typing, DLL format basics) cover foundational Windows API facts but lack depth to enrich specific vault techniques.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "concept:image-dos-header"
    target: "T-004"
    type: requires
    rationale: "PEB Walker and related manual function resolution depends on parsing the IMAGE_DOS_HEADER (e_magic MZ, e_lfanew at offset 0x3C) to locate the export directory — SEC670 Lab 3.1 GetFunctionAddress explicitly walks this structure."
  - source: "concept:thread-context-structure"
    target: "T-013"
    type: requires
    rationale: "SEC670 unit review questions establish that thread hijacking modifies the thread context construct (the CONTEXT structure containing Rip and register slots) rather than thread state or priority."
  - source: "concept:proc-thread-attribute-list"
    target: "T-015"
    type: enables
    rationale: "SEC670 unit review identifies PROC_THREAD_ATTRIBUTE_LIST as the structure used to change the parent process — the core primitive enabling PPID spoofing via STARTUPINFOEX."
  - source: "concept:in-memory-patching"
    target: "T-016"
    type: alternative_to
    rationale: "SEC670 presents in-memory patching (IAT walking, MZ scan, AMSI function patching) as the methodology for AMSI bypass, an alternative to the HW breakpoint PAGE_GUARD approaches also tracked under T-016."
  - source: "concept:in-memory-patching"
    target: "concept:image-dos-header"
    type: requires
    rationale: "SEC670 in-memory patching discussion locates target code by scanning for the MZ signature (4D 5A) of a loaded module — the same IMAGE_DOS_HEADER field the PE parsing material covers."
  - source: "concept:amsi-function-patching"
    target: "T-016"
    type: concept_link
    rationale: "AMSI patching via in-memory modification of AmsiScanBuffer/AmsiScanString is one of the AMSI bypass variants catalogued under the T-016 EDR Evasion Suite."
  - source: "concept:pe-optional-header-magic"
    target: "T-004"
    type: concept_link
    rationale: "PE32 vs PE32+ identification via the optional header magic value (0x10B vs 0x20B) is part of the same PE parsing foundation used by manual function resolution in T-004."
```

### Concept Nodes

```yaml
concepts:
  - id: "image-dos-header"
    name: "IMAGE_DOS_HEADER and the MZ/e_lfanew Pair"
    category: windows-structure
    description: "The IMAGE_DOS_HEADER sits at the start of every PE file. Its first field e_magic is the 2-byte MZ signature (0x4D 0x5A). The e_lfanew field at offset 0x3C holds the RVA to the PE header (IMAGE_NT_HEADERS). Almost every field in IMAGE_DOS_HEADER is WORD-sized, so each field occupies two bytes in a hex dump. Manual PE parsing begins by reading e_magic to confirm a valid image and following e_lfanew to reach the NT headers."
    relevant_to: [T-004, T-013, T-016]
    tags: [pe-format, image-dos-header, mz-signature, pe-parsing]

  - id: "pe-optional-header-magic"
    name: "IMAGE_OPTIONAL_HEADER Magic (PE32 vs PE32+)"
    category: windows-structure
    description: "The Magic field in IMAGE_OPTIONAL_HEADER distinguishes 32-bit from 64-bit PE images. Value 0x10B indicates PE32 (32-bit); value 0x20B indicates PE32+ (64-bit). The selected magic determines the size and layout of the optional header that follows — PE32+ omits BaseRelocationTable and uses 64-bit ImageBase. This field is the canonical check for distinguishing binary architecture during PE parsing."
    relevant_to: [T-004]
    tags: [pe-format, optional-header, pe32-plus, architecture-detection]

  - id: "thread-context-structure"
    name: "CONTEXT Structure for Thread Hijacking"
    category: windows-structure
    description: "The CONTEXT structure on x64 contains DWORD64 fields for each general-purpose register (R0–R15 equivalents including R11, R12, R13, R14, R15) and Rip. Thread hijacking operates by suspending the target thread, calling GetThreadContext to populate a CONTEXT buffer, modifying Rip to redirect execution (and possibly setting Rsp or argument registers), then SetThreadContext and ResumeThread. The construct that must be modified is the thread context itself — not thread state or priority."
    relevant_to: [T-013]
    tags: [context-structure, thread-hijacking, register-manipulation, rip-control]

  - id: "proc-thread-attribute-list"
    name: "PROC_THREAD_ATTRIBUTE_LIST for Parent Attribution"
    category: windows-structure
    description: "PROC_THREAD_ATTRIBUTE_LIST is an opaque structure consumed via InitializeProcThreadAttributeList, UpdateProcThreadAttribute, and DeleteProcThreadAttributeList. When attached to a STARTUPINFOEX and passed to CreateProcess (with EXTENDED_STARTUPINFO_PRESENT), it allows callers to specify process creation attributes including the parent process handle (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). Setting this attribute causes the new process to inherit the parent's PID for tooling that reads process ancestry — the foundation of PPID spoofing. The structure is distinct from KPROCESS and KUSER_SHARED_DATA, which are unrelated to parent attribution."
    relevant_to: [T-015]
    tags: [startupinfoex, ppid-spoofing, process-creation, attribute-list]

  - id: "in-memory-patching"
    name: "In-Memory Patching (Runtime Image Modification)"
    category: attack-pattern
    description: "In-memory patching modifies a process's loaded image at runtime rather than the binary on disk. The patch does not survive a process restart or system reboot. Operators locate target code by enumerating processes and obtaining handles, then walking the loaded module list, scanning for the MZ signature (0x4D 0x5A) of a module of interest, parsing the PE headers to reach the IAT, and patching the import or function body. Because no disk artifact changes, file integrity scanning cannot detect the modification — only memory scanners or behavioral hooks observe it."
    relevant_to: [T-016]
    tags: [in-memory-patching, iat-walking, mz-scan, runtime-modification]

  - id: "amsi-function-patching"
    name: "AmsiScanBuffer / AmsiScanString Function Patching"
    category: attack-pattern
    description: "AMSI bypass via function patching overwrites the prologue of AmsiScanBuffer or AmsiScanString inside the loaded amsi.dll module so that the function returns AMSI_RESULT_CLEAN without performing the scan. The patch typically replaces the first bytes with a sequence that sets EAX to S_OK (0x00000000) and returns. SEC670 lists AmsiScanBuffer and AmsiScanString as the two patch targets available to an operator already injected into a process, achieved through the in-memory patching methodology (IAT walking + MZ scan)."
    relevant_to: [T-016]
    tags: [amsi, amsi-bypass, function-patching, evasion]

  - id: "pe-entrypoint-resolution"
    name: "IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint"
    category: windows-structure
    description: "AddressOfEntryPoint in IMAGE_OPTIONAL_HEADER is the RVA where execution begins when the loader hands control to the image — what the material refers to as the program's main function. It is distinct from ImageBase (the preferred load address) and from IMAGE_FILE_HEADER.PointerToSymbolTable (which points to the COFF symbol table). Manual PE parsing and process hollowing both reference this field to locate the entry point for execution redirection."
    relevant_to: [T-004, T-013]
    tags: [pe-format, optional-header, entry-point, pe-parsing]

  - id: "dll-image-format"
    name: "DLL as PE32/PE32+ Shared Image"
    category: windows-structure
    description: "Dynamic-link libraries share the PE32 or PE32+ format with executables and use extensions such as .dll and .lib. DLLs export functions consumed via the export table (verifiable with dumpbin /exports). Loaded DLLs expose their .text section for disassembly. The shared-format property is what permits module stomping, module overloading, and IAT-based function resolution across image types."
    relevant_to: [T-004, T-013, T-016]
    tags: [dll, pe-format, shared-image, exports]

  - id: "windows-handle-types"
    name: "HANDLE Type Unification of HKEY/HINSTANCE/HRSRC"
    category: os-internal
    description: "The Windows HKEY (registry key), HINSTANCE (module instance), and HRSRC (resource handle) types are all defined as HANDLE (void*). The shared underlying type is why generic handle-manipulation APIs (CloseHandle, DuplicateHandle) operate uniformly across registry, module, and resource handles. Handle-table attacks and handle blocking defenses (T-016 Block-DLL, handle blocking) exploit this commonality."
    relevant_to: [T-016]
    tags: [handle, type-system, windows-internals]
```

### Detection Insights

```yaml
detection:
  - indicator: "In-memory patch of amsi.dll function prologue"
    source: memory-scan
    confidence: medium
    relevant_to: [T-016]
    description: "Memory scanners can compare the loaded amsi.dll .text section against the on-disk copy. A patched AmsiScanBuffer or AmsiScanString prologue that returns AMSI_RESULT_CLEAN without invoking the scan routine diverges from the on-disk bytes. The scanner flags the patched region as a modified module section. SEC670 notes that in-memory patches do not survive reboots — a process restart re-loads the original bytes, which is itself a behavioral tell if a previously patched process is observed suddenly functioning correctly after a restart."
    bypassed_by: "not discussed"

  - indicator: "PPID anomaly in process tree"
    source: behavioral
    confidence: medium
    relevant_to: [T-015]
    description: "A process whose PPID points to an unrelated process lineage (e.g., a child of explorer.exe spawned from a binary path with no user-shell interaction) is observable via Windows process-creation telemetry. PROC_THREAD_ATTRIBUTE_LIST manipulation does not modify the kernel EPROCESS parent pointer beyond the initial creation, so the anomaly appears at creation time."
    bypassed_by: "not discussed"

  - indicator: "Modified module .text section in memory"
    source: memory-scan
    confidence: high
    relevant_to: [T-016]
    description: "In-memory patching leaves the on-disk binary intact but modifies the in-memory image. Memory scanners that hash the loaded .text section of a module and compare to the on-disk hash detect the divergence. SEC670 explicitly states the patch is not permanent and does not survive reboots — confirming the in-memory-only nature of the modification."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "AMSI Function Prologue Memory Divergence"
    logsource: memory-scan
    condition_summary: "Loaded amsi.dll .text section hash differs from on-disk amsi.dll .text section hash for the same module version"
  - title: "PPID Lineage Anomaly on Process Creation"
    logsource: sysmon
    condition_summary: "Sysmon EID 1 process creation where ParentImage is explorer.exe (or unrelated shell) and Image path originates from a non-user-launched location, with no parent-grandparent link via shell invocation"
```

### Operational Chains

```yaml
chains:
  - name: "In-Memory AMSI Patch Chain"
    description: "Inject into a target process, locate amsi.dll in memory, patch the scan function to return clean."
    steps:
      - technique: T-013
        role: "Acquire code execution inside the target process that loads amsi.dll (e.g., process hollowing or thread hijacking)"
      - technique: "shellcode staging"
        role: "Stage the patch payload inside the injected process"
      - technique: T-004
        role: "Walk the loaded module list and parse PE structures to locate amsi.dll's export table and the address of AmsiScanBuffer/AmsiScanString"
      - technique: T-016
        role: "Patch the function prologue so subsequent scan calls return AMSI_RESULT_CLEAN without performing the scan"
    notes: "SEC670 states the patch is not permanent and does not survive reboots — the chain must be re-run after each process restart. Target process selection is an operational decision answered before or during the op."

  - name: "Thread Hijacking via CONTEXT Modification"
    description: "Suspend a target thread, redirect Rip to payload, resume execution."
    steps:
      - technique: T-013
        role: "Identify a thread inside a target process suitable for hijacking (the WaitingThread variant)"
      - technique: "thread context capture"
        role: "Suspend the thread and call GetThreadContext to populate a CONTEXT buffer including Rip and register slots R11-R15"
      - technique: T-013
        role: "Modify the CONTEXT Rip field to point at the injected payload address"
      - technique: "context restoration"
        role: "Call SetThreadContext to commit the modified CONTEXT and ResumeThread to begin execution at the new Rip"
    notes: "SEC670 emphasizes the construct modified is the thread context — not thread state or priority. The CONTEXT structure layout includes DWORD64 register fields including Rip, which is the only field strictly required for redirection."

  - name: "PPID-Spoofed Process Creation"
    description: "Create a child process attributed to a chosen parent via PROC_THREAD_ATTRIBUTE_LIST."
    steps:
      - technique: "attribute list initialization"
        role: "Call InitializeProcThreadAttributeList to allocate a PROC_THREAD_ATTRIBUTE_LIST with one entry"
      - technique: "parent handle acquisition"
        role: "Open a handle to the desired parent process with PROCESS_CREATE_PROCESS access"
      - technique: T-015
        role: "Call UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to set the spoofed parent"
      - technique: "extended process creation"
        role: "Call CreateProcess with EXTENDED_STARTUPINFO_PRESENT and a STARTUPINFOEX containing the attribute list"
    notes: "SEC670 identifies PROC_THREAD_ATTRIBUTE_LIST as the structure for changing the parent process; the chain requires a parent handle with the correct access mask and proper attribute-list cleanup via DeleteProcThreadAttributeList."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "pe-parsing-primitives-coverage"
    title: "PE Parsing Primitives as Standalone Capability"
    kind: coverage-gap
    description: "Multiple SEC670 units cover PE format fundamentals (IMAGE_DOS_HEADER, e_lfanew, IMAGE_OPTIONAL_HEADER magic, AddressOfEntryPoint) and Lab 3.1 GetFunctionAddress explicitly walks a PE file to resolve a function address. The vault references PE parsing inside T-004 PEB Walker and T-007 process injection but does not have a dedicated card documenting the PE header walking sequence (DOS -> NT -> Optional -> DataDirectory[Export] -> export name table -> export ordinal -> function RVA). A standalone card would consolidate this reusable primitive."
    would_relate_to: [T-004, T-013, T-016]
    source_units: ["unit 10", "unit 11", "unit 12", "unit 15", "unit 16", "unit 17", "unit 18", "unit 31", "unit 32", "unit 33", "unit 34", "unit 35", "unit 36"]
    tags: [pe-format, pe-parsing, coverage-gap, primitive]

  - id: "binary-versioninfo-impersonation"
    title: "VERSIONINFO Resource Impersonation"
    kind: proposed-technique
    description: "The MalDev Academy metadata.src unit shows a VERSIONINFO resource block impersonating Google Chrome (CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, ProductVersion=112.0.5615.86). This is a distinct anti-analysis technique — embedding spoofed version metadata in the PE resource section to bypass heuristics that check binary metadata against known-good vendor signatures. The vault's T-020 Anti-Analysis Suite covers IAT camouflage and self-deletion but does not surface resource-section metadata spoofing as a documented technique."
    would_relate_to: [T-020]
    source_units: ["unit 39"]
    tags: [versioninfo, metadata-spoofing, anti-analysis, resource-section, proposed-technique]

  - id: "native-application-entry-point"
    title: "Native Application Entry Point Signature"
    kind: coverage-gap
    description: "SEC670 unit 30 asks about the function signature for a native application (the NTSTATUS NTAPI entry form vs standard C main). The vault's dark_crystal dropper is a Windows implant that interacts with NT APIs but does not document native-application entry-point conventions or the choice between standard subsystem and native subsystem builds. This is a build-time tradecraft decision that affects loader visibility and would merit a note under T-022 architecture or a dedicated section."
    would_relate_to: [T-020]
    source_units: ["unit 30"]
    tags: [native-application, entry-point, ntapi, coverage-gap]
```
