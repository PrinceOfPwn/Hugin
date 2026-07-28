## Synthesis Summary

This batch of 40 SANS SEC670 units maps primarily to T-004 (PEB Walker), T-007 (Pool Party / process injection), T-013 (Remaining injection methods), T-014 (NtCreateUserProcess), T-015 (PPID Spoofing), and T-016 (EDR Evasion Suite). The material covers PE format internals (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, Optional Header, DataDirectory, export/import directories), Windows thread structures (ETHREAD, KTHREAD, TEB, PEB) and their kernel-vs-user address space layout, x64 calling conventions (fastcall register usage, the 32-byte shadow space at RSP+20h), Windows API patterns (HANDLE-typed Create* APIs, SAL annotations, InitializeProcThreadAttributeList), and walk-throughs of thread hijacking, process hollowing, and PE injection. The knowledge gap this fills is the Windows internals literacy that source code assumes: why the TEB is the only thread structure accessible from user mode (making PEB-based module resolution possible via gs:[0x60]), how GetProcAddress resolves exports through three parallel RVA arrays, why x64 syscall stubs must account for shadow space, and how PROC_THREAD_ATTRIBUTE_LIST underpins PPID spoofing. Several units are duplicates (units 26–27, 29–33, 38–40 repeat the same review questions) and were treated as a single knowledge point each. No units were skipped as off-theme — all 40 fall within offensive Windows tradecraft, though many are foundational rather than technique-specific.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "pe-image-export-directory"
    target: "T-004"
    type: enables
    rationale: "The IMAGE_EXPORT_DIRECTORY structure with its AddressOfFunctions, AddressOfNames, and AddressOfNameOrdinals arrays is the data the PEB walker traverses to resolve API functions by name via DJB2 hash — the export directory is what makes manual module resolution possible without GetProcAddress."

  - source: "T-004"
    target: "T-008"
    type: enables
    rationale: "Threadless injection depends on export hijack — resolving and overwriting a target process's exported function. The PEB walker's ability to walk export directories in a remote process without using GetProcAddress enables this technique."

  - source: "pe-thread-context"
    target: "T-013"
    type: requires
    rationale: "Thread hijacking requires modifying the thread's CONTEXT structure (SetThreadContext) after suspending the thread — the SANS walk-through explicitly lists 'Modify thread's context' as a mandatory step in the hijack sequence."

  - source: "proc-thread-attribute-list"
    target: "T-015"
    type: requires
    rationale: "PPID spoofing uses InitializeProcThreadAttributeList with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute to set the parent process handle — the attribute list API is the mechanism that makes PPID spoofing possible."

  - source: "T-016"
    target: "edr-userland-hooks"
    type: counters
    rationale: "The SANS material describes binary patching of NTDLL as modifying 'how functions of interest' execute — NTDLL unhook (part of T-016) restores the original .text section, countering EDR userland hooks that patch ntdll syscall stubs."

  - source: "T-014"
    target: "T-013"
    type: alternative_to
    rationale: "NtCreateUserProcess (T-014) provides direct NT process creation as an alternative to the CreateProcess-based process hollowing sequence described in the SANS walk-through — both create a suspended process for subsequent manipulation, but NtCreateUserProcess avoids the Win32 layer."

  - source: "pe-optional-header"
    target: "T-013"
    type: enables
    rationale: "Process hollowing and PE injection both require parsing the Optional Header to locate AddressOfEntryPoint, SizeOfImage, and section alignment values — the SANS walk-throughs list 'Copy over headers/sections' and 'PE Headers' as explicit steps."

  - source: "x64-shadow-space"
    target: "T-001"
    type: concept_link
    rationale: "Indirect syscall stubs (RecycledGate) must honor the x64 ABI shadow space at RSP+20h — the SANS material explains that the first 0x20 bytes of stack space are reserved as a shadow store for the callee, which syscall stubs that emulate function calls must account for."
```

### Concept Nodes

```yaml
concepts:
  - id: "pe-image-dos-header"
    name: "IMAGE_DOS_HEADER and e_lfanew RVA"
    category: windows-structure
    description: "The IMAGE_DOS_HEADER sits at the start of every PE file. Its e_lfanew field (a DWORD at offset 0x3C) is an RVA added to the module base address to locate the IMAGE_NT_HEADERS structure, whose first field is the 4-byte 'PE\\0\\0' Signature. The SANS material emphasizes that the Signature is a DWORD (4 bytes), not 2 bytes like the DOS e_magic, and that e_lfanew is the bridge between the DOS stub and the NT headers."
    relevant_to: [T-004, T-007, T-013]
    tags: [pe-format, dos-header, e_lfanew, rva, module-resolution]

  - id: "pe-optional-header"
    name: "IMAGE_OPTIONAL_HEADER — Magic, Alignment, AddressOfEntryPoint"
    category: windows-structure
    description: "The Optional Header follows IMAGE_FILE_HEADER in the PE format. Its Magic field distinguishes PE32 (0x10B) from PE32+ (0x20B). SectionAlignment and FileAlignment control how sections are laid out in memory versus on disk. AddressOfEntryPoint is the RVA of the program's entry point — the field that process hollowing and PE injection use to locate where to redirect execution after copying sections."
    relevant_to: [T-004, T-007, T-013]
    tags: [pe-format, optional-header, magic, alignment, entry-point]

  - id: "pe-image-export-directory"
    name: "IMAGE_EXPORT_DIRECTORY and GetProcAddress Resolution"
    category: windows-structure
    description: "The IMAGE_EXPORT_DIRECTORY contains three parallel arrays: AddressOfFunctions (RVA array of NumberOfFunctions entries), AddressOfNames (RVA array of NumberOfNames string pointers), and AddressOfNameOrdinals (index array mapping name entries to function entries). GetProcAddress walks AddressOfNames to find the requested function name, uses the parallel ordinal to index into AddressOfFunctions, and returns the RVA. The SANS material notes this is the most difficult part of the PE format to parse manually."
    relevant_to: [T-004, T-008]
    tags: [pe-format, exports, getprocaddress, rva-arrays, export-resolution]

  - id: "pe-image-import-descriptor"
    name: "IMAGE_IMPORT_DESCRIPTOR Structure"
    category: windows-structure
    description: "The import directory is an array of IMAGE_IMPORT_DESCRIPTOR structures, terminated by a zero-filled entry. Each descriptor has an OriginalFirstThunk (ILT pointer) and a FirstThunk (IAT pointer). The SANS material presents this structure as the counterpart to the export directory, showing how a PE file declares its dependencies — relevant to understanding IAT camouflage and module overloading."
    relevant_to: [T-004, T-007, T-013]
    tags: [pe-format, imports, iat, ilt, image-import-descriptor]

  - id: "ethread-kthread-teb-layout"
    name: "ETHREAD/KTHREAD/TEB — System vs User Address Space"
    category: os-internal
    description: "The kernel holds ETHREAD and KTHREAD objects in system address space, inaccessible from user mode. Only the TEB resides in process address space. The TEB contains the NT_TIB (with StackBase and StackLimit), ClientId, and a pointer to the PEB. This layout is why user-mode code accesses the PEB through the TEB (via gs:[0x60] on x64) rather than through the KTHREAD — the kernel structures are off-limits to user-mode implants."
    relevant_to: [T-004, T-007, T-013]
    tags: [thread-structure, teb, peb, kthread, ethread, system-address-space, gs-segment]

  - id: "x64-shadow-space"
    name: "x64 ABI Shadow Space (RSP+20h)"
    category: os-internal
    description: "In the x64 calling convention, the caller allocates 32 bytes (0x20) of shadow store at the top of the stack before calling a function. This space allows the callee to save the first four register arguments (RCX, RDX, R8, R9) to the stack if needed. Stack arguments therefore begin at RSP+20h, not RSP. The SANS material confirms this is a shadow store (not shadow stack enforcement) — the 0x20 bytes are reserved for the callee's use, not for return address protection."
    relevant_to: [T-001, T-002, T-003]
    tags: [x64-abi, calling-convention, shadow-space, rsp, stack-layout]

  - id: "x64-fastcall-convention"
    name: "x64 fastcall — RCX/RDX/R8/R9 Register Arguments"
    category: os-internal
    description: "The x64 calling convention uses fastcall semantics: the first four integer/pointer arguments are passed in RCX, RDX, R8, and R9, with remaining arguments on the stack. The SANS material identifies fastcall as the convention that primarily uses ECX/RCX and EDX/RDX registers. This is relevant to syscall stub construction since NT functions receive their syscall number in EAX and arguments in the fastcall register sequence."
    relevant_to: [T-001, T-002, T-003]
    tags: [x64-abi, fastcall, calling-convention, register-arguments]

  - id: "proc-thread-attribute-list"
    name: "PROC_THREAD_ATTRIBUTE_LIST and InitializeProcThreadAttributeList"
    category: windows-structure
    description: "InitializeProcThreadAttributeList creates a list of attributes applied to a thread or process during creation. The SANS material explains the function uses SAL annotations (_Out_writes_bytes_to_opt_ and _When_) to describe conditional behavior: when lpAttributeList is nullptr the function returns the required size, when non-null it initializes the list. The PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute within this list is the mechanism that enables PPID spoofing."
    relevant_to: [T-015, T-014]
    tags: [process-creation, attribute-list, ppid-spoofing, sal-annotations]

  - id: "binary-patching-memory-disk"
    name: "Binary Patching — In-Memory vs On-Disk Modification"
    category: attack-pattern
    description: "Binary patching modifies a binary as it resides on disk or in memory to change how it executes. The SANS material notes that patching system files like NTDLL directly in System32 would 'draw way too much attention' because hooks would be implemented everywhere. Instead, patching secondary or tertiary DLLs that NTDLL loads is more surgical. AV/EDR solutions themselves use in-memory binary patching to hook functions of interest — this is the mechanism operators counter with NTDLL unhooking."
    relevant_to: [T-016]
    tags: [binary-patching, ntdll, edr-hooking, evasion, persistence]

  - id: "pe-thread-context"
    name: "Thread CONTEXT Structure and Hijacking"
    category: windows-structure
    description: "Thread hijacking requires modifying the thread's CONTEXT structure via GetThreadContext/SetThreadContext. The SANS walk-through lists the sequence: obtain handle to target process, obtain handle to target's thread, allocate memory, suspend the thread, write DLL path or shellcode to the allocated memory, modify the thread's context (typically setting RIP to the shellcode address), then resume the thread. The SANS review question confirms that 'Thread context' is the construct that must be modified during hijacking — not thread state or priority."
    relevant_to: [T-007, T-013]
    tags: [thread-hijacking, context-structure, getthreadcontext, setthreadcontext, rip]

  - id: "windows-handle-types"
    name: "HANDLE-Based API Type System (HKEY, HINSTANCE, HRSRC)"
    category: os-internal
    description: "Windows API types such as HKEY, HINSTANCE, and HRSRC are all of type HANDLE underneath. The SANS material emphasizes this uniformity: despite different semantic names (registry key, instance, resource), they are all opaque handle values. This matters for understanding handle manipulation, duplicate handle operations, and the block-handle evasion technique where an implant restricts external handle access to its process."
    relevant_to: [T-016]
    tags: [handle-types, windows-api, hkey, hinstance, handle-manipulation]

  - id: "process-hollowing-sequence"
    name: "Classic Process Hollowing Sequence"
    category: attack-pattern
    description: "The SANS walk-through of process hollowing defines the canonical sequence: create a new suspended process (e.g., notepad.exe), open the replacement file (evil.exe), allocate memory in the suspended process, copy over the PE headers and sections from the replacement file, apply base relocations, fix the import table, then resume execution at the replacement's entry point. This differs from PE injection in that hollowing replaces the entire image rather than injecting a secondary PE alongside the host."
    relevant_to: [T-013]
    tags: [process-hollowing, suspended-process, pe-copy, relocation, injection-sequence]

  - id: "pe-injection-sequence"
    name: "PE Injection Sequence"
    category: attack-pattern
    description: "The SANS walk-through of PE injection defines the sequence: obtain a handle to the target process via OpenProcess, allocate memory in the target via VirtualAllocEx, copy the PE header and sections into the allocated memory, apply relocations using the .reloc section data, resolve imports and build the IAT, then create a remote thread via CreateRemoteThread pointing at the injected PE's entry point. The SANS material notes this method requires no shellcode knowledge — it is done purely in C/C++ with Windows APIs."
    relevant_to: [T-007, T-013]
    tags: [pe-injection, virtualallocex, createremotethread, relocation, iat, injection-sequence]
```

### Detection Insights

```yaml
detection:
  - indicator: "NTDLL.dll .text section modification in System32 on disk"
    source: windows-security-log
    confidence: high
    relevant_to: [T-016]
    description: "The SANS material explicitly warns that patching NTDLL where it sits in System32 would 'draw way too much attention' because hooks would be implemented all over the place. Windows File Integrity monitoring and Windows Resource Protection (WRP) detect modifications to system files in System32. A defender monitoring for writes to C:\\Windows\\System32\\ntdll.dll catches on-disk binary patching attempts."
    bypassed_by: "The SANS material suggests patching secondary or tertiary DLLs that NTDLL loads rather than patching NTDLL directly in System32 — this avoids system file integrity alerts while still achieving hook placement."

  - indicator: "Remote thread creation in target process via CreateRemoteThread"
    source: etw
    confidence: high
    relevant_to: [T-007, T-013]
    description: "The SANS PE injection walk-through uses CreateRemoteThread as the execution trigger. CreateRemoteThread generates ETW events from the Microsoft-Windows-Kernel-Thread provider and is flagged by most EDR solutions as suspicious cross-process thread creation. The event includes the source PID, target PID, start address, and creation flags."
    bypassed_by: "not discussed"

  - indicator: "Thread context modification (SetThreadContext on remote thread)"
    source: etw
    confidence: medium
    relevant_to: [T-013]
    description: "The SANS thread hijacking walk-through modifies the thread's context via SetThreadContext after suspending the target thread. NtSetContextThread on a thread in a different process is an ETW-TI observable event. The event includes the target thread handle, the modified register set, and the source process. Defenders alert on RIP/IP modifications that redirect to unbacked memory."
    bypassed_by: "not discussed"

  - indicator: "Suspended process creation followed by memory write to image region"
    source: behavioral
    confidence: medium
    relevant_to: [T-013]
    description: "The SANS process hollowing walk-through creates a suspended process then writes PE headers and sections into it. The behavioral pattern — CREATE_SUSPENDED followed by NtWriteVirtualMemory targeting the process's image base — is a classic hollowing heuristic. Defenders correlate the suspended creation with subsequent writes to the same region as the original image."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "NTDLL System32 File Modification"
    logsource: windows-security
    condition_summary: "Detect any write, rename, or replace operation targeting C:\\Windows\\System32\\ntdll.dll or other system DLLs in System32"

  - title: "Remote Thread Creation via CreateRemoteThread"
    logsource: etw
    condition_summary: "ETW Kernel-Thread event for CreateRemoteThread where TargetPid != SourcePid"

  - title: "Suspended Process with Subsequent Image-Region Write"
    logsource: etw
    condition_summary: "Sequence: process created with CREATE_SUSPENDED flag, followed by NtWriteVirtualMemory targeting an address within the target process's image base range"
```

### Operational Chains

```yaml
chains:
  - name: "Thread Hijacking Injection"
    description: "Hijack an existing thread in a target process to execute injected shellcode or DLL path"
    steps:
      - technique: T-013
        role: "Obtain handle to target process and target thread via OpenProcess and OpenThread"
      - technique: T-013
        role: "Allocate memory in target process for shellcode or DLL path"
      - technique: T-013
        role: "Suspend the target thread and write payload to allocated memory"
      - technique: T-013
        role: "Modify thread CONTEXT structure (RIP) to point at injected payload"
      - technique: T-013
        role: "Resume thread to trigger execution of injected payload"
    notes: "The SANS material lists these steps explicitly. The walk-through uses notepad.exe as the target. The review question confirms that Thread context (not state or priority) is the construct that must be modified."

  - name: "Process Hollowing"
    description: "Replace a legitimate process's image in memory with a malicious PE"
    steps:
      - technique: T-013
        role: "Create a new suspended process (e.g., notepad.exe) via CreateProcess with CREATE_SUSPENDED"
      - technique: T-013
        role: "Open replacement PE file and parse its headers"
      - technique: T-013
        role: "Allocate memory in suspended process and copy PE headers and sections"
      - technique: T-013
        role: "Apply base relocations and fix import table for new image base"
      - technique: T-013
        role: "Resume execution at replacement PE entry point"
    notes: "The SANS walk-through uses hproc.exe as the injector, notepad.exe as the host, and evil.exe as the replacement. The material notes this differs from PE injection in that it replaces the entire image rather than co-locating a secondary PE."

  - name: "PE Injection via Remote Thread"
    description: "Inject a complete PE into a remote process and execute via CreateRemoteThread"
    steps:
      - technique: T-007
        role: "Obtain handle to target process via OpenProcess"
      - technique: T-013
        role: "Allocate memory in target via VirtualAllocEx"
      - technique: T-013
        role: "Copy PE header and sections into allocated memory"
      - technique: T-013
        role: "Apply relocations using .reloc section data and build import table"
      - technique: T-013
        role: "Create remote thread via CreateRemoteThread pointing at injected PE entry point"
    notes: "The SANS material emphasizes this method requires no shellcode knowledge — it operates purely through C/C++ and Windows APIs. The .reloc section is processed to handle image base differences between the source and target allocation."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "pe-format-parsing-foundation"
    title: "PE Format Parsing as Foundational Technique Area"
    kind: coverage-gap
    description: "The SANS material dedicates substantial coverage to PE format internals — IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, Optional Header fields, DataDirectory entries, IMAGE_EXPORT_DIRECTORY with its three parallel RVA arrays, and IMAGE_IMPORT_DESCRIPTOR. The vault references PE parsing in T-004 (PEB Walker), T-007 (pe.rs), and T-013 (PE Loader) but does not have a dedicated card documenting the PE parsing primitives that multiple techniques depend on. The export directory resolution algorithm (walk AddressOfNames, index into AddressOfNameOrdinals, use ordinal to index AddressOfFunctions) is described in enough detail in the SANS material to warrant its own concept cluster."
    would_relate_to: [T-004, T-007, T-013]
    source_units: ["unit 3", "unit 5", "unit 6", "unit 7", "unit 8", "unit 9", "unit 18", "unit 24"]
    tags: [pe-format, coverage-gap, foundational, export-resolution, import-parsing]

  - id: "x64-abi-syscall-stub-construction"
    title: "x64 ABI and Shadow Space for Syscall Stub Construction"
    kind: coverage-gap
    description: "The SANS material covers x64 calling conventions (fastcall register assignment, the 32-byte shadow store at RSP+20h) that directly govern how syscall stubs must be constructed. The vault's T-001 (RecycledGate), T-002 (Hell's Gate), and T-003 (VEH Gate) all construct inline assembly stubs that must honor the shadow space convention. The material's explanation of why stack arguments start at RSP+20h (the callee's shadow store, not shadow stack enforcement) clarifies a subtle point about stub layout that source code alone does not convey."
    would_relate_to: [T-001, T-002, T-003]
    source_units: ["unit 28", "unit 29", "unit 30", "unit 31", "unit 32", "unit 33"]
    tags: [x64-abi, shadow-space, fastcall, syscall-stub, coverage-gap]

  - id: "binary-patching-as-distinct-technique"
    title: "Binary Patching — Memory vs Disk Modification"
    kind: cross-source-convergence
    description: "The SANS material treats binary patching as a distinct operational concept: modifying binaries on disk or in memory to change execution behavior. It explicitly discusses patching NTDLL, patching secondary/tertiary DLLs that NTDLL loads, and notes that AV/EDR solutions themselves use in-memory binary patching as their hooking mechanism. The vault's T-016 (NTDLL unhook) is a specific instance of this broader pattern. The SANS framing suggests binary patching deserves recognition as a cross-cutting technique that connects EDR evasion (T-016), persistence (patching DLLs for stable hooks), and IAT camouflage (T-020)."
    would_relate_to: [T-016, T-017, T-020]
    source_units: ["unit 20", "unit 21", "unit 22"]
    tags: [binary-patching, ntdll, edr-hooking, cross-source-convergence, persistence]

  - id: "token-manipulation-via-openprocesstoken"
    title: "Process Token Access and Manipulation"
    kind: coverage-gap
    description: "The SANS material introduces OpenProcessToken as the API for obtaining a handle to a process's access token, with the course listing TokenThief as a dedicated lab. The vault does not currently have a technique card covering token manipulation, token impersonation, or token theft — these appear only as implicit dependencies of privilege escalation (T-017 references UAC bypass but not token theft). The SANS material's inclusion of TokenThief as a lab alongside injection techniques suggests token manipulation is a peer capability to process injection in the operational toolkit."
    would_relate_to: [T-015, T-017]
    source_units: ["unit 4", "unit 19"]
    tags: [token-manipulation, openprocesstoken, token-theft, privilege-escalation, coverage-gap]
```