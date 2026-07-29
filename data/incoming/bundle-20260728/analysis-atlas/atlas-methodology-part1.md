## Synthesis Summary

This batch maps to T-004 (PEB Walker), T-007 (Pool Party and the broader process-injection family), T-016 (EDR Evasion Suite — specifically proxy DLL and the underlying DLL search order), and T-023 (Client Capabilities — recon via directory and process enumeration). The bulk of the 40 units consists of SANS SEC670 course roadmaps, CRTO Rules-of-Engagement content, organizational "Red Team as customer" material, and motivational/process slides that do not map to any vault technique and contribute no technical tradecraft. A smaller subset (units 2, 16, 33, 34, 35–39) covers on-theme Windows internals: the Windows Object Manager, executive/kernel/user object division, the CreateFile→NtCreateFile→executive-object→handle flow, the Create* API family, the DLL search order, and FindFirstFileA directory enumeration. These units are sparse on detection content and operational chains. The gap filled is foundational: source code in `dark_crystal` and `client_rust` calls `CreateThread`, `NtCreateFile`, `FindFirstFileA`, and similar APIs without explaining the object-manager abstraction that makes handles cross-process-capable, why user space receives handles rather than object pointers, and why DLL placement on the search path determines whether a proxy DLL loads. Roughly 28 of the 40 units were skipped as off-theme (course metadata, RoE/legal, organizational workflow, motivational slides).

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "windows-object-manager-handle-model"
    target: "T-007"
    type: "concept_link"
    rationale: "Process injection techniques rely on cross-process handles returned by the object manager (e.g., OpenProcess, CreateThread on a remote process). The SEC670 material states that all objects live in system address space and user space only receives handles, which is why a handle with PROCESS_CREATE_THREAD access can drive execution in another process."
  - source: "dll-search-order"
    target: "T-016"
    type: "concept_link"
    rationale: "Proxy DLL placement in T-016 depends on the documented Windows search order (config-file home, current directory, GetSystemDirectory, GetWindowsDirectory, %PATH%). The material lists this exact 5-step order, which is the mechanism the proxy DLL evasion leverages."
  - source: "findfirstfile-directory-walk"
    target: "T-023"
    type: "concept_link"
    rationale: "FindFirstFileA returning a search handle and WIN32_FIND_DATA structure is the primitive SEC670 teaches for directory enumeration, matching the recon/sysinfo-collect role in T-023 client capabilities."
  - source: "T-004"
    target: "windows-object-manager-handle-model"
    type: "requires"
    rationale: "PEB walking for module resolution (T-004) operates on the in-process representation of loaded modules, but the resulting HMODULE values are handles into the object manager's Section/Process object space. Understanding the handle/object split explains why PEB walking avoids the handle table entirely and is not observable through handle-based telemetry."
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-object-manager-handle-model"
    name: "Windows Object Manager Handle/Object Model"
    category: "os-internal"
    description: "Windows represents system resources (files, processes, threads, registry keys, sections, tokens, mutexes, desktops) as data structures in system address space. The kernel creates the object at the request of a user application and returns a handle to the caller; user space never touches the object directly. The SEC670 material notes over 4,000 executive object types, many not reachable through documented Win32 APIs. This separation is why cross-process operations require handle duplication and why object types such as Process and Section gate injection primitives."
    relevant_to: ["T-007", "T-016", "T-004"]
    tags: ["windows-internals", "object-manager", "handles", "kernel", "executive-objects"]
  - id: "executive-object-types"
    name: "Executive Object Types (Process, Thread, Section, Token, Mutex, Key, Desktop)"
    category: "windows-structure"
    description: "The Windows executive implements object types that gate operations relevant to offensive tradecraft: Process objects own a virtual address space controlling one or more Thread objects; Section objects back shared memory and file mappings used by mapping injection and module loaders; Token objects hold the security profile that governs what a thread/process can access; Mutex objects serialize access; Key objects reference registry data; Desktop objects bound window-station-scoped UI operations. The full type list is visible via the WinObj utility from Sysinternals."
    relevant_to: ["T-007", "T-014", "T-023"]
    tags: ["windows-internals", "object-types", "executive", "process", "thread", "section", "token"]
  - id: "createfile-to-ntcreatefile-flow"
    name: "CreateFile to NtCreateFile to Executive Object Flow"
    category: "os-internal"
    description: "A Win32 API call such as CreateFile transitions to NtCreateFile, which causes the object manager to allocate an executive File object in system space and return a handle to the user-mode caller. The same flow applies to CreateThread, CreateEvent, CreateToolhelp32Snapshot, and the broader Create* family (nearly 100 functions). The transition crosses the user/system boundary via the NT syscall dispatcher, which is the layer EDRs hook and the layer indirect-syscall techniques (T-001, T-002, T-003) bypass."
    relevant_to: ["T-001", "T-002", "T-003", "T-007"]
    tags: ["windows-internals", "create-apis", "syscall", "nt-api", "user-kernel-boundary"]
  - id: "dll-search-order"
    name: "Windows DLL Search Order"
    category: "os-internal"
    description: "When a process resolves a DLL by name without a full path, Windows searches in a documented order: (1) the directory containing the configuration file, (2) the current directory of the process, (3) the system directory returned by GetSystemDirectory, (4) the Windows directory returned by GetWindowsDirectory, and (5) directories listed in %PATH%. The current-directory slot (2) is the basis for DLL search-order hijacking and is constrained by SafeDLLSearchMode and the DllCharacteristics IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE-equivalent flags. This order governs where a proxy or hijacked DLL must be placed to load in preference to the legitimate module."
    relevant_to: ["T-016", "T-013"]
    tags: ["windows-internals", "dll", "search-order", "hijacking", "proxy-dll"]
  - id: "findfirstfile-directory-walk"
    name: "FindFirstFile/FindNextFile Directory Enumeration"
    category: "os-internal"
    description: "FindFirstFileA/W initializes a directory walk by returning a search handle and populating a WIN32_FIND_DATA structure with the first matching entry. The wildcard-capable lpFileName parameter accepts patterns such as C:\\Windows\\System32\\*.dll. Subsequent FindNextFile calls drain the search until no more matches exist, at which point the handle must be closed with FindFindClose to avoid handle leaks. The ANSI variant should be avoided for non-English paths because it cannot represent characters outside the system code page."
    relevant_to: ["T-023"]
    tags: ["windows-api", "file-enumeration", "recon", "win32-find-data"]
  - id: "hinstance-hmodule-interchangeability"
    name: "HINSTANCE and HMODULE Handle Equivalence"
    category: "windows-structure"
    description: "In the Win32 API, HINSTANCE and HMODULE are interchangeable handle types that both reference a loaded module's base address. The equivalence exists for historical 16-bit Windows compatibility, where an instance handle and a module handle were distinct concepts. Modern 32-bit and 64-bit Windows treats GetModuleHandle and GetInstanceHandle results as the same value, which matters for PEB-walking code that resolves module bases via either API."
    relevant_to: ["T-004"]
    tags: ["windows-internals", "handles", "module-resolution", "peb"]
```

### Detection Insights

```yaml
detection:
  - indicator: "DLL loaded from outside the system or Windows directory"
    source: "sysmon"
    confidence: "medium"
    relevant_to: ["T-016"]
    description: "Sysmon Event ID 7 (Image Loaded) records every DLL loaded into a process, including the full path. A DLL whose path matches the search-order slots above the system directory (current directory, application directory, %PATH% entries) and shares a name with a known legitimate module is the signature of a search-order hijack or proxy DLL placement. Correlating the loaded image path against the legitimate vendor install location surfaces the discrepancy."
    bypassed_by: "not discussed"
  - indicator: "Process opening handles to foreign Process objects"
    source: "windows-security-log"
    confidence: "low"
    relevant_to: ["T-007"]
    description: "The Windows security log Event ID 4656 (A handle to an object was requested) and 4663 (An attempt was made to access an object) record access-mask requests against Process, Thread, and Section object types when object-access auditing is enabled. Cross-process handle acquisition with PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION is the precondition for most injection techniques in T-007. Without SACL configuration on the Object Types the events do not fire."
    bypassed_by: "not discussed"
sigma_ideas:
  - title: "DLL Load from Current Directory or User-Writable Path"
    logsource: "sysmon"
    condition_summary: "EventID 7 where ImageLoaded path is not under System32/SysWOW64/Windows and matches the name of a known system DLL"
  - title: "Cross-Process Handle with VM_WRITE and CREATE_THREAD"
    logsource: "windows-security"
    condition_summary: "EventID 4656 where ObjectType is Process and AccessMask contains PROCESS_VM_WRITE and PROCESS_CREATE_THREAD bits and SubjectProcessId != TargetProcessId"
# additional detection coverage was not supported by the batch; the SEC670 material in these units is foundational Windows internals and does not surface ETW providers, kernel callbacks, or memory-scanner heuristics by name.
```

### Operational Chains

```yaml
chains:
  - name: "Object-Manager-Grounded Process Injection Flow"
    description: "Conceptual chain linking the object-manager abstraction to a concrete injection primitive"
    steps:
      - technique: "T-004"
        role: "PEB walk resolves the target module base (HMODULE) without invoking the object manager handle table, avoiding handle-based telemetry"
      - technique: "T-007"
        role: "A handle to the target Process executive object is acquired via OpenProcess; the kernel object manager mediates the cross-process reference"
      - technique: "T-007"
        role: "NtAllocateVirtualMemory and NtWriteVirtualMemory operate on the target Process object's address space through the handle"
      - technique: "T-007"
        role: "CreateThread (or NtCreateThreadEx) creates a Thread executive object owned by the target Process, returning a handle the caller can wait on"
    notes: "The SEC670 units in this batch describe the object/handle model conceptually (units 33, 35-39) but do not walk through a concrete injection sequence. The chain above is inferred from the relationship between the documented Create* API family and the object types table; no step timing or environmental prerequisites are stated in the source material."
# the batch does not contain explicit step-by-step operational sequences; units 1, 12, and 40 describe engagement-planning methodology rather than technical execution sequences.
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "windows-object-manager-foundational-concept"
    title: "Windows Object Manager as a Foundational Concept Card"
    kind: "coverage-gap"
    description: "Multiple SEC670 units (35-39) treat the Windows object manager — executive objects, the 4,000+ object type space, the kernel/user object split, and the Create*→Nt*→executive-object→handle flow — as prerequisite knowledge for understanding why handles mediate every cross-process and cross-thread operation. The vault documents techniques that depend on this model (T-007 injection, T-016 handle blocking, T-004 PEB walking) but has no standalone concept card explaining the object manager itself. Adding one would let operators trace why handle-based detection fires, why PEB walking avoids the handle table, and why Section objects are the backbone of mapping injection."
    would_relate_to: ["T-004", "T-007", "T-016"]
    source_units: ["unit 33", "unit 35", "unit 36", "unit 37", "unit 38", "unit 39"]
    tags: ["windows-internals", "object-manager", "handles", "coverage-gap"]
  - id: "dll-search-order-and-hijack-primitives"
    title: "DLL Search Order as Standalone Tradecraft"
    kind: "coverage-gap"
    description: "Unit 34 documents the 5-step DLL search order that underpins proxy DLL loading (T-016) and DLL hijacking broadly. The vault's proxy_dll.rs file implements the technique but the underlying search-order mechanism, SafeDLLSearchMode constraints, KnownDLLs registry exemption, and the role of the current-directory slot are not surfaced as a concept node. Documenting the search order separately would clarify why proxy DLLs must be placed in specific paths and when the technique fails (e.g., when the legitimate DLL is in KnownDLLs)."
    would_relate_to: ["T-016", "T-013"]
    source_units: ["unit 34"]
    tags: ["dll", "search-order", "proxy-dll", "hijacking", "coverage-gap"]
  - id: "executive-object-types-as-telemetry-surface"
    title: "Executive Object Types as a Telemetry Taxonomy"
    kind: "proposed-technique"
    description: "Unit 38 tabulates executive object types (Process, Thread, Section, Token, Mutex, Key, Desktop) and notes that object-access auditing is gated per object type. The vault currently treats detection concepts inline per technique card. A cross-cutting concept card mapping object types to the Event IDs 4656/4663/4658/4660 access masks they emit would give operators a single reference for which kernel-level handle operations are auditable per object class, enabling more precise EDR-evasion planning around which object types to touch."
    would_relate_to: ["T-007", "T-016", "T-015"]
    source_units: ["unit 38"]
    tags: ["windows-internals", "object-types", "auditing", "detection", "proposed-technique"]
```