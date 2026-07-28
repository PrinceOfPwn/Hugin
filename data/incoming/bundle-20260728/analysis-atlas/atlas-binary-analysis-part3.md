## Synthesis Summary

The batch consists of 40 SANS SEC670 units covering Windows API reference (FindFirstFile/FindNextFile/FindClose, GetUserProfileDirectoryA, NetUserEnum, GetAdapterAddresses, registry enumeration APIs) and Portable Executable format structure (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DATA_DIRECTORY). The material maps to T-004 (PEB Walker — manual module resolution via PE parsing), T-006 (Phantom Stubs — MEM_IMAGE-backed syscall stubs), T-007 (Process Injection — PE loading, module stomping, reflective loader), T-013 (Remaining Methods including PE Loader), T-017 (Persistence Suite — registry-walking APIs for COM hijack and schtask persistence), and T-023 (Client Capabilities — recon/sysinfo enumeration primitives). The training fills the structural knowledge gap between reading Rust source that references IMAGE_NT_HEADERS or RegQueryValueExW and understanding why each field exists, what the 0x10B/0x20B magic numbers discriminate, and how e_lfanew RVA arithmetic locates the PE header from a module base. Most units are API reference rather than tradecraft; detection bypass, operational sequencing, and EDR-specific behavior are sparsely supported.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: image-dos-header
    target: T-004
    type: enables
    rationale: "Manual module resolution via PEB walking depends on parsing IMAGE_DOS_HEADER->e_lfanew to locate the IMAGE_NT_HEADERS, then walking the export directory for symbol resolution"
  - source: image-optional-header
    target: T-007
    type: enables
    rationale: "PE loading techniques (module overloading, module stomping, reflective loader) require reading AddressOfEntryPoint, ImageBase, and DataDirectory entries from IMAGE_OPTIONAL_HEADER to map sections and resolve imports"
  - source: registry-walking-pattern
    target: T-017
    type: requires
    rationale: "COM hijack persistence and schtask persistence require enumerating registry keys and values via RegOpenKeyExW/RegQueryValueExW/RegEnumValue to identify hijack targets and verify existing entries"
  - source: pe-magic-numbers
    target: T-006
    type: concept_link
    rationale: "Phantom stubs construct MEM_IMAGE-backed syscall stubs; the 0x10B/0x20B Optional Header Magic field discriminates whether the fabricated PE is 32-bit or 64-bit"
  - source: netuserenum-resume-handle
    target: T-023
    type: chains_to
    rationale: "User account enumeration via NetUserEnum feeds recon/sysinfo collection in client capabilities, producing account lists for lateral movement planning"
  - source: win32-find-data-walk
    target: T-023
    type: chains_to
    rationale: "FindFirstFile/FindNextFile directory walks underlie file-based recon exfil enumeration in client capabilities"
  - source: image-data-directory
    target: image-nt-headers
    type: concept_link
    rationale: "IMAGE_DATA_DIRECTORY entries are reached via the DataDirectory array inside IMAGE_OPTIONAL_HEADER, which is itself reached via e_lfanew in IMAGE_DOS_HEADER; the chain of pointers is the standard PE traversal path"
```

### Concept Nodes

```yaml
concepts:
  - id: "image-dos-header"
    name: "IMAGE_DOS_HEADER and the e_lfanew Field"
    category: windows-structure
    description: "The MS-DOS 2.0 EXE header at the start of every PE file. The first two bytes spell 'MZ' (Mark Zbikowski's initials). The e_lfanew field at offset 0x3C is an RVA added to the module base address to locate the IMAGE_NT_HEADERS Signature field. Without e_lfanew, parsers cannot reach the PE header."
    relevant_to: [T-004, T-006, T-007, T-013]
    tags: [pe-format, windows-structure, module-resolution]

  - id: "image-nt-headers"
    name: "IMAGE_NT_HEADERS Structure"
    category: windows-structure
    description: "Structure reached via e_lfanew containing a DWORD Signature field ('PE\\0\\0', 4 bytes including the two trailing NULs), an IMAGE_FILE_HEADER, and an IMAGE_OPTIONAL_HEADER (32-bit or 64-bit variant). The struct is typedef'd differently for IMAGE_NT_HEADERS32 vs IMAGE_NT_HEADERS64; the _WIN64 macro selects which one is exported as IMAGE_NT_HEADERS in headers."
    relevant_to: [T-004, T-007, T-013]
    tags: [pe-format, windows-structure, header-parsing]

  - id: "image-optional-header"
    name: "IMAGE_OPTIONAL_HEADER64 and Key Fields"
    category: windows-structure
    description: "The Optional Header for PE32+ images. Notable fields: Magic (0x20B for PE32+, 0x10B for PE32), AddressOfEntryPoint (RVA of entry point), ImageBase (preferred load address, ULONGLONG for 64-bit), DllCharacteristics (CFG, ASLR, DEP flags), and DataDirectory array of IMAGE_DATA_DIRECTORY entries indexed by IMAGE_DIRECTORY_ENTRY_* constants (Import, Export, Resource, etc.)."
    relevant_to: [T-004, T-006, T-007, T-013]
    tags: [pe-format, windows-structure, optional-header, pe32-plus]

  - id: "image-data-directory"
    name: "IMAGE_DATA_DIRECTORY and Import/Export Directory Lookup"
    category: windows-structure
    description: "Each IMAGE_DATA_DIRECTORY entry has a VirtualAddress (RVA) and Size (DWORD pair). The array at the end of IMAGE_OPTIONAL_HEADER is indexed by constants such as IMAGE_DIRECTORY_ENTRY_IMPORT (index 1) and IMAGE_DIRECTORY_ENTRY_EXPORT (index 0). Import resolution and export enumeration both start by indexing this array to obtain the RVA of the corresponding directory structure."
    relevant_to: [T-004, T-007, T-013]
    tags: [pe-format, windows-structure, imports, exports, data-directory]

  - id: "pe-magic-numbers"
    name: "PE Magic Field Values 0x10B and 0x20B"
    category: os-internal
    description: "The Magic field in IMAGE_OPTIONAL_HEADER discriminates PE format variants. 0x10B indicates PE32 (32-bit), 0x20B indicates PE32+ (64-bit). Modern Windows binaries almost always use one of these two values; encountering another value is uncommon. Manual parsers check Magic first to select the correct optional header layout before reading subsequent fields whose offsets differ between PE32 and PE32+."
    relevant_to: [T-004, T-006, T-013]
    tags: [pe-format, pe32, pe32-plus, magic-number, parsing]

  - id: "e-lfanew-rva"
    name: "e_lfanew as RVA to PE Header"
    category: os-internal
    description: "The e_lfanew field in IMAGE_DOS_HEADER is interpreted as an RVA and added to the image base address to obtain the virtual address of the IMAGE_NT_HEADERS Signature field. The material emphasizes this is an RVA, not a file offset — when parsing a module already loaded in memory, the result is added directly to the base; when parsing a file on disk, file-to-VA translation is required."
    relevant_to: [T-004, T-007, T-013]
    tags: [pe-format, rva, module-resolution, image-base]

  - id: "section-alignment-vs-file-alignment"
    name: "Section Alignment and File Alignment in PE"
    category: os-internal
    description: "The SectionAlignment and FileAlignment fields in IMAGE_OPTIONAL_HEADER govern how sections are laid out. SectionAlignment specifies alignment of sections in memory (typically 0x1000 or larger); FileAlignment specifies alignment in the file (typically 0x200). These fields dictate how raw file bytes map into virtual memory and influence the permissions and layout of mapped sections, which matters for techniques that stomp or overwrite module sections."
    relevant_to: [T-006, T-007, T-013]
    tags: [pe-format, section-alignment, file-alignment, memory-mapping]

  - id: "registry-walking-pattern"
    name: "Registry Walking via RegOpenKeyExW + RegEnumValue + RegQueryInfoKey"
    category: attack-pattern
    description: "Operational pattern for enumerating registry content: open the key with RegOpenKeyExW (returns HKEY via _Out_ parameter; function returns LSTATUS for error checking, not a handle), call RegQueryInfoKey to learn subkey/value counts and max-name lengths for buffer sizing, then loop RegEnumValue with incrementing dwIndex until ERROR_NO_MORE_ITEMS. LSTATUS return values are interpreted via FormatMessage with FORMAT_MESSAGE_FROM_SYSTEM."
    relevant_to: [T-017, T-023]
    tags: [registry, enumeration, persistence, recon]

  - id: "win32-find-data-walk"
    name: "WIN32_FIND_DATA Directory Walk Pattern"
    category: attack-pattern
    description: "Directory enumeration pattern using FindFirstFileA/FindNextFileA/FindClose. WIN32_FIND_DATA is the user-mode structure holding file attributes returned per iteration. FindFirstFile opens a search handle and returns the first match; FindNextFile continues iteration until returning 0 (then GetLastError distinguishes ERROR_NO_MORE_ITEMS from a real failure); FindClose closes the search handle. The macro expands to ANSI/W variants."
    relevant_to: [T-023]
    tags: [filesystem, enumeration, recon, win32-api]

  - id: "netuserenum-resume-handle"
    name: "NetUserEnum Resume Handle for Large Account Enumerations"
    category: attack-pattern
    description: "NetUserEnum takes a resume_handle PDWORD parameter that lets callers continue enumeration across calls when the result set is too large for one buffer. The first call must pass zero; the function returns a new resume position the caller passes on the next iteration. The entriesread and totalentries LPDWORD outputs distinguish what was returned in the current buffer from what remains. Passing NULL disables resumption."
    relevant_to: [T-023]
    tags: [recon, user-enumeration, netapi, domain-enumeration]

  - id: "getuserprofiledirectory"
    name: "GetUserProfileDirectoryA Profile Path Lookup"
    category: attack-pattern
    description: "Retrieves the root directory path of the user profile associated with a token handle (typically obtained via OpenProcessToken). The lpProfileDir buffer and lpcchSize pointer follow the two-call pattern: first call with NULL buffer to obtain required size, then allocate and call again. Useful for resolving user-specific paths for exfil staging, persistence placement, and browser data harvesting."
    relevant_to: [T-023, T-017]
    tags: [recon, user-profile, path-resolution, persistence]

  - id: "service-win32-own-process-flag"
    name: "SERVICE_WIN32_OWN_PROCESS Service Type"
    category: os-internal
    description: "Service type flag indicating the service runs in its own process and does not share an address space with other services. Distinguishes from SERVICE_WIN32_SHARE_PROCESS where multiple services share a single svchost instance. Relevant for persistence design: own-process services are easier to attribute and analyze but provide a cleaner execution boundary."
    relevant_to: [T-017]
    tags: [services, persistence, process-isolation]
```

### Detection Insights

```yaml
detection:
  - indicator: "NetUserEnum invocation against a domain or local SAM"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "NetUserEnum against the local SAM or a domain triggers Windows security event 4799 (security-enabled group membership enumeration) when targeting groups, and may surface in Directory Service Access auditing depending on the target. The training material covers the API signature and parameters but does not discuss detection surface."
    bypassed_by: "not discussed"

  - indicator: "Process opens registry key outside expected hive paths for its declared purpose"
    source: sysmon
    confidence: low
    relevant_to: [T-017, T-023]
    description: "Sysmon Event ID 12 (RegistryEvent) and Event ID 13 (RegistryValueSet) capture RegOpenKeyExW/RegQueryValueExW/RegSetValueExW operations when configured with the appropriate RegistryEvent target path filters. The training material describes the API mechanics but does not address detection or evasion."
    bypassed_by: "not discussed"

  - indicator: "FindFirstFile/FindNextFile walking sensitive directories"
    source: behavioral
    confidence: low
    relevant_to: [T-023]
    description: "Mass directory enumeration of user profile paths, browser profile directories, or document folders is a behavioral indicator of recon/exfil staging. The training material covers the API mechanics but does not characterize detection."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "NetUserEnum Resume Handle Iteration"
    logsource: windows-security
    condition_summary: "Sequence of NetUserEnum calls with non-zero resume_handle values in the same process indicating large-scale account enumeration"
  - title: "Recursive FindFirstFile Walks of User Profile Directories"
    logsource: sysmon
    condition_summary: "Sysmon FileCreate/ProcessAccess events showing FindFirstFile/FindNextFile handles targeting %USERPROFILE%\\Documents, Desktop, or browser profile paths in rapid succession"
```

### Operational Chains

```yaml
chains:
  - name: "Manual Module Resolution and Export Lookup"
    description: "Locate a module by walking the PEB, parse its PE headers, and resolve a function by name from the export directory"
    steps:
      - technique: T-004
        role: "PEB walk to obtain the in-memory base address of the target module (e.g., ntdll.dll, kernelbase.dll)"
      - technique: "PE header traversal"
        role: "Read IMAGE_DOS_HEADER->e_lfanew, add to base to reach IMAGE_NT_HEADERS, parse IMAGE_OPTIONAL_HEADER to locate the export DataDirectory entry"
      - technique: "Export directory walk"
        role: "Walk IMAGE_EXPORT_DIRECTORY AddressOfNames array, hash each name, compare against the target DJB2 hash to resolve the function pointer"
    notes: "The training material covers the PE header traversal portion (units 23-40) but does not chain to export resolution; the export walk step is inferred from standard PE parsing practice the material establishes"

  - name: "Registry-Based Persistence Enumeration"
    description: "Identify persistence candidates by walking registry hives for hijackable COM objects and existing schtask entries"
    steps:
      - technique: T-017
        role: "COM hijack persistence requires identifying CLSID entries with weak permissions or missing InprocServer32 defaults via registry enumeration"
      - technique: "registry-walking-pattern"
        role: "RegOpenKeyExW on HKCR\\CLSID, RegQueryInfoKey for subkey count, RegEnumKeyEx iterating CLSIDs, RegQueryValueExW reading InprocServer32 default values"
      - technique: T-017
        role: "Scheduled task persistence verifies existing task state via the SchedSvc registry keys before creating a new task"
    notes: "The training material covers the registry enumeration APIs individually; the chaining into COM hijack persistence is implied by the persistence technique's reliance on these primitives"

  - name: "User-Aware Recon and Profile Path Discovery"
    description: "Enumerate local/domain users, then resolve each user's profile path for targeted exfil or persistence placement"
    steps:
      - technique: "NetUserEnum enumeration"
        role: "List user accounts via NetUserEnum with resume_handle pagination to handle large account sets"
      - technique: "OpenProcessToken + GetUserProfileDirectoryA"
        role: "Resolve each user's profile root path for staging data or placing persistence binaries in user-writable locations"
      - technique: T-023
        role: "Recon/sysinfo collection in client capabilities aggregates the user list and profile paths"
    notes: "The material does not describe the chain explicitly; it documents the individual API primitives (units 6-8) that compose the recon pattern"
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "pe-format-traversal-foundations"
    title: "PE Format Header Traversal as Cross-Cutting Foundation"
    kind: cross-source-convergence
    description: "The SANS SEC670 material dedicates roughly 18 units (23-40) to PE format structure: IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DATA_DIRECTORY. These structures underpin at least five vault cards (T-004 PEB Walker, T-006 Phantom Stubs, T-007 Process Injection, T-013 PE Loader, T-009/T-010 process creation techniques) but the vault has no dedicated concept node explaining the e_lfanew → IMAGE_NT_HEADERS → IMAGE_OPTIONAL_HEADER → DataDirectory traversal path. This convergence signals the path is load-bearing across multiple cards and merits a graph-level concept entry."
    would_relate_to: [T-004, T-006, T-007, T-013, T-009, T-010]
    source_units: ["unit 23", "unit 24", "unit 25", "unit 26", "unit 27", "unit 28", "unit 29", "unit 30", "unit 31", "unit 32", "unit 33", "unit 34", "unit 35", "unit 36", "unit 37", "unit 38", "unit 39", "unit 40"]
    tags: [pe-format, header-parsing, module-resolution, cross-cutting]

  - id: "registry-api-enumeration-primitives"
    title: "Registry Walking API Set for Persistence and Recon"
    kind: coverage-gap
    description: "Units 14-22 cover the complete registry-walking API set (RegOpenKeyExW, RegQueryValueExW, RegEnumValue, RegQueryInfoKey) including the two-pass buffer-sizing pattern and the ERROR_NO_MORE_ITEMS loop terminator. The vault's T-017 persistence suite and T-023 recon capabilities depend on these primitives but the underlying API mechanics are not documented as a graph concept. The material surfaces the LSTATUS error-interpretation pattern via FormatMessage and the _Out_ HKEY parameter convention as details that source code does not explain."
    would_relate_to: [T-017, T-023]
    source_units: ["unit 14", "unit 15", "unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 21", "unit 22"]
    tags: [registry, api-primitives, persistence, recon, coverage-gap]

  - id: "file-enumeration-recon-primitives"
    title: "FindFirstFile/FindNextFile Directory Walk for Recon and Exfil"
    kind: coverage-gap
    description: "Units 1-5 cover FindFirstFileA/FindNextFileA/FindClose and the WIN32_FIND_DATA structure. These primitives underlie directory-walking recon and exfil enumeration in T-023 client capabilities and are referenced in source files like amaterasu.rs and discovery.rs without explanation of the API contract. The material surfaces the BOOL return convention, the search-handle lifecycle, and the WIN32_FIND_DATA structure selection over KUSER_SHARED_DATA and FILE_OBJECT — details that explain why this API is used for user-mode enumeration."
    would_relate_to: [T-023]
    source_units: ["unit 1", "unit 2", "unit 3", "unit 4", "unit 5"]
    tags: [filesystem, enumeration, recon, api-primitives, coverage-gap]

  - id: "network-adapter-enumeration-primitive"
    title: "GetAdapterAddresses/GetNumberOfInterfaces for Network Recon"
    kind: coverage-gap
    description: "Units 11-13 cover GetAdapterAddresses and GetNumberOfInterfaces with their ULONG/DWORD return conventions and the ERROR_BUFFER_OVERFLOW two-pass allocation pattern. These primitives underlie network recon capabilities in client_rust byakugan.rs (ARP, TCP, AD enumeration) but the API mechanics are not documented as a graph concept. The material surfaces the resume/buffer-sizing convention and the error-code taxonomy (ERROR_ADDRESS_NOT_ASSOCIATED, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA) that source code does not annotate."
    would_relate_to: [T-023]
    source_units: ["unit 11", "unit 12", "unit 13"]
    tags: [network, recon, api-primitives, adapter-enumeration, coverage-gap]
```