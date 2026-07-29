# Cluster Spec — T-083: PE Export Directory Traversal for API Resolution

- **T-NNN ID**: `T-083`
- **Canonical name**: PE Export Directory Traversal for API Resolution
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: high — Two member notes; documents the PE export resolution mechanism shared by three existing cards (T-004, T-006, T-008); foundational prerequisite.
- **would_relate_to**: ['T-004', 'T-006', 'T-008']

## Consolidated Description

SEC670 units 23-32 walk through the PE export resolution chain: IMAGE_DOS_HEADER →
e_lfanew → IMAGE_NT_HEADERS → OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
→ IMAGE_EXPORT_DIRECTORY (in .rdata) → AddressOfNames (DWORD RVA array of name
pointers) → AddressOfNameOrdinals (WORD ordinal array, parallel to names) →
AddressOfFunctions (DWORD RVA array of function pointers, indexed by ordinal). The
resolution algorithm: binary-search AddressOfNames for the target function name, read
the parallel ordinal from AddressOfNameOrdinals, index into AddressOfFunctions with
that ordinal, and add the module base address to get the function's virtual address.
SEC670 Unit 40 tasks students with reimplementing GetProcAddress — the same primitive
T-004 PEB Walker implements by walking gs:[0x60] → PEB → Ldr → InLoadOrderModuleList
to find ntdll, then traversing its export table to resolve Nt* functions. This
traversal is the shared foundation for T-004 (API resolution), T-006 (module stomping,
which must locate export functions to stomp), and T-008 (thread hijacking, which must
resolve function addresses for hijack targets).


## Member LGTM Notes (2)

### Note 1: PE Export Resolution as Shared Foundation for T-004, T-006, T-008
- id: `lgtm:cross-source-pe-export-resolution-convergence`
- origin: atlas-exploit-dev-part2
- would_relate_to: ['T-004', 'T-006', 'T-008']
- tags: ['pe-format', 'export-resolution', 'peb-walker', 'threadless', 'phantom-stubs', 'cross-card-dependency']

**Kind:** cross-source-convergence
**Origin:** atlas-exploit-dev-part2
**Would relate to:** T-004, T-006, T-008
**Source units:** unit 23, unit 24, unit 25, unit 27, unit 28, unit 29, unit 30, unit 31, unit 32

SEC670 units 23-32 walk through IMAGE_FILE_HEADER → DataDirectory → IMAGE_EXPORT_DIRECTORY → AddressOfNames/NameOrdinals/Functions as a single pedagogical sequence. This is the exact algorithm T-004 PEB Walker reimplements with DJB2 hashing, that T-008 Threadless must understand to manipulate AddressOfFunctions entries for export hijack, and that T-006 Phantom Stubs relies on when locating legitimate exports to install alongside. The vault documents these three techniques as separate cards but does not currently surface that they share the same underlying export-table algorithm as a hard dependency. A graph node for this shared primitive (already added as concept pe-export-directory-resolution) makes the cross-card relationship explicit.

### Note 2: Custom GetProcAddress Implementation as API Resolution Primitive
- id: `lgtm:getprocaddress-implementation-as-resolution-primitive`
- origin: atlas-exploit-dev-part18
- would_relate_to: ['T-004']
- tags: ['getprocaddress', 'export-table', 'pe-walk', 'resolution', 'emerging-tradecraft']

**Kind:** emerging-tradecraft
**Origin:** atlas-exploit-dev-part18
**Would relate to:** T-004
**Source units:** unit 40

SEC670 Unit 40 tasks students with reimplementing GetProcAddress functionality. This is the same primitive T-004 PEB Walker implements for module and function resolution. The convergence between SEC670 framing it as a learning challenge and the vault implementing it as a core evasion primitive (DJB2 hash resolution) suggests documenting the manual-export-table-walk pattern as a standalone concept rather than burying it inside PEB Walker — operators need to understand export-by-name, export-by-ordinal, and forwarder entries separately.

---
Use `id: T-083`, canonical name above, and `member_notes: ['lgtm:cross-source-pe-export-resolution-convergence', 'lgtm:getprocaddress-implementation-as-resolution-primitive']`.
Cross-reference `would_relate_to`: ['T-004', 'T-006', 'T-008'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.