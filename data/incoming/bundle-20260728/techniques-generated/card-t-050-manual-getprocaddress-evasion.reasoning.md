Let me analyze the inputs carefully.

The task: produce T-050 technique card for "Manual GetProcAddress Implementation via Export Table Walking."

Key inputs:
1. Cluster spec: T-050, category `syscalls`, tier `A`, member notes `lgtm:manual-loader-api-reimplementation` and `lgtm:manual-getprocaddress-as-standalone-primitive`, would_relate_to: T-001, T-004, T-006.

2. Related cards T-001, T-004, T-006 provided.

3. Rust source files provided: overload.rs, pe_loader.rs, tls_cb.rs. Need to verify whether these actually implement manual GetProcAddress via export table walking.

- overload.rs: `fixing_iat` uses `crate::resolve::find_module_base(dll_name)` and `crate::resolve::resolve_export_by_ordinal(module_base, ordinal)` / `crate::resolve::resolve_export_by_name(module_base, name)`. So overload.rs CALLS export resolution functions from resolve.rs — but the file itself doesn't implement the export table walking; it delegates to resolve.rs. The T-004 card's source_file is `dark_crystal/crowd/src/resolve.rs`, which per the card "PE export table walking for function address resolution". So resolve.rs is the actual implementation, but that file is not included in my inputs. The manifest says resolve.rs maps to T-003 and T-004 cards.

Hmm. The question: does overload.rs implement the technique? The rule: "at least ONE function in it must implement the primary mechanism the card describes." overload.rs's `fixing_iat` calls `resolve_export_by_name` — the export table walking itself is in resolve.rs (not provided). overload.rs itself doesn't contain the AddressOfNames/AddressOfNameOrdinals/AddressOfFunctions traversal. So overload.rs does not implement the primary mechanism — it consumes it.

- pe_loader.rs: `resolve_imports` uses LoadLibraryA + GetProcAddress — the opposite of manual resolution. It explicitly calls the Win32 API. So pe_loader.rs does NOT implement this technique. It's the non-evasive variant.

- tls_cb.rs: This one is interesting. The PIC stub in `build_tls_stub` does implement a manual export table walk in raw x64 bytes: it walks PEB → kernel32 base, then parses e_lfanew, export dir RVA (0x88 offset), NumberOfNames (0x18), AddressOfNames (0x20), AddressOfNameOrdinals (0x24), AddressOfFunctions (0x1C), loops comparing names ("WinExec\0" 8-byte compare), gets ordinal via `movzx eax, word [r10+r9*2]`, then function RVA via `mov eax, [r10+rax*4]`, adds module base. This is a genuine manual GetProcAddress implementation via export table walking — albeit in emitted x64 machine code rather than Rust pointer arithmetic. The function `build_tls_stub` emits a PIC stub that performs the AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions resolution at runtime.

So does tls_cb.rs count? The primary mechanism the card describes: "manually traverse AddressOfNames, AddressOfNameOrdinals, and AddressOfFunctions to resolve function addresses without calling Win32 API." The stub emitted by build_tls_stub does exactly this — resolves WinExec from kernel32's export directory without calling GetProcAddress. The Rust function `build_tls_stub` implements the construction of that resolver. I'd argue yes, this is an implementation of the technique — the file contains code that performs manual export table walking (encoded as emitted shellcode). The intent of the stub is exactly this technique.

However, caution: the resolve_export_by_name/resolve_export_by_ordinal functions live in resolve.rs which is not provided. T-004's card already covers "PE export table walking for function address resolution" as a feature. The cluster spec says T-050 "complements PEB-walker" — the distinction being T-004 = module-level resolution (finding module base via PEB), T-050 = function-level resolution (export directory traversal to get function pointers). So the actual implementation in resolve.rs contains both halves; T-004's card claims the file. Since resolve.rs isn't in my inputs, I can't reference it as a verified source for T-050... but wait — the T-004 card provided states resolve.rs does "PE export table walking for function address resolution" at "full file for PE walking". That's a related card provided as input, so I can reference that fact. But the frontmatter `source_file` must be "a real path (verified from included files) or exactly none". resolve.rs is not included in my inputs as a file — only overload.rs, pe_loader.rs, tls_cb.rs are included.

Rule 3 in the context: "Matching source files (src/**/*.rs, optional) — Verify whether these files actually implement the technique before claiming they do."

So among included files:
- overload.rs: uses resolve_export_by_name/ordinal from crate::resolve — delegates. Does not itself walk the export tables. But its `fixing_iat` function is the consumer. Hmm — the explicit test: "at least ONE function in it must implement the primary mechanism the card describes." The primary mechanism is walking the three arrays. overload.rs doesn't do that walk; it calls resolve:: functions that do. So no.
- pe_loader.rs: uses GetProcAddress directly. Definitively no — it's the antithesis.
- tls_cb.rs: `build_tls_stub` emits x64 machine code that performs the export table walk (AddressOfNames at +0x20, AddressOfNameOrdinals at +0x24, AddressOfFunctions at +0x1C, NumberOfNames at +0x18, export dir RVA at NT+0x88). The emitted code resolves "WinExec" by 8-byte name comparison, then ordinal, then function RVA. This IS the primary mechanism — implemented as position-independent shellcode emitted by the Rust function. I think this counts as a genuine implementation, with the caveat that it's an embedded PIC stub inside the TLS persistence module, not a general-purpose resolver API.

So `source_file` could be `dark_crystal/crowd/src/persist/tls_cb.rs`. And I should note in Key Implementation Details that overload.rs's `fixing_iat` consumes `resolve_export_by_name`/`resolve_export_by_ordinal` from resolve.rs (which T-004 documents as containing the PE export walking code), that pe_loader.rs uses the Win32 API path (LoadLibraryA/GetProcAddress) and thus does not implement this technique, and that tls_cb.rs emits a PIC stub performing the walk.

Hmm, but should source_file be tls_cb.rs or none? Let me re-read the rule: "If matching Rust source is included in your inputs AND you verified it implements this technique: Reference the file path and specific functions... If no source implements this technique: Write 'No current implementation...'".

tls_cb.rs's build_tls_stub emits code that walks the export directory of kernel32 to resolve WinExec without calling GetProcAddress. That's verified — the bytes and comments clearly do: export dir RVA at [rbx+rax+0x88], NumberOfNames at [rdx+0x18], AddressOfNames RVA at [rdx+0x20], loop comparing names, AddressOfNameOrdinals at [rdx+0x24], movzx word [r10+r9*2], AddressOfFunctions at [rdx+0x1C], mov eax, [r10+rax*4], add base. Yes, this is a faithful manual GetProcAddress. I'll set source_file to tls_cb.rs and describe it accurately, while noting its scope (resolves a single hardcoded name inside a TLS-callback PIC stub; the general-purpose resolver used elsewhere lives in resolve.rs per T-004).

Wait — but I should be careful about false attribution. The vault's manifest maps tls_cb.rs to T-008-persistence. But that's the persistence card mapping; a file can contain multiple techniques. The instruction says verify the match. The match is real: build_tls_stub contains a complete export-walking resolver in emitted machine code. I'm confident.

Should source_file be a single path? The template shows a single path. I'll use `dark_crystal/crowd/src/persist/tls_cb.rs`.

Also, overload.rs is relevant context: its `fixing_iat` explicitly states the OPSEC rationale ("LoadLibraryA and GetProcAddress are hooked by EDR products and would break the stealth guarantees") and calls resolve_export_by_name/resolve_export_by_ordinal — I can mention this as the consumer pattern, noting the resolver itself lives in resolve.rs (covered by T-004's source). Actually careful: rule 8 says don't assume. I verified overload.rs calls those functions; I haven't seen resolve.rs's contents, but T-004's card (provided input) states it does "PE export table walking for function address resolution." That's a provided related card, so citing it is grounded.

Atlas material grounding:
- atlas-exploit-dev-part8 units 24-40: PE format, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, DataDirectory, IMAGE_EXPORT_DIRECTORY struct with fields, units 38-40: export resolution flow — AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions, hex dump of kernel32 export directory with concrete values: Name RVA 090058 → KERNEL32.DLL, Base = 1, NumberOfFunctions = 650 (0x28A? actually 0x650 shown as "50 06 00 00" = 0x650 = 1616... wait "50 06 00 00" little-endian = 0x00000650 = 1616. The slide comments "// 650" which is hex 0x650 = 1616 decimal. The material says "NumberOfFunctions; // 650" — meaning hex 0x650. I should be careful: the comment says 650 which is the hex value 0x650 = 1616 decimal. I'll say "0x650 (1616 decimal)" or just cite as the material does. Actually to avoid confusion I'll mention the annotated values as they appear: NumberOfFunctions = 0x650, NumberOfNames = 0x650, AddressOfFunctions RVA 0x08C138, AddressOfNames RVA 0x08DA78, AddressOfNameOrdinals RVA 0x08F3B8, Name RVA 0x090058 → "KERNEL32.DLL", Base = 1. First name at 0x90065 → "AcquireSRW..." (AcquireSRWLockExclusive presumably). These are great concrete details for OS Internals Context.
- unit 38: explains the three-array flow: AddressOfFunctions alone is anonymous — need names array to tie, ordinals array maps name index → function index.
- unit 35: IMAGE_EXPORT_DIRECTORY struct definition (40 bytes): Characteristics, TimeDateStamp, MajorVersion, MinorVersion, Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals.
- unit 33: IMAGE_DATA_DIRECTORY, DataDirectory in optional header; IMAGE_DIRECTORY_ENTRY_EXPORT index 0. PE32+ magic 0x20b. DataDirectory at NT+0x88 for PE32+ (from overload.rs code comments — grounded in source).
- atlas-exploit-dev-part17 units 25, 28: explicit linking via LoadLibrary/GetProcAddress/FreeLibrary; "these APIs are commonly monitored by security products and mentions future discussions on workarounds"; unit 28: "future plans to manually implement these APIs to further hide imports." Explicit linking leaves the DLL out of dumpbin /dependents and the import table, but the LoadLibrary/GetProcAddress calls themselves are the monitored surface.

MITRE: best fit? Manual GetProcAddress for hiding API resolution... Options: T1027 (Obfuscated Files or Information), T1027.007 (Dynamic API Resolution) — yes! T1027.007 is "Dynamic API Resolution" — adversaries obfuscate API calls resolved at runtime to hinder static analysis. Manual export walking is a form of dynamic API resolution that avoids even GetProcAddress. T1027.007 is the best fit. Alternatively T1106 (Native API) like the related cards use, but T1027.007 is more precise for import hiding. The related cards T-001/T-004 use T1106. For this card, T1027.007 Dynamic API Resolution is squarely correct. I'll use mitre: T1027.007, and maybe mitre_secondary: [T1106]. Hmm, T1106 Native API is about calling NT APIs directly. This technique is about resolving addresses without monitored APIs — T1027.007 primary is right. Secondary could be T1106 since it's used to feed syscall workflows. I'll include secondary T1106.

Category: `syscalls` proposed. Hmm — is export table walking a syscall technique? It's API resolution. The enum doesn't have "api-resolution"; syscalls category includes "Syscalls & API Resolution" per the INDEX header ("## Syscalls & API Resolution" contains T-001..T-006 including PEB Walker). So `syscalls` matches the vault's taxonomy. Keep it.

Tier: A proposed. Fine.

Tags: 5-10 kebab-case: [export-table-walk, api-resolution, import-hiding, image-export-directory, rva, peb, edr-hook-evasion, getprocaddress]. Maybe [api-resolution, export-directory, import-hiding, pe-walking, rva-resolution, edr-evasion, kernel32, peb-walk]. Let me pick: ['api-resolution', 'export-table-walk', 'import-hiding', 'pe-format', 'rva', 'edr-hook-evasion', 'kernel32', 'djb2-hash']. 8 tags.

Name: "Manual GetProcAddress via Export Table Walking" (4-8 words). Good.

Now structure the card per template:

Frontmatter:
- id: T-050
- name: Manual GetProcAddress via Export Table Walking
- category: syscalls
- tier: A
- crate: dark_crystal
- source_file: dark_crystal/crowd/src/persist/tls_cb.rs
- mitre: T1027.007
- mitre_secondary: [T1106]
- tags: [api-resolution, export-table-walk, import-hiding, pe-format, rva, edr-hook-evasion, kernel32-exports, djb2-hash]
- origin: atlas-synthesis
- member_notes: ['lgtm:manual-loader-api-reimplementation', 'lgtm:manual-getprocaddress-as-standalone-primitive']

Summary: 3-5 sentences. First sentence standalone. What: resolve function addresses by parsing IMAGE_EXPORT_DIRECTORY of an already-loaded module instead of calling GetProcAddress. OS primitive: PE export directory in the module's mapped image. Why: GetProcAddress/LoadLibrary are hooked by EDRs; explicit linking still leaves those calls visible; import table hiding. Detection surface: none of the resolution itself is visible (pure memory reads); detection shifts to the caller's behavior and IAT-less binary anomalies... but material doesn't discuss detection much — rule: don't invent detections. The material (part17 unit 25) says LoadLibrary/GetProcAddress "are commonly monitored by security products." That's the detection statement grounding. For Detection Considerations section, I have: material says the Win32 loader APIs are commonly monitored — that's the telemetry surface (userland hooks on kernel32!GetProcAddress etc.). Bypass: manual walking avoids those hooks. Residual artifacts: none discussed — material doesn't cover. I should write "Training material does not discuss detection beyond noting that LoadLibrary/GetProcAddress are commonly monitored" — careful phrasing to stay grounded. I can describe the monitored-API claim from the material, and state that the material does not describe specific ETW/Sysmon telemetry for the manual walk. Don't invent GUIDs or event IDs.

Mechanism — numbered steps:
1. Obtain target module base (e.g., kernel32.dll) — typically via PEB walk (T-004) since LoadLibrary is also monitored.
2. Read DOS header at base; e_lfanew at base+0x3C → NT headers.
3. Verify PE32+ magic (0x20B) at OptionalHeader.Magic; locate DataDirectory — for PE32+ begins at NT+0x88; entry [0] (IMAGE_DIRECTORY_ENTRY_EXPORT) gives export directory RVA.
4. Compute export directory VA = base + RVA → IMAGE_EXPORT_DIRECTORY (40 bytes, 11 fields).
5. Read NumberOfNames, AddressOfNames, AddressOfNameOrdinals, AddressOfFunctions RVAs; convert each to VA by adding base.
6. Iterate i in [0, NumberOfNames): name RVA = AddressOfNames[i]; compare string at base+nameRVA against target (or hash it, e.g., DJB2, and compare).
7. On match: ordinal index = AddressOfNameOrdinals[i] (u16).
8. function RVA = AddressOfFunctions[ordinal_index] (u32); function VA = base + function RVA.
9. For ordinal-only resolution: index = ordinal − Base; function RVA = AddressOfFunctions[index].
10. Optionally handle forwarded exports: if function RVA falls inside export directory range, it's a forwarder string... — is this in the material? Not mentioned. Skip or mention briefly as documented behavior? Rule: material is authority; well-established Windows internals documentation is allowed. Forwarder handling is well-established (function RVA pointing into the export section = "DLL.Function" forwarder string). I can mention it briefly as part of OS Internals Context since GetProcAddress handles forwarders and a manual implementation must too — grounded in Windows internals. Keep it short.

OS Internals Context:
- IMAGE_EXPORT_DIRECTORY layout (40 bytes) with field list and offsets: +0x00 Characteristics, +0x04 TimeDateStamp, +0x08 Major/MinorVersion, +0x0C Name, +0x10 Base, +0x14 NumberOfFunctions, +0x18 NumberOfNames, +0x1C AddressOfFunctions, +0x20 AddressOfNames, +0x24 AddressOfNameOrdinals. Wait — check offsets: Characteristics(4)+TimeDateStamp(4)=8, MajorVersion(2)+MinorVersion(2)=4 → 12, Name(4) at 0x0C, Base(4) at 0x10, NumberOfFunctions at 0x14, NumberOfNames at 0x18, AddressOfFunctions at 0x1C, AddressOfNames at 0x20, AddressOfNameOrdinals at 0x24. Total 0x28 = 40 bytes. And tls_cb.rs emits: NumberOfNames at [rdx+0x18], AddressOfNames at [rdx+0x20], AddressOfNameOrdinals at [rdx+0x24], AddressOfFunctions at [rdx+0x1C]. Consistent. Export dir RVA at NT+0x88 — for PE32+ the DataDirectory starts at offset 0x60 within OptionalHeader; NT headers = 4 (sig) + 20 (file header) + optional header; OptionalHeader starts at NT+0x18; DataDirectory at OptionalHeader+0x60 → NT+0x78? Wait: 0x18+0x60 = 0x78. Hmm, but tls_cb.rs and overload.rs both use NT+0x88 for PE32+. Let me recompute: IMAGE_OPTIONAL_HEADER64: standard fields before data directory: Magic(2) MajorLinkerVersion(1) MinorLinkerVersion(1) SizeOfCode(4) SizeOfInitializedData(4) SizeOfUninitializedData(4) AddressOfEntryPoint(4) BaseOfCode(4) ImageBase(8) SectionAlignment(4) FileAlignment(4) MajorOperatingSystemVersion(2) MinorOperatingSystemVersion(2) MajorImageVersion(2) MinorImageVersion(2) MajorSubsystemVersion(2) MinorSubsystemVersion(2) Win32VersionValue(4) SizeOfImage(4) SizeOfHeaders(4) CheckSum(4) Subsystem(2) DllCharacteristics(2) SizeOfStackReserve(8) SizeOfStackCommit(8) SizeOfHeapReserve(8) SizeOfHeapCommit(8) LoaderFlags(4) NumberOfRvaAndSizes(4). Sum: 2+1+1+4+4+4+4+4 = 24; +8=32; +4+4=40; +2*6=12 → 52; +4+4+4+4 = 68; +2+2=72; +8*4=32 → 104; +4+4=112 = 0x70. So DataDirectory starts at OptionalHeader+0x70. OptionalHeader starts at NT + 4 + 20 = NT+0x18. So DataDirectory at NT+0x18+0x70 = NT+0x88. Yes! NT+0x88 for PE32+. For PE32, ImageBase is 4 bytes and stack/heap sizes are 4 bytes each: 24+4=28... PE32: 2+1+1+4+4+4+4+4+4(BaseOfData)=28; +4(ImageBase)=32; +8=40; +12=52; +16=68; +4=72; +4*4=16 → 88; +8=96 = 0x60. DataDirectory at OptionalHeader+0x60 → NT+0x78. Matches overload.rs comments (PE32: 0x78, PE32+: 0x88). Good, consistent.

- The three parallel arrays and the indirection: AddressOfNames[i] → name; AddressOfNameOrdinals[i] → index into AddressOfFunctions; names sorted alphabetically (allows binary search — GetProcAddress uses binary search per Windows internals; is that documented? The material's unit 38 says names array, ordinals array. Alphabetical ordering is well-established — names are sorted, which is why ordinals array is needed. I can state this; it's textbook PE format. But "textbook" word is banned. Phrase without it.)
- Concrete kernel32 hex dump from material: Name RVA 0x090058 → "KERNEL32.DLL", Base = 1, NumberOfFunctions = 0x650, NumberOfNames = 0x650, AddressOfFunctions RVA 0x08C138 (first entries 0x9007D, 0x900B3, 0x1E310...), AddressOfNames RVA 0x08DA78 (first name 0x90065 → "AcquireSRW..."), AddressOfNameOrdinals RVA 0x08F3B8. Base=1 means ordinals start at 1; function VA for ordinal N = AddressOfFunctions[N-Base].
- Why names-only modules matter: NumberOfNames ≤ NumberOfFunctions; functions exported by ordinal only have no name entry.
- Kernel/user boundary: resolution is entirely user-mode reads on MEM_IMAGE pages already mapped; no syscalls, no kernel transitions, no ETW. The monitored surface (GetProcAddress in kernel32, LdrGetProcedureAddress in ntdll) is where EDR userland hooks live — manual walk bypasses those hooks.
- Distinction from what GetProcAddress does internally: GetProcAddress → LdrGetProcedureAddress in ntdll, which walks the same three arrays. The manual implementation replicates LdrGetProcedureAddress's name-lookup path minus forwarder handling and minus the loader lock. Is the GetProcAddress→LdrGetProcedureAddress chain well-established? Yes, documented. Forwarding: LdrGetProcedureAddress handles forwarders by recursing into the named DLL. A manual resolver must either handle forwarders or accept failure on forwarded exports (common for ntdll→kernelbase forwards, e.g., many kernel32 exports forward to KernelBase.dll). Grounded — mention.

Key Implementation Details:
- tls_cb.rs build_tls_stub emits a PIC x64 stub that performs the walk at runtime: PEB→kernel32 base (InLoadOrder third entry), export dir at [base+e_lfanew]+0x88, NumberOfNames +0x18, AddressOfNames +0x20, AddressOfNameOrdinals +0x24, AddressOfFunctions +0x1C, 8-byte immediate compare for "WinExec\0", movzx ordinal word, index into functions, add base, call rax. Deviation from hash-based approach: uses direct 8-byte name comparison against an immediate rather than DJB2 hashing; resolves a single hardcoded export.
- overload.rs fixing_iat: consumes crate::resolve::resolve_export_by_name / resolve_export_by_ordinal (module base via find_module_base — PEB walker, T-004); the resolver functions live in resolve.rs which T-004 documents as containing the PE export walking. IAT patch writes function VA into FirstThunk. Ordinal path: ordinal = thunk & 0xFFFF via IMAGE_ORDINAL_FLAG64.
- pe_loader.rs resolve_imports: uses LoadLibraryA + GetProcAddress — does NOT implement this technique; it is the explicit-linking path the material flags as monitored. State that.
- Note deviations: stub resolves only WinExec; general resolver in resolve.rs is DJB2 hash-based per T-004/T-001 cards (DJB2 mentioned in T-001/T-004 cards).

Why It Matters: bridges module-base resolution (T-004) to usable function pointers without touching monitored loader APIs; foundation for T-001 stub location, T-006 phantom stub construction, IAT fixup in manual mapping. Without it, PEB walking only yields module bases. Explicit linking (LoadLibrary/GetProcAddress) keeps DLLs out of the import table but still transits hooked APIs — the material explicitly flags this and points to manual reimplementation as the next step.

Detection Considerations:
- Material: LoadLibrary/LoadLibraryEx/GetProcAddress "are commonly monitored by security products" (part17 unit 25). Manual walk produces no API telemetry — pure reads on already-mapped MEM_IMAGE pages.
- Telemetry sources: material does not name ETW providers or Sysmon IDs for this technique — state that userland hooks on kernel32!GetProcAddress/ntdll!LdrGetProcedureAddress are the surface being avoided (grounded in the monitored-API statement). Don't invent GUIDs.
- Residual artifacts: none discussed in material. Static side effect discussed: explicit linking leaves the target DLL out of dumpbin /dependents and import table (part17 unit 28) — manual resolution additionally removes the GetProcAddress import itself.
- Bypass options: DJB2 hash comparison instead of embedded strings (from T-004/T-001 cards — those mention DJB2; grounded via related cards).

Related Techniques:
- T-004 PEB Walker — supplies the module base that is the input to export walking; resolve.rs hosts both halves.
- T-001 RecycledGate — locates ntdll syscall stubs via export-table-derived addresses; stub scanning starts from a resolved function address.
- T-006 Phantom Stubs — needs ntdll addresses/SSN info to build MEM_IMAGE-backed stubs; export resolution is the resolution layer.

Keep to those three (from would_relate_to).

References:
- atlas-exploit-dev-part8.md (units 24-40), atlas-exploit-dev-part17.md (units 25, 28)
- MITRE T1027.007 URL https://attack.mitre.org/techniques/T1027/007/
- LGTM notes both IDs
- Public references: SANS SEC670 Book 1 (named in material). winnt.h (named). No invented refs.

Source Reference: tls_cb.rs path; note resolve.rs holds the general-purpose resolver (documented under T-004) and pe_loader.rs explicitly uses the Win32 API path.

Length: aim ~1200-1600 words body.

Check banned words: avoid "elegant", "textbook", "notable", "worth noting", "interestingly", "essentially", "at its core", "key insight". Write declaratively.

Note the existing cards contain opsec_rating in frontmatter (T-001) — but rule 2 says no ratings; my card must not include it.

Mechanism steps — concrete with offsets:
1. Obtain module base (kernel32.dll/ntdll.dll) without LoadLibrary — via PEB InLoadOrderModuleList walk (T-004) or a SEC_IMAGE mapping.
2. Read e_lfanew at base+0x3C; NT headers at base+e_lfanew; verify Signature 0x00004550 ("PE\0\0") — hmm, material part8 units mention PE signature PE\0\0 (part17 unit 13). Fine.
3. Check OptionalHeader.Magic at NT+0x18: 0x20B = PE32+ → DataDirectory at NT+0x88; 0x10B = PE32 → NT+0x78.
4. Export directory RVA = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT=0].VirtualAddress; if zero, module has no exports.
5. IMAGE_EXPORT_DIRECTORY at base+RVA; read Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions (+0x1C), AddressOfNames (+0x20), AddressOfNameOrdinals (+0x24).
6. For i in 0..NumberOfNames: name VA = base + AddressOfNames[i]; compare string (or its DJB2 hash) to target.
7. Match at index i → name ordinal = read u16 at AddressOfNameOrdinals + 2*i.
8. function RVA = read u32 at AddressOfFunctions + 4*ordinal; VA = base + RVA.
9. Forwarder check: if RVA ∈ [exportDirRVA, exportDirRVA+Size), the "address" is a forwarder string; handle or fail.
10. Ordinal path: index = ordinal − Base.

Good. Also mention that names array is sorted (enables binary search) — established PE fact.

One caution: the cluster's canonical category is syscalls but nothing here issues syscalls — the Why It Matters can note the card sits in the Syscalls & API Resolution grouping of the vault (T-001..T-006 neighbors). Brief.

Now write it. Word count target 1200+. Let me draft.

For Key Implementation Details, structure:
- tls_cb.rs `build_tls_stub` — verified implementation, PIC emitted bytes, specific offsets, name compare vs hash deviation.
- overload.rs `fixing_iat` — consumer; delegates to resolve.rs `resolve_export_by_name`/`resolve_export_by_ordinal`; ordinal handling with IMAGE_ORDINAL_FLAG64; rationale comment quoted.
- pe_loader.rs `resolve_imports` — counter-example: calls LoadLibraryA/GetProcAddress; does not implement the technique; included to show the monitored path the technique replaces.

Frontmatter source_file: tls_cb.rs path.

mitre_secondary: [T1106] — fine.

Write the card now. Ensure exact section order and headers. Minimum 800 words; target 1200-1800.
