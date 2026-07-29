## Synthesis Summary

This batch maps thinly to several HUGIN techniques: T-002 (Hell's/Halo's/Tartarus Gate, which depends on PE parsing of ntdll to locate SSNs), T-004 (PEB Walker, which depends on understanding PEB-resident module lists and the IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint field), T-013 (Remaining Injection Methods, specifically thread hijacking via CONTEXT modification), T-014 (NtCreateUserProcess, contrasted with CreateProcessW), and T-016/T-017 tangentially via SetNamedSecurityInfoA and the per-process handle table. The SANS SEC670 units consist almost entirely of unit review questions and slide excerpts covering Windows PE internals (IMAGE_DOS_HEADER, IMAGE_OPTIONAL_HEADER64, PE32+ magic 0x20B), the x64 calling convention (shadow store at RSP+20h), the CONTEXT structure, native application entry signatures (NTSTATUS NT_main(PEB)), and basic API return-value semantics (CreateFile, HRESULT). The gap the material fills is the prerequisite Windows-internals literacy that source code assumes: a reader who cannot parse the DOS stub or locate AddressOfEntryPoint cannot meaningfully read T-002's SSN resolution or T-004's PEB walk. The batch is sparse on detection, evasion, and operational sequencing — most units are quiz items without tradecraft context.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "pe-image-optional-header64"
    target: T-002
    type: requires
    rationale: "Hells Gate SSN resolution walks the export directory of ntdll by parsing its IMAGE_OPTIONAL_HEADER64 DataDirectory entries, requiring knowledge of the Magic 0x20B field and DataDirectory layout covered in the SEC670 material."
  - source: "pe-image-dos-header"
    target: T-004
    type: requires
    rationale: "PEB Walker manual module resolution begins by reading the IMAGE_DOS_HEADER e_lfanew field at offset 0x3C to locate the PE header and walk export tables; the SEC670 material documents this field explicitly."
  - source: "thread-context-structure"
    target: T-013
    type: enables
    rationale: "The SEC670 review question establishes that thread hijacking requires modifying the thread context (not thread state or priority), which is the core primitive behind WaitingThread hijack and other T-013 thread-hijack variants."
  - source: "x64-shadow-store"
    target: T-005
    type: enables
    rationale: "Ekko ROP sleep chains depend on the x64 calling convention's 32-byte shadow store at RSP+0..RSP+20h to construct valid frames for RtlCaptureContext, SetWaitableTimer, and WaitForSingleObjectEx gadgets; the SEC670 material documents the RSP+20h reservation."
  - source: "native-application-peb-entry"
    target: T-014
    type: alternative_to
    rationale: "Native NT applications enter via NTSTATUS NT_main(PEB) rather than the Win32 main(), paralleling how NtCreateUserProcess creates processes that bypass the Win32 subsystem setup path that CreateProcessW drives."
  - source: "process-handle-table"
    target: T-015
    type: concept_link
    rationale: "PPID spoofing manipulates the parent-process handle stored in the creating process's handle table before NtCreateUserProcess inherits it; SEC670 establishes that handles live in a per-process table rather than a system-wide shared table."
  - source: T-014
    target: T-013
    type: alternative_to
    rationale: "The SEC670 material contrasts CreateProcessW with NT-level process creation, implying that direct NtCreateUserProcess (T-014) is the lower-level alternative used for hollowing (T-013) when CreateProcessW visibility is undesirable."
```

### Concept Nodes

```yaml
concepts:
  - id: "x64-shadow-store"
    name: "x64 Calling Convention Shadow Store (RSP+0..RSP+20h)"
    category: os-internal
    description: "On x64 Windows, the first 32 bytes (0x20) of every stack frame are reserved as a shadow store so the callee can spill RCX, RDX, R8, and R9. Stack arguments therefore begin at RSP+20h rather than RSP. SEC670 frames this as the reason 64-bit stack arguments start at RSP+20h and distinguishes it from shadow stack enforcement (Hardware Shadow Stack, a CET feature). The shadow store is a calling-convention artifact, not a security mitigation."
    relevant_to: [T-001, T-002, T-005]
    tags: [x64, calling-convention, stack-layout, rop, syscall-dispatch]

  - id: "pe-image-dos-header"
    name: "IMAGE_DOS_HEADER and e_lfanew"
    category: windows-structure
    description: "The MS-DOS 2.0 EXE header (IMAGE_DOS_HEADER) prefixes every PE file. The e_magic field at offset 0x0 contains 0x5A4D ('MZ'). The e_lfanew DWORD at offset 0x3C holds the file offset to the real PE header (IMAGE_NT_HEADERS). SEC670 notes that almost every field in IMAGE_DOS_HEADER is WORD-sized, allowing parsers to step two bytes at a time. The byte immediately following the DOS header is typically 0x00."
    relevant_to: [T-002, T-004, T-008, T-013]
    tags: [pe, dos-header, e_lfanew, image-parsing]

  - id: "pe-image-optional-header64"
    name: "IMAGE_OPTIONAL_HEADER64 (PE32+)"
    category: windows-structure
    description: "The 64-bit optional header structure for PE32+ images. The Magic field is 0x20B (PE32+); 0x10B indicates PE32. AddressOfEntryPoint (a DWORD RVA) is the field that refers to the program's main function — SEC670 explicitly contrasts this with ImageBase and PointerToSymbolTable. Other fields of interest to offensive tooling include ImageBase (ULONGLONG), DllCharacteristics (controls CFG, ASLR, DEP, CIG), and the DataDirectory array (which indexes Import, Export, Resource, and other directories used by Hells Gate SSN resolution and Threadless export hijacking)."
    relevant_to: [T-002, T-004, T-008, T-013]
    tags: [pe, optional-header, pe32+, address-of-entry-point, dllcharacteristics]

  - id: "thread-context-structure"
    name: "CONTEXT Structure and Thread Hijack Primitives"
    category: windows-structure
    description: "The x64 CONTEXT structure holds DWORD64 register slots including R11 through R15, Rip, and fields like LaufExceptionTop used for exception dispatch. SEC670 establishes that hijacking a thread requires modifying the thread context (SetThreadContext) — not thread state or thread priority. The Rip field within CONTEXT is the lever that redirects execution to injected shellcode or to a ROP pivot. CONTEXT manipulation is the unifying primitive behind WaitingThread hijack, thread hijack in T-013, and the frame restoration logic in Ekko ROP sleep (T-005)."
    relevant_to: [T-005, T-013]
    tags: [context, thread-hijack, setthreadcontext, rip, registers]

  - id: "process-handle-table"
    name: "Per-Process Handle Table"
    category: os-internal
    description: "Each user-mode process maintains its own handle table for kernel objects rather than sharing a system-wide table. SEC670 review answers identify this per-process organization as the correct model. This is operationally significant for techniques that rely on inheriting or duplicating handles across process boundaries: PPID spoofing depends on the parent-process handle sitting in the creator's table at NtCreateUserProcess time, handle blocking (T-016) manipulates which handles survive cross-process duplication, and Pool Party/Early Cascade (T-007/T-012) require crossing handle boundaries into a remote process's worker factory or thread objects."
    relevant_to: [T-007, T-012, T-015, T-016]
    tags: [handle-table, process-internals, handle-inheritance]

  - id: "native-application-peb-entry"
    name: "Native NT Application Entry Signature"
    category: os-internal
    description: "Native NT applications do not use the C runtime main() entry signature. Their entry point receives a pointer to the PEB and returns NTSTATUS, with the SEC670-identified signature NTSTATUS NT_main(PEB). Native applications bypass the Win32 subsystem initialization that CreateProcessW triggers, execute before Win32k is fully available, and are the model behind T-014's NtCreateUserProcess direct-creation path used to launch minimal-footprint sacrificial processes for hollowing and reflection."
    relevant_to: [T-004, T-014]
    tags: [native-application, peb, ntstatus, subsystem-bypass]

  - id: "win32-find-data-file-attributes"
    name: "WIN32_FIND_DATA File Attribute Structure"
    category: windows-structure
    description: "WIN32_FIND_DATA is the user-mode structure that holds the attributes of a file retrieved via FindFirstFile/FindNextFile. SEC670 contrasts it with KUSER_SHARED_DATA (a read-only user-shared kernel page) and FILE_OBJECT (the kernel-side structure). For offensive tradecraft, WIN32_FIND_DATA is the structure parsed when enumerating files for NTFS extended-attribute persistence (T-017) and when implant recon code inventories candidate paths for staging or exfil."
    relevant_to: [T-017, T-023]
    tags: [win32-find-data, file-enumeration, persistence]

  - id: "setnamedsecurityinfo"
    name: "SetNamedSecurityInfoA and Named-Securable-Object DACLs"
    category: os-internal
    description: "SetNamedSecurityInfoA modifies the security descriptor of a named object (file, registry key, service, etc.) by replacing the DACL, SACL, owner, or group. SEC670 documents the API signature in the context of persistence operations. Offensively, this API is used to weaken ACLs on persistence targets (scheduled task XML files, COM registry keys, NTFS EA files) so that lower-privileged implant code can write and later re-read them, and to harden planted artifacts against defender remediation."
    relevant_to: [T-017, T-016]
    tags: [dacl, security-descriptor, acl-manipulation, persistence]
```

### Detection Insights

```yaml
# Material is review-question oriented and does not discuss detection indicators, ETW providers, Sysmon event IDs, or memory scanner heuristics in any unit. No detection insights can be extracted without fabricating content not present in the material.
detection: []

sigma_ideas: []
```

### Operational Chains

```yaml
# The SANS SEC670 units in this batch are unit review questions and slide excerpts covering isolated Windows internals concepts. None of the 26 units describe a multi-step offensive chain with explicit sequencing language. No operational chains can be derived without inventing relationships the material does not state.
chains:
  - name: "PE-parse-to-function-address chain (implied by Lab 3.1 GetFunctionAddress)"
    description: "Implied by SEC670 Lab 3.1 but not operationally sequenced in the material"
    steps: []
    notes: "Lab 3.1: GetFunctionAddress instructs students to parse a PE file to obtain the address of a given function. The lab reference is the only sequencing cue in the batch; full step ordering is deferred to the eWorkbook and not visible in the excerpt."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "coverage-gap-pe-parsing-prerequisite"
    title: "PE Parsing as Documented Prerequisite for SSN Resolution and Export Hijack"
    kind: coverage-gap
    description: "Multiple SEC670 units cover the IMAGE_DOS_HEADER (e_magic, e_lfanew at 0x3C), IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+, AddressOfEntryPoint, DataDirectory), and the Lab 3.1 GetFunctionAddress exercise for parsing export tables. The vault documents T-002 (Hells Gate SSN resolution) and T-008 (Threadless export hijack) without a concept node that captures the prerequisite PE-walk primitive a reader needs. Adding a PE-parse concept cluster would make T-002 and T-008 navigable to readers without prior Windows internals background."
    would_relate_to: [T-002, T-004, T-008, T-013]
    source_units: ["unit 11", "unit 12", "unit 13", "unit 14", "unit 15", "unit 16", "unit 17", "unit 18", "unit 19", "unit 25", "unit 26"]
    tags: [pe-parsing, coverage-gap, prerequisite-knowledge, image-parsing]

  - id: "proposed-thread-context-hijack-primitive"
    title: "CONTEXT-Based Thread Hijack as Standalone Primitive"
    kind: proposed-technique
    description: "SEC670 establishes thread hijacking as the act of modifying a thread's CONTEXT structure (specifically the Rip field) rather than thread state or priority. T-013 bundles thread hijack under 'Remaining Methods' alongside hollowing, mapping, and module stomping. The CONTEXT-modification primitive is reusable beyond WaitingThread — it underlies thread hijack in sacrificial suspended processes, Ekko ROP sleep's frame restoration, and Early Cascade's pre-LdrInitializeThunk APC dispatch. Elevating CONTEXT hijack to its own concept node or sub-card would clarify which injection methods share the primitive versus those that use APCs or section mapping."
    would_relate_to: [T-005, T-013, T-012]
    source_units: ["unit 20", "unit 21", "unit 22"]
    tags: [context, thread-hijack, primitive, injection]

  - id: "cross-source-convergence-shadow-store-and-rop"
    title: "x64 Shadow Store as Foundation for ROP Frame Construction"
    kind: cross-source-convergence
    description: "SEC670 documents the x64 calling convention's 32-byte shadow store at RSP+0..RSP+20h, distinguishing it from Hardware Shadow Stack enforcement. This same reservation is the structural reason Ekko (T-005) ROP chains can construct valid caller frames for RtlCaptureContext, SetWaitableTimerEx, and WaitForSingleObjectEx, and is the reason Hell's Gate stubs leave the shadow store intact when invoking syscall stubs. The convergence between calling-convention fundamentals and the vault's ROP/sleep-obfuscation techniques is implicit in the source code but never surfaced as a shared concept. Documenting the shadow store as a concept node connected to both T-001 and T-005 would close that gap."
    would_relate_to: [T-001, T-002, T-005]
    source_units: ["unit 4", "unit 5"]
    tags: [x64, calling-convention, shadow-store, rop, cross-source]
```