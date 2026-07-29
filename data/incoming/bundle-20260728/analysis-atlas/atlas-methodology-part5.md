## Synthesis Summary

The substantive on-theme content in this batch maps to T-004 (PEB Walker), T-007 (Process Injection), T-013 (Remaining Injection Methods), T-015 (PPID Spoofing), and T-016 (EDR Evasion Suite) — but only at the foundational level: the material introduces the Windows Object Manager, object header/body structure, handle mechanics (multiples of 4, never zero, first valid handle 4), the role of ACLs and security descriptors on securable objects, and the HANDLE/HMODULE/HINSTANCE typedef lineage from WinNt.h. SANS SEC670 Book 1 (Units 21, 24, 25, 26, 27) supplies the OS-internals vocabulary that explains *why* handle blocking (T-016), process handle acquisition for injection (T-007/T-013), and parent-process handle operations (T-015) work at the kernel interface. Of the 40 units, 32 were skipped as off-theme: roughly 13 are CRTO methodology/red-team-definition/OPSEC/Kerberos content (Active Directory auth falls outside HUGIN's user-mode implant scope), 1 is an Ansible architecture diagram (Linux config management), and 18 are SEC670 course roadmaps, title slides, project-management exercises, and philosophical "why offensive tools" summaries that do not contribute graph-grade technical content. The knowledge gap filled by the 8 retained units is the Object Manager mental model that source code in `dark_crystal` and `client_rust` assumes the reader already possesses — without it, handle-table manipulation code reads as opaque boilerplate.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "windows-handle-mechanics"
    target: T-015
    type: requires
    rationale: "PPID spoofing operates on parent-process handles (NtOpenProcess → PROC_THREAD_ATTRIBUTE_PARENT_PROCESS); the SEC670 material establishes that handle values are indices into a per-process handle table (multiples of 4, first valid is 4) issued by the Object Manager, which is the substrate the spoofing primitive manipulates."
  - source: "windows-object-header-body"
    target: T-016
    type: concept_link
    rationale: "T-016's handle-blocking technique operates on the security descriptor and ACL embedded in the object header that SEC670 describes; the generic Close/Duplicate/QuerySecurity services the material names are exactly the calls an external process must route through the Object Manager to reach a target process object."
  - source: "securable-objects-acl-sd"
    target: T-016
    type: enables
    rationale: "SEC670 explicitly states securable objects exposed to user mode must be protected by ACLs and security descriptors, with the Object Manager acting as gatekeeper. T-016's 'block external handle access' technique works precisely because this gatekeeper enforces ACL checks on OpenProcess — and because the ACL can be hardened (or the access masked) to deny those checks."
  - source: T-004
    target: "windows-data-types-handle"
    type: requires
    rationale: "The PEB walker resolves modules through HMODULE values returned by the loader; SEC670 establishes that HMODULE/HINSTANCE are interchangeable typedefs of HANDLE, which is itself PVOID — the type identity the walker code relies on when treating module bases as opaque pointers."
  - source: "windows-object-manager"
    target: T-007
    type: requires
    rationale: "Every process injection primitive in T-007/T-013 begins with acquiring a process object via the Object Manager (NtOpenProcess) and operating on it via NtAllocateVirtualMemory, NtWriteVirtualMemory, etc. — services the material categorizes as 'specific services' on a process object body, distinct from generic Close/Duplicate."
  - source: "generic-vs-specific-object-services"
    target: "windows-handle-mechanics"
    type: concept_link
    rationale: "The material separates generic services (Close, duplicate, query/set security, wait) available to all objects from type-specific services (create, open, query). Handle mechanics — multiples of 4, never zero — are the index scheme that lets one generic Close primitive dispatch to any object body, which is why one syscall (NtClose) retires handles across all object types."
# Only six edges are supportable from this batch. The material is introductory and does not describe sequencing between specific HUGIN techniques (e.g., it does not state that PPID spoofing precedes injection, or that PEB unlink follows unhooking). Such edges would be fabricated.
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-object-manager"
    name: "Windows Object Manager"
    category: os-internal
    description: "A kernel subsystem that represents system resources (files, processes, threads, registry keys, images, semaphores) as data structures living in system address space. The Object Manager maintains a single common header schema for every object regardless of type, which permits one body of code to create, validate, query security, and close any object. SEC670 states the executive implements over 4,000 object types, some of which are not reachable via documented Windows APIs."
    relevant_to: [T-007, T-013, T-015, T-016]
    tags: [windows-internals, object-manager, kernel, handle, foundation]

  - id: "windows-object-header-body"
    name: "Object Header and Object Body Schema"
    category: windows-structure
    description: "Every executive object has a standardized header containing type, name, directory, security descriptor, handle count and list, and optional subheaders; the object body is unique to the object type. This separation is what lets the Object Manager service any object with generic operations. The handle count and list in the header track every process handle table entry that currently references the object — relevant when a process object's handle count is inspected by EDR or when an injector relies on the handle list for duplication."
    relevant_to: [T-016, T-007, T-013]
    tags: [windows-internals, object-header, handle-list, security-descriptor]

  - id: "windows-handle-mechanics"
    name: "Handle Value Mechanics"
    category: windows-internal
    description: "Handle values are always a multiple of 4, never zero, with the first valid handle being 4. A handle is a per-process table index (scaled by 4 on use) into the process handle table, which is itself managed by the Object Manager. SEC670 notes handle values are 32-bit or 64-bit depending on architecture. The 'multiple of 4' property encodes the table slot index in the low bits and historically left room for inherit/protect/audit attributes in the low two bits — relevant when an operator inspects or forges handle values."
    relevant_to: [T-004, T-007, T-013, T-015, T-016]
    tags: [windows-internals, handle-table, foundation, object-manager]

  - id: "securable-objects-acl-sd"
    name: "Securable Objects, ACLs, and Security Descriptors"
    category: defense-mechanism
    description: "Objects exposed to user mode must be protected. Each securable object carries its own access control list (ACL) and security descriptor that dictates what actions a querying process may perform. The system acts as gatekeeper, performing access checks on every Open*/NtOpen* call. SEC670 notes that internal kernel objects not exposed to user mode may not carry the same protections — a distinction operators rely on when reasoning about which objects an EDR's kernel callback can observe."
    relevant_to: [T-016, T-015, T-013]
    tags: [windows-internals, acl, security-descriptor, defense-mechanism, access-check]

  - id: "generic-vs-specific-object-services"
    name: "Generic vs. Type-Specific Object Services"
    category: os-internal
    description: "All objects regardless of type support generic services (Close, Duplicate, Query/Set Security, WaitForSingleObject); each object type additionally exposes type-specific services (Create, Open, Query). CloseHandle works on file, process, thread, event, and key handles alike because the generic dispatch path reads the object header to find the type-specific close routine. This is why a single NtClose syscall retires any handle and why handle-blocking techniques must intercept at the generic layer to be effective."
    relevant_to: [T-016, T-007, T-013]
    tags: [windows-internals, object-services, generic-dispatch, foundation]

  - id: "windows-data-types-handle"
    name: "HANDLE/HMODULE/HINSTANCE Typedef Lineage"
    category: windows-structure
    description: "Per WinNt.h, HANDLE is a typedef of PVOID (void*). Derived handle types (HKEY, HMODULE, HINSTANCE, HRSRC, LPHANDLE) are all built on this HANDLE base and are technically interchangeable — SEC670 demonstrates casting HKEY_LOCAL_MACHINE directly to PVOID with no functional issue. The convention exists for code clarity, not type safety. HMODULE and HINSTANCE are explicitly interchangeable; this matters when an operator inspects a loader-returned HMODULE in PEB-walking code (T-004) and treats it as a raw pointer for arithmetic."
    relevant_to: [T-004, T-007]
    tags: [windows-internals, data-types, handle, foundation, winnt-h]
```

### Detection Insights

```yaml
detection:
  - indicator: "Process handle acquisition with cross-process access rights (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_TERMINATE)"
    source: kernel-callback
    confidence: medium
    relevant_to: [T-007, T-013, T-015, T-016]
    description: "Every cross-process object access routes through the Object Manager's gatekeeper (SEC670 Windows Objects 6). When a process requests one of the high-privilege access masks listed above on a foreign process object, the access check against the target's security descriptor and ACL is observable. EDRs register ObRegisterCallbacks (process object pre-operation filter) to inspect or strip these rights before the handle is returned. The handle value itself (multiple of 4, architecture-width index) is not the indicator — the access mask negotiation is."
    bypassed_by: "T-016 handle-blocking masks the target process object so the access check denies the foreign opener, but this material does not describe evading ObRegisterCallbacks from the requestor side. SEC670 covers the defense mechanism's existence, not its circumvention."

  - indicator: "Foreign handle to current process visible in Process Explorer handle table"
    source: behavioral
    confidence: low
    relevant_to: [T-016]
    description: "SEC670 explicitly references Process Explorer for inspecting handles to objects. An analyst invoking Find → Find Handle or DLL on the suspect process can locate foreign handles pointing at the protected process's process object. The handle list field in the object header (per Windows Objects 4) is the underlying data source. This is a manual analyst technique, not automated telemetry."
    bypassed_by: "not discussed"

  - indicator: "Generic Close (NtClose) issued on a never-opened or zero handle"
    source: windows-security-log
    confidence: low
    relevant_to: [T-016]
    description: "SEC670 establishes the first valid handle value is 4 and that 0 is never a valid handle. Code that issues NtClose(0), NtClose on an already-freed slot, or NtClose on a value not a multiple of 4 generates STATUS_INVALID_HANDLE (0xC0000008). With object-access auditing enabled on the process object, these failures surface in the Windows Security log. Not all ecosystems audit this by default."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Cross-Process VM Handle Acquisition"
    logsource: kernel-callback
    condition_summary: "ObRegisterCallbacks process pre-operation filter fires on PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD access rights requested against a PID other than the requestor PID"
  - title: "Invalid Handle Closure Status"
    logsource: windows-security
    condition_summary: "Event ID 4689 or kernel audit subcategory Process Handle Operations reports STATUS_INVALID_HANDLE (0xC0000008) on NtClose of a zero or non-multiple-of-4 handle value"
```

### Operational Chains

```yaml
chains:
  - name: "No operational chains derivable from this batch"
    description: "The retained units (4, 15, 16, 21, 24, 25, 26, 27) introduce foundational Windows Object Manager and handle mechanics but do not sequence them into multi-step operational workflows. No language of the form 'after X, do Y' or 'X enables Z' connects HUGIN techniques in this material."
    steps: []
    notes: "The material is the introductory Book 1 of SEC670 covering Windows data types, object model basics, and course philosophy. Sequenced tradecraft (handle acquisition → access mask downgrade → cross-process write) appears in later SEC670 books and CRTO modules not present in this batch. Do not infer chains the material does not state."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "windows-object-manager-foundations-card"
    title: "Windows Object Manager Foundations as a Reference Concept Card"
    kind: coverage-gap
    description: "SEC670 Book 1 devotes multiple units to the Object Manager, object header/body schema, handle table mechanics, and ACL/security-descriptor gating on securable objects. The vault currently distributes this knowledge implicitly across T-007, T-013, T-015, and T-016 — operators must reverse-engineer the conceptual model from scattered technique cards. A standalone reference node (not a T-NNN technique, but a graph-anchored concept cluster) would let readers new to Windows internals reach the technique cards with the prerequisite mental model already in place."
    would_relate_to: [T-004, T-007, T-013, T-015, T-016]
    source_units: ["unit 21", "unit 24", "unit 25", "unit 26", "unit 27"]
    tags: [windows-internals, object-manager, foundation, coverage-gap, concept-cluster]

  - id: "object-access-audit-detection-surface"
    title: "Object Access Audit Detection Surface for Handle Operations"
    kind: coverage-gap
    description: "SEC670 frames the Object Manager as an explicit gatekeeper performing ACL checks on every handle negotiation. The vault's T-016 handle-blocking entry documents the offensive side; the corresponding defensive surface (audit-policy configuration that surfaces STATUS_INVALID_HANDLE and access-denied events when an EDR probes a hardened process object) is not represented as a detection concept node in the vault. SEC670's framing implies this is a primary blue-team telemetry source for handle-blocking efficacy."
    would_relate_to: [T-016]
    source_units: ["unit 26", "unit 27"]
    tags: [detection, audit-policy, object-access, handle, coverage-gap]

  - id: "sec670-book1-introductory-tier-filter"
    title: "SEC670 Book 1 Is Foundational Tier — Filter Out from Operational Batches"
    kind: cross-source-convergence
    description: "Across SEC670 Book 1 (units 1-4, 15-19, 21, 24-40) the material is consistently introductory: course roadmaps, data-type typedefs, Object Manager basics, project-management exercises, and philosophical framing. None of it documents executable tradecraft. Future batches sourced from SEC670 Books 2+ (Persistence, Evasion, C2, Shellcode) are expected to carry the operational density this batch lacks. This convergence signal suggests triaging SEC670 Book 1 content as a 'foundations' reference tier rather than primary graph material."
    would_relate_to: []
    source_units: ["unit 1", "unit 2", "unit 3", "unit 4", "unit 15", "unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 21", "unit 22", "unit 23", "unit 24", "unit 25", "unit 26", "unit 27", "unit 28", "unit 29", "unit 30", "unit 31", "unit 32", "unit 33", "unit 34", "unit 35", "unit 36", "unit 37", "unit 38", "unit 39", "unit 40"]
    tags: [foundations, triage, sec670, cross-source-convergence]

  - id: "crto-methodology-tier-offtheme"
    title: "CRTO Methodology and Kerberos Units Are Off-Theme for HUGIN"
    kind: coverage-gap
    description: "CRTO units 5-13 cover red-team definition, OPSEC, engagement phases, MITRE ATT&CK threat profiling, and Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP authentication. HUGIN's theme is user-mode Windows implant development and EDR evasion; CRTO methodology framing and AD-authentication flows sit outside that scope. The vault does not currently have a card covering Kerberos ticket manipulation (Diamond/PAC/RODC/S4U), and if that gap were ever addressed it would belong to a post-exploitation credential card distinct from the current 23."
    would_relate_to: []
    source_units: ["unit 5", "unit 6", "unit 7", "unit 8", "unit 9", "unit 10", "unit 11", "unit 12", "unit 13"]
    tags: [crto, methodology, kerberos, off-theme, triage]
```