## Synthesis Summary

This batch of 40 units from SANS SEC670 contains introductory Windows OS internals material and course methodology content. The substantive technical content maps to T-015 (PPID Spoofing), T-014 (NtCreateUserProcess), T-007 (Process Injection), T-016 (EDR Evasion Suite), T-004 (PEB Walker), and T-023 (Client Capabilities). The material covers the Windows Object Manager architecture (object headers, bodies, ObTypeIndexTable, ACL-protected securable objects), per-process handle tables and access rights (CreateProcess, CloseHandle, DuplicateHandle, GetHandleInformation with PROCESS_ALL_ACCESS), process creation internals via CreateProcess producing _EPROCESS/_KPROCESS kernel objects tracked in a linked list, and system enumeration via NtQuerySystemInformation with SYSTEM_PROCESS_INFORMATION. The knowledge gap this fills is the OS-level explanation of why handle-mediated techniques function: how the handle table indexes into objects, what security descriptors gate access, and how the kernel's process linked list underpins enumeration and PEB-based walking — none of which is visible in Rust source code. Approximately 25 of the 40 units are course roadmaps, philosophical discussions, duplicate slides, or table-of-contents pages and were skipped as off-theme methodology content.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: windows-handle-table
    target: T-015
    type: enables
    rationale: "PPID spoofing requires opening a handle to the desired parent process; the handle table and its access rights mediation (PROCESS_CREATE_PROCESS) determine whether the spoof succeeds"

  - source: windows-handle-table
    target: T-007
    type: requires
    rationale: "Process injection techniques require a handle to the target process with specific access rights (VM_WRITE, VM_OPERATION); the handle table entry governs whether these operations are permitted"

  - source: securable-object-acl
    target: T-016
    type: concept_link
    rationale: "The EDR evasion suite's handle blocking capability operates at the level of ACL-protected securable objects; understanding that user-mode-exposed objects carry security descriptors explains why handle blocking works and where it can be bypassed"

  - source: eprocess-kprocess
    target: T-004
    type: enables
    rationale: "The PEB walker reads module lists via the PEB, which is accessible through the _EPROCESS structure; the kernel linked list of _EPROCESS objects is the mechanism by which all processes are locatable"

  - source: eprocess-kprocess
    target: T-016
    type: concept_link
    rationale: "PEB unlinking modifies the module list reachable through the process's _EPROCESS→PEB chain; the linked-list organization of _EPROCESS is also what makes PEB-based detection of unlinked modules possible via scanning"

  - source: ntquerysysteminformation-enum
    target: T-023
    type: enables
    rationale: "NtQuerySystemInformation with SystemProcessInformation is the NT-level primitive for gathering system and process information, directly serving the recon and sysinfo capabilities documented in T-023"

  - source: windows-object-manager
    target: T-014
    type: concept_link
    rationale: "NtCreateUserProcess creates a process object through the Object Manager, which allocates the object header and body, assigns a handle, and links it into the kernel process list — explaining why direct NT process creation bypasses Win32-layer CreateProcess wrappers"
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-object-manager"
    name: "Windows Object Manager"
    category: os-internal
    description: "The Object Manager is the kernel component that standardizes creation, validation, and handle management for all Windows objects. Every object shares a common structure: an object header (type, name, directory, security descriptor, handle count) and an object body unique to the object type. The ObTypeIndexTable indexes object types so that generic operations (close, duplicate, query security) can be dispatched uniformly regardless of whether the object is a process, file, or event."
    relevant_to: [T-014, T-015, T-007]
    tags: [windows-internals, kernel, object-manager, handle]

  - id: "windows-handle-table"
    name: "Per-Process Handle Table"
    category: windows-structure
    description: "Each process maintains its own handle table where handles serve as indices into handle table entries. Each entry records the accessed object and the granted access rights (e.g., PROCESS_ALL_ACCESS, PROCESS_VM_WRITE). APIs such as CreateProcess, CloseHandle, DuplicateHandle, and GetHandleInformation operate on these entries. The Principle of Least Privilege governs that handles should carry only the access rights needed for the intended operation — a constraint that directly affects whether injection, PPID spoofing, or handle duplication succeeds."
    relevant_to: [T-015, T-007, T-014, T-016]
    tags: [handle-table, access-rights, least-privilege, windows-internals]

  - id: "securable-object-acl"
    name: "Securable Object ACL and Security Descriptor"
    category: defense-mechanism
    description: "Objects exposed to user mode are protected by access control lists (ACLs) and security descriptors. The Object Manager acts as a gatekeeper, checking ACLs before granting access to querying or manipulating processes. Kernel-internal objects not exposed to user mode do not require the same ACL protection. Process Explorer can enumerate and display handles to securable objects, making handle-based tradecraft visible to defenders who inspect open handles and their associated access masks."
    relevant_to: [T-016, T-015, T-007]
    tags: [acl, security-descriptor, object-security, defense-mechanism]

  - id: "eprocess-kprocess"
    name: "_EPROCESS and _KPROCESS Structures"
    category: windows-structure
    description: "Process creation via CreateProcess triggers the kernel to construct a process object in system space. The _EPROCESS is the executive process object containing the PEB pointer, image filename, and security context. The _KPROCESS is the kernel process object (embedded within _EPROCESS) containing scheduler-related fields such as thread list and quantum. The kernel tracks all processes by linking _EPROCESS objects in a doubly-linked list, which is the mechanism underlying process enumeration and PEB-based module walking."
    relevant_to: [T-004, T-016, T-014, T-023]
    tags: [eprocess, kprocess, peb, process-list, windows-internals]

  - id: "ntquerysysteminformation-enum"
    name: "NtQuerySystemInformation with SYSTEM_PROCESS_INFORMATION"
    category: os-internal
    description: "NtQuerySystemInformation is the NT-level API for enumerating system information. When called with the SystemProcessInformation class, it returns an NTSTATUS and populates a buffer of SYSTEM_PROCESS_INFORMATION structures, each describing a process's image name, PID, thread count, handle count, and CPU time. This API underlies tools that perform process enumeration without relying on the Win32 Toolhelp API (CreateToolhelp32Snapshot) or WTS session enumeration (WTSEnumerateProcesses)."
    relevant_to: [T-023, T-016]
    tags: [nt-api, process-enumeration, recon, sysinfo]

  - id: "windows-service-pack"
    name: "Windows Service Packs and Hotfix Bundling"
    category: os-internal
    description: "Service packs bundle groups of hotfixes so that a user can apply all prior fixes in a single update without installing each one sequentially. Different service pack levels change the set of patched vulnerabilities on a target, which affects exploit compatibility — implant developers and LPE technique authors must account for the target OS version and service pack when selecting or adjusting exploits, including those sourced from frameworks like Metasploit."
    relevant_to: []
    tags: [orphan, service-pack, hotfix, exploit-compat, patch-management]

  - id: "wua-patch-enumeration"
    name: "Windows Update Agent (WUA) APIs for Patch Enumeration"
    category: os-internal
    description: "The Windows Update Agent APIs provide a programmatic interface for querying installed patches and hotfixes. Red team tools can use WUA APIs to retrieve patch information during reconnaissance, determining which vulnerabilities remain unpatched on a target system and therefore which exploits or LPE techniques are viable."
    relevant_to: [T-023]
    tags: [wua, patch-enumeration, recon, sysinfo]
```

### Detection Insights

```yaml
detection:
  - indicator: "Process handle opened with PROCESS_ALL_ACCESS or PROCESS_VM_WRITE to a foreign process"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-007, T-015, T-016]
    description: "When a process opens a handle to another process with broad access rights such as PROCESS_ALL_ACCESS or PROCESS_VM_WRITE | PROCESS_VM_OPERATION, the Object Manager's ACL check generates an access attempt event. Security tools that monitor handle creation (including Process Explorer's handle view and kernel callback-based EDRs) can flag cross-process handle acquisition with excessive rights as a precursor to injection or PPID spoofing."
    bypassed_by: "not discussed"

  - indicator: "NtQuerySystemInformation calls with SystemProcessInformation class from an unbacked or suspicious process"
    source: behavioral
    confidence: low
    relevant_to: [T-023, T-016]
    description: "Process enumeration via NtQuerySystemInformation is a standard recon activity. While the API call itself is legitimate and used by many administrative tools, calling it from a process with no module on disk, from an unbacked memory region, or at high frequency can indicate implant reconnaissance behavior. The call returns SYSTEM_PROCESS_INFORMATION structures that reveal running processes, PIDs, and thread counts."
    bypassed_by: "not discussed"

  - indicator: "Open handles to parent processes from non-child processes"
    source: behavioral
    confidence: medium
    relevant_to: [T-015]
    description: "PPID spoofing requires opening a handle to the desired parent process with PROCESS_CREATE_PROCESS access. A process that is not a child of the target parent but holds an open handle to it with create-process rights is anomalous. Handle table inspection tools and EDR handle-monitoring capabilities can surface this pattern."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Cross-Process Handle with VM_WRITE Access"
    logsource: windows-security
    condition_summary: "Handle access event where the source PID differs from the target PID and the granted access mask includes PROCESS_VM_WRITE or PROCESS_VM_OPERATION"

  - title: "Parent Process Handle from Non-Child"
    logsource: windows-security
    condition_summary: "Handle access event where the target process is a known parent (e.g., explorer.exe) and the source process is not a descendant of that parent, with access mask including PROCESS_CREATE_PROCESS"
```

### Operational Chains

```yaml
chains:
  - name: "PPID-Spoofed Process Creation with Handle Acquisition"
    description: "Creating a process with a spoofed parent PID requires handle acquisition before the creation call"
    steps:
      - technique: T-015
        role: "Open handle to desired parent process with PROCESS_CREATE_PROCESS access right via the per-process handle table"
      - technique: T-014
        role: "Invoke NtCreateUserProcess (or CreateProcess with extended attributes) passing the parent handle to set the real parent of the new process"
      - technique: T-007
        role: "Inject into the newly created suspended process before its main thread resumes"
    notes: "The material does not describe this chain as a walkthrough; it is derived from the relationship between handle table access rights (Unit 8-9) and process creation internals (Unit 36). The chain requires the parent process to be securable and accessible per its ACL (Unit 5-7)."

  - name: "System Reconnaissance via NT Enumeration APIs"
    description: "Gathering process and system information using NT-level APIs to support target selection"
    steps:
      - technique: T-023
        role: "Query system and process information using NtQuerySystemInformation with SystemProcessInformation to enumerate running processes, PIDs, and thread counts"
      - technique: T-023
        role: "Gather OS version, service pack, and hotfix information via WUA APIs to determine exploit viability"
      - technique: T-023
        role: "Select target process for injection based on enumerated process list and patch status"
    notes: "The material presents these as separate enumeration modules (Units 20-22, 28-30, 33, 34, 40) rather than an explicit chain. The sequencing is inferred from the course structure placing OS info gathering before process enumeration."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "windows-object-manager-foundation"
    title: "Windows Object Manager as Foundational Knowledge for Handle Tradecraft"
    kind: coverage-gap
    description: "SEC670 dedicates multiple units to the Object Manager's role in standardizing object headers, bodies, handle tables, and ACL-gated access. The vault documents handle blocking (T-016), PPID spoofing (T-015), and injection (T-007) without explaining the Object Manager layer that mediates all of these. A cross-cutting concept document on the Object Manager would help operators understand why handle-based techniques succeed or fail at the kernel's ACL check, not just at the API call level."
    would_relate_to: [T-015, T-016, T-007, T-014]
    source_units: ["unit 2", "unit 3", "unit 5", "unit 8"]
    tags: [object-manager, handle, acl, coverage-gap, windows-internals]

  - id: "patch-recon-for-exploit-selection"
    title: "Patch and Hotfix Reconnaissance for Exploit Viability"
    kind: proposed-technique
    description: "The material covers using WUA APIs and service-pack/hotfix enumeration to determine which vulnerabilities remain unpatched, directly informing exploit and LPE technique selection. The vault's T-023 (Client Capabilities) includes recon and sysinfo collection but does not document a dedicated patch-status reconnaissance capability that feeds into exploit selection. This would merit its own treatment since patch status determines whether kernel-touching techniques (T-016 BYOVD, T-013 remaining injection) are viable on a given target."
    would_relate_to: [T-023]
    source_units: ["unit 28", "unit 30", "unit 33"]
    tags: [recon, patch-enumeration, wua, exploit-selection, proposed-technique]

  - id: "process-enumeration-method-comparison"
    title: "Process Enumeration Method Comparison (Toolhelp vs WTS vs NT)"
    kind: cross-source-convergence
    description: "SEC670's table of contents (Units 20-22) and process enumeration objectives (Unit 34) describe multiple methods for enumerating processes: CreateToolhelp32Snapshot, WTSEnumerateProcesses, and NtQuerySystemInformation with SYSTEM_PROCESS_INFORMATION. Each method surfaces different information and has different detection characteristics. The vault's T-023 recon and T-016 anti-analysis would benefit from documenting which enumeration method to choose based on stealth requirements, since NtQuerySystemInformation bypasses Win32-layer hooks while Toolhelp is more commonly monitored."
    would_relate_to: [T-023, T-016]
    source_units: ["unit 20", "unit 22", "unit 34", "unit 40"]
    tags: [process-enumeration, recon, method-comparison, cross-source-convergence]
```