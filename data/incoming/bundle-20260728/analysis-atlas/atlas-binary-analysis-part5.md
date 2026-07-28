## Synthesis Summary

This batch of SANS SEC670 "Red Teaming Tools: Developing Windows Implants" material maps primarily to T-001 (RecycledGate), T-002 (Hell's/Halo's/Tartarus Gate), T-004 (PEB Walker), T-013 (Remaining Injection Methods — Reflective DLL Injection), T-016 (EDR Evasion Suite — NTDLL patching, IAT hooking, memory hooking concepts), and T-017 (Persistence Suite — security structures and port monitor concepts). The material covers Windows PE file anatomy (DOS stub, COFF, optional header, .TEXT/.rdata sections, RVAs), system DLL interrelationships (ntdll/kernel32/kernelbase/user32 and forwarders), implicit vs explicit DLL linking, classic vs reflective DLL injection step-by-step, syscall number variation across Windows versions, user/kernel mode transition mechanics, IAT hooking mechanics with VirtualProtect page-permission flips, and binary patching risks for system files like NTDLL. The knowledge gap the material fills is foundational: why PE structures matter for module resolution (T-004), why section permissions matter for memory scanners (T-016), why IAT page-protection flips are observable (T-016), and the step-by-step operational differences between classic DLL injection and RDI (T-013). Off-theme units skipped: 11 and 37 (Linux ELF / shared object format, not Windows tradecraft). Units 8–10, 13, 14 (Windows security descriptor structures) are retained as on-theme Windows internals concept nodes because they underpin persistence and privilege-tradecraft even though they are not themselves offensive primitives.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "pe-file-structure-anatomy"
    target: T-004
    type: requires
    rationale: "PEB Walker relies on parsing in-memory PE export and import directories to resolve functions by hash; the SEC670 material walks through PE optional header, directory table, and export directory as prerequisites for module/function resolution."
  - source: "windows-system-dlls-architecture"
    target: T-004
    type: concept_link
    rationale: "SEC670 explicitly identifies ntdll, kernel32, kernelbase, and user32 as the DLLs mapped into nearly every process and notes that kernel32 re-exports many ntdll functions as forwarders — this is the structural backdrop that makes PEB-based module resolution meaningful."
  - source: "binary-patching-ntdll-system-files"
    target: T-016
    type: concept_link
    rationale: "The unit defines binary patching as in-memory modification of binaries and states AV/EDR solutions use memory patching for function hooking; this directly underlies the NTDLL unhook and hooking concepts documented in T-016."
  - source: "iat-import-address-table"
    target: T-016
    type: concept_link
    rationale: "SEC670 describes IAT hooking as overwriting function pointers in the Import Address Table after flipping page protections to PAGE_READWRITE — this is both a defense mechanism EDRs use and a hook primitive that T-016 techniques must consider."
  - source: "reflective-dll-injection-rdi"
    target: T-013
    type: alternative_to
    rationale: "SEC670 presents RDI as a 6-step position-independent loader alternative to classic LoadLibraryA-based DLL injection, both falling within the injection-method space T-013 catalogues."
  - source: "user-kernel-mode-syscall-transition"
    target: T-001
    type: concept_link
    rationale: "The unit depicts the user-mode to kernel-mode transition triggered by a syscall instruction (e.g., NtAllocateVirtualMemory) — this is the underlying mechanism T-001's indirect syscall dispatch operates within."
  - source: T-002
    target: "pe-file-structure-anatomy"
    type: requires
    rationale: "SSN resolution techniques (Hell's/Halo's/Tartarus Gate) parse ntdll's export table and walk syscall stub bytes in the .text section; SEC670's coverage of PE optional header directories, RVAs, and export directory layout is the prerequisite structural knowledge."
  - source: "pe-text-section-permissions"
    target: T-016
    type: concept_link
    rationale: "SEC670 emphasizes the .text section is mapped PAGE_EXECUTE_READ with the Write flag intentionally absent; this protection invariant is what NTDLL unhooking (T-016) must violate to overwrite syscall stubs, and what memory scanners verify to detect hook tampering."
  - source: "port-monitor-installation-addmonitor"
    target: T-017
    type: concept_link
    rationale: "SEC670 presents AddMonitor as a mechanism for installing local port monitors with MONITORINFO_2 — this is the foundation of print monitor persistence, a persistence vector not explicitly listed in T-017's COM/NTFS-EA/schtask/TLS/PhantomPersist layers."
```

### Concept Nodes

```yaml
concepts:
  - id: "pe-file-structure-anatomy"
    name: "Portable Executable File Anatomy"
    category: windows-structure
    description: "PE files consist of a DOS stub (legacy MS-DOS marker), the PE\\0\\0 signature, a COFF/File header (machine type, section count, characteristics like IMAGE_FILE_EXECUTABLE_IMAGE 0x0002 and IMAGE_FILE_RELOCS_STRIPPED), an Optional Header (magic 0x10B for PE32, 0x20B for PE32+, entry point, image base, section alignment), and a DataDirectory array of 16 entries pointing to directories such as Export, Import, Resource, Debug, and Base Relocation. The Optional Header is mandatory — the loader depends on it."
    relevant_to: [T-004, T-013, T-016]
    tags: [pe, windows-internals, pe-parsing, optional-header, coff]

  - id: "relative-virtual-address-rva"
    name: "Relative Virtual Address (RVA)"
    category: windows-structure
    description: "RVAs are offsets from the start of a module's loaded image base. Because DLLs load at randomized base addresses, all directory entries (Export, Import, Base Relocation, Debug) are stored as RVAs. To resolve to a virtual address at runtime, compute VA = ImageBase + RVA. To recover an RVA from a known VA, compute RVA = VA - ImageBase. RVA arithmetic underpins export-table walking, IAT location, and relocation processing."
    relevant_to: [T-004, T-013, T-016]
    tags: [rva, pe, windows-internals, address-calculation]

  - id: "pe-text-section-permissions"
    name: "PE .text Section: PAGE_EXECUTE_READ Invariant"
    category: windows-structure
    description: "The .text section holds executable code and is mapped by the loader as PAGE_EXECUTE_READ — the Write flag is intentionally absent so that an attacker cannot modify program code in place. The section's VirtualSize, RVA, RawDataSize, and RawDataPointer are recorded in the section header. Any runtime write to .text requires an explicit VirtualProtect flip to PAGE_READWRITE or PAGE_EXECUTE_READWRITE, which is itself a detectable event."
    relevant_to: [T-016]
    tags: [pe, text-section, memory-protection, page-permissions, evasion]

  - id: "pe-rdata-section-contents"
    name: "PE .rdata Section: Initialized Data and Directories"
    category: windows-structure
    description: "The .rdata section is read-only and holds initialized data plus the runtime-resident directory tables. The Export Directory and Debug Directory RVAs documented in the optional header resolve into .rdata. Verifying that an Export Directory RVA falls within the .rdata virtual range is a structural sanity check used during PE parsing."
    relevant_to: [T-004, T-013]
    tags: [pe, rdata, export-directory, pe-parsing]

  - id: "iat-import-address-table"
    name: "Import Address Table and IAT Hooking"
    category: windows-structure
    description: "The IAT is one of the 16 entries in the Optional Header's DataDirectory array and contains an array of function pointers that the loader fixes up at load time. The IAT is normally read-only. IAT hooking (function-pointer hooking) is performed by: (1) parsing PE headers to find the import table, (2) locating the module and function, (3) calling VirtualProtect to change IAT page protection to PAGE_READWRITE while saving the old protection, (4) overwriting the function pointer, and (5) restoring the original protection. AV/EDR solutions use this same primitive for userland API hooking."
    relevant_to: [T-016]
    tags: [iat, hooking, function-pointer, virtualprotect, edr-mechanism]

  - id: "windows-system-dlls-architecture"
    name: "System DLL Architecture: ntdll, kernel32, kernelbase, user32"
    category: os-internal
    description: "ntdll.dll is the only system DLL strictly required by a user-mode process and is always mapped by the OS. It exports the NT functions that act as the gateway to kernel land via syscall. kernel32.dll exports many functions that are pure forwarders — jumps or stubs that simply re-export ntdll functions — and some kernel32 exports contain no code at all. kernelbase.dll similarly re-exports. user32.dll provides the GUI function set. Understanding this forwarder chain is required for module resolution, EDR hook placement analysis, and unhooking strategies."
    relevant_to: [T-004, T-016]
    tags: [ntdll, kernel32, kernelbase, user32, forwarders, system-dlls]

  - id: "binary-patching-ntdll-system-files"
    name: "Binary Patching of System Files (NTDLL)"
    category: attack-pattern
    description: "Binary patching is the modification of a binary on disk or in memory to change execution behavior. In-memory patching is the technique AV/EDR solutions use to insert function hooks (including in ntdll). SEC670 warns that patching system files like ntdll in-place on disk is detectable and unstable; instead, patching a secondary or tertiary DLL loaded by ntdll is preferred. Patching ntdll's .text in memory (unhooking) requires flipping page protections on normally read-only executable regions."
    relevant_to: [T-016]
    tags: [binary-patching, ntdll, edr-hooking, evasion, memory-patching]

  - id: "reflective-dll-injection-rdi"
    name: "Reflective DLL Injection (RDI) vs Classic DLL Injection"
    category: attack-pattern
    description: "Classic DLL injection: (1) obtain process handle, (2) allocate remote memory for the DLL path, (3) write the path, (4) CreateRemoteThread on LoadLibraryA. RDI: (1) allocate local buffer and read raw DLL bytes, (2) obtain process handle, (3) allocate remote memory, (4) copy all sections preserving section permissions, (5) apply base-relocation fixups for the new image base, (6) execute AddressOfEntryPoint. RDI is position-independent, requires no on-disk file in the target, and bypasses LoadLibrary-based hooks but requires the loader logic itself be present in the injected buffer."
    relevant_to: [T-013]
    tags: [rdi, dll-injection, classic-injection, position-independent, base-relocation]

  - id: "user-kernel-mode-syscall-transition"
    name: "User-to-Kernel Mode Syscall Transition"
    category: os-internal
    description: "A user-mode thread issues a syscall instruction (e.g., to invoke NtAllocateVirtualMemory) which transitions execution into kernel mode. The syscall number (SSN) selects the kernel service routine. The syscall dispatcher in ntdll loads the SSN into EAX and executes the syscall instruction. The user-mode stack and registers are preserved across the transition and a kernel-mode return path restores execution. SSNs vary across Windows versions (XP vs Windows 10) and across builds, motivating runtime SSN resolution techniques."
    relevant_to: [T-001, T-002, T-003]
    tags: [syscall, user-kernel-transition, ssn, windows-internals]

  - id: "windows-api-calling-conventions"
    name: "Windows API Calling Conventions"
    category: os-internal
    description: "Windows APIs use a Windows-specific calling convention distinct from __cdecl. API names are descriptive and lengthy because they describe critical system functionality. The convention dictates argument passing (stack and registers), callee vs caller stack cleanup, and return-value registers. Correct invocation of NT and Win32 APIs from position-independent code requires adherence to this convention, including proper stack alignment."
    relevant_to: [T-001, T-013, T-016]
    tags: [calling-convention, winapi, windows-internals, stack-alignment]

  - id: "native-application-function-signature"
    name: "Native Application Function Signature"
    category: os-internal
    description: "Native Windows applications (those that do not link against the Win32 subsystem) use the entry point signature NTSTATUS NT_main(int argc, const char* argv[]) rather than int main(). Native applications are loaded directly by the smss-based loader path before the Win32 environment is fully initialized, providing an early-execution surface but restricting available APIs."
    relevant_to: []
    tags: [orphan, native-application, ntapi, entry-point]

  - id: "windows-service-failure-actions"
    name: "SERVICE_FAILURE_ACTIONS Structure"
    category: windows-structure
    description: "SERVICE_FAILURE_ACTIONS is a Windows structure used with the SCM API (ChangeServiceConfig2) to specify recovery actions when a service fails. It contains a failure action list specifying reboot, restart, or run-command behavior. Red teamers can abuse service failure actions as a persistence vector by configuring a malicious command to execute on service failure events, ensuring re-execution after defensive cleanup."
    relevant_to: [T-017]
    tags: [scm, service, persistence, windows-structure]

  - id: "ace-sddl-security-descriptors"
    name: "ACE String Layout and SDDL Security Descriptors"
    category: windows-structure
    description: "Security Descriptor Definition Language (SDDL) strings encode a security descriptor as text. An ACE string contains ace_type, ace_flags, and rights fields (generic_rights, registry_rights, standard_rights, label_rights, file_system_rights) plus trustee SIDs. The compound rights use shorthand flags (CC=CREATE_CHILD, CD=DELETE_CHILD, CA=CREATE_ALL, CR=READ_CONTROL, CN=NOTIFY, CL=LIST). The NULL well-known SID can appear in SDDL examples. GetNamedSecurityInfoA and EXPLICIT_ACCESS_A structures are the programmatic interface for reading and writing these descriptors on NTFS objects, services, registry keys, and shares."
    relevant_to: [T-017]
    tags: [sddl, ace, security-descriptor, acl, windows-internals]

  - id: "port-monitor-installation-addmonitor"
    name: "Local Port Monitor Installation via AddMonitor"
    category: attack-pattern
    description: "The AddMonitor Windows API installs a local port monitor and returns BOOL. It accepts a _MONITORINFO_2 structure containing monitor name, environment, and DLL path. A malicious port monitor DLL loaded by the print spooler service runs in the context of the spooler (typically SYSTEM) and persists across reboots because the monitor is enumerated at spooler startup. This is a recognized persistence vector distinct from COM hijack, NTFS EA, scheduled task, and TLS callback techniques."
    relevant_to: [T-017]
    tags: [port-monitor, print-spooler, persistence, addmonitor, system]
```

### Detection Insights

```yaml
detection:
  - indicator: "ntdll.dll .text section byte-level integrity violation"
    source: memory-scan
    confidence: high
    relevant_to: [T-016]
    description: "Memory scanners and EDR integrity checks compare the in-memory .text section of ntdll.dll against a pristine copy on disk (or a cached hash). The .text section is normally PAGE_EXECUTE_READ with the Write flag absent; any byte divergence indicates either EDR hook placement (jmp/call trampoline at function prologue) or attacker unhooking/restoration. SEC670 explicitly notes that patching system files 'could draw way too much attention' — the same telemetry that flags attacker patches also flags EDR hooks."
    bypassed_by: "not discussed"

  - indicator: "VirtualProtect call targeting IAT page with PAGE_READWRITE on a normally read-only IAT"
    source: etw
    confidence: medium
    relevant_to: [T-016]
    description: "SEC670 documents that IAT hooking requires changing page protections on the IAT from its default read-only state to PAGE_READWRITE before overwriting function pointers, then restoring. The intermediate PAGE_READWRITE on an IAT-resident page is observable via ETW kernel memory-protection telemetry and is anomalous because the IAT is not normally written post-loader."
    bypassed_by: "not discussed"

  - indicator: "PAGE_EXECUTE_READWRITE section allocation in a remote process"
    source: etw
    confidence: high
    relevant_to: [T-013, T-016]
    description: "Reflective DLL Injection as documented by SEC670 step 4 'Copy over all sections keeping section permissions' is preceded by step 3 'Allocate remote memory' which typically uses PAGE_EXECUTE_READWRITE for simplicity. A remote RWX allocation followed by remote writes and a thread/APC delivery matches the classic injection pattern observable via the Threat-Intelligence ETW provider."
    bypassed_by: "not discussed"

  - indicator: "Loaded DLL not backed by file on disk (RDI signature)"
    source: memory-scan
    confidence: medium
    relevant_to: [T-013]
    description: "RDI allocates remote memory, copies section contents directly, and invokes AddressOfEntryPoint without invoking the standard loader. The resulting module is not registered through LdrpLoadDll and lacks a file backing in the PEB loader list. Memory scanners that enumerate the PEB InLoadOrderModuleList and cross-check against actual loaded sections will flag the unbacked executable region."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "NTDLL .text Section Byte-Divergence from Disk Image"
    logsource: memory-scan
    condition_summary: "Hash of in-memory ntdll.dll .text section differs from the same region's on-disk hash; or byte-compare reports any divergence at function prologue addresses."

  - title: "VirtualProtect Flip on Import Address Table Region"
    logsource: etw
    condition_summary: "Microsoft-Windows-Threat-Intelligence NtProtectVirtualMemory event where the target address falls within a module's IAT DataDirectory range and the new protection includes WRITE bit while previous protection did not."

  - title: "Remote Process RWX Allocation Preceded by Cross-Process Write"
    logsource: etw
    condition_summary: "ETW-TI NtAllocateVirtualMemory with TargetPid != SourcePid and PAGE_EXECUTE_READWRITE, followed within a short window by NtWriteVirtualMemory to the same region from the same source PID."
```

### Operational Chains

```yaml
chains:
  - name: "Classic DLL Injection via LoadLibraryA"
    description: "Inject a DLL on disk into a remote process by inducing it to call LoadLibraryA on the DLL path."
    steps:
      - technique: "obtain process handle"
        role: "Open a handle to the target process with PROCESS_VM_OPERATION and PROCESS_VM_WRITE access."
      - technique: "allocate remote memory for DLL path"
        role: "VirtualAllocEx a string buffer in the target large enough to hold the DLL file path."
      - technique: "write the DLL path"
        role: "WriteProcessMemory the path string into the remote allocation."
      - technique: T-013
        role: "CreateRemoteThread on LoadLibraryA with the remote path buffer as the thread argument; the target loader maps the DLL and runs DllMain."
    notes: "SEC670 presents this as the 4-step classic approach; it depends on LoadLibraryA being unhooked in the target and on the DLL file existing on disk or accessible via UNC path."

  - name: "Reflective DLL Injection (RDI)"
    description: "Inject a DLL by means of a position-independent loader stub that performs manual mapping into a remote process, avoiding LoadLibraryA."
    steps:
      - technique: "allocate local buffer and read raw DLL bytes"
        role: "Stage the entire PE file in the operator's own process so it can be relocated into the target."
      - technique: "obtain process handle"
        role: "Open a handle to the target process with VM write and thread-creation rights."
      - technique: "allocate remote memory"
        role: "VirtualAllocEx a region in the target sized to the PE's ImageSize."
      - technique: "copy sections preserving section permissions"
        role: "WriteProcessMemory each section (typically .text as RX, .rdata as R, .data as RW) so the in-memory layout matches a normally loaded image."
      - technique: "apply base-relocation fixups"
        role: "Walk the Base Relocation Directory and patch absolute addresses in .text and .rdata so they refer to the remote allocation base, not the file's preferred ImageBase."
      - technique: T-013
        role: "Resolve the remote AddressOfEntryPoint and trigger execution via CreateRemoteThread, APC, or thread hijack; the loader stub resolves imports and calls DllMain."
    notes: "SEC670 emphasizes that RDI keeps the DLL off disk in the target, requires no LoadLibraryA invocation, and bypasses userland LoadLibrary hooks but does require the reflective loader stub itself to be injected and started — typically via a separate injection primitive."

  - name: "IAT Hooking Workflow"
    description: "Replace a function pointer in a target process's Import Address Table so that calls to the imported function divert to an attacker-controlled routine."
    steps:
      - technique: "parse PE headers to find import table"
        role: "Walk the target module's Optional Header DataDirectory[1] (Import Directory) to locate the IAT."
      - technique: "locate module that implements the hooked function"
        role: "Identify which loaded module (kernel32.dll, ntdll.dll, etc.) exports the target function."
      - technique: "locate the function in the found module"
        role: "Resolve the function's actual address by walking the exporter's Export Directory."
      - technique: "change IAT page protection to PAGE_READWRITE"
        role: "Call VirtualProtect on the IAT page (normally read-only) saving the original protection value for restoration."
      - technique: "overwrite function pointer"
        role: "Write the replacement address into the IAT entry."
      - technique: "restore previous page protections"
        role: "Call VirtualProtect again to restore the original read-only protection on the IAT page."
    notes: "SEC670 presents this as a 6-step procedure. The same primitive is used by AV/EDR for userland hooking and by attackers for API interception; the PAGE_READWRITE intermediate state is observable via ETW memory-protection telemetry."

  - name: "Runtime SSN Resolution Cascade"
    description: "Resolve a syscall service number at runtime by parsing ntdll's export table and inspecting syscall stub bytes, handling hooked-stub cases by walking neighbor stubs."
    steps:
      - technique: T-004
        role: "Walk the PEB InLoadOrderModuleList to locate ntdll.dll's base address without calling any Win32 API that itself may be hooked."
      - technique: "pe-file-structure-anatomy"
        role: "Parse ntdll's Optional Header DataDirectory[0] (Export Directory) to enumerate exported Zw* functions and their RVAs."
      - technique: "pe-text-section-permissions"
        role: "For each Zw* function, read the first bytes of its stub in .text; the syscall stub begins with mov r10, rcx; mov eax, <SSN>; syscall."
      - technique: T-002
        role: "Extract the SSN from the stub. If the stub has been hooked (bytes diverge from the expected mov eax pattern), apply Halo's/Tartarus Gate variants that infer the SSN from neighbor syscall stubs whose Zw* names sort adjacent in the export table."
      - technique: T-001
        role: "Dispatch the resolved SSN via an indirect syscall gadget located in ntdll's .text to avoid embedding a direct syscall instruction in the implant image."
    notes: "SEC670 frames the SSN-resolution problem in terms of the user/kernel transition and the version-dependence of SSNs (XP vs Windows 10); the operational cascade is what T-002 and T-001 actually implement."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "port-monitor-print-spooler-persistence"
    title: "Port Monitor (AddMonitor / Print Spooler) Persistence"
    kind: proposed-technique
    description: "SEC670 unit 18 documents the AddMonitor API and _MONITORINFO_2 structure for installing a local port monitor. A malicious port monitor DLL loaded by the spooler service executes in SYSTEM context and is enumerated at every spooler restart. The vault's T-017 persistence suite currently enumerates COM hijack, NTFS EA, scheduled task, TLS callback, and PhantomPersist layers but does not include print monitor / port monitor persistence as a distinct layer. This deserves its own card or its own entry in the T-017 layer catalog because the trigger (spooler service) and the persistence context (SYSTEM) differ from the existing layers."
    would_relate_to: [T-017]
    source_units: ["unit 18"]
    tags: [persistence, port-monitor, print-spooler, system, addmonitor]

  - id: "service-failure-actions-persistence"
    title: "Service Failure Actions as Persistence"
    kind: proposed-technique
    description: "SEC670 unit 8 documents the SERVICE_FAILURE_ACTIONS structure used with ChangeServiceConfig2. Operators can install a malicious recovery command that the SCM executes when a service fails — including services that fail deliberately or are forced to fail. This is a persistence vector orthogonal to T-017's existing layers and survives reboots because the failure-action configuration is stored in the service's registry entry. The vault does not currently surface this as a persistence technique."
    would_relate_to: [T-017]
    source_units: ["unit 8"]
    tags: [persistence, scm, service-failure-actions, registry, system]

  - id: "iat-hooking-as-technique"
    title: "IAT Hooking Primitive"
    kind: coverage-gap
    description: "SEC670 units 35 and 36 document IAT (Import Address Table) hooking as a complete 6-step primitive: parse PE headers, locate module and function, flip IAT page protection to PAGE_READWRITE, overwrite the pointer, restore protection. T-016 (EDR Evasion Suite) documents many evasion techniques but IAT hooking itself is not catalogued either as a defensive mechanism EDRs use (which T-016 techniques must counter) or as an offensive primitive for API interception / credential capture. The vault should document IAT hooking explicitly so that techniques which depend on the IAT being pristine can reference it, and so operators reading the vault understand the primitive EDRs apply."
    would_relate_to: [T-016]
    source_units: ["unit 35", "unit 36"]
    tags: [iat-hooking, edr-mechanism, function-pointer, coverage-gap, virtualprotect]

  - id: "native-application-execution-surface"
    title: "Native Application (NT_main) Execution Surface"
    kind: emerging-tradecraft
    description: "SEC670 unit 32 documents the NTSTATUS NT_main(int argc, const char* argv[]) entry signature used by native Windows applications that run before the Win32 subsystem is fully initialized. Native applications can be invoked by smss during early boot or by WinDbg-style native tooling and present an execution surface distinct from conventional Win32 EXEs. The vault does not currently document native-application execution as a technique; it would relate to early-boot persistence and to evasion contexts where avoiding the Win32 subsystem is operationally valuable."
    would_relate_to: []
    source_units: ["unit 32"]
    tags: [native-application, nt-main, early-boot, orphan, emerging]

  - id: "pe-parsing-foundational-utility"
    title: "PE Parsing as a Foundational Utility Across T-NNNs"
    kind: cross-source-convergence
    description: "Multiple SEC670 units in this batch (2, 3, 6, 12, 15, 16, 20, 23, 26) converge on PE file anatomy — DOS stub, COFF, Optional Header, section headers, RVAs, DataDirectory, export/import directories — as the foundational structural knowledge required by T-004 (PEB Walker), T-002 (Hell's Gate SSN resolution), T-013 (RDI), T-016 (NTDLL unhook / IAT manipulation), and T-017 (persistence involving module/DLL manipulation). The vault documents these techniques individually but does not currently surface PE parsing itself as a shared utility node in the graph. A 'PE parsing' concept anchored to multiple T-NNNs would improve navigation and make the shared prerequisite explicit."
    would_relate_to: [T-002, T-004, T-013, T-016, T-017]
    source_units: ["unit 2", "unit 3", "unit 6", "unit 12", "unit 15", "unit 16", "unit 20", "unit 23", "unit 26"]
    tags: [pe-parsing, shared-utility, cross-source-convergence, foundational]
```