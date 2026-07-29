## Synthesis Summary

This batch from SANS SEC670 (Books 1 and 2 of "Red Teaming Tools: Developing Windows Implants") covers foundational Windows internals required to build offensive tooling: Windows data types, x64/x86 calling conventions, handle table architecture, the PE file format (sections, RVAs, relocations, exports), the `Create*` API family, registry enumeration APIs, COM initialization, and the `_KPROCESS` / `SYSTEM_PROCESS_INFORMATION` kernel structures consumed by `NtQuerySystemInformation`. The material maps most directly to T-002 (Hell's/Halo's/Tartarus Gate — RVA-based SSN resolution), T-004 (PEB Walker — manual module resolution and RVA calculation), T-007/T-013 (process injection — `CreateProcess`, handle access rights, PE format for reflective loaders), T-014 (NtCreateUserProcess — direct NT process creation contrasted with Win32 `CreateProcess`), T-015 (PPID Spoofing — `PROCESS_CREATE_PROCESS` access), T-016 (EDR Evasion — handle blocking, PE stomping, proxy DLL), T-017 (Persistence — COM hijack via `CoInitialize`/`CoCreateInstance`, registry enumeration via `Reg*` family), T-020 (Anti-Analysis — system/process enumeration), and T-023 (Client Capabilities — recon via `NtQuerySystemInformation`). The knowledge gap this fills is the "why behind the Rust code": why RVAs matter for export resolution, why `.TEXT` lacks the Write bit (the basis of stomping detection), why the x64 calling convention constrains syscall stub construction, what access rights an opener must request on a target process handle, and how the handle table and `_KPROCESS` look to a defender scanning memory. No units in this batch are off-theme.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "pe-rva-calculation"
    target: T-002
    type: requires
    rationale: "Hell's/Halo's/Tartarus Gate SSN resolution walks the export directory of ntdll by computing export RVAs from the optional header DataDirectory — RVA calculation (Virtual Address = Base + RVA) is the prerequisite primitive."

  - source: "pe-rva-calculation"
    target: T-004
    type: requires
    rationale: "The PEB walker resolves module base addresses and then walks export tables using RVAs to locate Nt/Zw functions by hash. The unit's RVA formula is the manual module resolution primitive."

  - source: "process-thread-access-rights"
    target: T-007
    type: requires
    rationale: "Process injection openers must request specific access rights on the target process handle — PROCESS_CREATE_THREAD for CreateRemoteThread variants, PROCESS_VM_OPERATION | PROCESS_VM_WRITE for NtWriteVirtualMemory, PROCESS_DUP_HANDLE for handle-table attacks. The unit enumerates these rights explicitly."

  - source: "process-thread-access-rights"
    target: T-015
    type: requires
    rationale: "PPID spoofing via NtCreateProcessEx requires a parent handle opened with PROCESS_CREATE_PROCESS access. The unit identifies PROCESS_CREATE_PROCESS as the access flag for process creation."

  - source: "process-thread-access-rights"
    target: T-016
    type: concept_link
    rationale: "The block-handle evasion technique counters EDR handle acquisition by stripping access rights on the implant's own process object — the unit documents the rights EDR attempts to acquire (PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE)."

  - source: "pe-text-section-permissions"
    target: T-016
    type: concept_link
    rationale: "PE stomping and module stomping overwrite .TEXT content; the unit documents that .TEXT is mapped PAGE_EXECUTE_READ by the loader, which is the protection state stomping modifies and then restores."

  - source: "com-initialization"
    target: T-017
    type: requires
    rationale: "COM hijack persistence requires CoInitialize(Ex) in the host process before CoCreateInstance will resolve a hijacked CLSID from the registry. The unit lists CoInitialize as the COM setup function."

  - source: "ntquerysysteminformation-process-walk"
    target: T-023
    type: enables
    rationale: "Client recon enumerates running processes via NtQuerySystemInformation with SystemProcessInformation, walking the NextEntryOffset-linked SYSTEM_PROCESS_INFORMATION chain. The unit documents this exact call sequence."

  - source: "ntquerysysteminformation-process-walk"
    target: T-020
    type: enables
    rationale: "Anti-Analysis system inventory uses NtQuerySystemInformation to enumerate processes for EDR/AV detection and to identify analysis tooling. The unit surfaces the API and SYSTEM_PROCESS_INFORMATION struct as the enumeration path."

  - source: "kprocess-kernel-object"
    target: T-016
    type: concept_link
    rationale: "EDR evasion techniques that touch process objects (PEB unlink, handle stripping) operate on user-mode projections of the _KPROCESS; the unit documents the kernel-side structure including ThreadListHead and DirectoryTableBase that defenders inspect."

  - source: "windows-handle-table"
    target: T-016
    type: concept_link
    rationale: "The handle-blocking evasion suite manipulates handle table entries and access masks; the unit documents the HTE structure (Pointer, Access Mask, Audit/Lock/Inherit flags) and the multi-table handle architecture."

  - source: T-014
    target: "createprocess-win32"
    type: alternative_to
    rationale: "NtCreateUserProcess (T-014) is the direct NT alternative to the Win32 CreateProcess wrapper the unit walks through; both produce a PROCESS_INFORMATION result, but the NT path bypasses Win32 policy checks."
```

### Concept Nodes

```yaml
concepts:
  - id: "x64-calling-convention"
    name: "Windows x64 Calling Convention"
    category: os-internal
    description: "On x64 Windows, the first four integer/pointer arguments to a function are passed in RCX, RDX, R8, R9, with remaining arguments placed on the stack (in order) above the 32-byte shadow space. Floating-point arguments use XMM0-XMM3. There is no fixed 'order' in the source code — the registers are simply loaded with the proper values before the call. This convention is what makes direct syscall stubs possible: a stub needs to move the SSN into EAX and the syscall instruction's stack-frame requirements, without spilling arguments."
    relevant_to: [T-001, T-002, T-003, T-006]
    tags: [calling-convention, x64, syscall-stub, assembly, windows-internals]

  - id: "windows-handle-table"
    name: "Process Handle Table and Handle Table Entry"
    category: windows-structure
    description: "Each process has a pointer in its virtual address space to a handle table. Handles scale up to ~16,000,000 per process using a multi-level table scheme. Each Handle Table Entry (HTE) contains a Pointer to the object header, an Access Mask, and flag bits including Audit-on-close, Inheritable, Lock, and Protect-from-close. The Protect-from-close flag and Audit-on-close bit are set via NtSetInformationObject. Understanding the HTE structure is required to reason about handle duplication, handle stripping for evasion, and EDR handle-based detection."
    relevant_to: [T-016, T-013, T-015]
    tags: [handle-table, hte, kernel-object, edr-mechanism, windows-internals]

  - id: "process-thread-access-rights"
    name: "Process and Thread Access Rights"
    category: os-internal
    description: "When opening a process or thread handle, the caller requests a specific access mask. Process rights include PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS (required to use the handle as a parent in NtCreateProcessEx — i.e., PPID spoofing), PROCESS_CREATE_THREAD (required for CreateRemoteThread and APC injection), and PROCESS_DUP_HANDLE (required for NtDuplicateObject-based handle theft). Thread rights include THREAD_ALL_ACCESS, THREAD_SET_CONTEXT (for thread hijack injection), and THREAD_SUSPEND_RESUME (for Early Bird APC scheduling). EDR products subscribe to ETW-TI and kernel callbacks that observe cross-process opens with these access masks."
    relevant_to: [T-007, T-012, T-013, T-015, T-016]
    tags: [access-mask, handle, injection, ppid-spoofing, edr-mechanism]

  - id: "pe-optional-header-directories"
    name: "PE Optional Header DataDirectory Entries"
    category: windows-structure
    description: "The last portion of the PE optional header is the DataDirectory array (commonly 10+ entries on modern PE files). Key entries: Export Directory (index 0), Import Directory (index 1), Base Relocation Directory (index 5). RVAs in these directories are offsets from the file/image base; once the module is loaded, Virtual Address = Base Address + RVA. The Export Directory entry is what Hell's Gate, the PEB walker, and module-overloading reflective loaders walk to resolve symbols by hash."
    relevant_to: [T-002, T-004, T-006, T-013, T-016]
    tags: [pe-format, data-directory, rva, export-directory, module-resolution]

  - id: "pe-rva-calculation"
    name: "Relative Virtual Address (RVA) Calculation"
    category: os-internal
    description: "An RVA is an offset from the beginning (base) of a loaded PE image. RVAs let a single PE binary work regardless of where the loader places it in memory — DLLs by design do not get their preferred base address once ASLR or address contention occurs. Once the base address is known at runtime, Virtual Address = Base + RVA, and RVA = Virtual Address - Base. SSN resolution (Hell's Gate sorts Zw* export RVAs), export resolution (PEB walker), and module-overloading relocations all depend on this primitive."
    relevant_to: [T-002, T-004, T-006, T-013]
    tags: [rva, pe-format, aslr, module-resolution, windows-internals]

  - id: "pe-text-section-permissions"
    name: ".TEXT Section and PAGE_EXECUTE_READ Mapping"
    category: windows-structure
    description: "The .TEXT section of a PE file holds executable code. The loader maps it PAGE_EXECUTE_READ — Write is intentionally absent so an attacker cannot modify in-memory program code post-load. Section headers carry virtual size, RVA, and raw-data size. Module stomping, function stomping, and PE stomping evade detection by writing into this section despite the protection, then flipping to PAGE_EXECUTE_READWRITE (which generates an NtProtectVirtualMemory ETW-TI event) or by mapping a fresh section with WRITE permission and copying code into it before flipping to RX."
    relevant_to: [T-006, T-013, T-016]
    tags: [pe-section, text-section, memory-protection, page-execute-read, stomping, evasion]

  - id: "dll-preferred-base-relocation"
    name: "DLL Preferred Base Address and Relocation"
    category: windows-structure
    description: "EXEs and DLLs declare a preferred base address in the optional header. The loader will grant that address if free, but with ASLR and address-space contention the DLL more often does not get its preferred base. When this occurs, the loader applies the Base Relocation Directory to patch absolute addresses inside the image so it runs correctly at the new base. Proxy DLLs (T-016) and phantom stubs (T-006) must respect this behavior or their absolute references break. Reflective loaders must perform their own relocation if they cannot guarantee loading at the preferred base."
    relevant_to: [T-006, T-013, T-016]
    tags: [relocation, base-address, aslr, pe-format, reflective-loader, proxy-dll]

  - id: "com-initialization"
    name: "COM Library Initialization Sequence"
    category: os-internal
    description: "Before any COM operation, a process must call CoInitialize or CoInitializeEx to set up the COM library in the calling apartment. CoCreateInstance then resolves a CLSID to an in-process or out-of-process server by reading the registry under HKCR\\CLSID. COM hijack persistence (T-017) exploits this lookup: the attacker overwrites a HKCU\\Software\\Classes\\CLSID\\{...}\\InprocServer32 default value to point at a malicious DLL, which the host process loads on next CoCreateInstance for that CLSID. CoMemFree releases COM-allocated memory."
    relevant_to: [T-017]
    tags: [com, coinitialize, cocreateinstance, persistence, registry, com-hijack]

  - id: "registry-enumeration-apis"
    name: "RegOpenKeyExW / RegQueryInfoKey / RegEnumValue Enumeration Pattern"
    category: os-internal
    description: "The standard registry enumeration pattern: open a key with RegOpenKeyExW (returns LSTATUS, handle via _Out_ parameter), call RegQueryInfoKey to obtain subkey count + max subkey/value name lengths for buffer sizing, then loop RegEnumValue or RegEnumKeyEx with an incrementing index until ERROR_NO_MORE_ITEMS. LSTATUS is a typedef for LONG checked against ERROR_SUCCESS (0). This pattern is the basis of COM-hijack target discovery, persistence staging, and recon collection."
    relevant_to: [T-017, T-023]
    tags: [registry, regopenkeyex, regenumvalue, persistence, recon, lstatus]

  - id: "ntquerysysteminformation-process-walk"
    name: "NtQuerySystemInformation with SystemProcessInformation"
    category: os-internal
    description: "NtQuerySystemInformation (InfoCls = SystemProcessInformation) returns a variable-length buffer of SYSTEM_PROCESS_INFORMATION structs chained by NextEntryOffset. Each entry contains NumberOfThreads, CreateTime, ImageName (UNICODE_STRING), UniqueProcessId, InheritedFromUniqueProcessId, and a trailing SYSTEM_THREAD_INFORMATION array. Used for process enumeration in recon, PPID discovery (InheritedFromUniqueProcessId), and EDR/AV detection. Returns NTSTATUS; buffer must be re-allocated and re-queried if STATUS_INFO_LENGTH_MISMATCH is returned."
    relevant_to: [T-020, T-023]
    tags: [ntquerysysteminformation, process-enum, recon, system-process-information, ntapi]

  - id: "kprocess-kernel-object"
    name: "_KPROCESS Kernel Object"
    category: windows-structure
    description: "_KPROCESS is the kernel-mode object representing a process (the executive _EPROCESS embeds it as its first field). Layout (per unit): DISPATCHER_HEADER at 0x0, ProfileListHead at 0x18, DirectoryTableBase (CR3 value for this process's virtual address translations) at 0x28, ThreadListHead at 0x30, ProcessLock at 0x40, DeepFreezeStartTime at 0x48, Affinity at 0x50, ReadyListHead at 0x158. The lower layer of the kernel uses _KPROCESS for thread scheduling and address translation. Defenders inspect _KPROCESS to find orphaned thread list entries (post-PEB-unlink) and to correlate CR3 with VAD scans."
    relevant_to: [T-016]
    tags: [kprocess, eprocess, kernel-object, cr3, directorytablebase, threadlisthead, forensics]

  - id: "createprocess-win32"
    name: "CreateProcess Win32 Wrapper"
    category: os-internal
    description: "CreateProcess is the Win32 wrapper around NtCreateUserProcess. It accepts STARTUPINFO (or STARTUPINFOEX for extended attributes including parent-process handle assignment in PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) and returns PROCESS_INFORMATION containing hProcess and hThread. The minimum invocation pattern initializes STARTUPINFO.cb = sizeof(STARTUPINFO), passes a command line, and ignores most parameters. NtCreateUserProcess (T-014) bypasses this wrapper, skipping Win32-level policy checks (e.g., specific mitigation flags applied by the Win32 layer) but requiring the caller to construct RTL_USER_PROCESS_PARAMETERS manually."
    relevant_to: [T-014, T-015, T-013]
    tags: [createprocess, startupinfo, process-creation, win32, ntcreateuserprocess, ppid]
```

### Detection Insights

```yaml
detection:
  - indicator: "Cross-process handle open with PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE access mask"
    source: kernel-callback
    confidence: high
    relevant_to: [T-007, T-012, T-013]
    description: "The ObRegisterCallbacks OBJECT_PRE_OPERATION callback fires when a handle is opened on a process object. EDR inspects the DesiredAccess mask: combinations including PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, and PROCESS_VM_WRITE are classic injection signatures. The unit documents these as the canonical process-injection access rights."
    bypassed_by: "not discussed"

  - indicator: "Handle opened with PROCESS_DUP_HANDLE on lsass.exe or other protected process"
    source: kernel-callback
    confidence: high
    relevant_to: [T-016, T-023]
    description: "ObRegisterCallbacks reports handle duplication attempts. PROCESS_DUP_HANDLE on protected processes (lsass, services with PPL) is flagged. The unit explicitly identifies PROCESS_DUP_HANDLE as the access right used for handle duplication into child processes — also the right used for handle theft from foreign processes."
    bypassed_by: "not discussed"

  - indicator: ".TEXT section protection flip to PAGE_EXECUTE_READWRITE"
    source: etw
    confidence: high
    relevant_to: [T-006, T-013, T-016]
    description: "The Microsoft-Windows-Threat-Intelligence ETW provider reports NtProtectVirtualMemory calls. A flip on a region whose VAD corresponds to a loaded module's .TEXT section, with a target protection containing WRITE, is a stomping signature. The unit documents that .TEXT is mapped PAGE_EXECUTE_READ by the loader — any deviation from that protection on a module-backed region is anomalous."
    bypassed_by: "not discussed"

  - indicator: "NtQuerySystemInformation call with SystemProcessInformation information class"
    source: etw
    confidence: medium
    relevant_to: [T-020, T-023]
    description: "The NT API NtQuerySystemInformation (and its SystemProcessInformation class) is monitorable via ETW kernel-process events and via userland ntdll hooks. Volume and frequency of this call from a non-system process is a recon indicator. The unit documents this as the canonical process-enumeration NT API."
    bypassed_by: "not discussed"

  - indicator: "Registry enumeration pattern: RegOpenKeyExW followed by RegQueryInfoKey followed by repeated RegEnumValue"
    source: behavioral
    confidence: medium
    relevant_to: [T-017, T-023]
    description: "Sequential calls to RegOpenKeyExW (LSTATUS), RegQueryInfoKey (for sizing), and a loop of RegEnumValue until ERROR_NO_MORE_ITEMS is the standard registry-enumeration fingerprint. EDR behavioral engines flag this pattern against sensitive key roots such as HKCR\\CLSID (COM hijack discovery) and HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (autostart enumeration). The unit walks through each step of this pattern."
    bypassed_by: "not discussed"

  - indicator: "CoInitialize followed by CoCreateInstance with hijackable CLSID"
    source: behavioral
    confidence: low
    relevant_to: [T-017]
    description: "Behavioral engines track CoInitialize/CoCreateInstance call sequences and resolve the CLSID against HKCU\\Software\\Classes\\CLSID rather than HKCR; if the resolved InprocServer32 path points to a non-Microsoft-signed DLL loaded into a system process, that is a COM-hijack signature. The unit documents CoInitialize as the prerequisite to any CoCreateInstance."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Remote Process Handle Open with Injection Access Mask"
    logsource: etw
    condition_summary: "ObRegisterCallbacks or ETW-TI event where ObjectType == Process and DesiredAccess contains (PROCESS_CREATE_THREAD OR PROCESS_VM_OPERATION OR PROCESS_VM_WRITE) and SourcePid != TargetPid"

  - title: "Module TEXT Section Protection Flip to Writable"
    logsource: etw
    condition_summary: "ETW-TI NtProtectVirtualMemory event where the target address lies within a VAD backed by a loaded module and the new protection contains PAGE_READWRITE or PAGE_EXECUTE_READWRITE"

  - title: "Suspicious Registry Enumeration of CLSID or Run Keys"
    logsource: sysmon
    condition_summary: "Sysmon EventID 12/13 sequence: RegOpenKey on HKCR\\CLSID or HKLM\\...\\Run, followed by RegQueryInfoKey, followed by N RegEnumValue calls, where the calling process is not regedit/not a known management agent"
```

### Operational Chains

```yaml
chains:
  - name: "COM Hijack Persistence Installation"
    description: "Discover a hijackable CLSID, then write a malicious InprocServer32 default value into HKCU so the host process loads the attacker DLL on next CoCreateInstance."
    steps:
      - technique: "registry-enumeration-apis"
        role: "Enumerate HKCR\\CLSID to find an unused or loadable CLSID with an InprocServer32 subkey"
      - technique: T-017
        role: "COM hijack persistence writes the attacker-controlled DLL path into HKCU\\Software\\Classes\\CLSID\\{target-CLSID}\\InprocServer32"
      - technique: "com-initialization"
        role: "On next process startup, host calls CoInitialize and then CoCreateInstance for the target CLSID, which loads the attacker DLL"
    notes: "The unit documents CoInitialize as the prerequisite call before CoCreateInstance — without an initialized COM apartment, the hijacked CLSID lookup will not fire."

  - name: "Process Enumeration for Recon and EDR Detection"
    description: "Use NtQuerySystemInformation to enumerate running processes for situational awareness and EDR/AV identification."
    steps:
      - technique: "ntquerysysteminformation-process-walk"
        role: "Call NtQuerySystemInformation(SystemProcessInformation, ...) and walk the NextEntryOffset-linked buffer to enumerate PIDs, PPIDs (InheritedFromUniqueProcessId), image names, and thread counts"
      - technique: T-023
        role: "Client recon matches enumerated image names against an EDR/AV signature list"
      - technique: T-020
        role: "Anti-Analysis suite uses the enumeration result to decide whether to abort execution or proceed with evasion measures"
    notes: "If NtQuerySystemInformation returns STATUS_INFO_LENGTH_MISMATCH the buffer must be reallocated to the returned ReturnLength and the call repeated. SYSTEM_PROCESS_INFORMATION contains InheritedFromUniqueProcessId which is the basis of PPID-aware EDR detection."

  - name: "PE-Stomp Style Injection"
    description: "Open a target process handle with the required access rights, then overwrite a section of a loaded module's .TEXT to install shellcode."
    steps:
      - technique: "process-thread-access-rights"
        role: "OpenProcess on the target with PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ (and PROCESS_QUERY_INFORMATION for VAD walking)"
      - technique: T-013
        role: "Module stomping or function stomping overwrites a region inside a loaded module's .TEXT section with shellcode"
      - technique: T-016
        role: "PE stomping evasion may additionally stomp the PE header to confuse module-based scanning"
    notes: "The unit documents that .TEXT is mapped PAGE_EXECUTE_READ — stomping requires a protection flip on that region first, which is itself an ETW-TI observable."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "handle-table-entry-internals"
    title: "Handle Table Entry Structure and Protect-from-close Flag"
    kind: coverage-gap
    description: "The unit documents the HTE structure (Pointer, Access Mask, Audit-on-close, Inheritable, Lock, Protect-from-close) and notes Protect-from-close and Audit-on-close are set via NtSetInformationObject. The vault's T-016 covers handle blocking but does not document the underlying HTE layout, the Protect-from-close bit, or the NtSetInformationObject vector for hardening a handle against closure. This would strengthen T-016 with the kernel-side mechanism the evasion manipulates."
    would_relate_to: [T-016, T-013, T-015]
    source_units: ["unit 18", "unit 19"]
    tags: [handle-table, hte, ntsetinformationobject, protect-from-close, coverage-gap]

  - id: "kprocess-as-forensic-anchor"
    title: "_KPROCESS as Forensic Anchor for PEB-Unlink Detection"
    kind: coverage-gap
    description: "The unit documents _KPROCESS with DirectoryTableBase (CR3) and ThreadListHead offsets. The vault's T-016 PEB unlink operates on the user-mode PEB module list, but forensic scanners pivot through the EPROCESS->KPROCESS ThreadListHead to enumerate threads whose backing module is missing from the PEB. The vault does not document this defender-side pivot, which is the primary detection for PEB-unlinked modules."
    would_relate_to: [T-016]
    source_units: ["unit 38"]
    tags: [kprocess, eprocess, peb-unlink, forensics, threadlisthead, directorytablebase, coverage-gap]

  - id: "x64-calling-convention-stub-constraint"
    title: "x64 Calling Convention as Syscall Stub Design Constraint"
    kind: cross-source-convergence
    description: "SEC670 documents the x64 calling convention (RCX/RDX/R8/R9 + stack) in foundational form. MalDev Academy and CRTO both reference the same convention when explaining why direct syscall stubs must preserve the caller's register layout and why argument spoofing (T-016) must respect shadow-space placement. The vault's T-001 RecycledGate, T-003 VEH Gate, and T-006 Phantom Stubs all implicitly depend on this. Surfacing it as an explicit concept node would let readers cross-navigate from any stub implementation back to the ABI constraint."
    would_relate_to: [T-001, T-002, T-003, T-006, T-016]
    source_units: ["unit 8", "unit 9", "unit 10", "unit 11", "unit 12", "unit 13", "unit 14", "unit 15"]
    tags: [x64, calling-convention, syscall-stub, abi, cross-source-convergence]

  - id: "createprocess-vs-ntcreateuserprocess-policy-boundary"
    title: "CreateProcess vs NtCreateUserProcess Policy Boundary"
    kind: proposed-technique
    description: "The unit walks through CreateProcess as the Win32 wrapper, including STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as the Win32 path to PPID spoofing. The vault has T-014 NtCreateUserProcess and T-015 PPID Spoofing as separate cards but no explicit treatment of the policy boundary between the Win32 layer (which applies mitigation inheritance, block-dll policy, and parent-process validation) and the NT layer (which skips these). A proposed card documenting the policy delta would clarify when an operator should choose NT direct vs the Win32 wrapper."
    would_relate_to: [T-014, T-015, T-013, T-016]
    source_units: ["unit 16", "unit 17", "unit 19"]
    tags: [createprocess, ntcreateuserprocess, ppid-spoofing, policy-boundary, win32-vs-nt, proposed-technique]

  - id: "registry-enumeration-fingerprint"
    title: "RegOpenKeyExW + RegQueryInfoKey + RegEnumValue Fingerprint"
    kind: proposed-technique
    description: "The unit documents the canonical three-call registry enumeration pattern with LSTATUS return checking and ERROR_NO_MORE_ITEMS loop termination. This pattern is the operational basis for COM-hijack target discovery (T-017), autostart enumeration (T-017), and recon collection (T-023). The vault does not have a card documenting the pattern itself as a reusable recon primitive; a proposed card would consolidate the call sequence, error-handling contract, and detection fingerprint."
    would_relate_to: [T-017, T-023, T-020]
    source_units: ["unit 21", "unit 35", "unit 36", "unit 37"]
    tags: [registry, regopenkeyex, regenumvalue, recon, fingerprint, proposed-technique]
```