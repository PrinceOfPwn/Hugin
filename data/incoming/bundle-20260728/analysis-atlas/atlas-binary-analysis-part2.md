## Synthesis Summary

This batch of 40 units from SANS SEC670 covers Windows API fundamentals and kernel internals relevant to several HUGIN techniques. The material maps to T-004 (PEB Walker), T-007 (Pool Party and related process injection — target selection prerequisites), T-013 (Remaining Injection Methods — cross-session injection via WTS enumeration), T-014 (NtCreateUserProcess — executive object and KPROCESS fundamentals), and T-015 (PPID Spoofing — InheritedFromUniqueProcessId field understanding). The training content spans CreateProcess/STARTUPINFO/PROCESS_INFORMATION mechanics, three distinct process-enumeration API families (Toolhelp, EnumProcesses, NtQuerySystemInformation, WTS), the Windows Object Manager's header/body split, the _KPROCESS kernel structure with DirectoryTableBase and ThreadListHead, and the KUSER_SHARED_DATA page at VA 0x7FFE0000. The gap this fills that source code alone does not provide: the operational rationale for choosing one enumeration API over another (NtQuerySystemInformation avoids Toolhelp's API surface), why KUSER_SHARED_DATA is a detection-resistant info source versus PEB walking, how EPROCESS/KPROCESS split exposes (or hides) process metadata from the Object Manager, and how cross-session targets surface via WTS — none of which is visible in the Rust syscall dispatch code.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "kuser-shared-data"
    target: T-004
    type: alternative_to
    rationale: "KUSER_SHARED_DATA at VA 0x7FFE0000 provides system information (page size, processor counts, OS version equivalent data) at a fixed, shared VA without any API call — an alternative to PEB walking for resolving certain runtime values without touching ntdll exports."
  - source: "system-process-information-struct"
    target: T-007
    type: enables
    rationale: "SYSTEM_PROCESS_INFORMATION retrieved via NtQuerySystemInformation surfaces UniqueProcessId and InheritedFromUniqueProcessId for every process in a single native call, enabling target selection for injection without the userland Toolhelp or EnumProcesses APIs."
  - source: "wtsenum-process-sessions"
    target: T-013
    type: enables
    rationale: "WTSEnumProcessSessions enumerates processes across Terminal Services sessions, enabling cross-session process injection target selection that userland snapshot APIs do not expose by default."
  - source: "kprocess-structure"
    target: T-014
    type: concept_link
    rationale: "_KPROCESS contains DirectoryTableBase (CR3 / page-table root) and ThreadListHead — the kernel-level structures that NtCreateUserProcess populates when building a new process object; understanding these is necessary to reason about what the syscall actually constructs."
  - source: "windows-object-manager"
    target: T-015
    type: concept_link
    rationale: "The Object Manager exposes EPROCESS (visible) but not _KPROCESS (kernel-only); PPID spoofing manipulates InheritedFromUniqueProcessId which lives in the Object-Manager-visible portion, while the kernel scheduling structures remain untouched."
  - source: T-007
    target: "process-enumeration-toolhelp"
    type: requires
    rationale: "Injection primitives need a target PID, and the material shows CreateToolhelp32Snapshot + Process32First/Next as the canonical enumeration path feeding OpenProcess for injection handle acquisition."
  - source: "native-system-info-enum"
    target: "process-enumeration-toolhelp"
    type: alternative_to
    rationale: "NtQuerySystemInformation with SystemProcessInformation retrieves the same target PID/PPID data without invoking the userland Toolhelp APIs that EDR products commonly hook, serving as an evasion-friendlier alternative."
```

### Concept Nodes

```yaml
concepts:
  - id: "kuser-shared-data"
    name: "KUSER_SHARED_DATA Page (VA 0x7FFE0000)"
    category: windows-structure
    description: "KUSER_SHARED_DATA is a kernel-mapped, read-only page visible at virtual address 0x7FFE0000 in nearly every user-mode process on Windows. It contains a large number of frequently-read system values (tick count, system time, NtSystemRoot, product options, processor counts, page size) without requiring a syscall. Because it is a fixed VA mapped by the kernel during process creation, malware can read OS configuration data without touching ntdll exports or invoking any NT API."
    relevant_to: [T-004, T-020]
    tags: [windows-internals, info-source, evasion, kernel, shared-memory]

  - id: "kprocess-structure"
    name: "_KPROCESS Kernel Process Object"
    category: windows-structure
    description: "_KPROCESS is the lower-layer kernel object representing a process (~0x438 bytes). It holds DirectoryTableBase at offset 0x28 (the CR3 page-table root for virtual address translation), ThreadListHead at 0x30 (the linked list of threads owned by the process), ReadyListHead, and affinity data. Unlike EPROCESS, _KPROCESS is not exposed via the Object Manager — it is consumed only by the scheduler and memory manager. The split between EPROCESS (Object-Manager-visible) and KPROCESS (kernel-only) determines which process attributes user-mode callers can observe or manipulate through handles."
    relevant_to: [T-014, T-007, T-015]
    tags: [kernel, eprocess, kprocess, directory-table-base, scheduler, windows-internals]

  - id: "windows-object-manager"
    name: "Windows Object Manager Header/Body Split"
    category: os-internal
    description: "Every Windows kernel object (process, thread, file, event, etc.) uses a uniform header/body layout maintained by the Object Manager. The object header contains type-agnostic metadata: name, directory, security descriptor, handle count and list, and optional subheaders. The object body is unique to the type. The Object Manager validates access rights and creates objects on behalf of callers — e.g. CreateFile calls NtCreateFile, the Object Manager creates an executive file object, and a handle is returned to the caller via the process handle table. Tools like ObTypeIndexTable enumerate these types from a kernel debugger."
    relevant_to: [T-014, T-016]
    tags: [object-manager, executive-objects, handle-table, windows-internals]

  - id: "system-process-information-struct"
    name: "SYSTEM_PROCESS_INFORMATION Structure"
    category: windows-structure
    description: "SYSTEM_PROCESS_INFORMATION is the native structure returned by NtQuerySystemInformation with the SystemProcessInformation information class. It contains NextEntryOffset (linked-list traversal), NumberOfThreads, CreateTime/UserTime/KernelTime, ImageName (UNICODE_STRING), UniqueProcessId, InheritedFromUniqueProcessId, and a variable-length Threads[] array of SYSTEM_THREAD_INFORMATION entries. It also carries memory usage counters (WorkingSetPrivateSize, PagefileUsage, PrivatePageCount, QuotaPeakNonPagedPoolUsage) and I/O counters (ReadOperationCount, WriteOperationCount, ReadTransferCount). Because it returns PID, PPID, thread counts, and per-thread timing in a single buffer, it serves as a denser, evasion-friendlier alternative to EnumProcesses or CreateToolhelp32Snapshot."
    relevant_to: [T-007, T-015, T-020]
    tags: [native-api, process-enumeration, evasion, ntquerysysteminformation, windows-internals]

  - id: "native-system-info-enum"
    name: "NtQuerySystemInformation Native Process Enumeration"
    category: attack-pattern
    description: "NtQuerySystemInformation is a native NT API (returning NTSTATUS) that accepts a SYSTEM_INFORMATION_CLASS enumeration and a caller-allocated buffer. Specifying SystemProcessInformation returns a linked list of SYSTEM_PROCESS_INFORMATION entries covering every process in the system without invoking userland process-enumeration wrappers. Because it is a single direct syscall rather than a wrapper over Toolhelp32, it minimizes the userland API surface that EDRs commonly hook, making it the preferred enumeration path for tradecraft where enumeration must be quiet."
    relevant_to: [T-004, T-007, T-020]
    tags: [native-api, evasion, process-enumeration, syscall, recon]

  - id: "process-enumeration-toolhelp"
    name: "CreateToolhelp32Snapshot Process Enumeration"
    category: attack-pattern
    description: "CreateToolhelp32Snapshot creates a snapshot handle covering processes, heaps, threads, or loaded modules. Iteration uses Process32First/Process32Next with PROCESSENTRY32 structures (declared in tlhelp32.h). The snapshot is a single-handle abstraction that returns process name, PID, parent PID, and thread count. The material notes that this API is simple to call but does not return much information per entry, and is the conventional userland path before falling back to NtQuerySystemInformation for denser data."
    relevant_to: [T-007, T-020]
    tags: [toolhelp, process-enumeration, userland-api, recon]

  - id: "wtsenum-process-sessions"
    name: "WTSEnumerateProcesses / WTSEnumProcessSessions"
    category: attack-pattern
    description: "WTS_EnumerateProcessesA (Windows Terminal Services, BOOL return) enumerates processes across all Terminal Services sessions, including sessions other than the caller's. WTSEnumProcessSessions surfaces per-session process lists, enabling identification of cross-session injection targets that the caller's default session does not enumerate through Toolhelp or EnumProcesses. The material explicitly frames this API family as the path for identifying cross-session process injection opportunities."
    relevant_to: [T-013, T-020]
    tags: [wts, terminal-services, cross-session, process-enumeration, injection-targeting]

  - id: "createprocess-startupinfo-procinfo"
    name: "CreateProcess STARTUPINFO/PROCESS_INFORMATION Pattern"
    category: os-internal
    description: "CreateProcess accepts STARTUPINFO (window station, desktop, standard handles, show window flags) and writes PROCESS_INFORMATION (hProcess, hThread, dwProcessId, dwThreadId) on return. The PROCESS_INFORMATION structure holds the new process and its primary thread handles plus the PID and TID. Understanding this pattern is the prerequisite for any CreateProcess-based injection or parent-spoofing primitive: the returned handles are what NtAllocateVirtualMemory, NtWriteVirtualMemory, and QueueUserAPC target."
    relevant_to: [T-014, T-015, T-013]
    tags: [createprocess, startupinfo, process-information, handles, windows-internals]

  - id: "system-info-structure"
    name: "SYSTEM_INFO via GetNativeSystemInfo"
    category: windows-structure
    description: "GetNativeSystemInfo (VOID return) populates a SYSTEM_INFO structure with: dwPageSize (page size and the granularity used by VirtualAlloc for protection changes), lpMinimumApplicationAddress / lpMaximumApplicationAddress (user-mode VA bounds), dwActiveProcessorMask (0-31 bit per processor), dwNumberOfProcessors (used by GetLogicalProcessorInformation), and dwAllocationGranularity. Implant code uses these values when computing allocation sizes, ASLR bounds, and per-processor thread affinity."
    relevant_to: [T-007, T-020]
    tags: [system-info, virtualalloc, memory-layout, windows-internals]

  - id: "formatmessage-error-lookup"
    name: "FormatMessage System Error Lookup"
    category: os-internal
    description: "FormatMessageA with FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS converts a GetLastError or HRESULT value into a localized system error string. When FORMAT_MESSAGE_ALLOCATE_BUFFER is used, the system allocates the buffer and the caller must release it with LocalFree. The FORMAT_MESSAGE_IGNORE_INSERTS flag is mandatory for system-message lookups because system messages can contain insertion placeholders (%1, %2) that FormatMessage would otherwise attempt to fill from caller-supplied arguments, producing malformed output. SUCCEEDED(hr) and FAILED(hr) macros (defined in winerror.h) test HRESULT return values against zero / negative thresholds."
    relevant_to: []
    tags: [error-handling, formatmessage, hresult, getlasterror, orphan]

  - id: "executive-file-object-flow"
    name: "CreateFile to NtCreateFile Executive Object Flow"
    category: os-internal
    description: "A user-mode CreateFile call flows through kernelbase.dll into NtCreateFile, which causes the Object Manager to create an executive file object (header + body), insert it into the calling process's handle table, and return a handle. The handle returned to user mode is a small integer index into the process handle table that references the executive object; subsequent ReadFile/WriteFile calls use this handle to dereference the object. This is the canonical object-creation flow that injection primitives reuse for section/file handles used by NtMapViewOfSection and process-creation parameter blocks."
    relevant_to: [T-014, T-007]
    tags: [createfile, ntcreatefile, executive-object, handle-table, windows-internals]
```

### Detection Insights

```yaml
detection:
  - indicator: "CreateToolhelp32Snapshot invocation with TH32CS_SNAPPROCESS flag"
    source: etw
    confidence: medium
    relevant_to: [T-007, T-020]
    description: "Process enumeration via Toolhelp is observable through the kernel ETW provider for process/thread snapshot creation. EDRs flag short-lived snapshots (handle opened, iterated, closed within milliseconds) as recon-pattern behavior, especially when followed by OpenProcess with PROCESS_VM_WRITE | PROCESS_VM_OPERATION against an unrelated PID."
    bypassed_by: "NtQuerySystemInformation with SystemProcessInformation retrieves the same data via a single native call without the snapshot handle lifecycle, avoiding the Toolhelp-specific telemetry."

  - indicator: "OpenProcess against unrelated PID with PROCESS_VM_OPERATION | PROCESS_VM_WRITE rights"
    source: kernel-callback
    confidence: high
    relevant_to: [T-007, T-013]
    description: "The ObRegisterCallbacks OBJECT_PRE_OPERATION callback for the PsProcessType object type fires on OpenProcess. EDRs inspect DesiredAccess — combinations of PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, or PROCESS_VM_READ against a PID that the calling process did not spawn are the canonical injection-handle acquisition signal."
    bypassed_by: "not discussed in this batch"

  - indicator: "NtQuerySystemInformation with SystemProcessInformation information class"
    source: etw
    confidence: low
    relevant_to: [T-020, T-007]
    description: "Native NtQuerySystemInformation calls appear in ETW-TI and NT kernel tracing but are far less commonly alerted on than Toolhelp enumeration because the syscall is used by legitimate management tooling. The discriminating signal is buffer size — a single large allocation followed by a dense walk with no legitimate consumer is suspicious but not high-confidence."
    bypassed_by: "not discussed — the material positions NtQuerySystemInformation as the evasion-friendlier enumeration path but does not describe specific detection-evasion techniques layered on top."

  - indicator: "WTSEnumerateProcesses / WTSEnumProcessSessions call against sessions other than the caller's"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-013]
    description: "Cross-session WTS enumeration requires SeChangeNotifyPrivilege and generates audit log entries when a process enumerates sessions it does not own. Repeated WTS enumeration followed by OpenProcess against a session-foreign PID is a cross-session injection precursor signal."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Process Snapshot Followed by Cross-Process VM Write Handle"
    logsource: sysmon
    condition_summary: "Event ID 1 (Process Create) for the snapshot-creating process, followed within 5 seconds by Event ID 10 (ProcessAccess) with GrantedAccess containing 0x0020 (VM_WRITE) or 0x0008 (VM_OPERATION) targeting a process with a different parent."
  - title: "NtQuerySystemInformation with Large Output Buffer"
    logsource: etw
    condition_summary: "ETW-TI event for NtQuerySystemInformation where SystemInformationClass == SystemProcessInformation (5) and SystemInformationLength exceeds 64KB, executed by a process without a legitimate WMI/management tool image."
  - title: "WTS Cross-Session Enumeration Followed by OpenProcess"
    logsource: windows-security
    condition_summary: "Event ID 4663 (Object Access) on WtsApi process object types from a session ID other than the target process session, followed within 10 seconds by Event ID 4663 OpenProcess with VM_OPERATION access from the same source PID."
```

### Operational Chains

```yaml
chains:
  - name: "Process Injection Target Selection via Native Enumeration"
    description: "Select an injection target PID using a native syscall enumeration path that avoids Toolhelp userland hooks."
    steps:
      - technique: "NtQuerySystemInformation with SystemProcessInformation"
        role: "Enumerate all processes and their PIDs/PPIDs in a single native call, avoiding userland snapshot APIs."
      - technique: T-015
        role: "Filter candidates by InheritedFromUniqueProcessId to find a suitable parent-spoofed target lineage."
      - technique: T-007
        role: "OpenProcess on the selected PID and inject using the chosen primitive (Pool Party, Early Cascade, etc.)."
    notes: "The material presents NtQuerySystemInformation as the evasion-friendlier enumeration path because it does not invoke the Toolhelp snapshot-handle lifecycle. It does not specify timing constraints; the enumeration → OpenProcess → inject sequence is presented as a logical dependency chain, not a time-bounded workflow."

  - name: "Cross-Session Process Injection Targeting"
    description: "Identify and inject into a process running in a different Terminal Services session."
    steps:
      - technique: "WTSEnumProcessSessions enumeration"
        role: "Enumerate processes across all sessions, surfacing targets in sessions other than the caller's."
      - technique: "OpenProcess with PROCESS_VM_OPERATION | PROCESS_VM_WRITE"
        role: "Acquire a handle to the cross-session target PID."
      - technique: T-013
        role: "Execute the cross-session injection via a primitive from the remaining-methods set (Early Bird, APC, hollowing)."
    notes: "The material explicitly links WTS enumeration to cross-session process injection opportunities but does not specify which injection primitive is preferred for cross-session use or what session privilege boundary the caller must cross."

  - name: "Process Creation with Returned Handles for Injection"
    description: "Create a sacrificial process and use the returned handles for follow-on injection."
    steps:
      - technique: "CreateProcess with STARTUPINFO, suspended"
        role: "Spawn a sacrificial process; PROCESS_INFORMATION returns hProcess, hThread, dwProcessId, dwThreadId."
      - technique: T-007
        role: "Use the returned hProcess to allocate, write, and execute shellcode in the suspended process."
    notes: "The material describes CreateProcess and the PROCESS_INFORMATION return structure as foundational, but does not itself chain into a specific injection primitive — that connection is established by operational practice."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "kuser-shared-data-info-source"
    title: "KUSER_SHARED_DATA as Detection-Free System Info Source"
    kind: proposed-technique
    description: "SEC670 dedicates explicit material to KUSER_SHARED_DATA at VA 0x7FFE0000 — a fixed-VA kernel-mapped page readable without any API call. The vault's T-004 (PEB Walker) documents module resolution via the PEB, but the KUSER_SHARED_DATA page is a distinct info source for system values (page size, tick count, processor counts, system time, NtSystemRoot) that does not require touching the PEB or any ntdll export. This warrants a standalone concept node — and arguably a small T-NNN card — because it is a reusable, detection-resistant primitive distinct from PEB walking."
    would_relate_to: [T-004, T-020]
    source_units: ["unit 21", "unit 22", "unit 23"]
    tags: [kuser-shared-data, info-source, evasion, kernel, proposed-technique]

  - id: "native-process-enumeration-coverage"
    title: "NtQuerySystemInformation as Evasion-Friendlier Enumeration Path"
    kind: coverage-gap
    description: "The vault documents process injection (T-007 family) and anti-analysis (T-020), but does not explicitly cover the enumeration-API selection problem that precedes injection target selection. SEC670's contrast of CreateToolhelp32Snapshot, EnumProcesses, and NtQuerySystemInformation — with NtQuerySystemInformation framed as the native evasion-friendlier path — is operational knowledge that belongs in the graph as either a recon sub-technique or cross-cutting metadata on injection cards."
    would_relate_to: [T-007, T-020]
    source_units: ["unit 27", "unit 28", "unit 29", "unit 32", "unit 33", "unit 34", "unit 35"]
    tags: [ntquerysysteminformation, enumeration, evasion, coverage-gap, recon]

  - id: "cross-session-injection-primitive"
    title: "Cross-Session Process Injection via WTS Target Selection"
    kind: proposed-technique
    description: "SEC670 frames WTSEnumProcessSessions as the path to identifying cross-session process injection opportunities. The vault's T-013 (Remaining Injection Methods) catalogues injection primitives but does not specifically address cross-session targeting — the operational constraint that the target runs in a Terminal Services session other than the caller's, requiring SeChangeNotifyPrivilege / session-boundary traversal. This is a distinct operational tradecraft area worth surfacing as either a T-013 sub-technique or a new card."
    would_relate_to: [T-013, T-007]
    source_units: ["unit 30", "unit 31"]
    tags: [cross-session, wts, terminal-services, injection, proposed-technique]

  - id: "eprocess-kprocess-split-concept"
    title: "EPROCESS / KPROCESS Object-Manager Visibility Split"
    kind: coverage-gap
    description: "SEC670 documents that EPROCESS is exposed via the Object Manager while _KPROCESS (containing DirectoryTableBase, ThreadListHead, ReadyListHead, affinity) is kernel-only. The vault's T-014 (NtCreateUserProcess) and T-015 (PPID Spoofing) operate on Object-Manager-visible fields but do not document this visibility split or which structures are reachable from user mode versus kernel mode. A concept node on this split would clarify for graph readers what PPID spoofing cannot touch (kernel scheduler structures) and why."
    would_relate_to: [T-014, T-015, T-016]
    source_units: ["unit 24", "unit 25", "unit 26"]
    tags: [eprocess, kprocess, object-manager, visibility, coverage-gap]
```

