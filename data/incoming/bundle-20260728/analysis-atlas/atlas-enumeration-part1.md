## Synthesis Summary

The batch maps primarily to T-023 (Client Capabilities), T-007 (Process Injection), and T-017 (Persistence Suite). SANS SEC670 material systematically catalogs Win32 enumeration APIs for processes (CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcesses, NtQuerySystemInformation), users/groups (NetLocalGroupEnum and related lmaccess.h functions), services (EnumServicesStatusEx, QueryServiceStatusEx against the SCM database), scheduled tasks (ITaskScheduler COM interface), and network interfaces (GetAdaptersAddresses), along with PE analysis tooling (Dumpbin, PEview, PE-bear, CFF Explorer). The gap filled is the API taxonomy itself — source code shows recon and persistence modules exist but does not explain which enumeration API to choose for which target class, what access masks are required, what level parameters return which structures, or that snapshots are static views requiring re-query for live state. Eight units (30–37) covering AD enumeration tooling (PowerView, MailSniper), Python enumeration scripts, database relationships, and Hashcat password cracking were skipped as off-theme relative to the vault's focus on Rust implant development and Windows offensive tradecraft.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: createtoolhelp32snapshot-process-enum
    target: enumprocesses-pid-enum
    type: alternative_to
    rationale: "SEC670 presents CreateToolhelp32Snapshot and EnumProcesses as interchangeable process enumeration primitives, with EnumProcesses chosen when only PIDs are needed and CreateToolhelp32Snapshot chosen when detailed metadata is required."

  - source: ntquerysysteminfo-process-enum
    target: createtoolhelp32snapshot-process-enum
    type: alternative_to
    rationale: "SEC670 lists NtQuerySystemInformation alongside EnumProcesses and WTSEnumerateProcessesEx as undocumented process enumeration methods, providing a lower-layer alternative to the Win32 snapshot API."

  - source: wts-enumerate-processes
    target: createtoolhelp32snapshot-process-enum
    type: alternative_to
    rationale: "SEC670 contrasts WTSEnumerateProcesses with CreateToolhelp32Snapshot and EnumProcesses as a third documented process enumeration method, noting its Terminal Services lineage."

  - source: createtoolhelp32snapshot-process-enum
    target: T-007
    type: enables
    rationale: "Process enumeration is a prerequisite for injection — operators must identify a suitable host process PID before opening it and writing shellcode, as covered in T-007's injection variants."

  - source: static-snapshot-semantics
    target: createtoolhelp32snapshot-process-enum
    type: concept_link
    rationale: "The static-view behavior of CreateToolhelp32Snapshot directly shapes how the API must be used; SEC670 emphasizes that snapshots are not live views."

  - source: scm-database-enumeration
    target: T-017
    type: enables
    rationale: "Enumerating existing services via EnumServicesStatusEx informs persistence decisions — operators identify service insertion points, hosting PIDs, and existing service configurations before persisting via schtask or service modification in T-017."

  - source: itaskscheduler-com-enum
    target: T-017
    type: enables
    rationale: "Scheduled task enumeration via ITaskScheduler::Enum reveals existing tasks, their triggers, and namespaces — directly relevant to T-017's schtask persistence layer, which must coexist with or hide among existing tasks."

  - source: T-023
    target: createtoolhelp32snapshot-process-enum
    type: requires
    rationale: "T-023's recon module (byakugan.rs) requires process enumeration primitives to inventory running processes on target systems as part of client capability recon."

  - source: pe-analysis-toolchain
    target: T-007
    type: enhances
    rationale: "Static PE inspection tools (Dumpbin, PEview, PE-bear, CFF Explorer) aid operator understanding of the PE structures parsed by T-007's pe.rs module, accelerating development and debugging of injection primitives."
```

### Concept Nodes

```yaml
concepts:
  - id: "createtoolhelp32snapshot-process-enum"
    name: "CreateToolhelp32Snapshot for Process Enumeration"
    category: os-internal
    description: "The CreateToolhelp32Snapshot API creates a snapshot handle enumerating processes, threads, heaps, or modules on the local system. The dwFlags parameter (with TH32CS_SNAPPROCESS being most relevant for process enumeration) controls what data is captured. The snapshot is a static view taken at the time of the call — subsequent process changes are not reflected. Iteration is performed via Process32First followed by Process32Next using PROCESSENTRY32 structures, defined in TlHelp32.h."
    relevant_to: [T-023, T-007]
    tags: [process-enum, snapshot, api, recon]

  - id: "enumprocesses-pid-enum"
    name: "EnumProcesses API"
    category: os-internal
    description: "EnumProcesses is a Win32 API for retrieving process IDs on the local system. It accepts a DWORD pointer (lpidProcess), a buffer size in bytes (cb), and a pointer to receive bytes needed (lpcbNeeded), returning only PIDs without detailed information. The function returns BOOL and is suitable when detailed process metadata is not required."
    relevant_to: [T-023, T-007]
    tags: [process-enum, api, recon]

  - id: "wts-enumerate-processes"
    name: "WTSEnumerateProcesses via Terminal Services"
    category: os-internal
    description: "WTSEnumerateProcesses is a Windows Terminal Service API that provides an alternative enumeration path to CreateToolhelp32Snapshot and EnumProcesses. SEC670 highlights it as a documented method with potential to query remote systems when paired with a server handle, providing per-process information including SID data that the simpler EnumProcesses API does not surface."
    relevant_to: [T-023]
    tags: [process-enum, terminal-services, api, recon]

  - id: "ntquerysysteminfo-process-enum"
    name: "NtQuerySystemInformation for Process Enumeration"
    category: os-internal
    description: "NtQuerySystemInformation with SystemProcessInformation is an undocumented NT API that SEC670 lists alongside EnumProcesses and WTSEnumerateProcessesEx as a process enumeration method. It bypasses the Win32 API layer and returns kernel-maintained process lists directly, useful when Win32 APIs are hooked or filtered by EDR."
    relevant_to: [T-023, T-007, T-016]
    tags: [process-enum, nt-api, undocumented, recon, evasion]

  - id: "netlocalgroupenum-local-groups"
    name: "NetLocalGroupEnum for Local Group Enumeration"
    category: os-internal
    description: "NetLocalGroupEnum enumerates local or remote system groups, returning LOCALGROUP_INFO_0 or LOCALGROUP_INFO_1 structures depending on the level parameter. It returns NET_API_STATUS and supports a resumehandle for paged enumeration of large group lists. Related APIs in the lmaccess.h header include NetUserEnum, NetLocalGroupGetMembers, NetUserGetInfo, and NetGetGroupUsers."
    relevant_to: [T-023]
    tags: [user-enum, group-enum, net-api, recon]

  - id: "scm-database-enumeration"
    name: "Service Control Manager Database Enumeration"
    category: windows-structure
    description: "The Service Control Manager (SCM) maintains the database of installed services. EnumServicesStatusEx enumerates entries in this database, requiring an SC_HANDLE with at least SC_MANAGER_ENUMERATE_SERVICE access. The InfoLevel parameter only accepts SC_ENUM_PROCESS_INFO. dwServiceType filters by SERVICE_WIN32 etc., dwServiceState filters active/inactive services, and pszGroupName can filter by service group or be NULL to enumerate all groups. QueryServiceStatusEx with SC_STATUS_PROCESS_INFO then retrieves per-service details including the hosting PID."
    relevant_to: [T-023, T-017]
    tags: [service-enum, scm, api, recon]

  - id: "itaskscheduler-com-enum"
    name: "ITaskScheduler COM Interface for Task Enumeration"
    category: os-internal
    description: "Scheduled task enumeration on Windows requires COM — the ITaskScheduler interface's Enum method returns an IEnumWorkItems enumerator object, whose Next method retrieves task names as LPWSTR strings. The sequence requires CoInitialize and CoCreateInstance before invoking these methods. This is the v1.0 Task Scheduler API surface; the v2.0 surface uses ITaskService and XML-based definitions."
    relevant_to: [T-017, T-023]
    tags: [task-enum, com, scheduler, persistence, recon]

  - id: "getadaptersaddresses-netif"
    name: "GetAdaptersAddresses Network Interface Enumeration"
    category: os-internal
    description: "GetAdaptersAddresses is the API SEC670 identifies as including logical interfaces in its results, distinguishing it from GetNumberOfInterfaces (which counts only physical interfaces) and GetIpStatistics (which returns IP-layer counters). The function returns unicast, anycast, and multicast addresses along with adapter metadata, making it the preferred enumeration primitive for full network topology discovery."
    relevant_to: [T-023]
    tags: [network-enum, api, recon]

  - id: "static-snapshot-semantics"
    name: "Snapshot Static View Semantics"
    category: os-internal
    description: "Snapshots returned by CreateToolhelp32Snapshot are static views captured at the moment of the API call — subsequent process creation, termination, or state changes are not reflected in the snapshot handle. Operators enumerating dynamic targets (e.g., short-lived injection processes) must either re-snapshot or pair the snapshot with a live query such as QueryServiceStatusEx or OpenProcess followed by QueryInformationProcess for current state."
    relevant_to: [T-023, T-007]
    tags: [snapshot, semantics, process-enum]

  - id: "pe-analysis-toolchain"
    name: "PE Inspection Toolchain"
    category: defense-mechanism
    description: "SEC670 enumerates a set of static analysis tools for inspecting PE/DLL contents: Dumpbin (Microsoft utility for exports/imports), PEview, PE-bear, and CFF Explorer. These tools surface the import/export tables, section layout, and header fields that an operator must understand when developing PE-parsing logic for injection (T-007) or evasion primitives that target PE structures."
    relevant_to: [T-007, T-016]
    tags: [pe, analysis-tools, static-analysis]
```

### Detection Insights

```yaml
detection:
  - indicator: "CreateToolhelp32Snapshot with TH32CS_SNAPPROCESS from non-system process"
    source: etw
    confidence: medium
    relevant_to: [T-023, T-007]
    description: "Process enumeration via CreateToolhelp32Snapshot generates kernel-mode activity observable through the Microsoft-Windows-Kernel-Process ETW provider. Frequent or sweeping enumeration from a single process — particularly one that then opens handles to discovered PIDs — is a recon indicator. Defenders correlate enumeration bursts with subsequent OpenProcess sequences."
    bypassed_by: "not discussed"

  - indicator: "EnumServicesStatusEx with SC_MANAGER_ENUMERATE_SERVICE access from non-svchost host"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023, T-017]
    description: "Service enumeration via the SCM API surfaces through Service Control Manager audit events when detailed access logging is enabled. Rapid full-database enumeration (pszGroupName=NULL, dwServiceState=SERVICE_STATE_ALL) from an unusual process is a behavioral indicator of implant recon prior to persistence or service-based execution."
    bypassed_by: "not discussed"

  - indicator: "COM instantiation of ITaskScheduler from non-svchost host"
    source: sysmon
    confidence: low
    relevant_to: [T-017, T-023]
    description: "Sysmon Event ID 7 (image load) and Event ID 1 (process creation) can correlate COM activity from ITaskScheduler instantiation. Unusual parent processes loading taskschd.dll or invoking CoCreateInstance with CLSID_TaskScheduler outside of svchost.exe or authorized schedulers indicate task enumeration reconnaissance."
    bypassed_by: "not discussed"

  - indicator: "NtQuerySystemInformation with SystemProcessInformation class"
    source: etw
    confidence: high
    relevant_to: [T-023, T-016]
    description: "Direct invocation of NtQuerySystemInformation bypasses Win32 enumeration APIs and is observable via the SystemTrace provider (NT Kernel Logger). EDRs that hook ntdll!NtQuerySystemInformation see this as a low-level enumeration signal, often used by implants attempting to avoid CreateToolhelp32Snapshot telemetry."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Process Snapshot Enumeration Followed by Remote Handle Open"
    logsource: sysmon
    condition_summary: "Sequence: process creating snapshot handle followed within 60s by EventID 10 OpenProcess for multiple distinct PIDs from same SourceImage"
  - title: "SCM Full Database Enumeration From Non-Service Process"
    logsource: windows-security
    condition_summary: "EventID 4656 or 4673 with ObjectName containing 'ServicesActive' and AccessMask including 0x10 (SC_MANAGER_ENUMERATE_SERVICE) from process not in svc/svchost allowlist"
```

### Operational Chains

```yaml
chains:
  - name: "Targeted Process Injection Recon"
    description: "Enumerate processes to identify a host for injection"
    steps:
      - technique: T-023
        role: "Recon module identifies candidate host processes via CreateToolhelp32Snapshot or NtQuerySystemInformation, filtering by session, integrity, and module load history"
      - technique: "OpenProcess handle acquisition"
        role: "Operator opens a handle to the chosen PID with required access mask (PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)"
      - technique: T-007
        role: "Injection primitive (e.g., Pool Party, Threadless, Early Cascade) writes and dispatches shellcode into the host process"
    notes: "SEC670 emphasizes that snapshots are static — operators targeting short-lived processes must either re-snapshot or pair the enumeration with a live query. The chosen enumeration API determines what metadata is available for filtering: EnumProcesses returns only PIDs while CreateToolhelp32Snapshot returns full PROCESSENTRY32."

  - name: "Persistence Surface Discovery"
    description: "Enumerate existing scheduled tasks and services to inform persistence placement"
    steps:
      - technique: T-023
        role: "Recon module enumerates existing scheduled tasks via ITaskScheduler COM interface and services via EnumServicesStatusEx"
      - technique: T-017
        role: "Persistence layer (schtask, COM hijack, or NTFS EA) selects insertion point that does not collide with enumerated existing entries and matches observed naming conventions"
    notes: "Material does not specify a closed-form sequencing between enumeration and persistence; the chain is implied by the shared knowledge domain. SEC670 notes that task enumeration requires CoInitialize and CoCreateInstance before invoking ITaskScheduler::Enum."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "recon-api-taxonomy-coverage"
    title: "Recon API Taxonomy Coverage Gap"
    kind: coverage-gap
    description: "SEC670 dedicates substantial material to the taxonomy of Win32 enumeration APIs across processes, users, groups, services, scheduled tasks, and network interfaces — distinguishing each by return type, level parameter, and access mask. The vault's T-023 recon module (byakugan.rs) is documented as covering ARP, TCP, and AD enum, but the broader enumeration surface (SCM, COM task scheduler, NetLocalGroupEnum, GetAdaptersAddresses) is not surfaced in any technique card. This material would inform a more complete recon capability matrix."
    would_relate_to: [T-023, T-017, T-007]
    source_units: ["unit 1", "unit 2", "unit 3", "unit 5", "unit 13", "unit 17", "unit 19", "unit 22", "unit 24"]
    tags: [recon, enumeration, coverage-gap, api-taxonomy]

  - id: "undocumented-nt-enum-evasion-primitive"
    title: "Undocumented NT Enumeration as Evasion Primitive"
    kind: proposed-technique
    description: "SEC670 explicitly frames NtQuerySystemInformation as an undocumented alternative to EnumProcesses, WTSEnumerateProcessesEx, and CreateToolhelp32Snapshot for process enumeration. This positions direct NT enumeration as an evasion primitive that bypasses Win32-layer hooks and ETW providers tied to documented APIs. The vault has no card for direct-NT recon primitives, though T-016 (EDR Evasion Suite) covers the broader evasion space. A dedicated card could capture NT-API-based enumeration patterns as a distinct capability."
    would_relate_to: [T-016, T-023, T-004]
    source_units: ["unit 13"]
    tags: [nt-api, evasion, recon, undocumented, proposed-technique]

  - id: "sec670-maldev-recon-convergence"
    title: "Cross-Source Convergence on Process Enumeration API Choice"
    kind: cross-source-convergence
    description: "SEC670 material systematically compares CreateToolhelp32Snapshot, EnumProcesses, and WTSEnumerateProcesses as enumeration primitives with explicit tradeoffs (metadata depth vs. simplicity vs. remote capability). This converges with the broader MalDev Academy pattern of selecting enumeration APIs based on operational context. The vault's recon module would benefit from a documented decision matrix for enumeration API selection tied to operational intent (injection targeting vs. situational awareness vs. lateral movement)."
    would_relate_to: [T-023]
    source_units: ["unit 5", "unit 7", "unit 8", "unit 11", "unit 13"]
    tags: [convergence, process-enum, api-selection]
```