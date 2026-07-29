## Synthesis Summary

The batch maps primarily to T-023 (Client Capabilities — recon/sysinfo collection), T-017 (Five-Layer Persistence — scheduled task enumeration via ITaskScheduler COM), and T-007 (Process Injection, umbrella card per the file manifest); several units also touch T-013 (Remaining Methods) because process enumeration is the operational prerequisite for selecting an injection target. The SEC670 material covers Win32 and COM enumeration primitives at the API level: CreateToolhelp32Snapshot, EnumProcesses (K32EnumProcesses), WTSEnumerateProcesses, NtQuerySystemInformation with SystemProcessInformation, NetUserEnum with USER_INFO levels, EnumServicesStatusEx against the SCM database, the ITaskScheduler/IEnumWorkItems COM interface, and the FindFirstFile/FindNextFile directory enumeration pattern. The gap this material fills is the operator-side enumeration tradecraft — the Win32 and COM API surface used to survey processes, users, services, and tasks — which does not exist in the vault's Rust source. Unit 17 (CRTO combinator attack on password wordlists) is off-theme password-cracking content and is skipped.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "win32-process-enumeration-apis"
    target: "T-007"
    type: "enables"
    rationale: "SEC670 presents process enumeration via CreateToolhelp32Snapshot, K32EnumProcesses, WTSEnumerateProcesses, or NtQuerySystemInformation as the survey step that precedes selecting an injection target PID; the injection methods under T-007 require this enumeration to identify a suitable host process."

  - source: "T-017"
    target: "itaskscheduler-com-enumeration"
    type: "concept_link"
    rationale: "T-017's schtask persistence layer requires the operator to enumerate existing scheduled tasks via ITaskScheduler::Enum and IEnumWorkItems::Next to identify name collisions, observe existing task layouts, and confirm task registration."

  - source: "netapi-user-enumeration"
    target: "T-023"
    type: "enables"
    rationale: "NetUserEnum and the related lmaccess.h Net* APIs provide the local/remote user and group enumeration capability that feeds T-023's recon and credential-harvest workflow."

  - source: "scm-service-enumeration"
    target: "T-017"
    type: "concept_link"
    rationale: "EnumServicesStatusEx against the SCM database supports both persistence decisions (where to install a service or hijack an image path) and operational awareness of existing defensive services that the persistence suite may need to avoid disrupting."

  - source: "ntquerysysteminformation-process-enum"
    target: "win32-process-enumeration-apis"
    type: "alternative_to"
    rationale: "SEC670 frames NtQuerySystemInformation as one of three 'undocumented' enumeration alternatives alongside EnumProcesses and WTSEnumerateProcessesEx, treating them as interchangeable survey paths with different EDR visibility profiles."
```

### Concept Nodes

```yaml
concepts:
  - id: "itaskscheduler-com-enumeration"
    name: "ITaskScheduler COM Enumeration"
    category: "os-internal"
    description: "The ITaskScheduler COM interface exposes the Enum method, which returns an IEnumWorkItems enumerator that allows iteration over registered scheduled tasks by name. The enumerator's Next method retrieves an array of LPWSTR task names. SEC670 presents this as the canonical COM-based approach to enumerating scheduled tasks on a Windows system."
    relevant_to: ["T-017"]
    tags: ["com", "scheduled-tasks", "enumeration", "windows-internals"]

  - id: "win32-process-enumeration-apis"
    name: "Win32 Process Enumeration API Family"
    category: "attack-pattern"
    description: "SEC670 covers four Win32/NT APIs for enumerating processes on a Windows system: CreateToolhelp32Snapshot (toolhelp snapshot), EnumProcesses/K32EnumProcesses (PSAPI), WTSEnumerateProcesses (Terminal Services), and NtQuerySystemInformation (NT direct). Each returns process information at a different abstraction level; SEC670's lab sequence treats them as interchangeable alternatives with different EDR visibility profiles."
    relevant_to: ["T-023", "T-007"]
    tags: ["process-enumeration", "recon", "windows-api", "attack-pattern"]

  - id: "createtoolhelp32snapshot"
    name: "CreateToolhelp32Snapshot Process Enumeration"
    category: "os-internal"
    description: "CreateToolhelp32Snapshot with the TH32CS_SNAPPROCESS flag produces a snapshot handle that can be iterated with Process32First and Process32Next using a PROCESSENTRY32 structure. The same API also captures heap and thread snapshots via TH32CS_SNAPHEAPLIST and TH32CS_SNAPTHREAD. SEC670 frames this as the standard toolhelp API for process enumeration in implant development."
    relevant_to: ["T-023", "T-007"]
    tags: ["process-enumeration", "toolhelp", "windows-api", "enumeration"]

  - id: "wts-enumerate-processes"
    name: "WTSEnumerateProcesses Enumeration"
    category: "os-internal"
    description: "WTSEnumerateProcesses queries the Terminal Services subsystem and returns WTS_PROCESS_INFO arrays containing PID, process name, session ID, and user SID for every process on the system. SEC670 uses this API as the third of three labs covering process enumeration, positioning it alongside K32EnumProcesses and CreateToolhelp32Snapshot as an alternative enumeration path that exposes session and user context."
    relevant_to: ["T-023", "T-007"]
    tags: ["process-enumeration", "wts", "session", "windows-api"]

  - id: "enumprocesses-k32"
    name: "K32EnumProcesses (EnumProcesses)"
    category: "os-internal"
    description: "K32EnumProcesses (exported as EnumProcesses in psapi.dll) returns an array of DWORD process IDs for every process on the system. SEC670 covers it as the simplest enumeration API — it returns only PIDs without additional context, requiring a follow-up call such as OpenProcess and GetModuleBaseName to retrieve names. The material flags it as 'undocumented' alongside WTSEnumerateProcessesEx and NtQuerySystemInformation in a unit review question."
    relevant_to: ["T-023", "T-007"]
    tags: ["process-enumeration", "psapi", "undocumented-api", "windows-api"]

  - id: "ntquerysysteminformation-process-enum"
    name: "NtQuerySystemInformation Process Enumeration"
    category: "os-internal"
    description: "NtQuerySystemInformation with the SystemProcessInformation information class returns a linked list of SYSTEM_PROCESS_INFORMATION structures containing PID, thread count, handle count, image name, and quota usage for every process. SEC670 lists this NT API as one of three 'undocumented' enumeration primitives alongside EnumProcesses and WTSEnumerateProcessesEx. Because it is a direct NT system call, it does not pass through the Win32 API layer and is less commonly hooked by userland EDRs."
    relevant_to: ["T-023", "T-007"]
    tags: ["nt-api", "process-enumeration", "undocumented-api", "edr-evasion"]

  - id: "netapi-user-enumeration"
    name: "NetUserEnum and USER_INFO Levels"
    category: "os-internal"
    description: "NetUserEnum (netapi32.dll, declared in lmaccess.h) returns user account information at a level selected by the dwLevel parameter, with USER_INFO_0 through USER_INFO_20 providing progressively more detail (name only, then password metadata, then full account properties). The function returns a buffer that must be freed with NetApiBufferFree. SEC670 positions it as the Win32 enumeration primitive for surveying local or remote system users."
    relevant_to: ["T-023"]
    tags: ["netapi", "user-enumeration", "lmaccess", "windows-api"]

  - id: "netapi-group-enumeration"
    name: "NetGroupGetUsers / NetLocalGroupGetMembers"
    category: "os-internal"
    description: "The lmaccess.h header exposes a family of Net* APIs including NetGroupGetUsers (members of a global group), NetLocalGroupGetMembers (members of a local group), NetUseEnum (active use connections), and NetUseGetInfo. SEC670 lists these as additional survey APIs beyond NetUserEnum, useful for mapping group memberships and active SMB sessions during recon."
    relevant_to: ["T-023"]
    tags: ["netapi", "group-enumeration", "lmaccess", "windows-api"]

  - id: "scm-service-enumeration"
    name: "EnumServicesStatusEx SCM Enumeration"
    category: "os-internal"
    description: "EnumServicesStatusEx enumerates services in the Service Control Manager database when supplied an SC_HANDLE with SC_MANAGER_ENUMERATE_SERVICE access. The InfoLevel parameter accepts only SC_ENUM_PROCESS_INFO. The dwServiceType filter (typically SERVICE_WIN32) and dwServiceState filter scope the result set, while pszGroupName filters by service group (NULL means enumerate all groups). The function requires a pcbBytesNeeded value to size the output buffer correctly."
    relevant_to: ["T-023", "T-017"]
    tags: ["scm", "service-enumeration", "windows-api", "windows-service"]

  - id: "directory-enumeration-win32"
    name: "FindFirstFile / FindNextFile Directory Enumeration"
    category: "os-internal"
    description: "SEC670 frames directory listing as a non-malicious native Windows behavior also performed by legitimate binaries, and points to standard MSDN examples using FindFirstFile/FindNextFile pattern matching. The material notes that Meterpreter's ls command implements the same primitive, and that directory enumeration is a baseline recon capability expected of any implant."
    relevant_to: ["T-023"]
    tags: ["file-enumeration", "recon", "windows-api"]
```

### Detection Insights

```yaml
detection:
  - indicator: "NetUserEnum / NetGroupGetUsers / NetLocalGroupGetMembers RPC calls against SAM"
    source: "windows-security-log"
    confidence: "medium"
    relevant_to: ["T-023"]
    description: "The Net* family of enumeration APIs route through the SAMRPC interface exposed by lsass.exe. Excessive or broad enumeration (e.g., NetUserEnum at level 20 against a remote system) generates Windows Security event 4662 (object operation against SAM objects) and may trigger event 4799 when security-enabled local groups are enumerated. Volume and source matter more than a single call."
    bypassed_by: "not discussed"

  - indicator: "CreateToolhelp32Snapshot handle creation in a non-tool process"
    source: "kernel-callback"
    confidence: "low"
    relevant_to: ["T-023", "T-007"]
    description: "SEC670 presents CreateToolhelp32Snapshot as a benign enumeration primitive also used by legitimate utilities. Process enumeration via this API is not in itself suspicious; detection requires context such as the calling process being an unsigned or unbacked executable, or the snapshot being immediately followed by OpenProcess calls targeting multiple PIDs."
    bypassed_by: "not discussed"

  - indicator: "NtQuerySystemInformation with SystemProcessInformation class"
    source: "etw"
    confidence: "medium"
    relevant_to: ["T-023", "T-007"]
    description: "NtQuerySystemInformation is a direct NT system call and does not pass through the Win32 API layer. EDRs that hook only ntdll exports will not see the call. Detection requires either ETW-TI telemetry on the syscall itself or behavior-based heuristics such as rapid successive OpenProcess calls following the query. SEC670 classifies this as an 'undocumented' enumeration primitive, signaling reduced EDR coverage."
    bypassed_by: "Use NtQuerySystemInformation directly via syscall to avoid userland hooks — implicit in SEC670's framing of it as an undocumented alternative to the documented Win32 enumeration APIs."

  - indicator: "EnumServicesStatusEx against SCM with SC_MANAGER_ENUMERATE_SERVICE"
    source: "windows-security-log"
    confidence: "low"
    relevant_to: ["T-023", "T-017"]
    description: "Service Control Manager enumeration generates handle-audit events if SC_MANAGER_ENUMERATE_SERVICE access is audited. The behavior is common to legitimate administrative tools, so volume-based detection is the primary signal rather than a single call."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Bulk Local User Enumeration via NetUserEnum"
    logsource: "windows-security"
    condition_summary: "Multiple EventID 4662 operations on SAM objects by a single non-LSASS subject within a short window, originating from an unusual process."
  - title: "Direct NtQuerySystemInformation Process Enumeration by Unbacked Image"
    logsource: "etw"
    condition_summary: "ETW-TI NtQuerySystemInformation event where the calling process image is not backed by a file on disk or is loaded from a user-writable path."
```

### Operational Chains

```yaml
chains:
  - name: "Process Survey to Injection Target Selection"
    description: "Enumerate candidate host processes before injecting into one"
    steps:
      - technique: "T-023"
        role: "Use a process enumeration API (CreateToolhelp32Snapshot, K32EnumProcesses, WTSEnumerateProcesses, or NtQuerySystemInformation) to inventory PIDs and image names on the target system."
      - technique: "T-023"
        role: "Filter candidates by criteria such as session ID, integrity level, and matching architecture; identify the chosen host process PID."
      - technique: "T-007"
        role: "Open a handle to the chosen PID and execute the selected injection variant."
    notes: "SEC670 presents process enumeration as the prerequisite survey step that precedes injection. The material does not discuss integrity-level filtering or architecture matching explicitly — those are operator knowledge."

  - name: "Scheduled Task Survey for Persistence Planning"
    description: "Enumerate existing scheduled tasks before installing a new one"
    steps:
      - technique: "T-017"
        role: "Use ITaskScheduler::Enum and IEnumWorkItems::Next to enumerate registered tasks by name and identify name collisions and pre-existing defender-scheduled tasks."
      - technique: "T-017"
        role: "Register a new scheduled task via the schtask persistence layer, avoiding collisions and respecting pre-existing tasks the operator does not want to disturb."
    notes: "SEC670 documents the enumeration COM interface but does not describe the registration path itself; persistence registration lives in T-017."

  - name: "Service Survey for Persistence and Evasion Planning"
    description: "Enumerate SCM services before persistence installation"
    steps:
      - technique: "T-023"
        role: "Call EnumServicesStatusEx with SC_MANAGER_ENUMERATE_SERVICE access, filtered by SERVICE_WIN32, to enumerate running services and identify candidates for image-path stomping or service hijack persistence."
      - technique: "T-017"
        role: "Install or hijack a service based on the enumeration results."
    notes: "SEC670 covers the enumeration primitive; the persistence decision belongs to T-017's service-related persistence paths."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "enumeration-primitives-coverage"
    title: "Vault Lacks Dedicated Enumeration Technique Card"
    kind: "coverage-gap"
    description: "SEC670 devotes an entire book section to enumeration primitives — ITaskScheduler COM, CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcesses, NtQuerySystemInformation, NetUserEnum, EnumServicesStatusEx, and directory enumeration APIs. The vault references recon in T-023 but does not document the Win32/COM enumeration API surface as a structured capability. A dedicated technique card or expanded T-023 section documenting which APIs are documented, undocumented, NT-direct, or COM-routed would help operators choose enumeration paths with the right EDR-evasion profile."
    would_relate_to: ["T-023", "T-007", "T-017"]
    source_units: ["unit 1", "unit 2", "unit 4", "unit 6", "unit 7", "unit 15", "unit 19", "unit 20"]
    tags: ["enumeration", "recon", "coverage-gap", "win32", "com"]

  - id: "nt-direct-enumeration-as-evasion"
    title: "NtQuerySystemInformation as EDR-Resistant Enumeration Path"
    kind: "emerging-tradecraft"
    description: "SEC670 explicitly classifies NtQuerySystemInformation as an 'undocumented' enumeration primitive alongside EnumProcesses and WTSEnumerateProcessesEx, signaling reduced EDR visibility for direct NT API usage. The vault documents NT-direct syscall usage for execution and injection (T-001, T-002, T-003) but does not document NT-direct enumeration. An expansion area would document which NT information classes are useful for enumeration (SystemProcessInformation, SystemHandleInformation, SystemModuleInformation) and which escape userland hooks."
    would_relate_to: ["T-002", "T-023", "T-007"]
    source_units: ["unit 15", "unit 19"]
    tags: ["nt-api", "enumeration", "edr-evasion", "emerging-tradecraft"]

  - id: "netapi-rpc-telemetry-detection"
    title: "Net* API Family as RPC-Derived Detection Surface"
    kind: "cross-source-convergence"
    description: "SEC670's coverage of NetUserEnum, NetGroupGetUsers, NetLocalGroupGetMembers, and NetUseEnum surfaces a detection surface the vault does not currently address: the SAMRPC and Netr* RPC interfaces exposed by lsass.exe. These interfaces are the user-enumeration analog to process enumeration and are common in recon phases. The vault's T-016 EDR evasion suite does not cover RPC-side telemetry muffling for the Net* family."
    would_relate_to: ["T-016", "T-023"]
    source_units: ["unit 6", "unit 20"]
    tags: ["rpc", "lsass", "netapi", "detection", "recon"]
```