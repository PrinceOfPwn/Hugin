## Synthesis Summary

This batch of SANS SEC670 "Getting to Know Your Target" material maps primarily to **T-023 (Client Capabilities)** for recon/sysinfo, with secondary relationships to **T-007 (Process Injection)** for target selection, **T-017 (Five-Layer Persistence)** for registry/service-based persistence placement, and **T-022 (Network Suite)** for network adapter enumeration. The units document the Windows enumeration API surface across four domains: network adapters (GetAdapterAddresses vs. GetNumberOfInterfaces vs. GetIpStatistics), system memory layout (SYSTEM_INFO fields including dwPageSize, lpMinimumApplicationAddress, dwAllocationGranularity), the registry (five HKEY root keys and the link/merged-view semantics of HKCR/HKCU/HKCC), and process enumeration (EnumProcesses, WTSEnumerateProcessesEx with remote-host support, NtQuerySystemInformation as the NT/undocumented path, and the snapshot-lag limitation of CreateToolhelp32Snapshot), plus service security descriptor inspection via sc.exe sdshow in SDDL format. The gap the material fills that source code alone does not provide is the *operational* rationale for API choice: why NtQuerySystemInformation avoids userland hook surface that EnumProcesses cannot, why WTSEnumerateProcessesEx is the only one of the three that supports remote targets via WTSOpenServerEx, why the snapshot method silently misses post-snapshot process creation, and why SDDL parsing matters for finding weak-ACL services as persistence footholds.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "win32-process-enumeration-apis"
    target: T-007
    type: enables
    rationale: "Process enumeration supplies the PID required to OpenProcess a victim for injection; SEC670 frames enumeration as a prerequisite step before any process-injection technique."
  - source: "win32-process-enumeration-apis"
    target: T-023
    type: concept_link
    rationale: "Process enumeration is a core recon capability; the material catalogues EnumProcesses, WTSEnumerateProcessesEx, and NtQuerySystemInformation as the three primary approaches with distinct detection footprints."
  - source: "ntquerysysteminformation-direct-enum"
    target: T-001
    type: enhances
    rationale: "NtQuerySystemInformation for process enumeration is reachable via direct/indirect syscall without touching userland ntdll hooks, complementing RecycledGate indirect-syscall dispatch by reducing hookable API surface in the same implant that performs injection."
  - source: "registry-root-keys"
    target: T-017
    type: enables
    rationale: "Registry enumeration under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER surfaces the autostart, AppInit_DLLs, and COM registration locations used by COM-hijack and TLS-callback persistence layers."
  - source: "service-sddl-inspection"
    target: T-017
    type: enables
    rationale: "sc.exe sdshow exposes service ACLs; services with weak DACLs granting SERVICE_CHANGE_CONFIG or write-to-binary-path permissions are persistence and privilege-escalation targets the persistence suite can leverage."
  - source: "system-info-structure"
    target: T-005
    type: concept_link
    rationale: "SYSTEM_INFO's dwPageSize, lpMinimumApplicationAddress, and lpMaximumApplicationAddress define the user-mode address-space bounds within which Ekko ROP sleep obfuscation allocates and encrypts memory regions."
  - source: "application-install-directories"
    target: T-007
    type: enhances
    rationale: "Directory walks of C:\\Program Files and C:\\Program Files (x86) surface candidate host binaries for module-overloading, DLL-hijack, and function-stomping injection paths."
```

### Concept Nodes

```yaml
concepts:
  - id: "getadapteraddresses-api"
    name: "GetAdapterAddresses API"
    category: os-internal
    description: "The Win32 GetAdapterAddresses function (iphlpapi.dll) returns IP addresses, gateway information, and DNS suffixes for all network adapters including logical interfaces such as tunnel adapters and loopback pseudo-interfaces. It supersedes the older GetNumberOfInterfaces call (which returns only an interface count) and GetIpStatistics (which returns aggregate counters rather than per-adapter data). SEC670 identifies GetAdapterAddresses as the canonical API for enumerating target NIC configurations."
    relevant_to: [T-022, T-023]
    tags: [recon, network, win32-api, iphlpapi]

  - id: "registry-root-keys"
    name: "Windows Registry Predefined Root Keys"
    category: windows-structure
    description: "The Windows Registry exposes five predefined root keys: HKEY_USERS, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, and HKEY_CURRENT_CONFIG. The 'H' prefix indicates these names are handles to keys (HKEY). Three of the five (HKCR, HKCU, HKCC) are links or merged views rather than direct keys — HKCR is a merged view of HKLM\\Software\\Classes and HKCU\\Software\\Classes. Recon against HKLM and HKCU surfaces installed software, autostart locations, and COM registration data useful for persistence placement; HKCR is not directly writable for hijack purposes because it is a merged view."
    relevant_to: [T-017, T-023]
    tags: [registry, recon, persistence, windows-internals]

  - id: "win32-process-enumeration-apis"
    name: "Process Enumeration API Surface"
    category: attack-pattern
    description: "Three primary Windows API surfaces enumerate running processes: EnumProcesses (PSAPI, returns a PID array with minimal per-process metadata), WTSEnumerateProcessesEx (WTSAPI32, returns full WTS_PROCESS_INFOW structures and natively supports remote server targeting via WTSOpenServerEx), and NtQuerySystemInformation with SystemProcessInformation (ntdll, returns a SYSTEM_PROCESS_INFORMATION linked list, undocumented but avoids the Win32 layer). Each has a distinct detection footprint: WTSEnumerateProcessesEx issues an RPC to TermSrv, NtQuerySystemInformation is reachable via direct/indirect syscall without touching userland hooks, and EnumProcesses internally attempts to open each process for query access."
    relevant_to: [T-023, T-007]
    tags: [recon, process-enumeration, nt-api, win32-api, wts, rpc]

  - id: "ntquerysysteminformation-direct-enum"
    name: "NtQuerySystemInformation(SystemProcessInformation) Direct Enumeration"
    category: attack-pattern
    description: "Calling NtQuerySystemInformation with the SystemProcessInformation class returns a variable-length linked list of SYSTEM_PROCESS_INFORMATION structures containing PID, name, handle count, thread info, and timing fields for every process in the system. Because it is an Nt* syscall rather than a Win32 wrapper, it can be dispatched via indirect syscall (RecycledGate) or VEH Gate and avoids the userland ntdll hooks that EDR products place on PSAPI and WTSAPI32 imports. SEC670 identifies it as the 'undocumented' option for process enumeration."
    relevant_to: [T-001, T-003, T-023]
    tags: [recon, nt-api, indirect-syscall, evasion, process-enumeration]

  - id: "createtoolhelp32snapshot-limitation"
    name: "CreateToolhelp32Snapshot Enumeration Lag"
    category: os-internal
    description: "The CreateToolhelp32Snapshot + Process32First/Next enumeration method captures a point-in-time snapshot of the process list. Processes created after the snapshot is taken are not visible to subsequent walks of the snapshot, producing a silent gap. Implants that must detect newly-spawned processes (e.g., monitoring for spawned injection victims or sandbox launching analysis tools) must re-snapshot or use a notification-based approach such as WMI Win32_ProcessStartTrace event subscription."
    relevant_to: [T-023, T-020]
    tags: [recon, process-enumeration, snapshot, race-condition, limitation]

  - id: "system-info-structure"
    name: "SYSTEM_INFO Memory Layout Fields"
    category: windows-structure
    description: "The SYSTEM_INFO structure returned by GetSystemInfo (and the underlying NtQuerySystemInformation with SystemBasicInformation) exposes the page size (dwPageSize), allocation granularity (dwAllocationGranularity, typically 64KB), lowest and highest user-accessible addresses (lpMinimumApplicationAddress, lpMaximumApplicationAddress), active processor mask (dwActiveProcessorMask), and logical processor count (dwNumberOfProcessors). VirtualAlloc relies on dwPageSize and dwAllocationGranularity. These fields bound the user-mode address range within which implant memory allocation, module mapping, and sleep-obfuscation ROP must operate."
    relevant_to: [T-005, T-006, T-023]
    tags: [system-info, memory, virtualalloc, windows-internals]

  - id: "service-sddl-inspection"
    name: "Service Security Descriptor Inspection via sc.exe sdshow"
    category: attack-pattern
    description: "The sc.exe command-line utility with the sdshow argument retrieves a service's security descriptor in SDDL (Security Descriptor Definition Language) format. Parsing the SDDL string reveals the ACEs (DACL) controlling who can start, stop, query, or modify the service — including the SERVICE_CHANGE_CONFIG and SERVICE_WRITE access rights that permit binary-path or trigger modification. Services with weak ACLs allowing non-admin principals to change configuration are high-value persistence and privilege-escalation targets because the modification blends into legitimate service-management activity."
    relevant_to: [T-017, T-023]
    tags: [services, sddl, persistence, privilege-escalation, recon]

  - id: "application-install-directories"
    name: "Standard Application Install Directory Conventions"
    category: os-internal
    description: "On 64-bit Windows, 64-bit applications install under C:\\Program Files while 32-bit applications install under C:\\Program Files (x86) under the WOW64 splitter. This enables an implant to infer the architecture of discovered binaries from their install path. Some applications (e.g., Python) install at the system drive root rather than under Program Files. Recon walks of these directories surface installed software for LOLBin selection, DLL-hijack target identification, and module-overloading candidate selection."
    relevant_to: [T-023, T-007]
    tags: [recon, filesystem, lolbin, dll-hijack, wow64]
```

### Detection Insights

```yaml
detection:
  - indicator: "PSAPI EnumProcesses opening every process for PROCESS_QUERY_INFORMATION"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023, T-007]
    description: "EnumProcesses internally attempts to open each process for PROCESS_QUERY_LIMITED_INFORMATION (or PROCESS_QUERY_INFORMATION on older systems) to populate per-process metadata. A high volume of access attempts from a single caller against many unrelated PIDs appears as Audit Process Access events (Event ID 4663 / 4656) in the Security log when Process Access auditing is enabled. The pattern is distinct from legitimate task-manager / EDR enumeration which typically uses WTS or NtQuerySystemInformation instead."
    bypassed_by: "Switch to NtQuerySystemInformation(SystemProcessInformation) which returns the full process list via a single syscall with no per-process handle opens — no 4663/4656 events are generated."

  - indicator: "WTSEnumerateProcessesEx RPC to TermSrv on a remote host"
    source: windows-security-log
    confidence: high
    relevant_to: [T-023]
    description: "WTSEnumerateProcessesEx against a remote server issues an RPC call to the TermSrv (Terminal Services) service on the target. Remote WTS enumeration appears as logon-like RPC activity (Event ID 4624 type 3 network logon from the calling account) and can trigger Event ID 4648 (explicit credential use) when alternate credentials are supplied. EDR products flag remote WTS process enumeration as lateral-movement recon."
    bypassed_by: "Use local NtQuerySystemInformation instead, or enumerate via WMI which produces different but equally detectable RPC telemetry."

  - indicator: "sc.exe sdshow against many services in a brief window"
    source: process-creation
    confidence: medium
    relevant_to: [T-017]
    description: "Calling sc.exe sdshow <service> against many services in a short window is recon-looking behavior. The command line is captured in Sysmon Event ID 1 (ProcessCreate) and Windows Security Event ID 4688. Sigma rules that count distinct service names appearing as sdshow arguments from a single parent process within a sliding window flag this as service-permission enumeration."
    bypassed_by: "Read service security descriptors directly via QueryServiceObjectSecurity API from inside the implant rather than spawning sc.exe — avoids the process-creation event entirely."

sigma_ideas:
  - title: "Mass Service Security Descriptor Enumeration"
    logsource: process-creation
    condition_summary: "Process sc.exe with command line containing 'sdshow' against more than 5 distinct service names within a 60-second window from the same parent process"
  - title: "PSAPI Mass Process Open for Enumeration"
    logsource: windows-security
    condition_summary: "EventID 4656 or 4663 with access mask including PROCESS_QUERY_INFORMATION from a single caller process targeting more than 50 distinct PID handles within 30 seconds"
```

### Operational Chains

```yaml
chains:
  - name: "Remote Target Recon to Injection"
    description: "Enumerate processes on a remote target and select an injection victim"
    steps:
      - technique: T-023
        role: "WTSEnumerateProcessesEx against WTSOpenServerEx(handle) produces a list of remote PIDs and process names"
      - technique: T-007
        role: "NtOpenProcess on the selected remote PID, then dispatch injection (e.g., Pool Party, Early Cascade)"
    notes: "SEC670 specifies WTSEnumerateProcessesEx is the only one of the three enumeration APIs that natively supports remote targets; EnumProcesses and NtQuerySystemInformation are local-only. Remote injection requires the caller to hold credentials valid on the remote host."

  - name: "Registry Recon to Persistence Placement"
    description: "Survey registry persistence opportunities and place a foothold"
    steps:
      - technique: T-023
        role: "Enumerate HKLM\\SOFTWARE and HKCU\\SOFTWARE for installed COM objects, autostart keys, and AppInit_DLLs entries"
      - technique: T-017
        role: "Place COM-hijack or NTFS-EA persistence in a registry location surfaced by the recon"
    notes: "Material emphasizes that HKCU and HKLM are the operational persistence roots; HKCR is a merged view of HKLM\\Software\\Classes and HKCU\\Software\\Classes and is not directly writable for hijack purposes."

  - name: "Service ACL Recon to Service Persistence"
    description: "Identify a weakly-permissioned service and repurpose it for persistence"
    steps:
      - technique: T-023
        role: "sc.exe sdshow enumerates service security descriptors to find services writable by the implant's principal"
      - technique: T-017
        role: "Modify the service binary path or trigger conditions to point at the implant payload"
    notes: "The operational value of SDDL parsing is locating services whose DACL grants SERVICE_CHANGE_CONFIG or write-to-binary-path permissions to non-admin principals; the binary-path change blends into legitimate service-management activity."

  - name: "Local Process Recon to Indirect-Syscall Injection"
    description: "Enumerate processes via Nt* syscall and inject without touching userland hooks"
    steps:
      - technique: T-004
        role: "PEB walker resolves ntdll and locates the NtQuerySystemInformation SSN"
      - technique: T-001
        role: "RecycledGate dispatches NtQuerySystemInformation(SystemProcessInformation) to enumerate processes without userland hook interception"
      - technique: T-007
        role: "Inject into the selected process via indirect-syscall NT calls"
    notes: "Material frames NtQuerySystemInformation as the 'undocumented' enumeration option; combined with indirect-syscall dispatch it produces a process list without any of the three Win32 hookable API surfaces (PSAPI, WTSAPI32, Kernel32)."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "recon-enumeration-api-surface"
    title: "Recon Enumeration API Surface as a Standalone Technique"
    kind: proposed-technique
    description: "SEC670 dedicates an entire module to enumerating targets across four domains (network adapters, registry, processes, services) using specific Win32/NT/WTS APIs with operational trade-offs (snapshot lag, hookability, remote-vs-local). T-023 covers 'recon' at a coarse granularity but does not document the API-surface decisions an operator makes when assembling recon tradecraft. A dedicated recon-enumeration card documenting the three process-enumeration APIs, the network-adapter API ladder (GetAdapterAddresses > GetNumberOfInterfaces > GetIpStatistics), the SYSTEM_INFO fields an implant relies on, and the SDDL inspection flow would give the vault operator-grade coverage of pre-injection target selection."
    would_relate_to: [T-023, T-007, T-017]
    source_units: ["unit 1", "unit 2", "unit 5", "unit 12", "unit 13", "unit 16", "unit 17"]
    tags: [recon, enumeration, api-surface, proposed-card]

  - id: "ntquerysysteminformation-recon-via-syscall"
    title: "NtQuerySystemInformation Recon via Indirect Syscall"
    kind: cross-source-convergence
    description: "SEC670 surfaces NtQuerySystemInformation(SystemProcessInformation) as the 'undocumented' option for process enumeration that avoids userland hooks. The vault's syscall-dispatch techniques (T-001 RecycledGate, T-002 Hell's Gate family, T-003 VEH Gate) are framed around NT calls that perform writes, allocations, and protects. The vault does not currently document which recon-class Nt* calls are operationally dispatched via indirect syscall in the same implant that performs injection via indirect syscall. Cross-cutting metadata linking the syscall-dispatch cards to recon NT calls (NtQuerySystemInformation, NtQueryInformationProcess, NtOpenProcess) would clarify this."
    would_relate_to: [T-001, T-002, T-003, T-004, T-023]
    source_units: ["unit 12", "unit 13", "unit 14"]
    tags: [nt-api, recon, indirect-syscall, cross-source]

  - id: "weak-service-acl-persistence"
    title: "Weak Service ACL Persistence Coverage Gap"
    kind: coverage-gap
    description: "The persistence suite (T-017) documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist layers but does not appear to cover service-binary-replacement or service-config-change persistence via weak service ACLs. SEC670 treats sc.exe sdshow as a primary recon primitive for surfacing weak service permissions. Operators running T-017 in environments where COM hijack is monitored but legacy weak-ACL services are present would benefit from a documented service-based persistence layer in the suite."
    would_relate_to: [T-017]
    source_units: ["unit 17"]
    tags: [persistence, services, sddl, coverage-gap]
```