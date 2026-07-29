## Synthesis Summary

This batch maps primarily to T-023 (Client Capabilities — recon, sysinfo, network recon via byakugan.rs and sysinfo_collect.rs) and secondarily to T-020 (Anti-Analysis Suite — anti-VM checks consume the same enumeration primitives) and T-016 (EDR Evasion Suite — recon identifies which defenses are present). The SANS SEC670 material surveys Windows recon tradecraft: process enumeration via WTSEnumerateProcessesEx, EnumProcesses, NtQuerySystemInformation, and CreateToolhelp32Snapshot; installed-software discovery through C:\Program Files and C:\Program Files (x86) directory walks; user/group enumeration via the lmaccess.h NetAPI family (NetGroupGetUsers, NetLocalGroupGetMembers, NetUseEnum); Windows service and task enumeration through SCM; NIC/network enumeration via the IP Helper API family (GetIpStatistics, GetAdaptersAddresses, GetInterfaceInfo, GetNumberOfInterfaces); and the Windows Registry as a survey trove. The gap this fills is the API surface and operational rationale for recon primitives the vault's T-023 invokes but does not document at the API level — the vault's recon files call these APIs, while the SEC670 material explains why each one matters operationally (target-purpose inference, AV/EDR detection, research-VM identification) and how each is detected. All 40 units are on-theme for offensive Windows tradecraft; none were skipped.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: T-023
    target: T-020
    type: enables
    rationale: "SEC670 frames process enumeration, installed-software directory walks, and service enumeration as the foundation for VM/research-environment identification — the same primitives the vault's T-020 anti-VM checks rely on."
  - source: T-023
    target: T-016
    type: enables
    rationale: "Service and process enumeration surfaces AV/EDR product presence; SEC670 explicitly cites 'Detect services that could be vulnerable or ones that could belong to AV/EDR' as a primary recon purpose, which feeds evasion selection in T-016."
  - source: T-023
    target: T-013
    type: enables
    rationale: "Process enumeration identifies candidate target processes for the injection methods catalogued in T-013; SEC670 presents enumeration as the prerequisite for selecting an injection host."
  - source: "program-files-directory-survey"
    target: T-020
    type: concept_link
    rationale: "SEC670 states that seeing VMware, Process Hacker, and Notepad++ in C:\\Program Files indicates a research environment — the Program Files walk is the operational primitive behind T-020's research-VM detection."
  - source: "ip-helper-api-family"
    target: "wtsenumerate-processes-ex"
    type: concept_link
    rationale: "SEC670 presents the IP Helper family and the WTS enumeration family as parallel Win32 API surfaces for surveying distinct target attributes (network vs. processes)."
  - source: "pe-sieve-and-huntress"
    target: T-007
    type: detects
    rationale: "PE-sieve scans process memory for unbacked/private executable regions — the heuristic the vault's T-007 module stomping, module overloading, and section-mapping injection methods are designed to evade."
  - source: "pe-sieve-and-huntress"
    target: T-013
    type: detects
    rationale: "PE-sieve flags VadS private executable memory with no on-disk module backing — exactly what several T-013 injection methods (raw shellcode mapping, callback execution, fiber execution) produce when used without VAD-aware hardening."
  - source: T-023
    target: T-015
    type: enhances
    rationale: "Process enumeration output identifies the candidate parent process whose PID will be spoofed via T-015 PPID spoofing — enumeration precedes and informs spoofing target selection."
  - source: "registry-survey-trove"
    target: T-017
    type: concept_link
    rationale: "SEC670 presents the registry as the survey source for installed software and autoruns; T-017 persistence techniques write to many of the same autorun/COM registry locations the survey reads."
```

### Concept Nodes

```yaml
concepts:
  - id: "wtsenumerate-processes-ex"
    name: "WTSEnumerateProcessesEx API"
    category: os-internal
    description: "WTSEnumerateProcessesEx (wtsapi32.h) enumerates processes locally or remotely via Windows Terminal Services. The WTS_PROCESS_INFO_EXA structure returns NumberOfThreads, HandleCount, PagefileUsage, PeakPagefileUsage, WorkingSetSize, PeakWorkingSetSize, UserTime, and KernelTime per process. Remote queries require specific registry keys on the target to permit remote WTS queries and the API returns detailed per-process telemetry beyond what EnumProcesses provides."
    relevant_to: [T-023, T-020]
    tags: [recon, process-enum, wts, remote, windows-internals]

  - id: "nt-query-system-information-process-enum"
    name: "NtQuerySystemInformation for Process Enumeration"
    category: os-internal
    description: "NtQuerySystemInformation with the SystemProcessInformation information class enumerates running processes by walking the kernel's EPROCESS list from user mode. SEC670 lists this alongside EnumProcesses and WTSEnumerateProcessesEx as a process-enumeration API. Because it lives in ntdll and queries the kernel directly, calls are observable to EDRs that hook ntdll or subscribe to kernel ETW providers."
    relevant_to: [T-023]
    tags: [recon, process-enum, ntdll, etw-observable, windows-internals]

  - id: "ip-helper-api-family"
    name: "IP Helper API Family for NIC Enumeration"
    category: windows-structure
    description: "The IP Helper header (iphlpapi.h) exposes a family of APIs for enumerating network interfaces. GetIpStatistics returns MIB_IPSTATS for the IP stack. GetAdaptersAddresses returns adapter addresses across address families and is the API SEC670 identifies as returning a network adapter's IP address. GetInterfaceInfo returns IPv4-enabled adapters in an IP_INTERFACE_INFO structure with ERROR_INSUFFICIENT_BUFFER as the buffer-sizing sentinel. GetNumberOfInterfaces returns a quick interface count that includes logical interfaces and the loopback adapter, unlike GetAdaptersInfo and GetInterfaceInfo."
    relevant_to: [T-023]
    tags: [recon, network-enum, iphlpapi, nic, windows-internals]

  - id: "netapi-user-group-enum"
    name: "lmaccess.h NetAPI for User and Group Enumeration"
    category: os-internal
    description: "The lmaccess.h and lmuse.h headers expose NetGroupGetUsers, NetUseEnum, NetLocalGroupGetMembers, and NetUseGetInfo for enumerating user accounts, group memberships, and network resource use from a local or remote target. SEC670 presents these as the Win32 survey APIs that complement the standard local user-enumeration paths."
    relevant_to: [T-023]
    tags: [recon, user-enum, netapi, lmaccess, windows-internals]

  - id: "program-files-directory-survey"
    name: "C:\\Program Files and C:\\Program Files (x86) Directory Survey"
    category: attack-pattern
    description: "Enumerating the contents of C:\\Program Files (64-bit applications) and C:\\Program Files (x86) (32-bit applications) yields an inventory of installed applications. SEC670 frames the count and identity of installed applications as the operational primitive for inferring target purpose and detecting research environments — specifically naming VMware, Process Hacker, and Notepad++ as research-VM indicators."
    relevant_to: [T-023, T-020]
    tags: [recon, installed-software, anti-vm, directory-walk, attack-pattern]

  - id: "ntfs-directory-entries"
    name: "NTFS Directory Entry Structure"
    category: windows-structure
    description: "NTFS tracks directories and child directories in a directory tree where each directory holds a table of file-name entries. CreateDirectory, CreateDirectoryEx, and CreateDirectoryTransacted are the documented NT API entry points for directory creation. NTFS supports hard links against entries in these tables, which underpins the ADS-rename self-deletion technique used in T-020."
    relevant_to: [T-020, T-023]
    tags: [ntfs, directory, hard-links, windows-internals]

  - id: "windows-services-vs-processes"
    name: "Windows Services vs Processes Distinction"
    category: os-internal
    description: "SEC670 distinguishes Windows services from processes: a service is a process that has a registered entry with the Service Control Manager, started by services.exe, enumerable via SCM APIs. Enumerating services separately from processes surfaces server-role indicators (DHCP, DNS) and AV/EDR service footprint that process enumeration alone may not make obvious, and is the basis for identifying persistence candidates and security products."
    relevant_to: [T-023, T-020]
    tags: [recon, services, scm, windows-internals]

  - id: "registry-survey-trove"
    name: "Windows Registry as Survey Trove"
    category: attack-pattern
    description: "SEC670 presents the Windows Registry as a survey trove including installed software (HKLM\\SOFTWARE), service configuration (HKLM\\SYSTEM\\CurrentControlSet\\Services), and autorun locations. Much of the data is accessible to basic users without administrative privileges; only specific hives or keys require elevated access. The same registry locations are read by survey tools and written by persistence techniques."
    relevant_to: [T-023, T-017]
    tags: [recon, registry, survey, attack-pattern]

  - id: "pe-sieve-and-huntress"
    name: "PE-sieve and Huntress Labs Memory Scanners"
    category: edr-mechanism
    description: "SEC670 cites Huntress Labs (commercial, profit-driven) and PE-sieve (community-driven) as current state-of-the-art scanning tools. PE-sieve specifically walks process memory and VAD entries to flag injected, replaced, or unbacked executable regions — the heuristic the vault's VAD-aware injection methods (module stomping, module overloading, section mapping with backing) are designed to evade."
    relevant_to: [T-007, T-013, T-016]
    tags: [edr, memory-scan, pe-sieve, huntress, detection]

  - id: "sysinternals-procmon"
    name: "Process Monitor (ProcMon) for Behavior Observation"
    category: defense-mechanism
    description: "ProcMon from the Sysinternals Suite monitors process behavior at startup and during OS boot, capturing file, registry, network, and process/thread activity. SEC670 presents ProcMon as the primary tool for spotting program flaws during process startup — used by defenders to analyze implant behavior and by operators to identify behavioral footprints of their own tools."
    relevant_to: [T-020, T-023]
    tags: [defense-mechanism, sysinternals, procmon, behavioral-analysis]
```

### Detection Insights

```yaml
detection:
  - indicator: "Remote WTSEnumerateProcessesEx invocation against a target host"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "Remote WTS enumeration requires specific registry keys on the target and produces network logon events (4624 with LogonType 3) and explicit-credential logon events (4648) when alternate credentials are used. The 4624/4648 pattern combined with the WTS service being queried remotely is a recon indicator."
    bypassed_by: "not discussed"

  - indicator: "NtQuerySystemInformation call with SystemProcessInformation class from a non-system process"
    source: etw
    confidence: medium
    relevant_to: [T-023]
    description: "EDRs that hook ntdll or subscribe to ETW providers observe NtQuerySystemInformation invocations with the SystemProcessInformation information class. Calls from a non-system, non-svchost process to enumerate all running processes are a recon signature."
    bypassed_by: "not discussed"

  - indicator: "Directory walk of C:\\Program Files and C:\\Program Files (x86) via cmd.exe or PowerShell"
    source: sysmon
    confidence: high
    relevant_to: [T-023, T-020]
    description: "Sysmon EID 1 (ProcessCreate) captures cmd.exe or powershell.exe spawning with arguments containing 'C:\\Program Files' or 'C:\\Program Files (x86)'. Tools that enumerate the directories directly via FindFirstFileW/FindNextFileW produce Sysmon EID 11 (FileCreate) or file-access telemetry depending on configuration."
    bypassed_by: "not discussed"

  - indicator: "OpenSCManager with SC_MANAGER_ENUMERATE_SERVICE followed by EnumServicesStatus"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "Service enumeration via OpenSCManager + EnumServicesStatus produces 4624 (network logon if remote), 7045 (service install), and 7036 (service state change) event correlations. Local enumeration by a non-services.exe process is a recon signature."
    bypassed_by: "not discussed"

  - indicator: "Unbacked private executable memory (VadS node with execute permissions)"
    source: memory-scan
    confidence: high
    relevant_to: [T-007, T-013]
    description: "PE-sieve walks process VAD entries and flags VadS (MEM_PRIVATE) regions with execute permissions that have no on-disk module backing — the 'unbacked executable' heuristic. Detects raw shellcode mapping, callback execution, and fiber execution that leave payload as private RWX/RX."
    bypassed_by: "Mapping shellcode as a section with a backing file path (MEM_IMAGE) produces a non-VadS VAD node; module stomping and module overloading reuse a legitimate module's on-disk backing, evading PE-sieve's unbacked-memory heuristic."

  - indicator: "GetAdaptersAddresses or GetInterfaceInfo call patterns from non-networking processes"
    source: behavioral
    confidence: low
    relevant_to: [T-023]
    description: "IP Helper API calls from processes without a network-service lineage (e.g., a Word macro spawning an implant) are a low-confidence recon signal. Most EDRs do not alert on these calls directly; they appear in behavioral analytics correlating recon API usage with process lineage."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Program Files Directory Enumeration via cmd.exe"
    logsource: sysmon
    condition_summary: "Sysmon EID 1 where Image in (cmd.exe, powershell.exe) and CommandLine contains 'Program Files' or 'Program Files (x86)'"
  - title: "Remote WTS Process Enumeration"
    logsource: windows-security
    condition_summary: "EID 4624 LogonType 3 from a source host followed by EID 4648 within 5 minutes, where the target account is used to query the TermService endpoint"
  - title: "Service Enumeration by Non-Services Process"
    logsource: windows-security
    condition_summary: "EID 7036/7045 burst within 60 seconds originating from a process that is not services.exe or svchost.exe hosting the Service Control Manager"
  - title: "Unbacked Private Executable Memory via PE-sieve"
    logsource: memory-scan
    condition_summary: "PE-sieve output contains a VadS region with PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ and no matching module in the PEB Ldr list"
```

### Operational Chains

```yaml
chains:
  - name: "Recon-Driven Evasion Selection"
    description: "Enumerate target defenses before selecting an evasion technique"
    steps:
      - technique: "process enumeration (WTSEnumerateProcessesEx)"
        role: "Identify running AV/EDR processes and candidate injection target processes"
      - technique: "service enumeration (OpenSCManager + EnumServicesStatus)"
        role: "Identify AV/EDR services that may not appear in process list; infer system role (DHCP/DNS)"
      - technique: "directory walk of C:\\Program Files and C:\\Program Files (x86)"
        role: "Identify research-VM indicators (VMware, Process Hacker, Notepad++) and installed security tooling"
      - technique: T-016
        role: "Select appropriate EDR evasion technique (AMSI patch, ETW muffling, stack spoofing, etc.) based on observed defenses"
    notes: "SEC670 explicitly frames recon output as the driver of evasion selection; the material cites detecting AV/EDR services and research-VM software as the purpose of survey."

  - name: "Implant Survey Pipeline"
    description: "Standard ordered survey sequence after first execution"
    steps:
      - technique: "OS info and hotfix enumeration"
        role: "Determine Windows version, build, and patch level for exploit/evasion compatibility"
      - technique: "process enumeration"
        role: "Identify processes for injection and AV/EDR presence"
      - technique: "installed software walk"
        role: "Identify target purpose and research-env indicators"
      - technique: "user and group enumeration (NetGroupGetUsers, NetLocalGroupGetMembers)"
        role: "Identify high-value accounts and group memberships for lateral movement"
      - technique: "services and tasks enumeration"
        role: "Identify persistence candidates and AV/EDR service footprint"
      - technique: "network and NIC enumeration (IP Helper API)"
        role: "Map interfaces, addresses, and routes for lateral movement"
      - technique: "registry enumeration"
        role: "Collect installed-software, autorun, and configuration data"
    notes: "SEC670's course roadmap (units 14, 16, 25, 39) presents this exact ordered sequence as the 'Getting to Know Your Target' section of the Windows Tool Development module. The vault's T-023 recon/sysinfo capabilities execute steps from this pipeline."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "proposed-recon-survey-card"
    title: "Dedicated Recon & Survey Technique Card"
    kind: proposed-technique
    description: "SEC670 dedicates an entire course section to Windows survey APIs: process enumeration (WTSEnumerateProcessesEx, NtQuerySystemInformation, CreateToolhelp32Snapshot), installed-software discovery via Program Files directory walks, user/group enumeration (lmaccess.h NetAPI family), services/tasks enumeration via SCM, NIC/network enumeration via the IP Helper family, and registry survey. The vault's T-023 captures recon as a client capability but does not document the API catalog at the depth SEC670 demonstrates. A dedicated card would document the Win32 API surface, the per-API detection signature, and the recon-to-evasion decision flow."
    would_relate_to: [T-023, T-020, T-016]
    source_units: ["unit 1", "unit 4", "unit 8", "unit 15", "unit 20", "unit 27", "unit 40"]
    tags: [recon, survey, api-catalog, coverage-expansion]

  - id: "gap-anti-vm-detection-primitives"
    title: "Anti-VM Detection Primitives Coverage Gap"
    kind: coverage-gap
    description: "The vault's T-020 lists 10 anti-VM checks but does not document the recon API primitives that power them. SEC670 shows that the same APIs used for survey (Program Files directory walk, WTSEnumerateProcessesEx, NIC enumeration via IP Helper) also enable research-environment identification. Documenting these primitives at the API level would explain how T-020's anti-VM checks obtain the data they test against."
    would_relate_to: [T-020, T-023]
    source_units: ["unit 8", "unit 9", "unit 10", "unit 27"]
    tags: [anti-vm, recon-primitives, coverage-gap]

  - id: "convergence-pe-sieve-vs-vault-injection"
    title: "PE-sieve Heuristics vs Vault Injection Methods Cross-Reference"
    kind: cross-source-convergence
    description: "SEC670 cites PE-sieve and Huntress Labs as state-of-the-art memory scanners; the vault documents multiple injection methods (T-007 module stomping, module overloading, section mapping; T-008 Threadless; T-011 Dirty Vanity; T-013 mapping injection) that specifically aim to evade the unbacked-executable heuristic PE-sieve applies. The convergence between SEC670's defender-side scanner presentation and the vault's attacker-side injection coverage deserves explicit cross-referencing in the graph."
    would_relate_to: [T-007, T-008, T-011, T-013, T-016]
    source_units: ["unit 11"]
    tags: [pe-sieve, memory-scan, injection-evasion, cross-source, convergence]
```