## Synthesis Summary

This batch maps primarily to **T-023 (Client Capabilities)** for host recon/sysinfo gathering and tangentially to **T-016 (Kaguya LOtL)** for its EDR/AV detection inventory logic and **T-020 (Anti-Analysis Suite)** for environment fingerprinting. The material is drawn entirely from SANS SEC670 "Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control" Book 2 (Getting to Know Your Target) plus Book 4 excerpts on WMI persistence. It covers process enumeration via four distinct API families (CreateToolhelp32Snapshot, WTSEnumerateProcessesEx, EnumProcesses, NtQuerySystemInformation), OS version identification via GetNativeSystemInfo and the SYSTEM_INFO struct, directory walking via FindFirstFile/FindNextFile, installed-software discovery via C:\Program Files and C:\Program Files (x86), user enumeration via `net user`/`net localgroup`, and WMI/CIM schema enumeration via Win32_Process/Win32_Service/Win32_Registry classes. The gap filled is operational tradecraft: when to prefer snapshot enumeration versus WTS, why NtQuerySystemInformation is "stealthier" but riskier, why Program Files inventory matters for environment classification (e.g., detecting research VMs by spotting Notepad++/Process Hacker/VMware), and how the SYSTEM_INFO wProcessorArchitecture field disambiguates WoW64 from native x64 — none of which the source code alone conveys. No units were skipped as off-theme; all 40 fit the offensive-Windows tradecraft space.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "ntquerysysteminformation-enum"
    target: T-023
    type: enables
    rationale: "SEC670 frames NtQuerySystemInformation as a stealthier process enumeration alternative to the Win32 API surface (CreateToolhelp32Snapshot, EnumProcesses) used in the implant's recon module, because it avoids documented Win32 wrappers and returns SystemProcessInformation directly from the kernel."

  - source: "wts-enumerate-processes"
    target: "ntquerysysteminformation-enum"
    type: alternative_to
    rationale: "SEC670 presents WTSEnumerateProcessesEx and NtQuerySystemInformation as two distinct enumeration paths; WTS adds the unique capability of remote-target enumeration while NtQuerySystemInformation is local-only but lower-overhead and undocumented."

  - source: "createtoolhelp-snapshot"
    target: "ntquerysysteminformation-enum"
    type: alternative_to
    rationale: "SEC670 enumerates three lab options (ProcEnum via CreateToolhelp32Snapshot, NtQuerySystemInformation, WTSEnumerateProcessesEx) as interchangeable enumeration techniques with different detection and capability tradeoffs."

  - source: "system-info-architecture"
    target: T-023
    type: enables
    rationale: "GetNativeSystemInfo and the SYSTEM_INFO struct (wProcessorArchitecture, dwNumberOfProcessors) feed the implant's sysinfo capability; SEC670 emphasizes that WoW64 vs native x64 distinction drives payload selection."

  - source: "wmi-win32-provider-classes"
    target: T-023
    type: enables
    rationale: "Win32_Process, Win32_Service, Win32_Registry, Win32_OperatingSystem classes enumerated by SEC670 supply the same inventory data the implant recon module produces, via an alternate WMI/DCOM channel."

  - source: "directory-walk-findfirstfile"
    target: T-020
    type: concept_link
    rationale: "FindFirstFile/FindNextFile directory walks feed both installed-software inventory (recon, T-023) and anti-VM environment fingerprinting (T-020), per SEC670 framing of C:\\Program Files inspection for research-VM indicators like Process Hacker and VMware."

  - source: T-023
    target: "wmi-win32-provider-classes"
    type: concept_link
    rationale: "SEC670 introduces WMI queries in the persistence book but the same Win32_Process/Win32_Service enumeration classes are dual-use for recon; the implant's recon subsystem could leverage WMI as an alternate inventory channel."

  - source: "ntfs-directory-entries"
    target: "directory-walk-findfirstfile"
    type: requires
    rationale: "SEC670 explains NTFS directory tables (which hold entries with file names) before covering FindFirstFile/FindNextFile traversal; the directory walk depends on the NTFS directory entry structure."

  - source: T-016
    target: "wmi-win32-provider-classes"
    type: enhances
    rationale: "Kaguya's LOtL binary inventory and EDR detection logic (T-016) is enhanced by WMI enumeration of Win32_Service and Win32_Process; SEC670 shows WMI as a non-binary-inventory path to the same operational data."
```

### Concept Nodes

```yaml
concepts:
  - id: "ntquerysysteminformation-enum"
    name: "NtQuerySystemInformation with SystemProcessInformation"
    category: os-internal
    description: "NtQuerySystemInformation is a native (NT) API invoked with the SystemProcessInformation information class to enumerate processes from kernel EPROCESS structures directly, bypassing the Win32 Process Status API (EnumProcesses) and Toolhelp32 wrappers. SEC670 flags it as riskier but stealthier than documented Win32 alternatives because the SYSTEM_INFORMATION_CLASS enum is officially undocumented and subject to change between Windows releases, yet it returns detail the documented APIs do not expose."
    relevant_to: [T-023]
    tags: [nt-api, process-enum, recon, stealth, undocumented]

  - id: "system-information-class-enum"
    name: "SYSTEM_INFORMATION_CLASS Undocumented Enum"
    category: windows-structure
    description: "The SYSTEM_INFORMATION_CLASS enumeration determines what information NtQuerySystemInformation returns. Microsoft does not officially document the enum, but reverse engineers and researchers have reverse-documented it. SEC670 notes the enum drives multiple information classes beyond process enumeration and that values can shift across Windows versions, making hardcoded indices a reliability risk."
    relevant_to: [T-023]
    tags: [nt-api, undocumented, enum, recon]

  - id: "createtoolhelp-snapshot"
    name: "CreateToolhelp32Snapshot Process Enumeration"
    category: attack-pattern
    description: "CreateToolhelp32Snapshot captures a snapshot of process/thread/module/heap state at a single moment and is enumerated via Process32First/Process32Next. SEC670 identifies its major downside as missing newly created processes after the snapshot is taken, making it unsuitable for real-time injection-target selection against an active system."
    relevant_to: [T-023, T-007]
    tags: [process-enum, win32, snapshot, recon]

  - id: "wts-enumerate-processes"
    name: "WTSEnumerateProcessesEx Remote Enumeration"
    category: attack-pattern
    description: "WTSEnumerateProcessesEx from wtsapi32.h enumerates processes via Windows Terminal Services and returns WTS_PROCESS_INFO_EX with fields beyond PID/Name: NumberOfThreads, HandleCount, PagefileUsage, WorkingSetSize, UserTime, KernelTime. Unique among enumeration APIs, it supports remote targets when appropriate registry keys permit the query. SEC670 requires the caller to free returned memory with WTSFreeMemory."
    relevant_to: [T-023]
    tags: [process-enum, wts, remote, lateral-movement, recon]

  - id: "system-info-architecture"
    name: "GetNativeSystemInfo and SYSTEM_INFO struct"
    category: windows-structure
    description: "GetNativeSystemInfo fills a SYSTEM_INFO struct with dwPageSize, lpMinimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask, dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity, wProcessorLevel, and wProcessorRevision. SEC670 highlights wProcessorArchitecture as the field that distinguishes native x64 from WoW64, which matters for selecting payload architecture and avoiding Wow64 redirection surprises."
    relevant_to: [T-023, T-020]
    tags: [os-info, architecture, wow64, payload-selection]

  - id: "windows-version-mapping"
    name: "Windows Version Number Mapping"
    category: os-internal
    description: "Windows releases report internal version numbers via OS query APIs rather than marketing names: Windows XP=5.1, Server 2003=5.2, Vista/Server 2008=6.0, Windows 7/Server 2008 R2=6.1, Windows 8/Server 2012=6.2, Windows 8.1/Server 2012 R2=6.3, Windows 10/Server 2016=10. SEC670 provides this table as a reference for translating the numeric query response into a release name for payload compatibility decisions."
    relevant_to: [T-023]
    tags: [os-info, version-mapping, payload-compat]

  - id: "ntfs-directory-entries"
    name: "NTFS Directory Entry Table"
    category: windows-structure
    description: "NTFS represents each directory as a table holding entries with file names of contained files. Directories are created via CreateDirectory, CreateDirectoryEx, or CreateDirectoryTransacted, support hard links, and form a tree structure rooted at the system root. SEC670 introduces this structure as the foundation for directory-walking recon techniques."
    relevant_to: [T-023]
    tags: [ntfs, filesystem, directory-walk, recon]

  - id: "directory-walk-findfirstfile"
    name: "FindFirstFile / FindNextFile Directory Walk"
    category: attack-pattern
    description: "FindFirstFile and FindNextFile are the three core APIs (with FindClose) for recursively walking a directory tree from the system root to locate files. SEC670 notes a recursive walk can take significant time but yields information on installed applications, user artifacts, and environment indicators. The walking pattern is foundational to FileFinder-style recon tools."
    relevant_to: [T-023, T-020]
    tags: [filesystem, recon, directory-walk, win32]

  - id: "program-files-inventory"
    name: "C:\\Program Files / C:\\Program Files (x86) Inventory"
    category: attack-pattern
    description: "Inventorying C:\\Program Files (64-bit apps) and C:\\Program Files (x86) (32-bit apps) reveals installed applications and supports environment-purpose inference. SEC670 identifies Notepad++, Process Hacker, and VMware directory entries as research-VM indicators that should change or terminate an operation. The C:\\ root directory is also surveyed for user home folders, Python installations, and other context."
    relevant_to: [T-020, T-023]
    tags: [anti-vm, environment-fingerprint, recon, filesystem]

  - id: "wmi-cim-schema"
    name: "WMI CIM and Win32 Schemas"
    category: os-internal
    description: "WMI classes are grouped into schemas: the CIM Schema contains classes prefixed CIM_ providing Core/Common definitions, and the Win32 Schema contains classes prefixed Win32_ that extend CIM classes for the Win32 environment. Developers can author custom classes in either schema. SEC670 establishes this taxonomy before covering WMI persistence and recon via Win32_ classes."
    relevant_to: [T-017, T-023]
    tags: [wmi, cim, schema, classes]

  - id: "wmi-win32-provider-classes"
    name: "Win32 Provider Classes for Recon"
    category: attack-pattern
    description: "The Win32 Provider exposes Win32_Account (user/group accounts), Win32_LoggedOnUser (session accounts), Win32_OperatingSystem (installed OS), Win32_Process (processes), Win32_Registry (system registry), Win32_Service (services), and Win32_Thread (executing threads). SEC670 documents these as a WMI-based inventory channel equivalent in data to Toolhelp32/WTS enumeration, queryable via WQL with filters."
    relevant_to: [T-023, T-017]
    tags: [wmi, win32-provider, recon, inventory]

  - id: "net-user-enumeration"
    name: "net user / net localgroup User Recon"
    category: attack-pattern
    description: "Command-line utilities `net user` and `net localgroup` enumerate local accounts and group membership. SEC670 highlights identifying members of the Administrators group and detecting a logged-on Domain Admin as high-value recon outcomes feeding privilege escalation and lateral movement decisions. Programmatic alternatives to the net command exist for implants that avoid spawning processes."
    relevant_to: [T-023]
    tags: [user-enum, command-line, recon, privilege-escalation]

  - id: "named-pipe-network-capable"
    name: "Named Pipe Network Capability"
    category: os-internal
    description: "Among Windows pipe types (half pipe, named pipe, anonymous pipe), only named pipes can operate over a network. SEC670 establishes this distinction as foundational for implant C2 and lateral movement over SMB. Anonymous pipes are process-local only and cannot support remote IPC."
    relevant_to: [T-022]
    tags: [pipes, ipc, smb, lateral-movement]

  - id: "sc-security-descriptor"
    name: "sc.exe Security Descriptor Viewing"
    category: os-internal
    description: "sc.exe is the command-line utility that exposes an object's security descriptor for inspection, used in SEC670 review questions to distinguish security-descriptor viewing from cmd.exe and tasklist.exe. Security descriptors define which accounts can manipulate services and are core to service-based persistence and privilege-escalation tradecraft."
    relevant_to: [T-017]
    tags: [security-descriptor, services, acl, recon]
```

### Detection Insights

```yaml
detection:
  - indicator: "NtQuerySystemInformation call with SystemProcessInformation"
    source: behavioral
    confidence: medium
    relevant_to: [T-023]
    description: "SEC670 characterizes NtQuerySystemInformation as 'stealthier' than Win32 enumeration wrappers but does not identify a specific ETW provider or Sysmon event that fires on it. From a behavioral standpoint, an implant invoking the native NtQuerySystemInformation instead of the documented EnumProcesses or CreateToolhelp32Snapshot API is anomalous for legitimate user-mode software and can be flagged by API-call telemetry that keys on syscall-name rather than Win32 layer."
    bypassed_by: "not discussed"

  - indicator: "WTSEnumerateProcessesEx remote enumeration"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "SEC670 notes that WTSEnumerateProcessesEx can query remote targets when appropriate registry keys permit it. Remote WTS enumeration produces logon-like network activity observable in Windows Security Log event 4624 (logon type 3, network) and 4648 (explicit credential use) if alternate credentials are supplied, plus SMB connection events. The registry keys enabling remote WTS queries are a hardening target."
    bypassed_by: "not discussed"

  - indicator: "Get-WmiObject WQL query against Win32_Process"
    source: etw
    confidence: high
    relevant_to: [T-023, T-017]
    description: "SEC670 demonstrates WMI query testing via PowerShell Get-WmiObject with WQL filters like \"select * from Win32_Process where name='notepad.exe'\" and \"select * from win32_ntlogevent where eventcode=4625 and logfile='security' and message like %alice%\". These queries are logged by the Microsoft-Windows-WMI-Activity/Operational ETW provider and Sysmon Event ID 20 (WmiEventConsumer), 21 (WmiFilterToConsumerBinding), and 19 (WmiFilter). Suspicious WQL filters against Win32_Process, Win32_Service, and Win32_NTLogEvent are detection-eligible."
    bypassed_by: "not discussed"

  - indicator: "Recursive directory walk from system root"
    source: sysmon
    confidence: medium
    relevant_to: [T-023, T-020]
    description: "SEC670 acknowledges a recursive FindFirstFile/FindNextFile walk from the system root can take significant time and traverses many directories. Sysmon Event ID 1 (process creation) and Event ID 11 (FileCreate) combined with high-volume file access in a short window is the observable pattern. The walk pattern targeting C:\\Program Files, C:\\Program Files (x86), and user profile directories specifically is fingerprintable."
    bypassed_by: "not discussed"

  - indicator: "Research-VM directory artifact inventory"
    source: behavioral
    confidence: low
    relevant_to: [T-020]
    description: "SEC670 identifies Notepad++, Process Hacker, and VMware directory entries in C:\\Program Files as research-environment indicators the operator should detect. Defenders can invert this heuristic: a system running these tools is more likely a research/analysis environment, and unexpected process or filesystem enumeration originating from such a host is detection-eligible as analysis-tooling misuse."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Remote WTS Process Enumeration"
    logsource: windows-security
    condition_summary: "Windows Security Log Event 4624 Logon Type 3 from a non-system source account immediately followed by WTSEnumerateProcessesEx network activity on the target"

  - title: "Suspicious WMI Win32_NTLogEvent Security Log Query"
    logsource: etw
    condition_summary: "Microsoft-Windows-WMI-Activity/Operational event with WQL filter containing 'win32_ntlogevent' and 'logfile=security' indicating security log scraping via WMI"

  - title: "Recursive Filesystem Walk from System Root"
    logsource: sysmon
    condition_summary: "High rate of Sysmon Event 11 FileCreate or File_ACCESS events originating from a single process traversing C:\\, C:\\Program Files, C:\\Program Files (x86), and user profile directories within a short window"
```

### Operational Chains

```yaml
chains:
  - name: "Host Survey Recon Chain"
    description: "Sequential host survey that informs payload selection, privilege-escalation targeting, and persistence channel choice"
    steps:
      - technique: "system-info-architecture"
        role: "Gather OS version, service pack, kernel version (ntoskrnl.exe), and processor architecture via GetNativeSystemInfo to determine payload compatibility and WoW64 redirection behavior"
      - technique: "ntquerysysteminformation-enum"
        role: "Enumerate running processes via the stealthier NtQuerySystemInformation path to identify AV/EDR, injection candidates, and analyst tooling without invoking documented Win32 wrappers"
      - technique: "program-files-inventory"
        role: "Inventory C:\\Program Files and C:\\Program Files (x86) to detect installed applications, development software, and research-VM indicators (Notepad++, Process Hacker, VMware) that may abort the operation"
      - technique: "net-user-enumeration"
        role: "Enumerate local users and Administrators group membership; detect logged-on Domain Admin accounts for lateral-movement targeting"
      - technique: "wmi-win32-provider-classes"
        role: "Query Win32_Service and Win32_Registry via WMI for service-based persistence candidate identification and registry target enumeration"
      - technique: T-023
        role: "Aggregate findings into the implant's recon subsystem output to drive subsequent operational decisions"
    notes: "SEC670 establishes this as the implicit Section 2 roadmap (OS Info → Process Enumeration → Installed Software → Directory Walks → User Information → Services and Tasks → Network Information → Registry Information). The order matters: OS/architecture information gates payload selection, process enumeration gates EDR detection and injection targeting, and software inventory gates environment-fingerprint abort decisions."

  - name: "Remote Target Recon via WTS"
    description: "Remote process enumeration against a networked target via WTSEnumerateProcessesEx"
    steps:
      - technique: "system-info-architecture"
        role: "Confirm remote target architecture matches available payload before initiating remote enumeration"
      - technique: "wts-enumerate-processes"
        role: "Enumerate processes on the remote target via WTSEnumerateProcessesEx, leveraging the registry keys that permit remote WTS queries"
      - technique: T-023
        role: "Feed WTS_PROCESS_INFO_EX fields (NumberOfThreads, HandleCount, WorkingSetSize, UserTime, KernelTime) into the implant recon subsystem for target-side process profiling"
    notes: "SEC670 highlights remote enumeration as the unique capability of WTS versus the local-only NtQuerySystemInformation path. Requires the appropriate remote registry keys to be enabled on the target."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "proposed-host-survey-recon-card"
    title: "Host Survey Recon as a Standalone Technique Card"
    kind: proposed-technique
    description: "SEC670 devotes an entire book (Section 2) to host surveying: OS info, service packs, process enumeration across four API families, installed software directory walks, user enumeration, services and tasks, network info, and registry info. The vault folds recon into T-023 Client Capabilities as one capability among many, but the operational weight SEC670 places on survey-first tradecraft (gating payload selection, aborting on research-VM detection, targeting Domain Admins) suggests a dedicated T-NNN card for host-survey recon would surface tradecraft the vault currently under-documents."
    would_relate_to: [T-023, T-016, T-020]
    source_units: ["unit 1", "unit 2", "unit 3", "unit 8", "unit 11", "unit 21", "unit 35"]
    tags: [recon, host-survey, tradecraft, coverage-gap]

  - id: "coverage-gap-process-enumeration-variants"
    title: "Process Enumeration API Variant Tradecraft Coverage"
    kind: coverage-gap
    description: "SEC670 documents four distinct process-enumeration APIs (CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcessesEx, NtQuerySystemInformation) with explicit tradeoffs: snapshot staleness, remote capability, stealth, undocumented status. The vault references process enumeration tangentially under injection-target selection but does not document which enumeration path pairs with which injection technique. A cross-cutting reference mapping enumeration API to injection technique would close a tradecraft gap."
    would_relate_to: [T-007, T-012, T-013, T-023]
    source_units: ["unit 1", "unit 30", "unit 31", "unit 32", "unit 33", "unit 34"]
    tags: [process-enum, tradecraft, coverage-gap, api-selection]

  - id: "cross-source-wmi-recon-persistence-convergence"
    title: "WMI as Dual-Use Recon and Persistence Channel"
    kind: cross-source-convergence
    description: "SEC670 Book 4 (Persistence) and Book 2 (Recon) both cover WMI Win32_ classes — Book 4 for __EventFilter/__EventConsumer persistence binding and Book 2 for Win32_Process/Win32_Service enumeration. The dual-use nature of WMI as both recon channel and persistence substrate is a cross-cutting insight the vault splits across T-017 and T-023. A graph edge or concept tying WMI recon to WMI persistence would surface the operational coupling."
    would_relate_to: [T-017, T-023]
    source_units: ["unit 15", "unit 16", "unit 17", "unit 18"]
    tags: [wmi, recon, persistence, convergence]

  - id: "emerging-ntfs-directory-entry-tradecraft"
    title: "NTFS Directory Entry Table Tradecraft Beyond File Walks"
    kind: emerging-tradecraft
    description: "SEC670 introduces the NTFS directory entry table as the storage substrate behind directory walks but does not extend into NTFS-specific tradecraft (MFT parsing, USN journal, alternate data streams, NTFS EA). The vault has T-017 NTFS EA persistence but no card covering NTFS-low-level recon primitives (MFT enumeration, USN journal scraping, $I30 index parsing) that bypass the Win32 file API entirely and avoid the Sysmon Event 11 footprint. Flagged as emerging territory the vault should track."
    would_relate_to: [T-017, T-023, T-020]
    source_units: ["unit 7", "unit 9", "unit 10"]
    tags: [ntfs, mft, usn-journal, recon, evasion, emerging]
```