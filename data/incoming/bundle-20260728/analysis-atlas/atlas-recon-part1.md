## Synthesis Summary

The batch maps primarily to T-023 (Client Capabilities — recon, sysinfo) and secondarily to T-020 (Anti-Analysis Suite — Kaguya LOtL binary inventory + EDR detection) and T-022 (Network Suite — recon). The SANS SEC670 material covers Windows host survey tradecraft at the API level: documented and undocumented OS-info methods (`GetNativeSystemInfo`, `KUSER_SHARED_DATA`), hotfix/patch inventory via WMI `Win32_QuickFixEngineering` and the Windows Update Agent (WUA) COM APIs (`UpdateSession`/`UpdateSearcher`/`SearchResult`), process enumeration through `EnumProcesses`, `CreateToolhelp32Snapshot`, and `WTSEnumerateProcesses`, NIC enumeration through IP Helper (`GetIpStatistics`, `GetAdapterAddresses`), and registry root-key structure including HKCR's merged-view semantics. CRTO units 9 and 11 were skipped as off-theme (Linux Oracle DB query and Wireshark/pcap analysis, not Windows offensive tradecraft). The source code shows that `byakugan.rs` performs ARP/TCP/AD enumeration and `kaguya.rs` performs LOtL inventory + EDR detection, but reading the source alone does not explain why specific Windows APIs are chosen over alternatives, which methods are reliable across OS versions, how HKCR's merged view affects COM hijack persistence, or how patch-status awareness gates exploit selection — the training material supplies that operational reasoning.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: host-survey-script
    target: T-023
    type: enables
    rationale: "SEC670 frames the host survey as the foundation for operational decisions — querying OS version, installed software, processes, and AV/EDR presence to determine next actions such as privilege escalation paths."

  - source: kuser-shared-data
    target: T-023
    type: alternative_to
    rationale: "SEC670 presents KUSER_SHARED_DATA reads as an undocumented alternative to documented APIs like GetNativeSystemInfo for obtaining OS version and architecture, useful when avoiding API-call telemetry."

  - source: wmi-quickfix-engineering
    target: T-020
    type: concept_link
    rationale: "SEC670 shows Get-HotFix and wmic qfe list both query Win32_QuickFixEngineering — the same data source Kaguya-style LOtL inventory would walk to enumerate patch status without custom tooling."

  - source: wua-com-api
    target: wmi-quickfix-engineering
    type: alternative_to
    rationale: "SEC670 notes that WUA APIs (UpdateSession/UpdateSearcher) provide a programmatic alternative to WMI for enumerating installed and available updates, useful when WMI is monitored."

  - source: createtoolhelp32-snapshot
    target: T-023
    type: enables
    rationale: "SEC670 identifies CreateToolhelp32Snapshot as one of the most common malware APIs for process enumeration, returning detailed per-process information needed for injection target selection and AV/EDR identification."

  - source: hkcr-registry-root
    target: T-017
    type: concept_link
    rationale: "SEC670 explains HKCR is a virtual root merging HKCU\\SOFTWARE\\Classes and HKLM\\SOFTWARE\\Classes — the same merged view COM hijack persistence (T-017) manipulates by writing per-user class registrations that override HKLM entries."

  - source: patch-status-inventory
    target: T-020
    type: enhances
    rationale: "SEC670 emphasizes awareness of applied hotfixes before attempting exploits to avoid detection — Kaguya's LOtL inventory gains operational value when it surfaces missing patches that map to known CVEs."
```

### Concept Nodes

```yaml
concepts:
  - id: "kuser-shared-data"
    name: "KUSER_SHARED_DATA (Shared User Data Page)"
    category: "windows-structure"
    description: "A read-only page mapped at a fixed user-mode address (0x7FFE0000 on x86/x64) containing system information populated by the kernel at boot, including NT version, build number, processor features, and time fields. SEC670 presents direct reads of this page as an undocumented method for obtaining OS version/architecture information without invoking NtCurrentTec/GetVersionEx, avoiding the API-call telemetry those generate."
    relevant_to: [T-023, T-020]
    tags: [windows-internals, undocumented-api, os-info, recon, telemetry-evasion]

  - id: "getnativesysteminfo"
    name: "GetNativeSystemInfo and SYSTEM_INFO"
    category: "os-internal"
    description: "Kernel32 export that populates a SYSTEM_INFO structure with page size, min/max application address, active processor mask, processor count, and architecture (wProcessorArchitecture). SEC670 contrasts it with GetSystemInfo for WoW64 correctness — a 32-bit process calling GetSystemInfo receives the 32-bit subsystem view, while GetNativeSystemInfo returns the host architecture, which is the value needed for architecture-aware payload selection."
    relevant_to: [T-023]
    tags: [windows-api, os-info, architecture, recon, wow64]

  - id: "wmi-quickfix-engineering"
    name: "Win32_QuickFixEngineering WMI Class"
    category: "os-internal"
    description: "A WMI class exposed by the CIM repository that returns installed hotfix records (HotFixID, InstalledOn, Description). SEC670 documents that both the Get-HotFix PowerShell cmdlet and the wmic qfe list command ultimately query this class, meaning they return the same data set and may not show every update applied by modern servicing stacks — a limitation operators should account for when assessing patch coverage."
    relevant_to: [T-023, T-020]
    tags: [wmi, patch-status, hotfix, recon, qfe]

  - id: "wua-com-api"
    name: "Windows Update Agent (WUA) COM APIs"
    category: "os-internal"
    description: "A COM-based API surface (Wuapi.h, Wuaueng.lib) introduced with Windows XP for programmatically querying installed and available updates via UpdateSession -> CreateUpdateSearcher -> Search(criteria) -> ISearchResult -> IUpdateCollection. SEC670 presents this as a more thorough alternative to Win32_QuickFixEngineering when enumerating patch status, at the cost of additional COM instantiation telemetry."
    relevant_to: [T-023, T-020]
    tags: [com, wua, patch-status, hotfix, recon]

  - id: "createtoolhelp32-snapshot"
    name: "CreateToolhelp32Snapshot Process Enumeration"
    category: "os-internal"
    description: "Kernel32 export that captures a snapshot of running processes, threads, heaps, and modules for enumeration via Process32First/Process32Next. SEC670 describes it as one of the more common malware APIs because it returns detailed per-process records (PID, PPID, name, module list) in a single snapshot, making it suitable for injection-target and AV/EDR-process identification."
    relevant_to: [T-023, T-007]
    tags: [windows-api, process-enum, recon, injection-targeting]

  - id: "wts-enumerate-processes"
    name: "WTSEnumerateProcesses"
    category: "os-internal"
    description: "Wtsapi32 export that enumerates processes across multiple sessions on the local machine or on a remote system via an open WTS handle. SEC670 highlights its ability to return process information for processes in other sessions and to query remote systems — capabilities EnumProcesses and CreateToolhelp32Snapshot lack — at the cost of requiring the SeQueryServerAccess privilege for remote queries."
    relevant_to: [T-023]
    tags: [windows-api, process-enum, recon, multi-session, remote]

  - id: "enum-processes"
    name: "EnumProcesses (Psapi)"
    category: "os-internal"
    description: "A minimal Psapi export that returns an array of process IDs with no associated metadata. SEC670 describes it as the easiest enumeration API but notes the lack of detail (no name, no PID-to-path resolution) makes it unsuitable for AV/EDR identification without a follow-up call such as GetModuleBaseName per PID, which increases the API-call surface."
    relevant_to: [T-023]
    tags: [windows-api, process-enum, recon, minimal-footprint]

  - id: "ip-helper-api"
    name: "IP Helper API (IPHLPAPI)"
    category: "os-internal"
    description: "A user-mode DLL exposing network configuration and statistics queries. SEC670 specifically references GetIpStatistics (MIB_IPSTATS — IP datagram counts) and GetAdaptersAddresses (IP_ADAPTER_ADDRESSES — per-NIC addresses, gateway, DNS, adapter type) for NIC inventory. The same surface is exposed to defenders via Get-NetAdapter and netstat -e, so query patterns are well-baselined."
    relevant_to: [T-023, T-022]
    tags: [windows-api, network-enum, nic, recon]

  - id: "hkcr-registry-root"
    name: "HKEY_CLASSES_ROOT Merged View"
    category: "windows-structure"
    description: "A virtual registry root formed by merging HKCU\\SOFTWARE\\Classes over HKLM\\SOFTWARE\\Classes. SEC670 documents that HKCR holds file-extension associations, COM class registrations, and the virtualized registry root used by UAC file/registry virtualization. Per-user class registrations in HKCU\\SOFTWARE\\Classes take precedence over HKLM, which is the mechanism COM hijack persistence relies on."
    relevant_to: [T-017, T-023]
    tags: [registry, com, hijack, persistence, uac]

  - id: "host-survey-script"
    name: "Host Survey Script"
    category: "attack-pattern"
    description: "An operational pattern documented by SEC670 in which an implant or operator-collected script enumerates OS version, service pack, hotfixes, installed software, running processes, services, tasks, NIC configuration, and registry state before any further action. The output drives subsequent operational decisions: evasion technique selection based on AV/EDR identity, exploit selection based on patch status, and injection-target selection based on process list."
    relevant_to: [T-023, T-020]
    tags: [recon, survey, tradecraft, operational-decision]

  - id: "patch-status-inventory"
    name: "Patch Status Inventory as Exploit Precondition"
    category: "attack-pattern"
    description: "SEC670 frames knowledge of applied hotfixes as a precondition for exploitation: an operator selects an exploit primitive only after confirming the corresponding patch is absent. The same inventory supports EDR-evasion decisions, since some detection logic is itself patched into kernel callbacks or ETW providers and behaves differently across build numbers."
    relevant_to: [T-020, T-023]
    tags: [patch-status, exploit-selection, recon, kernel-build]

  - id: "qfe-hotfix-semantics"
    name: "Hotfix and Quick Fix Engineering (QFE) Terminology"
    category: "os-internal"
    description: "SEC670 defines a hotfix as a patch applied while the system remains running (no reboot required in the traditional sense), as opposed to updates that require a reboot to complete installation. The term QFE refers to the legacy servicing branch that produced these patches. Awareness of the distinction matters because reboot-pending hotfixes may not yet be reflected in the running kernel image, complicating patch-status conclusions drawn from a single snapshot."
    relevant_to: [T-020, T-023]
    tags: [windows-servicing, hotfix, qfe, patch-management]
```

### Detection Insights

```yaml
detection:
  - indicator: "WMI query against Win32_QuickFixEngineering class"
    source: "etw"
    confidence: "medium"
    relevant_to: [T-023, T-020]
    description: "Both the Get-HotFix PowerShell cmdlet and the wmic qfe list command issue IWbemServices::ExecQuery against the Win32_QuickFixEngineering class. The query surfaces in Microsoft-Windows-WMI-Activity/Operational (Event ID 11 for the consumer, Event ID 12 for the provider) and as a Sysmon Event ID 20/21 (WmiFilter registration) if a permanent consumer is involved. The query text 'SELECT * FROM Win32_QuickFixEngineering' is highly baselined, so volume rather than presence is the alerting signal."
    bypassed_by: "SEC670 documents the Windows Update Agent COM APIs as an alternative path that returns equivalent data without touching WMI; not discussed as an evasion technique but presented as a programmatic option."

  - indicator: "CreateToolhelp32Snapshot invoked against the running process set"
    source: "etw"
    confidence: "medium"
    relevant_to: [T-023, T-007]
    description: "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) generates a kernel ETW event under the Microsoft-Windows-Kernel-Process provider (GUID {22FB2CD6-0E7B-422B-A12C-601D440CC5ED}) on Windows 8+. Many legitimate processes snapshot the process list, so the call alone is not anomalous, but repeated snapshots from a non-baselined process are. The same applies to TH32CS_SNAPMODULE and TH32CS_SNAPMODULE32 cross-bitness module walks."
    bypassed_by: "not discussed"

  - indicator: "COM instantiation of Microsoft.Update.Session (WUA API)"
    source: "etw"
    confidence: "low"
    relevant_to: [T-023, T-020]
    description: "WUA API use requires CoCreateInstance on the Microsoft.Update.Session CLSID, which emits an ETW event under Microsoft-Windows-Com+/RuntimeSetup or surfaces in Sysmon Event ID 7 (image load ofwuaueng.dll) when the search executes. The pattern is rare outside Windows Update itself, wuauclt, and patch-management tooling, making non-Wuauclt source processes notable."
    bypassed_by: "not discussed"

  - indicator: "Direct read of KUSER_SHARED_DATA at 0x7FFE0000"
    source: "memory-scan"
    confidence: "low"
    relevant_to: [T-023]
    description: "A dereference of the fixed user-mode address 0x7FFE0000 (or 0x7FFE0000 + offset for SystemTime / NtMajorVersion / NtMinorVersion / ProductType fields) appears in code without an API import for the equivalent data. Memory scanners can flag an instruction stream that loads from this address as a recon primitive used to avoid GetVersionEx/GetNativeSystemInfo telemetry."
    bypassed_by: "not discussed"

  - indicator: "Process enumeration by a process not present in standard tooling allow-list"
    source: "behavioral"
    confidence: "medium"
    relevant_to: [T-023]
    description: "SEC670 documents three enumeration APIs — EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcesses — all of which produce process-list access patterns. EDRs baseline which binaries legitimately enumerate processes (taskmgr, svchost-hosted services, monitoring agents). A non-baselined process invoking any of these APIs, especially in close temporal proximity to NtOpenProcess attempts against specific PIDs, is a behavioral signal."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "WMI QuickFixEngineering Query from Non-Baselined Process"
    logsource: "sysmon"
    condition_summary: "Sysmon Event ID 20 or 21 (WmiEvent) where Query contains 'Win32_QuickFixEngineering' and the originating Image is not in the standard patch-management process allow-list (wuauclt.exe, USOClient.exe, sdiagnhost.exe, SCCM agents)."

  - title: "CreateToolhelp32Snapshot from Unusual Image"
    logsource: "etw"
    condition_summary: "Microsoft-Windows-Kernel-Process provider event for CreateToolhelp32Snapshot where the calling Image is not in the baseline allow-list of legitimate snapshot sources; correlate with subsequent OpenProcess on the enumerated PIDs."

  - title: "WUA COM Instantiation Outside Windows Update"
    logsource: "etw"
    condition_summary: "CoCreateInstance of CLSID {4CB43D7F-9D67-4B1A-8E8C-84E0C4E6CFA7} (Microsoft.Update.Session) or load of wuaueng.dll by a process whose Image is not signed by Microsoft or is not in the Windows Update / patch-management allow-list."
```

### Operational Chains

```yaml
chains:
  - name: "Host Survey Driving Evasion and Injection Decisions"
    description: "Standard SEC670 host-survey sequence producing the inputs for evasion technique selection and injection-target selection."
    steps:
      - technique: T-023
        role: "Query OS version and architecture via GetNativeSystemInfo (or KUSER_SHARED_DATA reads) to gate payload bitness and Windows-build-specific behavior."
      - technique: T-023
        role: "Enumerate hotfixes and service packs via Win32_QuickFixEngineering or WUA APIs to determine which patched vulnerabilities are unavailable and which detection logic may differ on the running build."
      - technique: T-023
        role: "Enumerate running processes via CreateToolhelp32Snapshot or WTSEnumerateProcesses to identify AV/EDR process names and PID values."
      - technique: T-020
        role: "Use the AV/EDR identity to select appropriate evasion techniques from the Anti-Analysis / Kaguya LOtL inventory."
      - technique: T-007
        role: "Use the enumerated process list to select an injection target that is not AV/EDR-protected and that matches the operational narrative for the engagement."
    notes: "SEC670 frames this chain as the survey phase of Section 2 — the sequence is implied by the module ordering (OS Info -> Service Packs -> Process Enumeration -> Installed Software -> User Information -> Services and Tasks -> Network Information -> Registry) rather than stated as a strict prerequisite graph."

  - name: "Patch-Status Inventory to Exploit Selection"
    description: "Sequence by which patch enumeration gates exploit-primitive availability per SEC670."
    steps:
      - technique: T-023
        role: "Enumerate applied hotfixes via WUA APIs (UpdateSession -> UpdateSearcher -> SearchResult) or WMI Win32_QuickFixEngineering."
      - technique: T-020
        role: "Map missing hotfixes to known CVEs and the corresponding exploit primitives available in the running environment."
    notes: "SEC670 states that awareness of patch status is required before attempting exploitation to avoid detection; the chain ordering is operational, not enforced by the system."

  - name: "Directory Walk to Software-Inventory Recon"
    description: "SEC670 Lab 2.5 FileFinder pattern for enumerating installed software by walking Program Files directories."
    steps:
      - technique: T-023
        role: "Enumerate C:\\Program Files and C:\\Program Files (x86) to identify installed 64-bit and 32-bit applications respectively."
      - technique: T-023
        role: "Walk user-specific folders and root-of-drive locations for non-standard installations that automated survey tools may miss."
    notes: "SEC670 notes that some applications (Python is cited) install at the root of the system drive rather than under Program Files, and that automated survey tools may miss these non-standard paths."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "host-survey-script-primitive"
    title: "Host Survey Script as a Unified Recon Capability"
    kind: "proposed-technique"
    description: "SEC670 dedicates an entire Section 2 to the host survey — a unified operational primitive that aggregates OS version, patch status, process list, installed software, services/tasks, NIC state, and registry state into a single survey output. The vault currently distributes these capabilities across T-023 (Client Capabilities: recon, sysinfo), T-020 (Kaguya LOtL + EDR detection), and T-022 (network recon), with no explicit technique card documenting the survey as a coordinated first-phase action. A dedicated card would capture the SEC670 sequence and the operational-decision handoff to evasion and injection technique selection."
    would_relate_to: [T-023, T-020, T-022, T-007]
    source_units: ["unit 19", "unit 20", "unit 21"]
    tags: [recon, survey, tradecraft, operational-decision, coverage-gap]

  - id: "patch-status-inventory-card"
    title: "Patch / Hotfix Inventory as a Standalone Capability"
    kind: "proposed-technique"
    description: "SEC670 covers hotfix enumeration via three distinct paths (Get-HotFix cmdlet, wmic qfe list, WUA COM APIs) and frames the result as a precondition for exploit selection and for reasoning about kernel-callback/ETW differences across builds. The vault does not currently document patch-status enumeration as a distinct capability; it appears implicitly inside Kaguya's LOtL inventory (T-020) and is not surfaced as an independent recon primitive that gates T-013/T-016 kernel-touching techniques."
    would_relate_to: [T-020, T-023]
    source_units: ["unit 27", "unit 28", "unit 29", "unit 32", "unit 33", "unit 34"]
    tags: [patch-status, hotfix, wua, wmi, exploit-selection, coverage-gap]

  - id: "kuser-shared-data-recon"
    title: "KUSER_SHARED_DATA Direct Reads as Telemetry-Free Recon"
    kind: "emerging-tradecraft"
    description: "SEC670 presents direct reads of KUSER_SHARED_DATA at 0x7FFE0000 as the undocumented alternative to documented OS-info APIs, useful precisely because it does not generate API-call telemetry. The vault documents KUSER_SHARED_DATA indirectly (T-004 PEB Walker relies on the same family of fixed user-mode structures) but does not surface direct KUSER_SHARED_DATA reads as a recon technique for OS version / architecture / system time. Worth tracking because the same page exposes SystemTime, Cookie, and other fields that support additional primitives."
    would_relate_to: [T-023, T-004]
    source_units: ["unit 5", "unit 17", "unit 24"]
    tags: [kuser-shared-data, undocumented-api, telemetry-evasion, recon]

  - id: "domain-recon-standard-user"
    title: "Domain Recon from Standard User Context"
    kind: "coverage-gap"
    description: "CRTO unit 10 surfaces domain reconnaissance as an action a standard domain user can perform without elevated integrity, and notes that running domain recon in a high-integrity process can be detrimental (token duplication context). The vault's recon coverage (T-023 byakugan.rs performs AD enum) does not currently document the integrity-level tradeoff — running recon as standard user vs high integrity — that CRTO flags as a tradecraft decision."
    would_relate_to: [T-023]
    source_units: ["unit 10"]
    tags: [domain-recon, integrity-level, tradecraft, ad-enum, coverage-gap]

  - id: "process-enumeration-api-tradeoffs"
    title: "Process Enumeration API Tradeoff Matrix"
    kind: "cross-source-convergence"
    description: "SEC670 documents three documented process-enumeration APIs (EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcesses) with explicit tradeoffs: simplicity vs detail vs remote/multi-session capability. The vault uses CreateToolhelp32Snapshot-style enumeration implicitly in T-023 recon but does not document why that API is selected over the alternatives. A concept node capturing the tradeoff matrix (already added) plus a card-internal note would surface this as a tradecraft decision rather than an arbitrary implementation choice."
    would_relate_to: [T-023, T-007]
    source_units: ["unit 15", "unit 40"]
    tags: [process-enum, api-tradeoff, tradecraft, recon, coverage-gap]
```

