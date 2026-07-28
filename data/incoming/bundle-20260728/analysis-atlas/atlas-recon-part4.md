## Synthesis Summary

This batch maps primarily to T-023 (Client Capabilities — recon, sysinfo) with secondary relationships to T-016 (EDR Evasion Suite — service enumeration surfaces AV/EDR services), T-017 (Five-Layer Persistence — Registry enumeration underpins COM hijack target selection), and T-020 (Anti-Analysis Suite — OS/hotfix enumeration informs anti-VM and capability selection). The material is drawn from SANS SEC670 Book 2 "Getting to Know Your Target" with CRTO Nmap/AD policy context. It covers Windows APIs for OS/architecture discovery (GetNativeSystemInfo, GetProductInfo, GetWindowsDirectory, GetComputerName, KUSER_SHARED_DATA), network adapter enumeration (GetInterfaceInfo, GetAdaptersAddresses), the six Registry hives (HKU, HKCU, HKCR, HKLM, HKCC, HKPD) with their structures and value types, Windows Update Agent COM interfaces (UpdateSession, UpdateSearcher, ISearchResult) for hotfix/patch enumeration, and three process enumeration APIs (EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcessesEx). The gap filled is the OS/registry/COM background that lets a reader understand why the Rust sysinfo_collect.rs, byakugan.rs, and recon paths in client_rust enumerate what they enumerate, which registry keys carry actionable data, and how WUA COM interfaces expose installed-patch state. Units 2-4 (Nmap/IDS/network topology from CRTO) are general network scanning rather than Windows host tradecraft and were skipped as off-theme; unit 1 (Get-DomainPolicyData) is AD enumeration and was noted but maps loosely to T-023's recon scope.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "windows-registry-hive-structure"
    target: T-017
    type: enables
    rationale: "SEC670 states HKCU\\SOFTWARE\\Classes and HKLM\\SOFTWARE\\Classes combine to form HKCR, which holds COM class registrations — the registry path targeted by COM hijack persistence in T-017"
  - source: "windows-registry-hive-structure"
    target: T-023
    type: enables
    rationale: "SEC670 describes the Registry as 'troves of information critical to your survey tool' including user profiles via ProfileList, installed software, and boot configuration — directly feeding T-023's sysinfo/recon paths"
  - source: "service-enumeration-av-edr-discovery"
    target: T-016
    type: concept_link
    rationale: "SEC670 states service enumeration is used to 'detect services that could be vulnerable or ones that could belong to AV/EDR' — enumerating defensive services precedes selection of T-016 evasion modules"
  - source: "kuser-shared-data"
    target: T-023
    type: alternative_to
    rationale: "SEC670 lists KUSER_SHARED_DATA as a BONUS undocumented method to obtain system information, presented as an alternative to documented APIs like GetNativeSystemInfo used in T-023's sysinfo path"
  - source: "hotfix-servicepack-enumeration"
    target: T-020
    type: enhances
    rationale: "SEC670 frames hotfix/service pack awareness as informing exploit adjustment and target OS versioning — directly supports anti-VM patch-state checks and capability gating in T-020"
  - source: "hotfix-servicepack-enumeration"
    target: T-023
    type: enables
    rationale: "SEC670's WUA API enumeration of installed updates is part of the survey/sysinfo surface collected by T-023 client capabilities"
  - source: "windows-update-agent-com-api"
    target: "hotfix-servicepack-enumeration"
    type: requires
    rationale: "SEC670 documents UpdateSession, UpdateSearcher, and ISearchResult COM interfaces as the programmatic path to enumerate patches — the WUA COM stack is the mechanism that enables hotfix enumeration"
  - source: "process-enumeration-apis"
    target: T-023
    type: enables
    rationale: "SEC670 covers EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcessesEx as the three documented APIs backing process enumeration in T-023's recon path"
  - source: "getadaptersaddresses-api"
    target: T-023
    type: enables
    rationale: "SEC670 describes GetAdaptersAddresses as the API for finding which adapters have which IP addresses (IPv4 and IPv6) — foundational to T-023's network recon in byakugan.rs"
```

### Concept Nodes

```yaml
concepts:
  - id: "kuser-shared-data"
    name: "KUSER_SHARED_DATA (User-Shared Data Region)"
    category: windows-structure
    description: "KUSER_SHARED_DATA is an undocumented, user-mode readable shared page (mapped at fixed virtual address on x86 and x64) populated by the kernel at boot with system state including OS version, tick count, product type, and timezone bias. SEC670 presents it as a bonus undocumented alternative to GetNativeSystemInfo/GetVersionEx for obtaining target OS details without invoking a syscall. Reading the page directly avoids the documented API path that EDRs may hook."
    relevant_to: [T-023, T-020]
    tags: [windows-internal, undocumented, sysinfo, recon, anti-edr]

  - id: "getnativesysteminfo-system-info-struct"
    name: "GetNativeSystemInfo and SYSTEM_INFO"
    category: os-internal
    description: "GetNativeSystemInfo populates a SYSTEM_INFO structure with processor architecture, page size, min/max application address, active processor mask, and processor count. Unlike GetSystemInfo, it reflects the native (non-WoW64) architecture, so a 32-bit process on a 64-bit OS receives x64 architecture values. The wProcessorArchitecture field distinguishes PROCESSOR_ARCHITECTURE_AMD64 (9) from INTEL (0)."
    relevant_to: [T-023]
    tags: [sysinfo, api, architecture, wow64, recon]

  - id: "windows-registry-hive-structure"
    name: "Windows Registry Hives and Access Timing"
    category: windows-structure
    description: "The Registry is composed of hives (HKU, HKCU, HKCR, HKLM, HKCC, HKPD) holding keys, subkeys, and values of 12 possible types (most common: REG_DWORD for numbers/booleans, REG_BINARY for >32-bit numbers or encrypted passwords, REG_SZ for strings). Configuration data is read at four critical times: initial boot, kernel boot, logon, and application startup. SEC670 states the Registry holds 'troves of information critical to your survey tool' and is consulted by the system itself."
    relevant_to: [T-023, T-017, T-020]
    tags: [registry, sysinfo, recon, persistence, windows-internal]

  - id: "hkey-users-profilelist-sid-enumeration"
    name: "HKU ProfileList for User Enumeration"
    category: windows-structure
    description: "The HKEY_USERS (HKU) hive contains a subkey (HKCU) for each user profile on the local system plus HKU\\.Default used by Winlogon for desktop background and system profile. The ProfileList subkey under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList enumerates local users by SID, providing a programmatic path to user discovery that does not require NetUserEnum or active directory queries."
    relevant_to: [T-023]
    tags: [registry, user-enum, recon, sid]

  - id: "hkey-local-machine-sam-security"
    name: "HKLM SAM, SECURITY, and BCD Subkeys"
    category: windows-structure
    description: "The HKLM root key holds BCD00000000 (boot entries), COMPONENTS (Component Based Servicing), HARDWARE, SAM (account password storage), SECURITY (LSA policy/secrets), and SOFTWARE (systemwide software config). SEC670 identifies SAM as containing 'account passwords' and BCD as holding 'boot entries.' SAM and SECURITY are restricted to SYSTEM context; standard user recon cannot directly query them."
    relevant_to: [T-023]
    tags: [registry, sam, lsasecrets, boot, recon]

  - id: "hkey-performance-data-programmatic-access"
    name: "HKEY_PERFORMANCE_DATA Programmatic Access Requirement"
    category: windows-structure
    description: "HKEY_PERFORMANCE_DATA (HKPD) cannot be accessed via regedit.exe and must be queried programmatically through Registry APIs such as RegQueryValueEx. The performance counter data is provided by external providers and is technically not stored in the registry hive itself — the registry API simply routes the query to the relevant performance counter provider. SEC670 recommends the Performance Data Helper (Pdh.dll) API as a preferred access method."
    relevant_to: [T-023]
    tags: [registry, performance, pdh, recon]

  - id: "windows-update-agent-com-api"
    name: "Windows Update Agent (WUA) COM Interfaces"
    category: os-internal
    description: "Introduced in Windows XP, the WUA APIs expose COM interfaces (UpdateSession, UpdateSearcher, ISearchResult, IUpdateCollection) for programmatically determining available, installed, or removable updates. The sequence is CreateUpdateSearcher -> Search(criteria, &results) -> results->get_Updates(&upList) -> upList->get_Count(&upSize). Header wuapi.h and lib wuguid.lib are required. WUA can target both Windows Update and WSUS."
    relevant_to: [T-023, T-020]
    tags: [com, wua, patch, hotfix, recon, sysinfo]

  - id: "hotfix-servicepack-enumeration"
    name: "Hotfix, Service Pack, and QFE Enumeration"
    category: attack-pattern
    description: "Hotfixes (Quick Fix Engineering or QFE updates) apply vital fixes while the system is running. Service Packs bundle one or more hotfixes so a user can jump to the most recent SP without installing each sequentially. SEC670 frames SP level awareness as informing exploit adjustment — different SP levels affect exploit compatibility and require consideration of target OS version when designing implants or LPE techniques."
    relevant_to: [T-023, T-020]
    tags: [patch, hotfix, qfe, service-pack, recon, exploit-prep]

  - id: "process-enumeration-apis"
    name: "Documented Process Enumeration APIs"
    category: attack-pattern
    description: "SEC670 presents three documented APIs for process enumeration with trade-offs: EnumProcesses (easiest, least detail), CreateToolhelp32Snapshot (more detail, common in malware), and WTSEnumerateProcessesEx (remote-capable, multi-session, returns WTS_PROCESS_INFO_EX with NumberOfThreads, HandleCount, PagefileUsage, WorkingSetSize, UserTime, KernelTime). Documented APIs are described as 'safe and reliable' but produce telemetry through normal syscalls."
    relevant_to: [T-023, T-013]
    tags: [process-enum, recon, wts, toolhelp, sysinfo]

  - id: "wts-process-info-ex-struct"
    name: "WTS_PROCESS_INFO_EX Structure"
    category: windows-structure
    description: "WTS_PROCESS_INFO_EX (returned by WTSEnumerateProcessesExA) exposes process metadata including NumberOfThreads, HandleCount, PagefileUsage, PeakPagefileUsage, WorkingSetSize, PeakWorkingSetSize, UserTime (LARGE_INTEGER), and KernelTime (LARGE_INTEGER). This richer structure differentiates WTSEnumerateProcessesEx from the simpler EnumProcesses snapshot and supports remote system interrogation subject to required registry keys."
    relevant_to: [T-023]
    tags: [wts, process-enum, windows-structure, recon]

  - id: "getadaptersaddresses-api"
    name: "GetAdaptersAddresses and IP_INTERFACE_INFO"
    category: os-internal
    description: "GetInterfaceInfo (IPHLPAPI) returns a list of IPv4-enabled adapters as IP_INTERFACE_INFO containing NumAdapters and an IP_ADAPTER_INDEX_MAP array. GetAdaptersAddresses extends this to both IPv4 and IPv6 with parameters Family, Flags, Reserved, AdapterAddresses (PIP_ADAPTER_ADDRESSES), and SizePointer. Both return ULONG/DWORD status codes including ERROR_INSUFFICIENT_BUFFER when the caller must retry with a larger buffer."
    relevant_to: [T-023]
    tags: [iphlpapi, network-enum, adapter, recon, sysinfo]

  - id: "registry-virtualization-uac-classes"
    name: "Registry Virtualization and HKCR Composition"
    category: os-internal
    description: "HKCR is a composite view of HKCU\\SOFTWARE\\Classes and HKLM\\SOFTWARE\\Classes holding three information types: file extension associations (REG_SZ keys typically pointing to other keys), COM class registrations, and a virtualized registry root for UAC. 32-bit applications on 64-bit systems are redirected through registry virtualization to WOW6432Node subkeys. This composition affects which hive a COM hijack or persistence entry actually writes to."
    relevant_to: [T-017, T-023]
    tags: [registry, uac, com, virtualization, wow64, persistence]

  - id: "service-enumeration-av-edr-discovery"
    name: "Service Enumeration for AV/EDR Discovery"
    category: attack-pattern
    description: "SEC670 frames service enumeration as revealing a target's purpose (DHCP, DNS, FTP roles) and surfacing services that 'could belong to AV/EDR.' Awareness of defensive services is presented as a precondition for selecting appropriate evasion techniques — high-visibility targets with EDR services require different tradecraft than low-visibility targets without."
    relevant_to: [T-023, T-016]
    tags: [service-enum, recon, av-edr-detection, evasion-prep]

  - id: "pe-analysis-tools"
    name: "PE File Analysis Tooling"
    category: attack-pattern
    description: "SEC670 lists Dumpbin (command-line, ships with Visual Studio), PEview (minimal GUI structure viewer), PE-bear (rich GUI supporting multi-file load with tabbed navigation), CFF Explorer, and WinDbg as PE/DLL structure analysis tools. The course emphasizes using Dumpbin and PE-bear for navigating PE headers — relevant for implant developers validating module layout before PEB walking or export resolution."
    relevant_to: [T-004, T-006]
    tags: [pe, analysis, tooling, dev-aid]
```

### Detection Insights

```yaml
detection:
  - indicator: "PowerShell Get-HotFix cmdlet execution"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023, T-020]
    description: "SEC670 identifies Get-HotFix as the PowerShell cmdlet that queries the Quick Fix Engineering class to enumerate installed hotfixes. ScriptBlock logging (EID 4104) captures the cmdlet invocation and arguments, revealing attacker interest in patch state. Querying all hotfixes via this cmdlet is unusual for normal user activity and is commonly seen during attacker survey."
    bypassed_by: "not discussed"

  - indicator: "wmic qfe list invocation"
    source: process-creation
    confidence: high
    relevant_to: [T-023]
    description: "SEC670 identifies 'wmic qfe list' as the WMIC command-line path to enumerate QFE updates. Process creation (Sysmon EID 1, Security EID 4688) records wmic.exe executing with 'qfe' arguments — a high-signal pattern for attacker reconnaissance that is rare in legitimate administrative work."
    bypassed_by: "not discussed"

  - indicator: "WMI event subscription via WUA COM objects"
    source: sysmon
    confidence: medium
    relevant_to: [T-023]
    description: "SEC670 documents UpdateSession -> CreateUpdateSearcher -> Search as the WUA COM sequence to enumerate patches. Sysmon EID 19/20/21 (WMI filter/consumer/subscriber) does not directly cover WUA COM instantiation, but Sysmon EID 1 with Image=wmiprvse.exe spawned by unusual parent plus Module Load EID 7 for wuaueng.dll loading in a non-Windows-Update process context indicates WUA activity outside expected svchost-hosted wuauserv."
    bypassed_by: "not discussed"

  - indicator: "WTSEnumerateProcessesEx invocation"
    source: etw
    confidence: low
    relevant_to: [T-023, T-013]
    description: "WTSEnumerateProcessesEx is the most information-rich documented process enumeration API and is also capable of remote system interrogation when proper registry keys permit it. EDR telemetry on the API itself is limited; the observable is the subsequent access pattern to process handles or the remote-target network authentication (EID 4624 type 3) when targeting another host."
    bypassed_by: "not discussed"

  - indicator: "KUSER_SHARED_DATA page access"
    source: memory-scan
    confidence: low
    relevant_to: [T-023, T-020]
    description: "SEC670 presents direct reads of KUSER_SHARED_DATA as a BONUS undocumented method for obtaining system info without invoking GetNativeSystemInfo. Direct memory reads of the shared user data page (fixed address on x86/x64) bypass documented API hooks but are observable via memory-access ETW providers monitoring unusual user-mode reads outside the PEB/TEB region. The behavior is rare in normal applications."
    bypassed_by: "Reading KUSER_SHARED_DATA requires no syscall or API hook, evading userland EDR instrumentation entirely — the material presents this as an advantage over documented sysinfo APIs"

  - indicator: "Registry enumeration of HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    source: sysmon
    confidence: medium
    relevant_to: [T-023]
    description: "SEC670 identifies ProfileList as the programmatic path to enumerate local user SIDs. Sysmon EID 12/13/14 (Registry event) captures access to this key from non-system processes. Combined with reads of HKLM\\SAM\\Domains (which would fail access-denied for standard users but signal enumeration intent) the pattern indicates user discovery."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "QFE Enumeration via wmic qfe list"
    logsource: process-creation
    condition_summary: "Process Image ends with 'wmic.exe' and CommandLine contains 'qfe'"
  - title: "PowerShell Get-HotFix Survey"
    logsource: powershell
    condition_summary: "ScriptBlock text contains 'Get-HotFix' or 'qfe'"
  - title: "WTSEnumerateProcessesEx remote process enumeration"
    logsource: windows-security
    condition_summary: "Logon event EID 4624 type 3 (network) from a process that shortly after spawns process enumeration behavior or queries wtsapi32 via module load EID 7"
```

### Operational Chains

```yaml
chains:
  - name: "Host Survey Chain"
    description: "Standard SEC670 host-survey sequence establishing OS state, patch level, defensive service presence, network posture, and persistence-relevant registry state on a newly accessed target."
    steps:
      - technique: T-023
        role: "Enumerate OS version, architecture, and product info via GetNativeSystemInfo/GetProductInfo (or undocumented KUSER_SHARED_DATA read)"
      - technique: T-023
        role: "Enumerate installed hotfixes and service packs via WUA COM interfaces (UpdateSession -> UpdateSearcher -> ISearchResult) to inform exploit selection and capability gating"
      - technique: T-023
        role: "Enumerate running services to identify target purpose (DHCP/DNS/FTP) and surface AV/EDR defensive services that gate T-016 evasion module selection"
      - technique: T-023
        role: "Enumerate network adapters and IP assignments via GetAdaptersAddresses/GetInterfaceInfo to map reachable subnets and identify dual-homed hosts"
      - technique: T-023
        role: "Enumerate HKU ProfileList, HKLM\\SOFTWARE, and HKCU\\SOFTWARE\\Classes to identify users, installed software, and COM-hijackable class registrations"
      - technique: T-017
        role: "Use registry survey output to select HKCU\\Software\\Classes COM hijack target suitable for the current user context"
    notes: "SEC670 frames each survey category as an independent module; the chain order reflects dependency flow (OS info gates hotfix relevance, hotfix state gates exploit selection, service enum gates evasion selection, registry enum gates persistence target selection) rather than a strict operational sequence the material mandates"

  - name: "Process Enumeration API Selection Chain"
    description: "Trade-off driven selection among SEC670's three documented process enumeration APIs based on detail requirements and remote-interrogation needs."
    steps:
      - technique: T-023
        role: "If only process count or basic existence is required, use EnumProcesses — easiest API, least detail"
      - technique: T-023
        role: "If process tree with parent/child relationships and module info is required, use CreateToolhelp32Snapshot — common in malware, more detail"
      - technique: T-023
        role: "If remote system interrogation or thread/handle/working-set metadata is required, use WTSEnumerateProcessesEx returning WTS_PROCESS_INFO_EX"
    notes: "SEC670 explicitly compares these three APIs on simplicity, detail level, and remote capability; selection is context-driven, not sequential. Remote WTS interrogation requires specific registry keys on the target to permit the query."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "proposed-host-survey-card"
    title: "Host Survey and Situational Awareness as a Standalone Technique"
    kind: proposed-technique
    description: "SEC670 dedicates an entire Book (Book 2, 'Getting to Know Your Target') to host survey: OS info, hotfixes/SPs, process enum, services, network adapters, registry hives, and user enumeration. The vault folds this into T-023 Client Capabilities under recon/sysinfo but does not elevate the survey process itself to a technique card. A dedicated survey T-NNN would let operators compose recon steps against a coherent capability rather than treating each enumeration API as an isolated T-023 sub-item, and would surface the explicit dependency: survey output gates evasion, persistence, and exploit technique selection."
    would_relate_to: [T-023, T-016, T-017, T-020]
    source_units: ["unit 7", "unit 9", "unit 14", "unit 25", "unit 26", "unit 29", "unit 38"]
    tags: [recon, survey, coverage-gap, technique-proposal]

  - id: "coverage-kuser-shared-data-access"
    title: "KUSER_SHARED_DATA Direct Read Coverage Gap"
    kind: coverage-gap
    description: "SEC670 presents KUSER_SHARED_DATA as a BONUS undocumented method to obtain system info without invoking documented sysinfo syscalls, framing it as an alternative path for recon. The vault has no technique card or concept node documenting the fixed user-mode shared page, the specific fields it exposes (OS version, tick count, product type, timezone bias), or the evasion implication of reading it directly (no syscall, no API hook contact). This is a concrete evasion-adjacent sysinfo path worth documenting as either a concept node on existing T-023/T-020 cards or a standalone LGTM-tracked item."
    would_relate_to: [T-023, T-020, T-016]
    source_units: ["unit 26", "unit 28"]
    tags: [kuser-shared-data, undocumented, sysinfo, evasion, coverage-gap]

  - id: "coverage-wua-com-patch-enum"
    title: "Windows Update Agent COM API for Patch Enumeration"
    kind: coverage-gap
    description: "SEC670 documents the full WUA COM interface stack (UpdateSession, UpdateSearcher, ISearchResult, IUpdateCollection) for enumerating installed hotfixes and identifying missing patches. The vault mentions patch awareness implicitly in T-020 anti-VM and T-023 sysinfo but has no documented COM interface walkthrough, no list of required headers/libs (wuapi.h, wuguid.lib), and no enumeration of the SearchResult -> Updates -> Count access pattern. WUA COM is a high-fidelity recon primitive that produces less telemetry than PowerShell Get-HotFix or wmic qfe and is under-represented in the vault."
    would_relate_to: [T-023, T-020]
    source_units: ["unit 33", "unit 34", "unit 35", "unit 37"]
    tags: [wua, com, patch-enumeration, recon, coverage-gap]

  - id: "coverage-registry-hive-operational-map"
    title: "Registry Hive Operational Map"
    kind: coverage-gap
    description: "SEC670 dedicates Units 15-24 to enumerating the six Registry hives with operational implications: HKU ProfileList for user SID discovery, HKLM SAM/SECURITY as restricted SYSTEM-only targets, HKCR composition affecting where COM hijack writes land, HKPD as programmatic-only access. The vault's T-017 persistence card references COM hijack and Registry use but does not document the hive-by-hive operational map that informs which key to query for which data type. A cross-cutting Registry reference would improve operator navigation between T-017 persistence targets and T-023 recon collection."
    would_relate_to: [T-017, T-023]
    source_units: ["unit 15", "unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 21", "unit 22", "unit 23", "unit 24"]
    tags: [registry, hives, coverage-gap, persistence, recon]

  - id: "convergence-process-enum-api-tradeoffs"
    title: "Process Enumeration API Trade-off Convergence"
    kind: cross-source-convergence
    description: "SEC670, MalDev Academy, and CRTO all converge on presenting EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcesses as the three documented process enumeration APIs with the same trade-off matrix (simplicity vs detail vs remote capability). This is strong tradecraft consensus that the vault should reflect: T-023 currently treats process enumeration as a single capability rather than three distinct APIs with different telemetry profiles and operational niches. Documenting the trade-off explicitly would help operators select the lowest-telemetry API that meets their detail requirement."
    would_relate_to: [T-023, T-013]
    source_units: ["unit 39", "unit 40"]
    tags: [process-enum, convergence, telemetry, api-selection]
```

