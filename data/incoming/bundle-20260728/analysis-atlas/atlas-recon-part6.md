## Synthesis Summary

This batch maps primarily to T-023 (Client Capabilities — recon, sysinfo, network enumeration) and T-017 (Five-Layer Persistence — specifically COM hijack, which depends on HKCR registry internals documented here), with peripheral relevance to T-007/T-013 (process injection — detection via PE-sieve). The material draws from SANS SEC670 (Windows tool development: directory walks, process enumeration via CreateToolhelp32Snapshot and WTSEnumerateProcesses, NIC enumeration via GetAdapterAddresses, Windows registry structure with deep dives into HKCR/HKCC composition) and CRTO (host and AD reconnaissance: Nmap port scans, PowerView cmdlets Get-DomainComputer/Get-DomainGPO/Find-DomainUserLocation, ADSearch LDAP queries, DNS record analysis for infrastructure ownership). The knowledge gap this material fills is the operational "why" behind recon API selection (why GetAdapterAddresses includes logical interfaces while GetNumberOfInterfaces does not), the structural reason COM hijack persistence works (HKCR is a merged view of HKCU\SOFTWARE\Classes and HKLM\SOFTWARE\Classes, letting per-user classes override per-machine ones), and the OPSEC cost of common AD enumeration cmdlets (Find-DomainUserLocation queries every machine in the domain). All 40 units are on-theme; none were skipped.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "hkcr-merged-view"
    target: T-017
    type: enables
    rationale: "SEC670 explains HKCR is the combination of HKCU\\SOFTWARE\\Classes and HKLM\\SOFTWARE\\Classes with per-user classes loaded first; this merged-view behavior is what allows per-user COM hijack persistence to override machine-wide COM registrations without elevation."
  - source: "windows-process-enumeration-apis"
    target: T-023
    type: enables
    rationale: "SEC670 Lab 2.2-2.4 cover CreateToolhelp32Snapshot and WTSEnumerateProcesses as the APIs backing process enumeration, which is a core T-023 recon capability for sysinfo collection."
  - source: "getadapteraddresses-api"
    target: T-023
    type: enables
    rationale: "SEC670 review questions identify GetAdapterAddresses() as the API that returns IP addresses for network adapters including logical interfaces, supporting T-023 network recon."
  - source: "pe-sieve-memory-scanner"
    target: T-007
    type: detects
    rationale: "SEC670 lists PE-sieve as a community-driven state-of-the-art tool for identifying malicious activity, directly relevant to detecting process injection artifacts in memory."
  - source: "pe-sieve-memory-scanner"
    target: T-013
    type: detects
    rationale: "PE-sieve scans for modified PE modules in process memory, which would detect module stomping, function stomping, and module overloading techniques documented in T-013."
  - source: "find-domainuserlocation-opsec"
    target: T-023
    type: concept_link
    rationale: "CRTO notes that Find-DomainUserLocation queries every machine in the domain and is 'obviously very noisy' — this OPSEC property affects how T-023 recon primitives should be sequenced."
  - source: "wmi-process-query"
    target: T-023
    type: enables
    rationale: "SEC670 demonstrates Get-WmiObject -Query 'Select * from Win32_Process' as a process enumeration alternative, expanding T-023 recon options beyond the Toolhelp/WTS APIs."
  - source: "ad-enumeration-toolset"
    target: T-023
    type: concept_link
    rationale: "CRTO PowerView cmdlets (Get-DomainComputer, Get-DomainGPO, Find-DomainUserLocation) and ADSearch LDAP queries are recon primitives overlapping with T-023's recon scope in domain contexts."
  - source: "dns-record-recon"
    target: T-022
    type: chains_to
    rationale: "CRTO discusses DNS records revealing exposed services and Cloudflare proxying; DNS-based infrastructure recon chains into T-022 network suite infrastructure decisions."
```

### Concept Nodes

```yaml
concepts:
  - id: "hkcr-merged-view"
    name: "HKEY_CLASSES_ROOT Merged View Semantics"
    category: windows-structure
    description: "HKCR is a merged view of HKCU\\SOFTWARE\\Classes and HKLM\\SOFTWARE\\Classes. Per-user class registrations in HKCU take precedence over per-machine registrations in HKLM. HKCR holds three categories of information: file extension associations, COM class registrations, and the virtualized registry root used by UAC. This merge semantics is the structural foundation that makes per-user COM hijack persistence viable without elevation."
    relevant_to: [T-017]
    tags: [registry, com-hijack, persistence, hkcr, windows-internals]

  - id: "hkcc-link-to-hklm"
    name: "HKEY_CURRENT_CONFIG as Link to HKLM"
    category: windows-structure
    description: "HKEY_CURRENT_CONFIG (HKCC) is entirely linked to HKEY_LOCAL_MACHINE. It is one of the three predefined root keys marked with an asterisk in the registry editor to denote that it is a link or merged view rather than a distinct store. HKCC provides the current hardware profile view derived from HKLM\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current."
    relevant_to: []
    tags: [registry, hkcc, hklm, windows-internals, orphan]

  - id: "windows-registry-root-keys"
    name: "Five Predefined Registry Root Keys"
    category: windows-structure
    description: "Windows exposes five predefined root keys: HKEY_USERS, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, and HKEY_CURRENT_CONFIG. The H prefix denotes handle (HKEY = handle to key). Keys marked with an asterisk (HKCR, HKCU, HKCC) are links or merged views rather than independent stores, while HKU and HKLM are the underlying physical stores."
    relevant_to: [T-017]
    tags: [registry, root-keys, windows-internals]

  - id: "windows-process-enumeration-apis"
    name: "CreateToolhelp32Snapshot and WTSEnumerateProcesses"
    category: attack-pattern
    description: "SEC670 Labs 2.3 and 2.4 cover two distinct process enumeration APIs. CreateToolhelp32Snapshot takes a snapshot of process/heap/module/thread state and is walked via Process32First/Process32Next. WTSEnumerateProcesses enumerates processes on a specified server (including remote via WTS) and returns SID and session information in addition to process name/PID. The two APIs return overlapping but not identical information; WTSEnumerateProcesses provides session/SID context that Toolhelp does not."
    relevant_to: [T-023]
    tags: [process-enum, recon, toolhelp, wts, windows-api]

  - id: "getadapteraddresses-api"
    name: "GetAdapterAddresses Logical Interface Inclusion"
    category: attack-pattern
    description: "GetAdapterAddresses is the Windows IP Helper API that returns IP address information for network adapters. Unlike GetNumberOfInterfaces (which counts physical adapters) and GetIpStatistics (which returns IP layer counters), GetAdapterAddresses includes logical interfaces such as loopback, tunnel adapters, and VPN interfaces in its results. SEC670 review questions emphasize this distinction for accurate NIC enumeration."
    relevant_to: [T-023]
    tags: [network-recon, nic, ip-helper, windows-api]

  - id: "windows-version-internal-mapping"
    name: "Windows Internal Version Number Mapping"
    category: os-internal
    description: "Windows reports an internal version number rather than a marketing name when queried via OS info APIs. The mapping: Windows XP=5.1, Server 2003=5.2, Vista/Server 2008=6.0, Windows 7/Server 2008 R2=6.1, Windows 8/Server 2012=6.2, Windows 8.1/Server 2012 R2=6.3, Windows 10/Server 2016=10. Implant recon logic must translate these numbers to marketing names since the OS API does not return them directly."
    relevant_to: [T-023]
    tags: [os-fingerprint, sysinfo, version-mapping, windows-internals]

  - id: "wmi-process-query"
    name: "WMI Win32_Process Query Enumeration"
    category: attack-pattern
    description: "WMI provides process enumeration via the Win32_Process class queried through Get-WmiObject -Query 'Select * from Win32_Process where name=...' or the WMI COM API. Unlike Toolhelp, WMI queries can be issued locally or remotely and return executable path, process handle, and command-line fields. WMI queries can trigger network logon events when targeting remote hosts via smbclient-style access, which has detection implications."
    relevant_to: [T-023]
    tags: [wmi, process-enum, recon, opsec]

  - id: "pe-sieve-memory-scanner"
    name: "PE-sieve Memory Scanner"
    category: defense-mechanism
    description: "PE-sieve is a community-driven memory scanner (contrasted by SEC670 against profit-driven products like Huntress Labs) that scans running processes for modified or replaced PE modules. It detects hollowed processes, process wiping, and module replacements by comparing in-memory PE headers and section contents against their on-disk originals. It is the canonical community tool for post-execution injection artifact discovery."
    relevant_to: [T-007, T-013]
    tags: [memory-scan, pe-sieve, defense, detection, injection]

  - id: "ad-enumeration-toolset"
    name: "PowerView AD Enumeration Cmdlets"
    category: attack-pattern
    description: "CRTO documents PowerView cmdlets for Active Directory recon: Get-DomainComputer returns computer objects with DNS alias names; Get-DomainGPO lists Group Policy Objects including Default Domain Policy, Roaming Users, and Windows Defender policies; Find-DomainUserLocation identifies which machines a domain user is logged into. These cmdlets issue LDAP queries against domain controllers and are noisy: Find-DomainUserLocation queries every machine in the domain."
    relevant_to: [T-023]
    tags: [ad-recon, powerview, ldap, opsec, domain]

  - id: "adsearch-ldap-tool"
    name: "ADSearch LDAP Query Tool"
    category: attack-pattern
    description: "ADSearch is a command-line tool for executing custom LDAP queries against Active Directory. CRTO demonstrates its use with a custom LDAP distinguished name filter (dc=...\\dc=...) returning a bounded result set. Unlike PowerView cmdlets which wrap common queries, ADSearch accepts raw LDAP filter strings, making it more flexible but also easier to misuse."
    relevant_to: [T-023]
    tags: [ad-recon, ldap, adsearch, recon]

  - id: "dns-record-recon"
    name: "DNS Record Infrastructure Reconnaissance"
    category: attack-pattern
    description: "DNS records expose services published by an organization including web servers, mail, and SaaS dependencies. CRTO emphasizes that DNS alone cannot confirm infrastructure ownership — a domain fronted by Cloudflare proxies traffic between client and origin, hiding whether the origin is on-premises, hosted at a third-party cloud provider, or a SaaS offering such as Office 365. Operators must confirm hosting with the client before engaging."
    relevant_to: [T-022]
    tags: [dns, infra-recon, cloudflare, saas, recon]

  - id: "procmon-sysinternals"
    name: "Process Monitor (ProcMon) for Behavior Tracing"
    category: defense-mechanism
    description: "Process Monitor from the Sysinternals Suite traces file system, registry, network, and process/thread activity in real time. SEC670 Lab 1.2 uses ProcMon to spot flaws in program startup behavior, and ProcMon also supports boot-time monitoring to capture driver and service initialization. Defenders use ProcMon to identify persistence mechanisms, anomalous file writes, and registry modifications characteristic of implant behavior."
    relevant_to: [T-017, T-020]
    tags: [procmon, sysinternals, behavior-trace, detection]

  - id: "nmap-port-scanning"
    name: "Nmap Port and Service Scanning"
    category: attack-pattern
    description: "CRTO documents Nmap as the primary port scanner for host reconnaissance, used with flags like -p 1-65535 for full-range TCP scans and --version for service fingerprinting. Ncat provides listener and relay capability, the Nmap Scripting Engine (NSE) automates service-specific probes, and hping3 supports low-level packet crafting. These tools together support host reconnaissance preceding lateral movement."
    relevant_to: [T-022]
    tags: [nmap, port-scan, recon, network]
```

### Detection Insights

```yaml
detection:
  - indicator: "Find-DomainUserLocation enumerates every machine in the domain"
    source: behavioral
    confidence: high
    relevant_to: [T-023]
    description: "CRTO explicitly flags Find-DomainUserLocation as 'obviously very noisy' because it queries every machine in the domain to locate where a user has a session. Detection is via Windows event log logon events generated on each queried host, network connections from the scanner to every machine, and LDAP query volume against domain controllers."
    bypassed_by: "not discussed"

  - indicator: "WMI query to remote host triggers network logon"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "SEC670 notes that Get-WmiObject queries against remote hosts can trigger logon events visible via smbclient. Windows Security Log event 4624 (Logon) with Logon Type 3 (Network) is generated for each remote WMI query, and event 4648 (Logon Process) may be generated when explicit credentials are used."
    bypassed_by: "not discussed"

  - indicator: "PE module modification in process memory detected by PE-sieve"
    source: memory-scan
    confidence: high
    relevant_to: [T-007, T-013]
    description: "PE-sieve scans running processes for PE modules whose in-memory contents diverge from their on-disk image. It flags hollowed processes (replaced image), module stomping (foreign code in legitimate module), and unbacked executable regions. SEC670 lists PE-sieve alongside Huntress Labs as state-of-the-art tools for identifying malicious activity."
    bypassed_by: "not discussed"

  - indicator: "Process Monitor trace of registry writes to HKCU\\SOFTWARE\\Classes"
    source: behavioral
    confidence: medium
    relevant_to: [T-017]
    description: "ProcMon captures real-time registry write events including COM hijack modifications to HKCU\\SOFTWARE\\Classes. The trace shows the writing process, the specific value and key path, and the operation type (RegSetValue, RegCreateKey). A process writing COM LocalServer32 or InprocServer32 keys outside an installer context is anomalous."
    bypassed_by: "not discussed"

  - indicator: "Nmap full-range TCP port scan"
    source: network
    confidence: high
    relevant_to: [T-022]
    description: "nmap -p 1-65535 sends SYN packets to every TCP port on the target. Network IDS signatures flag the characteristic packet rate and uniform source-destination pattern. Windows host firewall logs (event 5152) record blocked inbound connection attempts at high volume."
    bypassed_by: "not discussed"

  - indicator: "ADSearch LDAP query with custom filter"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "ADSearch issues LDAP queries against a domain controller. Windows Security Log event 2888 (directory service access) and event 4662 (operation performed on object) capture the query filter, search base, and the requesting account. High-volume or unusual attribute queries (e.g., requesting all user objects with specific properties) are flagged by AD-attack-detection rules."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Find-DomainUserLocation Domain-Wide Enumeration"
    logsource: windows-security
    condition_summary: "Detect a single account issuing network logons (EventID 4624 Logon Type 3) to more than N unique hosts within a short window, combined with LDAP queries to the domain controller"
  - title: "Remote WMI Query Network Logon"
    logsource: windows-security
    condition_summary: "EventID 4624 Logon Type 3 from a remote host immediately followed by EventID 4648 (Logon Process) or WMI-Activity log events indicating remote WMI invocation"
  - title: "Nmap Full TCP Range Scan"
    logsource: windows-security
    condition_summary: "Windows Filtering Platform event 5152 (blocked packet) count from a single source IP exceeding a threshold across the full TCP port range within a short window"
  - title: "COM Hijack Registry Write to HKCU\\Classes"
    logsource: sysmon
    condition_summary: "Sysmon EventID 13 (Registry Value Set) where TargetObject contains 'HKCU\\SOFTWARE\\Classes\\CLSID' and (EventType is SetValue) and Image is not a known installer binary"
```

### Operational Chains

```yaml
chains:
  - name: "SEC670 Implant Recon Sweep"
    description: "Sequential information gathering an implant performs after landing to characterize the host"
    steps:
      - technique: T-023
        role: "Query OS version via internal version number mapping (5.1=XP, 6.1=Win7, 10=Win10/Server2016) and service pack/hotfix inventory"
      - technique: T-023
        role: "Enumerate running processes via CreateToolhelp32Snapshot or WTSEnumerateProcesses for AV/EDR/agent identification"
      - technique: T-023
        role: "Enumerate installed software via directory walks of Program Files and registry uninstall keys"
      - technique: T-023
        role: "Enumerate network adapters and IP configuration via GetAdapterAddresses (includes logical interfaces)"
      - technique: T-023
        role: "Walk registry root keys including HKCU and HKLM for installed services, autoruns, and COM registrations"
    notes: "SEC670 Section 2 'Getting to Know Your Target' organizes these in this order; the labs (2.1 OS Info, 2.2 ProcEnum, 2.3 CreateToolhelp, 2.4 WTSEnum, 2.5 FileFinder) are sequential and build on each other. Operators should treat the network enumeration step carefully as remote WMI queries trigger 4624 logon events."

  - name: "CRTO Domain Recon-to-Lateral-Movement Chain"
    description: "Active Directory reconnaissance sequence preceding lateral target selection"
    steps:
      - technique: T-022
        role: "DNS record enumeration to identify exposed services, hosting providers, and SaaS dependencies"
      - technique: T-023
        role: "Get-DomainComputer to enumerate computer objects and their DNS host names"
      - technique: T-023
        role: "Get-DomainGPO to identify applied policies including Windows Defender configuration"
      - technique: T-023
        role: "ADSearch with custom LDAP filter to extract a bounded result set for a specific target class"
      - technique: T-023
        role: "Find-DomainUserLocation to identify which hosts a target user is logged into — OPSEC: noisy, queries every machine"
    notes: "CRTO emphasizes Find-DomainUserLocation is 'obviously very noisy' — operators should minimize its use or prefer session enumeration from a single compromised host's event logs rather than domain-wide queries."

  - name: "ProcMon Defensive Triage"
    description: "Defender workflow for identifying persistence or anomalous behavior on a suspect host"
    steps:
      - technique: "ProcMon boot trace"
        role: "Capture boot-time registry, file system, and process events to identify persistence points loaded at startup"
      - technique: "PE-sieve memory scan"
        role: "Scan running processes for modified PE modules to detect injection artifacts"
    notes: "SEC670 positions ProcMon and PE-sieve as complementary — ProcMon captures behavior over time while PE-sieve captures current memory state. Neither alone is sufficient for full triage."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "active-directory-recon-coverage-gap"
    title: "Active Directory Reconnaissance as Distinct Capability"
    kind: coverage-gap
    description: "CRTO devotes substantial material to AD enumeration via PowerView (Get-DomainComputer, Get-DomainGPO, Find-DomainUserLocation) and ADSearch with custom LDAP filters. T-023 covers 'recon' generically but does not document AD-specific enumeration primitives, their OPSEC costs (Find-DomainUserLocation queries every machine), or how they integrate with the broader recon flow. The vault would benefit from surfacing AD recon as a first-class capability area."
    would_relate_to: [T-023]
    source_units: ["unit 30", "unit 31", "unit 32", "unit 33"]
    tags: [ad-recon, powerview, ldap, coverage-gap, opsec]

  - id: "pe-sieve-detection-coverage"
    title: "PE-sieve Detection Mechanics Against Injection Techniques"
    kind: proposed-technique
    description: "SEC670 identifies PE-sieve as a community-driven state-of-the-art tool for identifying malicious activity, alongside profit-driven products like Huntress Labs. The vault documents many injection techniques (T-007 through T-013) but does not document how PE-sieve specifically detects each — its hollowed-process detection, module stomp detection, and unbacked executable heuristics follow distinct algorithms that operators must understand to evade. A dedicated concept node per technique card on PE-sieve detection mechanics would close this gap."
    would_relate_to: [T-007, T-008, T-013]
    source_units: ["unit 36"]
    tags: [pe-sieve, detection, memory-scan, coverage-gap]

  - id: "windows-registry-internals-deep-dive"
    title: "Windows Registry Internal Structure and Link Semantics"
    kind: proposed-technique
    description: "SEC670 dedicates multiple slides to the merged-view and link semantics of HKCR, HKCU, and HKCC, explaining that per-user classes override machine-wide ones and that HKCC is entirely linked to HKLM. This structural knowledge underpins COM hijack persistence (T-017) and per-user persistence generally, but is not surfaced as a concept area in the vault. A dedicated concept cluster on registry link semantics would improve navigation for operators implementing per-user persistence."
    would_relate_to: [T-017]
    source_units: ["unit 16", "unit 17", "unit 18", "unit 19"]
    tags: [registry, hkcr, hkcc, com-hijack, persistence, windows-internals]

  - id: "cross-source-recon-api-selection-consensus"
    title: "Recon API Selection Consensus Across SEC670 and CRTO"
    kind: cross-source-convergence
    description: "Both SEC670 (GetAdapterAddresses vs GetNumberOfInterfaces vs GetIpStatistics distinction; CreateToolhelp32Snapshot vs WTSEnumerateProcesses vs WMI Win32_Process) and CRTO (PowerView cmdlet selection based on OPSEC) converge on the principle that recon API selection is consequential — different APIs return different fields, hit different log sources, and have different noise profiles. The vault currently treats T-023 recon as a single bucket; surfacing this selection tradeoff would help operators choose APIs deliberately rather than by default."
    would_relate_to: [T-023]
    source_units: ["unit 10", "unit 11", "unit 12", "unit 21", "unit 32"]
    tags: [recon, api-selection, opsec, convergence, sec670, crto]
```