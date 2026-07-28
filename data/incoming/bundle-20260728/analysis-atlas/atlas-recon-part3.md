## Synthesis Summary

This batch of 40 recon-themed units maps primarily to T-023 (Client Capabilities — recon/sysinfo) and T-017 (Five-Layer Persistence), with secondary relevance to T-016 (EDR Evasion Suite) and T-020 (Anti-Analysis Suite). The on-theme material — drawn from SANS SEC670 — covers Windows Registry hive structure (HKU, HKCU, HKLM, HKCR, HKCC, HKPD), registry read timing windows during boot/kernel/logon/app-startup, KUSER_SHARED_DATA as a direct-read sysinfo primitive, the WMI Win32 Provider class catalog (Win32_Process, Win32_Service, Win32_Account, Win32_OperatingSystem, Win32_Registry, Win32_Thread, Win32_LoggedOnUser), WQL query types, and the root\subscription WMI namespace as a persistence surface. Roughly 18 units are off-theme: nmap network scanning, AD forest/trust enumeration, Linux /etc/passwd enumeration, SPF/DMARC/DKIM email security, MailSniper, and AD PowerShell cmdlets (Get-Domain, Get-DomainController, Find-DomainShare) document external network recon and AD enumeration that fall outside the vault's Windows implant focus. The training material fills the knowledge gap between reading recon code and understanding which Windows data sources are operationally meaningful, when they are read by the OS (and thus blend with legitimate activity), and which WMI query surfaces survive EDR userland hooks because they route through the WMI service host rather than ntdll.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "kuser-shared-data"
    target: T-023
    type: enables
    rationale: "KUSER_SHARED_DATA is a fixed-address user-mode read-only page SEC670 lists as a BONUS sysinfo source alongside GetProductInfo/GetWindowsDirectory/GetComputerName/GetNativeSystemInfo — T-023 recon/sysinfo capability"
  - source: "wmi-win32-provider-classes"
    target: T-023
    type: enables
    rationale: "Win32 Provider classes (Win32_Process, Win32_Service, Win32_Account, Win32_Registry, Win32_Thread) enumerate host state via WQL — T-023 recon surface"
  - source: "wmi-event-subscription-namespace"
    target: T-017
    type: concept_link
    rationale: "root\\subscription __EventFilter/__EventConsumer/__FilterToConsumerBinding is a persistence vector; T-017 covers COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist — WMI event subscription persistence is not listed"
  - source: "registry-hive-structure"
    target: T-017
    type: enables
    rationale: "HKLM\\SOFTWARE and HKCU subkeys are the write targets for T-017 COM hijack, schtask, and TLS callback persistence — registry hive structure determines valid persistence locations"
  - source: "registry-profilelist-enumeration"
    target: T-023
    type: enables
    rationale: "HKU ProfileList SID subkeys enumerate local user accounts for recon; SEC670 names ProfileList as the source for user SID enumeration — T-023 recon"
  - source: "registry-read-timing-windows"
    target: T-017
    type: enhances
    rationale: "SEC670 identifies four registry read windows (boot, kernel boot, logon, app startup) — writing persistence values during these windows blends with legitimate registry reads"
  - source: "wmi-win32-provider-classes"
    target: "wmi-event-subscription-namespace"
    type: concept_link
    rationale: "Same WMI infrastructure surfaces both recon (Win32_* data queries) and persistence (root\\subscription event consumers); operator knowledge of one transfers to the other"
  - source: "wql-query-types"
    target: "wmi-event-subscription-namespace"
    type: requires
    rationale: "Event Query WQL type is required to define __EventFilter triggers; SEC670 lists Event Query as one of four WQL categories including intrinsic polling"
```

### Concept Nodes

```yaml
concepts:
  - id: "kuser-shared-data"
    name: "KUSER_SHARED_DATA Page"
    category: windows-structure
    description: "KUSER_SHARED_DATA is a read-only page shared between user mode and the kernel, accessed at a fixed virtual address without a syscall. SEC670 lists it as a BONUS sysinfo primitive alongside GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo. It exposes system time, tick count, NT version, and other fields without invoking NtQuerySystemInformation, sidestepping syscall-based EDR telemetry."
    relevant_to: [T-023]
    tags: [windows-internal, sysinfo, anti-edr, recon, direct-read]

  - id: "registry-hive-structure"
    name: "Windows Registry Root Key Hierarchy"
    category: windows-structure
    description: "Five predefined root keys: HKEY_USERS (HKU, per-user subkeys including .Default for SYSTEM), HKEY_CURRENT_USER (HKCU, link to HKU\\<SID>, backed by \\Users\\<user>\\Ntuser.dat), HKEY_CLASSES_ROOT (HKCR, link to HKLM\\Software\\Classes), HKEY_LOCAL_MACHINE (HKLM, system-wide config), HKEY_CURRENT_CONFIG (HKCC, link to HKLM\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current kept for backward compat). HKEY_PERFORMANCE_DATA (HKPD) is queried via RegQueryValueEx but data is not technically stored in that location."
    relevant_to: [T-017, T-016, T-020]
    tags: [registry, windows-internal, persistence-target, evasion]

  - id: "registry-read-timing-windows"
    name: "Registry Read Timing Windows"
    category: os-internal
    description: "SEC670 identifies four critical registry-read times: initial boot, kernel boot, logon process, application startup. New application installations trigger additional reads; some applications poll the registry continuously for live updates. Persistence writes during boot/logon blend with legitimate activity, reducing the relative detection signal of anomalous registry modifications."
    relevant_to: [T-017]
    tags: [registry, timing, persistence, blending, windows-internal]

  - id: "registry-profilelist-enumeration"
    name: "ProfileList User SID Enumeration"
    category: attack-pattern
    description: "HKU holds a subkey (HKCU) for each local user profile, plus HKU\\.Default for the SYSTEM account used by Winlogon for desktop background. HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList contains SIDs as subkey names for every user that has logged on locally (roaming-profile users excluded). Operators enumerate these to map local user accounts without querying SAM or calling NetUserEnum."
    relevant_to: [T-023]
    tags: [recon, user-enumeration, registry, attack-pattern]

  - id: "wmi-win32-provider-classes"
    name: "WMI Win32 Provider Class Catalog"
    category: os-internal
    description: "The Win32 Provider exposes Windows-specific data via classes: Win32_Account (user/group accounts), Win32_LoggedOnUser (session↔user relation), Win32_OperatingSystem (OS version/build), Win32_Process (running processes), Win32_Registry (system registry info), Win32_Service (installed services), Win32_Thread (executing threads). Filters narrow results; event queries trigger on property changes. This is the WMI surface for host situational awareness."
    relevant_to: [T-023]
    tags: [wmi, recon, sysinfo, host-enumeration]

  - id: "wql-query-types"
    name: "WMI Query Language Query Categories"
    category: os-internal
    description: "WQL defines four query categories: Data Query (retrieve current state), Event Query (intrinsic events must be polled at defined intervals; extrinsic events queried normally), Vulnerability Query, Schema Query (class definitions). PowerShell Get-WmiObject -Query is the standard test interface. Event Query is the WQL basis for __EventFilter trigger definitions used in WMI persistence."
    relevant_to: [T-023, T-017]
    tags: [wmi, wql, query, recon, persistence]

  - id: "wmi-event-subscription-namespace"
    name: "WMI Event Subscription Persistence Surface"
    category: attack-pattern
    description: "The root\\subscription WMI namespace hosts three classes for event-driven persistence: __EventFilter (trigger condition), __EventConsumer (action — CommandLineEventConsumer, ActiveScriptEventConsumer, etc.), and __FilterToConsumerBinding (links filter to consumer). Together they form a persistent trigger mechanism that survives reboots and executes in WmiPrvSE.exe context. SEC670 demonstrates enumeration via Get-WmiObject -Namespace root\\subscription."
    relevant_to: [T-017]
    tags: [wmi, persistence, event-subscription, attack-pattern]

  - id: "pe-analysis-toolchain"
    name: "PE Static Analysis Tool Suite"
    category: os-internal
    description: "Tools for parsing Portable Executable structure: dumpbin (CLI, ships with Visual Studio), PEview (minimal GUI), PE-bear (rich GUI, multi-file loading), CFF Explorer, and WinDbg with the !dh extension to parse executable images and dump headers. Used to inspect DLL exports, IAT, sections, and imports during implant development and reverse engineering."
    relevant_to: [T-004, T-006]
    tags: [pe, tooling, static-analysis, reverse-engineering]
```

### Detection Insights

```yaml
detection:
  - indicator: "WMI __EventFilter / __EventConsumer / __FilterToConsumerBinding creation in root\\subscription"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon EID 19 (WmiFilter), EID 20 (WmiConsumer), EID 21 (WmiFilterConsumerBinding) log each WMI persistence object at creation time. SEC670 enumerates these via Get-WmiObject -Namespace root\\subscription against __EventFilter, __EventConsumer, and __FilterToConsumerBinding — defenders use the same queries to audit persistence state."
    bypassed_by: "not discussed"

  - indicator: "WQL data query against Win32_Process / Win32_Service / Win32_Account"
    source: etw
    confidence: medium
    relevant_to: [T-023]
    description: "Microsoft-Windows-WMI-Activity ETW provider logs WQL queries executed via IWbemServices::ExecQuery. SEC670's Get-WmiObject -Query 'select * from Win32_Process where name=notepad.exe' produces a query event visible in WMI-Activity traces. High-volume enumeration queries against Win32_Account or Win32_Process are a recon signal."
    bypassed_by: "not discussed"

  - indicator: "Read of HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    source: windows-security-log
    confidence: low
    relevant_to: [T-023]
    description: "ProfileList enumeration reads do not generate Sysmon EID 12/13 events (those capture writes). Reads are only observable via Process Monitor or verbose Kernel-Registry ETW. SEC670 names ProfileList as the source for user SID enumeration — low-confidence detection requiring verbose tracing."
    bypassed_by: "not discussed"

  - indicator: "Direct memory read of KUSER_SHARED_DATA page"
    source: behavioral
    confidence: low
    relevant_to: [T-023]
    description: "SEC670 lists KUSER_SHARED_DATA as a BONUS sysinfo primitive. Because the page is mapped read-only at a fixed address and accessed without a syscall, conventional syscall-based EDR telemetry does not observe the read. Detection requires memory introspection, page-access tracing, or DBVM/hypervisor-level monitoring."
    bypassed_by: "not discussed"

  - indicator: "sc.exe query for service security descriptors"
    source: process-creation
    confidence: low
    relevant_to: [T-023]
    description: "SEC670 identifies sc.exe as the command-line utility for viewing an object's security descriptor. Process creation of sc.exe with sdshow/sdset arguments is a recon signal but is also legitimate administrator activity — low confidence in isolation."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "WMI Event Subscription Persistence Audit"
    logsource: sysmon
    condition_summary: "EID 19 OR EID 20 OR EID 21 fires; consumer type CommandLineEventConsumer or ActiveScriptEventConsumer elevates severity"
  - title: "WMI Recon Sweep via WMI-Activity"
    logsource: etw
    condition_summary: "Microsoft-Windows-WMI-Activity events where QueryString contains Win32_Account OR Win32_LoggedOnUser OR Win32_Service in rapid succession from same PID"
  - title: "sc.exe Security Descriptor Enumeration"
    logsource: process-creation
    condition_summary: "Image ends with sc.exe AND CommandLine contains sdshow OR sdset"
```

### Operational Chains

```yaml
chains:
  - name: "Registry-based Local User Enumeration"
    description: "Enumerate local user SIDs via registry reads to avoid SAM/NetUserEnum queries"
    steps:
      - technique: T-023
        role: "Read HKU\\<SID> subkeys and HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList to map local users"
      - technique: "registry-profilelist-enumeration"
        role: "ProfileList provides SID-to-user-path mapping for downstream credential targeting"
    notes: "SEC670 notes ProfileList works for every local user that has logged on; roaming profiles are excluded. HKU\\.Default belongs to SYSTEM and is used by Winlogon."

  - name: "WMI Host Situational Awareness Sweep"
    description: "Single WMI provider sweep for process/service/account/OS inventory"
    steps:
      - technique: T-023
        role: "Run WQL data queries against Win32_Process, Win32_Service, Win32_Account, Win32_OperatingSystem, Win32_Thread, Win32_Registry, Win32_LoggedOnUser"
      - technique: "wmi-win32-provider-classes"
        role: "Class catalog guides targeted enumeration and filter construction"
    notes: "SEC670 demonstrates Get-WmiObject -Query 'select * from Win32_Process where name=notepad.exe' as the canonical test interface. Filters reduce noise; event queries require polling intervals."

  - name: "WMI Event Subscription Persistence Audit"
    description: "Verify or inventory WMI persistence objects post-deployment"
    steps:
      - technique: "wmi-event-subscription-namespace"
        role: "Enumerate __EventFilter, __EventConsumer, __FilterToConsumerBinding in root\\subscription via Get-WmiObject -Namespace root\\subscription"
    notes: "SEC670 presents this as a verification step. Defenders use the same queries — operational and defensive tradecraft converge on the same enumeration interface."

  - name: "KUSER_SHARED_DATA Stealth Sysinfo Read"
    description: "Gather system time/version/tick count via direct page read instead of NtQuerySystemInformation"
    steps:
      - technique: T-023
        role: "Read KUSER_SHARED_DATA at fixed user-mode address to obtain system info fields"
      - technique: "kuser-shared-data"
        role: "Page layout provides tick count, system time, NT version, CryptoRandom without syscall"
    notes: "SEC670 lists this as a BONUS challenge alongside GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo — those APIs are syscall-backed, KUSER_SHARED_DATA is not."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "wmi-event-subscription-persistence-gap"
    title: "WMI Event Subscription Persistence"
    kind: coverage-gap
    description: "SEC670 covers __EventFilter / __EventConsumer / __FilterToConsumerBinding in root\\subscription as a WMI persistence mechanism, with Get-WmiObject -Namespace root\\subscription as the enumeration interface. T-017 Five-Layer Persistence covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not list WMI event subscription persistence. This is a major Windows persistence vector — Sysmon EID 19/20/21 was added to Windows specifically for it — and would fit naturally as a sixth persistence layer alongside the existing five."
    would_relate_to: [T-017]
    source_units: ["unit 23", "unit 24"]
    tags: [wmi, persistence, coverage-gap, sysmon-19-20-21, root-subscription]

  - id: "kuser-shared-data-sysinfo-primitive"
    title: "KUSER_SHARED_DATA Direct-Read Sysinfo Primitive"
    kind: proposed-technique
    description: "SEC670 cites KUSER_SHARED_DATA as a BONUS sysinfo target alongside GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo. The vault's T-023 lists sysinfo collection but does not document the direct-page-read approach that bypasses syscall-based EDR hooks entirely. This merits its own treatment as a stealth sysinfo primitive distinct from the API-call family."
    would_relate_to: [T-023, T-016]
    source_units: ["unit 15", "unit 16"]
    tags: [kuser-shared-data, sysinfo, anti-edr, direct-read, proposed-technique]

  - id: "host-recon-surface-catalog-gap"
    title: "Host Recon Surface Catalog for Implant Developers"
    kind: coverage-gap
    description: "The on-theme portions of this batch — registry hives, WMI Win32 Provider classes, KUSER_SHARED_DATA, ProfileList, sc.exe security descriptors — form a recon surface catalog: the specific Windows data sources an implant queries for situational awareness. T-023 mentions 'recon' generically but does not enumerate these sources, their detection profiles, or their evasion characteristics. A dedicated catalog would help operators pick recon primitives matching their evasion posture."
    would_relate_to: [T-023]
    source_units: ["unit 4", "unit 9", "unit 15", "unit 20", "unit 23", "unit 18"]
    tags: [recon, coverage-gap, sysinfo, wmi, registry, catalog]

  - id: "registry-blending-timing-tradecraft"
    title: "Registry Write Blending via OS Read-Timing Windows"
    kind: emerging-tradecraft
    description: "SEC670's identification of four registry-read timing windows (initial boot, kernel boot, logon, app startup) plus continuous-polling applications is operational tradecraft that does not appear in the vault's T-017 persistence card. The implication — persistence writes performed during these windows blend with legitimate registry reads — is the kind of OS-internals grounding that separates a working persistence implementation from one that survives detection. Worth surfacing as a concept node tied to T-017."
    would_relate_to: [T-017]
    source_units: ["unit 2", "unit 3"]
    tags: [registry, timing, blending, persistence, emerging-tradecraft]

  - id: "cross-source-wmi-convergence"
    title: "WMI Tradecraft Convergence Across SEC670 and CRTO"
    kind: cross-source-convergence
    description: "WMI enumeration (Win32_Process, Win32_Registry, Win32_Service via Get-WmiObject) appears in SEC670 units 19-24; WMI also surfaces in CRTO units via Get-Domain / Get-DomainController PowerShell cmdlets (which wrap WMI/CIM). Multiple courses converge on WMI as a recon and persistence substrate, indicating strong tradecraft consensus. The vault's T-023 and T-017 would benefit from explicit WMI surface documentation."
    would_relate_to: [T-023, T-017]
    source_units: ["unit 20", "unit 23", "unit 39", "unit 40"]
    tags: [wmi, cross-source, convergence, recon, persistence]
```