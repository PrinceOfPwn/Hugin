## Synthesis Summary

The batch maps to **T-021 (Crypto & Obfuscation)** and **T-023 (Client Capabilities)** for the UAC bypass content, and operates adjacent to **T-023** credential-harvest functionality for the SeDebugPrivilege / token-manipulation material (LSASS access prerequisites). The 40 SANS SEC670 units cover Windows privilege-escalation primitives at the API and OS-internals level: programmatic token manipulation (LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges, SeDebugPrivilege), Windows services as a privilege-escalation surface (Service Control Manager, OpenSCManager, EnumServicesStatus, unquoted service paths, CVE-2019-1322), UAC bypass mechanics (autoElevate manifests, the UACMe project's FusionScanDirectory/FusionCheckFile workflow, elevation-prompt color coding), and security-descriptor analysis (SDDL, ACE string layout, GetNamedSecurityInfoA, SE_BACKUP_NAME/SE_RESTORE_NAME ACL-bypass privileges). The knowledge gap the source code alone cannot fill: the vault implements UAC bypass (CMSTP, T-021/T-023) and credential harvest (T-023) but contains no dedicated technique card for the privilege-escalation prerequisites — token privilege adjustment, SCM enumeration, security-descriptor interpretation — that make those higher-level techniques operationally viable. Reading the source shows *that* a syscall or NT API is invoked; this material explains *why* SeDebugPrivilege must be enabled before LSASS access succeeds, *why* autoElevate manifests are the gatekeeper for UAC-bypass binary selection, and *how* defenders observe AdjustTokenPrivileges and service-descriptor modifications.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: sedebugprivilege-enablement
    target: T-023
    type: requires
    rationale: "SEC670 establishes that programmatic privilege enablement (LookupPrivilegeValue + OpenProcessToken + AdjustTokenPrivileges on SeDebugPrivilege) is the prerequisite step before any cross-process operation against protected targets such as LSASS — the source code shows the LSASS dump call but not the privilege-escalation chain that makes it succeed."
  - source: autoelevate-manifest-attribute
    target: T-021
    type: enables
    rationale: "The material frames autoElevate=TRUE in an application manifest as the gating condition for UAC bypass binary selection; CMSTP and other T-021/T-023 UAC bypass primitives only function against binaries whose Fusion-stored manifest declares autoElevate."
  - source: uacme-fusion-scanning
    target: autoelevate-manifest-attribute
    type: concept_link
    rationale: "The UACMe project's FusionScanDirectory / FusionScanFiles / FusionCheckFile workflow is the discovery mechanism that enumerates which on-disk binaries have autoElevate set in their embedded manifest, surfacing candidates for bypass weaponization."
  - source: unquoted-service-path-lpe
    target: scm-service-database
    type: requires
    rationale: "Identifying unquoted service path LPE vectors requires SCM interaction via OpenSCManager and EnumServicesStatus to enumerate registered service ImagePath values; the LPE primitive depends on the enumeration surface."
  - source: se-backup-restore-privileges
    target: acl-bypass-primitive
    type: enables
    rationale: "The unit review explicitly identifies SE_RESTORE_NAME as the privilege granting complete write access regardless of DACL — the canonical ACL-bypass primitive that elevates file/registry writes above configured permissions."
  - source: sddl-ace-string-layout
    target: scm-service-database
    type: concept_link
    rationale: "sc.exe sdshow outputs service security descriptors in SDDL syntax; interpreting the ACE string layout (ace_type, ace_flags, rights constants, SID abbreviations like BA/IU/SU/SY) is the parsing layer required to assess service-permission LPE viability surfaced by SCM enumeration."
  - source: getnamedsecurityinfo-api
    target: sddl-ace-string-layout
    type: chains_to
    rationale: "GetNamedSecurityInfoA retrieves the raw security descriptor for NTFS, service, registry, share, and file-mapping objects; the resulting descriptor is then interpreted via SDDL/ACE string syntax to identify weak-permission targets."
```

### Concept Nodes

```yaml
concepts:
  - id: "access-token-luid"
    name: "LUID-Indexed Access Token Privileges"
    category: os-internal
    description: "Windows privileges present in a process access token are referenced by a Locally Unique Identifier (LUID) rather than by name. LookupPrivilegeValue translates a privilege constant (e.g., SeDebugPrivilege) into its LUID on the local system; the LUID is then embedded in a TOKEN_PRIVILEGES structure passed to AdjustTokenPrivileges to enable or disable the privilege on a token handle obtained via OpenProcessToken. Privileges must be *present* in the token to be enabled; absent privileges cannot be inserted programmatically by an unprivileged caller."
    relevant_to: [T-023]
    tags: [token, luid, privilege, windows-internals, lsass-prereq]

  - id: "sedebugprivilege-enablement"
    name: "SeDebugPrivilege Enablement Sequence"
    category: attack-pattern
    description: "Three-API sequence (LookupPrivilegeValue → OpenProcessToken with TOKEN_ADJUST_PRIVILEGES → AdjustTokenPrivileges) that transitions SeDebugPrivilege from disabled to enabled in the calling process's token. Once enabled, the holder can open any process (including LSASS, Winlogon, and PPL-excluded system processes) with PROCESS_ALL_ACCESS, regardless of the target's DACL. SEC670 frames this as the canonical prerequisite step for token stealing and credential access operations."
    relevant_to: [T-023]
    tags: [privilege-escalation, sedebugprivilege, token, lsass, prereq]

  - id: "scm-service-database"
    name: "Service Control Manager Database and OpenSCManager"
    category: os-internal
    description: "The SCM maintains a database of installed services under HKLM\\SYSTEM\\CurrentControlSet\\Services, with the SCManager object acting as a container for individual service objects. OpenSCManager returns a handle to this container; that handle is required before any operation (enumerate, modify, delete, create) on a service object. Services can start at boot and run without an interactive logon (e.g., BITS, EventLog, schedule, iphlpsvc), making them a privilege-escalation and persistence surface available in session 0."
    relevant_to: [T-017]
    tags: [scm, services, session-0, persistence-surface, privesc]

  - id: "unquoted-service-path-lpe"
    name: "Unquoted Service Path Local Privilege Escalation"
    category: attack-pattern
    description: "When a service's ImagePath contains spaces and is not quoted (e.g., C:\\Program Files\\My Service\\svc.exe), Windows' CreateProcess resolution attempts to execute progressively shorter prefixes (C:\\Program.exe, C:\\Program Files\\My.exe, ...). If a non-administrative user can write to any prefix path, dropping a malicious binary at that path causes the service to execute attacker code in the context of the service (often LocalSystem). EnumServicesStatus and QueryServiceStatus enumerate ImagePath values to discover vulnerable services."
    relevant_to: [T-017]
    tags: [lpe, services, unquoted-path, path-traversal, privesc]

  - id: "autoelevate-manifest-attribute"
    name: "Application Manifest autoElevate Attribute"
    category: os-internal
    description: "Windows applications carry an XML manifest parsed by the Fusion subsystem during CreateProcess. The autoElevate element, when set to TRUE, signals that the binary should silently elevate to High-IL when launched by an administrator in an elevated split-token session — without displaying a UAC consent prompt. Binaries with autoElevate=TRUE are the targets of UAC bypass techniques: an attacker injects into or hijacks such a binary to inherit its silent elevation."
    relevant_to: [T-021, T-023]
    tags: [uac, manifest, fusion, autoelevate, elevation]

  - id: "uacme-fusion-scanning"
    name: "UACMe Project Fusion Scan Workflow"
    category: attack-pattern
    description: "The UACMe GitHub project ships fusion.c and fusion.h, which implement three functions — FusionScanDirectory, FusionScanFiles, FusionCheckFile — for enumerating on-disk binaries and parsing their embedded manifests to identify those declaring autoElevate=TRUE. This scan workflow is the discovery phase that surfaces candidate binaries for UAC bypass weaponization; bypass methods in the same project then exploit specific behaviors of the discovered binaries (e.g., DLL hijack, COM interface abuse) to gain High-IL."
    relevant_to: [T-021, T-023]
    tags: [uac, uacme, fusion, manifest-scanning, discovery]

  - id: "uac-elevation-prompt-color-coding"
    name: "UAC Elevation Prompt Title-Bar Color Coding"
    category: defense-mechanism
    description: "Windows UAC consent prompts encode publisher trust via title-bar color: blue indicates a Microsoft-signed, trusted publisher; yellow indicates a signed but non-Microsoft publisher (verified but untrusted); red indicates an unsigned or blocked publisher (group policy disallowed). The color reflects the publisher's signing chain resolution at prompt time, not the binary's autoElevate state. Bypass techniques that route through autoElevate binaries inherit the *blue* prompt behavior, making the elevation effectively silent — the prompt that would have appeared for an unknown publisher is suppressed by the trusted binary's manifest."
    relevant_to: [T-021, T-023]
    tags: [uac, prompt, publisher-trust, signature, evasion]

  - id: "se-backup-restore-privileges"
    name: "SE_BACKUP_NAME and SE_RESTORE_NAME ACL Bypass Privileges"
    category: os-internal
    description: "SE_BACKUP_NAME grants read access to objects regardless of DACL; SE_RESTORE_NAME grants write access regardless of DACL. Both privileges enable the holder to bypass discretionary access controls on files, registry keys, and objects for backup/restore operations. SEC670 frames SE_RESTORE_NAME as the answer to 'what privilege gives complete write access regardless of the ACL' — the canonical primitive for writing to ACL-protected targets (e.g., overwriting service binaries, modifying HKLM\\SYSTEM registry branches) without modifying the DACL itself."
    relevant_to: []
    tags: [orphan, privileges, acl-bypass, privesc, restore]

  - id: "sddl-ace-string-layout"
    name: "SDDL ACE String Syntax"
    category: windows-structure
    description: "Security Descriptor Definition Language encodes ACEs as compact strings: ace_type (A=allow, D=deny, OA=object-allow, OD=object-deny, AU=audit, AL=alarm), ace_flags (CI=container-inherit, OI=object-inherit, NP=no-propagate, IO=inherit-only, ID=inherited, SA=audit-success), and rights constants partitioned by object type (generic: GA/GR/GW/GX; standard: RC/SD/WD/WO; directory: RP/WP/CC/DC/LC/SW; registry: KA/KR/KW/KX; file: FA/FR/FW/FX). SID constants abbreviate well-known accounts (BA=Builtin Administrators, IU=Interactive User, SU=Service User, SY=Local System). sc.exe sdshow emits service security descriptors in this format."
    relevant_to: []
    tags: [orphan, sddl, acl, security-descriptor, parsing]

  - id: "getnamedsecurityinfo-api"
    name: "GetNamedSecurityInfoA Security Descriptor Retrieval"
    category: os-internal
    description: "GetNamedSecurityInfoA retrieves the security descriptor of a named object across multiple SE_OBJECT_TYPE categories — NTFS files, services, registry keys, shares, and file-mapping objects — returning owner SID, group SID, DACL, and SACL via output pointers. The caller specifies the SECURITY_INFORMATION bitmask (OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION) to control which components are returned. It is the programmatic counterpart to sc.exe sdshow for arbitrary object types."
    relevant_to: []
    tags: [orphan, security-descriptor, acl, reconnaissance, api]

  - id: "uac-non-security-boundary"
    name: "UAC as Non-Security Boundary"
    category: defense-mechanism
    description: "SEC670 explicitly characterizes UAC as a convenience feature rather than a security boundary: a High-IL admin in a split-token session runs un elevated processes at Medium-IL by default, but autoElevate binaries transition to High-IL silently without consent. Because the boundary is administrative rather than enforced, bypass techniques that route through autoElevate binaries are not treated by Microsoft as security vulnerabilities — they are within the supported elevation contract, which is why UAC bypass remains a durable tradecraft primitive rather than a patched attack surface."
    relevant_to: [T-021, T-023]
    tags: [uac, security-boundary, tradecraft-durability, evasion]

  - id: "token-stealing-primitive"
    name: "Token Stealing for Privilege Escalation"
    category: attack-pattern
    description: "Privilege-escalation pattern in which a process with SeDebugPrivilege opens a higher-privilege target (typically winlogon.exe or lsass.exe), retrieves its access token via OpenProcessToken, and assigns it to the calling thread via ImpersonateLoggedOnUser or SetThreadToken. The stolen token carries the target's privileges and integrity level, elevating the caller without spawning a new process or modifying service configuration. SEC670 frames this as the conceptual payload enabled by the SeDebugPrivilege enablement sequence."
    relevant_to: [T-023]
    tags: [token-impersonation, privesc, sedebugprivilege, lsass]
```

### Detection Insights

```yaml
detection:
  - indicator: "AdjustTokenPrivileges enabling SeDebugPrivilege"
    source: windows-security-log
    confidence: high
    relevant_to: [T-023]
    description: "Windows Security Event 4673 (Sensitive Privilege Use) fires when a caller invokes a privileged system service; SeDebugPrivilege use is in the sensitive set when SACL auditing is enabled on the calling process token or via Advanced Audit Policy → Privilege Use → Sensitive Privilege Use. The event captures the CallerProcessName, CallerProcessId, Privilege=SeDebugPrivilege, and SubjectUserName. Token stealing operations and LSASS handle acquisition both surface this event when audit policy is configured."
    bypassed_by: "not discussed"

  - indicator: "OpenSCManager followed by EnumServicesStatus from a non-service binary"
    source: behavioral
    confidence: medium
    relevant_to: [T-017]
    description: "Service enumeration for LPE reconnaissance typically appears as a sequence: OpenSCManagerA/W with SC_MANAGER_ENUMERATE_SERVICE access, then EnumServicesStatusEx iterating the service database, then QueryServiceConfig2 pulling ImagePath for unquoted-path analysis. Process creation telemetry showing a non-management binary (e.g., not sc.exe, services.msc, or PowerShell Get-Service) issuing these calls is anomalous and indicates enumeration tooling."
    bypassed_by: "not discussed"

  - indicator: "Process creation with autoElevate binary as parent of untrusted child"
    source: sysmon
    confidence: medium
    relevant_to: [T-021, T-023]
    description: "UAC bypass via autoElevate binaries typically produces a Sysmon Event 1 (Process Creation) where the parent process is a known Windows autoElevate binary (e.g., fodhelper.exe, computerdefaults.exe, cmstp.exe) and the child is an attacker payload or cmd.exe / powershell.exe. The image path of the parent and the command line of the child together indicate bypass weaponization rather than legitimate administrative use."
    bypassed_by: "not discussed"

  - indicator: "Service security descriptor modification via sc.exe sdset"
    source: windows-security-log
    confidence: high
    relevant_to: [T-017]
    description: "Modifying a service's DACL to grant write access to a non-admin principal generates Windows Security Event 4670 (Permissions on an object were changed) with ObjectType=Service object and the modified security descriptor in SDDL. Telemetry includes the modified principal, the original and new SDDL, and the calling process. This is the detection counterpart to the SDDL manipulation tradecraft the material documents."
    bypassed_by: "not discussed"

  - indicator: "GetNamedSecurityInfoA querying service or registry security descriptors"
    source: behavioral
    confidence: low
    relevant_to: []
    description: "Security-descriptor enumeration via GetNamedSecurityInfoA across many service or registry objects in a short window indicates reconnaissance tooling assessing ACL configuration for weak-permission targets. The pattern is low-confidence in isolation but correlates with subsequent service or registry modification events."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "SeDebugPrivilege Use by Non-System Process"
    logsource: windows-security
    condition_summary: "EventID 4673 with Privilege=SeDebugPrivilege and SubjectUserSid not in (S-1-5-18, S-1-5-19, S-1-5-20) and CallerProcessName not matching known service binaries"
  - title: "UAC Bypass Binary Spawning Command Interpreter"
    logsource: sysmon
    condition_summary: "EventID 1 with ParentImage in (fodhelper.exe, computerdefaults.exe, cmstp.exe, schtasks.exe, sdclt.exe) and Image in (cmd.exe, powershell.exe, wscript.exe, rundll32.exe)"
  - title: "Service Security Descriptor Modification"
    logsource: windows-security
    condition_summary: "EventID 4670 with ObjectType=Service object and NewSd containing ACE with Mandatory Label or granting WRITE_DAC to non-admin SID"
  - title: "Service Enumeration by Non-Management Process"
    logsource: process-creation
    condition_summary: "Process creation where Image is not in (sc.exe, services.msc, mmc.exe, powershell.exe, pwsh.exe) and CommandLine contains 'EnumServicesStatus' or calls OpenSCManager via named pipe binding"
```

### Operational Chains

```yaml
chains:
  - name: "SeDebugPrivilege to Credential Access"
    description: "Enable SeDebugPrivilege programmatically, then access LSASS for credential harvest."
    steps:
      - technique: "LookupPrivilegeValue for SeDebugPrivilege LUID"
        role: "Resolve the LUID for SeDebugPrivilege on the local system"
      - technique: "OpenProcessToken on calling process"
        role: "Obtain a token handle with TOKEN_ADJUST_PRIVILEGES access"
      - technique: "AdjustTokenPrivileges to enable SeDebugPrivilege"
        role: "Transition SeDebugPrivilege from disabled to enabled in the caller's token"
      - technique: T-023
        role: "Open LSASS with PROCESS_ALL_ACCESS and dump credentials — succeeds only because SeDebugPrivilege is now enabled"
    notes: "Privileges must already be present in the token; this chain does not work for principals whose token lacks SeDebugPrivilege at assignment time. Standard user tokens lack SeDebugPrivilege entirely; the chain requires either a service account, an elevated split-token admin, or a prior privilege-escalation step."

  - name: "Service Enumeration to Unquoted Path LPE"
    description: "Enumerate registered services to identify unquoted ImagePath values, then plant a malicious binary at a writable prefix path."
    steps:
      - technique: "OpenSCManager with SC_MANAGER_ENUMERATE_SERVICE"
        role: "Obtain a handle to the SCM database container"
      - technique: "EnumServicesStatus iterating service database"
        role: "List all installed services and their states"
      - technique: "QueryServiceConfig2 retrieving ImagePath"
        role: "Inspect each service binary path for spaces without surrounding quotes"
      - technique: "GetNamedSecurityInfoA on prefix paths"
        role: "Verify writability of candidate prefix directories"
      - technique: "Drop malicious binary at writable prefix path"
        role: "Plant the payload that the service will execute on next start"
      - technique: "Service restart or sc start"
        role: "Trigger service launch, causing CreateProcess to resolve the planted binary"
    notes: "Requires a service that runs as LocalSystem (or another privileged account) and an ImagePath with both unquoted spaces and a writable prefix directory. Most modern Windows service binaries ship with quoted paths; this primitive is increasingly rare on patched systems."

  - name: "UAC Bypass via autoElevate Binary Weaponization"
    description: "Discover autoElevate binaries, identify a vulnerability, weaponize it, and execute to inherit silent High-IL elevation."
    steps:
      - technique: "UACMe FusionScanDirectory / FusionScanFiles / FusionCheckFile"
        role: "Enumerate on-disk binaries and parse embedded manifests to identify autoElevate=TRUE candidates"
      - technique: "Process Monitor behavioral analysis"
        role: "Trace the autoElevate binary's process activity to find DLL search-order weaknesses, registry reads, or COM object lookups that occur post-elevation"
      - technique: "Identify hijackable artifact (DLL, registry value, COM object)"
        role: "Locate a writable resource the binary consults during its silent elevation"
      - technique: "Plant hijack payload at the hijackable location"
        role: "Position the malicious DLL / registry value / COM server so the autoElevate binary loads it"
      - technique: "Launch the autoElevate binary"
        role: "Trigger the binary's silent elevation; the hijacked payload now runs at High-IL without a UAC consent prompt"
      - technique: T-021
        role: "Use the resulting High-IL context for subsequent operations (credential access, persistence installation, kernel-driver loading)"
    notes: "Only functions for users in an administrator's split-token session — standard users do not receive silent elevation even when autoElevate=TRUE. Microsoft does not treat bypass of autoElevate binaries as a security vulnerability; the technique remains durable across Windows versions."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "coverage-gap-windows-privesc-primitives"
    title: "Windows Privilege Escalation Primitives Coverage Gap"
    kind: coverage-gap
    description: "The vault documents LSASS credential harvest (T-023) and CMSTP-based UAC bypass (T-021/T-023) as standalone capabilities, but contains no technique card for the privilege-escalation prerequisites that make those operations operationally viable: programmatic SeDebugPrivilege enablement via LookupPrivilegeValue/OpenProcessToken/AdjustTokenPrivileges, SCM-based service enumeration for unquoted-path LPE, or token-stealing via OpenProcessToken + ImpersonateLoggedOnUser. SEC670 dedicates a full module to these primitives as the foundation for the vault's higher-level credential-access and elevation techniques. The vault currently leaves an operator unable to chain T-023 LSASS access without external knowledge of how to enable SeDebugPrivilege first."
    would_relate_to: [T-023, T-021]
    source_units: ["unit 1", "unit 2", "unit 3", "unit 6", "unit 7", "unit 8", "unit 14", "unit 15"]
    tags: [coverage-gap, privesc, token, sedebugprivilege, services, lsass-prereq]

  - id: "proposed-technique-service-lpe-enumeration"
    title: "Service-Based LPE Enumeration and Exploitation"
    kind: proposed-technique
    description: "SEC670 devotes multiple units (9–16) to Windows services as a privilege-escalation surface: SCM interaction via OpenSCManager, service enumeration via EnumServicesStatus and QueryServiceStatus, unquoted-service-path LPE, weak service permissions, and CVE-2019-1322 (which the material references as an example service-configuration LPE). The vault has no card covering service enumeration as an offensive capability. This would merit its own T-NNN card distinct from T-017 persistence because the operational purpose is privilege escalation rather than persistence, and the technique surface (ImagePath enumeration, BINARY_PATH_NAME inspection, service-descriptor SDDL analysis) is a discrete tradecraft area."
    would_relate_to: [T-017, T-023]
    source_units: ["unit 9", "unit 10", "unit 11", "unit 12", "unit 13", "unit 14", "unit 15", "unit 16", "unit 37", "unit 38", "unit 39"]
    tags: [proposed-technique, services, scm, lpe, unquoted-path, sddl]

  - id: "proposed-technique-security-descriptor-reconnaissance"
    title: "Security Descriptor and SDDL Reconnaissance"
    kind: proposed-technique
    description: "SEC670 documents a structured tradecraft workflow around security descriptors: sc.exe sdshow for service DACLs, SDDL/ACE string interpretation (ace_type, ace_flags, rights constants, SID abbreviations), GetNamedSecurityInfoA for cross-object-type descriptor retrieval, and SE_BACKUP_NAME/SE_RESTORE_NAME as ACL-bypass privileges. This is a reconnaissance capability with distinct API surface and parsing requirements that the vault does not document anywhere. Adding a card would help operators identify weak-permission targets (services, registry keys, file paths) systematically rather than via ad-hoc tooling."
    would_relate_to: [T-023]
    source_units: ["unit 28", "unit 29", "unit 30", "unit 35", "unit 36", "unit 37", "unit 38", "unit 39", "unit 40"]
    tags: [proposed-technique, sddl, acl, reconnaissance, security-descriptor, se-backup-restore]

  - id: "cross-source-convergence-uac-tradecraft"
    title: "UAC Bypass Tradecraft Cross-Source Convergence"
    kind: cross-source-convergence
    description: "SEC670's treatment of UAC (units 17–27, 31–32) converges with the vault's existing T-021 and T-023 UAC bypass implementations on the same conceptual model: autoElevate manifests as the gatekeeper, Fusion as the parsing subsystem, the UACMe project as the canonical reference corpus, and elevation-prompt color coding as the trust indicator. The convergence indicates strong tradecraft consensus: any operator working in this space encounters the same autoElevate+Fusion+UACMe mental model across SANS, the source corpus, and the broader red-team community. Surfacing this convergence in the graph would help operators recognize that the vault's CMSTP bypass is one instance of a broader technique family the material systematically documents."
    would_relate_to: [T-021, T-023]
    source_units: ["unit 17", "unit 18", "unit 19", "unit 20", "unit 21", "unit 22", "unit 23", "unit 24", "unit 25", "unit 26", "unit 31", "unit 32"]
    tags: [cross-source-convergence, uac, autoelevate, fusion, uacme, tradecraft-model]
```