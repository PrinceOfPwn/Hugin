## Synthesis Summary

The batch maps to HUGIN techniques T-021 (UAC bypass is explicitly listed under Crypto & Obfuscation), T-023 (UAC bypass via CMSTP appears in client capabilities), and T-017 (IFEO persistence is adjacent to the persistence suite even though IFEO is not among the five layers currently documented). The material comes from SANS SEC670 Book 3 "Operational Actions" and CRTO, covering AdjustTokenPrivileges, SeDebugPrivilege, Windows token privilege attributes (SE_PRIVILEGE_ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS), LUID_AND_ATTRIBUTES, integrity levels (Untrusted through Protected), the Service Control Manager and OpenSCManager/EnumServicesStatus enumeration, UAC as a non-security-boundary including autoElevate manifests and Fusion parsing via the UACMe project, and SE_BACKUP_NAME/SE_RESTORE_NAME for ACL bypass. Unit 9 (Linux sudo permissions via Nmap) is off-theme and was skipped. The training material fills the gap between source code that calls `AdjustTokenPrivileges` and the operational understanding of why privilege attributes matter, how UAC autoElevate manifests are parsed to identify bypass targets, and how backup/restore privileges structurally bypass DACL enforcement.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "uac-autoelevate-manifest"
    target: "T-021"
    type: enables
    rationale: "SEC670 states that applications with autoElevate set to TRUE in their embedded manifest can be targeted for UAC bypass; UAC bypass is documented under T-021."

  - source: "se-debug-privilege"
    target: "token-stealing-privesc"
    type: requires
    rationale: "SEC670 frames SeDebugPrivilege as required for obtaining handles to processes running under other security contexts, which is the prerequisite for token stealing."

  - source: "se-backup-restore-privileges"
    target: "explicit-access-a-acl-modification"
    type: counters
    rationale: "SEC670 states SE_BACKUP_NAME and SE_RESTORE_NAME grant read/write access regardless of file ACLs, structurally bypassing DACL enforcement that EXPLICIT_ACCESS_A modifications rely on."

  - source: "uacme-project"
    target: "uac-autoelevate-manifest"
    type: chains_to
    rationale: "SEC670 describes the UACMe project's FusionScanDirectory/FusionScanFiles/FusionCheckFile functions as the mechanism to discover binaries with autoElevate manifests that become bypass targets."

  - source: "image-file-execution-options-persistence"
    target: "T-017"
    type: alternative_to
    rationale: "SEC670 documents IFEO as a persistence method requiring Admin/SYSTEM on HKLM, operating as an alternative vector to the COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist layers in T-017."

  - source: "windows-service-control-manager"
    target: "T-017"
    type: concept_link
    rationale: "SEC670 covers service-based LPE via SCM enumeration and binary replacement; services are also the runtime substrate for PhantomPersist monitoring in T-017."

  - source: "token-stealing-privesc"
    target: "T-016"
    type: chains_to
    rationale: "Elevated token acquisition via stealing feeds into the EDR evasion suite — SeDebugPrivilege is a prerequisite for handle-based operations like PEB unlink and block-handle operations in T-016."
```

### Concept Nodes

```yaml
concepts:
  - id: "adjust-token-privileges"
    name: "AdjustTokenPrivileges and PTOKEN_PRIVILEGES"
    category: os-internal
    description: "AdjustTokenPrivileges enables or disables privileges on an access token using a PTOKEN_PRIVILEGES structure containing NewState, BufferLength, and PreviousState parameters. The function returns BOOL and does not throw — callers must check the return value and GetLastError, since partial success (privilege present but not all attributes set) is possible. SEC670 identifies this as the final step in privilege escalation after the token handle is opened."
    relevant_to: [T-016, T-023]
    tags: [token, privileges, luid, windows-internals, escalation]

  - id: "se-debug-privilege"
    name: "SeDebugPrivilege"
    category: os-internal
    description: "SeDebugPrivilege grants the right to open any process in the system regardless of DACL, enabling handle acquisition to SYSTEM-owned processes such as lsass.exe and winlogon.exe. SEC670 notes debuggers like WinDbg require this privilege and that it is the standard mechanism for token stealing escalation — once a SYSTEM process handle is open, its primary token can be captured and reapplied to the caller's process or thread."
    relevant_to: [T-016, T-023]
    tags: [privilege, debug, token-stealing, lsass, escalation]

  - id: "se-backup-restore-privileges"
    name: "SE_BACKUP_NAME and SE_RESTORE_NAME"
    category: os-internal
    description: "SE_BACKUP_NAME grants complete read access to any file regardless of its DACL, and SE_RESTORE_NAME grants complete write access regardless of DACL. SEC670 explicitly frames these as ACL-bypass privileges — they do not modify the ACL, they override its enforcement. The privileges are present but disabled by default on standard user tokens and must be enabled via AdjustTokenPrivileges before use."
    relevant_to: [T-017]
    tags: [privilege, acl-bypass, backup, restore, dac, file-system]

  - id: "luid-and-attributes"
    name: "LUID_AND_ATTRIBUTES Structure"
    category: windows-structure
    description: "LUID_AND_ATTRIBUTES pairs a Locally Unique Identifier (LUID) for a privilege with an attributes DWORD describing its state. SEC670 enumerates four SE_PRIVILEGE_* attribute flags: ENABLED (privilege is set and active), ENABLED_BY_DEFAULT (enabled at token creation), REMOVED (used to strip privileges from a token), and USED_FOR_ACCESS (the privilege was checked during an object open). These attributes are what AdjustTokenPrivileges modifies."
    relevant_to: [T-016]
    tags: [luid, token, privilege-attributes, windows-structure]

  - id: "windows-integrity-levels"
    name: "Windows Integrity Levels (IL)"
    category: os-internal
    description: "Windows uses six integrity levels for privilege separation: Untrusted (0), Low (1), Medium (2), High (3), System (4), and Protected (5). SEC670 maps processes to ILs — browsers typically run at Low-IL for untrusted content, standard user processes at Medium-IL, elevated admin processes at High-IL, and lsass.exe/winlogon.exe at System-IL. GetTokenInformation retrieves the IL of a token. UAC is the mechanism that transitions a Medium-IL admin user to High-IL on consent."
    relevant_to: [T-021, T-023]
    tags: [integrity-level, il, token, uac, mandatory-integrity-control]

  - id: "windows-service-control-manager"
    name: "Service Control Manager (SCM)"
    category: os-internal
    description: "SCM is the Windows subsystem managing services — processes that start at boot and run without a logged-on user. SEC670 identifies schedule, EventLog, BITS, gupdate, and iphlpsvc as services running in the background. OpenSCManager returns a handle to the SCManager object container, which holds individual service objects, a database lock, and supports operations EnumServicesStatus and QueryServiceStatus used by LPE scanners to find unquoted service paths and weak binary permissions."
    relevant_to: [T-017]
    tags: [scm, services, openscmanager, lpe, enum-services, unquoted-path]

  - id: "uac-security-context"
    name: "UAC as Non-Security Boundary"
    category: edr-mechanism
    description: "SEC670 explicitly states UAC is not a security boundary — it is a convenience feature. UAC prompts present three title bar colors: blue (Microsoft-signed, trusted), yellow (known publisher, unverified), red (unsigned or unknown publisher). Standard users run at Medium-IL; admin users with UAC enabled also run at Medium-IL until a consent prompt elevates them to High-IL. autoElevate in an application manifest allows a Microsoft-signed binary to silently elevate without a prompt, which is the substrate UAC bypass techniques exploit."
    relevant_to: [T-021, T-023]
    tags: [uac, integrity-level, autoelevate, security-boundary, elevation]

  - id: "uac-autoelevate-manifest"
    name: "Application Manifests and autoElevate"
    category: windows-structure
    description: "Application manifests are XML files embedded in PE binaries describing security context, including supportedOS, heapType (e.g., SegmentHeap), and the autoElevate element. When CreateProcess invokes the Fusion database, it reads the manifest; if autoElevate is TRUE and the binary is signed by Microsoft, the process is silently elevated to High-IL without a UAC consent prompt. SEC670 identifies this as the target surface for UAC bypass research — find an autoElevate binary with a logic flaw and weaponize it."
    relevant_to: [T-021, T-023]
    tags: [manifest, autoelevate, fusion, uac-bypass, pe]

  - id: "uacme-project"
    name: "UACMe Project"
    category: attack-pattern
    description: "UACMe is a GitHub repository hosting a collection of UAC bypass methods. SEC670 describes its Fusion parsing utilities — fusion.c and fusion.h with three key functions: FusionScanDirectory (walk a directory for PE binaries), FusionScanFiles (filter to candidates with embedded manifests), and FusionCheckFile (extract and read the autoElevate element value). The project serves as both a bypass catalog and a research tool for discovering new autoElevate binaries."
    relevant_to: [T-021, T-023]
    tags: [uacme, uac-bypass, fusion, autoelevate, github]

  - id: "image-file-execution-options-persistence"
    name: "Image File Execution Options (IFEO) Persistence"
    category: attack-pattern
    description: "IFEO persistence uses HKLM Registry keys under the Image File Execution Options subtree to redirect execution of a target binary to an attacker payload. SEC670 requires Admin or SYSTEM privileges — standard users are denied access to HKLM. The technique appears in Lab 4.2 (Sauron IFEO) and Lab 4.3 (IFEOPersisto). The course recommends building an uninstall command to revert registry modifications and avoid leaving traces."
    relevant_to: [T-017]
    tags: [ifeo, persistence, registry, hklm, escalation]

  - id: "token-stealing-privesc"
    name: "Token Stealing Privilege Escalation"
    category: attack-pattern
    description: "Token stealing is the pattern of opening a higher-privileged process (typically SYSTEM via SeDebugPrivilege), extracting its primary token, and applying it to the attacker's process or thread via SetThreadToken or NtSetInformationProcess. SEC670 Book 3 includes a dedicated lab on the steps and APIs involved, framing it as the canonical LPE technique when an admin token is already present but SYSTEM is required."
    relevant_to: [T-016]
    tags: [token-stealing, lpe, sedebug, system, escalation]

  - id: "explicit-access-a-acl-modification"
    name: "EXPLICIT_ACCESS_A and ACL Modification"
    category: windows-structure
    description: "EXPLICIT_ACCESS_A structures describe access control entries for a trustee, containing grfAccessPerms (permission mask), grfAccessMode (GRANT_ACCESS, DENY_ACCESS, SET_ACCESS, REVOKE_ACCESS), grfInheritance, and a TRUSTEE_A identifying the user/group/program. SEC670 identifies this as the primary structure used with SetNamedSecurityInfoA to apply changes to an object's security descriptor, including DACL and SACL modifications."
    relevant_to: [T-017]
    tags: [acl, explicit-access, trustee, security-descriptor, dac, sacl]

  - id: "applocker-whitelisting"
    name: "AppLocker Application Whitelisting"
    category: edr-mechanism
    description: "AppLocker is Microsoft's application whitelisting technology. CRTO states that when an AppLocker category is enforced, everything in that category is blocked by default, and specific deny rules override allow rules. The default-deny posture means an operator must identify an allow rule that covers a usable LOLBin or staging path, or target the rule set itself for modification."
    relevant_to: [T-020]
    tags: [applocker, whitelisting, application-control, default-deny]

  - id: "gpo-abuse-privesc"
    name: "GPO Abuse for Privilege Escalation"
    category: attack-pattern
    description: "SharpGPOabuse is a tool for weaponizing write access to Group Policy Objects to push arbitrary settings — including scheduled tasks, immediate tasks, and PowerShell one-liners — that execute as SYSTEM on every machine in the GPO's scope. CRTO frames this as a domain-tier privesc/lateral movement vector: compromise a principal with GPO write access, push code, and harvest execution on multiple hosts simultaneously."
    relevant_to: []
    tags: [orphan, gpo, group-policy, domain, lateral-movement, sharp-gpoabuse]
```

### Detection Insights

```yaml
detection:
  - indicator: "Registry write to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target.exe>\\Debugger"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "IFEO persistence adds a Debugger value under a target executable's IFEO key, causing the OS to launch the attacker's binary instead of the target. Sysmon Event ID 13 (Registry Value Set) on the IFEO subtree with a Debugger value pointing to an unusual path is a high-confidence persistence indicator."
    bypassed_by: "not discussed"

  - indicator: "AdjustTokenPrivileges enabling SeDebugPrivilege on a non-system process"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-016]
    description: "Enabling SeDebugPrivilege on a process that did not previously hold it is anomalous — only debuggers and certain system utilities legitimately enable this privilege. Windows Security Event ID 4673 (Sensitive Privilege Use) captures SeDebugPrivilege attempts when object access auditing is configured for privileged operations."
    bypassed_by: "not discussed"

  - indicator: "Service binary path modification under HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\ImagePath"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Unquoted service path and weak binary permission LPE both culminate in either a new ImagePath value or a replaced service executable. Sysmon Event ID 13 on the Services registry key, combined with Event ID 1 (Process Create) for the service host launching an unexpected binary path, identifies service-based LPE."
    bypassed_by: "not discussed"

  - indicator: "SE_BACKUP_NAME / SE_RESTORE_NAME privilege enabled on a process token"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-017]
    description: "SEC670 states these privileges bypass ACL enforcement. Windows Security Event ID 4673/4674 captures attempts to use backup/restore privileges. Any non-backup-software process enabling SE_RESTORE_NAME and subsequently writing to a DACL-protected path is a strong indicator of ACL bypass tradecraft."
    bypassed_by: "not discussed"

  - indicator: "Process launching with High-IL from an autoElevate binary without a UAC consent event"
    source: behavioral
    confidence: medium
    relevant_to: [T-021, T-023]
    description: "When a Microsoft-signed autoElevate binary silently elevates to High-IL, no UAC prompt is shown to the user. Correlating the absence of a consent.exe launch (Event ID 4688 on consent.exe) with a High-IL child of an autoElevate binary identifies abuse of the Fusion autoElevate path rather than legitimate elevation."
    bypassed_by: "not discussed"

  - indicator: "Manifest parsing activity via FusionScan-style operations"
    source: behavioral
    confidence: low
    relevant_to: [T-021, T-023]
    description: "UACMe's FusionScanDirectory walks the filesystem reading PE manifests to identify autoElevate candidates. High-volume PE header reads across System32 by a non-system process is reconnaissance indicative of UAC bypass target selection."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "IFEO Debugger Persistence via Sysmon Registry Value Set"
    logsource: sysmon
    condition_summary: "EventID 13 where TargetObject contains 'Image File Execution Options' and contains 'Debugger' and Details not in typical system paths"

  - title: "SeDebugPrivilege Enable on Non-System Process"
    logsource: windows-security
    condition_summary: "EventID 4673 or 4674 where PrivilegeList contains SeDebugPrivilege and SubjectUserName does not match known debugger service accounts"

  - title: "Service ImagePath Modification"
    logsource: sysmon
    condition_summary: "EventID 13 where TargetObject contains 'CurrentControlSet\\Services' and contains 'ImagePath' with Details not matching previously observed service binary path"

  - title: "AutoElevate Silent Elevation Without Consent"
    logsource: windows-security
    condition_summary: "EventID 4688 for process creation with MandatoryLabel of High Mandatory Level where parent process is an autoElevate binary and no consent.exe process appears in the preceding 5 seconds"
```

### Operational Chains

```yaml
chains:
  - name: "UAC Bypass via autoElevate Binary Weaponization"
    description: "Identify a vulnerable autoElevate binary and weaponize it for silent High-IL execution without a consent prompt"
    steps:
      - technique: "uacme-project"
        role: "Run FusionScanDirectory/FusionScanFiles across System32 to enumerate binaries with autoElevate=TRUE in their embedded manifest"
      - technique: "uacme-project"
        role: "For each candidate, use FusionCheckFile to confirm the manifest content and review the binary's behavior with Process Monitor"
      - technique: T-021
        role: "Identify a logic flaw (DLL side-load, COM hijack, registry-configurable path) in the autoElevate binary and craft a payload that the binary will load and execute at High-IL"
      - technique: T-023
        role: "Deploy the payload via the weaponized autoElevate binary to achieve High-IL execution, enabling subsequent privileged operations"
    notes: "SEC670 Lab 3.7 (UACBypass-Research) is the explicit walkthrough for this chain. Requires a Medium-IL admin context — the operator must already be in the local Administrators group for autoElevate bypass to be meaningful, since UAC bypass on a standard user yields no privilege gain."

  - name: "Token Stealing for SYSTEM Privilege Escalation"
    description: "Acquire SeDebugPrivilege, open a SYSTEM process, and steal its token for SYSTEM-level execution"
    steps:
      - technique: "se-debug-privilege"
        role: "Enable SeDebugPrivilege via AdjustTokenPrivileges on the current process token — requires the privilege to be present (admin token) but disabled"
      - technique: "token-stealing-privesc"
        role: "OpenProcess on a SYSTEM-IL process such as winlogon.exe with PROCESS_QUERY_LIMITED_INFORMATION, capture its primary token via OpenProcessToken"
      - technique: "token-stealing-privesc"
        role: "Apply the stolen token to a new or existing thread via SetThreadToken, or duplicate it with DuplicateTokenEx and launch a new process with CreateProcessWithTokenW"
    notes: "SEC670 Book 3 includes a dedicated lab on this sequence. SeDebugPrivilege must be both present in the token and enabled — AdjustTokenPrivileges only changes the enabled attribute, it cannot add a privilege the token does not hold. This is why token stealing is typically chained after an initial admin/UAC bypass."

  - name: "Service Binary Replacement LPE"
    description: "Enumerate services with weak binary permissions and replace the executable to gain execution as the service account"
    steps:
      - technique: "windows-service-control-manager"
        role: "OpenSCManager to obtain an SCManager handle, then EnumServicesStatus to enumerate all services and QueryServiceStatus to fetch each service's binary path"
      - technique: "windows-service-control-manager"
        role: "Get-Acl on each service binary to identify Modify+Synchronize or Full Control permissions granted to the current user context"
      - technique: "windows-service-control-manager"
        role: "Replace the service binary with attacker payload, then Start-Service (or wait for the next service trigger) to execute payload as LocalSystem"
    notes: "SEC670 covers the enumeration and detection steps. CRTO demonstrates the Get-Acl + ls -la inspection pattern. Requires either an unquoted path with a writable parent directory or direct write access to the service binary itself."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "ifeo-persistence-coverage-gap"
    title: "IFEO Persistence Not in T-017 Five-Layer Suite"
    kind: coverage-gap
    description: "SEC670 dedicates two labs (4.2 Sauron IFEO, 4.3 IFEOPersisto) and explicit permission modeling to IFEO persistence, requiring Admin/SYSTEM on HKLM and recommending uninstall logic for cleanup. T-017 currently documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — IFEO is absent despite being a peer-classic persistence vector. Adding IFEO as a sixth layer would close a visible gap in the persistence suite."
    would_relate_to: [T-017]
    source_units: ["unit 3", "unit 4"]
    tags: [ifeo, persistence, registry, coverage-gap]

  - id: "token-privilege-abuse-proposed-technique"
    title: "Token Privilege Abuse as Standalone Technique"
    kind: proposed-technique
    description: "SEC670 covers AdjustTokenPrivileges, SeDebugPrivilege, SE_BACKUP_NAME/SE_RESTORE_NAME ACL bypass, and token stealing as a coherent privilege-abuse tradecraft block. The vault references SeDebugPrivilege implicitly through T-016 handle operations but has no dedicated card for privilege token manipulation as a distinct capability — the AdjustTokenPrivileges + SeDebugPrivilege + token-stealing chain is reusable across escalation scenarios independent of injection or evasion."
    would_relate_to: [T-016, T-023]
    source_units: ["unit 5", "unit 6", "unit 13", "unit 14", "unit 28", "unit 32", "unit 34", "unit 35", "unit 40"]
    tags: [privilege-abuse, token, sedebug, sebackup, serestore, lpe, proposed-technique]

  - id: "service-based-lpe-proposed-technique"
    title: "Service-Based Local Privilege Escalation"
    kind: proposed-technique
    description: "SEC670 and CRTO both cover service enumeration (OpenSCManager, EnumServicesStatus, QueryServiceStatus), weak binary permissions (Get-Acl on service paths), and unquoted path LPE. This is distinct from the persistence suite — the operational purpose is one-shot elevation rather than persistence. A dedicated T-NNN for service LPE tradecraft would document the enumeration, ACL inspection, and replacement workflow the vault currently lacks."
    would_relate_to: [T-017, T-020]
    source_units: ["unit 11", "unit 15", "unit 16", "unit 17", "unit 18"]
    tags: [scm, services, lpe, unquoted-path, weak-permissions, proposed-technique]

  - id: "uac-bypass-research-methodology-convergence"
    title: "UAC Bypass Research Methodology Across Courses"
    kind: cross-source-convergence
    description: "SEC670's UAC bypass module (Fusion manifest parsing, Process Monitor behavior analysis, UACMe project integration) converges with the UAC bypass already documented under T-021 and T-023. The training material adds the discovery methodology (FusionScanDirectory/FusionScanFiles/FusionCheckFile) and the lab workflow (find autoElevate binaries, observe with ProcMon, weaponize) — operational knowledge that source code alone does not surface."
    would_relate_to: [T-021, T-023]
    source_units: ["unit 19", "unit 20", "unit 21", "unit 22", "unit 23", "unit 24", "unit 25", "unit 26", "unit 30"]
    tags: [uac, autoelevate, fusion, uacme, process-monitor, convergence]

  - id: "gpo-abuse-domain-privesc-orphan"
    title: "GPO Abuse for Domain-Tier Privilege Escalation"
    kind: emerging-tradecraft
    description: "CRTO covers SharpGPOabuse for pushing SYSTEM-context execution across GPO-scoped machines. The vault's T-NNN scope is Windows-local offensive tradecraft; GPO abuse is domain-tier and does not directly slot into any existing card. However, the operational output (SYSTEM execution on remote hosts) is adjacent to T-017 persistence and T-022 networking. Flagging as emerging tradecraft the vault may want to address if scope expands to Active Directory."
    would_relate_to: []
    source_units: ["unit 7", "unit 8"]
    tags: [orphan, gpo, sharp-gpoabuse, domain, active-directory, lateral-movement]
```