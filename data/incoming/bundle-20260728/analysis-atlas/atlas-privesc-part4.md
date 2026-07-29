## Synthesis Summary

This batch maps primarily to T-017 (Five-Layer Persistence), T-022 (Network Suite / BYOVD), T-023 (Client Capabilities / credential harvest / UAC bypass), and T-016 (EDR Evasion Suite / handle blocking). The SANS SEC670 material covers Windows Se*Privilege exploitation (SeDebugPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege), the programmatic privilege-adjustment API triad (LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges), token stealing for Admin-to-SYSTEM escalation, two persistence mechanisms absent from the vault's T-017 five-layer suite (Port Monitor registry abuse and Image File Execution Options), and Windows security descriptor internals (ACE string layout, SDDL, EXPLICIT_ACCESS_A, securable objects). The knowledge gap this fills is the operational "why and how" of privilege escalation chains, the Windows ACL/security-descriptor data structures that underpin access checks the vault's techniques must respect or bypass, and persistence vectors the vault does not document. One unit (unit 18, Linux execute/elevate) was skipped as off-theme Linux content; unit 19 was retained as an on-theme section header but contributed no extractable technical detail.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: token-manipulation-api-triad
    target: se-privilege-escalation-set
    type: requires
    rationale: "LookupPrivilegeValue, OpenProcessToken, and AdjustTokenPrivileges are the API sequence required to programmatically enable Se*Privileges; the privilege set cannot be activated at runtime without this triad."
  - source: se-privilege-escalation-set
    target: T-022
    type: enables
    rationale: "SeLoadDriverPrivilege — one of the privileges SEC670 enumerates — is the prerequisite for BYOVD driver loading; without it the operator cannot load a vulnerable kernel driver from user mode."
  - source: se-privilege-escalation-set
    target: T-016
    type: concept_link
    rationale: "SEC670 identifies SeDebugPrivilege as the privilege that grants arbitrary process handle access; T-016's handle-blocking evasion directly counters the capability this privilege provides."
  - source: token-manipulation-api-triad
    target: T-023
    type: enables
    rationale: "SEC670's token-stealing lab uses OpenProcessToken and AdjustTokenPrivileges to elevate from Admin to SYSTEM; the same API surface underpins credential-harvest and UAC-bypass workflows in T-023."
  - source: port-monitor-persistence
    target: T-017
    type: alternative_to
    rationale: "Port Monitor registry abuse achieves the same operational goal (SYSTEM-level persistence via DLL load) as T-017's five-layer persistence suite but uses a registry vector the vault's COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist layers do not include."
  - source: ifeo-image-file-execution-options
    target: T-017
    type: alternative_to
    rationale: "IFEO persistence achieves autostart execution via the HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options key, serving the same persistence role as T-017's layers through a mechanism the vault does not document."
  - source: se-backup-restore-acl-bypass
    target: securable-objects
    type: concept_link
    rationale: "SEC670 presents SeBackupPrivilege and SeRestorePrivilege as privileges that override the ACLs on securable objects; the securable-objects concept (files, processes, registry keys, threads with SECURITY_ATTRIB) defines the objects these privileges bypass."
  - source: port-monitor-persistence
    target: se-privilege-escalation-set
    type: requires
    rationale: "SEC670 states the Port Monitor registry method requires local admin privileges to modify HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors; the admin token and its privilege set are prerequisites."
```

### Concept Nodes

```yaml
concepts:
  - id: "se-privilege-escalation-set"
    name: "Windows Se*Privileges for Privilege Escalation"
    category: os-internal
    description: "SEC670 enumerates SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, and SeDebugPrivilege as privileges typically absent from standard user tokens but present in admin tokens. These privileges enable ownership takeover of securable objects, token impersonation at TCB level, arbitrary token creation, kernel driver loading, and cross-process debug access respectively. Enabling SeDebugPrivilege in an admin token permits opening any process including SYSTEM processes for handle duplication and token theft."
    relevant_to: [T-016, T-022, T-023]
    tags: [privilege-escalation, token, se-debug, se-load-driver, se-tcb, windows-internals]

  - id: "token-manipulation-api-triad"
    name: "LookupPrivilegeValue / OpenProcessToken / AdjustTokenPrivileges API Triad"
    category: os-internal
    description: "SEC670 documents the three-API sequence for programmatic privilege manipulation. LookupPrivilegeValue retrieves the LUID for a named privilege (e.g., SeDebugPrivilege). OpenProcessToken opens a handle to the calling process's access token with TOKEN_ADJUST_PRIVILEGES access. AdjustTokenPrivileges enables or disables the privilege identified by the LUID in the token. The material notes AdjustTokenPrivileges has a BOOL return type and that privileges exist in enabled or disabled states within the token."
    relevant_to: [T-023]
    tags: [token-manipulation, privilege-escalation, win32-api, luid]

  - id: "luid-privilege-identifier"
    name: "Locally Unique Identifier (LUID) for Privilege Constants"
    category: windows-structure
    description: "SEC670 explains that LookupPrivilegeValue retrieves a Locally Unique Identifier (LUID) corresponding to a privilege name string such as SeDebugPrivilege. The LUID is the value the token structures use internally to reference the privilege; AdjustTokenPrivileges operates on LUID values, not string names. The function accepts lpSystemName (optional, can be NULL for local), lpName (the privilege string), and lpLuid (output PLUID)."
    relevant_to: [T-023]
    tags: [luid, token, privilege, windows-structure]

  - id: "port-monitor-persistence"
    name: "Print Monitors Registry Persistence"
    category: attack-pattern
    description: "SEC670 describes modifying the registry key HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors to add a malicious port monitor DLL entry. On system reboot, the print spooler service (running as SYSTEM) loads the DLL. This method requires local admin privileges to modify the registry key and a system reboot to trigger execution. The subkeys under the Monitors key represent installed port monitors."
    relevant_to: [T-017]
    tags: [persistence, registry, port-monitor, system, dll-load]

  - id: "ifeo-image-file-execution-options"
    name: "Image File Execution Options (IFEO) Persistence"
    category: attack-pattern
    description: "SEC670 describes the IFEO registry key (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options) as a Windows mechanism designed for process debugging and tracing. When a process matching a configured IFEO subkey is launched, Windows instead launches the configured debugger application, passing the original target as an argument. Malware authors abuse this by setting a Debugger value under a target executable's IFEO subkey so that launching the target executes the attacker's payload instead."
    relevant_to: [T-017]
    tags: [persistence, registry, ifeo, debugger, autostart]

  - id: "ace-string-layout"
    name: "ACE String Layout (SDDL Component)"
    category: windows-structure
    description: "SEC670 documents the ACE string layout used in Security Descriptor Definition Language (SDDL). An ACE string contains fields for ace_type (allow/deny), ace_flags (inheritance flags such as CI, OI), generic_rights, standard_rights, registry_rights, label_rights, and file_system_rights. Abbreviations include ACE.cc (create child), ACE.cd (delete child), ACE.od (delete), ACE.ad (delete), ACE.al (read/list), CC (create child), CD (delete child), CA (create all), CR (create right), CN (create new), CL (create list)."
    relevant_to: []
    tags: [sddl, ace, acl, security-descriptor, windows-structure, orphan]

  - id: "sddl-service-acl"
    name: "SDDL for Service Access Control"
    category: windows-structure
    description: "SEC670 presents an SDDL string configuring a service's DACL and SACL. The DACL denies delete, list, write, delete tree, and standard delete to interactive users (IU), service users (SU), and built-in admins (BA). It allows create, list, self-write, list object, control access, and read control to IU and SU, with broader permissions for local system (SY). The material suggests validating these configurations with PowerShell's Get-Service cmdlet."
    relevant_to: []
    tags: [sddl, service, dacl, sacl, acl, windows-structure, orphan]

  - id: "explicit-access-structure"
    name: "EXPLICIT_ACCESS_A Structure for ACL Modification"
    category: windows-structure
    description: "SEC670 documents the EXPLICIT_ACCESS_A structure used when programmatically modifying an object's ACL. The structure contains grfAccessPerms (DWORD specifying access permissions), grfAccessMode (ACCESS_MODE enum specifying grant, deny, set, revoke, etc.), grfInheritance (DWORD for inheritance flags), and Trustee (TRUSTEE_A structure identifying the user, group, or program the ACE applies to). The TRUSTEE_A structure identifies the principal against whom the access rule is applied."
    relevant_to: []
    tags: [acl, explicit-access, trustee, security-descriptor, windows-structure, orphan]

  - id: "securable-objects"
    name: "Securable Objects and SECURITY_ATTRIBUTES"
    category: windows-structure
    description: "SEC670 describes securable objects as objects with a corresponding security descriptor, including files, processes, registry keys, and threads. Most securable objects are created at the request of the user via system calls such as CreateProcess, CreateThread, and CreateFile. The creation functions accept a pointer to a SECURITY_ATTRIBUTES structure that specifies the security descriptor applied to the newly created object."
    relevant_to: [T-016]
    tags: [securable-objects, security-descriptor, security-attributes, windows-structure]

  - id: "se-backup-restore-acl-bypass"
    name: "SeBackupPrivilege and SeRestorePrivilege for ACL Bypass"
    category: os-internal
    description: "SEC670 presents SeBackupPrivilege (SE_BACKUP_NAME) and SeRestorePrivilege (SE_RESTORE_NAME) as privileges that grant file system access regardless of the object's ACL. The material frames these in the context of complete write access bypass of ACL restrictions, discussing SE_BACKUP_NAME, SE_RESTORE_NAME, and a non-standard SE_WRITE_NAME as candidate answers to a review question about ACL-bypassing write access. These privileges are not present in standard user tokens."
    relevant_to: []
    tags: [privilege-escalation, acl-bypass, se-backup, se-restore, windows-internals, orphan]
```

### Detection Insights

```yaml
detection:
  - indicator: "Registry value creation under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon Event ID 13 (RegistryValueSet) or Event ID 12 (RegistryCreate/Delete) fires when a new subkey or value is added under the Print Monitors registry path. The event captures the registry path, value name, and value data. A new DLL path under a Print Monitors subkey that does not correspond to a legitimately installed print monitor is anomalous."
    bypassed_by: "not discussed"

  - indicator: "Debugger value creation under IFEO registry key"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon Event ID 13 fires when a 'Debugger' string value is written under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target_exe>. The value data contains the path to the payload executable that will be launched instead of the target. IFEO Debugger values are rare on production systems outside debugging scenarios."
    bypassed_by: "not discussed"

  - indicator: "AdjustTokenPrivileges enabling SeDebugPrivilege"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-023]
    description: "Windows Security Event ID 4673 (Sensitive Privilege Use) or Event ID 4674 can capture when SeDebugPrivilege is enabled via AdjustTokenPrivileges. The event includes the calling process, target token, and privilege name. SeDebugPrivilege enablement by non-system processes is suspicious, though many legitimate administrative tools also trigger this."
    bypassed_by: "not discussed"

  - indicator: "Service SDDL modification via SetServiceObjectSecurity or sc.exe sdset"
    source: windows-security-log
    confidence: medium
    relevant_to: []
    description: "Windows Security Event ID 4670 (Permissions on an object were changed) fires when a service's security descriptor is modified. The event captures the object type (Service object), object name (service name), the modifying process, and the old and new SDDL strings. SDDL changes that grant service control permissions to non-admin principals are anomalous."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Suspicious Print Monitor DLL Registration"
    logsource: sysmon
    condition_summary: "EventID 13 where TargetObject contains 'HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors' and EventType is SetValue"
  - title: "IFEO Debugger Value Creation"
    logsource: sysmon
    condition_summary: "EventID 13 where TargetObject contains 'Image File Execution Options' and TargetObject endswith 'Debugger'"
  - title: "SeDebugPrivilege Enablement by Non-System Process"
    logsource: windows-security
    condition_summary: "EventID 4673 where PrivilegeList contains SeDebugPrivilege and SubjectUserName does not contain '$'"
```

### Operational Chains

```yaml
chains:
  - name: "Admin-to-SYSTEM via Token Stealing"
    description: "Escalate from local admin to SYSTEM by stealing the token of a SYSTEM process"
    steps:
      - technique: "enable SeDebugPrivilege via token-manipulation-api-triad"
        role: "LookupPrivilegeValue for SeDebugPrivilege LUID, OpenProcessToken on own token, AdjustTokenPrivileges to enable SeDebugPrivilege"
      - technique: "open SYSTEM process with PROCESS_QUERY_INFORMATION"
        role: "Use the now-enabled SeDebugPrivilege to open a SYSTEM-level process (e.g., winlogon.exe, csrss.exe) with token query access"
      - technique: "duplicate primary token from SYSTEM process"
        role: "OpenProcessToken on the SYSTEM process to extract its primary token, then DuplicateTokenEx to create a usable duplicate"
      - technique: "impersonate or launch with stolen token"
        role: "CreateProcessWithTokenW or SetThreadToken to operate under SYSTEM identity"
    notes: "SEC670 frames this as a lab exploring the steps and APIs for stealing a token to escalate privileges. Requires local admin token with SeDebugPrivilege present (may be disabled initially). T-016's handle-blocking evasion can interfere with the SYSTEM process open step."

  - name: "Port Monitor Registry Persistence to SYSTEM"
    description: "Persist a malicious DLL as a print monitor that loads as SYSTEM on reboot"
    steps:
      - technique: "obtain local admin privileges"
        role: "Prerequisite: SEC670 states the registry method requires local admin to modify the Print Monitors hive"
      - technique: "write DLL path to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<monitor_name>\Driver"
        role: "Register a malicious DLL as a port monitor by creating a subkey with a Driver value pointing to the payload DLL path"
      - technique: "trigger or wait for system reboot"
        role: "SEC670 states a system reboot is required for the print spooler to load the new monitor DLL"
      - technique: T-017
        role: "Alternative persistence vector to the vault's five-layer suite; DLL executes as SYSTEM via spoolsv.exe"
    notes: "SEC670 notes two methods exist for abusing port monitors; this chain covers the registry method. The reboot requirement introduces a timing constraint — the operator must either wait for a natural reboot or trigger one."

  - name: "IFEO Debugger Persistence"
    description: "Persist by configuring a debugger for a target executable that launches the payload instead"
    steps:
      - technique: "obtain write access to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        role: "Requires admin privileges to write under the HKLM IFEO key"
      - technique: "create IFEO subkey for target executable"
        role: "Create a subkey named after the target executable (e.g., sethc.exe, utilman.exe) under the IFEO key"
      - technique: "set Debugger value to payload path"
        role: "Write a REG_SZ value named 'Debugger' containing the full path to the attacker's payload executable"
      - technique: T-017
        role: "When the target executable is launched (by user or system trigger), Windows launches the Debugger payload instead, passing the original target path as an argument"
    notes: "SEC670 presents IFEO as a persistence mechanism abused by malware authors. Common target executables include accessibility tools (sethc.exe, utilman.exe) that can be triggered from the logon screen."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "privesc-token-stealing-coverage-gap"
    title: "Privilege Escalation via Token Stealing and Se*Privilege Abuse"
    kind: coverage-gap
    description: "SEC670 dedicates substantial material to Admin-to-SYSTEM escalation through Se*Privilege enablement (SeDebugPrivilege, SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege) and token stealing via the LookupPrivilegeValue/OpenProcessToken/AdjustTokenPrivileges triad. The vault has no dedicated privilege-escalation technique card. T-023 touches UAC bypass and credential harvest, and T-022 covers BYOVD which requires SeLoadDriverPrivilege, but the token-stealing primitive itself — opening a SYSTEM process, duplicating its token, and launching under it — is undocumented. This is a core red-team capability that would merit its own T-NNN card."
    would_relate_to: [T-016, T-022, T-023]
    source_units: ["unit 1", "unit 2", "unit 3", "unit 5", "unit 15"]
    tags: [privilege-escalation, token-stealing, se-debug, coverage-gap, privesc]

  - id: "port-monitor-persistence-proposed"
    title: "Port Monitor Registry Persistence as a T-017 Layer"
    kind: proposed-technique
    description: "SEC670 documents a persistence method via the HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors registry key that loads a DLL as SYSTEM through the print spooler on reboot. T-017's five-layer persistence suite covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include Port Monitor abuse. This is a distinct registry-vector persistence mechanism with its own requirements (local admin, reboot trigger) and detection signature (Print Monitors registry write). It would integrate naturally as a sixth persistence layer or a standalone T-NNN card."
    would_relate_to: [T-017]
    source_units: ["unit 8"]
    tags: [persistence, port-monitor, registry, proposed-technique]

  - id: "ifeo-persistence-proposed"
    title: "Image File Execution Options Persistence"
    kind: proposed-technique
    description: "SEC670 documents IFEO as a Windows registry key enabling debugger attachment on process launch, abused for persistence by setting a Debugger value under a target executable's IFEO subkey. The vault's T-017 persistence suite does not include IFEO. This is a well-known autostart mechanism (MITRE ATT&CK T1546.012) with a distinct registry signature and execution trigger model that differs from COM hijack and schtask. Worth a standalone card or integration into T-017's layer model."
    would_relate_to: [T-017]
    source_units: ["unit 9", "unit 6"]
    tags: [persistence, ifeo, registry, autostart, proposed-technique]

  - id: "security-descriptor-manipulation-coverage-gap"
    title: "Programmatic ACL and Security Descriptor Manipulation"
    kind: coverage-gap
    description: "SEC670 covers SDDL string construction, ACE string layout fields, the EXPLICIT_ACCESS_A structure, and the TRUSTEE_A structure as the programmatic interface for modifying object ACLs. The vault's techniques interact with security descriptors indirectly (e.g., T-016 handle blocking, T-017 persistence requiring specific ACLs on service objects) but do not document the structures and APIs for reading, writing, or modifying security descriptors as a first-class capability. This knowledge underpins service-permission modification, file ACL weakening, and registry-key permission changes that support persistence and privilege escalation."
    would_relate_to: [T-016, T-017]
    source_units: ["unit 7", "unit 25", "unit 26", "unit 24"]
    tags: [acl, sddl, security-descriptor, explicit-access, coverage-gap]

  - id: "se-backup-restore-acl-bypass-proposed"
    title: "SeBackup/SeRestore Privilege for ACL-Bypassing File Access"
    kind: proposed-technique
    description: "SEC670 presents SeBackupPrivilege and SeRestorePrivilege as privileges granting file system read/write access regardless of the object's DACL. These privileges enable a privileged operator to access or modify files protected by restrictive ACLs without changing the ACL itself — useful for credential file access (SAM/SYSTEM registry hives, NTDS.dit) and for modifying files owned by other principals. The vault does not document privilege-based ACL bypass as a technique. This would be a narrow but operationally significant capability for credential access and file manipulation chains."
    would_relate_to: [T-023]
    source_units: ["unit 16", "unit 17", "unit 20", "unit 21"]
    tags: [privilege-escalation, acl-bypass, se-backup, se-restore, proposed-technique]
```