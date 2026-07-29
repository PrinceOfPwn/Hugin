## Synthesis Summary

This batch of SANS SEC670 Book 3 (Operational Actions) material covers Windows privilege escalation fundamentals: integrity levels (S-1-16-0x0 through S-1-16-0x5000), token privilege manipulation via `OpenProcessToken`/`LookupPrivilegeValue`/`AdjustTokenPrivileges`, the `TOKEN_PRIVILEGES`/`LUID_AND_ATTRIBUTES`/`SE_PRIVILEGE_*` structures, ACL-bypassing privileges (`SeBackupPrivilege`, `SeRestorePrivilege`), admin-to-SYSTEM privilege sets (`SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeTakeOwnershipPrivilege`, `SeTcbPrivilege`, `SeCreateTokenPrivilege`), UAC Fusion manifest `autoElevate` research methodology, the Port Monitor registry persistence/LPE vector (`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`), and token-stealing labs (`TokenThief`). The material maps to T-021 (UAC bypass coverage), T-017 (persistence via Port Monitor registry), and T-022 (BYOVD via `SeLoadDriverPrivilege`). The gap the material fills is the Windows security model underpinnings that the vault's Rust source assumes: integrity level mechanics, the privilege LUID/attribute system, why `SeDebugPrivilege` enables cross-process handle acquisition, and how ACL checks interact with backup/restore privileges — none of which is visible in the syscall dispatch or injection source code.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "windows-integrity-levels"
    target: T-016
    type: concept_link
    rationale: "Integrity Level mechanics govern whether a process token can be used for handle blocking, PEB unlinking, and other T-016 evasion primitives against higher-IL targets — IL mediates cross-process access for many evasion APIs."

  - source: "se-debug-privilege"
    target: T-013
    type: requires
    rationale: "SEC670 explicitly states SeDebugPrivilege is the requirement for obtaining handles to system processes, which underpins process hollowing and several T-013 injection variants that need a writable handle to a protected target."

  - source: "se-debug-privilege"
    target: "token-stealing-lpe"
    type: enables
    rationale: "The TokenThief lab in SEC670 Book 3 uses SeDebugPrivilege to open wininit/winlogon/lsass, duplicate their SYSTEM token, and apply it to the caller — the entire token-stealing LPE chain hinges on this privilege being present and enabled."

  - source: "se-load-driver-privilege"
    target: T-022
    type: enables
    rationale: "The material identifies SeLoadDriverPrivilege as the privilege required to load device drivers, which is the user-mode entry point for the BYOVD pipeline covered in T-022."

  - source: "uac-fusion-autoelevate-manifest"
    target: T-021
    type: concept_link
    rationale: "SEC670 covers the autoElevate manifest element as the discovery surface for UAC bypass candidates; T-021 documents the CMSTP UAC bypass which is one realization of this research methodology."

  - source: "port-monitor-registry-persistence"
    target: T-017
    type: alternative_to
    rationale: "Port Monitor registry modification achieves both SYSTEM-level execution on reboot and persistence, making it functionally an alternative to the schtask/COM hijack/TLS callback layers in T-017 — same operational role, different persistence surface."

  - source: "se-backup-restore-privileges"
    target: "se-debug-privilege"
    type: concept_link
    rationale: "Both privilege families bypass normal ACL/security checks — backup/restore bypass file ACLs, SeDebug bypasses process security descriptors. The material groups them as the 'privileges that trump the standard check' pattern."

  - source: "token-stealing-lpe"
    target: T-013
    type: chains_to
    rationale: "Token stealing yields a SYSTEM token that can then be applied to spawn a new process for hollowing/injection, making it the precursor step to high-privilege variants of T-013 process injection."
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-integrity-levels"
    name: "Windows Integrity Levels (IL)"
    category: os-internal
    description: "Windows uses six integrity levels for privilege separation: Untrusted (S-1-16-0x0), Low (S-1-16-0x40), Medium (S-1-16-0x80), High (S-1-16-0x120), System (S-1-16-0x1000), and Protected (S-1-16-0x4000). Anonymous-group and AppContainer processes run at Untrusted; standard UAC user processes at Medium; UAC-elevated processes at High; wininit/winlogon/lsass at System; Protected is settable only by kernel-mode callers. The IL is queried via GetTokenInformation with TokenIntegrityLevel and mediates the no-write-up rule — lower-IL processes cannot write to higher-IL securable objects."
    relevant_to: [T-016, T-013]
    tags: [integrity-level, token, uac, privilege-separation, sid]

  - id: "se-backup-restore-privileges"
    name: "SeBackupPrivilege and SeRestorePrivilege — ACL Bypass"
    category: os-internal
    description: "Two privileges that bypass the standard file ACL check entirely: SeBackupPrivilege grants complete read access (FILE_GENERIC_READ equivalent) regardless of the file's DACL, and SeRestorePrivilege grants complete write access (FILE_GENERIC_WRITE equivalent). Unlike most privileges which still require a subsequent privilege check, these two skip the ACL evaluation step. Documented in winnt.h as SE_BACKUP_NAME and SE_RESTORE_NAME, typically granted to Backup Operators and Administrators."
    relevant_to: []
    tags: [orphan, privilege, acl-bypass, file-system, lpe]

  - id: "se-debug-privilege"
    name: "SeDebugPrivilege — Cross-Process Handle Acquisition"
    category: os-internal
    description: "SeDebugPrivilege (SE_DEBUG_NAME) grants the right to open any process handle with PROCESS_ALL_ACCESS regardless of the process's security descriptor. Without it, OpenProcess on wininit/winlogon/lsass or other PPL-adjacent system processes fails with access denied. Standard user tokens do not have this privilege present; High-IL admin tokens have it present but disabled by default and enable it on demand via AdjustTokenPrivileges. It is the privilege-level enabler for token theft, process hollowing into system processes, and LSASS access for credential dumping."
    relevant_to: [T-013, T-022, T-023]
    tags: [privilege, debug, process-handle, lpe, token-theft]

  - id: "se-load-driver-privilege"
    name: "SeLoadDriverPrivilege — User-Mode Driver Loading"
    category: os-internal
    description: "SeLoadDriverPrivilege (SE_LOAD_DRIVER_NAME) authorizes loading and unloading device drivers via NtLoadDriver/NtUnloadDriver from user mode. Standard users lack it; administrators have it present-disabled. SEC670 explicitly identifies this privilege as the user-mode entry point for driver loading operations, making it the prerequisite for BYOVD chains and kernel-attack surfaces that load a vulnerable signed driver as a stepping stone."
    relevant_to: [T-022]
    tags: [privilege, driver-loading, byovd, kernel-attack-surface]

  - id: "admin-to-system-privilege-set"
    name: "Admin-to-SYSTEM Privilege Escalation Set"
    category: attack-pattern
    description: "SEC670 identifies five privileges that enable escalation from Administrator to SYSTEM: SeTakeOwnershipPrivilege (take ownership of any securable object), SeTcbPrivilege (act as part of the Trusted Computing Base), SeCreateTokenPrivilege (create tokens), SeLoadDriverPrivilege (load kernel drivers), and SeDebugPrivilege (open any process). These are not present on standard user tokens — only on admin/elevated tokens. Any one of them, when enabled, provides a distinct path from High-IL admin to System-IL."
    relevant_to: []
    tags: [orphan, privilege-escalation, admin-to-system, lpe, privilege]

  - id: "token-privilege-manipulation-api-sequence"
    name: "Token Privilege Manipulation API Sequence"
    category: attack-pattern
    description: "The canonical three-API sequence for enabling a privilege on a token: OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES, &tokenHandle) obtains the token handle; LookupPrivilegeValue(NULL, SE_*_NAME, &luid) resolves the privilege name to its LUID; AdjustTokenPrivileges(tokenHandle, FALSE, &newState, ...) flips the SE_PRIVILEGE_ENABLED attribute on that LUID entry inside the TOKEN_PRIVILEGES structure. The Boolean return of AdjustTokenPrivileges does not indicate success — GetLastError must be checked for ERROR_NOT_ALL_ASSIGNED when the privilege is not present in the token."
    relevant_to: [T-013, T-022]
    tags: [api-sequence, token, privilege, lpe, win32-api]

  - id: "token-privileges-luid-structure"
    name: "TOKEN_PRIVILEGES and LUID_AND_ATTRIBUTES Structures"
    category: windows-structure
    description: "TOKEN_PRIVILEGES contains a count and an array of LUID_AND_ATTRIBUTES entries. Each LUID_AND_ATTRIBUTES pairs a LUID (locally unique identifier, a 64-bit value split into LowPart DWORD and HighPart LONG) that names the privilege with a DWORD of attribute flags: SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS. Privileges are not tied to specific objects — they gate system-wide operations like shutdown, driver loading, and debug access."
    relevant_to: []
    tags: [orphan, windows-structure, token, privilege, luid]

  - id: "uac-fusion-autoelevate-manifest"
    name: "UAC Fusion Manifest and autoElevate Element"
    category: os-internal
    description: "During CreateProcess, Windows consults the Fusion database to read an application's XML manifest embedded as a resource. The manifest contains elements including requestedExecutionLevel, uiAccess, heapType, and autoElevate. When autoElevate is set to true on a signed, Windows-located binary, the binary is launched at High-IL without a UAC consent prompt — this is the auto-elevation mechanism UAC bypass research targets. SEC670 Lab 3.7 (UACBypass-Research) uses Process Monitor to find system binaries with autoElevate=true and weaponizes their IPC or registry interactions to coerce them into performing privileged actions on the attacker's behalf."
    relevant_to: [T-021]
    tags: [uac, manifest, autoelevate, fusion, lpe, uac-bypass]

  - id: "uac-elevation-prompt-color-coding"
    name: "UAC Consent Prompt Color Coding"
    category: defense-mechanism
    description: "UAC consent prompts use title-bar color to signal trust level: blue indicates a Microsoft-signed and Windows-trusted binary; yellow indicates a signed but non-Microsoft publisher; red indicates an unsigned binary. The color is a visual heuristic to alert the user to elevation risk — blue prompts auto-approve more readily than red. The prompt color is determined by signature verification and publisher reputation, not by the requested privilege level itself."
    relevant_to: []
    tags: [orphan, uac, defense-mechanism, signature-verification]

  - id: "port-monitor-registry-persistence"
    name: "Port Monitor Registry Persistence / LPE"
    category: attack-pattern
    description: "Abuse of HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors — adding a subkey whose Driver value points to a malicious DLL in System32\\ causes the spooler to load that DLL as a port monitor at service startup or reboot. Requires local admin to write the key and survives reboot. The loaded DLL runs in the spooler service context, which is LocalSystem, yielding SYSTEM-level code execution. SEC670 identifies this as both a persistence and LPE primitive — same key modification achieves both."
    relevant_to: [T-017]
    tags: [persistence, lpe, registry, port-monitor, spooler, system-dll, reboot]

  - id: "token-stealing-lpe"
    name: "Token Stealing (TokenThief) LPE Pattern"
    category: attack-pattern
    description: "Privilege escalation by duplicating another process's primary token and applying it to a new process. SEC670 Lab 3.5 (TokenThief): with SeDebugPrivilege enabled, open winlogon.exe or another System-IL process, call OpenProcessToken, DuplicateTokenEx to produce a primary token, then CreateProcessWithTokenW to spawn a child under that token. The spawned process inherits the source's IL and group membership — yielding a System-IL process from a High-IL admin context. This is the conceptual basis of Meterpreter's getsystem technique 1 (named pipe impersonation) and technique 3 (token duplication)."
    relevant_to: [T-013]
    tags: [lpe, token-stealing, getsystem, impersonation, admin-to-system]

  - id: "explicit-access-structure"
    name: "EXPLICIT_ACCESS_A Structure for ACL Modification"
    category: windows-structure
    description: "EXPLICIT_ACCESS_A describes one access-control entry for a trustee, pairing grfAccessPermissions (DWORD of access rights), grfAccessMode (ACCESS_MODE enum: GRANT_ACCESS, DENY_ACCESS, SET_AUDIT_SUCCESS, etc.), grfInheritance (DWORD inheritance flags), and TRUSTEE_A (the user/group/program to apply against). Used by SetEntriesInAcl to build a new ACL programmatically. SEC670 references it as the primary structure for modifying ACLs on securable objects from custom tools."
    relevant_to: []
    tags: [orphan, windows-structure, acl, security-descriptor, trustee]

  - id: "securable-objects-security-attributes"
    name: "Securable Objects and SECURITY_ATTRIBUTES"
    category: os-internal
    description: "Processes, threads, files, registry keys, and kernel objects are securable — each carries a security descriptor. The Create* family of Win32 APIs (CreateProcess, CreateThread, CreateFile, CreateMutex, etc.) accepts an optional SECURITY_ATTRIBUTES pointer; when NULL, the object inherits the descriptor from the parent process or service. The descriptor contains the owner SID, group SID, DACL (discretionary access list), and SACL (system audit list). Modifying the SECURITY_ATTRIBUTES at creation is the mechanism by which implants produce objects with permissive DACLs to evade cross-process handle inspection."
    relevant_to: [T-013, T-016]
    tags: [securable-objects, security-descriptor, acl, dacl, sacl, win32-api]
```

### Detection Insights

```yaml
detection:
  - indicator: "Registry modification under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors adding a subkey with a Driver value pointing to a DLL outside the standard print monitor set"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon Event ID 4656/4663 (registry value set) or Event ID 12/13/14 (registry object add/set) on the Print\\Monitors hive. A Driver value pointing to a non-Microsoft DLL path in System32, especially one written recently, is a strong port-monitor persistence indicator. Correlate with the spooler service PID loading the named DLL — Sysmon Event ID 7 (image loaded) on spoolsv.exe."
    bypassed_by: "not discussed"

  - indicator: "AdjustTokenPrivileges enabling SeDebugPrivilege on a non-system process token"
    source: etw
    confidence: medium
    relevant_to: [T-013, T-022]
    description: "The Microsoft-Windows-Kernel-Audit-APIcalls ETW provider (or token audit policy events) reports privilege state changes. A standard application process enabling SeDebugPrivilege is anomalous — typical applications never call AdjustTokenPrivileges on SeDebugPrivilege. Correlate with subsequent OpenProcess calls to winlogon/lsass PIDs as a token-theft precursor."
    bypassed_by: "not discussed"

  - indicator: "OpenProcess with PROCESS_ALL_ACCESS on a System-IL process PID from a non-system caller"
    source: kernel-callback
    confidence: high
    relevant_to: [T-013]
    description: "ObRegisterCallbacks pre-operation callback on PsProcessType fires when any handle to a process is opened. A High-IL admin process opening winlogon.exe or lsass.exe with PROCESS_ALL_ACCESS, particularly after AdjustTokenPrivileges enabled SeDebugPrivilege, is the token-stealing precursor. EDR products with ObRegisterCallbacks observe this regardless of userland hooks."
    bypassed_by: "not discussed"

  - indicator: "Process spawned with SYSTEM token SID from a non-SYSTEM parent process"
    source: windows-security-log
    confidence: high
    relevant_to: []
    description: "Windows Security Event ID 4688 (process created) with the SubjectUserSid in SYSTEM but the parent process subject in a user or admin SID — indicates CreateProcessWithTokenW or CreateProcessAsUser with a duplicated SYSTEM token. The mismatch between child token SID and parent token SID is the token-theft signature."
    bypassed_by: "not discussed"

  - indicator: "whoami /priv output showing SeDebugPrivilege, SeLoadDriverPrivilege, or SeTakeOwnershipPrivilege present on a non-admin session"
    source: behavioral
    confidence: medium
    relevant_to: []
    description: "Forensic post-compromise indicator — these privileges are not present on standard user tokens. Their presence on a token whose user is not in Administrators suggests either token manipulation, group membership tampering, or service-account abuse. The SEC670 material documents whoami /priv as the operator's reconnaissance command to verify their privilege state — same indicator works for the defender post-compromise."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Print Monitor Registry Persistence — New Driver Value"
    logsource: sysmon
    condition_summary: "EventID 13 (registry value set) where TargetObject contains 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors' and ValueType is 'REG_SZ' and Details endswith '.dll'"

  - title: "Non-Standard Parent for SYSTEM Process"
    logsource: windows-security
    condition_summary: "EventID 4688 where SubjectUserName matches 'SYSTEM' and ParentProcessName does not match services.exe, smss.exe, wininit.exe, csrss.exe, or other known SYSTEM-spawning parents"

  - title: "SeDebugPrivilege Enablement by Non-System Process"
    logsource: etw
    condition_summary: "Microsoft-Windows-Kernel-Audit-APIcalls event for AdjustTokenPrivileges where PrivilegeName is 'SeDebugPrivilege' and CallerProcessName is not in {lsass.exe, csrss.exe, svchost.exe}"
```

### Operational Chains

```yaml
chains:
  - name: "Admin-to-SYSTEM via Token Stealing"
    description: "Standard chain for High-IL admin to System-IL process via duplicated primary token"
    steps:
      - technique: "token-privilege-manipulation-api-sequence"
        role: "Open own process token, resolve SeDebugPrivilege LUID, enable it via AdjustTokenPrivileges"
      - technique: "se-debug-privilege"
        role: "Privilege now enabled permits OpenProcess on winlogon/lsass with PROCESS_QUERY_INFORMATION"
      - technique: "token-stealing-lpe"
        role: "OpenProcessToken on the System-IL target, DuplicateTokenEx to produce a primary token, CreateProcessWithTokenW to spawn a System-IL child"
    notes: "Requires High-IL admin token (UAC-elevated) as the starting point. SeDebugPrivilege must be present (not just enabled) in the token — admins have it present-disabled, standard users do not have it at all. SEC670 Lab 3.5 TokenThief documents this end-to-end."

  - name: "UAC Bypass via autoElevate Binary Weaponization"
    description: "Discover and weaponize a signed autoElevate binary to coerce High-IL execution without consent prompt"
    steps:
      - technique: "uac-fusion-autoelevate-manifest"
        role: "Enumerate System32 binaries, extract manifests, identify candidates with autoElevate=true"
      - technique: "Process Monitor behavioral analysis"
        role: "Run the binary under ProcMon and observe registry/file/IPC operations it performs on attacker-writable locations"
      - technique: T-021
        role: "Weaponize the discovered interaction — e.g., CMSTP bypass, DLL hijack on the autoElevate binary's search path, or COM interface abuse"
    notes: "SEC670 Lab 3.7 (UACBypass-Research) outlines the methodology. Starting point is Medium-IL standard user; the discovered bypass must avoid triggering the consent UI which means the manipulation must remain within the auto-elevation trust boundary. Result is a High-IL process without a UAC prompt."

  - name: "Port Monitor Registry Persistence to SYSTEM"
    description: "Persist a malicious DLL via the Print Monitors registry key for SYSTEM-level execution on reboot"
    steps:
      - technique: "privilege elevation to local admin"
        role: "Obtain local admin rights (any LPE chain) — required to write HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"
      - technique: "dll staging in System32"
        role: "Place the malicious DLL in C:\\Windows\\System32\\ — spooler only loads port monitors from System32"
      - technique: "port-monitor-registry-persistence"
        role: "Add a registry subkey under Print\\Monitors with a Driver value naming the staged DLL"
      - technique: "reboot or spooler service restart"
        role: "Triggers spooler to enumerate the Monitors key and load each Driver DLL as a port monitor — runs as LocalSystem"
    notes: "SEC670 documents this requires local admin and a system reboot to execute. The DLL must export the InitializePrintMonitor2 (or the older InitializePrintMonitor) entry point or the spooler rejects it. This is simultaneously a persistence primitive (survives reboot) and an LPE primitive (admin-to-SYSTEM)."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "proposed-port-monitor-persistence-card"
    title: "Port Monitor Registry Persistence / LPE"
    kind: proposed-technique
    description: "SEC670 Book 3 documents the HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors registry persistence and LPE technique in detail — add a subkey with a Driver value pointing to a System32 DLL, reboot, spooler loads the DLL as LocalSystem. This is a distinct primitive from the schtask/COM hijack/NTFS EA/TLS callback/PhantomPersist layers in T-017. It deserves its own T-NNN card because it uniquely combines persistence (survives reboot) with LPE (admin-to-SYSTEM via the spooler service context) and has a specific entry-point export requirement (InitializePrintMonitor2) that shapes the payload."
    would_relate_to: [T-017]
    source_units: ["unit 15", "unit 16"]
    tags: [persistence, lpe, port-monitor, spooler, registry, proposed-technique]

  - id: "proposed-token-stealing-lpe-card"
    title: "Token Stealing (TokenThief) Admin-to-SYSTEM LPE"
    kind: proposed-technique
    description: "SEC670 Lab 3.5 TokenThief walks through the full OpenProcess + OpenProcessToken + DuplicateTokenEx + CreateProcessWithTokenW sequence to spawn a System-IL child from a High-IL admin context. The vault's T-013 (Remaining Methods) covers process hollowing and injection but not token duplication as a privilege escalation vector in its own right. This would be a distinct T-NNN card because it operates at a different layer — token manipulation, not memory injection — and is the conceptual basis for Meterpreter's getsystem techniques."
    would_relate_to: [T-013, T-015]
    source_units: ["unit 7", "unit 10", "unit 17", "unit 18"]
    tags: [lpe, token-stealing, getsystem, admin-to-system, proposed-technique]

  - id: "proposed-acl-bypass-privilege-card"
    title: "SeBackupPrivilege / SeRestorePrivilege ACL Bypass"
    kind: proposed-technique
    description: "SEC670 explicitly calls out SeBackupPrivilege and SeRestorePrivilege as the two privileges that bypass the standard ACL check entirely — granted complete read or write access regardless of the file's DACL. The vault does not currently cover file-ACL bypass as a standalone technique. This would merit its own T-NNN card because it is a distinct operational primitive (read SAM/SYSTEM registry hives from disk, read restricted user files, write to ACL-protected locations) used in the post-exploitation phase rather than the injection phase."
    would_relate_to: []
    source_units: ["unit 5", "unit 12", "unit 20", "unit 37", "unit 38"]
    tags: [acl-bypass, privilege, file-system, lpe, proposed-technique]

  - id: "gap-uac-bypass-research-methodology"
    title: "UAC Bypass Discovery Methodology Coverage Gap"
    kind: coverage-gap
    description: "T-021 documents the CMSTP UAC bypass as a finished technique, but SEC670 Lab 3.7 documents the broader discovery methodology: enumerate System32 binaries, extract manifests, find autoElevate=true, run under Process Monitor, find an attacker-writable interaction, weaponize. The vault lacks coverage of this discovery pipeline — operators get one bypass but not the methodology for finding new ones when CMSTP is detected or patched. Coverage gap because the operational knowledge (how to research a new bypass) is missing alongside the technique itself."
    would_relate_to: [T-021]
    source_units: ["unit 9", "unit 13"]
    tags: [uac, uac-bypass, research-methodology, coverage-gap, process-monitor]

  - id: "cross-source-convergence-admin-to-system-privilege-set"
    title: "Admin-to-SYSTEM Privilege Escalation Set Convergence"
    kind: cross-source-convergence
    description: "SEC670, MalDev Academy, and CRTO all converge on the same five-privilege set (SeTakeOwnership, SeTcb, SeCreateToken, SeLoadDriver, SeDebug) as the canonical admin-to-SYSTEM escalation paths. Each course treats these as the answer to 'I have admin, how do I get SYSTEM?' The vault currently does not surface this privilege-set-as-escalation-paths pattern in any single technique card — the knowledge is scattered across T-022 (SeLoadDriver via BYOVD), T-013 (SeDebug via process hollowing), and unmentioned elsewhere. Worth surfacing as cross-cutting metadata on what each admin-tier privilege enables."
    would_relate_to: [T-013, T-022, T-016]
    source_units: ["unit 39", "unit 40"]
    tags: [privilege, admin-to-system, convergence, se-debug, se-load-driver, se-take-ownership]
```