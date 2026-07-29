Let me analyze the task carefully.

I need to produce a technique card for T-044: Service-Based Local Privilege Escalation via SCM Enumeration.

Key inputs:
1. Cluster spec: T-044, category `privesc`, tier `A`, member notes `lgtm:proposed-technique-service-lpe-enumeration` and `lgtm:service-based-lpe-proposed-technique`
2. Related cards: T-017, T-020, T-023
3. Matching source files: `src/client_rust/src/byakugan.rs`, `src/dark_crystal/crates/core/src/experimental/api_hammering.rs`, `src/dark_crystal/crowd/src/kaguya.rs`
4. Atlas material: atlas-privesc-part2.md and atlas-privesc-part3.md

First: verify source files. Do any of them implement service-based LPE via SCM enumeration?

- `byakugan.rs`: Network recon — ARP scan, port scan, banner grab, AD enumeration, passive discovery. No SCM interaction, no service enumeration via OpenSCManager/EnumServicesStatus. Does NOT implement this technique.
- `api_hammering.rs`: Anti-sandbox time-wasting. It does walk `SYSTEM\CurrentControlSet\Services` registry key but only enumerates the first 20 subkeys as a time sink — it does not query service configurations, ImagePaths, DACLs, or perform any LPE logic. Does NOT implement this technique.
- `kaguya.rs`: LOtL binary inventory + EDR detection. Uses NtOpenFile to check binary existence, NtQuerySystemInformation for process enumeration. No SCM/service enumeration for LPE. Does NOT implement this technique.

So: **no current implementation in the HUGIN source**. I must state that clearly, and set `source_file: none` and `crate: none`.

Now, the atlas material gives me:
- SEC670 units 9-16: Windows services as privesc surface. Services interact with SCM, run without user logon, can start at boot. Examples: schedule, EventLog, BITS, gupdate, iphlpsvc.
- OpenSCManager API to get handle to SCM database. Handles: SCManager, Service, Database lock.
- EnumServicesStatus and QueryServiceStatus for enumeration.
- Unquoted service path LPE, weak permissions, CVE-2019-1322 (referenced as example service-configuration LPE).
- sc.exe sdshow to view a service's security descriptor (BITS example), SDDL and ace_strings to interpret.
- ACE string layout: ace_type (A, D, OA, OD, AU, AL), ace_flags (CI, OI, NP, IO, ID, SA), generic rights (GA, GR, GW, GX), standard rights (RC, SD, WD, WO), directory rights (RP, WP, CC, DC, LC, SW), registry rights (KA, KR, KW, KX), file rights (FA, FR...).
- SDDL exercise: DACL with deny ACEs for IU (interactive user), SU (service user), BA (built-in admins), allow ACEs for IU, SU, SY (local system). SIDs: IU, SU, BA, SY.
- GetNamedSecurityInfoA: retrieves security descriptor for NTFS objects, services, keys, shares, file-mapping objects. Parameters: pObjectName, SE_OBJECT_TYPE, SECURITY_INFORMATION, ppsidOwner, ppsidGroup, ppDacl, ppSacl, pSecDscrptr.
- SetNamedSecurityInfoA: applies changes.
- EXPLICIT_ACCESS_A structure: grfAccessPerms, grfAccessMode, grfInheritance, Trustee.
- CRTO: Service Binary Permissions — Get-Acl on service paths, "Allow: Modify, Synchronize" — binary permission issues leading to privesc.
- Privilege material: LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges for SeDebugPrivilege.
- HKLM\SYSTEM\CurrentControlSet\Services registry location.
- Services are managed via RPC (SCM is an RPC server).

MITRE mapping: The best fit for service-based LPE... Options:
- T1543.003 (Create or Modify System Process: Windows Service) — that's more persistence/privesc via creating/modifying services.
- T1574 (Hijack Execution Flow) — sub-techniques: T1574.005? No. Unquoted service path is T1574.009 (Path Interception by Unquoted Path). Weak service permissions → T1574.011? Actually:
  - T1574.009 Path Interception by Unquoted Path — yes, unquoted service path.
  - T1574.011 Services Registry Permissions Weakness — weak service registry permissions.
  - T1574.010 Services File Permissions Weakness — weak binary permissions.
  - T1543.003 Windows Service — create/modify service.
  - T1068 Exploitation for Privilege Escalation — CVE-2019-1322.

The technique is primarily about exploiting weak service configurations. The consolidated description says: "identify services running as SYSTEM or with weak binary permissions, and exploit unquoted service paths or weak DACL/ACL". The single best-fit MITRE ID... The primary mechanism across the material is hijacking execution flow via weak service configurations. T1574 (Hijack Execution Flow) is the parent. Given the cluster spec covers unquoted path + weak service permissions + weak binary permissions, I could pick T1574.011 (Services Registry Permissions Weakness) or T1574.010 (Services File Permissions Weakness) or T1574.009 (unquoted path).

Hmm. The canonical name is "Service-Based Local Privilege Escalation via SCM Enumeration". The technique spans: enumeration + multiple exploitation primitives. The best single ID: I'd argue T1543.003 (Windows Service) is about creating/modifying services for persistence/privesc. But the focus here is exploiting existing weak service configurations, which maps to T1574's sub-techniques. 

Actually let me think about which is the "single best-fit". The card covers:
1. SCM enumeration (discovery-ish, T1007 System Service Discovery is the enumeration part)
2. Unquoted path exploitation → T1574.009
3. Weak service DACL (service object permissions, modifiable via sc sdset / SetNamedSecurityInfoA) → this is T1574.011 Services Registry Permissions Weakness? Actually T1574.011 is about weak permissions on the service's registry key allowing ImagePath modification. Weak service object DACL (SERVICE_CHANGE_CONFIG granted to low-priv user) also maps to T1543.003 in some writeups... ATT&CK T1574.011: "Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services... adversaries may abuse weaknesses in the permissions of the Registry entries." Service security descriptor weakness maps to T1543.003 (Create or Modify System Process: Windows Service) since modifying binPath via sc config requires SERVICE_CHANGE_CONFIG. 

Given the span, I'll pick `T1574.011` as primary? Or T1543.003? Let me reconsider. The MITRE IDs I'm confident about:
- T1543.003 — Create or Modify System Process: Windows Service. Real.
- T1574.009 — Path Interception by Unquoted Path. Real.
- T1574.010 — Services File Permissions Weakness. Real.
- T1574.011 — Services Registry Permissions Weakness. Real.
- T1007 — System Service Discovery. Real.
- T1068 — Exploitation for Privilege Escalation. Real.

The format allows `mitre: T####.###` single best fit plus `mitre_secondary` list. The core exploitation primitive that covers most of the material (weak service permissions DACL allowing config change, weak binary permissions, unquoted path) — the parent T1574 Hijack Execution Flow? The instruction says "pick the single best-fit ATT&CK technique ID". 

The technique as described: enumerate services, find ones running as SYSTEM with weak binary perms or unquoted paths or weak DACLs, exploit. The single best fit covering "weak service configuration exploitation" — I'd say T1574.011 (Services Registry Permissions Weakness) is one primitive, T1574.010 (Services File Permissions Weakness) is the binary replacement primitive. The cluster emphasizes "unquoted service paths or weak DACL/ACL". Weak DACL/ACL → file permissions weakness (T1574.010) for binary path replacement, or service object DACL → change config → T1543.003.

I'll use primary: T1574.011? Hmm, no. Let me think about what the material emphasizes most. SEC670 units: OpenSCManager handles, EnumServicesStatus, QueryServiceStatus, unquoted path LPE, weak permissions, CVE-2019-1322, sc.exe sdshow SDDL analysis of service security descriptors. CRTO: service binary permissions Get-Acl "Allow: Modify".

The unifying primitive: services as execution-hijack surface. I think the best primary is T1574.010 (Services File Permissions Weakness)? Or unquoted path T1574.009?

Actually — the consolidated description lists: "identify services running as SYSTEM or with weak binary permissions, and exploit unquoted service paths or weak DACL/ACL". The service DACL (security descriptor shown by sc sdshow) weakness → attacker with SERVICE_CHANGE_CONFIG reconfigures binPath → that's "Modify System Process: Windows Service" T1543.003. The weak binary permissions → T1574.010. Unquoted path → T1574.009.

Given the SDDL/service security descriptor analysis is heavily emphasized in the atlas material (units 37-39 of part2, plus unit 1-2 of part3 SetNamedSecurityInfoA/EXPLICIT_ACCESS_A), and sc.exe config modification is the exploitation path, I lean toward T1543.003 as primary (create or modify Windows Service — modification of existing service config via weak DACL), with secondary T1574.009, T1574.010, T1574.011, T1007, T1068.

Hmm, but T1543.003 in ATT&CK is primarily a persistence + privesc technique where adversaries create or modify services. Modifying binPath of an existing weakly-secured service = T1543.003 per ATT&CK examples ("sc config upnphost binpath=..."). Yes, ATT&CK T1543.003 explicitly mentions modifying existing services' binPath with sc config. So T1543.003 is a defensible primary.

Alternatively the enumeration focus suggests T1007. But the card is about the full LPE flow, not just discovery. I'll go:

mitre: T1543.003
mitre_secondary: [T1574.009, T1574.010, T1574.011, T1007]

CVE-2019-1322 → that's exploitation for privilege escalation T1068; it was a UPnP service (upnphost) misconfiguration LPE — actually CVE-2019-1322 was a Windows UPnP Service elevation of privilege vulnerability where the service ran a command as SYSTEM that could be influenced by a low-priv user (the "upnphost" service would execute a scheduled task / it related to the UPnP Device Host service deleting/executing files...). Let me recall: CVE-2019-1322 "Windows UPnP Service Elevation of Privilege Vulnerability". The material just references it as "an example service-configuration LPE". I should describe it only as the material does — an example service-configuration LPE referenced by SEC670. I shouldn't invent deep details. I can say: the material cites CVE-2019-1322 as a worked example of a service-configuration LPE. Keep it at that level.

Now structure the card.

Frontmatter:
```yaml
---
id: T-044
name: Service-Based LPE via SCM Enumeration and Weak Service Configuration
category: privesc
tier: A
crate: none
source_file: none
mitre: T1543.003
mitre_secondary: [T1574.009, T1574.010, T1574.011, T1007]
tags: [privesc, services, scm, sddl, unquoted-path, service-dacl, imagepath, enum-services]
origin: atlas-synthesis
member_notes: [lgtm:proposed-technique-service-lpe-enumeration, lgtm:service-based-lpe-proposed-technique]
---
```

Name: 4-8 words. "Service-Based Local Privilege Escalation via SCM Enumeration" — that's 8 words (Service-Based(1) Local(2) Privilege(3) Escalation(4) via(5) SCM(6) Enumeration(7)) — 7 words. Good, keep canonical name.

Tags: 5-10 kebab-case. e.g. [privesc, windows-services, scm, unquoted-path, service-dacl, sddl, imagepath-hijack, binary-permissions, service-enumeration]. That's 9.

H1: `# Service-Based Local Privilege Escalation via SCM Enumeration — Hijacking Weakly Configured Services for SYSTEM Execution`

## Summary
3-5 sentences. First sentence standalone. What it does, OS primitive, why operator uses, primary detection surface.

## Mechanism
Numbered steps:
1. Open handle to SCM database: OpenSCManager(lpMachineName, SERVICES_ACTIVE_DATABASE/"ServicesActive", dwDesiredAccess e.g. SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT).
2. Enumerate services: EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, ...) returning ENUM_SERVICE_STATUS array with lpServiceName, lpDisplayName, ServiceStatus.dwCurrentState.
3. For each service: OpenService(hSCM, lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL).
4. QueryServiceConfig → QUERY_SERVICE_CONFIG with lpBinaryPathName (BINARY_PATH_NAME), dwStartType (SERVICE_AUTO_START), lpServiceStartName (account: LocalSystem = NT AUTHORITY\SYSTEM). QueryServiceStatus / QueryServiceStatusEx → SERVICE_STATUS_PROCESS dwProcessId, dwCurrentState.
5. Filter candidates: services running as LocalSystem (or other privileged accounts), auto-start, in paths writable by the operator.
6. Unquoted path check: lpBinaryPathName containing spaces without surrounding quotes (e.g. `C:\Program Files\Sub Dir\service.exe`) → CreateProcess resolution order tries `C:\Program.exe`, `C:\Program Files\Sub.exe` before the full path. Operator checks write access on each prefix location.
7. Binary permissions check: Get-Acl / GetNamedSecurityInfoA on the resolved binary path; look for Allow: Modify/Write (F, M) for the operator's SID or broad groups (Authenticated Users, Everyone, Users). CRTO: "Allow: Modify, Synchronize".
8. Service DACL check: sc.exe sdshow <service> or QueryServiceObjectSecurity / GetNamedSecurityInfoA with SE_SERVICE; parse SDDL; look for ACEs granting RP/WP (SERVICE_CHANGE_CONFIG 0x0002), CC? Wait — for services, the SDDL rights letters: CC = SERVICE_QUERY_CONFIG, LC = SERVICE_QUERY_STATUS? Let me recall the actual service-specific SDDL rights:
   - CC — SERVICE_QUERY_CONFIG
   - DC — SERVICE_CHANGE_CONFIG
   - LC — SERVICE_QUERY_STATUS
   - SW — SERVICE_ENUMERATE_DEPENDENTS
   - LO? Hmm. Let me get this right:
   
   Service object SDDL rights mapping (documented):
   - CC = SERVICE_QUERY_CONFIG (0x0001)
   - DC = SERVICE_CHANGE_CONFIG (0x0002)
   - LC = SERVICE_QUERY_STATUS (0x0004)
   - SW = SERVICE_ENUMERATE_DEPENDENTS (0x0008)
   - RP = SERVICE_START (0x0010)
   - WP = SERVICE_STOP (0x0020)
   - DT = SERVICE_PAUSE_CONTINUE (0x0040)
   - LO = SERVICE_INTERROGATE (0x0080)
   - CR = SERVICE_USER_DEFINED_CONTROL (0x0100)
   - plus standard rights: RC (READ_CONTROL), SD (DELETE), WD (WRITE_DAC), WO (WRITE_OWNER)
   
   Cross-check with the atlas material unit 38: "(A;;CCLCSWLOCRRC;;;IU) interactive user, allow: create, list, selfwrite, list obj, control access, read control" — the material glosses CCLCSWLOCRRC loosely as "create, list, selfwrite, list obj, control access, read control". And the deny ACE "DCLCWPDTSD" glossed as "delete, list, write, delete tree, standard delete". The material's glosses are approximate. I should describe the SDDL as the material does and name the precise documented mapping where I'm confident. Per rule 4, well-established Windows documentation is allowed. The service SDDL rights mapping above is well-established (MSDN "Service Security and Access Rights" / SDDL rights strings). I'm confident: DC = SERVICE_CHANGE_CONFIG is the dangerous one, WP = SERVICE_STOP, RP = SERVICE_START, DT = pause/continue, SD = standard delete.

   Unit 38: "D: DACL (D;;DCLCWPDTSD;;;IU)" — contains DC (change config), LC (query status), WP (stop), DT (pause continue), SD (delete) as DENY for interactive user. And allow "(A;;CCLCSWLOCRRC;;;IU)" = CC (query config), LC (query status), SW (enumerate dependents), LO (interrogate), CR (user defined control), RC (read control). And SY gets "CCLCSWRPWPDTLOCRRC" = +RP (start), +WP (stop), +DT. This aligns with the documented mapping. Good — I can decode the exercise SDDL with the real rights letters and note the material presents it as a worked exercise.

9. Exploitation paths:
   a. Unquoted path: place executable at a prefix location (e.g. C:\Program.exe) in a directory where the operator has write access; on service start/restart, SCM's CreateProcess resolves the prefix binary first → runs as the service account (SYSTEM).
   b. Weak binary permissions: replace or patch the service binary (retain original as needed / copy payload over), then trigger restart via sc stop/start if SERVICE_STOP/SERVICE_START (WP/RP) are granted, or wait for reboot.
   c. Weak service DACL: if DACL grants DC (SERVICE_CHANGE_CONFIG) → reconfigure: ChangeServiceConfig(hService, ..., lpBinaryPathName = attacker command) or sc.exe config <service> binpath= <cmd>; then start the service.
   d. Registry-level: weak ACL on HKLM\SYSTEM\CurrentControlSet\Services\<name> → modify ImagePath value directly (T1574.011).
10. Trigger: StartService / sc start (requires RP), or ControlService stop then start (WP + RP), or wait for natural restart/reboot.
11. Result: payload executes with the service's logon account token — LocalSystem for the targets of interest — yielding privilege escalation from medium-integrity user/admin to SYSTEM. CVE-2019-1322 is cited by the material as a worked example of a service-configuration LPE.

Also mention database lock handle (SCMLock) — the material lists three handle types: SCManager, Service, Database lock. LockServiceDatabase for atomic changes.

## OS Internals Context
- SCM: services.exe, user-mode RPC server (RPC interface over ncalrpc/LPC, \pipe\... actually SCM listens on ncalrpc [SCM] — the Win32 service APIs are RPC stubs in sechost.dll/advapi32 that marshal to services.exe). The material says services "are managed via RPC". So: OpenSCManager is not a direct kernel object open; it's an RPC call that returns an RPC context handle (SC_RPC_HANDLE) bound to the client's access token. Access checks are performed by services.exe against the SCM database object's security descriptor (SC_MANAGER_* rights) and per-service security descriptors stored in the registry.
- HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>: per-service key with ImagePath (REG_EXPAND_SZ), Start (0=boot,1=system,2=auto,3=manual,4=disabled), Type, ObjectName (service account; default LocalSystem for many), plus a Security subkey? Service security descriptors are stored under the service key in the Security value (HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security\Security REG_BINARY). That's documented behavior. If absent, SCM synthesizes a default DACL. I'm fairly confident service SDs persist in the Security value of the service key. Yes — documented: "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ServiceName\Security". sc sdset writes there.
- Unquoted path resolution: CreateProcessW lpApplicationName NULL + lpCommandLine unquoted with spaces → the documented tokenization loop tries appending .exe to progressively longer prefixes. Documented in MSDN CreateProcess remarks. SCM passes ImagePath as command line. So prefix hijack works when an earlier prefix directory is writable.
- Service accounts: LocalSystem has full local authority (equivalent to the computer account on domain), SERVICE_START_NAME. Service processes run in session 0, non-interactive since Vista (session 0 isolation).
- DACLs: access check uses the token of the calling user against the service object SD. WRITE_DAC (WD) lets an attacker rewrite the service DACL itself (then grant self DC), WRITE_OWNER (WO) lets take ownership then rewrite DACL. So WP? No — WO/WD are also exploitable even without DC.
- Service object access rights (0x0001-0x0100 range specific rights plus standard/generic mapping via SC_MANAGER_* GENERIC mapping: SERVICE_GENERIC_READ = STANDARD_RIGHTS_READ | QC | QS | ED | I; SERVICE_GENERIC_EXECUTE includes START...). I can mention the generic mapping briefly.
- QueryServiceObjectSecurity / SetServiceObjectSecurity (advmore... advapi32) are the programmatic equivalents of sc sdshow/sdset; GetNamedSecurityInfoA with SE_SERVICE type also works per the atlas unit 40 (services listed among object types).

## Key Implementation Details
No implementation. State per template: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (Win32 API) and PowerShell/sc.exe." Then a paragraph on what an implementation would look like: PEB-walked advapi32/sechost resolution or direct advapi32 imports, OpenSCManagerA, EnumServicesStatusExW(SC_ENUM_PROCESS_INFO) buffer two-pass (call with 0 to get pcbBytesNeeded), OpenService, QueryServiceConfigW, GetNamedSecurityInfoA(SE_SERVICE) for DACL parse, GetNamedSecurityInfoA(SE_FILE_OBJECT) on binary path, writable-prefix probing for unquoted paths with NtCreateFile/NtOpenFile FILE_WRITE_DATA test or GetEffectiveRightsFromAcl, and exploitation via ChangeServiceConfigW + StartServiceW. Mention byakugan.rs/api_hammering.rs/kaguya.rs were grep-matched but verified as not implementing this technique (byakugan is network recon, api_hammering touches the Services registry key only as an anti-sandbox time sink, kaguya inventories LOtL binaries) — should I mention this? Rule 8 says don't attribute; mentioning why they don't match is good for transparency but not required. A brief sentence is fine and useful for vault integrity. Actually the template for no-source says exactly what to write, then "briefly describe what an implementation would look like". I'll add one short sentence noting the grep-matched files were checked and do not implement it. That seems within spirit — it aids vault integrity. Keep it to one sentence.

## Why It Matters
Why own card: distinct operational purpose (one-shot elevation vs T-017 persistence), discrete tradecraft surface (ImagePath enumeration, BINARY_PATH_NAME inspection, SDDL analysis of service objects). 2-4 sentences. Also mention: the vault has service persistence (T-017) but no service enumeration/LPE card; the technique fills the recon-to-elevation gap on hosts where kernel exploits are patched.

## Detection Considerations
Material coverage: The atlas material doesn't discuss detection for this technique directly. Per rule: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections."

Hmm — do the related T-cards describe detection? T-017 doesn't describe detection either. The atlas privesc material doesn't mention ETW/Sysmon for service enumeration. Rule 4 says claims must trace to material/related cards/source/Windows internals docs. The Detection Considerations instruction is explicit: if material doesn't cover detection, write the single line. The atlas material does not discuss detection for service LPE. So I write that single line. But maybe I can add the residual-artifact side from the material? No — the rule says write the line and do not invent detections. I'll write exactly: "Training material does not discuss detection for this technique." That's the safest compliance. 

Hmm, but the section template also has bullets for telemetry/bypass/residual. The instruction says write the line. I'll write the line as the whole section content. Actually, can I note operational artifacts the mechanism inherently produces without framing as "detection"? The rule is explicit: do not invent detections. The line it prescribes is the entire guidance. I'll write just that line.

## Related Techniques
From would_relate_to: T-017, T-020, T-023.
- T-017 Five-Layer Persistence — persistence complement: T-017 uses services-adjacent persistence (schtask via COM) while T-044 is one-shot elevation; also after elevation, T-017's HKLM-touching layers become writable. Relationship: distinct purpose — persistence vs elevation; service tradecraft overlap via SCM.
- T-020 Anti-Analysis Suite — Kaguya inventories LOtL binaries and detects EDR; service LPE tradecraft relies on LOtL tools (sc.exe, Get-Acl, PowerShell) which Kaguya-style inventory informs. Hmm, the member note says would_relate_to T-020. The relationship: Kaguya catalogs living-off-land binaries (sc.exe-adjacent tooling) — actually kaguya catalog doesn't include sc.exe. The note relationship: service LPE enumeration is often executed with native binaries (sc.exe sdshow, Get-Acl) — the same LOtL-as-code philosophy as T-020's Kaguya. I should be careful to justify from inputs. The lgtm note says "would_relate_to T-020". I'll write: T-020's Kaguya module inventories LOtL binaries and EDR presence — the same on-target reconnaissance pattern under which service enumeration executes; service LPE enumeration feeds the same target-profiling phase. Keep one line.
- T-023 Client Capabilities Suite — sysinfo_collect/byakugan-style recon; the client performs on-host enumeration (sysinfo, recon) into which service enumeration slots as a privilege-escalation-oriented extension. The member note says would_relate_to T-023. Relationship: T-023's sysinfo_collect and recon modules gather host state for the operator; service enumeration is the privesc-oriented extension of that recon surface.

## References
- Atlas: atlas-privesc-part2.md, atlas-privesc-part3.md
- MITRE: T1543.003 https://attack.mitre.org/techniques/T1543/003/ — plus secondary.
- LGTM notes: the two IDs.
- Public references: CVE-2019-1322 (referenced in SEC670 material as example service-configuration LPE); UACMe? No — that's UAC. sc.exe, Get-Acl — tools named in material. I can cite SEC670 (Jonathan Reiter, SANS) and CRTO (RastaMouse? No — CRTO book by RastaMouse/zero-point security). Don't invent author names. The atlas material shows "© 2024 Jonathan Reiter" — so Jonathan Reiter is named in the material. CRTO Book.pdf — just name it. Public references: SEC670 (SANS, Jonathan Reiter), CRTO course book; CVE-2019-1322 as referenced.

## Source Reference
"No current implementation. See atlas material and MITRE reference for public tooling." — per template. Can note the grep-matched files do not implement it. Template says: `<If no source: "No current implementation. See atlas material and MITRE reference for public tooling.">` — I'll use that line, possibly with the verification note.

Word count: target 1200-1800 words body. Let me draft with sufficient depth.

Also frontmatter details:
- mitre_secondary format: list of additional IDs. Include T1574.009, T1574.010, T1574.011, T1007.
- tags 5-10 kebab-case: [privesc, windows-services, scm, unquoted-path, service-dacl, sddl, imagepath-hijack, weak-binary-permissions, service-enumeration] — 9 tags, kebab-case ok.
- crate: none; source_file: none (no quotes? template shows `none` unquoted in template `source_file: <relative path from repo root, or "none">` — other cards use plain values; I'll write `source_file: none`).

Category: privesc — from enum. Good.

Now writing the body. Rules: no fanboy words (check: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable). Avoid "worth noting", "it is important to note", "essentially", "at its core", "interestingly", "the key insight". No first person, no rhetorical questions, no exclamation marks.

Careful with banned: "clean" — avoid "cleanly". "robust" avoid. "notable" avoid. "sophisticated" avoid.

Let me draft.

---

Summary (3-5 sentences):

"Service-based local privilege escalation enumerates the Service Control Manager (SCM) database, identifies services that execute as LocalSystem yet expose a configuration weakness, and converts that weakness into code execution under the service account. The technique targets the service-control architecture itself: the SCM database, per-service security descriptors expressed in SDDL, ImagePath resolution semantics in CreateProcess, and NTFS ACLs on service binaries. Operators use it because services start at boot without an interactive logon and commonly run with the most powerful local token on the host, making a single misconfiguration a direct path from a medium-integrity user to SYSTEM. The primary weakness classes are unquoted service paths, writable service binaries, and service DACLs that grant SERVICE_CHANGE_CONFIG, WRITE_DAC, or WRITE_OWNER to low-privileged principals. The principal detection surface is the Win32 service API set (OpenSCManager, EnumServicesStatus, QueryServiceConfig, ChangeServiceConfig) and the sc.exe / PowerShell equivalents, all of which marshal to the services.exe RPC server."

That's 5 sentences. Good.

Mechanism (numbered):

1. Acquire an SCM database handle with OpenSCManager(lpMachineName, "ServicesActive"/SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE). The material frames three handle types: the SCManager handle, per-service Service handles, and the database lock handle.
2. Enumerate services with EnumServicesStatus (or EnumServicesStatusEx), requesting SERVICE_WIN32 and SERVICE_STATE_ALL; the two-pass call first sizes the buffer via pcbBytesNeeded, then fills an array of ENUM_SERVICE_STATUS containing lpServiceName, lpDisplayName, and SERVICE_STATUS.
3. For each entry, call OpenService with SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL, then QueryServiceConfig to retrieve QUERY_SERVICE_CONFIG: lpBinaryPathName (BINARY_PATH_NAME), dwStartType, lpServiceStartName. QueryServiceStatus returns current state. The material names EnumServicesStatus and QueryServiceStatus as the canonical enumeration pair.
4. Filter to high-value targets: services whose lpServiceStartName is LocalSystem (or another privileged account), start type auto (0x2), and preferably already running.
5. Test for an unquoted service path: lpBinaryPathName contains spaces and no surrounding quotes (C:\Program Files\Vendor\svc.exe). Because CreateProcess tokenizes an unquoted command line by probing C:\Program.exe, then C:\Program Files\Vendor.exe... wait: "C:\Program Files\Vendor\svc.exe" → probes "C:\Program.exe", then "C:\Program Files\Vendor.exe", then full. For each prefix, test write access in the containing directory.
6. Test binary permissions on the resolved path: CRTO uses Get-Acl and looks for Allow: Modify, Synchronize for the operator's SID or broad groups (Everyone, Authenticated Users, BUILTIN\Users). Programmatic equivalent: GetNamedSecurityInfoA with SE_FILE_OBJECT.
7. Test the service object DACL: sc.exe sdshow <service> or GetNamedSecurityInfoA with SE_SERVICE (the material lists services among supported object types). Parse the SDDL using the ACE string grammar the material lays out: ace_type (A allow, D deny, OA/OD object variants, AU audit), ace_flags (CI, OI, NP, IO, ID, SA), rights letters, and account SIDs (IU interactive, SU service, BA built-in administrators, SY local system).
8. Flag DACLs granting low-privileged principals any of: DC (SERVICE_CHANGE_CONFIG), WD (WRITE_DAC), WO (WRITE_OWNER), or the combination RP+WP (start/stop) which enables triggering. The material's worked exercise decodes a BITS-style DACL into deny ACEs for IU/SU/BA and allow ACEs for IU, SU, SY, demonstrating manual SDDL interpretation with sc.exe and Get-Service.
9. Exploit via the matching path: (a) unquoted path — drop a payload at a resolvable prefix in a writable directory; (b) weak binary ACL — replace or patch the binary in place; (c) SERVICE_CHANGE_CONFIG — call ChangeServiceConfig (or sc.exe config <svc> binPath= "<command>") to repoint lpBinaryPathName at the payload; (d) weak ACL on HKLM\SYSTEM\CurrentControlSet\Services\<name> — rewrite the ImagePath value directly. The material ties service configuration to this registry hive.
10. Trigger execution: StartService / sc start if RP (SERVICE_START) is granted, ControlService stop followed by start if WP+RP are granted, or wait for the next boot or crash-recovery restart.
11. On start, services.exe spawns the configured binary with the service account's token; for a LocalSystem target the payload executes as NT AUTHORITY\SYSTEM in session 0. The material cites CVE-2019-1322 as a worked example of this service-configuration LPE class.

That's 11 steps. Good length.

OS Internals Context:

- SCM is services.exe, a user-mode RPC server; the Win32 service APIs in advapi32/sechost.dll are client stubs that marshal parameters to services.exe over the local RPC endpoint. Handles returned by OpenSCManager/OpenService are RPC context handles bound to the caller's token, and access checks execute inside services.exe, not in the kernel.
- SCM database object has its own security descriptor governing SC_MANAGER_* rights (SC_MANAGER_ENUMERATE_SERVICE 0x0004, SC_MANAGER_CREATE_SERVICE 0x0002, SC_MANAGER_CONNECT 0x0001, SC_MANAGER_LOCK 0x0008, plus database lock semantics via LockServiceDatabase).
- Per-service security descriptors are stored in the registry under HKLM\SYSTEM\CurrentControlSet\Services\<name> in the Security value; when absent, SCM applies a default DACL granting full control to Administrators and SYSTEM and read/start to interactive users — the material's exercise DACL (allow CCLCSWLOCRRC to IU and SU; fuller set CCLCSWRPWPDTLOCRRC to SY; denies DCLCWPDTSD for IU/SU/BA) is an example of a hardened custom descriptor written with sc.exe sdset.
- Rights letters for services map to access masks: CC=SERVICE_QUERY_CONFIG (0x1), DC=SERVICE_CHANGE_CONFIG (0x2), LC=SERVICE_QUERY_STATUS (0x4), SW=SERVICE_ENUMERATE_DEPENDENTS (0x8), RP=SERVICE_START (0x10), WP=SERVICE_STOP (0x20), DT=SERVICE_PAUSE_CONTINUE (0x40), LO=SERVICE_INTERROGATE (0x80), CR=SERVICE_USER_DEFINED_CONTROL (0x100); standard rights RC, SD, WD, WO carry their usual meanings. WRITE_DAC on a service object lets an attacker grant themselves SERVICE_CHANGE_CONFIG; WRITE_OWNER lets them seize ownership first.
- Unquoted path resolution: when CreateProcessW is called with lpApplicationName NULL and an unquoted lpCommandLine containing spaces, the loader probes progressively longer prefixes with .exe appended. SCM launches services through this path using ImagePath as the command line, so any writable prefix directory earlier than the real binary yields execution as the service account. This is a documented CreateProcess tokenization behavior, not a service-specific bug.
- Service processes execute in session 0 (session-0 isolation since Vista); service account LocalSystem (ObjectName "LocalSystem", also expressible as NT AUTHORITY\SYSTEM) holds nearly unrestricted local authority, including SeDebugPrivilege-equivalent reach via token rights — the material's privilege-adjustment APIs (LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges) are the same primitives used to manipulate tokens after elevation.
- HKLM\SYSTEM\CurrentControlSet\Services\<name> values: ImagePath (REG_EXPAND_SZ), Start, Type, ObjectName. Weak registry ACLs on the key itself are the fourth attack surface, independent of the service object DACL, because SCM reads configuration from this key at start time.
- CVE-2019-1322 is referenced in the material as an example service-configuration LPE; treat it as the class exemplar (service misconfiguration → privileged execution) rather than as a memory-corruption exploit.

Wait — need to be careful about claiming the Security value storage. It is documented that service security descriptors are stored in HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Security (value name "Security", REG_BINARY). Yes, that's documented in MS references ("Service security descriptor is stored in the Security value"). I'm confident enough.

Also SCM RPC endpoint: the SCM Win32 APIs use RPC over ncalrpc (LRPC). Documented. I'll phrase carefully: "marshal to services.exe over local RPC (ncalrpc)".

Default service DACL: documented that SCM assigns a default security descriptor when none is stored. I'll phrase as documented behavior without inventing exact ACEs: default grants full access to administrators and SYSTEM, and read/start access to interactive/authenticated users — hmm, exact default: "The default security descriptor grants: SYSTEM Full Control, Administrators Full Control, Interactive users Read+Start..." I recall default grants Everyone read? Better to phrase generally: "a default DACL that grants full control to Administrators and LocalSystem and read-level access to interactive users" — that matches the exercise's allow CCLCSWLOCRRC for IU which is query config/query status/enum deps/interrogate/user-defined/read-control (i.e., read-level + user-defined control). I'll keep the claim aligned with the exercise.

Key Implementation Details:

No implementation. Template text + implementation sketch paragraph + one-sentence verification note about the three grep-matched files.

Implementation sketch: two-pass EnumServicesStatusExW with SC_ENUM_PROCESS_INFO to get PID and state in one call; QUERY_SERVICE_CONFIG via QueryServiceConfigW two-pass; GetNamedSecurityInfoA with SE_SERVICE for SDDL/SD; GetEffectiveRightsFromAcl or AccessCheck to test the caller's effective rights against binary DACLs; unquoted-path probing by attempting NtCreateFile with FILE_WRITE_DATA on each prefix (aligns with HUGIN's RecycledGate Nt* style); exploitation via ChangeServiceConfigW + StartServiceW, or direct registry write to ImagePath when only the key ACL is weak. Note that advapi32 service APIs cannot be resolved via raw syscalls because they are RPC client stubs — an implementation must either load advapi32/sechost (PEB-walked) or speak the SCM RPC protocol directly. That last point is genuinely useful internals-grounded implementation guidance. Good.

Why It Matters (2-4 sentences):

"This is the only vault card covering services as an elevation surface; T-017 uses service-adjacent mechanisms for persistence, which is a different operational goal — one-shot token elevation versus durable re-entry. The tradecraft surface is discrete: ImagePath enumeration, BINARY_PATH_NAME inspection, service-descriptor SDDL analysis, and prefix-writability probing have no overlap with the injection or evasion cards. It also degrades gracefully: enumeration works from a medium-integrity user with read-only rights, and each weakness class (unquoted path, binary ACL, service DACL, registry key ACL) is independently exploitable, so the operator can chain from whatever misconfiguration the target exposes."

Detection Considerations: single line per rule.

Related Techniques: T-017, T-020, T-023 as drafted.

References:
- Atlas: atlas-privesc-part2.md (units 9-16, 37-39), atlas-privesc-part3.md (units 11, 15-18)
- MITRE: T1543.003 URL; secondaries.
- LGTM notes IDs.
- Public: SANS SEC670 (Red Teaming Tools, Jonathan Reiter) as named in material; CRTO Book; sc.exe / Get-Acl tooling; CVE-2019-1322 as referenced by the material. Don't invent blog posts.

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling." Maybe add: "Grep-matched files byakugan.rs, api_hammering.rs, and kaguya.rs were reviewed and do not implement SCM enumeration or service exploitation." — I think including this is good for vault integrity. The template's no-source line is prescriptive; I'll lead with the exact prescribed sentence then add the verification note. Hmm, the template says: `<If no source: "No current implementation. See atlas material and MITRE reference for public tooling.">` — I'll write that sentence and add one more sentence noting the reviewed files. That shouldn't violate anything; it increases accuracy.

Word count check: I'll aim for ~1400-1600 words.

Let me also double check EnumServicesStatus signature details to avoid fabricating: EnumServicesStatus(hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle). Returns ENUM_SERVICE_STATUS with lpServiceName, lpDisplayName, ServiceStatus. Good.

EnumServicesStatusEx adds SC_ENUM_PROCESS_INFO info level returning ENUM_SERVICE_STATUS_PROCESS with SERVICE_STATUS_PROCESS (dwProcessId). Documented. Good.

QueryServiceConfig returns QUERY_SERVICE_CONFIG: dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, dwTagId, lpDependencies, lpServiceStartName, lpDisplayName. Good — lpServiceStartName is the account name. Material says "BINARY_PATH_NAME inspection" — BINARY_PATH_NAME is the sc.exe query field name for lpBinaryPathName. Include both names.

Service start values: SERVICE_BOOT_START 0, SERVICE_SYSTEM_START 1, SERVICE_AUTO_START 2, SERVICE_DEMAND_START 3, SERVICE_DISABLED 4. Good.

Unquoted path probe order: for command line "C:\Program Files\Sub Dir\Program.exe" CreateProcess tries:
- C:\Program.exe
- C:\Program Files\Sub.exe
- C:\Program Files\Sub Dir\Program.exe
Documented in MSDN CreateProcessW remarks ("the system tries the following..."). Good. The material only says "unquoted path privilege escalation" without the probe order; the probe order is well-established MSDN documentation, allowed.

sc.exe sdshow BITS example: material unit 37 explicitly uses BITS. Good — mention BITS as the material's example.

CVE-2019-1322: described by material as example of service-configuration LPE / "services with weak permissions or incorrect configurations". I'll say exactly that.

The registry rights in the ACE grammar from unit 35: KA all, KR read, KW write, KX execute — for the registry-key ACL path I can mention KW/KX? KA/KR/KW/KX are registry rights letters in SDDL. Fine to reference from material.

One more internals point: service objects are not kernel objects in the ObManager namespace; they are database records inside the SCM. That's why you cannot open them with NtOpen*. True and useful. The "handles" are RPC context handles (SC_RPC_HANDLE). Good.

Also mention: EnumServicesStatus requires SC_MANAGER_ENUMERATE_SERVICE on the SCM object; by default any authenticated user can enumerate (the default SCM DACL grants read/enum to authenticated users) — documented; the material's exercise DACL shows IU allowed CCLCSWLOCRRC which includes SW (enumerate dependents) but enumeration of the database is an SCM-object right. I'll state: default SCM descriptor permits interactive/authenticated enumeration, which is why recon works unprivileged. That's well-established.

Tags final: [privesc, windows-services, scm, unquoted-path, service-dacl, sddl, imagepath-hijack, weak-binary-permissions, service-enumeration] — 9. kebab-case ✓.

member_notes: ['lgtm:proposed-technique-service-lpe-enumeration', 'lgtm:service-based-lpe-proposed-technique'].

mitre: T1543.003 — best single fit for "modify service config / binPath" exploitation which the material emphasizes (sc config, ChangeServiceConfig, sdshow/sdset). mitre_secondary: [T1574.009, T1574.010, T1574.011, T1007].

Hmm, let me reconsider primary once more. The card's name is "Service-Based Local Privilege Escalation via SCM Enumeration". Enumeration emphasis → T1007 System Service Discovery is discovery not privesc. The consolidated description: "identify services running as SYSTEM or with weak binary permissions, and exploit unquoted service paths or weak DACL/ACL" — the weak DACL/ACL (service object DACL via sdshow/SDDL) is the most distinctive surface of the material (units 37-39, plus SetNamedSecurityInfoA/EXPLICIT_ACCESS_A units in part3). Service object DACL abuse → modify service → T1543.003. ATT&CK T1543.003 explicitly covers "modifying existing services" including binPath changes with sc config. Confident. T1543.003 primary stands.

Format for mitre_secondary: YAML list. [T1574.009, T1574.010, T1574.011, T1007].

Now write the final card. Ensure exactly the prescribed sections, in order. No extra commentary outside the file.

Also check banned words as I write: avoid "canonical"? Not banned. Avoid "textbook" (banned) — I used "canonical enumeration pair" in mechanism; "canonical" is fine, but let me rephrase to "the enumeration pair the material names". Avoid "solid", "robust", "clean". "elegant" no. "key" — "the key insight" banned as phrase; "key" alone in "registry key" is fine.

Length: I'll write thorough sections. Let me count roughly at the end.

Mechanism step numbering — use "1." style.

Write it.