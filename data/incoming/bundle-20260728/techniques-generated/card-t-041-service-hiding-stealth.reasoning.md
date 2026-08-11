Let me analyze the task:

1. I'm generating a technique card for T-041: Service Hiding from SCM Enumeration
2. Category: persistence
3. Tier: B
4. Member notes: lgtm:sddl-service-hiding-tradecraft, lgtm:hidden-service-technique, lgtm:service-hiding-coverage-gap
5. would_relate_to: T-017, T-020

Let me check the source files provided:
- `src/client_rust/src/byakugan.rs` — This is network reconnaissance (ARP scan, port scan, banner grab, AD enum). It does NOT implement service hiding. Keyword grep probably hit "service" in guess_service(). Not an implementation.
- `src/dark_crystal/crates/core/src/experimental/api_hammering.rs` — API hammering anti-sandbox. Not service hiding.
- `src/dark_crystal/crowd/src/kaguya.rs` — LOtL binary inventory. Not service hiding.

So: no current implementation in source. The byakugan.rs file matched probably on "service" keyword (guess_service function) but it's network recon, not service hiding. I must state "no current implementation."

Now the atlas material:
- atlas-edr-evasion-part2.md, units 3, 4, 5: Joshua Wright's SDDL string:
```
"D: (D;;DCLCWPDTSD;;;IU) (D;;DCLCWPDTSD;;;SU) (D;;DCLCWPDTSD;;;BA) (A;;CCLCSWLOCRRC;;;IU) (A;;CCLCSWLOCRRC;;;SU) (A;;CCLCSWRPWPDTLOCRRC;;;SY) (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) S: (AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
```
- Programmatic implementation via SetSecurityDescriptorControl and SetNamedSecurityInfo (securitybaseapi.h, aclapi.h)
- atlas-post-exploit-part17.md unit 1: "What Else?; Hiding a service" — SANS Book 4 (Persistence) slide
- atlas-post-exploit-part8.md unit 13: Lab 4.4 "NotInService" — develop custom service, install code, hide code using Win32 APIs

Let me decode the SDDL string for the card. This is well-established Windows internals knowledge:

SDDL structure: `D:` = DACL, `S:` = SACL.

DACL ACEs:
1. `(D;;DCLCWPDTSD;;;IU)` — Deny ACE, no flags, rights DCLCWPDTSD, for Interactive Users (IU)
2. `(D;;DCLCWPDTSD;;;SU)` — Deny, same rights, for Service Users (SU)
3. `(D;;DCLCWPDTSD;;;BA)` — Deny, same rights, for Built-in Administrators (BA)
4. `(A;;CCLCSWLOCRRC;;;IU)` — Allow, CCLCSWLOCRRC, for IU
5. `(A;;CCLCSWLOCRRC;;;SU)` — Allow, CCLCSWLOCRRC, for SU
6. `(A;;CCLCSWRPWPDTLOCRRC;;;SY)` — Allow, CCLCSWRPWPDTLOCRRC, for LocalSystem (SY)
7. `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)` — Allow, full rights, for BA

SACL:
- `(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)` — Audit ACE, failed access (FA), all rights, for Everyone (WD)

Now let me decode the service-specific rights. Service Manager and service object rights in SDDL:
- CC — SERVICE_QUERY_CONFIG (Query service configuration)
- DC — SERVICE_CHANGE_CONFIG (Change service configuration)
- LC — SERVICE_QUERY_STATUS (Query service status)
- SW — SERVICE_ENUMERATE_DEPENDENTS (Enumerate dependent services)
- RP — SERVICE_START (Start the service)
- WP — SERVICE_STOP (Stop the service)
- DT — SERVICE_PAUSE_CONTINUE (Pause/continue)
- LO — SERVICE_INTERROGATE (Interrogate the service)
- CR — SERVICE_USER_DEFINED_CONTROL (User-defined control)
- RC — READ_CONTROL (Read security descriptor)
- SD — DELETE (Delete)
- WD — WRITE_DAC (Modify permissions)
- WO — WRITE_OWNER (Change owner)
- GA — Generic all
- GX — Generic execute
- GW — Generic write
- GR — Generic read

So:
1. `(D;;DCLCWPDTSD;;;IU)` — Deny Interactive Users: DC (change config), LC (query status), SW (enumerate dependents), WP (stop), DT (pause/continue), SD (delete)
2. Same for SU
3. Same for BA
4. `(A;;CCLCSWLOCRRC;;;IU)` — Allow IU: CC (query config), LC (query status)... wait, but deny overrides allow. Deny ACEs are evaluated first. So the deny of LC for IU means query status is denied even though allow grants it.

Hmm wait — allow grants CCLCSWLOCRRC = CC (query config), LC (query status), SW (enum dependents), LO (interrogate), CR (user-defined control), RC (read control). But deny takes precedence for DCLCWPDTSD: DC, LC, SW, WP, DT, SD.

So the net effect for IU/SU: they get CC (query config), LO (interrogate), CR (user-defined control), RC (read control). They're denied: DC (change config), LC (query status), SW (enumerate dependents), WP (stop), DT (pause/continue), SD (delete).

Critically, denying SERVICE_QUERY_STATUS (LC) is what hides the service from `sc query` and services.msc enumeration — EnumServicesStatus / EnumServicesStatusEx will skip or fail on services whose status can't be queried... Actually, the way service hiding works with DACLs: `EnumServicesStatusEx` returns only services the caller has SERVICE_QUERY_STATUS access to. So denying LC removes the service from enumeration results. That's the core mechanism. Similarly `sc query` fails with Access Denied.

Actually, let me be precise. The documented behavior: EnumServicesStatus and EnumServicesStatusEx only return services for which the caller has SERVICE_QUERY_STATUS access. Services for which the caller lacks that right are silently omitted from the returned list. This is documented in MSDN remarks for EnumServicesStatusEx? Let me recall... The sc.exe queryex uses EnumServicesStatusEx. services.msc uses the SCM enumeration. The service is hidden from enumeration but still runs — SYSTEM retains full access so the SCM itself (running as SYSTEM) can start and manage it.

5. `(A;;CCLCSWRPWPDTLOCRRC;;;SY)` — Allow SYSTEM: CC, LC, SW, RP (start), WP (stop), DT, LO, CR, RC — full operational rights except DC (change config), SD, WD, WO. Actually SY gets query/start/stop/pause/interrogate — everything needed for normal service management.

6. `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)` — Allow BA full rights: CC, DC, LC, SW, RP, WP, DT, LO, CR, SD, RC, WD, WO. But wait — BA also has a deny ACE (D;;DCLCWPDTSD;;;BA). Deny evaluated first → administrators are denied query status, change config, stop, pause, delete... but allowed them too via the allow ACE. Net effect: denied rights win. So administrators get: RP (start), LO, CR, RC, WD, WO. Interesting — admins can start it and change its DACL/owner (WD/WO), which means a determined admin can seize ownership and rewrite the DACL. That's the standard escape hatch — WRITE_OWNER lets an admin take ownership and then rewrite.

Actually with WRITE_DAC (WD) directly, an admin could just reset the DACL. And SeTakeOwnershipPrivilege lets admins take ownership regardless. So the hiding is a speed bump against casual enumeration, not a hard block against a determined elevated responder. But for `sc query` / services.msc running as admin, the service won't appear because enumeration filters on SERVICE_QUERY_STATUS which is denied.

SACL: `(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)` — audit failed access attempts for Everyone on all rights. This logs failed access attempts (Security event 4663/4674?) if SACL auditing is enabled. Service object access auditing — event 4663 on the service object? Actually service object access events are in the Security log; auditing service objects requires "Audit object access" policy and the SCManager/service SACLs. The material doesn't elaborate, so I'll note it briefly without inventing event IDs... Actually 4663 "An attempt was made to access an object" is well established for object access auditing. But the material doesn't mention it. I should be careful. I can mention it as the SACL's purpose (audit failures) without asserting specific event IDs, or say the material doesn't specify which event IDs fire.

Now, the mechanism steps:

1. Create the service (CreateService or sc.exe create) — the service gets a default DACL from the SCM.
2. Apply the custom security descriptor:
   - Manual: `sc.exe sdset <service> "D:(D;;DCLCWPDTSD;;;IU)..."` — sc sdset accepts SDDL.
   - Programmatic: ConvertStringSecurityDescriptorToSecurityDescriptor (ADVAPI32, sddl.h) to convert SDDL string → SECURITY_DESCRIPTOR, then SetServiceObjectSecurity (winsvc.h) with DACL_SECURITY_INFORMATION. OR build the descriptor programmatically with SetSecurityDescriptorControl / SetNamedSecurityInfo (aclapi.h) as mentioned in unit 5.
3. The SCM (services.exe, running as SYSTEM) stores the security descriptor with the service record in its in-memory database (and it persists — the security descriptor is stored in the registry under HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security\Security as REG_BINARY).

That's a good registry artifact: `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Security` value `Security` (REG_BINARY) contains the self-relative security descriptor. That's well-established Windows knowledge (documented). The default location where CreateService stores the security descriptor — yes, the Security subkey under the service key.

4. Enumeration tools (sc query, services.msc, Get-Service, EnumServicesStatusEx) omit services for which the caller lacks SERVICE_QUERY_STATUS.
5. Service still starts at boot because SCM runs as SYSTEM which retains full access.

API details for programmatic path (from material unit 5): securitybaseapi.h (SetSecurityDescriptorControl), aclapi.h (SetNamedSecurityInfo). SetNamedSecurityInfo with SE_SERVICE object type can set the DACL on a named service. SetServiceObjectSecurity is the winsvc.h equivalent taking a service handle. The material mentions SetSecurityDescriptorControl and SetNamedSecurityInfo specifically. SetSecurityDescriptorControl sets the control bits (SE_DACL_PROTECTED etc.) of a security descriptor.

Detection considerations — what does the material say? The material doesn't discuss detection for this technique explicitly. Hmm. The notes say the SACL audits failed access. The material covers the technique itself but not defender-side detection. Per rule: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections."

But wait — I can note residual artifacts grounded in Windows documentation (registry Security subkey is well-established). The rule says detection info must come from material; but "Well-established Windows internals documentation" is an allowed source for claims. The Detection Considerations section asks for telemetry sources "the training material describes." I think the safest approach: state the training material does not cover defender detection, then note the residual artifacts that are inherent to the mechanism and traceable to Windows documentation (the Security registry subkey, the fact that sc sdshow reveals the DACL to SYSTEM, that an admin with WRITE_DAC/WRITE_OWNER can revert). Also the SACL audit ACE in the string itself is from the material — auditing failed access is part of the tradecraft string. I can describe that the reference SDDL includes a SACL that audits failed access attempts for Everyone — which itself implies a detection angle (failed-access audit events) — that's from the material's string. I'll keep it grounded.

Actually, being careful: the SACL in Joshua Wright's string audits failed access — that's a defender-relevant detail embedded in the tradecraft string itself. I'll mention it.

Also `sc.exe sdshow <service>` displays the SDDL — a responder running as SYSTEM can see the non-default DACL. Well-established.

MITRE ID: Best fit. Service hiding via security descriptor modification... Candidates:
- T1543.003 Create or Modify System Process: Windows Service — that's creating the service.
- T1562 Impair Defenses? Not quite.
- T1070 Indicator Removal? No.
- T1036 Masquerading? No.
- T1564 Hide Artifacts — "Hide Artifacts" is the tactic technique for hiding artifacts from users. Service hiding fits T1564 (Hide Artifacts). There's no sub-technique for service hiding specifically. Sub-techniques: T1564.001 Hidden Files and Directories, .002 Hidden Users, .003 Hidden Window, .004 NTFS File Attributes, .005 Hidden File System, .006 Run Virtual Instance, .007 VBA Stomping, .008 Email Hiding Rules, .009 Resource Forking, .010 Process Argument Spoofing, .011 Ignore Process Interrupts. None is "hidden service". So parent T1564 Hide Artifacts is the best fit.

Hmm, but modifying the security descriptor of a service to prevent enumeration could also map to T1543.003 (Create or Modify System Process: Windows Service) since we're modifying a service. The primary intent here is hiding, so T1564 as primary with T1543.003 secondary. The card frontmatter template says mitre_secondary is optional list. I'll do mitre: T1564, mitre_secondary: [T1543.003]. That's defensible: the technique modifies a Windows service's security descriptor (T1543.003 covers "modify" of system process/service config) to hide artifacts (T1564).

Category: persistence per spec. The mechanism is a stealth layer on service persistence — persistence category is the spec's directive. Fine.

Tier: B per spec.

crate: none (no implementation).
source_file: none.

The cluster spec priority says "distinct stealth mechanism complementing service persistence."

Verify source files: byakugan.rs — network recon, contains guess_service() but no SCM/service security descriptor code. api_hammering.rs — anti-sandbox. kaguya.rs — LOtL inventory; walks services registry key? kaguya.rs has registry_deep_walk in api_hammering.rs touching SYSTEM\CurrentControlSet\Services for enumeration as time-waster — not hiding. None implement service hiding. So source_file: none.

Tags: 5-10 kebab-case: [service-hiding, sddl, security-descriptor, dacl, scm, service-enumeration-evasion, acl-manipulation, persistence-stealth]

Now, sections:

## Summary — 3-5 sentences. What it does, OS primitive (service object security descriptor / DACL enforced by SCM + object manager), why operator uses it (hide persistence service from sc query/services.msc/Get-Service), primary detection surface.

## Mechanism — numbered steps:
1. Operator creates/registers the payload service via CreateService / sc.exe create (or T-017 layer equivalent). SCM registers under HKLM\SYSTEM\CurrentControlSet\Services\<name>.
2. Craft SDDL string (Joshua Wright reference string) — D: DACL with deny ACEs for IU/SU/BA on DCLCWPDTSD, allow ACEs granting SYSTEM full operational rights and constrained rights to IU/SU/BA; S: SACL auditing failed access for Everyone.
3. Apply manually via sc.exe sdset <name> "D:... S:...", or programmatically: ConvertStringSecurityDescriptorToSecurityDescriptorW → SECURITY_DESCRIPTOR, then SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, sd). Alternative pure-API route from the material: build the descriptor with securitybaseapi.h functions (SetSecurityDescriptorControl) and apply with aclapi.h SetNamedSecurityInfo using SE_SERVICE.
4. SCM persists the self-relative security descriptor to HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security\Security (REG_BINARY).
5. Enumeration: sc query / services.msc / Get-Service / EnumServicesStatusEx omit the service because caller lacks SERVICE_QUERY_STATUS.
6. Boot/start unaffected: services.exe runs as SYSTEM; SY ACE grants start/stop/query.

Wait — does the service still auto-start? Yes, SCM as SYSTEM has SERVICE_START (RP) etc. Good.

## OS Internals Context

- Service objects are securable objects managed by the Service Control Manager (services.exe); access checks happen in services.exe (user mode, RPC over \pipe
tsvcs / MS-SCMR) not the kernel object manager — services aren't kernel objects. The SCM performs AccessCheck against the stored security descriptor for each service on API calls like OpenService, QueryServiceStatus, EnumServicesStatusEx.
- Access masks: map the SDDL two-letter codes to SERVICE_* constants: CC=SERVICE_QUERY_CONFIG (0x0001), DC=SERVICE_CHANGE_CONFIG (0x0002), LC=SERVICE_QUERY_STATUS (0x0004), SW=SERVICE_ENUMERATE_DEPENDENTS (0x0008), RP=SERVICE_START (0x0010), WP=SERVICE_STOP (0x0020), DT=SERVICE_PAUSE_CONTINUE (0x0040), LO=SERVICE_INTERROGATE (0x0080), CR=SERVICE_USER_DEFINED_CONTROL (0x0100), plus standard rights RC=READ_CONTROL, SD=DELETE, WD=WRITE_DAC, WO=WRITE_OWNER.
- ACE ordering: deny-first canonical ordering in the DACL; access check stops at first deny match for requested mask.
- EnumServicesStatusEx behavior: returns only services caller can query status on (per MSDN: "services... the caller must have SERVICE_QUERY_STATUS"— actually MSDN documents that EnumServicesStatus/Ex return services regardless? Let me think. Hmm.

Careful here. What is the documented behavior? From MSDN EnumServicesStatusExA remarks: I don't recall an explicit "services are filtered by access" statement. But empirically and widely documented (e.g., in red team literature and Microsoft's own docs for sc.exe), services that deny SERVICE_QUERY_STATUS do not appear in sc query output / services.msc. The well-known public reference: "hiding services with sc sdset" — the SDDL trick from Joshua Wright (also in his "Windows Service Security" talks / SANS). The observed behavior: EnumServicesStatusEx filters out services the caller cannot open with SERVICE_QUERY_STATUS. This is established operational fact in the tradecraft material itself ("effectively hiding a service from sc query and similar enumeration"). The material asserts the effect; I can describe the mechanism (SCM-side filtering during enumeration, because enumeration internally performs an access check for SERVICE_QUERY_STATUS per service record) as the implementation detail. This is consistent with MSDN's statement for EnumServicesStatus: "If the caller does not have the SERVICE_QUERY_STATUS access right to a service, the service is silently omitted from the list of services returned to the client." — I'm fairly confident this sentence exists in MSDN docs for EnumServicesStatusExW (Services). Actually yes — I believe the remark exists for EnumServicesStatusEx: "This function returns only those services for which the caller has SERVICE_QUERY_STATUS access." I'll state it as documented behavior without over-hedging. To be safe I'll phrase: "documented to silently omit services for which the caller lacks SERVICE_QUERY_STATUS."

- Registry persistence of the descriptor: HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Security subkey, value "Security" (REG_BINARY) holds the self-relative SD. CreateService accepts lpSecurityDescriptor (usually NULL → default from SCM). Documented in MSDN service security.
- Default DACL: services created without explicit SD inherit the SCM default (SCManager's default DACL grants Everyone SERVICE_QUERY_STATUS etc. — actually default grants: Authenticated Users certain rights, SYSTEM/Administrators full, Everyone READ_CONTROL...). I should avoid over-specific claims about default DACL contents. Keep general.
- SACL: the trailing S: ACE audits failed access (FA = FAILED_ACCESS_ACE_FLAG) for WD (Everyone) across all service rights — requires Audit object access policy; produces Security log object-access events. The material includes the SACL; describing its purpose is grounded in the string itself.
- The BA allow includes WD/WO — an elevated administrator retains WRITE_DAC/WRITE_OWNER, so the hiding is reversible by a determined admin (take ownership, rewrite DACL); note this as limitation — grounded in decoding the string (BA has WO). Also SeSecurityPrivilege / takeown. Good nuance: the technique hides from casual admin-level enumeration but SYSTEM sees everything and admins retain ownership rights in this particular string.

Hmm, wait — BA deny includes DC/LC/SW/WP/DT/SD, BA allow includes everything (CCDCLCSWRPWPDTLOCRSDRCWDWO). Net for BA: allowed CC, RP, LO, CR, RC, WD, WO; denied DC, LC, SW, WP, DT, SD. So admin cannot stop the service (WP denied) or delete it (SD denied) or query its status (LC denied) — but can start it, and can rewrite its DACL (WD) and take ownership (WO). So the "revert path" is: admin uses WRITE_DAC to reset DACL, or WRITE_OWNER to take ownership then reset. That's accurate string decoding. Also note SeTakeOwnershipPrivilege makes all of this moot for a determined admin regardless — but that's extra; I can mention the string's own escape hatch as observed in the ACEs.

- Where the check happens relative to kernel: SCM is user-mode (services.exe, RPC server implementing MS-SCMR over ncalrpc/\pipe
tsvcs). Kernel object manager never sees the service — only the underlying process/registry. So no kernel callback observes "service enumeration"; EDR visibility comes from RPC telemetry, registry monitoring (Security subkey write), and Security auditing from the SACL.

## Key Implementation Details

No current implementation. Template sentence + paragraph on what implementation would look like: a persist/ module addition in dark_crystal/crowd that, after CreateService, converts the reference SDDL via ConvertStringSecurityDescriptorToSecurityDescriptorW (windows crate, Win32_Security) and applies via SetServiceObjectSecurity with DACL_SECURITY_INFORMATION; or builds ACEs programmatically with SetEntriesInAclW + SetNamedSecurityInfo (SE_SERVICE). Rust specifics: windows-targets link, RAII LocalFree for the converted SD. Must run elevated (WRITE_DAC on the service required).

## Why It Matters

T-017's five layers make the implant survive; none address visibility of a service once created. A service registered for persistence is one `sc query` away from discovery. This card is the stealth complement: same object, different axis (ACL-based enumeration suppression). Distinct from T-020 (pre-execution environment analysis) — this is post-install artifact concealment. It fills the gap noted in all three member notes: the vault documents persistence and anti-analysis but not SCM enumeration evasion.

## Detection Considerations

Material doesn't cover defender detection explicitly. State that. Then:
- The reference SDDL embeds its own tripwire: SACL ACE (AU;FA;...;;;WD) audits failed access attempts by Everyone — the string anticipates responders probing the service. (From the string itself.)
- Residual artifacts (grounded in Windows docs, flagged as such): Security\Security REG_BINARY value under the service key — non-default SD is itself an anomaly; sc.exe sdshow <svc> run as SYSTEM reveals the DACL; an SD containing deny ACEs for BA on a service is rare in baseline images.
- Bypass options: material doesn't discuss. Keep short.

## Related Techniques

- T-017 Five-Layer Persistence — the concealment target; this technique hides the service-execution layer that T-017-style persistence registers.
- T-020 Anti-Analysis Suite — complementary axis: T-020 gates execution on environment checks; T-041 conceals an installed artifact from post-hoc enumeration.

## References

- Atlas material: atlas-edr-evasion-part2.md (units 3-5), atlas-post-exploit-part17.md (unit 1), atlas-post-exploit-part8.md (unit 13)
- MITRE ATT&CK: T1564 https://attack.mitre.org/techniques/T1564/ (and T1543.003 secondary https://attack.mitre.org/techniques/T1543/003/)
- LGTM notes: the three IDs
- Public references: Joshua Wright (SANS instructor) crafted the reference SDDL on an engagement, as documented in SEC670. Don't invent more.

## Source Reference

No current implementation...

Frontmatter:
- id: T-041
- name: Service Hiding via SDDL Security Descriptor (4-8 words) — "Service Hiding from SCM Enumeration" is the canonical name; use it. Maybe "SDDL Service Hiding from SCM Enumeration" (6 words). Keep canonical: "Service Hiding from SCM Enumeration".
- category: persistence
- tier: B
- crate: none
- source_file: none
- mitre: T1564
- mitre_secondary: [T1543.003]
- tags: [service-hiding, sddl, security-descriptor, dacl, scm-enumeration, acl-tampering, persistence-stealth, service-dacl]
- member_notes: exact three.

Word count target 1200-1800 body. Let me write carefully, decode the SDDL fully in a table-ish list (not a table — numbered/bulleted fine).

Deny rights DCLCWPDTSD decode:
- DC = SERVICE_CHANGE_CONFIG
- LC = SERVICE_QUERY_STATUS
- SW = SERVICE_ENUMERATE_DEPENDENTS
- WP = SERVICE_STOP
- DT = SERVICE_PAUSE_CONTINUE
- SD = DELETE

Allow CCLCSWLOCRRC:
- CC = SERVICE_QUERY_CONFIG
- LC = SERVICE_QUERY_STATUS
- SW = SERVICE_ENUMERATE_DEPENDENTS
- LO = SERVICE_INTERROGATE
- CR = SERVICE_USER_DEFINED_CONTROL
- RC = READ_CONTROL

Allow SY CCLCSWRPWPDTLOCRRC:
- CC, LC, SW, RP (SERVICE_START), WP (SERVICE_STOP), DT, LO, CR, RC

Allow BA CCDCLCSWRPWPDTLOCRSDRCWDWO:
- CC, DC, LC, SW, RP, WP, DT, LO, CR, SD, RC, WD (WRITE_DAC), WO (WRITE_OWNER)

SACL: AU (audit), FA (failed access), all rights CCDCLCSWRPWPDTLOCRSDRCWDWO, WD (Everyone).

SIDs: IU = INTERACTIVE (interactive users), SU = SERVICE (service logon sessions), BA = BUILTIN_ADMINISTRATORS, SY = LOCAL_SYSTEM, WD = WORLD/Everyone.

ACE ordering note: the SDDL presents denies first (canonical order), ensuring access check denial precedence.

Net effect per principal:
- Interactive users & service accounts: can query config, interrogate, send user-defined controls, read the SD; cannot query status (hidden from enum), stop, pause, change config, delete.
- Administrators: can start, interrogate, user-control, read/write DACL, take ownership; cannot query status (hidden), stop, pause, change config, delete — unless they first use their WRITE_DAC to remove the deny ACEs.
- SYSTEM: everything except change config/delete/write-DACL/write-owner — i.e., everything the SCM needs for routine start/stop/status. This is the crucial design point: services.exe runs as SYSTEM, so hiding does not interfere with boot-time start.

That last point: SY lacks DC/SD/WD/WO — SYSTEM can't change config via its own token without taking ownership, but it doesn't need to.

sc.exe sdset syntax: `sc.exe sdset <service> "D:(...)(...)S:(...)"` — well established; sc sdshow to read back.

Registry: HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security, value name "Security", REG_BINARY. Documented: CreateService's lpSecurityDescriptor "is stored in the Security value of the service's registry key" — well-established.

Programmatic APIs from material unit 5: securitybaseapi.h (SetSecurityDescriptorControl), aclapi.h (SetNamedSecurityInfo). I'll add the SDDL conversion path (ConvertStringSecurityDescriptorToSecurityDescriptorW + SetServiceObjectSecurity) as the standard companion — is that "inventing"? SetServiceObjectSecurity is the canonical API for this; ConvertStringSecurityDescriptorToSecurityDescriptor is documented in sddl.h. These are well-established Windows APIs and the Implementation Details section asks "what an implementation would look like". That's allowed ("briefly describe what an implementation would look like (data structures, syscalls...)"). The template explicitly invites this for the no-source case. Good.

Lab reference: SEC670 Lab 4.4 "NotInService" — develop service, install code, hide code via Win32 APIs (atlas-post-exploit-part8 unit 13).

Length check: I'll aim ~1400-1600 words.

Also must avoid banned words. Check: no "elegant", "notably" (banned is "notable"), avoid "worth noting", "key insight". Careful with "essentially" — banned. Avoid.

No suggestions ("Consider also") — but describing the implementation-shape paragraph is mandated by the template; keep it descriptive, not suggestive.

H1: "# Service Hiding from SCM Enumeration — DACL-Based Suppression of Service Visibility" — the template: `# <Technique Name> — <One-Line Purpose>`.

Now write.

Also mitre URL format: https://attack.mitre.org/techniques/T1564/ and https://attack.mitre.org/techniques/T1543/003/.

Sysmon/ETW: don't invent IDs. The Security event for service object access: I won't cite 4663 unless confident... 4663 is "An attempt was made to access an object" — applies to file system/registry/kernel objects; service object access auditing... I recall service SACLs generate 4663 events with Object Server "Service Control Manager". I believe that's correct (object access auditing covers SCM objects). But to be safe: "Security log object-access auditing (when Audit Object Access policy is enabled)" without a hard event ID. Rule says do not invent Sysmon event IDs / ETW GUIDs. I'll say: material does not document telemetry sources; the SACL implies Security-log object-access auditing; GUID not documented in material — actually no ETW mentioned at all, so I just won't raise ETW.

Write the card now. Ensure sections in exact order, no extras.

Body word count — I'll write generously in Mechanism and OS Internals.

One more check on "would_relate_to" — T-017 and T-020 only. Related Techniques section: exactly those two.

Tags count 5-10: [service-hiding, sddl, security-descriptor, dacl, scm, enumeration-evasion, acl-tampering, persistence-stealth] = 8. Good.

Frontmatter name: "Service Hiding from SCM Enumeration" (5 words) ✓.