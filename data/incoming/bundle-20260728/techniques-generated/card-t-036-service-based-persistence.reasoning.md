Let me analyze the task:

1. I need to produce a technique card for T-036: Windows Service-Based Persistence via SCM
2. Category: persistence, Tier: A
3. Member notes: 5 LGTM notes listed
4. would_relate_to: T-017

Let me check the source files provided:
- `src/client_rust/src/browser_hook.rs` — This is about browser extension hooking with persistence layers (shortcut patching, Run key, schtask, protocol handler). It uses schtasks and reg.exe but NOT SCM service creation (no OpenSCManager/CreateService calls). This does NOT implement service-based persistence via SCM. The persistence here is Run key + scheduled task via `schtasks` command, not the SCM API. So this file does NOT count as implementing this technique.
- `src/dark_crystal/crowd/src/byovd.rs` — This DOES use OpenSCManagerW, CreateServiceW, StartServiceW, DeleteService, ControlService. But it's for BYOVD — loading a kernel driver temporarily for EDR file deletion, NOT for persistence. It registers the driver as a kernel-mode service via SCM but with SERVICE_DEMAND_START (on-demand, not auto), and it explicitly removes the service registration after use. The purpose is NOT persistence — it's transient driver loading. The comment says "On-demand start type (no persistence in boot sequence)". So this file uses the SCM APIs but does NOT implement service-based persistence. The primary mechanism of this card is persistence (surviving reboot, auto-start). The BYOVD file explicitly avoids persistence. So I should NOT attribute this as an implementation of T-036.

Wait — let me re-read rule 8: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes." The primary mechanism of T-036 is SCM-based persistence — services that survive reboot and auto-start. byovd.rs's `register_and_start_service` uses CreateServiceW with SERVICE_DEMAND_START and then deletes the service. That is explicitly NOT persistence. The card documents persistence. So byovd.rs uses the same API family but for a different purpose (transient driver load, cleanup after). I should state no current implementation, but I can mention that byovd.rs demonstrates the SCM API surface (OpenSCManagerW/CreateServiceW/StartServiceW/DeleteService) already exists in the codebase for a different purpose. Actually, the rules say if no source implements it, write the "No current implementation" line and describe what an implementation would look like. I can note the SCM API usage in byovd.rs as a related building block but must be careful — the Key Implementation Details section says "If no source implements this technique" then write the standard line. I think the cleanest approach: state no current implementation, note that byovd.rs exercises the same SCM API family for transient driver loading (not persistence), and describe what a persistence implementation would look like.

Actually, let me be careful about the byovd.rs mention. The rule says "False attribution is worse than 'no current implementation'". Mentioning that byovd.rs uses SCM APIs for a different purpose is factual and not false attribution, as long as I'm clear it does not implement this technique. I'll include it as context in the Key Implementation Details section.

- `src/dark_crystal/crowd/src/chain.rs` — the chain orchestrator, mentions persistence phase 6 but that's the T-017 five-layer suite, not services. No service persistence here.

So: `crate: dark_crystal` or `none`? The frontmatter `crate` field — since no source implements this technique, `crate: none` and `source_file: none`. Hmm, but the cluster spec says "crate: dark_crystal" implicitly? No, the spec says proposed category persistence, tier A. It doesn't assign a crate. Since there's no implementation, `crate: none` and `source_file: none`.

Wait, but let me double check the browser_hook.rs persistence — Layer 3 is Scheduled Task via `schtasks` command line, not a service. And Run key. Those are not SCM services. Confirmed not an implementation.

Now for the MITRE mapping: The best fit for Windows service persistence is T1543.003 (Create or Modify System Process: Windows Service). That's the canonical ATT&CK ID. Secondary could include T1569.002 (System Services: Service Execution) for the execution aspect. I'll use T1543.003 as primary, and add T1569.002 as secondary. Both are real ATT&CK IDs I'm confident about.

Now the content. Let me gather the material facts:

From atlas-post-exploit-part6 (Book 4, units 9-33):
- Services ripe for attackers: commonly misconfigured, incorrect permissions, automatic starts, run as SYSTEM, most users don't pay attention to new/modified services
- What to Change: ImagePath (Registry key holding absolute path to service binary), binPath (typically matches ImagePath), FailureCommand (what happens if service fails to start or is terminated)
- Service failure criteria: SCM considers a service failed when it terminates without reporting SERVICE_STOPPED, or when Win32ExitCode member of SERVICE_STATUS is not ERROR_SUCCESS
- SERVICE_FAILURE_ACTIONS structure: dwResetPeriod, lpRebootMsg, lpCommand, cActions, lpsaActions (SC_ACTION array)
- Implementation pseudo code: SecureZeroMemory the struct, dwResetPeriod = INFINITE, lpRebootMsg = "", lpCommand = "ping C2", cActions = 0, lpsaActions = NULL, then ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)
- Hiding a service via SDDL — no kernel driver or function hooking needed
- sc.exe sdshow to view security descriptors
- Joshua Wright's real-world SDDL hiding string: `D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`
- Unhiding: sc.exe sdset SWCUEngine with the restore SDDL: `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`
- Module summary: persistence via services, APIs related to services, creating new services and modifying existing ones, manual service hiding using SDDL

From atlas-binary-analysis-part4 (units 32-37):
- QueryServiceStatusEx: 5 params — hService (SC_HANDLE), InfoLevel (SC_STATUS_TYPE), lpBuffer, cbBufSize, pcbBytesNeeded; Boolean return; used to query services for detailed info after enumerating
- QueryServiceConfig: obtains configuration of a service; SC_HANDLE, QUERY_SERVICE_CONFIG pointer, buffer size, bytes needed
- ChangeServiceConfig: modifies a service's configuration; Boolean return
- Services: Creation (2) — VOID WINAPI EvilMain(...) service main function
- CreateService / CreateServiceA / SC_HANDLE
- Parameter details: lpBinaryPathName must be full path to executable, command-line args can be appended after exe name; lpLoadOrderGroup optional NULL; lpdwTagId only for kernel drivers; lpDependencies optional list of services this depends on; lpServiceStartName is the account the service runs under; lpPassword for that account

From atlas-exploit-dev-part3 (units 2, 11, 12):
- Service creation C code: SERVICE_TABLE_ENTRY table with {ServiceName, EvilMain}, NULL terminator; StartServiceCtrlDispatcher(table) called from main; if other services share the process address space, the table is passed as argument
- Programmatically Hide a Service: securitybaseapi.h and aclapi.h headers; SetSecurityDescriptorControl and SetNamedSecurityInfo APIs; manual SDDL vs programmatic APIs
- Lab 4.4 NotInService: develop custom service, install code, hide code via Win32 APIs

From atlas-post-exploit-part12 (units 1-16):
- Lab 4.1 PersistentService: creating your own service for persistence
- "When you have administrative and/or SYSTEM privileges, creating a service is a perfect action to take"
- Hiding a service similar to hiding a process; no kernel driver or function hooking needed
- SDDL structure: O: owner_sid, G: group_sid, D: dacl_flags, S: sacl_flags; SDDL is a string format for ConvertSecurityDescriptorToStringSecurityDescriptor and ConvertStringSecurityDescriptorToSecurityDescriptor APIs
- ACE string layout: ace_type (A access allowed, D access denied, OA object allowed, OD object denied, AU audit, AL alarm), ace_flags (CI container inherit, OI object inherit, NP no propagate, IO inherit only, ID inherited, SA audit success), generic rights (GA GR GW GX), standard rights (RC read control, SD standard delete, WD write dac, WO write owner), directory rights (RP WP CC DC LC SW), registry rights (KA KR KW KX), file rights (FA FR)
- sc.exe sdset for unhiding
- Programmatic hiding via SetNamedSecurityInfo

From atlas-misc-part1 (units 1, 10):
- Book 4 module: "persist using services. This includes services that we take advantage of or services that we create ourselves."
- ImagePath/binPath/FailureCommand modification for persistence

Now, tier: A is proposed. T-017 is S tier with five layers + resilience. Service persistence is a well-known, heavily-detected technique (Sysmon, Windows Event 7045). A tier seems right — it's operationally valuable (SYSTEM context, survives reboot) but noisier than the T-017 layers.

Detection considerations: The material mentions hiding via SDDL as the primary evasion. The material does not discuss ETW/Sysmon explicitly. Per rule 4, I must not invent detections. But well-established Windows documentation knowledge is allowed. Hmm — rule says "Every claim in the card must trace to either: the atlas material provided, the related T-NNN cards, the Rust source, or well-established Windows internals documentation." So for detection, the material says: hiding via SDDL makes the service invisible to sc.exe and "several tools like the sc.exe command-line utility"; PowerShell Get-Service is mentioned in the exercise solution context. The material mentions cleanup/unhiding via sc.exe sdset. I can note: material describes SDDL hiding as bypass for enumeration tools; the material does not discuss ETW/Sysmon detection — I'll write what's in the material and say the material doesn't cover telemetry beyond that. Well-known facts like Windows Event ID 7045 (service installed) — is that "well-established Windows documentation"? It's fairly well established, but the rule says for detection specifically "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.'" The material DOES cover detection-adjacent content (SDDL hiding, sc.exe sdshow, enumeration evasion). So I'll write the detection section based on the material: enumeration surface (sc.exe query, Get-Service, services.msc), the SDDL hiding bypass, residual artifacts (service registry keys under HKLM\SYSTEM\CurrentControlSet\Services\<name> — the material mentions ImagePath as a Registry key, so the services registry hive is grounded), and cleanup pattern (unhide + delete). I should be careful: Event ID 7045 — I could mention it as well-established but the rule about not inventing Sysmon event IDs and ETW GUIDs is strict. Event 7045 is a Windows System log event from Service Control Manager — this is well-established documentation. I'll mention it carefully as "Windows System event log records service installation (Event ID 7045, Service Control Manager)" — this is extremely well documented. Actually, to be safe and comply with "Do not invent detections" — but 7045 is not invented, it's well-established. The rule says claims must trace to material OR well-established Windows internals documentation. Event ID 7045 is well-established Microsoft documentation. I'll include it but keep ETW GUIDs out (write "GUID not documented in material" if needed — better to just not mention GUIDs at all).

Structure of the card:

Frontmatter:
- id: T-036
- name: Service-Based Persistence via SCM (or "Windows Service Persistence via SCM with SDDL Hiding" — 4-8 words). Let me pick "Windows Service Persistence via SCM" — the canonical name is "Windows Service-Based Persistence via SCM". That's 6 words (counting "Service-Based" as one). Good.
- category: persistence
- tier: A
- crate: none
- source_file: none
- mitre: T1543.003
- mitre_secondary: [T1569.002]
- tags: persistence, scm, create-service, sddl, dacl-hiding, service-failure-actions, imagepath, system-privilege — 5-10 kebab-case. Let me do: [persistence, scm, create-service, sddl, dacl-hiding, failure-actions, imagepath, system-context]
- origin: atlas-synthesis
- member_notes: exact 5 IDs

Sections:

# Windows Service-Based Persistence via SCM — SYSTEM-Context Autostart Through the Service Control Manager

## Summary
3-5 sentences. First sentence standalone. What: create or modify Windows services via SCM Win32 APIs (OpenSCManager, CreateService, ChangeServiceConfig, ChangeServiceConfig2) so the implant relaunches on boot under LocalSystem. OS primitive: SCM + services registry. Why: survives reboot, SYSTEM context, failure actions provide re-execution triggers. Detection surface: service enumeration (sc.exe, Get-Service, services.msc) — mitigated by SDDL DACL manipulation that hides the service without kernel drivers or hooking.

## Mechanism
Numbered steps:
1. Privilege gate — admin/SYSTEM required (SC_MANAGER_CREATE_SERVICE on local SCM). Material: "When you have administrative and/or SYSTEM privileges, creating a service is a perfect action to take."
2. OpenSCManager(A/W) with SC_MANAGER_ALL_ACCESS or SC_MANAGER_CREATE_SERVICE → SC_HANDLE to SCM database (SERVICES_ACTIVE_DATABASE).
3. CreateService with: lpBinaryPathName full path to exe (+ optional args appended), dwServiceType (SERVICE_WIN32_OWN_PROCESS / SHARE_PROCESS, or SERVICE_KERNEL_DRIVER for drivers), dwStartType (SERVICE_AUTO_START for persistence / SERVICE_DEMAND_START for on-demand), dwErrorControl (SERVICE_ERROR_NORMAL), lpServiceStartName (NULL → LocalSystem), lpDependencies optional, lpdwTagId only for kernel drivers.
4. Service binary contract: main() calls StartServiceCtrlDispatcher with SERVICE_TABLE_ENTRY array {name, ServiceMain}, NULL-terminated; ServiceMain registers handler and reports status to SCM promptly or SCM terminates the service.
5. Modify existing services: ChangeServiceConfig to rewrite binPath/ImagePath; ImagePath is the registry key holding the absolute path to the service binary; values/args in the key are passed to the executable.
6. Failure actions: SERVICE_FAILURE_ACTIONS struct (dwResetPeriod, lpRebootMsg, lpCommand, cActions, lpsaActions) applied via ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa). SCM declares failure when the service terminates without reporting SERVICE_STOPPED or Win32ExitCode != ERROR_SUCCESS. lpCommand gives a re-execution trigger (material example: "ping C2").
7. Enumeration recon before/after: QueryServiceStatusEx (SC_HANDLE, SC_STATUS_TYPE, lpBuffer, cbBufSize, pcbBytesNeeded) and QueryServiceConfig to read existing services.
8. Hiding: modify the service object's DACL. Manual: sc.exe sdset <name> <SDDL>. Programmatic: SetNamedSecurityInfo (aclapi.h) with security descriptor control via SetSecurityDescriptorControl (securitybaseapi.h). Joshua Wright's engagement SDDL adds deny ACEs (D;;DCLCWPDTSD;;;IU/SU/BA) for Interactive User, Service, Built-in Administrators while preserving SYSTEM full control.
9. Cleanup: unhide via sc.exe sdset with restore SDDL, then DeleteService; close SC_HANDLEs with CloseServiceHandle.

## OS Internals Context
- SCM (services.exe) is the RPC server managing the services database; user-mode APIs in advapi32.dll (OpenSCManager, CreateService, etc.) marshal over RPC to services.exe. The database persists in HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName> — ImagePath value holds the binary path (material confirms ImagePath is a registry key).
- Service objects are securable kernel objects with security descriptors; DACL controls who can query/start/stop/configure. SDDL is the string format consumed by ConvertStringSecurityDescriptorToSecurityDescriptor / produced by ConvertSecurityDescriptorToStringSecurityDescriptor. ACE layout: (ace_type;ace_flags;rights;object_guid;inherit_guid;account_sid) — material lists ace types A/D/OA/OD/AU/AL, flags CI/OI/NP/IO/ID/SA, generic rights GA/GR/GW/GX, standard rights RC/SD/WD/WO.
- Deny-ACE-first ordering: placing deny ACEs for enumeration-relevant rights before allow ACEs makes QueryServiceStatus/EnumServicesStatus fail access checks for those principals, so the service disappears from sc.exe and "several tools" — while SY (LocalSystem) retains CCLCSWRPWPDTLOCRSDRCWDWO (full) so SCM itself can still manage the service. No kernel driver or function hooking required — hiding is purely an access-control effect on the SCM's own access checks.
- SCM failure semantics: SERVICE_STATUS reporting via SetServiceStatus; a service that exits without reporting SERVICE_STOPPED or with Win32ExitCode != ERROR_SUCCESS is "failed", triggering SERVICE_FAILURE_ACTIONS — sc_action types and lpCommand. This is why a crashed/terminated implant service can re-execute.
- Service process model: SERVICE_WIN32_OWN_PROCESS vs shared svchost (SERVICE_WIN32_SHARE_PROCESS); dispatcher table allows multiple services per process (material: "if other services are going to share this process' address space, the table is passed as an argument").
- StartServiceCtrlDispatcher must be called quickly (SCM timeout ~30s — hmm, is that in material? Not explicitly. The material says "if they do not [answer to the SCM], they are promptly terminated." I'll say the material emphasizes services must report to the SCM promptly or be terminated — keep to what material says).
- lpdwTagId is for kernel drivers only — tag ordering in load-order groups.

## Key Implementation Details
No current implementation in HUGIN source. Note: dark_crystal/crowd/src/byovd.rs exercises the same SCM API family (OpenSCManagerW, CreateServiceW with SERVICE_KERNEL_DRIVER | SERVICE_DEMAND_START, StartServiceW, DeleteService) for transient vulnerable-driver loading — it explicitly deletes the registration afterward and does not implement persistence. browser_hook.rs persistence layers use schtasks/Run keys, not SCM services. What an implementation would look like: a persist/service.rs module beside T-017's layers — winapi winsvc bindings for OpenSCManagerW/CreateServiceW/ChangeServiceConfig2W, a SERVICE_FAILURE_ACTIONS struct with lpCommand pointing at the implant, ConvertStringSecurityDescriptorToSecurityDescriptorW + SetServiceObjectSecurity (or SetNamedSecurityInfoW) for the DACL hide, and integration into install_all/resilience monitor. Keep to one paragraph as instructed.

Wait — the template says: write the standard line, "See the atlas material for reference implementations in <source language/tool>." — the atlas material is C (SEC670 C code snippets: SERVICE_TABLE_ENTRY, ChangeServiceConfig2 pseudo code) and sc.exe command line. So: "See the atlas material for reference implementations in C (SEC670 service module) and sc.exe command-line."

## Why It Matters
- T-017's five layers don't include SCM services; the SEC670 material dedicates a full module to it. Operationally distinct: runs as SYSTEM (not user context like HKCU COM hijack), SCM-managed restart semantics, failure actions give redundancy, and the SDDL hiding primitive is reusable across any operator-installed service. It fills the "elevated, boot-time, SYSTEM-context" gap that user-context layers (COM hijack HKCU, schtask) don't cover. 2-4 sentences.

## Detection Considerations
- Telemetry: the material's detection discussion centers on enumeration tools — sc.exe query/enum, PowerShell Get-Service, services.msc. Service security descriptors are viewable via sc.exe sdshow. The material does not discuss ETW/Sysmon. I can add: Windows System event log Event ID 7045 (well-established Microsoft documentation) records new service installation — that's well-established. Residual artifacts: HKLM\SYSTEM\CurrentControlSet\Services\<name> key with ImagePath value (material-grounded), the service binary on disk, SDDL modifications on the service object.
- Bypass: SDDL DACL hiding (deny read/enumerate to IU/SU/BA while retaining SY full control) — hides from sc.exe and several tools without kernel drivers or hooking. Material explicitly notes the beauty: "no need for a kernel driver or function hooking."
- Residual: registry key, binary path, DACL modification itself is an artifact visible via sdshow to anyone who queries the object directly (deny ACEs are themselves anomalous — hmm, is that in material? The material shows unhiding restores the descriptor, implying the hidden state is detectable by direct descriptor inspection. I'll say: the modified DACL remains visible to direct sc.exe sdshow queries by principals who retain READ_CONTROL, which is why cleanup restores the original descriptor via sc.exe sdset).

## Related Techniques
- **T-017 Five-Layer Persistence with Resilience Monitor** — service persistence is a sixth, elevated-context layer absent from the suite; complements the HKCU/user-context layers and would slot into the same install_all/resilience-monitor model.
Only T-017 is in would_relate_to. Should I mention BYOVD? It's not in would_relate_to and there's no T-NNN card text provided for it (the manifest lists T018-byovd as a card slug in the old manifest, but the current vault INDEX lists T-018 as Edo Tensei — the manifest's card slugs are stale/old numbering). I should not invent relationships. Only T-017. Good — rule 9 says restraint.

## References
- Atlas material: atlas-binary-analysis-part4.md, atlas-exploit-dev-part3.md, atlas-misc-part1.md, atlas-post-exploit-part12.md, atlas-post-exploit-part6.md
- MITRE ATT&CK: T1543.003 https://attack.mitre.org/techniques/T1543/003/ and T1569.002 https://attack.mitre.org/techniques/T1569/002/
- LGTM notes: the 5 IDs
- Public references: Joshua Wright's SDDL service-hiding string (named in atlas material); SANS SEC670 Book 4 "Persistence: Die Another Day"

## Source Reference
No current implementation. See atlas material and MITRE reference for public tooling. I can note byovd.rs uses the SCM API family for transient driver loading (not persistence).

Length: target 1200-1800 words body. Let me draft carefully.

Tags: 5-10 kebab-case: [persistence, scm, create-service, sddl, dacl-hiding, failure-actions, imagepath, system-context, service-main] — that's 9. Good.

mitre: T1543.003 — "Create or Modify System Process: Windows Service". Confident.
mitre_secondary: [T1569.002] — "System Services: Service Execution". Confident.

Name: "Windows Service Persistence via SCM" — canonical is "Windows Service-Based Persistence via SCM". I'll use the canonical. H1: "Windows Service-Based Persistence via SCM — SYSTEM-Context Autostart Through the Service Control Manager".

Word count check — I'll aim for ~1400-1600 words of body.

Let me be careful about banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "the beauty" — material says "The beauty about this is there is no need for a kernel driver" — I can quote it as material attribution? Better to paraphrase: "the material emphasizes that hiding requires no kernel driver or function hooking." Avoid quoting with banned word. Also avoid "cleanly", "clean" — I used "cleanup" which is fine (it's a noun for the cleanup pattern, not the banned adjective "clean"). "Cleanup" as a term is used in the material ("cleanup pattern", "clean up"). The banned word is "clean" as praise; "cleanup" is standard operational terminology. I'll keep "cleanup".

Also banned phrases: "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". Avoid.

No first person, no rhetorical questions, no exclamation marks. The material has "To be, or not to be, a service?" — don't use it.

Third-person present declarative. Good.

Let me now draft the full card.

Mechanism steps — concrete, numbered:

1. Gate on privilege: material states service creation is the action to take once administrative and/or SYSTEM privileges are held; OpenSCManager with SC_MANAGER_CREATE_SERVICE requires admin on the local machine.
2. Open the SCM database: OpenSCManager(lpMachineName NULL = local, lpDatabaseName NULL = SERVICES_ACTIVE_DATABASE, dwDesiredAccess) returns an SC_HANDLE.
3. Enumerate/interrogate existing services when modifying rather than creating: QueryServiceStatusEx (hService, SC_STATUS_TYPE InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded) for runtime state; QueryServiceConfig (hService, QUERY_SERVICE_CONFIG, cbBufSize, pcbBytesNeeded) for the persisted configuration.
4. Create the service: CreateService(hSCM, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword). Material details: lpBinaryPathName must be the full path to the executable and may carry command-line arguments appended after the exe name; lpLoadOrderGroup optional NULL; lpdwTagId only meaningful for kernel drivers; lpDependencies optional; lpServiceStartName selects the run-as account (NULL → LocalSystem).
5. Build the service binary to the SCM contract: main() builds a SERVICE_TABLE_ENTRY array — {ServiceName, ServiceMain} rows terminated by {NULL, NULL} — and calls StartServiceCtrlDispatcher(table). Material: the dispatcher table supports multiple services sharing one process address space. ServiceMain (material's example: VOID WINAPI EvilMain(...)) must register a control handler and report status to the SCM promptly; the SCM terminates services that do not answer.
6. Or hijack an existing service: ChangeServiceConfig rewrites the configuration — the material names ImagePath (registry key holding the absolute path to the service binary on disk) and binPath (typically matches ImagePath; arguments in the value are passed to the executable) as the modification points.
7. Arm the failure trigger: populate SERVICE_FAILURE_ACTIONS {dwResetPeriod, lpRebootMsg, lpCommand, cActions, lpsaActions} and apply with ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa). Material pseudo-code: SecureZeroMemory the struct, dwResetPeriod = INFINITE, lpRebootMsg = "", lpCommand = "ping C2", cActions = 0, lpsaActions = NULL.
8. Understand the trigger condition: SCM declares failure when the service terminates without reporting SERVICE_STOPPED, or when the Win32ExitCode member of SERVICE_STATUS is not ERROR_SUCCESS — at that point the failure actions (including lpCommand) fire, giving a re-execution path on crash or kill.
9. Hide the service: rewrite the service object's DACL. Manually via sc.exe sdset <name> <SDDL>; programmatically via SetNamedSecurityInfo (aclapi.h) with SetSecurityDescriptorControl (securitybaseapi.h) for control flags. The material's engagement example (Joshua Wright): D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
10. Cleanup: restore the descriptor with sc.exe sdset using the unhide SDDL (material's SWCUEngine example), then DeleteService and CloseServiceHandle on both SC_HANDLEs.

Hmm, that's 10 steps. Good — mechanism requires it.

OS Internals Context — paragraphs:
1. SCM architecture: services.exe as the SCM; advapi32 stubs marshal RPC; database at HKLM\SYSTEM\CurrentControlSet\Services; each subkey a service; ImagePath value. The SCM is "the end-all-be-all" per material — services answer to it.
2. Securable object model: service objects have security descriptors; SCM performs access checks on every operation; SDDL is the string format for the two conversion APIs; O:/G:/D:/S: header; ACE six-field layout; deny-first canonical ordering means deny ACEs for DCLCWPDTSD rights on IU/SU/BA precede allows, so enumeration (which needs SERVICE_QUERY_STATUS / SERVICE_ENUMERATE — hmm, the SDDL rights letters: CC = SERVICE_QUERY_CONFIG, LC = SERVICE_QUERY_STATUS, SW = SERVICE_ENUMERATE_DEPENDENTS? Actually the standard service rights mapping: CC=QUERY_CONFIG, DC=CHANGE_CONFIG, LC=QUERY_STATUS, DT=STOP, RP=START, WP=PAUSE_CONTINUE, LO=INTERROGATE, CR=USER_DEFINED_CONTROL, plus SD/RC/WD/WO standard rights. The deny set DCLCWPDTSD = DC(CHANGE_CONFIG)+LC(QUERY_STATUS)+WP(PAUSE)+DT(STOP)+SD(DELETE). Interesting — the deny ACE doesn't remove enumeration rights per se (enumeration of services via EnumServicesStatus requires SC_MANAGER_ENUMERATE_SERVICE on the SCM, not per-service rights)... Actually, per-service hiding works because EnumServicesStatus filters out services the caller cannot query? Hmm. Let me not over-claim. The documented behavior: denying SERVICE_QUERY_STATUS (LC) and other rights makes the service inaccessible and it disappears from sc.exe query and tools per the material. The material says hiding "from the user and from several tools like the sc.exe command-line utility". I'll describe the ACE rights letters as the material gives them without over-explaining which right does what — the material's SDDL unit gives generic rights GA/GR/GW/GX and standard rights RC/SD/WD/WO; the service-specific letters (CC, LC, DC, DT, RP, WP, LO, CR) appear in the Wright string but the material doesn't expand them. I can say: the string combines service-specific right pairs with well-known SIDs — IU (Interactive), SU (Service), BA (Built-in Administrators), SY (LocalSystem), WD (World/Everyone). Well-known SID aliases: those are well-established SDDL documentation. Deny ACEs for IU/SU/BA on DC/LC/WP/DT/SD rights while granting SY full control (CCDCLCSWRPWPDTLOCRSDRCWDWO). The effect per material: the service remains manageable by SCM/SYSTEM but invisible to interactive users and admin tools.

Careful: does BA get an allow too in Wright's string? Yes: (A;;CCDCLCSWRPWPDTLOCRRC;;;BA) — BA gets an allow with RC but also a deny first (D;;DCLCWPDTSD;;;BA). Deny-first wins for the denied bits. The unhide restore SDDL: D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;...;;;WD). Good.

3. Failure semantics: SERVICE_STATUS / SetServiceStatus contract; Win32ExitCode; SCM failure determination triggers SERVICE_FAILURE_ACTIONS; SC_ACTION array lpsaActions with cActions; lpCommand executed. dwResetPeriod = INFINITE per material pseudo-code.
4. Process model: OWN_PROCESS vs SHARE_PROCESS; dispatcher table; SCM starts the binary and waits for StartServiceCtrlDispatcher; timeout/termination if no answer. Kernel driver services (SERVICE_KERNEL_DRIVER) have no ServiceMain dispatcher contract — they load via the I/O manager; lpdwTagId applies to drivers only. (Grounded: material says lpdwTagId is only for kernel drivers; byovd.rs demonstrates SERVICE_KERNEL_DRIVER path but I should keep source references in Key Implementation Details. I can mention driver services as internals contrast — the material's unit 37 says "lpdwTagId is only for kernel drivers and as this is not a kernel class, we do not need to worry about this one." Good.)

Key Implementation Details: standard no-implementation line + note on byovd.rs SCM usage + one paragraph on what implementation would look like.

Wait — the template's standard line: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>." Then "briefly describe what an implementation would look like (data structures, syscalls, roughly one paragraph)."

I'll write the line, then a paragraph noting: nearest existing code is crowd/src/byovd.rs which opens the SCM (OpenSCManagerW, SC_MANAGER_ALL_ACCESS), registers a SERVICE_KERNEL_DRIVER | SERVICE_DEMAND_START service via CreateServiceW, starts it, then unwinds with ControlService(SERVICE_CONTROL_STOP)/DeleteService and a 3-pass file shred — the same API family in service of a transient, explicitly non-persistent driver load. A persistence implementation would instead register SERVICE_WIN32_OWN_PROCESS (or a DLL hosted in svchost) with SERVICE_AUTO_START, point lpBinaryPathName at the implant, apply SERVICE_FAILURE_ACTIONS via ChangeServiceConfig2W, convert the hiding SDDL with ConvertStringSecurityDescriptorToSecurityDescriptorW, and apply it via SetServiceObjectSecurity (or SetNamedSecurityInfoW), and wire install/remove into crowd's persist module (install_all + resilience monitor) alongside the existing five layers. That's grounded in the byovd.rs code I read and the T-017 card's architecture.

Hmm — SetServiceObjectSecurity: is that in the material? The material names SetNamedSecurityInfo and SetSecurityDescriptorControl. I'll use SetNamedSecurityInfoW (material-grounded) and mention SetServiceObjectSecurity — that's the natural service-specific API; but to be safe stick to what the material names: SetNamedSecurityInfo. ConvertStringSecurityDescriptorToSecurityDescriptor is named in the material (SDDL unit). OK.

Why It Matters: 2-4 sentences.
- T-017's five layers all execute in user context or user-triggered contexts; none provides an SCM-managed, boot-time SYSTEM-context layer. Service persistence fills the elevated-context gap: LocalSystem by default, auto-start across reboots, SCM-enforced restart semantics, and a failure-command channel that re-executes on crash. The SDDL DACL-hiding primitive is reusable against any service the operator installs and requires no kernel driver or hooking. SEC670 dedicates a full module (services revisited, Lab 4.1 PersistentService, Lab 4.4 NotInService) to this layer, which the vault did not previously surface.

Detection Considerations:
- Telemetry sources: The material frames the detection surface as enumeration: sc.exe query/enum, PowerShell Get-Service, and security-descriptor review via sc.exe sdshow. It does not discuss ETW providers, Sysmon, or kernel callbacks for this technique. I'll add: Windows service installation is recorded in the System event log as Event ID 7045 from the Service Control Manager provider (well-established Microsoft documentation; not covered in the training material). Registry: the services database at HKLM\SYSTEM\CurrentControlSet\Services\<name> — modification of an existing service's ImagePath leaves a registry diff.
- Bypass options: SDDL DACL hiding per the material — deny ACEs against IU/SU/BA remove the service from standard enumeration while SY retains full control; no kernel driver or function hooking required. The material also notes most users do not pay attention to new or modified services — the tradecraft rationale for modifying an existing service (ImagePath/binPath) rather than creating a new one.
- Residual artifacts: services registry key (ImagePath, plus FailureCommand config), the service binary on disk referenced by lpBinaryPathName, and the modified security descriptor itself — direct sc.exe sdshow inspection by a principal holding READ_CONTROL reveals the anomalous deny ACEs, which is why the material's cleanup restores the original descriptor via sc.exe sdset before deleting the service.

Related Techniques:
- **T-017 Five-Layer Persistence with Resilience Monitor** — service persistence is the elevated (SYSTEM, boot-time) counterpart absent from T-017's five user-context layers; it slots into the same install_all + 30-minute resilience-monitor model as a sixth layer.

References:
- Atlas material: atlas-binary-analysis-part4.md (units 32-37), atlas-exploit-dev-part3.md (units 2, 11, 12), atlas-misc-part1.md (units 1, 10), atlas-post-exploit-part12.md (units 1-16), atlas-post-exploit-part6.md (units 9-33)
- MITRE: T1543.003 URL https://attack.mitre.org/techniques/T1543/003/, T1569.002 URL https://attack.mitre.org/techniques/T1569/002/
- LGTM notes: 5 IDs
- Public references: Joshua Wright's SDDL service-hiding string (named in the SEC670 material); SANS SEC670 Book 4 "Persistence: Die Another Day" (Services Revisited module, Lab 4.1 PersistentService, Lab 4.4 NotInService)

Source Reference: "No current implementation. dark_crystal/crowd/src/byovd.rs exercises the same SCM API family (OpenSCManagerW/CreateServiceW/StartServiceW/DeleteService) for transient driver loading only. See atlas material and MITRE reference for public tooling."

Word count: Let me draft and count roughly. I'll aim for solid depth in OS Internals Context and Mechanism.

Also the H1 format: "# <Technique Name> — <One-Line Purpose>".

Draft the frontmatter tags: [persistence, scm, create-service, sddl, dacl-hiding, failure-actions, imagepath, system-context, service-main] — 9 entries, all kebab-case. Good.

Now write it. Watch for banned words throughout: no "elegant", "robust", "notable", "sophisticated". No "essentially", "at its core", "worth noting", "interestingly". No exclamation marks. Third person present.

One more check on the summary: "3-5 sentences... First sentence must be complete and standalone."

Summary draft:
"Windows service-based persistence registers or modifies an entry in the Service Control Manager database so the Service Control Manager relaunches the implant at boot under LocalSystem. The operator calls the advapi32 service APIs — OpenSCManager, CreateService, and ChangeServiceConfig — to create a new auto-start service or to repoint an existing service's ImagePath/binPath at attacker-controlled code, and optionally arms SERVICE_FAILURE_ACTIONS via ChangeServiceConfig2 so a crash or kill re-executes a configured command. The technique exploits two OS primitives: the SCM's role as the authoritative manager of service lifecycles, and the fact that service objects are securable objects whose DACLs can be rewritten with SDDL to hide the service from sc.exe, Get-Service, and similar enumeration tools without a kernel driver or function hooks. Operators use it once administrative or SYSTEM privileges are held because it survives reboot, runs as SYSTEM, and provides SCM-managed restart semantics that user-context persistence lacks. The primary detection surface is service enumeration and the services registry hive, which the SDDL DACL-hiding step directly targets."

That's 5 sentences. Good.

Mechanism numbering — finalize 10 steps as above. Make each concrete with API names/structures.

OS Internals Context — 4-5 paragraphs:
1. SCM database + RPC + registry hive + ImagePath.
2. Securable object model + SDDL format + ACE layout + Wright string breakdown.
3. Why deny-first works for hiding + SCM access checks + SY retains control.
4. SERVICE_STATUS contract + failure determination + SERVICE_FAILURE_ACTIONS fields.
5. Process model OWN vs SHARE + dispatcher + kernel-driver contrast (lpdwTagId).

Let me write the final card now. Count words at the end — need 800+ minimum, target 1200-1800.

For the SDDL breakdown of the Wright string, let me be accurate:
`D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`

- D: header → DACL follows
- (D;;DCLCWPDTSD;;;IU) — deny, rights DC+LC+WP+DT+SD, to IU (Interactive User)
- (D;;DCLCWPDTSD;;;SU) — same deny to SU (Service logon)
- (D;;DCLCWPDTSD;;;BA) — same deny to BA (Built-in Administrators)
- (A;;CCLCSWLOCRRC;;;IU) — allow CC+LC+SW+LO+CR+RC to IU
- (A;;CCLCSWLOCRRC;;;SU) — allow same to SU
- (A;;CCLCSWRPWPDTLOCRRC;;;SY) — allow broader set to SY (LocalSystem)
- (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) — allow full set to BA
- S:(AU;FA;...;;;WD) — SACL: audit all access by Everyone (WD)

Wait — there's an apparent contradiction: BA gets both deny (first) and allow (later). Canonical ACL ordering: deny ACEs first, so BA's denied rights (DC, LC, WP, DT, SD) are denied even though a later allow grants them. The net effect for BA: has CC, SW, LO, CR, RP, RC, WD, WO but NOT DC, LC, WP, DT, SD. LC = SERVICE_QUERY_STATUS — denying query status is what breaks tools. Actually wait — does denying LC hide from sc.exe query? sc.exe query uses EnumServicesStatus/QueryServiceStatus. Hmm. In practice, the documented hiding trick (Wright's) works because deny SERVICE_QUERY_STATUS causes the service to be filtered from enumeration results. I'll describe the string factually without asserting the exact filtering mechanism beyond what the material claims ("hides from sc.exe and several tools"). Also note the net effect: interactive users, service accounts, and even administrators cannot query status, stop, delete, or change config; LocalSystem retains full control so the SCM can still start/manage the service; Everyone is audited. The material says it "applies to several SIDs" and was used on an engagement to hide a created service. I'll present the breakdown as: deny ACEs placed ahead of allows in canonical order strip query/stop/delete/change rights from IU/SU/BA while SY keeps full control.

Hmm, but BA also has an allow-all — I should mention the deny-first ordering means the deny wins for the overlapping rights. That's standard Windows ACL evaluation and is exactly what the string demonstrates. This is well-established internals knowledge.

Right-letter mapping: the material's ACE unit lists generic rights GA/GR/GW/GX, standard rights RC/SD/WD/WO, directory rights, registry rights KA/KR/KW/KX, file rights FA/FR. The service-specific rights letters (CC, DC, LC, SW, RP, WP, DT, LO, CR) are in the Wright string but not expanded in the material. Can I expand them? They're documented in MSDN SDDL/service security documentation — well-established. But to be conservative, I can describe the groups: "deny change-config, query-status, pause/continue, stop, and delete" — these mappings are well-established MSDN service access right strings: CC = SERVICE_QUERY_CONFIG, DC = SERVICE_CHANGE_CONFIG, LC = SERVICE_QUERY_STATUS, SW = SERVICE_ENUMERATE_DEPENDENTS, RP = SERVICE_START, WP = SERVICE_STOP... wait no. Let me recall precisely:

Service-specific rights in SDDL (from MSDN "Service Security and Access Rights"):
- CC — SERVICE_QUERY_CONFIG
- DC — SERVICE_CHANGE_CONFIG
- LC — SERVICE_QUERY_STATUS
- SW — SERVICE_ENUMERATE_DEPENDENTS
- RP — SERVICE_START
- WP — SERVICE_STOP
- DT — SERVICE_PAUSE_CONTINUE
- LO — SERVICE_INTERROGATE
- CR — SERVICE_USER_DEFINED_CONTROL

Hmm — actually I recall DT = SERVICE_STOP? Let me think again. From MSDN access rights string mapping for services: "CC" SERVICE_QUERY_CONFIG, "DC" SERVICE_CHANGE_CONFIG, "LC" SERVICE_QUERY_STATUS, "SW" SERVICE_ENUMERATE_DEPENDENTS, "RP" SERVICE_START, "WP" SERVICE_STOP, "DT" SERVICE_PAUSE_CONTINUE, "LO" SERVICE_INTERROGATE, "CR" SERVICE_USER_DEFINED_CONTROL. Yes — WP = SERVICE_STOP and DT = SERVICE_PAUSE_CONTINUE. I'm fairly confident: "WP" stop, "DT" pause/continue. (Mnemonic from sc.exe documentation.) This matches the common "DCLCWPDTSD" deny set = change config, query status, stop, pause/continue, delete — precisely the rights needed to manage/kill/remove a service. That makes sense for hiding+protecting: you can't query it (invisible-ish), can't stop it, can't delete it, can't reconfigure it — except as SYSTEM.

I'll state this mapping with confidence since it's well-established MSDN documentation, and it's consistent with the operational purpose.

The SACL: S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD) — audit (AU), failed... FA = audit failed? In ACE flags for audit: SA = success audit, FA = failure audit. Material's ace_flags list includes "SA: audit success" (truncated, but FA would be failure audit). So the SACL audits all failed access attempts by Everyone (WD) across all service rights. I can say: the trailing SACL audits failed access by Everyone. That's consistent with material's partial list (SA audit success; FA failure audit is the complement — hmm, the material excerpt only shows "SA: audit success" before truncation to generic rights. FA as failure audit is well-established SDDL. I'll state it as well-established.)

Alright. Also mention sc.exe sdshow BITS example from material (viewing a service's security descriptor).

Also unit: "Viewing Security Descriptors — sec command utility help menu" — there's a custom "sec" tool mentioned. Not needed.

Length check as I write. Let me produce the final output now.

One more consideration on frontmatter `crate`: the enum is dark_crystal|client_rust|none. No implementation → `none`. source_file: `none`.

H1: `# Windows Service-Based Persistence via SCM — SYSTEM-Context Autostart Through the Service Control Manager`

Body word count target 1200-1800. Let me write generously in OS Internals and Mechanism.

Final check on member_notes exact strings:
- lgtm:service-based-persistence-as-distinct-technique
- lgtm:service-based-persistence-with-dacl-hiding
- lgtm:proposed-service-modification-persistence
- lgtm:service-persistence-card
- lgtm:proposed-windows-services-persistence-card

Good. Writing now.