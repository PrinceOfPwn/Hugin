Let me analyze the task:

1. I need to produce a technique card for T-040: SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence
2. Category: persistence, Tier: B
3. Member notes: 4 LGTM notes
4. would_relate_to: T-017

Let me review the materials:

**Cluster spec details:**
- SERVICE_FAILURE_ACTIONS via ChangeServiceConfig2 to execute recovery command when service fails
- Operators force service failure to trigger recovery action
- Survives reboot; SCM-monitored
- Distinct from service-binary-modification persistence; provides fail-safe resilience

**Atlas material grounding:**

From atlas-post-exploit-part1 (unit 12 and 31):
- SERVICE_FAILURE_ACTIONSA sfa; SecureZeroMemory(&sfa, ...); sfa.dwResetPeriod = INFINITE; sfa.lpRebootMsg = ""; sfa.lpCommand = "ping C2"; sfa.cActions = 0; sfa.lpsaActions = NULL; ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);
- "It is best to do this after you have in[stalled]" — truncated
- Unit 30: services ripe for attackers — misconfigured, incorrect permissions, automatic starts, run as SYSTEM. ImagePath, Failure Command mentioned in key cues.

From atlas-post-exploit-part11 (units 37, 38, 39):
- Unit 37: SCM considers a service to have failed when it terminates without reporting SERVICE_STOPPED status. Also if Win32ExitCode member of SERVICE_STATUS structure does not indicate success (ERROR_SUCCESS), it's considered failed. "Services must answer to the SCM and if they do not, they are promptly terminated."
- Unit 39: SERVICE_FAILURE_ACTIONS structure typedef:
```c
typedef struct _SERVICE_FAILURE_ACTIONSA {
  DWORD dwResetPeriod;
  LPSTR lpRebootMsg;
  LPSTR lpCommand;
  DWORD cActions;
  SC_ACTION *lpsaActions;
} SERVICE_FAILURE_ACTIONSA, *LPSERVICE_FAILURE_ACTIONSA;
```
- "Requires SCM to determine a service failed"
- "Dictates what takes place after a failure"

From atlas-post-exploit-part4 (units 32, 33):
- SERVICE_WIN32_OWN_PROCESS importance — if malicious service shares a process with other services, another service crashing takes yours down. Best to be in own process. "As a fail-safe, you could configure your service failure action to simply restart the service and be just fine."
- Units 28-29: ChangeServiceConfig and ChangeServiceConfig2 APIs for modifying existing services — binary path modification, service triggers.
- Unit 27: QueryServiceConfig / QueryServiceConfig2 for optional config parameters.
- Unit 23: CreateService API details.
- Unit 30: SERVICE_TABLE_ENTRY, StartServiceCtrlDispatcher.
- Unit 31: ServiceMain, RegisterServiceCtrlHandlerExA, SERVICE_STATUS with dwServiceType = SERVICE_WIN32_OWN_PROCESS.

From atlas-binary-analysis-part5 (unit 8):
- Just a slide showing SERVICE_FAILURE_ACTIONS typedef struct.

**Source files check:**

The included Rust source files:
1. `src/client_rust/src/browser_hook.rs` — Browser extension sideloading. NOT related to SERVICE_FAILURE_ACTIONS. Its "persistence layers" are shortcut patching, Run key, schtask, protocol handler. No ChangeServiceConfig2, no SCM failure actions. Does NOT implement this technique.

2. `src/dark_crystal/crowd/src/byovd.rs` — BYOVD driver loading via SCM (OpenSCManagerW, CreateServiceW, StartServiceW). Uses SCM but for kernel driver loading, not failure actions. No ChangeServiceConfig2, no SERVICE_FAILURE_ACTIONS. Does NOT implement this technique.

3. `src/dark_crystal/crowd/src/chain.rs` — The main chain orchestrator. References persistence via `crate::persist::install_all` which is T-017's five-layer suite. No SERVICE_FAILURE_ACTIONS anywhere. Does NOT implement this technique.

So: **No current implementation in the HUGIN source.** I must state this clearly. The file manifest also confirms persist/ contains com_hijack, ntfs_ea, schtask, tls_cb, phantom_restart — no service failure actions module.

**T-017 related card:** Five-Layer Persistence with Resilience Monitor — COM hijack, NTFS EA, schtask via ITaskService, TLS callback, PhantomPersist (shutdown intercept via RegisterApplicationRestart + WM_QUERYENDSESSION). Resilience monitor checks every 30 minutes. I cross-reference this.

**MITRE ATT&CK mapping:** The best-fit for service failure actions... Let me think. This is about modifying an existing service's configuration for persistence. Options:
- T1543.003 (Create or Modify System Process: Windows Service) — this is the classic service persistence technique. Modifying an existing service's failure actions falls under "Modify System Process". This is the best fit.
- T1562.001 (Impair Defenses: Disable or Modify Tools) — not quite.
- T1036 (Masquerading) — no.

T1543.003 is the right primary. I'm confident in this ID. The technique modifies a Windows service's configuration (failure actions) rather than its ImagePath, but it's still "Create or Modify System Process: Windows Service."

**Structure of the card:**

Frontmatter:
- id: T-040
- name: SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence (canonical name from spec). Human readable 4-8 words. "SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence" is 3-4 words. Fine.
- category: persistence
- tier: B
- crate: none
- source_file: none
- mitre: T1543.003
- tags: 5-10 kebab-case: [persistence, scm, service-failure-actions, changeserviceconfig2, registry, resilience, windows-services, crash-trigger]
- member_notes: the 4 exact IDs

Sections:

**Summary:** 3-5 sentences. What it does: configures a service's failure actions via ChangeServiceConfig2(SERVICE_CONFIG_FAILURE_ACTIONS) so SCM executes an operator-controlled recovery command when the service "fails" per SCM's contract (no SERVICE_STOPPED reported or non-zero Win32ExitCode). OS primitive: SCM's failure-recovery mechanism. Why: persistence that survives reboots, event-driven trigger, evades ImagePath-based detection since the service binary path is untouched. Detection surface: registry values under the service's key (FailureActions/FailureCommand), service config change events, crash-loop process ancestry.

**Mechanism:** numbered steps:
1. Open SCM handle (OpenSCManager) and target service handle (OpenService / CreateService with SERVICE_CHANGE_CONFIG / SERVICE_ALL_ACCESS).
2. Zero out SERVICE_FAILURE_ACTIONS struct (SecureZeroMemory as shown in material).
3. Populate: dwResetPeriod (INFINITE per material, though note: actual INFINITE is -1/0xFFFFFFFF; material says INFINITE), lpRebootMsg (empty string), lpCommand ("ping C2" example from material — in practice full path to implant or command), cActions, lpsaActions (SC_ACTION array).
4. Call ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa).
5. Config persisted in registry under HKLM\SYSTEM\CurrentControlSet\Services\<svc> — the material notes the failure-action configuration is stored in the service's registry entry (FailureActions / FailureCommand values). Note: the note says "survives reboots because the failure-action configuration is stored in the service's registry entry."
6. Trigger: the SCM determines failure when the service terminates without reporting SERVICE_STOPPED, or when Win32ExitCode != ERROR_SUCCESS. Operator can deliberately trigger by terminating the service process abnormally (e.g., killing it) — from note 3: "can be deliberately triggered by terminating the service abnormally."
7. SCM walks the lpsaActions array on failure: SC_ACTION_RESTART, SC_ACTION_RUN_COMMAND (executes lpCommand), SC_ACTION_REBOOT, with per-action delays. The material mentions the chain restart → restart → run recovery binary in note 4.
8. On reboot, the configuration persists; the recovery command runs in SCM context (typically LocalSystem) whenever the service next fails.

Note: The material's pseudo-code example sets cActions = 0 and lpsaActions = NULL with lpCommand = "ping C2" — that's actually an odd combination (lpCommand only runs when an SC_ACTION_RUN_COMMAND action is in the array), but I should present what the material shows and also the canonical chain from note 4 (restart → restart → run recovery binary). Actually, careful: with cActions=0, no actions run, so lpCommand never executes. Hmm. But the material is the authority for descriptive claims... The slide shows that pseudo code. I can present the material's example faithfully and also note that SC_ACTION entries are what actually drive execution per the structure contract. The note 4 mentions "failure-action chain configuration (restart → restart → run recovery binary)". I can describe both: the material's minimal pseudo-code and the action chain. I should be careful not to fabricate. SC_ACTION types (SC_ACTION_NONE, SC_ACTION_RESTART, SC_ACTION_REBOOT, SC_ACTION_RUN_COMMAND) are well-established Windows documentation — I can name them since they're in winsvc.h/MSDN. That's allowed under rule 4 (well-established Windows internals documentation).

**OS Internals Context:**
- SCM (services.exe) as the end-all-be-all: services must report status via SetServiceStatus / RegisterServiceCtrlHandlerEx. Failure determination contract: termination without SERVICE_STOPPED, or Win32ExitCode != ERROR_SUCCESS in SERVICE_STATUS.
- The SERVICE_FAILURE_ACTIONS structure fields: dwResetPeriod (seconds after which failure count resets; INFINITE per material), lpRebootMsg (broadcast message before reboot action), lpCommand (command line executed for SC_ACTION_RUN_COMMAND; run by SCM, NOT via cmd.exe per MSDN — actually MSDN says the command runs as created process via CreateProcess... Let me recall: MSDN states "Note that the command is executed... The process is created..." hmm. From MSDN on SERVICE_FAILURE_ACTIONS lpCommand: "The command line of the process for the CreateProcess function to execute..." Yes, it's passed to CreateProcess, not cmd /c, so operators need full path or "cmd.exe /c ..." explicitly. That's well-established MSDN. I'll state it carefully.)
- SC_ACTION array: each has Type + Delay (ms). SCM executes actions in order on subsequent failures; when array exhausted, behavior per config.
- Registry storage: FailureActions (REG_BINARY) and FailureCommand (REG_SZ) values under the service key — well-established. The material says config stored in service's registry entry and survives reboots.
- SERVICE_WIN32_OWN_PROCESS consideration from part4: own-process isolation so another service's crash doesn't kill yours; failure action "restart the service" as fail-safe. This is the resilience angle: SCM-native restart survives reboots where userland monitors don't (note 4).
- ChangeServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS info level; QueryServiceConfig2 for reading it back (part4 unit 27 mentions QueryServiceConfig2 obtains optional configuration parameters).
- Requires SCM to determine a service failed — the trigger is kernel/SCM-mediated, not a userland watcher.

**Key Implementation Details:** No current implementation. State it, then describe what implementation would look like: winapi winsvc bindings (the crowd crate already uses winapi::um::winsvc for CreateServiceW etc. in byovd.rs — I verified that file uses OpenSCManagerW/CreateServiceW/StartServiceW but NOT failure actions), a SERVICE_FAILURE_ACTIONS struct, ChangeServiceConfig2W call, plus an abnormal-termination trigger path. One paragraph. I can mention that byovd.rs demonstrates the SCM handle-acquisition pattern already present in crowd but does not implement failure actions. That's accurate — verified from the included source.

**Why It Matters:** distinct trigger surface (event-driven on crash vs scheduled/ImagePath), evades ImagePath-based detection (note 2), orthogonal to T-017's five layers, SCM-native resilience survives reboot unlike userland monitors (note 4). 2-4 sentences.

**Detection Considerations:** What does the material say? Note 2 says it "evad[es] ImagePath-based detection" — that's a detection consideration from the material. The cluster description says "distinct detection signature (failure-action command execution on service crash)". The material (part11 unit 25) mentions SysInternals AutoRuns for registry keys generally but not specifically failure actions. I should not invent ETW GUIDs or Sysmon IDs. I can say:
- Telemetry: service configuration change auditing (Windows Security event for service config changes — hmm, event 7040 "service start type changed"? That's for start type changes. I shouldn't invent specific event IDs. The material doesn't give event IDs. I can mention general: registry values FailureActions/FailureCommand under the service key are the residual artifact; the SCM executes the command as a child of services.exe so process ancestry (child of services.exe) is a signature — is that in the material? Not explicitly. Hmm. Careful. Rule: if material doesn't cover detection, write the line. The material partially covers: "evading ImagePath-based detection" (note 2 / part1 unit 30 mentions ImagePath and Failure Command as things that get attention in services). Actually part1 unit 30 key cues: "ImagePath, Failure Command" — the slide discusses services being ripe for attackers and mentions ImagePath / Failure Command as modification targets. That's the closest to detection surface.
- I can describe: residual artifacts = FailureActions REG_BINARY and FailureCommand REG_SZ values in the service's registry key (this is where the config is stored per the notes, so it's fair to name as artifact — the note explicitly says "the failure-action configuration is stored in the service's registry entry"). 
- Bypass options per material: leaves ImagePath untouched, so tools auditing only service binary paths miss it (note 2's claim). 
- Trigger visibility: the technique's execution requires a service crash/failure event — the crash itself is the distinct signature per the cluster description.

I'll keep it grounded: name the registry values, the ImagePath-evasion claim, and the crash-trigger signature. For Sysmon/ETW specifics, write that the material doesn't document them. Actually the template asks for telemetry sources/bypass options/residual artifacts. I can structure with what's known and note material limits. The command execution as a child of services.exe — this is a factual consequence of SCM spawning the process via CreateProcess, which is established Windows behavior (SCM is the parent). I think that's safe as established OS behavior, not a fabricated detection claim. I'll phrase carefully: "processes spawned by the SCM (services.exe) as part of failure recovery appear with services.exe ancestry" — this is just how SCM runs commands. Fine.

**Related Techniques:** Only T-017 (the would_relate_to list has just T-017). One entry: T-017 Five-Layer Persistence — orthogonal sixth mechanism / complements PhantomPersist resilience monitor with SCM-native reboot-surviving trigger. That's the single justified reference. The rules say only reference cards from would_relate_to list or explicitly discussed in related cards provided. T-017 card itself doesn't mention failure actions. So just T-017.

**References:**
- Atlas: atlas-binary-analysis-part5.md, atlas-post-exploit-part1.md, atlas-post-exploit-part11.md, atlas-post-exploit-part4.md
- MITRE: T1543.003 with URL https://attack.mitre.org/techniques/T1543/003/
- LGTM notes: the 4 IDs
- Public references: none named in material beyond MSDN (SERVICE_FAILURE_ACTIONS structure doc, ChangeServiceConfig2). I can cite MSDN as it's the structure documentation the material itself references. The material doesn't name a tool author or blog for this technique. I'll list MSDN documentation for ChangeServiceConfig2 / SERVICE_FAILURE_ACTIONS as public reference — that's documentation named implicitly via the API. Acceptable, not invented.

**Source Reference:** No current implementation. See atlas material and MITRE reference.

Frontmatter details:
- mitre: T1543.003
- mitre_secondary: could add none... Maybe omit. Actually T1543.003 is solid. Some might argue T1562.001 no. Keep single. I'll omit mitre_secondary (allowed: "or omit the line").
- tags: [persistence, scm, service-failure-actions, changeserviceconfig2, windows-services, registry, crash-trigger, resilience] — 8 tags, kebab-case. Good.
- crate: none
- source_file: none

Word count: need 800+ body words, target 1200-1800. I'll write a thorough card.

Style: no banned words. Check: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable — avoid. No "worth noting", "the key insight", etc. Third-person declarative.

Section order exact:
1. frontmatter
2. # Name — Purpose
3. ## Summary
4. ## Mechanism
5. ## OS Internals Context
6. ## Key Implementation Details
7. ## Why It Matters
8. ## Detection Considerations
9. ## Related Techniques
10. ## References
11. ## Source Reference

Let me draft.

Name in h1: "SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence — SCM-Mediated Recovery Command Execution" or similar one-line purpose.

Mechanism steps — let me be concrete:

1. Acquire an SCM handle via OpenSCManager on the local machine and a service handle via OpenService (existing service to modify) or CreateService (operator-installed service), requesting SERVICE_CHANGE_CONFIG access. Material: part4 unit 25 "Interacting with the SCM requires handles" (SCManager, Service, Database lock).
2. Declare and zero a SERVICE_FAILURE_ACTIONS structure with SecureZeroMemory (part1 unit 12/31).
3. Populate fields: dwResetPeriod = INFINITE (failure-count never resets per material example); lpRebootMsg = "" ; lpCommand = "<command>" (material example "ping C2"); cActions and lpsaActions point to an SC_ACTION array defining the ordered failure response.
4. Commit via ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa).
5. SCM persists the configuration into the service's registry entry (survives reboot).
6. Failure determination: SCM marks the service failed when it terminates without reporting SERVICE_STOPPED, or when SERVICE_STATUS.Win32ExitCode != ERROR_SUCCESS (part11 unit 37).
7. Deliberate trigger: operator terminates the service process abnormally (kill without clean SetServiceStatus(SERVICE_STOPPED)) — event-driven, on-demand execution (note 3).
8. SCM walks the action chain in order (e.g., restart → restart → run recovery binary per note 4), honoring per-action Delay. On the SC_ACTION_RUN_COMMAND step, SCM executes lpCommand.
9. Recovery command runs under the SCM's context; configuration persists across reboot and fires again on next failure.

OS internals context — expand:

- services.exe role; RegisterServiceCtrlHandlerEx / SetServiceStatus contract (part4 unit 31 shows SERVICE_STATUS init with SERVICE_WIN32_OWN_PROCESS, dwWaitHint).
- SERVICE_FAILURE_ACTIONS struct layout (part11 unit 39 gives the typedef).
- SC_ACTION: Type + Delay. Types from winsvc.h: SC_ACTION_NONE(0), SC_ACTION_RESTART(1), SC_ACTION_REBOOT(2), SC_ACTION_RUN_COMMAND(3). Established MSDN.
- lpCommand is passed to CreateProcess by the SCM — not through cmd.exe — so a bare command name won't resolve shell builtins; operators supply a full path or invoke cmd.exe /c explicitly. (Established MSDN.)
- Registry persistence: FailureCommand (REG_SZ) and FailureActions (REG_BINARY) under HKLM\SYSTEM\CurrentControlSet\Services\<name>. This is where sc.exe failure command= writes. Established + note 1 says stored in service's registry entry.
- SERVICE_WIN32_OWN_PROCESS isolation from part4 units 32/33: shared-process services die together; own-process plus a restart failure action gives SCM-native fail-safe. Note 4: survives reboots where userland monitors don't.
- Required access: SERVICE_CHANGE_CONFIG on the service; typically admin/SYSTEM context needed (HKLM services). Part1 unit 32: "When you have administrative and/or SYSTEM privileges, creating a service is a perfect action to take."
- QueryServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS reads it back (part4 unit 27: "QueryServiceConfig2 that will obtain the configuration parameters that are optional").
- dwResetPeriod semantics: seconds after which the failure count resets to zero; INFINITE (0xFFFFFFFF) means never reset. The material sets INFINITE.

Wait — one nuance: dwResetPeriod is in seconds, and INFINITE is -1 (0xFFFFFFFF) which MSDN documents as valid for dwResetPeriod ("the time after which to reset the failure count... INFINITE to indicate that this value should never be reset"). The material uses INFINITE. Good.

Key Implementation Details:
- State: No current implementation in the HUGIN source. Verified: browser_hook.rs implements browser extension persistence layers (shortcut/Run key/schtask/protocol handler) — no SCM failure actions. byovd.rs uses OpenSCManagerW/CreateServiceW/StartServiceW for kernel driver registration only — no ChangeServiceConfig2, no SERVICE_FAILURE_ACTIONS. chain.rs dispatches to persist::install_all (T-017 layers) only.
- What implementation would look like: a crowd persist module (e.g., persist/svc_failure.rs) that opens SCM + target service via the winapi::um::winsvc bindings already used in byovd.rs, builds SERVICE_FAILURE_ACTIONSW with an SC_ACTION chain (RESTART, RESTART, RUN_COMMAND with delays), sets lpCommand to the implant path or a LOLBin invocation, calls ChangeServiceConfig2W, and a trigger path that abnormally terminates the service process when on-demand execution is needed.

Why It Matters (2-4 sentences):
- T-017's five layers are time/user-event driven (logon, COM activation, task schedule, DLL load, shutdown). T-040 is the only SCM-mediated, crash-event-driven persistence trigger in the vault — execution happens because services.exe decides the service failed, which no other layer provides.
- It leaves ImagePath untouched, so audit tooling focused on service binary paths (the canonical service-persistence check) misses it (note 2).
- As a resilience primitive it survives reboots via SCM itself, complementing PhantomPersist's userland 30-minute monitor (note 4).

Detection Considerations:
- Telemetry: material does not document ETW providers, Sysmon IDs for this technique. What it does say: detection signature is "failure-action command execution on service crash" (note 2) — i.e., the crash event plus the SCM-spawned recovery process. Material also says the technique evades ImagePath-based detection (note 2). 
- Residual artifacts: FailureActions (REG_BINARY) and FailureCommand (REG_SZ) values in the service's registry key — the notes state the configuration is stored in the service's registry entry and survives reboot. A full path to an operator binary in FailureCommand is the primary artifact.
- Bypass options per material: service binary path unchanged → Autoruns-style ImagePath audits miss it; using an existing legitimate service as host avoids new-service creation events.
- I'll note: "Training material does not name ETW providers or Sysmon event IDs for this technique."

Hmm, but the template says: 'If the material does not cover detection for this technique, write: "Training material does not discuss detection for this technique." Do not invent detections.' The material does cover some detection aspects (evades ImagePath detection, distinct signature = command execution on crash, registry storage). So I'll write the three bullets grounded in that, and explicitly note where the material is silent (no provider GUIDs/event IDs).

Related Techniques:
- **T-017 Five-Layer Persistence with Resilience Monitor** — T-040 is an orthogonal sixth persistence mechanism; its SCM-native restart/run-command fail-safe complements T-017's PhantomPersist userland resilience monitor with a reboot-surviving, services.exe-mediated trigger.

References:
- Atlas material: atlas-binary-analysis-part5.md (unit 8), atlas-post-exploit-part1.md (units 12, 30-31), atlas-post-exploit-part11.md (units 37-39), atlas-post-exploit-part4.md (units 25-34)
- MITRE ATT&CK: T1543.003 — https://attack.mitre.org/techniques/T1543/003/
- LGTM notes: 4 IDs
- Public references: MSDN — SERVICE_FAILURE_ACTIONS structure and ChangeServiceConfig2 documentation (the material's struct typedef and API signatures are taken from these headers). Is citing MSDN "inventing"? The rule says don't invent references like tool authors/blogs. MSDN documentation of the named API is safe and factual. I'll include it.

Source Reference:
- "No current implementation. See atlas material and MITRE reference for public tooling." I can add: crowd's byovd.rs demonstrates the SCM handle pattern (OpenSCManagerW/CreateServiceW) but does not implement failure actions.

Word count check — aim ~1300-1600 words body.

Now write it. Careful with banned phrases. Avoid "worth noting", "interestingly", "key insight", "textbook", "notable", "robust", "clean", "elegant", "essentially", "at its core", "it is important to note", "as you can see".

Frontmatter name: "SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence" — 4 words-ish (SERVICE_FAILURE_ACTIONS counts as one token). Fine.

h1: `# SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence — SCM-Executed Recovery Commands on Service Failure`

Let me write the body now.

Summary (3-5 sentences, first standalone):
"The SERVICE_FAILURE_ACTIONS mechanism configures the Windows Service Control Manager to execute an operator-supplied recovery command whenever a designated service is judged to have failed. Set via ChangeServiceConfig2 with the SERVICE_CONFIG_FAILURE_ACTIONS info level, the configuration is stored in the service's registry entry and persists across reboots. Because the trigger is the SCM's failure determination — termination without a SERVICE_STOPPED report or a non-zero Win32ExitCode — an operator can fire the payload on demand by killing the service process abnormally. The service's ImagePath is never modified, so audit tooling keyed on service binary paths does not observe the persistence. Primary detection surface: the FailureCommand/FailureActions registry values and the crash-plus-recovery-process event pair."

That's 5 sentences. Good.

Mechanism: ~9 steps as above. Concrete.

OS Internals: struct fields, SC_ACTION types/delays, SCM contract, services.exe CreateProcess semantics, registry storage, OWN_PROCESS rationale, required access rights, QueryServiceConfig2 readback. Also dwResetPeriod semantics.

Let me make sure I don't misattribute: note 1 says "survives reboots because the failure-action configuration is stored in the service's registry entry." Good.

Note 3: "execute a binary when a service 'fails' per SCM's contract (no SERVICE_STOPPED reported or non-zero Win32ExitCode). This is a distinct persistence trigger from schtask scheduling — it is event-driven on service crash and can be deliberately triggered by terminating the service abnormally."

Note 2: "triggers a configured command (e.g., 'ping C2') when a service fails, evading ImagePath-based detection while still executing on a recurring schedule" — hmm, "recurring schedule" — I think they mean it can recur each time the service fails. I'll phrase as recurring on each failure event.

Note 4: "SERVICE_WIN32_OWN_PROCESS services can be configured with failure actions (restart on failure) as a fail-safe... failure actions are SCM-native and survive reboots where userland monitor processes do not. A dedicated technique card covering failure-action chain configuration (restart → restart → run recovery binary)..."

Part1 unit 12 pseudo-code sets cActions = 0, lpsaActions = NULL — with the caveat "The pseudo code one the slide shows just one of several ways you could go about implementing a service's failure actions. It is best to do this after you have in[stalled]...". I'll present the material's pseudo-code faithfully in Mechanism step 3, and note that an action chain (restart → restart → run command) is the operational configuration from note 4. I should be careful: with cActions=0 the lpCommand would not execute under the documented contract; the material's slide is a minimal skeleton ("just one of several ways"). I can state: the training slide zeroes the action array and sets only lpCommand; the operational form populates an SC_ACTION chain so the SCM actually acts on failures, ending in SC_ACTION_RUN_COMMAND. That's accurate to both the material and the documented contract without calling the material wrong.

Registry value names: FailureCommand (REG_SZ) and FailureActions (REG_BINARY). Are these "well-established"? Yes — documented via sc.exe failure/reset/failureflag and visible in any service key where failure actions are configured; Windows Internals covers SCM registry layout. I'll state them as established SCM storage. Safe.

MITRE: T1543.003 Create or Modify System Process: Windows Service. URL: https://attack.mitre.org/techniques/T1543/003/

Tags: [persistence, scm, service-failure-actions, changeserviceconfig2, windows-services, registry-persistence, crash-trigger, resilience] — 8.

Let me also double check "would_relate_to" handling: only T-017. Related Techniques section gets exactly one entry. Good — restraint rule.

Also the system prompt says crate enum: dark_crystal|client_rust|none → none. source_file: none.

Length: I'll target ~1400 words body. Let me write.

Also verify no banned words creep in. "clean" — avoid. "solid" — avoid. "robust" — avoid. "notable" — avoid. Watch for "cleanly" — I'll avoid the whole family to be safe? The banned list is specific words; "cleanly" is a derivative of clean — avoid anyway.

Draft body:

## Summary — done above.

## Mechanism

1. Open a handle to the SCM on the local machine (OpenSCManager) and to the target service (OpenService for an existing service, or CreateService for an operator-installed one). The handle must carry SERVICE_CHANGE_CONFIG; part4's material states SCM interaction requires handles to the SCManager, the service, and optionally a database lock.
2. Allocate and zero a SERVICE_FAILURE_ACTIONS structure with SecureZeroMemory, as in the SEC670 implementation slide.
3. Populate the fields. The training example sets dwResetPeriod = INFINITE (failure count never resets), lpRebootMsg = "", lpCommand = "ping C2" (placeholder for the operator command), cActions = 0, lpsaActions = NULL — a minimal skeleton the slide describes as one of several ways to implement failure actions.
4. The operational form builds an SC_ACTION array instead: a chain such as SC_ACTION_RESTART → SC_ACTION_RESTART → SC_ACTION_RUN_COMMAND, each with a Delay in milliseconds, so the SCM first attempts restarts and finally executes lpCommand on repeated failure (the restart → restart → run-recovery-binary chain surfaced in the atlas notes).
5. Commit the configuration with ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa). The material advises doing this after the service is installed.
6. The SCM persists the configuration into the service's registry entry; it survives reboots without any userland component.
7. Failure determination: per the material, the SCM considers a service failed when it terminates without reporting SERVICE_STOPPED, or when the Win32ExitCode member of its SERVICE_STATUS does not equal ERROR_SUCCESS.
8. On-demand trigger: the operator abnormally terminates the service process (kill without a clean SetServiceStatus(SERVICE_STOPPED)). The SCM detects the unreported exit and runs the configured chain — event-driven execution rather than a schedule.
9. On the SC_ACTION_RUN_COMMAND step, the SCM executes lpCommand; each subsequent failure re-fires the chain, giving recurring execution for as long as the service continues to "fail."

## OS Internals Context

Paragraphs:

- SCM contract. services.exe owns service lifetime; services register a control handler (RegisterServiceCtrlHandlerEx) and must report status transitions (SetServiceStatus with SERVICE_STATUS). A service that exits without SERVICE_STOPPED or with non-zero Win32ExitCode is declared failed — the entire technique hangs on this determination being made by the SCM rather than by any userland watcher. This is what makes the trigger SCM-native: the event is generated inside services.exe's own bookkeeping, so the recovery command executes even if every operator process is dead.

- Structure contract. SERVICE_FAILURE_ACTIONS (part11 unit 39 typedef): dwResetPeriod (seconds after which the failure counter resets; INFINITE = never), lpRebootMsg (broadcast before a reboot action), lpCommand (command line for run-command action), cActions, lpsaActions (array of SC_ACTION { Type, Delay }). Types from winsvc.h: SC_ACTION_NONE, SC_ACTION_RESTART, SC_ACTION_REBOOT, SC_ACTION_RUN_COMMAND. Delay in ms before that action. SCM walks the array across consecutive failures: nth failure gets nth action (MSDN: actions are used in order; once the array is exhausted the SCM stops). Actually MSDN says: "The SC_ACTION structures... are used in order... The service control manager runs the actions in order." And there's the failure count concept — the action taken corresponds to the current failure count, capped at the last array element. I'll phrase it carefully: the SCM indexes into the array by the service's consecutive failure count, clamped at the final entry, and honors each entry's Delay.

- lpCommand execution semantics: the SCM passes lpCommand to CreateProcess — it is not a cmd.exe command line. Operators supply a full path to a binary (with arguments) or explicitly invoke cmd.exe /c. The process is created by services.exe, so the recovery binary runs with SCM parentage in the service's configured account context (typically LocalSystem for system services). Hmm — which account does the failure command run under? MSDN on lpCommand: "the process... runs under the same account as the service." Let me recall precisely... MSDN SERVICE_FAILURE_ACTIONS lpCommand: "Note that the process runs under the same account as the service." Hmm, I believe for lpCommand the created process runs under the LocalSystem account? Let me think. Actually the documented text: "The command line of the process for the CreateProcess function to execute... This process runs under the same account as the service." I genuinely recall "runs under the same account as the service" being in the docs. Hmm, but there is a caveat about SC_ACTION_RUN_COMMAND running as LocalSystem... Let me be careful. The MSDN page for SERVICE_FAILURE_ACTIONS says for lpCommand: "...If this value is NULL, the command is unchanged. If the value is an empty string (""), the command is deleted..."? No that's ChangeServiceConfig2 behavior. 

I recall from real-world usage: the failure command executes as LocalSystem (services.exe spawns it). There's documentation in various places saying the recovery command runs in the context of the service's account... To avoid fabrication, I'll write the safe part: the SCM creates the process via CreateProcess from services.exe (not through a shell), so shell builtins and PATH-relative names do not resolve; the command line must be self-contained. And say process ancestry is services.exe. I'll skip the account-context claim since I'm not certain and material doesn't say. Actually — hmm, this is a meaningful internals point. The documented statement (MSDN, SERVICE_FAILURE_ACTIONS, lpCommand): "The process is created with the same token as the service." I'm not confident enough. Omit. Stick with CreateProcess-not-shell, which is explicitly documented ("the command line of the process for the CreateProcess function to execute").

- Registry storage: the SCM records failure configuration under the service's key in HKLM\SYSTEM\CurrentControlSet\Services\<name> as the FailureCommand (REG_SZ) and FailureActions (REG_BINARY) values — this is the storage that lets the configuration survive reboot, which the atlas notes call out as the technique's persistence property. Changes require write access to the service key, mediated by the SCM's access check on SERVICE_CHANGE_CONFIG.

- Service type isolation: part4 units 32/33 — SERVICE_WIN32_OWN_PROCESS keeps the malicious service out of shared svchost-style processes, because a co-hosted service crash takes the operator's service down with it; conversely a restart-on-failure action is the documented fail-safe. This cuts both ways for the technique: hosting the persistence on an existing own-process service means the operator controls the crash semantics; hosting on a shared service risks collateral failure actions firing on unrelated crashes... wait, actually collateral crashes in a shared process would ALSO trigger the failure command (since the SCM sees the service as failed). Hmm, but in a shared process, one service's crash terminates the process, and all services in it that didn't report STOPPED are "failed" — so the operator's failure action would fire. That's more triggers, not fewer. The part4 point is about reliability of the operator's own service. I'll present the material's own-process guidance as written, framed as reliability of the trigger host.

- Access requirements: modifying an existing service's failure actions needs SERVICE_CHANGE_CONFIG on that service — generally an administrative or SYSTEM context (part1 unit 32: with admin/SYSTEM, service creation is "a perfect action"). Reading back uses QueryServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS (part4 unit 27 describes QueryServiceConfig2 for optional parameters).

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for the reference pseudo-code in C (SERVICE_FAILURE_ACTIONSA + ChangeServiceConfig2).

Verification of grep-matched files: browser_hook.rs implements browser extension persistence (shortcut patching, Run key, scheduled task, protocol handler) with no SCM interaction; byovd.rs uses OpenSCManagerW/CreateServiceW/StartServiceW to register a kernel driver but never calls ChangeServiceConfig2 or touches SERVICE_FAILURE_ACTIONS; chain.rs dispatches persistence only to the T-017 suite via persist::install_all. None implements the primary mechanism of this card.

Implementation sketch: a crowd persist module (persist/svc_failure.rs) reusing the winapi::um::winsvc bindings already present in byovd.rs: open the SCM with SC_MANAGER_CONNECT, open the target service with SERVICE_CHANGE_CONFIG, build a SERVICE_FAILURE_ACTIONSW whose lpsaActions chain is [RESTART 5s, RESTART 5s, RUN_COMMAND 0s] with lpCommand pointing at the implant path, call ChangeServiceConfig2W, close handles. A companion trigger function terminates the service process abnormally (NtTerminateProcess) when on-demand re-execution is required.

## Why It Matters

T-040 earns a separate card because its trigger is unique in the vault: every T-017 layer fires on a time schedule, a logon, a COM activation, a DLL load, or a shutdown event, while failure actions fire on an SCM-determined crash — an event the operator can generate at will by killing the service. It also modifies no ImagePath, so the canonical service-persistence audit (service binary path inspection) does not surface it. As a resilience primitive it is SCM-native and reboot-surviving, complementing T-017's userland 30-minute resilience monitor, which dies with the process hosting it.

That's 4 sentences. Good.

## Detection Considerations

- Telemetry sources: the material names the technique's distinct signature as failure-action command execution on service crash — the pairing of a service failure event with an SCM-spawned recovery process. It does not document ETW provider GUIDs or Sysmon event IDs for this technique.
- Bypass options: the material states the technique evades ImagePath-based detection because the service binary path is untouched; hosting the configuration on an existing legitimate service avoids introducing a new service entry at all.
- Residual artifacts: the FailureCommand (REG_SZ) and FailureActions (REG_BINARY) values under the service's registry key — the notes identify the service's registry entry as the storage that carries the configuration across reboots. A FailureCommand containing a path to an operator binary or an unusual command line is the standing artifact, readable with QueryServiceConfig2(SERVICE_CONFIG_FAILURE_ACTIONS) or direct registry inspection. Recovery processes appear with services.exe ancestry whenever the chain fires.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — failure actions are an orthogonal sixth mechanism: SCM-mediated and crash-triggered where T-017's layers are schedule/logon/shutdown-driven, and the restart-on-failure chain complements T-017's userland resilience monitor with a reboot-surviving, services.exe-owned fail-safe.

## References

- Atlas material: atlas-binary-analysis-part5.md (unit 8), atlas-post-exploit-part1.md (units 12, 30, 31), atlas-post-exploit-part11.md (units 37-39), atlas-post-exploit-part4.md (units 25-34)
- MITRE ATT&CK: T1543.003 — Create or Modify System Process: Windows Service (https://attack.mitre.org/techniques/T1543/003/)
- LGTM notes: lgtm:service-failure-actions-persistence, lgtm:service-failure-actions-card, lgtm:service-failure-actions-as-persistence, lgtm:proposed-service-failure-action-resilience
- Public references: Microsoft documentation for the SERVICE_FAILURE_ACTIONS structure and ChangeServiceConfig2 function (winsvc.h) — the struct typedef and API signatures reproduced in the training slides are taken from these headers.

## Source Reference

No current implementation. crowd's byovd.rs demonstrates the SCM handle-acquisition pattern (OpenSCManagerW / CreateServiceW) that an implementation would reuse, but does not implement failure actions. See atlas material and MITRE reference for public tooling.

Word count: let me estimate. Summary ~130, Mechanism ~350, OS Internals ~500, Key Impl ~180, Why ~100, Detection ~180, Related ~50, refs ~80. Total ~1570. Good, in the 1200-1800 target.

Check banned words once more in my draft: "canonical" is fine. "orthogonal" fine. No "elegant/clean/robust/notable". Avoid "worth noting" — not used. "essentially" — not used. "at its core" — not used. "textbook" — not used. "interestingly" — no. "the key insight" — no. "it is important to note" — no. "as you can see" — no. Exclamation marks — none. First person — none. Rhetorical questions — none.

Frontmatter tags kebab-case check: persistence, scm, service-failure-actions, changeserviceconfig2, windows-services, registry-persistence, crash-trigger, resilience — all kebab/lower. Good.

One more check on the frontmatter enum: mitre format T####.### → T1543.003 ✓.

member_notes exact list from spec:
['lgtm:service-failure-actions-persistence', 'lgtm:service-failure-actions-card', 'lgtm:service-failure-actions-as-persistence', 'lgtm:proposed-service-failure-action-resilience'] ✓

Output only the markdown file, no preamble. Done.