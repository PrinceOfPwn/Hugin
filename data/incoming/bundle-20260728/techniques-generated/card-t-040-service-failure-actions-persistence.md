---
id: T-040
name: SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence
category: persistence
tier: B
crate: none
source_file: none
mitre: T1543.003
tags: [persistence, scm, service-failure-actions, changeserviceconfig2, windows-services, registry-persistence, crash-trigger, resilience]
origin: atlas-synthesis
member_notes: ['lgtm:service-failure-actions-persistence', 'lgtm:service-failure-actions-card', 'lgtm:service-failure-actions-as-persistence', 'lgtm:proposed-service-failure-action-resilience']
---

# SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence — SCM-Executed Recovery Commands on Service Failure

## Summary

The SERVICE_FAILURE_ACTIONS mechanism configures the Windows Service Control Manager to execute an operator-supplied recovery command whenever a designated service is judged to have failed. The configuration is committed via ChangeServiceConfig2 with the SERVICE_CONFIG_FAILURE_ACTIONS info level and is stored in the service's registry entry, where it persists across reboots without any userland component. Because the trigger is the SCM's own failure determination — termination without a SERVICE_STOPPED report, or a non-zero Win32ExitCode — an operator can fire the payload on demand by abnormally terminating the service process. The service's ImagePath is never modified, so audit tooling keyed on service binary paths does not observe the persistence. The primary detection surface is the FailureCommand/FailureActions registry values and the crash-plus-recovery-process event pair.

## Mechanism

1. Open a handle to the SCM on the local machine (OpenSCManager) and to the target service — OpenService for an existing service to modify, CreateService for an operator-installed one. The service handle must carry SERVICE_CHANGE_CONFIG. The training material states that interacting with the SCM requires handles to the SCManager, the service, and optionally a database lock.
2. Declare and zero a SERVICE_FAILURE_ACTIONS structure with SecureZeroMemory, matching the SEC670 implementation slide.
3. Populate the fields. The training example sets `dwResetPeriod = INFINITE`, `lpRebootMsg = ""`, `lpCommand = "ping C2"`, `cActions = 0`, `lpsaActions = NULL`, and the slide notes this is one of several ways to implement failure actions. lpCommand holds the operator's recovery command line.
4. The operational form populates an SC_ACTION array instead of leaving it empty: a chain such as SC_ACTION_RESTART → SC_ACTION_RESTART → SC_ACTION_RUN_COMMAND, each entry carrying its own Delay, so the SCM first attempts service restarts and finally executes lpCommand on repeated failure — the restart → restart → run recovery binary chain surfaced in the atlas notes.
5. Commit the configuration with `ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)`. The material advises doing this after the service has been installed.
6. The SCM persists the configuration into the service's registry entry. It survives reboots because the failure-action configuration lives in that entry, not in any operator process.
7. Failure determination: per the material, the SCM considers a service to have failed when it terminates without reporting the SERVICE_STOPPED status, or when the Win32ExitCode member of its SERVICE_STATUS structure does not indicate ERROR_SUCCESS.
8. On-demand trigger: the operator abnormally terminates the service process — a kill with no clean SetServiceStatus(SERVICE_STOPPED). The SCM registers the unreported exit as a failure and runs the configured chain. Execution is event-driven on crash rather than schedule-driven.
9. On the SC_ACTION_RUN_COMMAND step, the SCM executes lpCommand. Each subsequent failure re-fires the chain, giving recurring execution for as long as the service continues to fail.

## OS Internals Context

The technique hangs entirely on the SCM's status contract. services.exe owns service lifetime: a service registers a control handler (RegisterServiceCtrlHandlerEx, shown in the material alongside SERVICE_STATUS initialization with dwServiceType = SERVICE_WIN32_OWN_PROCESS and dwWaitHint) and must report state transitions via SetServiceStatus. The material is explicit that services must answer to the SCM, and that the SCM is the end-all-be-all of failure determination. Because the failure event is generated inside services.exe's own bookkeeping, the recovery command executes even when every operator-controlled process on the box is dead — no userland watcher thread is required, which is what separates this from T-017's resilience monitor.

The SERVICE_FAILURE_ACTIONS structure is reproduced in the material directly from winsvc.h: dwResetPeriod (seconds after which the consecutive-failure counter resets; the material uses INFINITE so it never resets), lpRebootMsg (message broadcast before a reboot action), lpCommand (command line for the run-command action), cActions, and lpsaActions pointing to an array of SC_ACTION entries of the form { Type, Delay }. The documented SC_ACTION types are SC_ACTION_NONE, SC_ACTION_RESTART, SC_ACTION_REBOOT, and SC_ACTION_RUN_COMMAND. The SCM indexes into the array by the service's consecutive failure count, clamped at the final entry, honoring each entry's Delay in milliseconds before performing that action.

The lpCommand string is the command line for a process the SCM creates with CreateProcess — it is not passed through a shell. Shell builtins, environment-variable expansion conveniences, and PATH-relative bare names do not resolve the way they would under cmd.exe; the command line must be self-contained, either a full path to a binary with arguments or an explicit cmd.exe /c invocation. The resulting process is spawned by services.exe, so recovery execution carries SCM parentage rather than the ancestry of any operator process.

Persistence is realized through the service's registry key. The SCM records failure configuration under HKLM\SYSTEM\CurrentControlSet\Services\<name> in the FailureCommand (REG_SZ) and FailureActions (REG_BINARY) values — the storage the atlas notes identify as the reason the configuration survives reboots. Writing it requires SERVICE_CHANGE_CONFIG on the target service, which in practice means an administrative or SYSTEM context; the material notes that with administrative and/or SYSTEM privileges, service creation is a natural action to take. Reading the configuration back uses QueryServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS, which the material describes as the API that obtains a service's optional configuration parameters.

The material also surfaces a service-type consideration that shapes target selection. SERVICE_WIN32_OWN_PROCESS keeps a service out of a shared process, because a co-hosted service's crash terminates the shared process and takes every service inside it down. The material's own fail-safe recommendation is a restart-on-failure action. For this technique, the choice of host service determines the crash semantics the operator can rely on: an own-process service gives a controlled, individually terminable trigger host, while a shared-process host produces failure events whenever any co-hosted service crashes.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for the reference pseudo-code in C (SERVICE_FAILURE_ACTIONSA populated and committed via ChangeServiceConfig2).

Verification of the grep-matched Rust files: `client_rust/src/browser_hook.rs` implements browser extension persistence layers (shortcut patching, Run key, scheduled task, protocol handler) with no SCM interaction; `dark_crystal/crowd/src/byovd.rs` uses OpenSCManagerW, CreateServiceW, and StartServiceW to register and start a kernel driver but never calls ChangeServiceConfig2 and never touches SERVICE_FAILURE_ACTIONS; `dark_crystal/crowd/src/chain.rs` dispatches persistence exclusively to the T-017 suite via `persist::install_all`. None of them implements this card's primary mechanism.

An implementation would be a crowd persist module (for example `persist/svc_failure.rs`) reusing the `winapi::um::winsvc` bindings already vendored for byovd.rs: open the SCM, open the target service with SERVICE_CHANGE_CONFIG, build a SERVICE_FAILURE_ACTIONSW whose lpsaActions chain is restart → restart → run-command with per-action delays, set lpCommand to the implant path, and call ChangeServiceConfig2W. A companion trigger function would abnormally terminate the service process when on-demand re-execution is required.

## Why It Matters

T-040 earns its own card because its trigger is unique in the vault: every T-017 layer fires on a schedule, a logon, a COM activation, a DLL load, or a shutdown event, while failure actions fire on an SCM-determined crash that the operator can generate at will by killing the service. It modifies no ImagePath, so the standard service-persistence audit — service binary path inspection — does not surface it. As a resilience primitive it is SCM-native and reboot-surviving, where T-017's 30-minute resilience monitor is a userland thread that dies with the process hosting it.

## Detection Considerations

- **Telemetry sources**: the material names the technique's distinct detection signature as failure-action command execution on service crash — the pairing of a service failure with an SCM-spawned recovery process. Training material does not document ETW provider GUIDs or Sysmon event IDs for this technique.
- **Bypass options**: the material states the technique evades ImagePath-based detection because the service binary path is untouched. Hosting the failure configuration on an existing legitimate service avoids introducing a new service entry entirely.
- **Residual artifacts**: the FailureCommand (REG_SZ) and FailureActions (REG_BINARY) values under the service's registry key — the notes identify this registry entry as the storage that carries the configuration across reboots. A FailureCommand holding a path to an operator binary or an unusual command line is the standing artifact, readable via QueryServiceConfig2(SERVICE_CONFIG_FAILURE_ACTIONS) or direct registry inspection. Recovery processes appear with services.exe ancestry each time the chain fires.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — failure actions are an orthogonal sixth mechanism: SCM-mediated and crash-triggered where T-017's layers are schedule-, logon-, and shutdown-driven, and the restart-on-failure chain complements T-017's userland resilience monitor with a reboot-surviving, services.exe-owned fail-safe.

## References

- Atlas material: atlas-binary-analysis-part5.md (unit 8), atlas-post-exploit-part1.md (units 12, 30, 31), atlas-post-exploit-part11.md (units 37–39), atlas-post-exploit-part4.md (units 25–34)
- MITRE ATT&CK: T1543.003 — Create or Modify System Process: Windows Service (https://attack.mitre.org/techniques/T1543/003/)
- LGTM notes: lgtm:service-failure-actions-persistence, lgtm:service-failure-actions-card, lgtm:service-failure-actions-as-persistence, lgtm:proposed-service-failure-action-resilience
- Public references: Microsoft documentation for the SERVICE_FAILURE_ACTIONS structure and the ChangeServiceConfig2 function (winsvc.h) — the struct typedef and API signatures reproduced in the training slides originate from these headers.

## Source Reference

No current implementation. `dark_crystal/crowd/src/byovd.rs` demonstrates the SCM handle-acquisition pattern (OpenSCManagerW / CreateServiceW) an implementation would reuse, but does not implement failure actions. See atlas material and MITRE reference for public tooling.