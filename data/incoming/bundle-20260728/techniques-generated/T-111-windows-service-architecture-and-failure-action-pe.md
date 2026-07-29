---
id: T-111
name: Windows Service Architecture and Failure-Action Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1543.003
tags: [persistence, service-architecture, failure-actions, changeserviceconfig2, auto-restart, resilience, sc-action-restart, control-handler]
origin: atlas-synthesis
member_notes: ['lgtm:windows-service-persistence-coverage', 'lgtm:service-failure-actions-resilience']
---

# Windows Service Architecture and Failure-Action Persistence — Three-Component Service Model and Self-Healing Auto-Restart

## Summary

SEC670 documents the three-component Windows service architecture required to construct a functional persistence service: the main thread calling StartServiceCtrlDispatcher with a SERVICE_TABLE_ENTRY array, the service thread executing the ServiceMain callback, and the control handler registered via RegisterServiceCtrlHandlerEx for SERVICE_CONTROL_STOP and other control events. For persistence resilience, the SERVICE_FAILURE_ACTIONS structure is set via ChangeServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS, specifying SC_ACTION_RESTART with a configurable delay — ensuring the service auto-restarts on failure and survives termination. This mechanism provides built-in self-healing persistence at the SCM level without requiring a separate monitor process, complementing T-017's PhantomPersist 30-minute resilience monitor with a native Windows recovery mechanism.

## Mechanism

1. The service binary's main thread calls StartServiceCtrlDispatcher, passing a SERVICE_TABLE_ENTRY array. Each entry maps a service name string to a ServiceMain function pointer. The dispatcher blocks the main thread, waiting for the SCM to send control requests via the named pipe \\.\pipe\net\NtControlPipe16.
2. When the SCM starts the service (at boot for SERVICE_AUTO_START, or on demand via StartService), StartServiceCtrlDispatcher receives the start command, creates a new thread, and invokes the ServiceMain callback registered in the SERVICE_TABLE_ENTRY.
3. Within ServiceMain, the service thread calls RegisterServiceCtrlHandlerEx (or the older RegisterServiceCtrlHandler) to register a HandlerEx callback function. This callback receives SERVICE_CONTROL_STOP, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, and user-defined control codes from the SCM.
4. ServiceMain calls SetServiceStatus to transition the service through the state machine: SERVICE_START_PENDING → SERVICE_RUNNING. The SERVICE_STATUS structure passed to SetServiceStatus includes dwCurrentState, dwControlsAccepted (which control codes the service handles), dwWin32ExitCode, dwCheckPoint, and dwWaitHint (timeout for the SCM before assuming the service is unresponsive).
5. The payload executes within ServiceMain or on a thread spawned by ServiceMain. The service thread maintains the SERVICE_RUNNING state by not returning from ServiceMain (or by keeping a worker thread alive).
6. The control handler callback processes SERVICE_CONTROL_STOP by calling SetServiceStatus to transition to SERVICE_STOP_PENDING, performing cleanup, and then setting SERVICE_STOPPED. This allows clean shutdown via the SCM.
7. For persistence resilience, the operator calls ChangeServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS (0x2), passing a SERVICE_FAILURE_ACTIONS structure. This structure specifies cActions (count of SC_ACTION entries) and lpsaActions (array of SC_ACTION structures). Each SC_ACTION contains a type field (SC_ACTION_RESTART=0) and a dwDelay field (milliseconds to wait before restarting).
8. When the service process exits unexpectedly — whether from a crash, external termination, or resource exhaustion — the SCM applies the failure actions in sequence. For SC_ACTION_RESTART, the SCM waits dwDelay milliseconds and then re-launches the service process, re-executing the payload. The failure count resets after dwResetPeriod (specified in the SERVICE_FAILURE_ACTIONS structure) without further failures.

## OS Internals Context

The three-component service architecture reflects the Windows service threading model. The main thread is consumed by StartServiceCtrlDispatcher's blocking loop, which services the SCM control pipe. The service thread is created by the dispatcher when a start request arrives, executing the ServiceMain callback. The control handler runs on an SCM-managed thread context when control requests arrive. This separation means the payload must not block ServiceMain's control handler registration — if the handler is not registered within the SCM's 30-second timeout, the SCM considers the service unresponsive and may terminate it.

The SERVICE_STATUS structure's dwWaitHint field tells the SCM how long to wait between SetServiceStatus calls before assuming the service is hung. During SERVICE_START_PENDING, the service must periodically call SetServiceStatus with an incremented dwCheckPoint value to indicate progress. Failure to update within dwWaitHint causes the SCM to kill the service process and apply failure actions if configured.

The RegisterServiceCtrlHandlerEx function (available on Windows 2000 and later) extends the older RegisterServiceCtrlHandler by passing a user-defined context pointer and additional control codes. The HandlerEx prototype receives dwControl (the control code), dwEventType (for device events), lpEventData (event-specific data), and lpContext (user-defined context). This allows the service to handle device notifications and power management events in addition to standard service controls.

The SERVICE_FAILURE_ACTIONS structure is applied via ChangeServiceConfig2, which sends an RPC to services.exe to update the service's configuration in the registry. The failure actions are stored under HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\FailureActions as a binary REG_BINARY value. The SCM monitors the service process handle and, on unexpected process termination, increments an internal failure counter and applies the corresponding SC_ACTION from the array. If the counter exceeds the array length, the last action is repeated. The counter resets to zero after dwResetPeriod seconds without a failure.

SC_ACTION_RESTART causes the SCM to re-execute the service's ImagePath via CreateProcess, starting a new instance of the service binary. The new process goes through the full StartServiceCtrlDispatcher → ServiceMain → SetServiceStatus sequence. The delay specified in dwDelay provides a grace period before restart, which can be used to avoid tight crash loops that would trigger SCM's anti-loop protection (after approximately 5 rapid failures, the SCM stops auto-restarting and logs Event ID 7034).

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN BYOVD module (`dark_crystal/crowd/src/byovd.rs`) uses SCM APIs for driver loading but does not implement the three-component service architecture or failure actions. A persistence implementation would construct a binary with a main function calling StartServiceCtrlDispatcher, a ServiceMain callback that registers the control handler and executes the payload, a HandlerEx function that handles SERVICE_CONTROL_STOP, and a post-registration sequence that calls ChangeServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS specifying SC_ACTION_RESTART with a 60-second delay. The T-017 PhantomPersist module's 30-minute resilience monitor (`dark_crystal/crowd/src/persist/phantom_restart.rs`) provides a user-mode resilience pattern that failure actions complement at the SCM level.

## Why It Matters

The three-component service architecture is a prerequisite for any service-based persistence — a binary that does not implement the SCM contract will be killed by the SCM within 30 seconds and logged as a failed service. The failure-action mechanism provides native self-healing persistence without requiring a separate monitor process, complementing T-017's PhantomPersist resilience monitor with a built-in Windows recovery mechanism. The combination of auto-start at boot (SERVICE_AUTO_START) and auto-restart on failure (SC_ACTION_RESTART) creates a persistence layer that survives both reboots and process termination.

## Detection Considerations

- **Telemetry sources**: Event log System channel EID 7031 (service terminated unexpectedly) and EID 7041 (service failed to start) indicate failure-action triggers. EID 7034 (service terminated) logged when the SCM gives up after repeated restart failures. Sysmon EID 1 (process creation) for repeated service process launches. Registry monitoring on FailureActions value changes detects failure-action configuration.
- **Bypass options**: Setting a reasonable dwDelay (e.g., 60 seconds) avoids tight crash loops that trigger SCM anti-loop protection. Implementing a functional control handler that responds to SERVICE_CONTROL_STOP prevents the SCM from logging timeout errors. Setting dwResetPeriod to a long value (e.g., 86400 seconds) ensures the failure counter resets daily, allowing indefinite restart capability.
- **Residual artifacts**: The FailureActions registry value persists. The System event log records each restart attempt. Repeated EID 7031 events in sequence indicate auto-restart behavior, which may be flagged by anomaly detection rules.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-111 complements T-17's PhantomPersist resilience monitor with native SCM-level auto-restart
- **T-040 SERVICE_FAILURE_ACTIONS Crash-Triggered Persistence** — existing vault card covering the failure-action mechanism from the same angle
- **T-109 Windows Service SCM Persistence as Distinct Layer** — companion card covering the broader SCM programming model and service variants
- **T-110 Windows Service SCM Persistence via CreateService** — companion card covering the CreateService API and registration sequence

## References

- Atlas material: atlas-exploit-dev-part18.md, atlas-exploit-dev-part19.md
- MITRE ATT&CK: T1543.003 — https://attack.mitre.org/techniques/T1543/003/
- LGTM notes: lgtm:windows-service-persistence-coverage, lgtm:service-failure-actions-resilience

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.