---
id: T-109
name: Windows Service SCM Persistence as Distinct Layer
category: persistence
tier: A
crate: none
source_file: none
mitre: T1543.003
tags: [persistence, services, scm, servicemain, service-control-handler, auto-start, svchost, binary-patching, set-servicestatus]
origin: atlas-synthesis
member_notes: ['lgtm:scm-service-persistence-layer', 'lgtm:service-based-persistence-gap', 'lgtm:services-and-binary-patching-persistence-gap', 'lgtm:services-persistence-gap']
---

# Windows Service SCM Persistence as Distinct Layer — SCM Programming Model and Service Persistence Variants

## Summary

Windows Service Control Manager persistence leverages the SCM programming model to install a malicious service binary that auto-starts at boot under SYSTEM or service-account context. SEC670 dedicates multiple units to the SCM contract: ServiceMain entry point, StartServiceControlDispatcher binding of SERVICE_TABLE_ENTRY arrays, RegisterServiceCtrlHandlerEx for control callback registration, and SetServiceStatus for the SERVICE_RUNNING to SERVICE_STOPPED state machine. Three persistence variants exist: classic own-process registration (Type=0x10, Start=2), shared-process blending (Type=0x20 for svchost cohabitation), and binary patching of an existing service's ImagePath. The SCM contract is more demanding than other persistence layers because the binary must implement a functional control handler or the SCM marks the service as failed.

## Mechanism

1. The operator crafts a service binary implementing the three-component SCM contract. The main thread calls StartServiceControlDispatcher with a SERVICE_TABLE_ENTRY array mapping the service name to the ServiceMain callback. The service thread executes ServiceMain, which registers a control handler via RegisterServiceCtrlHandlerEx and transitions through SetServiceStatus to SERVICE_RUNNING. The control handler processes SERVICE_CONTROL_STOP and other control requests.
2. For classic own-process persistence (variant 1), the operator registers the binary via CreateService with dwServiceType=SERVICE_WIN32_OWN_PROCESS (0x10), dwStartType=SERVICE_AUTO_START (0x2), and lpBinaryPathName pointing to the malicious binary on disk. The registry entry is created at HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName> with ImagePath, Start, and Type values.
3. For shared-process persistence (variant 2), the operator sets dwServiceType=SERVICE_WIN32_SHARE_PROCESS (0x20), causing the service to load into a shared svchost.exe instance. This variant blends the malicious service with legitimate cohabiting services in the same process, making process-level attribution harder. The svchost group is specified via the ServiceDll registry value or the -k command-line parameter on svchost.exe.
4. For binary patching persistence (variant 3), the operator modifies an existing service's ImagePath registry value to point to an attacker-controlled binary, preserving the original service name for operational cover. The existing service's ACL, description, and start type remain unchanged, reducing the anomaly surface compared to creating a new service.
5. On boot, the SCM (services.exe) enumerates services with Start=2 (SERVICE_AUTO_START) and starts them in dependency order. The SCM creates the service process, and the binary's main thread calls StartServiceCtrlDispatcher to connect to the SCM's control pipe.
6. The service binary's ServiceMain callback receives control, registers its handler, and reports SERVICE_RUNNING via SetServiceStatus. At this point, the payload executes within the service process context.
7. If the service process exits without reporting SERVICE_STOPPED or without calling StartServiceCtrlDispatcher within the SCM's 30-second timeout, the SCM logs an error (Event ID 7000 or 7038) and may mark the service as failed. This makes the SCM contract operationally distinct from schtask or COM hijack persistence.

## OS Internals Context

The Service Control Manager (services.exe) is the user-mode component responsible for managing the service database, starting and stopping services, and maintaining service state. At boot, the SCM reads HKLM\SYSTEM\CurrentControlSet\Services to enumerate all registered services and their configurations. For each service with Start=2 (auto-start), the SCM creates a process via CreateProcessW and waits for the service process to call StartServiceControlDispatcher, which connects to the SCM's named pipe (\\.\pipe
et\NtControlPipe16).

The StartServiceCtrlDispatcher function blocks the main thread, waiting for the SCM to dispatch a service start request. When the SCM sends a start command, StartServiceCtrlDispatcher creates a new thread for the service and calls the ServiceMain function registered in the SERVICE_TABLE_ENTRY. This threading model means the service binary's main thread is occupied by the dispatcher loop, and the payload must execute either within ServiceMain (synchronously, before reporting SERVICE_RUNNING) or on a separate thread spawned by ServiceMain.

The SERVICE_TABLE_ENTRY structure contains two fields: lpServiceName (the service name string, which must match the name registered with CreateService) and lpServiceProc (the ServiceMain function pointer). A single binary can host multiple services by registering multiple SERVICE_TABLE_ENTRY entries, each with a different ServiceMain callback.

RegisterServiceCtrlHandlerEx registers a HandlerEx callback that receives service control messages: SERVICE_CONTROL_STOP, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, and user-defined control codes. The handler must call SetServiceStatus to acknowledge each control request. Failure to call SetServiceStatus within the SCM's timeout causes the SCM to consider the service unresponsive.

The service type field (Type) in the registry determines the process model. SERVICE_WIN32_OWN_PROCESS (0x10) means the service gets its own process. SERVICE_WIN32_SHARE_PROCESS (0x20) means the service loads into a shared svchost.exe process, grouped with other services by the ImagePath and ServiceDll configuration. An additional flag, SERVICE_WIN32_OWN_PROCESS with the isolated variant (0x110), provides process isolation for services that require it.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN BYOVD module (`dark_crystal/crowd/src/byovd.rs`) uses SCM APIs — OpenSCManagerW, CreateServiceW, StartServiceW — for kernel driver loading but configures SERVICE_DEMAND_START rather than SERVICE_AUTO_START and removes the service after use, making it a transient driver-loading mechanism rather than a persistence implementation. A persistence implementation would register the service with SERVICE_AUTO_START, implement the StartServiceCtrlDispatcher loop and ServiceMain callback, and leave the service registered across reboots. The byovd.rs file demonstrates the SCM API calling pattern (OpenSCManagerW → CreateServiceW → StartServiceW → CloseServiceHandle) that a persistence implementation would adapt.

## Why It Matters

Service-based persistence is one of the two most common real-world persistence vectors per SEC670 material (alongside registry Run keys), with incident response data consistently showing service installation as a primary attacker technique. The SCM contract requirement — a functional control handler and proper state machine — makes this persistence layer operationally distinct from schtask or COM hijack, which do not impose runtime behavioral requirements on the payload. The shared-process variant provides svchost blending that no other persistence mechanism offers.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 1 (process creation) for service process launches. Sysmon EID 3 (network connection) for service processes making outbound connections. Event log System channel EID 7045 (service installed) logs new service registration with the binary path. Sysmon can be configured with EID 4657 or registry monitoring on HKLM\SYSTEM\CurrentControlSet\Services to detect ImagePath modification. EDR products typically flag unsigned service binaries or ImagePath values pointing outside %SystemRoot%.
- **Bypass options**: Binary patching an existing service (variant 3) avoids creating a new service registration, reducing the EID 7045 detection surface. Using a signed binary or a binary with a legitimate-looking name and publisher reduces anomaly scoring. Placing the binary in a standard Windows directory (e.g., System32 or Program Files) blends with legitimate service paths.
- **Residual artifacts**: The registry entry under HKLM\SYSTEM\CurrentControlSet\Services persists. The binary file on disk remains. The System event log records service installation (EID 7045) and service failures (EID 7000, 7034, 7038). Autoruns enumerates services in its Services category.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-109 fills the SCM service persistence gap absent from T-017's suite
- **T-036 Service-Based Persistence via SCM** — existing vault card covering service persistence from the same MITRE angle
- **T-110 Windows Service SCM Persistence via CreateService** — companion card focusing on the CreateService API signature and Lab 4.1 PersistentService
- **T-111 Windows Service Architecture and Failure-Action Persistence** — companion card covering the three-component architecture and failure-action resilience
- **T-044 Service-Based Local Privilege Escalation** — SCM enumeration for privilege escalation rather than persistence

## References

- Atlas material: atlas-exploit-dev-part9.md, atlas-labs-part2.md, atlas-methodology-part4.md, atlas-methodology-part7.md
- MITRE ATT&CK: T1543.003 — https://attack.mitre.org/techniques/T1543/003/
- LGTM notes: lgtm:scm-service-persistence-layer, lgtm:service-based-persistence-gap, lgtm:services-and-binary-patching-persistence-gap, lgtm:services-persistence-gap

## Source Reference

No current implementation. The file `dark_crystal/crowd/src/byovd.rs` demonstrates SCM API calling patterns (OpenSCManagerW, CreateServiceW, StartServiceW) for kernel driver loading but does not implement service persistence.