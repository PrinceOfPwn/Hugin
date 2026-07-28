---
id: T-110
name: Windows Service SCM Persistence via CreateService
category: persistence
tier: A
crate: none
source_file: none
mitre: T1543.003
tags: [persistence, create-service, scm, service-auto-start, imagepath, boot-persistence, service-control-manager, persistent-service]
origin: atlas-synthesis
member_notes: ['lgtm:gap-persistence-surface-coverage', 'lgtm:service-based-persistence-card', 'lgtm:gap-service-based-persistence', 'lgtm:scm-service-persistence-coverage-gap']
---

# Windows Service SCM Persistence via CreateService — Boot-Time SYSTEM Persistence via Service Registration

## Summary

The CreateService API provides the programmatic interface for registering a Windows service that auto-starts at boot, executing an attacker-controlled binary under SYSTEM or service-account context. SEC670 Book 4 Lab 4.1 PersistentService walks through the complete registration sequence: OpenSCManager to obtain the SCM handle, CreateService with SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, and SERVICE_AUTO_START parameters, followed by StartService to launch the service. The service binary's ImagePath is stored in the registry at HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath and auto-restarts on every boot. Failure-action recovery can be configured via ChangeServiceConfig to restart the service on crash, providing self-healing persistence. SEC670 identifies services and Run keys as the two most commonly deployed persistence vectors in real-world intrusions.

## Mechanism

1. The operator calls OpenSCManagerW with SC_MANAGER_ALL_ACCESS (or SC_MANAGER_CREATE_SERVICE) to obtain a handle to the local SCM. This call requires administrator privileges — the SCM validates the caller's token against the SCM object's DACL.
2. The operator calls CreateServiceW with the following key parameters: hSCManager (from step 1), lpServiceName (internal service name, used as the registry key name), lpDisplayName (human-readable name shown in services.msc), dwDesiredAccess=SERVICE_ALL_ACCESS, dwServiceType=SERVICE_WIN32_OWN_PROCESS (0x10), dwStartType=SERVICE_AUTO_START (0x2), dwErrorControl=SERVICE_ERROR_NORMAL (0x1), lpBinaryPathName (full path to the service binary), lpServiceStartName (account context, NULL for LocalSystem), and lpPassword (NULL for LocalSystem).
3. CreateService writes the service configuration to the registry under HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>. The ImagePath value stores the binary path, Start=2 enables auto-start, Type=0x10 specifies own-process, and ErrorControl=1 specifies normal error handling.
4. The operator optionally calls ChangeServiceConfig2 with SERVICE_CONFIG_FAILURE_ACTIONS to configure crash-recovery behavior: a SERVICE_FAILURE_ACTIONS structure specifying SC_ACTION_RESTART with a delay (e.g., 60000 ms), ensuring the SCM automatically restarts the service if its process terminates abnormally.
5. The operator calls StartServiceW to start the service immediately, or waits for the next boot for SERVICE_AUTO_START to trigger. On boot, the SCM enumerates auto-start services and launches them in dependency order.
6. The service binary executes its ServiceMain callback, which registers a control handler and reports SERVICE_RUNNING via SetServiceStatus. The payload executes within the service process context, running as NT AUTHORITY\SYSTEM when lpServiceStartName is NULL.
7. Persistence persists across reboots via the registry entry. The SCM re-launches the service at every boot. If failure actions are configured, the SCM also restarts the service after crashes.

## OS Internals Context

The CreateService API is the programmatic interface to the SCM's service database. Internally, CreateService sends an RPC to services.exe, which creates the registry entries under HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>. The registry key contains values for ImagePath (binary path), Start (start type: 2=auto, 3=demand, 4=disabled), Type (service type: 0x10=own process, 0x20=shared process, 0x110=own process isolated), ErrorControl (error handling severity), DependOnService (dependency list), and ObjectName (service account).

The dwDesiredAccess parameter in CreateService specifies the access mask for the returned service handle. SERVICE_ALL_ACCESS (0xF01FF) grants full control, including SERVICE_START, SERVICE_STOP, SERVICE_CHANGE_CONFIG, SERVICE_DELETE, and all query rights. This handle is used for subsequent operations like StartService, ChangeServiceConfig, and ChangeServiceConfig2.

The SERVICE_AUTO_START start type (Start=2) causes the SCM to start the service during boot, after the boot-time services (Start=0, kernel drivers) and system services (Start=1) have started. The SCM processes services in groups defined by the load ordering group (lpLoadOrderGroup parameter), respecting the DependOnService list for ordering. Services without a group specification start in the default group.

The lpServiceStartName parameter controls the security context. NULL (or "LocalSystem") causes the service to run as NT AUTHORITY\SYSTEM. Specifying "NT AUTHORITY\NetworkService" or "NT AUTHORITY\LocalService" runs the service under those reduced-privilege accounts. Specifying a domain\username pair with a password runs the service under that user context. For persistence, LocalSystem is the default choice as it provides the highest privilege level available to a service.

The ChangeServiceConfig2 API with SERVICE_CONFIG_FAILURE_ACTIONS (0x2) configures the SERVICE_FAILURE_ACTIONS structure, which contains dwResetPeriod (time after which the failure count resets), lpRebootMsg (message displayed on reboot), lpCommand (command to execute on failure), and cActions/lpsaActions (array of SC_ACTION entries). Each SC_ACTION specifies a type (SC_ACTION_RESTART=0, SC_ACTION_REBOOT=1, SC_ACTION_RUN_COMMAND=2) and a delay in milliseconds. The SCM monitors the service process and, if it exits unexpectedly, applies the failure actions in sequence.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN BYOVD module (`dark_crystal/crowd/src/byovd.rs`) calls CreateServiceW with SERVICE_KERNEL_DRIVER and SERVICE_DEMAND_START for transient driver loading — the service is created, started, used for IOCTL communication, then stopped and deleted. A persistence implementation would adapt this pattern by setting dwServiceType=SERVICE_WIN32_OWN_PROCESS, dwStartType=SERVICE_AUTO_START, omitting the cleanup (stop and delete) calls, and implementing the ServiceMain contract in the payload binary. The byovd.rs file demonstrates the correct FFI calling pattern for CreateServiceW, including wide string encoding via `to_wide_null()`, error handling via GetLastError, and handle cleanup via CloseServiceHandle.

## Why It Matters

CreateService-based persistence is identified by SEC670 as one of the two most commonly deployed persistence vectors in real-world intrusions. The mechanism provides SYSTEM-privilege execution at boot, before user logon, with built-in auto-restart resilience via failure actions. The service registration creates a persistent registry entry that survives reboots without requiring additional scheduling mechanisms. T-017's five-layer suite documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits the CreateService vector.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 7045 (service installed) is the primary detection event, logging the service name, binary path, service type, and start type. Event log System channel EID 7000 (service start failure) and EID 7034 (service terminated unexpectedly) indicate operational issues. EDR products typically flag new service creation with unsigned binaries, binaries outside standard directories, or suspicious service names. Registry monitoring on HKLM\SYSTEM\CurrentControlSet\Services detects ImagePath modification on existing services.
- **Bypass options**: Binary patching an existing service's ImagePath avoids triggering EID 7045. Using a signed binary or a binary with a legitimate publisher name reduces anomaly scoring. Placing the binary in a standard Windows directory blends with legitimate service paths. Setting the service description via ChangeServiceConfig2 mimics legitimate service metadata.
- **Residual artifacts**: The registry entry under HKLM\SYSTEM\CurrentControlSet\Services persists. The binary file on disk remains. The System event log records service installation (EID 7045), start/stop events, and failure-recovery actions. Autoruns enumerates services in its Services category.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-110 fills the CreateService persistence gap absent from T-017's suite
- **T-036 Service-Based Persistence via SCM** — existing vault card covering service persistence from the same MITRE angle
- **T-109 Windows Service SCM Persistence as Distinct Layer** — companion card covering the broader SCM programming model and service variants
- **T-111 Windows Service Architecture and Failure-Action Persistence** — companion card covering the three-component architecture and failure-action resilience mechanism

## References

- Atlas material: atlas-misc-part1.md, atlas-post-exploit-part10.md, atlas-post-exploit-part14.md, atlas-post-exploit-part16.md
- MITRE ATT&CK: T1543.003 — https://attack.mitre.org/techniques/T1543/003/
- LGTM notes: lgtm:gap-persistence-surface-coverage, lgtm:service-based-persistence-card, lgtm:gap-service-based-persistence, lgtm:scm-service-persistence-coverage-gap

## Source Reference

No current implementation. The file `dark_crystal/crowd/src/byovd.rs` demonstrates the CreateServiceW FFI calling pattern for kernel driver loading but does not implement service persistence.