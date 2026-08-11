<!-- BEGIN CARD T-107 -->
---
id: T-107
name: Port Monitor DLL Persistence via AddMonitor
category: persistence
tier: A
crate: none
source_file: none
mitre: T1547.010
tags: [persistence, port-monitor, addmonitor, print-spooler, system-privilege, registry, dll-loading, winspool]
origin: atlas-synthesis
member_notes: ['lgtm:port-monitor-persistence-gap', 'lgtm:port-monitor-persistence-coverage']
---

# Port Monitor DLL Persistence via AddMonitor — SYSTEM-Privilege Persistence via Print Spooler

## Summary

The AddMonitor API from winspool.drv registers a custom DLL as a port monitor that the print spooler service (spoolsv.exe) loads at service startup, providing SYSTEM-privilege persistence that triggers on boot rather than user logon. The monitor entry persists in the registry under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors with the DLL path, and the spooler service loads it on every restart. This mechanism differs from logon-triggered persistence because it executes under the print spooler's SYSTEM context and blends with legitimate printer driver installation activity. The AddMonitor call requires SeLoadDriverPrivilege, making it accessible only from an elevated context.

## Mechanism

1. The operator obtains SeLoadDriverPrivilege through token adjustment or prior privilege escalation. AddMonitor validates the caller's token for this privilege before creating the registry entry.
2. A custom DLL is crafted implementing the port monitor interface. The DLL must export InitializePrintMonitor (for legacy monitors) or InitializePrintMonitor2 (for version 2 monitors), returning a MONITOR_INFO structure containing function pointers for the monitor's print job operations.
3. The operator calls AddMonitor with a MONITOR_INFO_2 structure containing three fields: pName (the monitor's display name), pEnvironment (target environment string such as "Windows x64" or "Windows NT x86"), and pDLLName (the filename of the DLL to load).
4. AddMonitor internally invokes an RPC to the spooler service, which creates a registry subkey under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName> with the Driver value set to the DLL filename.
5. The print spooler service (spoolsv.exe) loads the registered DLL during its next initialization sequence via LoadLibrary. The DLL executes within the spoolsv.exe process, which runs as NT AUTHORITY\SYSTEM.
6. The registry entry persists across reboots. Each time the spooler service starts — typically at boot via its SERVICE_AUTO_START configuration — the DLL is loaded, re-executing the monitor's initialization routine.
7. The loaded DLL performs arbitrary actions within its InitializePrintMonitor callback: spawning threads, loading additional payloads, or establishing C2 channels. The callback must return a valid MONITOR structure to avoid spooler error logging.
8. To remove the persistence, the operator calls DeleteMonitor or deletes the registry subkey and the DLL file from disk.

## OS Internals Context

The print spooler service (spoolsv.exe) hosts all print-related components and runs as a SYSTEM-privilege process managed by the Service Control Manager. Port monitors occupy the lowest layer of the Windows print architecture, acting as the interface between the spooler and physical or virtual print devices. When spoolsv.exe initializes, it enumerates the HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors registry key and loads each registered monitor DLL.

The MONITOR_INFO_2 structure used by AddMonitor contains three string fields. The pDLLName field specifies only the filename — not a full path — and the spooler resolves it against the %SystemRoot%\System32\spool\DRIVERS\x64\ (or x86) directory. This path resolution behavior means the operator's DLL must be placed in the spool driver directory or a directory on the system DLL search path. Alternatively, the operator can write the registry entry directly via RegCreateKeyExW, specifying a full path in the Driver value, bypassing AddMonitor's path resolution.

The AddMonitor function is exported by winspool.drv (the print spooler client DLL) and internally invokes an RPC to the spooler service to perform the registration. The spooler validates the caller's token for SeLoadDriverPrivilege before creating the registry entry. This privilege check makes AddMonitor a privileged operation distinct from typical registry writes — even an administrator with write access to the Print\Monitors key cannot use AddMonitor without SeLoadDriverPrivilege. Direct registry writes bypass this check but require separate SeTakeOwnershipPrivilege or SeRestorePrivilege to modify the ACL-protected registry key.

The registry structure under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors stores each monitor as a subkey. Default monitors present on a standard installation include Local Port, Standard TCP/IP Port, USB Port Monitor, and WSD Port Monitor. A new monitor subkey with a Driver value pointing to the attacker's DLL appears alongside these legitimate entries. The spooler does not verify the digital signature of port monitor DLLs on default Windows configurations, though Secure Boot with Code Integrity may enforce signing requirements on locked-down systems.

The spooler's LoadLibrary call for each monitor DLL occurs early in spoolsv.exe's initialization, before the spooler processes any print jobs. This timing means the malicious DLL's code runs before any user-mode print-related activity, providing a clean execution window. The DLL remains loaded for the lifetime of the spooler process.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would call AddMonitorW via FFI, passing a MONITOR_INFO_2W structure with the monitor name, environment string, and DLL filename. The DLL payload would export InitializePrintMonitor2, performing its malicious work in the callback before returning a minimal MONITOR structure to avoid spooler error logging. The DLL should be written to the spool driver directory or the registry entry should be created directly via RegCreateKeyExW with a full path in the Driver value. On cleanup, DeleteMonitor or manual registry deletion removes the persistence entry, and the DLL file is shredded from disk.

## Why It Matters

Port monitor persistence provides SYSTEM-privilege execution that triggers at service start rather than user logon, making it suitable for server targets where user sessions are infrequent. The mechanism blends with legitimate printer driver installation activity and persists across reboots via a registry key that is less commonly monitored than Run keys or scheduled tasks. T-017's five-layer persistence suite covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits this print spooler vector entirely.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 7 (image load) captures spoolsv.exe loading unexpected DLLs from the spool driver directory or arbitrary paths. Registry monitoring on HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors detects new monitor subkey creation. The Microsoft-Windows-PrintService/Operational ETW channel logs port monitor registration and load operations. Autoruns enumerates port monitor entries in its Print Monitor DLLs category.
- **Bypass options**: Naming the monitor and DLL to mimic legitimate entries (e.g., using a manufacturer-prefixed name or a generic-sounding port description) reduces visual anomaly during manual review. Placing the DLL in the standard spool driver directory avoids path-based suspicion. Direct registry writes bypass the AddMonitor privilege check if the operator has taken ownership of the registry key.
- **Residual artifacts**: The registry subkey under Print\Monitors persists until removed via DeleteMonitor or manual deletion. The DLL file on disk remains at the dropped path. The spooler service logs monitor load failures to the System event log if the DLL does not export the required interface.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-107 fills the port monitor persistence gap absent from T-017's suite of COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist
- **T-035 Port Monitor Persistence via Print Spooler** — existing vault card covering the same MITRE technique from the same operational angle

## References

- Atlas material: atlas-exploit-dev-part10.md, atlas-exploit-dev-part19.md
- MITRE ATT&CK: T1547.010 — https://attack.mitre.org/techniques/T1547/010/
- LGTM notes: lgtm:port-monitor-persistence-gap, lgtm:port-monitor-persistence-coverage

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-107 -->

<!-- BEGIN CARD T-108 -->
---
id: T-108
name: Registry Run/RunOnce Key Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1547.001
tags: [persistence, registry, run-key, runonce, hklm, hkcu, autostart, logon, shell-launch]
origin: atlas-synthesis
member_notes: ['lgtm:gap-registry-run-key-persistence', 'lgtm:registry-run-key-persistence-coverage-gap', 'lgtm:registry-persistence-coverage-gap']
---

# Registry Run/RunOnce Key Persistence — Logon-Triggered Execution via Registry Autostart

## Summary

The Run and RunOnce registry keys under HKLM and HKCU provide the most commonly used Windows persistence mechanism, executing a specified command or binary at user logon. SEC670 identifies the Run key as the single most prevalent registry persistence vector in real-world intrusions, citing APT28, Emotet, and APT39 as operators that leverage it. HKLM Run keys require administrator privileges and execute for all users at logon, while HKCU Run keys provide per-user persistence accessible from medium integrity without elevation. The RunOnce variant executes its entries a single time and then deletes the registry value, providing single-shot persistence for first-stage payloads. T-017's five-layer persistence suite documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits Run/RunOnce despite their prevalence.

## Mechanism

1. The operator selects the target registry key based on the desired scope and privilege context. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run executes for all users at logon but requires administrator privileges to modify. HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run executes only for the current user but requires no elevation, making it accessible from a medium-IL implant.
2. The operator creates a registry value under the selected key using RegSetValueExW. The value name is an arbitrary string (often mimicking a legitimate application name), and the value data is a REG_SZ or REG_EXPAND_SZ string containing the command to execute — a binary path, optionally with arguments.
3. At the next user logon, the Windows shell (explorer.exe) enumerates the Run keys in a specific order: HKLM\...\Run first, then HKCU\...\Run. Each value's command string is parsed and executed via CreateProcess.
4. For RunOnce keys (HKLM\...\RunOnce and HKCU\...\RunOnce), the shell executes the command and then deletes the registry value immediately after execution. This provides single-shot persistence useful for first-stage droppers that establish a more durable mechanism on first run.
5. The HKLM\...\RunOnce key supports the optional RunOnceEx mechanism, which uses a structured registry layout under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx to execute multiple commands in sequence with dependency ordering. RunOnceEx processes entries via the rundll32 shim iernonce.dll, providing a different execution path from standard RunOnce.
6. The executed binary runs in the user's logon session context, inheriting the user's token, environment variables, and integrity level. HKLM-launched processes run in the first logging user's context.
7. Persistence persists across reboots for standard Run keys, as the registry values remain until manually deleted. RunOnce values are self-deleting after a single execution.

## OS Internals Context

The Windows shell (explorer.exe) processes Run and RunOnce keys during its initialization sequence at user logon. The shell reads HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run first, then HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, executing each value's command string via CreateProcess. The command string is passed as the lpCommandLine parameter, which means it is subject to the same parsing rules as any CreateProcess call — the first token is treated as the executable path, and the shell resolves unqualified paths against the system PATH.

The registry key hierarchy for Run/RunOnce persistence spans both per-machine (HKLM) and per-user (HKCU) scopes. HKLM keys require SeTakeOwnershipPrivilege or administrator access to modify, and they execute for every user who logs on. HKCU keys are writable by the current user without elevation and execute only for that user's sessions. This distinction makes HKCU\...\Run the primary persistence vector for medium-IL implants that have not achieved elevation.

The RunOnce key's self-deleting behavior is implemented by the shell: after executing the command, the shell calls RegDeleteValue on the registry entry. If the command fails to execute (e.g., the binary path is invalid), the shell still deletes the value, meaning a failed RunOnce entry provides no persistence benefit. This contrasts with the standard Run key, which retries on every logon regardless of execution success.

The RunOnceEx mechanism uses a different execution path. Instead of direct CreateProcess by the shell, RunOnceEx entries are processed by iernonce.dll (loaded via rundll32), which reads a structured registry layout with subkeys for each command, supporting dependency ordering and status logging. RunOnceEx entries are also self-deleting.

On 64-bit Windows, the registry's WOW64 redirection affects Run key access. A 32-bit process reading HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run is redirected to HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run. An operator writing a Run key from a 32-bit process must account for this redirection or use KEY_WOW64_64KEY to access the native 64-bit view.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would call RegCreateKeyExW to open the target Run key, then RegSetValueExW to write the command string. For HKCU scope, no elevation is required. For HKLM scope, the implementation would need to either run elevated or adjust the process token to include SeTakeOwnershipPrivilege and take ownership of the key before modifying its DACL. The command string should use a fully qualified path to avoid PATH-based execution ambiguity, and the value name should mimic a legitimate startup application to reduce visual anomaly in Autoruns output.

## Why It Matters

Run/RunOnce registry persistence is the most prevalent autostart mechanism in real-world intrusions per SEC670 material, predating and exceeding in frequency the five persistence layers documented in T-017. HKCU\...\Run provides medium-IL persistence without elevation, making it accessible from standard user-context implants. The technique's prevalence in APT operations — SEC670 cites APT28, Emotet, APT39, CherryPicker, and T9000 — demonstrates its operational utility and detection surface tradeoffs.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 12 (registry value set) and EID 13 (registry value renamed) with a target path filter on Run/RunOnce keys. Autoruns detects all Run/RunOnce entries in its Logon category. Windows Security event log EID 4657 (registry value modified) if registry auditing is enabled on the Run keys. EDR products typically monitor Run key modifications as a high-priority persistence indicator.
- **Bypass options**: Using a legitimate-looking binary name and path (e.g., placing the payload in a Program Files subdirectory) reduces anomaly scoring. Setting the value name to mimic a known startup application (e.g., "OneDrive" or "SecurityHealthService") blends with legitimate entries. Using REG_EXPAND_SZ with environment variables obscures the full path in casual inspection.
- **Residual artifacts**: The registry value under Run/RunOnce persists until manually deleted. The referenced binary file on disk remains. Autoruns and similar persistence enumeration tools flag entries with unsigned binaries, unusual paths, or suspicious command-line patterns.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-108 fills the registry Run-key gap absent from T-017's persistence suite
- **T-034 IFEO GlobalFlag and SilentProcessExit Registry Persistence** — distinct registry persistence mechanism using Image File Execution Options rather than Run keys
- **T-038 AppInit_DLLs Registry Persistence** — distinct registry DLL-loading mechanism triggered by user32 import rather than shell logon

## References

- Atlas material: atlas-post-exploit-part5.md, atlas-post-exploit-part14.md, atlas-post-exploit-part16.md
- MITRE ATT&CK: T1547.001 — https://attack.mitre.org/techniques/T1547/001/
- LGTM notes: lgtm:gap-registry-run-key-persistence, lgtm:registry-run-key-persistence-coverage-gap, lgtm:registry-persistence-coverage-gap

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-108 -->

<!-- BEGIN CARD T-109 -->
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
<!-- END CARD T-109 -->

<!-- BEGIN CARD T-110 -->
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
<!-- END CARD T-110 -->

<!-- BEGIN CARD T-111 -->
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

1. The service binary's main thread calls StartServiceCtrlDispatcher, passing a SERVICE_TABLE_ENTRY array. Each entry maps a service name string to a ServiceMain function pointer. The dispatcher blocks the main thread, waiting for the SCM to send control requests via the named pipe \\.\pipe
et\NtControlPipe16.
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
<!-- END CARD T-111 -->

<!-- BEGIN CARD T-112 -->
---
id: T-112
name: AppInit DLLs and AppCert DLL Registry Loading
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.010
mitre_secondary: [T1546.009]
tags: [persistence, appinit-dlls, appcert-dlls, registry, user32, create-process, dll-loading, secure-boot]
origin: atlas-synthesis
member_notes: ['lgtm:appinit-and-appcert-persistence', 'lgtm:registry-dll-loading-mechanisms']
---

# AppInit DLLs and AppCert DLL Registry Loading — Subsystem-Triggered DLL Injection via Registry

## Summary

AppInit_DLLs and AppCertDlls are two registry-driven DLL loading mechanisms that inject specified DLLs into processes based on subsystem events rather than logon or boot triggers. AppInit_DLLs causes user32.dll to load listed DLLs into any process that imports user32.dll, providing broad-scope persistence across GUI processes. AppCertDlls loads listed DLLs into processes that invoke CreateProcess-family APIs, targeting process creation rather than GUI initialization. SEC670 treats these as distinct from Run/RunOnce keys because they trigger on subsystem events rather than at logon, and cites APT28 and T9000 as historical AppInit_DLLs operators. Modern Windows versions progressively restrict both mechanisms: RequireSignedAppInit_DLLs enforces signature verification, and Secure Boot disables AppInit_DLLs entirely on supported systems.

## Mechanism

1. For AppInit_DLLs persistence, the operator writes a DLL path (or semicolon-separated list of paths) to the registry value HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs as a REG_SZ string.
2. The operator optionally sets HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\RequireSignedAppInit_DLLs to 0 (REG_DWORD) to disable signature verification, or to 1 to require Authenticode-signed DLLs. On systems with Secure Boot enabled, AppInit_DLLs is disabled regardless of this registry value.
3. When any process loads user32.dll (which occurs for any process that creates a window or uses GDI/User32 functions), user32.dll's DllMain routine reads the AppInit_DLLs registry value and calls LoadLibrary on each listed DLL path. The loaded DLL's DllMain executes within the host process's context.
4. For AppCertDlls persistence, the operator creates a registry value under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls. Each value name is an arbitrary string, and the value data is a REG_SZ path to the DLL.
5. When any process calls CreateProcess, CreateProcessAsUser, or CreateProcessWithTokenW, the kernel-mode subsystem routing invokes each AppCertDlls entry's exported CreateProcessNotify or equivalent callback. The DLL's NotifyRoutine executes before the new process begins, allowing the DLL to inspect, modify, or block the process creation.
6. Both mechanisms provide persistence across reboots via registry storage. AppInit_DLLs re-triggers on every user32.dll load. AppCertDlls re-triggers on every CreateProcess call.
7. The loaded DLL can perform arbitrary actions within its DllMain (AppInit) or NotifyRoutine (AppCert) callback, including spawning threads, establishing C2 channels, or modifying the host process's behavior.

## OS Internals Context

The AppInit_DLLs mechanism is implemented within user32.dll's initialization code. When user32.dll is loaded into a process (via implicit import, explicit LoadLibrary, or delayed load), its DllMain function with DLL_PROCESS_ATTACH reason reads the AppInit_DLLs and RequireSignedAppInit_DLLs registry values from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows. For each path in the AppInit_DLLs value (semicolon-delimited), user32.dll calls LoadLibraryExW to load the DLL. The loaded DLL's DllMain executes within the host process's address space, inheriting its token, integrity level, and privilege context.

A documented hazard exists with AppInit_DLLs: if the loaded DLL's DllMain itself imports or loads user32.dll (directly or transitively), an infinite recursion occurs. User32.dll loads the AppInit DLL, which loads user32.dll, which loads the AppInit DLL again. This causes a stack overflow and process termination. The operator's DLL must avoid re-loading user32.dll during its DllMain — typically by deferring user32-dependent operations to a separate thread created within DllMain.

The RequireSignedAppInit_DLLs registry value, introduced in Windows Vista, controls whether user32.dll verifies the Authenticode signature of each AppInit DLL before loading. When set to 1, only Authenticode-signed DLLs are loaded. When set to 0, unsigned DLLs are loaded without verification. On systems with Secure Boot enabled (UEFI Secure Boot + Windows 8.1 or later), AppInit_DLLs is disabled entirely — user32.dll skips the registry read regardless of the RequireSignedAppInit_DLLs value. This makes AppInit_DLLs persistence ineffective on modern Secure Boot systems.

The AppCertDlls mechanism operates at a different layer. The registry key HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls stores DLL paths that the Windows subsystem (winsrv.dll in session 0, or the kernel-mode portion of CreateProcess routing) loads into any process that calls the CreateProcess family. Each AppCertDlls DLL must export a function (historically named CreateProcessNotify) that receives information about the process being created. This mechanism is less commonly abused than AppInit_DLLs because it requires a reboot to take effect (the DLL list is read at subsystem initialization) and operates at a broader scope.

On 64-bit Windows, the AppInit_DLLs registry value is subject to WOW64 redirection. A 32-bit process loading user32.dll reads from the WOW6432Node registry view (HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs), while a 64-bit process reads from the native view. An operator targeting both architectures must write to both registry views.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An AppInit_DLLs implementation would write the DLL path to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs via RegSetValueExW, set RequireSignedAppInit_DLLs to 0 if the DLL is unsigned, and ensure the DLL's DllMain avoids re-loading user32.dll by deferring payload execution to a spawned thread. The DLL must be placed at a path accessible to the processes that will load user32.dll. For AppCertDlls, the implementation would write the DLL path under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls and export the required notification function.

## Why It Matters

AppInit_DLLs and AppCertDlls provide DLL-loading persistence triggered by subsystem events rather than logon, giving them a different execution profile from Run/RunOnce keys. AppInit_DLLs in particular has historical significance as a persistence vector used by APT28 and T9000 per SEC670 material. The mechanisms are distinct from registry autostart because they inject into already-running processes rather than launching a new process, providing in-process execution context that can hook or modify host process behavior. The progressive restriction of AppInit_DLLs on modern Windows (signature requirements, Secure Boot disablement) limits its current applicability but does not eliminate it on non-Secure Boot systems.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 7 (image load) captures unexpected DLLs loaded into processes via the AppInit mechanism, with the image loaded by user32.dll rather than the process itself. Registry monitoring on HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows detects AppInit_DLLs value changes. Registry monitoring on HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls detects AppCertDlls additions. Autoruns detects both in its AppInit DLLs and AppCertDlls categories.
- **Bypass options**: Signing the DLL with a valid or stolen Authenticode certificate allows operation with RequireSignedAppInit_DLLs=1. Writing to the WOW6432Node view targets 32-bit processes, which may be less monitored. Naming the DLL to mimic a legitimate application component reduces visual anomaly.
- **Residual artifacts**: The registry value persists until manually deleted. The DLL file on disk remains at the specified path. The loaded DLL appears in the module list of every process that imports user32.dll, creating a broad detection footprint.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-112 fills the AppInit/AppCert gap absent from T-017's suite
- **T-038 AppInit_DLLs Registry Persistence** — existing vault card covering the AppInit_DLLs mechanism
- **T-067 AppCert DLL Injection Persistence** — existing vault card covering the AppCertDlls mechanism
- **T-108 Registry Run/RunOnce Key Persistence** — companion card covering shell-launch registry persistence as distinct from subsystem-triggered DLL loading

## References

- Atlas material: atlas-post-exploit-part1.md, atlas-post-exploit-part11.md
- MITRE ATT&CK: T1546.010 — https://attack.mitre.org/techniques/T1546/010/
- LGTM notes: lgtm:appinit-and-appcert-persistence, lgtm:registry-dll-loading-mechanisms

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-112 -->

<!-- BEGIN CARD T-113 -->
---
id: T-113
name: Service Hiding via SDDL DACL Security Descriptor Tampering
category: persistence
tier: A
crate: none
source_file: none
mitre: T1564
mitre_secondary: [T1222]
tags: [persistence, sddl, security-descriptor, dacl, service-hiding, enumeration-evasion, sc-exe, setnamedsecurityinfo]
origin: atlas-synthesis
member_notes: ['lgtm:sddl-security-descriptor-tampering', 'lgtm:programmatically-hidden-service']
---

# Service Hiding via SDDL DACL Security Descriptor Tampering — Enumeration Evasion via Security Descriptor Modification

## Summary

SDDL (Security Descriptor Definition Language) string manipulation on service objects denies enumeration rights to common SIDs, causing the service to be invisible to sc query, services.msc, Get-Service, and other standard enumeration tools. Using sc.exe sdset or SetNamedSecurityInfo with DACL_SECURITY_INFORMATION, an operator denies SERVICE_QUERY_STATUS and SERVICE_ENUMERATE_DEPENDENTS to Everyone or INTERACTIVE while retaining SERVICE_START in a separate ACE for their own access. The service remains startable and persists across reboots, but is invisible to standard enumeration. This is a persistence resilience measure layered on top of service-based persistence (CreateService), not a standalone autostart mechanism. T-016 and T-017 do not document this stealth hardening.

## Mechanism

1. The operator creates a service via CreateService with standard parameters (SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS) establishing the persistence base layer.
2. The operator constructs an SDDL string that denies enumeration rights to broad SIDs while allowing start and control to a narrower SID. The SDDL string format is: D:(A;ace_flags;rights;object_guid;inherit_guid;account_sid), where D: denotes DACL, A denotes allow ACE, and the rights token controls the specific access.
3. The SDDL rights tokens relevant to service objects include: SC_MANAGER_CONNECT (standard), SERVICE_QUERY_CONFIG (0x0001), SERVICE_CHANGE_CONFIG (0x0002), SERVICE_QUERY_STATUS (0x0004), SERVICE_ENUMERATE_DEPENDENTS (0x0008), SERVICE_START (0x0010), SERVICE_STOP (0x0020), SERVICE_PAUSE_CONTINUE (0x0040), SERVICE_INTERROGATE (0x0080), SERVICE_USER_DEFINED_CONTROL (0x0100), and SERVICE_ALL_ACCESS (0xF01FF).
4. The operator denies SERVICE_QUERY_STATUS (0x0004) and SERVICE_ENUMERATE_DEPENDENTS (0x0008) to Everyone (S-1-1-0) or INTERACTIVE (S-1-5-4) by including a deny ACE: D:(D;;0x000C;;;WD) where D denotes deny, 0x000C is the bitmask for QUERY_STATUS|ENUMERATE_DEPENDENTS, and WD is the well-known SID for Everyone.
5. The operator allows SERVICE_START (0x0010) and SERVICE_ALL_ACCESS to SYSTEM (S-1-5-18) and the operator's SID in separate allow ACEs: D:(A;;GA;;;SY)(A;;0x10;;;S-1-5-32-544) where GA is GENERIC_ALL for SYSTEM and 0x10 is SERVICE_START for Administrators.
6. The operator applies the SDDL string via sc.exe sdset <ServiceName> "<SDDL_STRING>" or programmatically via SetNamedSecurityInfo with SE_OBJECT_TYPE=SE_SERVICE, specifying DACL_SECURITY_INFORMATION in the SecurityInformation parameter.
7. After the DACL is applied, sc query returns ACCESS_DENIED for the service, services.msc does not display it, and Get-Service throws an access error. The service remains registered in the SCM database and auto-starts at boot per its Start=2 configuration, but is invisible to standard enumeration.
8. The operator can still control the service by calling StartServiceW or ControlService with a handle opened with SERVICE_START access, which the DACL allows for their SID.

## OS Internals Context

Service objects in Windows are securable objects managed by the SCM. Each service has an associated security descriptor containing an owner SID, a group SID, a SACL (system access control list for auditing), and a DACL (discretionary access control list for access control). The DACL contains ACEs (access control entries) that map SIDs to access rights. When a caller attempts to open a service handle via OpenService, the SCM performs an access check against the service's DACL using the caller's primary token.

The SDDL string format encodes the security descriptor in a text representation. The DACL section begins with D: and contains a parenthesized list of ACEs. Each ACE has six semicolon-delimited fields: ace_type (A=allow, D=deny), ace_flags (inheritance and audit flags), rights (access mask as a hex string or SDDL-specific string constants), object_guid (for object-specific ACEs), inherit_object_guid, and account_sid (as a well-known SID string like WD for Everyone, SY for SYSTEM, or a full SID string).

The rights field for service objects uses the same access mask values as the dwDesiredAccess parameter to OpenService and CreateService. SERVICE_QUERY_STATUS (0x0004) is the right required by EnumServicesStatus and sc query to retrieve service state. SERVICE_ENUMERATE_DEPENDENTS (0x0008) is required to list dependent services. By denying these specific rights to broad SIDs while allowing them to SYSTEM and the operator's SID, the service becomes invisible to any process running under a non-privileged token that does not have an explicit allow ACE.

The SetNamedSecurityInfo API (from advapi32.dll) is the programmatic interface for modifying a service's security descriptor. It accepts the service name, SE_OBJECT_TYPE=SE_SERVICE (0x2), a SecurityInformation bitmask (DACL_SECURITY_INFORMATION=0x4), and optional pointers to the new owner SID, group SID, DACL, and SACL. The function internally sends an RPC to services.exe to update the service's security descriptor in the SCM database. The NtSetSecurityObject native API provides a lower-level alternative that operates on a service handle rather than a name, avoiding the advapi32 hook surface.

## Key Implementation Details

**No current implementation in the HUGIN source for service object DACL manipulation.** The file `dark_crystal/crowd/src/block_handle.rs` implements the same SDDL/DACL buffer construction pattern for process objects via NtSetSecurityObject — building a raw SECURITY_DESCRIPTOR with ACL header, deny ACE for Everyone (S-1-1-0), and allow ACE for SYSTEM (S-1-5-18) in a byte buffer, then applying it with DACL_SECURITY_INFORMATION. This pattern would be adapted for service objects by changing the target from a process handle to a service handle (obtained via OpenServiceW) and modifying the denied access rights from PROCESS_ALL_ACCESS to SERVICE_QUERY_STATUS|SERVICE_ENUMERATE_DEPENDENTS. The block_handle.rs implementation constructs the security descriptor in a manual byte buffer rather than using BuildSecurityDescriptor or SDDL parsing functions, avoiding the advapi32 hook surface.

## Why It Matters

Service DACL hiding provides enumeration evasion for service-based persistence, complementing the autostart mechanism with stealth. A hidden service survives reboots, auto-starts at boot, and is invisible to standard incident response tooling (sc query, services.msc, Get-Service). This addresses a gap in T-016's evasion suite (which covers PEB unlink and stack spoofing but not SDDL-based enumeration hiding) and in T-017's persistence suite (which documents PhantomPersist resilience but not service-level stealth). The technique applies to any securable Windows object, making it a general-purpose evasion primitive.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 4657 (registry value modified) if registry auditing is enabled on the Services key, as the security descriptor is stored in the registry's SECURITY value. Windows Security event log EID 4678 (security descriptor modified) if SACL auditing is configured. The sc.exe sdset command generates a command-line event (Sysmon EID 1) that can be filtered. Anomalous DACL configurations on services can be detected by baseline comparison — querying all service DACLs and flagging those that deny SERVICE_QUERY_STATUS to Everyone.
- **Bypass options**: Using SetNamedSecurityInfo via FFI rather than sc.exe avoids command-line logging. Using NtSetSecurityObject on a service handle avoids the advapi32 hook surface. Denying only SERVICE_QUERY_STATUS rather than all access reduces anomaly scoring while still hiding the service from standard enumeration.
- **Residual artifacts**: The modified security descriptor persists in the SCM database and the registry's SECURITY value under the service key. A service that returns ACCESS_DENIED to sc query while still appearing in the boot start list (Start=2) is a detection indicator. Tools that enumerate services via SCM RPC at a lower level than sc query (e.g., direct EnumServicesStatusEx calls) may still enumerate the service name even if status query is denied.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-113 complements T-017's persistence suite with service-level enumeration evasion
- **T-016 EDR Evasion Suite** — T-113 fills the SDDL-based enumeration hiding gap absent from T-016's evasion suite
- **T-041 Service Hiding from SCM Enumeration** — existing vault card covering service hiding from the same conceptual angle
- **T-062 Security Descriptor Manipulation for Object Access Control** — existing vault card covering SDDL manipulation as a general technique

## References

- Atlas material: atlas-post-exploit-part2.md, atlas-post-exploit-part12.md
- MITRE ATT&CK: T1564 — https://attack.mitre.org/techniques/T1564/
- LGTM notes: lgtm:sddl-security-descriptor-tampering, lgtm:programmatically-hidden-service

## Source Reference

No current implementation for service object DACL manipulation. The file `dark_crystal/crowd/src/block_handle.rs` implements the same SDDL/DACL buffer construction pattern for process objects via NtSetSecurityObject, which would be adapted for service objects by changing the target handle type and denied access rights.
<!-- END CARD T-113 -->

<!-- BEGIN CARD T-114 -->
---
id: T-114
name: Service Architecture Unquoted Path and SCM Suspended Start
category: persistence
tier: B
crate: none
source_file: none
mitre: T1543.003
mitre_secondary: [T1574.009]
tags: [persistence, service-internals, unquoted-path, svchost, suspended-start, service-isolation, injection-target, process-hollowing]
origin: atlas-synthesis
member_notes: ['lgtm:service-archetype-injection-target-selection', 'lgtm:gap-unquoted-service-path-exploitation', 'lgtm:gap-scm-housekeeping-suspended-start']
---

# Service Architecture, Unquoted Path, and SCM Suspended-Start Internals — Service Hosting Archetypes, Path Traversal, and Suspended-Boot Semantics

## Summary

SEC670 surfaces three service-internal concepts that serve as prerequisites for multiple offensive techniques. First, the SERVICE_WIN32_SHARE_PROCESS vs SERVICE_WIN32_OWN_PROCESS vs SERVICE_WIN32_OWN_PROCESS (isolated) archetypes from QueryServiceConfig2 affect injection target selection — an injected shared svchost crashes all cohabiting services, while an isolated own-process service contains the blast radius. Second, unquoted service binary paths enable privilege escalation via path traversal when Windows resolves the binary. Third, the SCM performs a five-step housekeeping sequence on service start including creating the service process in a suspended state and resuming after mapping the binary, described as process-hollowing-like semantics that create a hook-free window. All three are documented in SEC670 review and lab material as foundational knowledge for service-based operations.

## Mechanism

1. The operator queries a service's hosting archetype via QueryServiceConfig2 with SERVICE_CONFIG_SERVICE_TYPE to retrieve dwServiceType. The returned value distinguishes SERVICE_WIN32_OWN_PROCESS (0x10), SERVICE_WIN32_SHARE_PROCESS (0x20), and SERVICE_WIN32_OWN_PROCESS isolated (0x110).
2. For injection target selection (concept 1), the operator enumerates services via EnumServicesStatusEx, filters by dwServiceType, and selects a target based on isolation characteristics. A shared-process service (0x20) runs in a svchost.exe group — injecting into it risks destabilizing all cohabiting services in the group if the injection causes a crash. An own-process service (0x10) or isolated own-process service (0x110) runs in a dedicated process, containing the blast radius to a single service.
3. For unquoted path exploitation (concept 2), the operator enumerates service ImagePath values via QueryServiceConfig. A path containing spaces without enclosing quotes (e.g., C:\Program Files\My Service\srv.exe) is vulnerable. Windows CreateProcess resolves unquoted paths by trying each prefix: C:\Program.exe, C:\Program Files\My.exe, C:\Program Files\My Service\srv.exe. The operator places a malicious binary at the first writable path in the resolution chain.
4. On the next service start, the SCM's CreateProcessW call resolves the unquoted path and loads the attacker's binary instead of (or in addition to) the legitimate service binary, executing in the service's privilege context.
5. For SCM suspended-start semantics (concept 3), when the SCM starts a service, it performs a five-step housekeeping sequence: (a) CreateProcessW with CREATE_SUSPENDED flag, creating the process in a suspended state; (b) mapping the service binary into the process address space; (c) setting up the service environment (job object, token, desktop); (d) notifying the SCM database that the process is created; (e) ResumeThread to begin execution.
6. The suspended window between steps (a) and (e) provides a hook-free execution period — the service process exists with its image mapped but no code has executed yet, meaning no user-mode hooks (EDR instrumentation, DLL load callbacks) have been applied to the process. An operator with a handle to the service process can perform injection during this window.
7. For blending service-based persistence with hollowing-style injection, a malicious service binary can hijack the suspended-start phase: the binary is the service's ImagePath, so the SCM creates the process suspended, maps the binary, and resumes — the binary's code executes before any EDR hook is applied, because the SCM's CreateProcessW with CREATE_SUSPENDED does not trigger the standard process creation callback sequence until ResumeThread.

## OS Internals Context

The SERVICE_WIN32_SHARE_PROCESS archetype causes the SCM to launch the service within a pre-existing or newly created svchost.exe process. The svchost group is determined by the service's ImagePath registry value (for services using svchost, this is %SystemRoot%\System32\svchost.exe -k <GroupName>) and the ServiceDll value (pointing to the actual service DLL loaded via LoadLibrary into the svchost process). Multiple services sharing a group cohabit in the same process, sharing the address space, handles, and thread pool. This sharing is why Microsoft moved many services to isolated own-process (0x110) in Windows 10 1709 and later — a vulnerability or crash in one shared service affects all cohabitants.

The SERVICE_WIN32_OWN_PROCESS isolated variant (0x110, SERVICE_WIN32_OWN_PROCESS with the SERVICE_WIN32_OWN_PROCESS_ISOLATION flag) was introduced to provide process-level isolation for security-critical services. An isolated service gets its own process even if configured as a shared-process type, preventing cross-service impact.

The unquoted service path vulnerability exploits CreateProcessW's path resolution behavior. When lpApplicationName is NULL and lpCommandLine contains an unquoted path with spaces, CreateProcessW attempts to resolve the executable by treating each space as a potential path boundary. For C:\Program Files\My Service\srv.exe, it tries C:\Program.exe, then C:\Program Files\My.exe, then C:\Program Files\My Service\srv.exe. If an attacker can write a binary to C:\Program.exe or C:\Program Files\My.exe (depending on directory ACLs), that binary executes instead of the legitimate service, inheriting the service's privilege context (typically LocalSystem). This is a privilege escalation technique rather than a persistence technique per se — it exploits misconfigured existing services.

The SCM's suspended-start sequence is an internal implementation detail of services.exe. When starting a service, the SCM calls CreateProcessW with the CREATE_SUSPENDED flag (dwCreationFlags=0x4) to create the process in a suspended state. This allows the SCM to perform additional setup (job object assignment, token impersonation, environment block configuration) before the process's main thread begins execution. After setup, the SCM calls ResumeThread. The process creation kernel callbacks (PsSetCreateProcessNotifyRoutine) fire at the CreateProcessW call, but user-mode DLL load callbacks and EDR hooks are not applied until the process's first thread begins executing and the loader (ntdll!LdrpInitializeThunk) runs. This creates a window where the process exists but is not yet instrumented.

## Key Implementation Details

**No current implementation in the HUGIN source for service archetype enumeration or unquoted path exploitation.** The file `dark_crystal/crowd/src/early_bird.rs` uses CREATE_SUSPENDED (0x00000004) via CreateProcessW for process injection, which is the same flag the SCM uses internally for service startup — but early_bird.rs creates its own suspended process rather than hijacking the SCM's suspended-start phase. The file `dark_crystal/crowd/src/byovd.rs` uses QueryServiceConfig-equivalent patterns (OpenServiceW → QueryServiceConfig) in its cleanup path but does not enumerate service archetypes for injection target selection. An implementation of unquoted path exploitation would enumerate services via EnumServicesStatusEx, query each service's ImagePath via QueryServiceConfig, identify unquoted paths with spaces, determine writable directories in the resolution chain, and place a malicious binary at the first writable path.

## Why It Matters

The service hosting archetype directly affects injection stability — injecting into a shared svchost risks destabilizing multiple services, while targeting an isolated own-process service contains the impact. The unquoted path vulnerability is a classic privilege escalation vector that requires no code execution on the target — only filesystem write access to a directory in the path resolution chain. The SCM suspended-start semantics provide a hook-free injection window that blends with legitimate service startup, making injection during this phase harder to distinguish from normal service initialization.

## Detection Considerations

- **Telemetry sources**: For unquoted path exploitation, Sysmon EID 1 (process creation) captures the unexpected binary path when the attacker's binary executes as a service. Regular auditing of service ImagePath values for unquoted paths with spaces identifies the vulnerability before exploitation. EDR products may flag service processes loading from non-standard paths.
- **Bypass options**: For archetype-based target selection, targeting an isolated own-process service (0x110) minimizes collateral impact and avoids the multi-service crash anomaly that would trigger alerting. For unquoted path exploitation, using a binary name that matches a legitimate application in the path chain reduces visual anomaly.
- **Residual artifacts**: Unquoted path exploitation leaves the attacker's binary on disk at the path traversal location. The service's ImagePath registry value remains unquoted. The SCM suspended-start window leaves no direct artifact — the process creation and resume are standard SCM operations that do not generate anomalous events unless the injected code triggers subsequent detection.

## Related Techniques

- **T-007 Pool Party** — injection technique whose target selection is informed by service hosting archetype analysis
- **T-017 Five-Layer Persistence** — T-114 documents service internals prerequisite to the persistence layers in T-017
- **T-109 Windows Service SCM Persistence as Distinct Layer** — companion card covering the broader SCM programming model and service variants
- **T-044 Service-Based Local Privilege Escalation** — SCM enumeration for privilege escalation, related to unquoted path exploitation

## References

- Atlas material: atlas-post-exploit-part3.md, atlas-post-exploit-part4.md
- MITRE ATT&CK: T1543.003 — https://attack.mitre.org/techniques/T1543/003/
- LGTM notes: lgtm:service-archetype-injection-target-selection, lgtm:gap-unquoted-service-path-exploitation, lgtm:gap-scm-housekeeping-suspended-start

## Source Reference

No current implementation. The file `dark_crystal/crowd/src/early_bird.rs` uses CREATE_SUSPENDED for process injection (the same flag the SCM uses for service startup) but does not hijack the SCM's suspended-start phase. The file `dark_crystal/crowd/src/byovd.rs` uses SCM API patterns (OpenServiceW, ControlService, DeleteService) in its cleanup path.
<!-- END CARD T-114 -->