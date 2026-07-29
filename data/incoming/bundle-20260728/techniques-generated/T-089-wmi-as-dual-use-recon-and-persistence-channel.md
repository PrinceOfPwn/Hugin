---
id: T-089
name: WMI as Dual-Use Recon and Persistence Channel
category: discovery
tier: A
crate: none
mitre: T1047
mitre_secondary: [T1546.003]
tags: [wmi, com-interfaces, iwbeanservices, recon, persistence, dual-use, event-subscription, root-subscription, win32-classes]
origin: atlas-synthesis
member_notes: ['lgtm:cross-source-wmi-convergence', 'lgtm:cross-source-wmi-recon-persistence-convergence']
---

# WMI as Dual-Use Recon and Persistence Channel — Single COM Session for Enumeration and Permanent Event Subscription

## Summary

Windows Management Instrumentation (WMI) is the single Windows management substrate that supports both host reconnaissance (read queries via IWbemServices::ExecQuery on standard namespaces) and persistence (write operations via permanent event subscriptions in the root\subscription namespace) using the same COM interfaces. An operator can enumerate processes, services, and registry data via Win32_* class queries and establish persistence via __EventFilter/__EventConsumer/__FilterToConsumerBinding binding — all within a single IWbemServices COM session obtained through CoCreateInstance(CLSID_WbemLocator) → IWbemLocator::ConnectServer. The HUGIN vault's T-023 recon card and T-017 persistence card both miss this dual-use nature, which means the same COM channel serves both operational phases without reconnection or reconfiguration.

## Mechanism

1. **COM initialization**: Call CoInitializeEx(NULL, COINIT_MULTITHREADED) to initialize the COM apartment, then CoInitializeSecurity to set the authentication level (RPC_C_AUTHN_LEVEL_PKT_PRIVACY for encrypted traffic) and impersonation level (RPC_C_IMP_LEVEL_IMPERSONATE).

2. **Locator creation**: Call CoCreateInstance with CLSID_WbemLocator (0x4590F811-1D3A-11D0-891F-00AA004B2E24) and IID_IWbemLocator to obtain an IWbemLocator interface pointer.

3. **Namespace connection for recon**: Call IWbemLocator::ConnectServer with bstrNamespace = L"ROOT\\CIMV2" to connect to the standard CIM namespace. This returns an IWbemServices pointer for querying management data. For registry enumeration, connect to L"ROOT\\DEFAULT" and use the StdRegProv class.

4. **Recon queries via ExecQuery**: Call IWbemServices::ExecQuery with WQL query strings: "SELECT * FROM Win32_Process" returns process information including Name, ProcessId, CommandLine, ExecutablePath. "SELECT * FROM Win32_Service" returns service name, state, start mode, and path. "SELECT * FROM Win32_Registry" or the StdRegProv provider returns registry key values. The query results come back as an IEnumWbemClassObject enumerator, and each object's properties are accessed via IWbemClassObject::Get with property names like "ProcessId", "Name", "ExecutablePath".

5. **Namespace connection for persistence**: Using the same IWbemLocator instance, call ConnectServer with bstrNamespace = L"ROOT\\SUBSCRIPTION" to connect to the subscription namespace. This returns a separate IWbemServices pointer for persistence operations. The root\subscription namespace hosts __EventFilter, __EventConsumer, and __FilterToConsumerBinding classes.

6. **Persistence via permanent event subscription**: Create instances of three classes in root\subscription:
   - __EventFilter: Defines the trigger condition via the Query property (WQL query, e.g., "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12").
   - __EventConsumer (typically ActiveScriptEventConsumer or CommandLineEventConsumer): Defines the action. CommandLineEventConsumer has an ExecutablePath and CommandLineTemplate property. ActiveScriptEventConsumer has a ScriptText property for VBScript/JScript execution.
   - __FilterToConsumerBinding: Links the filter to the consumer via the Filter and Consumer properties (references to the __EventFilter and __EventConsumer instances).

7. **Writing persistence instances**: Call IWbemServices::PutInstance on each class instance (filter, consumer, binding). The PutInstance method with WBEM_FLAG_CREATE_OR_UPDATE creates the instances in the WMI repository (located at %SystemRoot%\System32\wbem\Repository). These instances persist across reboots and execute the consumer action whenever the filter condition triggers.

8. **Cleanup of recon session**: The IWbemServices pointer for root\cimv2 can be released after recon queries complete. The IWbemServices pointer for root\subscription must remain valid only during PutInstance calls — the persistence instances survive in the repository independently of the COM session.

## OS Internals Context

WMI is implemented by the Windows Management Instrumentation service (WmiSvc, hosted in a svchost.exe process under the NetworkService account). The service exposes DCOM interfaces that client processes access through the COM activation framework. When ConnectServer is called, the COM runtime marshals the call to the WMI service via RPC, which in turn accesses the CIMOM (Common Information Model Object Manager) to resolve the namespace and return an IWbemServices proxy.

The root\cimv2 namespace is the default repository for system management data. Win32_* provider classes are implemented by provider DLLs loaded by the WMI service on demand. Win32_Process is backed by the WmiPerfClass provider that queries the kernel process list. Win32_Service is backed by the SCM provider that queries the Service Control Manager. These providers execute in the WMI service process, not in the caller's process — the caller receives serialized results via DCOM marshaling.

The root\subscription namespace is special: it is not backed by dynamic providers but by the WMI event delivery subsystem. Permanent event subscriptions are stored in the CIM repository database (a compound file stored on disk). The WMI service polls for event triggers at the interval specified in the __EventFilter.Query (the WITHIN clause). When the trigger fires, the service instantiates the __EventConsumer and executes its action. CommandLineEventConsumer spawns a process under the WMI service's security context (NetworkService by default, or LocalSystem if the service runs under that account).

The dual-use nature arises because the same COM activation path — CoCreateInstance → IWbemLocator → ConnectServer → IWbemServices — serves both the read path (ExecQuery on root\cimv2) and the write path (PutInstance on root\subscription). The only difference is the namespace string passed to ConnectServer and the method called on the returned IWbemServices pointer. An EDR monitoring IWbemServices method calls would need to distinguish between ExecQuery (recon) and PutInstance (persistence) calls — both use the same RPC interface and service endpoint.

The CRTO course surfaces WMI via Get-Domain / Get-DomainController PowerShell cmdlets, which wrap WMI/CIM calls under the hood. These cmdlets query Win32_* classes through the System.Management.ManagementObjectSearcher class, which internally uses the same IWbemServices::ExecQuery path.

## Key Implementation Details

**No current implementation in the HUGIN source.** The provided source files do not implement WMI operations. The broader HUGIN file manifest references `src/experimental/harvest/wmi_exec.rs` with role "WMI execution," but this file was not available for verification.

An implementation would require the `windows` crate's COM bindings for IWbemLocator, IWbemServices, IWbemClassObject, and IEnumWbemClassObject. The Rust code would use `CoInitializeEx` and `CoCreateInstance` via the `windows::Win32::System::Com` module, then call `ConnectServer` and `ExecQuery` through the `windows::Win32::System::Wmi` module if available, or through manual COM vtable invocation via `Interface::vtable()`.

For the persistence path, the implementation would use `IWbemServices::GetObject` to obtain class objects for __EventFilter, CommandLineEventConsumer, and __FilterToConsumerBinding, spawn instances via `IWbemClassObject::SpawnInstance`, set properties via `IWbemClassObject::Put`, and commit via `IWbemServices::PutInstance`.

## Why It Matters

The vault splits WMI across T-023 (recon) and T-017 (persistence), and T-037 (WMI permanent event subscription persistence) documents the persistence mechanism in isolation. The operational coupling — that the same COM channel, the same CLSID_WbemLocator activation, and the same IWbemServices interface serve both recon and persistence — is not surfaced anywhere. An operator who establishes an IWbemServices session for recon can reuse that session's IWbemLocator to connect to root\subscription and write persistence instances without a second COM activation. This eliminates a second DCOM binding event that would otherwise be observable by EDR. Documenting the dual-use nature makes this operational efficiency explicit.

## Detection Considerations

- **Telemetry sources**: COM activation of CLSID_WbemLocator generates DistributedCOM ETW events (Microsoft-Windows-DistributedCOM, Event ID 4 for DCOM activation). IWbemServices::ExecQuery calls generate Microsoft-Windows-WMI Activity ETW events. PutInstance calls on root\subscription are logged in the WMI repository and are queryable via `Get-WmiObject -Namespace root\subscription -Class __EventFilter`. The WMI service logs permanent subscription creation in the Event Log under Microsoft-Windows-WMI-Activity/Operational.
- **Bypass options**: Using direct DCOM instead of the COM moniker path reduces string artifacts. Connecting to root\subscription with the same IWbemLocator used for root\cimv2 recon avoids a second DCOM activation event. CommandLineEventConsumer with a benign-looking ExecutablePath blends with legitimate WMI-triggered processes. ActiveScriptEventConsumer with obfuscated script text avoids static analysis of the payload.
- **Residual artifacts**: __EventFilter, __EventConsumer, and __FilterToConsumerBinding instances persist in the CIM repository database at %SystemRoot%\System32\wbem\Repository. These are queryable via PowerShell `Get-WmiObject -Namespace root\subscription -List` and are a standard persistence detection target. The spawned consumer process appears as a child of the WMI service host (svchost.exe).

## Related Techniques

- **T-023 Client Capabilities** — Recon module could leverage WMI Win32_* classes for host enumeration via the same COM session used for persistence
- **T-017 Persistence Suite** — WMI permanent event subscription persistence in root\subscription uses the same IWbemServices COM channel as WMI recon queries

## References

- Atlas material: atlas-recon-part3.md, atlas-recon-part5.md
- MITRE ATT&CK: T1047 — https://attack.mitre.org/techniques/T1047
- LGTM notes: lgtm:cross-source-wmi-convergence, lgtm:cross-source-wmi-recon-persistence-convergence
- Public references: SEC670 Book 2 Units 19-24 (WMI recon via Win32_* classes), SEC670 Book 4 (WMI persistence via __EventFilter/__EventConsumer), CRTO (Get-Domain / Get-DomainController WMI wrappers)

## Source Reference

No current implementation in the provided source files. The file manifest references `src/experimental/harvest/wmi_exec.rs` with role "WMI execution" but the file was not available for verification. See atlas material and MITRE reference for public WMI tooling.