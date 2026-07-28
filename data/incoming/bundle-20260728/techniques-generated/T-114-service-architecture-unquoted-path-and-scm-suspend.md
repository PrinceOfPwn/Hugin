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