---
id: T-058
name: svchost Hosting Model Analysis for Injection Targeting
category: discovery
tier: B
crate: none
source_file: none
mitre: T1007
mitre_secondary: [T1055]
tags: [svchost, services, target-selection, process-injection, service-hosting, opsec, blast-radius, discovery]
origin: atlas-synthesis
member_notes: [lgtm:svchost-hosting-model-target-selection]
---

# svchost Hosting Model — Injection Target Selection via Shared vs Isolated Services

## Summary

Windows hosts most services inside generic svchost.exe processes, and whether a given service shares its host process with other services determines the blast radius of an injection failure. Shared services (SERVICE_WIN32_SHARE_PROCESS, co-hosted under one `svchost.exe -k <group>`) share address space, heap state, and crash fate; isolated services run in a dedicated svchost. An operator selecting a process-injection host uses this distinction to avoid destabilizing co-tenant services unrelated to the objective, and to match the target's token and protection level to the operation. The selection step itself is low-noise — service enumeration is routine system behavior — but the downstream injection telemetry (Sysmon 8, ETW-TI) and any induced service-crash events (System log 7034) are where the decision pays or costs.

## Mechanism

1. Connect to the Service Control Manager with OpenSCManagerW and call EnumServicesStatusExW with SC_ENUM_PROCESS_INFO. The returned ENUM_SERVICE_STATUS_PROCESS array maps every service to its hosting PID via SERVICE_STATUS_PROCESS.dwProcessId.
2. Group the results by PID. Multiple service entries resolving to the same dwProcessId identify a shared svchost instance; a PID with exactly one entry identifies an isolated host.
3. Correlate with the group definition in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`, where each REG_MULTI_SZ value names a group and lists its member services, and with QueryServiceConfigW output — a shared host's lpBinaryPathName takes the form `C:\Windows\System32\svchost.exe -k <group>`.
4. Read each candidate service's configuration from `HKLM\SYSTEM\CurrentControlSet\Services\<name>`: the Type value (0x10 SERVICE_WIN32_OWN_PROCESS versus 0x20 SERVICE_WIN32_SHARE_PROCESS), the ServiceDll under the Parameters subkey, and any SvcHostSplitDisable override that forces sharing on builds that would otherwise split.
5. Account for the Windows 10 1703 service-splitting change: on hosts with sufficient RAM, services that historically shared a group each receive a dedicated svchost, so most svchost processes on modern builds are already single-service. Classification must be performed per host, not assumed from version alone.
6. Filter candidates by execution context: open the host process token and distinguish LocalSystem, LocalService, and NetworkService identities; confirm the process is not protected (GetProcessInformation with ProcessProtectionLevelInfo) — PPL-hosted services reject external handle access regardless of the caller's privileges.
7. Score co-tenancy risk. An unhandled exception in injected code terminates the host process; in a shared svchost every co-hosted service dies with it, the SCM marks each as unexpectedly stopped, and recovery actions or watchdogs fire. Select an isolated svchost whose loss affects exactly one non-critical service.
8. Hand the selected PID, service name, token class, and hosting-model annotation to the injection dispatcher as target metadata.

## OS Internals Context

The SCM (services.exe) owns the service database and tracks which process hosts which service; the EnumServicesStatusExW path is a local RPC client call into the SCM's interface, which is why enumeration produces no suspicious driver-level activity. The svchost grouping mechanism predates Vista and historically concentrated dozens of services into groups such as netsvcs, LocalServiceNetworkRestricted, and netsvcs-style composites. Service splitting, introduced in Windows 10 version 1703 for machines with more than 3.5 GB of RAM, inverted the default: services get their own svchost unless the per-service SvcHostSplitDisable value or a group definition forces sharing. Split hosts frequently appear on the command line as `svchost.exe -k <group> -p`; the `-p` switch is undocumented, with public research indicating it marks the host as dedicated to a single service.

Crash fate sharing is a consequence of process granularity, not a service mechanism: the EPROCESS is the protection and accounting boundary, and every hosted service's DLLs execute on threads inside that one EPROCESS. When the process dies, the SCM's notification of process exit walks its record of services running in that PID and transitions each to a failed state, emitting Event 7034 per service into the System log and scheduling any configured recovery actions. A shared host therefore converts one injection defect into a burst of service-failure telemetry.

Session placement also matters: services execute in Session 0, so reaching an svchost from an interactive-session implant crosses the session boundary, which constrains handle acquisition and UI-adjacent techniques. Protection level is orthogonal: an isolated but PPL-protected svchost is a worse target than a shared unprotected one. The classification step must therefore evaluate hosting model, token, session, and protection level as a tuple, not hosting model in isolation.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a recon module producing an annotated process list: for each svchost PID, the set of hosted service names (from EnumServicesStatusExW correlation), the group name, the service Type flags, the token identity, and the protection level. Injection selection in the dispatch layer would then filter on `hosted_services.len() == 1`, exclude protected processes, and prefer hosts whose single tenant is restartable and non-critical. The module requires only read access to the SCM and registry, making it safe to run early in the kill chain.

## Why It Matters

Injection technique cards describe how to enter a process; this card describes which process to enter. Mis-selecting a shared svchost converts a recoverable injection failure into a multi-service outage with clustered event-log entries — an operator-visible, defender-alerting cascade. The 1703 service-splitting change means the optimal target set differs materially between legacy and modern hosts, so the distinction must be computed, not remembered.

## Detection Considerations

- **Telemetry sources**: The enumeration phase rides benign APIs and produces little signal. Detection weight falls on the injection itself: Sysmon Event ID 8 (CreateRemoteThread) with source and target images, the ETW Threat-Intelligence provider reporting cross-process memory writes and thread creation, and kernel image-load callbacks catching unsigned modules mapped into svchost (Sysmon 7). Induced failures emit System-log Event 7034 (unexpected termination) per co-hosted service, plus WER artifacts.
- **Bypass options**: Choose an isolated, non-PPL svchost whose tenant is a restartable, non-critical service with a matching token. Prefer injection paths that avoid CreateRemoteThread — thread-pool manipulation, thread hijack, or APC-based entry — so the hosting decision is not undermined by a high-fidelity thread-creation alert.
- **Residual artifacts**: Injected allocations inside the host's address space, a 7034 cluster if the host crashes, and service recovery activity if SCM restarts the tenant. On split hosts the crash signature is a single-service failure, which blends with routine service flakiness far better than a multi-service group death.

## Related Techniques

- **T-007 Pool Party** — thread-pool injection requires a live host process; hosting-model classification supplies the target with bounded crash blast radius.
- **T-013 Remaining Injection Methods** — hollowing, hijacking, and stomping variants inherit the same co-tenant crash-fate constraint when aimed at service hosts.

## References

- Atlas material: atlas-methodology-part3.md
- MITRE ATT&CK: T1007 (https://attack.mitre.org/techniques/T1007/), T1055 (https://attack.mitre.org/techniques/T1055/)
- LGTM notes: lgtm:svchost-hosting-model-target-selection

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.