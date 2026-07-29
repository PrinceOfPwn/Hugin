---
id: T-087
name: Win32 Enumeration API Taxonomy and Primitive Selection
category: discovery
tier: A
crate: none
mitre: T1082
tags: [enumeration, win32-api, com-enumeration, process-enum, service-enum, task-scheduler, peb-walker, api-taxonomy, discovery]
origin: atlas-synthesis
member_notes: ['lgtm:recon-api-taxonomy-coverage', 'lgtm:sec670-maldev-recon-convergence', 'lgtm:enumeration-primitives-coverage', 'lgtm:toolhelp-vs-peb-walker-divergence']
---

# Win32 Enumeration API Taxonomy and Primitive Selection — Discovery Surface Across Object Types

## Summary

Windows exposes a fragmented surface of enumeration APIs across Win32, COM, and NT syscall boundaries, each with different return types, access mask requirements, and EDR visibility profiles. SEC670 systematically catalogs these primitives across processes (CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcessesEx), users and groups (NetUserEnum, NetLocalGroupEnum), services (EnumServicesStatusEx), scheduled tasks (ITaskScheduler COM), and network interfaces (GetAdaptersAddresses). The HUGIN vault's T-004 (PEB Walker) deliberately avoids all Win32 enumeration patterns by walking the PEB via gs:[0x60] for module resolution — an in-process memory traversal that produces no kernel telemetry. This card documents the full enumeration taxonomy, the detection surface for each primitive, and the PEB-walker alternative as the evasion path for operators who need enumeration without the observability of Win32 API calls.

## Mechanism

1. **Process enumeration**: Three documented APIs plus one undocumented. CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) produces a snapshot handle and PROCESSENTRY32W structures with parent PID. K32EnumProcesses produces a flat PID array. WTSEnumerateProcessesEx produces session-aware results with SID and full process path. NtQuerySystemInformation(SystemProcessInformation) produces the raw kernel linked list with thread data and image base (see T-086 for the full trade-off matrix).

2. **User and group enumeration**: NetUserEnum (netapi32.dll) takes level parameter (0-4) controlling detail depth — level 0 returns username only, level 3 returns USER_INFO_3 with privilege and home directory data. NetLocalGroupEnum enumerates local groups with level 0-1. NetGroupEnum enumerates global groups. All require the caller to have appropriate access and produce network traffic to the Netlogon or SAM RPC interfaces. Active Directory enumeration via LDAP (adsi) or System.DirectoryServices namespaces provides domain-wide user, group, and computer data through the DirectoryEntry class bound to LDAP://RootDSE.

3. **Service enumeration**: EnumServicesStatusEx (advapi32.dll) takes an SC manager handle (from OpenSCManager), a service type filter, a service state filter, and a level parameter (SC_STATUS_PROCESS_INFO returns SERVICE_STATUS_PROCESS with PID, service type, current state, and process ID). Requires SC_MANAGER_ENUMERATE_SERVICE access on the SCM database. The SCM RPC interface is monitored by EDR via the Service Control Manager ETW provider (Microsoft-Windows-Service Control Manager, Event ID 4 for service enumeration queries). An alternative path is EnumDependentServicesW which enumerates services dependent on a specific service handle.

4. **Scheduled task enumeration**: The ITaskScheduler COM interface (CLSID 0x148BD52A) provides IScheduledTasksFolder with EnumTasks returning an IEnumWorkItems enumerator. Each task is an ITask COM object exposing task name, status, trigger, and action data. Alternatively, the XML-based Task Scheduler 2.0 API (ITaskService, CLSID 0x0F87369F) provides folder enumeration via ITaskFolder::GetTasks. The COM activation is observable via the Microsoft-Windows-DistributedCOM ETW provider.

5. **Network interface enumeration**: GetAdaptersAddresses (iphlpapi.dll) returns IP_ADAPTER_ADDRESSES linked list with adapter name, friendly name, IP addresses (unicast, anycast, multicast), DNS suffixes, and gateway addresses. Takes Family (AF_UNSPEC for both IPv4 and IPv6), Flags (GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_DNS_SERVER), and BufferSize parameters. The underlying NDIS and TCP/IP driver interfaces can also be queried via NtDeviceIoControlFile to the AFD (Ancillary Function Driver) and TCP device objects, bypassing iphlpapi.dll hooks.

6. **PEB-walker alternative (evasion path)**: Instead of calling any Win32 enumeration API, walk the PEB via gs:[0x60] (x64) or fs:[0x30] (x86) to access PEB → Ldr → InLoadOrderModuleList for loaded module enumeration. This is pure in-process memory traversal — no kernel calls, no handle creation, no RPC traffic, no ETW events. The HUGIN T-004 implementation uses DJB2 hashing to resolve module and function names without string literals. The trade-off: PEB walking only enumerates loaded modules in the current process, not system-wide processes, services, or tasks.

## OS Internals Context

The enumeration API surface maps to three layers of the Windows architecture. Win32 APIs (kernel32, advapi32, netapi32, iphlpapi) are user-mode wrappers that route to NT syscalls, RPC calls, or device IOCTLs. COM interfaces (ITaskScheduler, ITaskService) activate through the Service Control Manager or DCOM service, generating RPC traffic visible to network monitoring. NT-direct APIs (NtQuerySystemInformation, NtQueryDirectoryObject) bypass the Win32 layer and talk directly to the executive through syscalls.

The detection divergence between Toolhelp and PEB walking is structural. CreateToolhelp32Snapshot calls NtCreateSection and NtQuerySystemInformation internally, creating a kernel snapshot object that appears in the process handle table. The Kernel-Process ETW provider fires Event ID 4 (handle creation) when the snapshot handle is created. EDR products monitoring handle table growth or specific handle type creation detect this enumeration activity.

PEB walking reads gs:[0x60] to locate the PEB, then traverses the Ldr.InLoadOrderModuleList — a doubly-linked list of LDR_DATA_TABLE_ENTRY structures each containing a BaseDllName (UNICODE_STRING) and DllBase (PVOID) field. This traversal touches only already-mapped memory pages in the current process address space. No kernel transitions occur, no handles are created, no ETW providers fire. The detection surface is limited to memory scanning heuristics that look for code reading PEB-relative offsets in a sequential pattern.

The ITaskScheduler COM interface routes through RPC to the Schedule service (schedsvc.dll hosted in svchost.exe). The RPC call binds to the scheduled tasks endpoint and is visible in RPC ETW providers. The Task Scheduler 2.0 ITaskService interface similarly activates via DCOM, generating DistributedCOM ETW events with the CLSID of the Task Scheduler class.

## Key Implementation Details

**No current implementation in the HUGIN source** for the full enumeration taxonomy. The PEB-walker alternative is implemented in `dark_crystal/crowd/src/etw.rs` via the `resolve_export_by_hash` function, which reads the module base and walks its export table. The broader HUGIN codebase references enumeration in `src/client_rust/src/byakugan.rs` (network recon including ARP, TCP, AD enum) and `src/client_rust/src/sysinfo_collect.rs` (system info collection), but these files were not available for verification.

The PEB-walker implementation in etw.rs reads MZ at the module base, e_lfanew at offset 0x3C, and navigates to the export directory via raw offset arithmetic. This same code pattern serves as the evasion alternative to calling EnumProcessModules or EnumServicesStatusEx — by resolving function addresses through in-memory PE traversal rather than Win32 API calls.

## Why It Matters

The vault documents T-023 (Client Capabilities) recon and T-004 (PEB Walker) as separate techniques, but does not explain why PEB walking is the preferred enumeration path or what detections it sidesteps. An operator choosing between CreateToolhelp32Snapshot and NtQuerySystemInformation for process enumeration, or between ITaskScheduler COM and registry parsing for task enumeration, needs to understand the telemetry profile of each option. The cross-source convergence between SEC670 and MalDev Academy on this taxonomy — both present the same three process enumeration APIs with the same trade-off matrix — indicates strong tradecraft consensus that warrants a dedicated discovery card.

## Detection Considerations

- **Telemetry sources**: CreateToolhelp32Snapshot generates Kernel-Process ETW Event ID 4 for handle creation. EnumServicesStatusEx generates Service Control Manager ETW events. NetUserEnum generates SAM RPC traffic. ITaskScheduler COM activation generates DistributedCOM ETW events. GetAdaptersAddresses calls through iphlpapi.dll which is hookable in userland. PEB walking generates no ETW events, no handle table entries, and no RPC traffic.
- **Bypass options**: PEB walking for module enumeration eliminates all Win32 API telemetry. NtQuerySystemInformation via indirect syscall eliminates userland hooks for process enumeration. Registry parsing for scheduled tasks (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache) avoids ITaskScheduler COM activation. Direct NT device IOCTLs to the TCP driver bypass iphlpapi.dll hooks for network interface enumeration.
- **Residual artifacts**: CreateToolhelp32Snapshot leaves a snapshot handle. WTSEnumerateProcessesEx leaves RPC binding handles. ITaskScheduler leaves COM references. PEB walking leaves no artifacts.

## Related Techniques

- **T-004 PEB Walker** — Deliberately avoids Win32 enumeration APIs by walking the PEB for module resolution, sidestepping all ETW telemetry and handle table artifacts
- **T-023 Client Capabilities** — Recon module (byakugan.rs) implements enumeration capabilities that should align with the API taxonomy and telemetry profiles documented here
- **T-017 Persistence Suite** — Persistence techniques interact with SCM, scheduled tasks, and COM interfaces whose enumeration primitives are documented in this taxonomy

## References

- Atlas material: atlas-enumeration-part1.md, atlas-enumeration-part2.md, atlas-exploit-dev-part16.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:recon-api-taxonomy-coverage, lgtm:sec670-maldev-recon-convergence, lgtm:enumeration-primitives-coverage, lgtm:toolhelp-vs-peb-walker-divergence
- Public references: SEC670 (enumeration API taxonomy across processes, users, groups, services, tasks, network interfaces), MalDev Academy (enumeration API selection), CRTO (recon tradecraft)

## Source Reference

No current implementation for the full enumeration taxonomy. The PEB-walker alternative is implemented in `dark_crystal/crowd/src/etw.rs` (`resolve_export_by_hash` function). See atlas material for the complete API matrix.