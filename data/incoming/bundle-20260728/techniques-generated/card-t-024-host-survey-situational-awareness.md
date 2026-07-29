---
id: T-024
name: Host Survey and Situational Awareness: Unified Reconnaissance
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1057, T1518.001, T1087, T1016, T1007, T1012]
tags: [host-survey, discovery, process-enumeration, ip-helper-api, wts-api, ntquerysysteminformation, registry-hives, wua-com, situational-awareness, edr-detection]
origin: atlas-synthesis
member_notes: ['lgtm:host-survey-script-primitive', 'lgtm:proposed-recon-survey-card', 'lgtm:proposed-host-survey-card', 'lgtm:proposed-host-survey-recon-card', 'lgtm:recon-enumeration-api-surface']
---

# Host Survey and Situational Awareness: Unified Reconnaissance — Coordinated First-Phase Target Assessment

## Summary

The host survey is a unified reconnaissance primitive that aggregates OS version and architecture, patch status, running processes, installed software, users and groups, services and scheduled tasks, network adapter configuration, and registry state into a single coordinated output consumed by every later phase of an operation. SEC670 dedicates Book 2 ("Getting to Know Your Target") to this capability, treating it not as a loose collection of enumeration calls but as a first-phase action whose output gates payload selection, evasion technique selection, injection target selection, and the continue-or-abort decision. The technique exploits no single OS primitive; it is the disciplined composition of the documented Win32/NT/WTS/IP-Helper API catalog, with per-API trade-offs (snapshot lag, hookability, remote-versus-local capability) that the operator weighs per target. The primary detection surface is the API layer itself: documented enumeration APIs sit at the most commonly hooked boundary in user mode, which is why the material presents undocumented alternatives such as `NtQuerySystemInformation` for stealth-sensitive enumeration.

## Mechanism

1. **Determine OS version and architecture.** Call `GetNativeSystemInfo` (VOID return; fills a caller-supplied `SYSTEM_INFO`). Read `wProcessorArchitecture` to distinguish native x64 from WoW64, and map the numeric OS version against the release table the material provides: 5.1 = XP, 5.2 = Server 2003, 6.0 = Vista/2008, 6.1 = 7/2008 R2, 6.2 = 8/2012, 6.3 = 8.1/2012 R2, 10 = Windows 10/Server 2016. Kernel version derives from `ntoskrnl.exe` under `C:\Windows\System32`. Supplement with `GetProductInfo`, `GetWindowsDirectory`, and `GetComputerName` (the SEC670 bootcamp set), and optionally the undocumented `KUSER_SHARED_DATA` page for version fields without touching the Win32 layer.
2. **Query patch and service-pack status.** Query the WMI `Win32_QuickFixEngineering` class (the same class behind `Get-HotFix` and `wmic qfe list`; the material notes it may not present a complete view of all updates), or use the Windows Update Agent (WUA) COM APIs: create an `IUpdateSession`, call `CreateUpdateSearcher`, run `IUpdateSearcher::Search(criteria, &results)`, then walk `ISearchResult::get_Updates` → `IUpdateCollection::get_Count`. Hotfix level determines whether a given exploit or service-pack-dependent payload will run or crash the host.
3. **Enumerate processes, selecting among four API families.** `EnumProcesses` is the simplest and returns the least detail. `CreateToolhelp32Snapshot` is described as one of the more common malware enumeration APIs and returns richer detail, but carries snapshot lag: processes created after the snapshot are missed. `WTSEnumerateProcessesEx` (wtsapi32.h) enumerates across sessions on the local machine and against remote servers via an `hServer` handle, with remote interrogation requiring specific registry keys on the target. The undocumented path is `NtQuerySystemInformation` with the `SystemProcessInformation` class of the community-documented `SYSTEM_INFORMATION_CLASS` enum — riskier to call, stealthier at the hook layer.
4. **Inventory installed software via directory walks.** Walk `C:\Program Files` (64-bit assumption), `C:\Program Files (x86)` (32-bit assumption), the system drive root (Python-style non-standard installs), and per-user folders using `FindFirstFile`/`FindNextFile` recursion (the SEC670 FileFinder pattern). Interpret the inventory: development tools suggest a workstation role; Notepad++, Process Hacker, and VMware artifacts indicate a research VM and feed the abort decision.
5. **Enumerate users and groups.** From the command line, `net user` and `net localgroup`; programmatically, the lmaccess.h/lmuse.h NetAPI family — `NetGroupGetUsers`, `NetLocalGroupGetMembers`, `NetUseEnum`, `NetUseGetInfo` (a sampling, not exhaustive). The operational prize is a member of the local Administrators group, or a Domain Admin logged into the host.
6. **Enumerate services and scheduled tasks via the SCM.** Service inventory reveals target purpose (DHCP/DNS/FTP services indicate server roles), potentially vulnerable services for privilege escalation or persistence, and services belonging to AV/EDR products. Inspect individual service security descriptors with `sc.exe sdshow` and parse the SDDL output.
7. **Gather NIC and network configuration via the IP Helper ladder.** `GetAdaptersAddresses` is the primary API — IPv4 and IPv6, mapping adapters to addresses, with the two-call buffer-sizing pattern (`SizePointer` in/out). `GetInterfaceInfo` returns the list of IPv4-enabled devices (`IP_INTERFACE_INFO` with `NumAdapters` and an `IP_ADAPTER_INDEX_MAP` array; `ERROR_INSUFFICIENT_BUFFER` on first sizing call). `GetNumberOfInterfaces` is the quick count, and its result includes logical interfaces and the loopback adapter. `GetIpStatistics` fills a `MIB_IPSTATS` for aggregate IP counters. Command-line equivalents (`ipconfig`, `netstat -e`, `Get-NetAdapter`) exist but spawn processes.
8. **Survey the registry.** Enumerate across the five predefined root keys — `HKEY_USERS`, `HKEY_LOCAL_MACHINE`, and the three link/merged-view keys `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_CURRENT_CONFIG`. High-value targets: `HKLM\SOFTWARE` for installed-software configuration, the `ProfileList` key under HKLM for per-SID user profiles, and HKU for per-user hives. The material stresses that much of the registry is readable by basic users even though portions require administrative privilege.
9. **Aggregate and hand off.** Combine all domains into one survey report. The report drives the next action: evasion selection against the detected AV/EDR product, injection target selection from the process list, payload adjustment to service-pack level, or abort if the host profiles as a research environment.

## OS Internals Context

`SYSTEM_INFO` is not a version blob; its fields are load-bearing for later implant operations, which is why the material walks them individually. `dwPageSize` is the value `VirtualAlloc` aligns to; `dwAllocationGranularity` governs reservation alignment; `lpMinimumApplicationAddress`/`lpMaximumApplicationAddress` bound the usable user-mode address space; `dwActiveProcessorMask` encodes configured processors as bits 0–31; `dwNumberOfProcessors` feeds `GetLogicalProcessorInformation`. Reading this struct first tells the implant what memory and threading behavior the machine will tolerate before any allocation strategy is chosen.

`KUSER_SHARED_DATA` is the undocumented alternative for version queries: a kernel-maintained page shared read-only into every user-mode process at a fixed address (0x7FFE0000), exposing fields including `NtMajorVersion`/`NtMinorVersion` and `NtBuildNumber` without any API call that an EDR hook would observe. The material presents it as the stealth counterweight to the documented version APIs.

On the process side, the kernel represents each process as an EPROCESS block in system address space; every user-mode enumeration API is a different projection over that list. `CreateToolhelp32Snapshot` copies a point-in-time view — hence the documented lag. `WTSEnumerateProcessesEx` returns a `WTS_PROCESS_INFO_EXA` array carrying per-process `NumberOfThreads`, `HandleCount`, `PagefileUsage`, `PeakPagefileUsage`, `WorkingSetSize`, `PeakWorkingSetSize`, `UserTime`, and `KernelTime` — materially richer than `EnumProcesses`, and the remote capability flows through the terminal-services RPC channel opened by the server handle. `NtQuerySystemInformation(SystemProcessInformation)` bypasses the Win32 projection entirely and returns the native linked list, which is why the material flags it as both the most detailed and the riskiest of the four.

The registry survey rests on hive mechanics the material details: HKCR is a merged view of `HKCU\SOFTWARE\Classes` and `HKLM\SOFTWARE\Classes` (file associations, COM registrations, UAC virtualization); HKCU is a link to the user's subkey under HKU, backed by `\Users\<username>\Ntuser.dat`; HKLM holds `BCD00000000` (boot entries), `COMPONENTS` (Component Based Servicing), `SAM` (account passwords), `SECURITY`, and `SOFTWARE`; HKCC is a compatibility link to `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current`. `HKEY_PERFORMANCE_DATA` is not stored in any hive — it is provider-supplied, invisible to regedit, reachable only through `RegQueryValueEx` or preferably Pdh.dll. Of the twelve registry value types, three dominate: `REG_DWORD`, `REG_BINARY`, `REG_SZ`. The registry is read at four critical times — initial boot, kernel boot, logon, and application startup — which is why it doubles as a persistence map.

WUA is a COM subsystem (Wuaapi.h, Wuguid.lib, introduced with Windows XP) whose object chain — session, searcher, search result, update collection — reports both installed and available updates against Windows Update or WSUS, giving a patch picture independent of the QFE class.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (SEC670 Labs 2.1–2.5: OS Info, ProcEnum, CreateToolhelp, WTSEnum, FileFinder).

An implementation would be a single survey module that walks the nine-step mechanism above: a `SystemInfo` struct populated from `GetNativeSystemInfo`/`SYSTEM_INFO` plus a `KUSER_SHARED_DATA` read; a hotfix list from a WMI QFE query or the WUA COM chain; a process list behind a strategy enum selecting `CreateToolhelp32Snapshot`, `WTSEnumerateProcessesEx`, or `NtQuerySystemInformation`; a recursive `FindFirstFile`/`FindNextFile` walker over the three install roots with a research-VM indicator list; NetAPI calls for users and Administrators membership; SCM enumeration for services with optional SDDL retrieval; the IP Helper ladder for adapter configuration; and a registry pass over ProfileList and `HKLM\SOFTWARE`. Results serialize into one report consumed by technique-selection logic.

Two adjacent client capabilities exist but do not constitute this technique. `client_rust/src/sysinfo_collect.rs` gathers hostname, OS, CPU, RAM, disk, and adapters for the HELLO message (documented under T-023) — a fixed HELLO payload, not a survey. `client_rust/src/byakugan.rs` implements ARP scan, port scan, banner grab, passive discovery, and AD enumeration, but does so by spawning system commands (`arp -a`, `ipconfig /all`, `net user /domain`, `nltest`) and parsing stdout rather than calling the Win32/NT/WTS/IP-Helper API surface this card documents; its AD enumeration covers the domain-user slice only, as a network reconnaissance engine (T-023, T-022).

## Why It Matters

The vault distributes reconnaissance across T-023 (sysinfo, Byakugan), T-020 (Kaguya LOtL inventory and EDR detection), and T-022 (network reconnaissance) with no card documenting the survey as a coordinated first-phase action. SEC670 devotes an entire book to it because survey output is the input to every subsequent decision: which evasion techniques in T-016 apply against the detected product, which process in the enumerated list becomes the T-007 injection target, whether the patch level supports the chosen exploit, and whether the host is a research VM that warrants abort. The card also preserves the per-API trade-off catalog — snapshot lag, hookability, remote-versus-local, documented-versus-undocumented — that the operator weighs when assembling recon tradecraft, which no existing card captures.

## Detection Considerations

The material frames detection as an API-selection trade-off rather than a telemetry catalog. Documented Win32 enumeration APIs are described as "safe and reliable" but reside at the user-mode layer where EDRs most commonly install hooks; the undocumented `NtQuerySystemInformation` path is presented as stealthier precisely because it avoids the most-instrumented wrappers, at the cost of relying on an unofficially documented `SYSTEM_INFORMATION_CLASS`. Snapshot-based enumeration (`CreateToolhelp32Snapshot`) carries an operational-fidelity risk — missing newly created processes — rather than a detection risk. Remote use of `WTSEnumerateProcessesEx` requires specific registry keys on the target, a configuration artifact. The material's patch-awareness guidance is itself detection-driven: attempting an exploit against a hotfixed build risks crashes and exposure, so the survey reduces self-inflicted detection. Training material does not enumerate specific ETW providers, Sysmon event IDs, or kernel-callback telemetry for the survey API surface.

## Related Techniques

- **T-023 Client Capabilities Suite** — sysinfo_collect and Byakugan currently carry fragments of the survey as client features; this card elevates the survey to the coordinated phase those fragments serve.
- **T-020 Anti-Analysis Suite** — Kaguya's LOtL inventory and security-product detection via `NtQuerySystemInformation` is a survey consumer, and the anti-VM checks parallel the research-VM indicators the survey's software inventory surfaces.
- **T-016 EDR Evasion Suite** — survey identification of the resident AV/EDR product gates selection among AMSI bypass, ETW muffling, NTDLL unhooking, and Block-DLL policy.
- **T-022 Network and Protocol Suite** — Byakugan's ARP/port-scan/AD-enum output complements the local NIC and adapter configuration gathered through the IP Helper ladder.
- **T-007 Pool Party Injection** — the enumerated process list is the target-selection input for injection; service and process ownership data determines which processes are viable hosts.

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part2.md, atlas-recon-part4.md, atlas-recon-part5.md, atlas-recon-part7.md
- MITRE ATT&CK: T1082 (System Information Discovery) — https://attack.mitre.org/techniques/T1082/; secondaries T1057, T1518.001, T1087, T1016, T1007, T1012
- LGTM notes: lgtm:host-survey-script-primitive, lgtm:proposed-recon-survey-card, lgtm:proposed-host-survey-card, lgtm:proposed-host-survey-recon-card, lgtm:recon-enumeration-api-surface
- Public references: SANS SEC670 "Red Teaming Tools: Developing Custom Tools for Windows," Book 2 "Getting to Know Your Target" (Section 2, Labs 2.1–2.5)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Adjacent capabilities: `client_rust/src/sysinfo_collect.rs` (HELLO-payload system info, T-023) and `client_rust/src/byakugan.rs` (network reconnaissance via spawned system commands, T-023/T-022) — neither implements the unified API-surface host survey this card documents.