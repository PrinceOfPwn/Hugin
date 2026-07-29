---
id: T-035
name: Port Monitor Persistence via Print Spooler
category: persistence
tier: A
crate: none
source_file: none
mitre: T1547.010
mitre_secondary: [T1112]
tags: [persistence, port-monitor, print-spooler, spoolsv, addmonitor, monitor-info-2, system-context, registry-persistence, service-start-trigger]
origin: atlas-synthesis
member_notes: ['lgtm:port-monitor-print-spooler-persistence', 'lgtm:proposed-port-monitor-persistence', 'lgtm:proposed-port-monitor-persistence-card', 'lgtm:port-monitor-addmonitor-persistence', 'lgtm:port-monitor-persistence', 'lgtm:port-monitor-persistence-card']
---

# Port Monitor (AddMonitor) Persistence via Print Spooler — SYSTEM-Context DLL Load at Spooler Startup

## Summary

Port Monitor persistence registers an attacker-controlled DLL as a print port monitor so that the Print Spooler service (`spoolsv.exe`) loads it with NT AUTHORITY\SYSTEM privileges every time the service starts. The installation primitive is either a direct registry write under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` or a single call to the `AddMonitor` API with a populated `MONITOR_INFO_2` structure. Because the spooler is an automatic-start service that re-enumerates its registered monitors at every initialization, the DLL executes at boot, on service restart, and after spooler crash recovery, all inside a legitimate Microsoft process in session 0. The primary detection surface named in the training material is Sysmon Event ID 7 (Image Loaded) observing `spoolsv.exe` loading a DLL from outside the driver store.

## Mechanism

1. The operator obtains local administrator or SYSTEM privileges on the target. The material is explicit that the method requires local admin, because installation writes under HKLM and registers a component the spooler will trust.

2. The operator compiles the monitor DLL for the target architecture. The `AddMonitor` unit in SEC670 documents that the API fails if the monitor does not match the system architecture: the `pEnvironment` field must carry the correct environment string (`"Windows x64"` on 64-bit systems) or the call fails outright.

3. The DLL is placed on disk at a path readable by the spooler service, conventionally under `System32`. The file must remain present for the persistence to survive.

4. Installation proceeds by one of the two methods the training material documents:
   - **Method one — registry:** create a subkey `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>` and set its `Driver` value to the monitor DLL file name. The material presents this as the manual method performed through Registry Editor or `reg.exe`.
   - **Method two — programmatic:** populate a `MONITOR_INFO_2` structure — `pName` (monitor name), `pEnvironment` (`"Windows x64"`), `pDLLName` (DLL path) — and call `AddMonitor(NULL, 2, (LPBYTE)&monitorInfo)`. The API has a `BOOL` return type and writes the same registry state as the manual method. SEC670's review questions deliberately contrast `AddMonitor` against the decoy names `CreateNewMonitor` and `AddNewMonitor`; `AddMonitor` is the correct API.

5. The monitor lies dormant until the spooler next initializes. Activation occurs on reboot, on an explicit spooler stop/start, or on service recovery after a crash.

6. At service startup, `spoolsv.exe` enumerates the `Monitors` registry key and loads each monitor's `Driver` DLL through the standard image loader. `DllMain(DLL_PROCESS_ATTACH)` executes, followed by the spooler calling the monitor's initialization export.

7. Attacker code now runs as NT AUTHORITY\SYSTEM in session 0, before any user logon, and re-executes on every subsequent spooler start until the registry key and DLL are removed.

## OS Internals Context

The Print Spooler architecture defines two monitor types: language monitors and port monitors. The material describes a port monitor as a bridge from user mode to kernel mode: the user-mode side is hosted inside `spoolsv.exe` and communicates with a port driver resident in the kernel, bridging the physical printer connection to the print queue the user sees. This legitimate role is what makes the load point credible — the spooler is designed to load third-party monitor DLLs from a registered list.

`spoolsv.exe` is the Print Spooler service, a standalone service process running as LocalSystem with automatic startup. The atlas notes describe it as having auto-restart semantics, which matters operationally: even a spooler crash becomes a re-execution opportunity rather than a persistence failure, because service recovery reloads all registered monitors.

The persistence anchor is registry-backed enumeration. The `Monitors` key lives in the SYSTEM hive and survives reboots independently of any service configuration; the spooler reads it during initialization and `LoadLibrary`s each subkey's `Driver` DLL. The DLL is mapped as `MEM_IMAGE` and remains resident for the lifetime of the service, which is why the material's named detection is an image-load event rather than a process-creation event.

The `MONITOR_INFO_2` structure is the version-2 monitor descriptor consumed by `AddMonitor` when its `Level` parameter is 2. Its three fields — `pName`, `pEnvironment`, `pDLLName` — map directly onto the registry state created under the monitor's subkey. The architecture enforcement on `pEnvironment` is a hard contract: a mismatch between the DLL's bitness, the environment string, and the host causes the install to fail rather than degrade.

Execution context differs from userland persistence in three concrete ways. First, the code runs in session 0 inside a service process, so no interactive logon is ever required — unlike HKCU-based mechanisms that fire only when a specific user logs in. Second, the host process is a Microsoft-signed, expected system binary, so there is no new service entry in the Service Control Manager database and no suspicious service binary path; the only module-level artifact is the loaded monitor DLL itself. Third, the privilege level is SYSTEM rather than the installing user's context, so the mechanism both persists and escalates in a single primitive.

The monitor DLL interface expects a defined export set that the spooler invokes after load; the SEC670 "Port Monitor Source Code" module walks through a reference implementation of that DLL. For persistence purposes the payload can execute from `DllMain` at load time, which runs before the spooler calls any monitor-specific export.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C.

Three Rust files were supplied as keyword-grep candidates and were verified not to implement this technique. `client_rust/src/browser_hook.rs` implements Chromium extension sideloading with its own four-layer persistence (shortcut patching, Run key, scheduled task, protocol handler) — none of it touches `AddMonitor`, `winspool.drv`, or `Print\Monitors`. `client_rust/src/commands.rs` is command dispatch for the client; its persistence-adjacent handlers drive the browser hook only. `dark_crystal/crowd/src/main.rs` wires the T-017 Phase 6 persistence chain (COM hijack, NTFS EA, scheduled task, TLS callback, resilience monitor) and contains no port-monitor code.

An implementation would consist of two binaries. The installer resolves `AddMonitorW` from `winspool.drv` (or writes the `Monitors\<name>\Driver` value directly via `NtSetValueKey` through the vault's RecycledGate dispatcher for syscall consistency), fills a `MONITOR_INFO_2W` with `pEnvironment = "Windows x64"`, copies the monitor DLL into `System32`, and optionally triggers a spooler restart for immediate activation. The monitor DLL builds as a `cdylib` whose `DllMain` spawns the payload on `DLL_PROCESS_ATTACH` without blocking the spooler's loader lock — typically by creating a detached thread or scheduling work and returning from the loader-critical path quickly, since a hang inside `DllMain` stalls spooler initialization.

## Why It Matters

This technique earns a standalone card because it shares almost nothing with the five layers of T-017 beyond the word "persistence." The trigger is a service-start enumeration inside `spoolsv.exe`, not a user logon (COM hijack), a filesystem metadata read (NTFS EA), a task scheduler event, a PE loader detail (TLS callback), or a shutdown intercept (PhantomPersist). The install primitive — `AddMonitor` with `MONITOR_INFO_2`, or the equivalent registry write — and the SYSTEM/session-0 execution context are likewise disjoint from every T-017 layer, as is the detection surface of Sysmon Event 7 on the spooler. The mechanism carries historical weight: the atlas notes identify it as the same persistence vector used by Stuxnet, and the broader spooler abuse surface has the PrintNightmare lineage behind it, which shapes both its credibility as a load point and the defender attention it attracts. The tradeoff is explicit in the material: the method requires local admin up front and returns SYSTEM-context, reboot-surviving execution inside a core Windows service.

## Detection Considerations

**Telemetry sources:** The training material names Sysmon Event ID 7 (Image Loaded) as the primary surface — specifically `spoolsv.exe` loading a DLL that does not originate from the driver store or expected monitor locations. The registry write under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` is the second observable, visible to registry telemetry at install time regardless of which installation method is used, since `AddMonitor` produces the same key and `Driver` value as the manual method. A spooler service restart performed to trigger immediate activation is itself an operational artifact visible in service-control telemetry.

**Bypass options:** The training material does not discuss bypass options for this technique.

**Residual artifacts:** The registry subkey `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>` with its `Driver` value persists independently of the spooler's state and survives reboot until removed. The monitor DLL remains on disk, conventionally under `System32`. While active, the DLL appears as a loaded module inside the `spoolsv.exe` address space. Cleanup requires removing the registry key (the documented API counterpart for removal is `DeleteMonitor`) and either restarting the spooler or rebooting to unload the mapped DLL, and the material's notes flag cleanup tradeoffs as an operational consideration of this vector.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — T-017 composes COM hijack, NTFS EA, scheduled task, TLS callback, and PhantomPersist layers under a 30-minute resilience monitor. Port Monitor persistence is the service-hosted, SYSTEM-context counterpart that T-017 does not cover; the two are complementary rather than overlapping, and a port monitor layer could in principle be enrolled under the same resilience-monitoring model.

## References

- Atlas material: atlas-binary-analysis-part5.md (unit 18 — AddMonitor / _MONITOR_INFO_2), atlas-exploit-dev-part22.md (units 19–20 — Port Monitor source code module), atlas-exploit-dev-part24.md (unit 25 — Port Monitor source code review, Book 4), atlas-exploit-dev-part4.md (unit 31 — AddMonitor API contract and architecture constraint), atlas-labs-part1.md (unit 35 — AddMonitor vs. CreateNewMonitor/AddNewMonitor), atlas-post-exploit-part12.md (units 24–29 — port monitor definition, registry method, permissions, module summary)
- MITRE ATT&CK: T1547.010 — Boot or Logon Autostart Execution: Port Monitors (https://attack.mitre.org/techniques/T1547/010/)
- LGTM notes: lgtm:port-monitor-print-spooler-persistence, lgtm:proposed-port-monitor-persistence, lgtm:proposed-port-monitor-persistence-card, lgtm:port-monitor-addmonitor-persistence, lgtm:port-monitor-persistence, lgtm:port-monitor-persistence-card
- Public references: SANS SEC670 Book 4 "Persistence: Die Another Day" (port monitor module, pp. 68–77, the source material for this card); Stuxnet's use of port monitor persistence as named in the atlas notes.

## Source Reference

No current implementation. The three Rust files provided (`client_rust/src/browser_hook.rs`, `client_rust/src/commands.rs`, `dark_crystal/crowd/src/main.rs`) matched persistence keywords on grep but were verified to implement browser-extension persistence and the T-017 persistence chain respectively — none implement `AddMonitor` or `Print\Monitors` registration. See atlas material and the MITRE reference for public tooling.