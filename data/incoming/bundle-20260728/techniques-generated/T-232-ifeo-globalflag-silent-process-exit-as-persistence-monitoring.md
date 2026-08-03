---
id: T-232
title: "IFEO GlobalFlag Silent Process Exit as Persistence / Monitoring"
category: persistence
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: ifeo-globalflag-silent-process-exit
member_notes: ["lgtm:ifeo-globalflag-silent-exit-persistence"]
---

## Summary
This technique covers IFEO GlobalFlag Silent Process Exit as Persistence / Monitoring, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the IFEO GlobalFlag Silent Process Exit mechanism: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>\.GlobalFlag set to FLG_MONITOR_SILENT_PROCESS_EXIT (0x2) triggers silent-process-exit monitoring, configurable via gflags.exe / sflg.exe (bundled with Windows SDK). When the monitored process exits, the Windows Error Reporting (WER) service invokes ReportingMode flags (LAUNCH_DEBUGGER = 0x1 for debugger persistence, NOTIFICATION = 0x2 for event log, LOCAL_DUMP = 0x4 for minidump) and StartDebugger processes specified under SilentProcessExit\ReportingMode and \MonitorProcess. Distinct from the traditional IFEO Debugger key (which spawns the debugger on process start) — Silent Process Exit triggers on process termination, providing postmortem persistence and exit monitoring. Configurable via gflags.exe -i <image> +sls.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// HKLM\...\Image File Execution Options\<image>\.GlobalFlag = 0x2 (FLG_MONITOR_SILENT_PROCESS_EXIT); SilentProcessExit\ReportingMode = 0x1 (LAUNCH_DEBUGGER) for persistence
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:ifeo-globalflag-silent-exit-persistence: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.

## References
- Internal vault documentation on IFEO GlobalFlag Silent Process Exit as Persistence / Monitoring
