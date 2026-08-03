---
id: T-210
title: "Persistence Vector Catalog Gap (Run, AppInit, AppCert, IFEO, WMI, PortMon, Weak Svc ACL)"
category: persistence
tier: S
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: persistence-vector-suite-gap
member_notes: ["lgtm:gap-run-key-persistence", "lgtm:gap-appinit-appcert-ifeo-wmi-persistence", "lgtm:persistence-suite-coverage-gap", "lgtm:cross-source-persistence-tradecraft-convergence", "lgtm:weak-service-acl-persistence"]
---

## Summary
This technique covers Persistence Vector Catalog Gap (Run, AppInit, AppCert, IFEO, WMI, PortMon, Weak Svc ACL), focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
T-017 documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but lacks Run / RunOnce (HKLM and HKCU\Software\Microsoft\Windows\CurrentVersion\Run), AppInit_DLLs (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs loaded into every User32-linked process), AppCert (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls), IFEO Debugger values (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger, plus SilentProcessExit monitor), WMI Event Subscriptions (__EventFilter + __EventConsumer + __FilterToConsumerBinding in root\subscription namespace), Port Monitors (HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver), and weak service ACL replacement via sc.exe sdset combined with binary path overwrite. The convergence pattern: each abuses an admin or debugging feature by redirecting a code path the OS executes on a scheduled or trigger-based event. The vault's T-017 currently lists only five layers and should be expanded to catalog at least seven more vectors with explicit trigger, detection surface, and required privilege per vector.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// IFEO Debugger value at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>\Debugger + WMI __EventFilter / __EventConsumer / __FilterToConsumerBinding binding in root\subscription namespace
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:gap-run-key-persistence: Contributed insights into the specific mechanism.
- Note lgtm:gap-appinit-appcert-ifeo-wmi-persistence: Contributed insights into the specific mechanism.
- Note lgtm:persistence-suite-coverage-gap: Contributed insights into the specific mechanism.
- Note lgtm:cross-source-persistence-tradecraft-convergence: Contributed insights into the specific mechanism.
- Note lgtm:weak-service-acl-persistence: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.

## References
- Internal vault documentation on Persistence Vector Catalog Gap (Run, AppInit, AppCert, IFEO, WMI, PortMon, Weak Svc ACL)
