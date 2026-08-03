---
id: T-235
title: "RegNotifyChangeKey Resilience Monitor Primitive"
category: persistence
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: regnotify-change-key-resilience-monitor
member_notes: ["lgtm:regnotify-resilience-monitor-primitive"]
---

## Summary
This technique covers RegNotifyChangeKey Resilience Monitor Primitive, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
RegNotifyChangeKey allows a thread to receive asynchronous notification when a registry key or its subkeys / values change, with filters REG_NOTIFY_CHANGE_NAME (0x1), REG_NOTIFY_CHANGE_LAST_SET (0x2), REG_NOTIFY_CHANGE_ATTRIBUTES (0x4), REG_NOTIFY_CHANGE_SECURITY (0x8), and the REG_NOTIFY_THREAD_APCWOW64 flag for cross-architecture APC delivery. SEC670 uses this as a watchdog primitive: a worker thread blocks in RegNotifyChangeKey on the persistence key, and on notification rewrites the value or signals an upper layer to re-establish persistence. The primitive also serves for AV-install detection by watching HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall or HKLM\SOFTWARE\Microsoft\Windows Defender for new subkeys. The vault's T-017 PhantomPersist layer mentions a resilience monitor but does not document the RegNotify API surface or the APC delivery mechanism.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// RegNotifyChangeKey with REG_NOTIFY_CHANGE_LAST_SET (0x2) filter and REG_NOTIFY_THREAD_APCWOW64 flag for async APC delivery to a wait thread via NtNotifyChangeKey
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:regnotify-resilience-monitor-primitive: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-017: Relates conceptually based on evidence.
- T-020: Relates conceptually based on evidence.

## References
- Internal vault documentation on RegNotifyChangeKey Resilience Monitor Primitive
