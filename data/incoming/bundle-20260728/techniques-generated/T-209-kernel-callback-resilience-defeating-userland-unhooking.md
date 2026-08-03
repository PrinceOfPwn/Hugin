---
id: T-209
title: "Kernel-Callback Resilience Defeating Userland Unhooking"
category: edr-evasion
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: kernel-callback-resilience-metadata
member_notes: ["lgtm:kernel-callback-resilience-metadata"]
---

## Summary
This technique covers Kernel-Callback Resilience Defeating Userland Unhooking, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the cross-cutting limitation of T-016 userland NTDLL unhooking: kernel callbacks continue to observe operations regardless of userland hook state. The relevant callback primitives: PsSetCreateProcessNotifyRoutine (process create/exit, via PsSetCreateProcessNotifyRoutineEx2 with extended info), PsSetLoadImageNotifyRoutine (image load — fires for every PE mapped, including ntdll itself), ObRegisterCallbacks (object handle pre/post-operation — filters on OB_PRE_OPERATION_HANDLER for process/thread/file types), CmRegisterCallback (registry — fires on NtSetValueKey, NtCreateKey, NtDeleteKey), and ExNotifyCallback (object directory). The operational consequence: any T-007 process injection or T-013 thread hijack that triggers a kernel-observable transition (process creation, image load, thread creation via NtCreateThreadEx) will be observed. Evasion responses: direct thread creation via existing thread CONTEXT hijack (avoids NtCreateThreadEx trigger), map-and-execute without image load (PIC shellcode rather than DLL reflect), or kernel-mode compromise (driver unload / callback deregistration).


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// PsSetCreateProcessNotifyRoutineEx2 + PsSetLoadImageNotifyRoutine + ObRegisterCallbacks(OB_PRE_OPERATION_HANDLER) — kernel callbacks fire after T-016 unhook
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:kernel-callback-resilience-metadata: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-007: Relates conceptually based on evidence.
- T-013: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on Kernel-Callback Resilience Defeating Userland Unhooking
