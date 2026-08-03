---
id: T-226
title: "Thread Hijack Requires CONTEXT Modification"
category: process-injection
tier: A
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: thread-hijack-context-modification-primitive
member_notes: ["lgtm:cross-source-convergence-thread-context-hijack-requirement"]
---

## Summary
This technique covers Thread Hijack Requires CONTEXT Modification, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// NtGetContextThread / NtSetContextThread on CONTEXT.Rip (offset 0xF8 on x64) and Rsp (offset 0x98) for stack pivot
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:cross-source-convergence-thread-context-hijack-requirement: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-013: Relates conceptually based on evidence.

## References
- Internal vault documentation on Thread Hijack Requires CONTEXT Modification
