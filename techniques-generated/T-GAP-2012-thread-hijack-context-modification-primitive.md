---
id: T-GAP-2012
title: "Thread Hijack Requires CONTEXT Modification"
category: "process-injection"
tier: "A"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: thread-hijack-context-modification-primitive
member_notes: ['lgtm:cross-source-convergence-thread-context-hijack-requirement']
---

## Summary
Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Single convergence note formulating the foundational thread-hijack primitive (CONTEXT.Rip manipulation) referenced across SEC670, MalDev Academy, and CRTO.

## Evidence
- lgtm:cross-source-convergence-thread-context-hijack-requirement: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
