---
id: T-1587
title: "Thread Hijack Requires CONTEXT Modification"
category: process-injection
tier: A
tags: [thread, hijack, context, modification]
mitre: []
origin: glm-expand-cluster
source_cluster: thread-hijack-context-modification-primitive
member_notes: ['lgtm:cross-source-convergence-thread-context-hijack-requirement']
---

## Summary
Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.

## Technical Deep Dive
Single convergence note formulating the foundational thread-hijack primitive (CONTEXT.Rip manipulation) referenced across SEC670, MalDev Academy, and CRTO.

Key technical anchor: NtGetContextThread / NtSetContextThread on CONTEXT.Rip (offset 0xF8 on x64) and Rsp (offset 0x98) for stack pivot

## Evidence
- lgtm:cross-source-convergence-thread-context-hijack-requirement: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-013 - related to Thread Hijack Requires CONTEXT Modification

## References
- Refer to internal research note thread-hijack-context-modification-primitive for preliminary data.
