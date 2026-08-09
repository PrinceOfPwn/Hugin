---
id: T-212
title: "Thread Hijack Requires CONTEXT Modification"
category: process-injection
tier: A
tags: ['research-gap', 'thread-hijack-context-modification-primitive']
mitre: []
origin: glm-expand-cluster
source_cluster: thread-hijack-context-modification-primitive
member_notes: ['lgtm:cross-source-convergence-thread-context-hijack-requirement']
---

## Summary

This technique card addresses the research gap identified in cluster `thread-hijack-context-modification-primitive`.
Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


## Technical Deep Dive

Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


Technical anchor points:
```
NtGetContextThread / NtSetContextThread on CONTEXT.Rip (offset 0xF8 on x64) and Rsp (offset 0x98) for stack pivot
```

## Evidence

- **lgtm:cross-source-convergence-thread-context-hijack-requirement**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-013: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `thread-hijack-context-modification-primitive`
- Generated as part of batch processing to fill identified research gaps.
