---
id: T-3012
title: "Thread Hijack Requires CONTEXT Modification"
category: process-injection
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: thread-hijack-context-modification-primitive
member_notes: ['lgtm:cross-source-convergence-thread-context-hijack-requirement']
---
## Summary

This technique card covers Thread Hijack Requires CONTEXT Modification. It details mechanisms required to implement or understand thread-hijack-context-modification-primitive operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.



```c
// Example for Thread Hijack Requires CONTEXT Modification
// Implementation specific to thread-hijack-context-modification-primitive
void execute_thread_hijack_context_modification_primitive() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:cross-source-convergence-thread-context-hijack-requirement`: Referenced in internal atlas batches as a core component of thread-hijack-context-modification-primitive.

## Detection & Mitigation

Detecting this behavior requires deep visibility into API calls. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Thread Hijack Requires CONTEXT Modification
