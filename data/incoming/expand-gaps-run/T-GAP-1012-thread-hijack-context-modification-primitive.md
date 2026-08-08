---
id: T-GAP-1012
title: "Thread Hijack Requires CONTEXT Modification"
tier: "A"
category: "process-injection"
---

# Thread Hijack Requires CONTEXT Modification

## Description
Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


## Rationale
Single convergence note formulating the foundational thread-hijack primitive (CONTEXT.Rip manipulation) referenced across SEC670, MalDev Academy, and CRTO.

## References
- lgtm:cross-source-convergence-thread-context-hijack-requirement
