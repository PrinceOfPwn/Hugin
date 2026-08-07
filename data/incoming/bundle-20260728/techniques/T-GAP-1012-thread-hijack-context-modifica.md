---
id: T-GAP-1012
name: "Thread Hijack Requires CONTEXT Modification"
category: process-injection
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:cross-source-convergence-thread-context-hijack-requirement"]
---

# Thread Hijack Requires CONTEXT Modification

## Summary

Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


## Mechanism

NtGetContextThread / NtSetContextThread on CONTEXT.Rip (offset 0xF8 on x64) and Rsp (offset 0x98) for stack pivot

## Rationale

Single convergence note formulating the foundational thread-hijack primitive (CONTEXT.Rip manipulation) referenced across SEC670, MalDev Academy, and CRTO.

## Related To

T-013
