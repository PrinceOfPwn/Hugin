---
id: T-15812
title: "Thread Hijack Requires CONTEXT Modification"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "thread-hijack-context-modification-primitive"
member_notes: ["lgtm:cross-source-convergence-thread-context-hijack-requirement"]
---

## Summary
This card covers the research gap identified as Thread Hijack Requires CONTEXT Modification. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.


## Evidence
- lgtm:cross-source-convergence-thread-context-hijack-requirement: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-013: Related technique identified in gap analysis.

## References
- To be added.
