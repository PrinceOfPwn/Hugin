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

The technique known as **Thread Hijack Requires CONTEXT Modification** represents a sophisticated vector that leverages low-level system structures. Documents the foundational thread-hijack primitive: hijacking execution requires NtGetContextThread / NtSetContextThread to modify the thread's CONTEXT record (specifically Rip on x64, Rsp for stack pivot, and segment registers for WOW64 transitions). Modifying thread priority (NtSetInformationThread(ThreadPriority)) or thread state (NtSetEvent / NtAlertThread) is not hijacking — these do not redirect the instruction pointer. The canonical sequence: suspend target thread via NtSuspendThread, NtGetContextThread to capture CONTEXT, overwrite Rip with the payload address, optionally Rbp/Rsp for stack pivot, NtSetContextThread to apply, then NtResumeThread. Pairs with T-013's waiting_thread_hijack_ref.rs but elevates the primitive to its own card so the CONTEXT modification step is documented independently.

The primary mechanism relies on invoking `NtGetContextThread` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `thread-hijack-context-modification-primitive`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Thread Hijack Requires CONTEXT Modification
NTSTATUS status = NtGetContextThread(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific thread-hijack-context-modification-primitive constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:cross-source-convergence-thread-context-hijack-requirement: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Thread Hijack Requires CONTEXT Modification** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `NtGetContextThread` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `thread-hijack-context-modification-primitive` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-013: Related technique identified in gap analysis.

## References

- Microsoft Documentation on NtGetContextThread: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Thread Hijack Requires CONTEXT Modification and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to thread-hijack-context-modification-primitive.
