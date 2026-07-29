---
id: T-1584
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: "edr-evasion"
tier: "S"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "direct-vs-indirect-syscall-callstack-detection"
member_notes: ["lgtm:direct-vs-indirect-syscall-callstack-detection"]
---

## Summary
This card covers the research gap identified as Kernel Call-Stack Origin Check Defeating Direct Syscalls. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Kernel Call-Stack Origin Check Defeating Direct Syscalls** represents a sophisticated vector that leverages low-level system structures. Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.

The primary mechanism relies on invoking `Kernel` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `direct-vs-indirect-syscall-callstack-detection`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Kernel Call-Stack Origin Check Defeating Direct Syscalls
NTSTATUS status = Kernel(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific direct-vs-indirect-syscall-callstack-detection constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:direct-vs-indirect-syscall-callstack-detection: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Kernel Call-Stack Origin Check Defeating Direct Syscalls** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `Kernel` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `direct-vs-indirect-syscall-callstack-detection` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on Kernel: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Kernel Call-Stack Origin Check Defeating Direct Syscalls and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to direct-vs-indirect-syscall-callstack-detection.
