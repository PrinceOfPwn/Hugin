---
id: T-1585
title: "Heaven's Gate 32→64-bit WOW64 Syscall Bridge"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "heavens-gate-wow64-bridge"
member_notes: ["lgtm:vault-gap-heavens-gate"]
---

## Summary
This card covers the research gap identified as Heaven's Gate 32→64-bit WOW64 Syscall Bridge. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Heaven's Gate 32→64-bit WOW64 Syscall Bridge** represents a sophisticated vector that leverages low-level system structures. Documents the Heaven's Gate technique: a 32-bit Wow64 process jumps to 64-bit code via ntdll.Wow64Transition (the 0x33 segment selector FAR jump into the 64-bit code segment) and wow64cpu.dll's TurboDispatch, allowing direct 64-bit syscalls that bypass 32-bit ntdll hooks. The 32-bit process must construct a 64-bit syscall stub in memory, switch CS to 0x33 via a far return with a manually crafted frame, issue the syscall, and return to 0x23 (32-bit CS). Operationally valuable because 32-bit EDR hooks cannot observe the transition; superseded in part by SysWhispers3 WoW64 stubs and the modern Hells Gate-style SSN extraction.

The primary mechanism relies on invoking `Far` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `heavens-gate-wow64-bridge`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Heaven's Gate 32→64-bit WOW64 Syscall Bridge
NTSTATUS status = Far(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific heavens-gate-wow64-bridge constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:vault-gap-heavens-gate: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Heaven's Gate 32→64-bit WOW64 Syscall Bridge** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `Far` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `heavens-gate-wow64-bridge` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.

## References

- Microsoft Documentation on Far: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Heaven's Gate 32→64-bit WOW64 Syscall Bridge and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to heavens-gate-wow64-bridge.
