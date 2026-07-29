---
id: T-1583
title: "x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "x64-abi-syscall-stub-construction"
member_notes: ["lgtm:x64-calling-convention-stub-constraint", "lgtm:x64-abi-syscall-stub-construction", "lgtm:cross-source-convergence-shadow-store-and-rop"]
---

## Summary
This card covers the research gap identified as x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs** represents a sophisticated vector that leverages low-level system structures. Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.

The primary mechanism relies on invoking `32-byte` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `x64-abi-syscall-stub-construction`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs
NTSTATUS status = 32-byte(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific x64-abi-syscall-stub-construction constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:x64-calling-convention-stub-constraint: Identified gap in the research corpus.
- lgtm:x64-abi-syscall-stub-construction: Identified gap in the research corpus.
- lgtm:cross-source-convergence-shadow-store-and-rop: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `32-byte` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `x64-abi-syscall-stub-construction` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-003: Related technique identified in gap analysis.
- T-005: Related technique identified in gap analysis.
- T-006: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on 32-byte: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to x64-abi-syscall-stub-construction.
