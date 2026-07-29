---
id: T-15815
title: "Import Address Table (IAT) Hooking Primitive"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "iat-hooking-primitive"
member_notes: ["lgtm:iat-hooking-as-technique"]
---

## Summary
This card covers the research gap identified as Import Address Table (IAT) Hooking Primitive. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **Import Address Table (IAT) Hooking Primitive** represents a sophisticated vector that leverages low-level system structures. Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.

The primary mechanism relies on invoking `DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `iat-hooking-primitive`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of Import Address Table (IAT) Hooking Primitive
NTSTATUS status = DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific iat-hooking-primitive constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:iat-hooking-as-technique: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **Import Address Table (IAT) Hooking Primitive** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `iat-hooking-primitive` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References

- Microsoft Documentation on DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of Import Address Table (IAT) Hooking Primitive and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to iat-hooking-primitive.
