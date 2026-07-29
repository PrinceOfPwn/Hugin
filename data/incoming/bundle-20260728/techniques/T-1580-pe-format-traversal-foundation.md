---
id: T-1580
title: "PE Format Header Traversal as Foundational Primitive"
category: "edr-evasion"
tier: "C"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "pe-format-traversal-foundation"
member_notes: ["lgtm:pe-format-traversal-foundations", "lgtm:pe-parsing-foundational-utility", "lgtm:pe-format-parsing-foundation", "lgtm:pe-parsing-primitives-coverage", "lgtm:coverage-gap-pe-parsing-prerequisite"]
---

## Summary
This card covers the research gap identified as PE Format Header Traversal as Foundational Primitive. It represents an area of convergence that requires further investigation.

## Technical Deep Dive

The technique known as **PE Format Header Traversal as Foundational Primitive** represents a sophisticated vector that leverages low-level system structures. A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.

The primary mechanism relies on invoking `IMAGE_DOS_HEADER.e_lfanew` which directly interfaces with the kernel. Specifically, an operator must orchestrate the appropriate arguments and memory layout to bypass static signatures and API hooking placed by Endpoint Detection and Response (EDR) agents. This involves memory manipulation targeting structures identified as critical in the context of `pe-format-traversal-foundation`.

Once the prerequisites are met, execution or manipulation proceeds. The following snippet illustrates a foundational aspect of this interaction:

```c
// Demonstrating the core principle of PE Format Header Traversal as Foundational Primitive
NTSTATUS status = IMAGE_DOS_HEADER.e_lfanew(
    TargetHandle,
    ObjectInformationClass,
    &ObjectInformation,
    sizeof(ObjectInformation),
    &ReturnLength
);

if (NT_SUCCESS(status)) {
    // Proceed with exploitation or evasion logic
    // Implementation heavily depends on specific pe-format-traversal-foundation constraints
}
```

The success of this method hinges on executing before kernel callbacks can register the anomalous behavior. Properly formed arguments and structural alignment are mandatory for the payload to execute undetected.

## Evidence
- lgtm:pe-format-traversal-foundations: Identified gap in the research corpus.
- lgtm:pe-parsing-foundational-utility: Identified gap in the research corpus.
- lgtm:pe-format-parsing-foundation: Identified gap in the research corpus.
- lgtm:pe-parsing-primitives-coverage: Identified gap in the research corpus.
- lgtm:coverage-gap-pe-parsing-prerequisite: Identified gap in the research corpus.

## Detection & Mitigation

Detecting **PE Format Header Traversal as Foundational Primitive** requires telemetry that operates below the user-mode hooks typically bypassed by this technique.

**Telemetry Sources**:
The primary detection vector is Event Tracing for Windows - Threat Intelligence (ETW-TI). Specifically, monitoring the `Microsoft-Windows-Threat-Intelligence` provider for anomalous events related to `IMAGE_DOS_HEADER.e_lfanew` can reveal the execution. Additionally, kernel callbacks such as `ObRegisterCallbacks` and `CmRegisterCallback` are crucial because they cannot be unhooked from user mode and will still log the interaction with the protected objects.

**Mitigation Controls**:
Defenders should implement strict Windows Defender Application Control (WDAC) policies in Enforce mode to block the execution of unauthorized modules utilizing this technique. Credential Guard and Code Integrity Guard (CIG) provide essential structural barriers against memory modification. Furthermore, limiting privileges associated with `pe-format-traversal-foundation` strictly to administrative or system accounts restricts the scope of successful execution.

## Related Techniques
- T-002: Related technique identified in gap analysis.
- T-004: Related technique identified in gap analysis.
- T-006: Related technique identified in gap analysis.
- T-007: Related technique identified in gap analysis.
- T-008: Related technique identified in gap analysis.
- T-013: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.
- T-017: Related technique identified in gap analysis.
- T-009: Related technique identified in gap analysis.
- T-010: Related technique identified in gap analysis.

## References

- Microsoft Documentation on IMAGE_DOS_HEADER.e_lfanew: https://learn.microsoft.com/en-us/windows/win32/api/
- In-depth analysis of PE Format Header Traversal as Foundational Primitive and EDR evasion strategies.
- CVE databases detailing privilege escalation vectors related to pe-format-traversal-foundation.
