---
id: T-1580
title: "PE Format Header Traversal as Foundational Primitive"
category: edr-evasion
tier: C
tags: [research-gap, procedural-generated]
mitre: [T1059]
origin: procedural-fallback
source_cluster: pe-format-traversal-foundation
member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']
---

## Summary
This technique covers the concepts surrounding PE Format Header Traversal as Foundational Primitive. It represents a synthesized view of the identified research gap `pe-format-traversal-foundation` and highlights key operational mechanisms for red team operators.

## Technical Deep Dive
A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.

At a deeper API level, this involves understanding the specific structures and offsets associated with pe-format-traversal-foundation. Operators must carefully navigate the constraints of the target environment to successfully execute the primitive.

```c
// Procedurally generated example code structure
NTSTATUS Status;
HANDLE hProcess;
OBJECT_ATTRIBUTES ObjectAttributes;
InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
// Execution logic here
```

## Evidence
- Synthesized from research gap cluster `pe-format-traversal-foundation`.
- Addresses foundational concepts needed for advanced evasion and persistence mechanisms.

## Detection & Mitigation
- **ETW Providers**: Monitor relevant ETW providers such as `Microsoft-Windows-Threat-Intelligence` for anomalous API calls.
- **Sysmon**: Configure Sysmon to log detailed process creation and API access events.
- **Preventive Controls**: Implement strict WDAC (Windows Defender Application Control) rules to restrict unsigned code execution.

## Related Techniques
- T-000 Placeholder Reference
- T-999 General Evasion Techniques

## References
- Internal Vault Reference: `pe-format-traversal-foundation`
- Synthesized Coverage Gap Documentation