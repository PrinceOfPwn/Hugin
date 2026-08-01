---
id: T-1575
title: "PE Format Header Traversal as Foundational Primitive"
category: discovery
tier: C
tags: [pe, format, traversal, foundation]
mitre: []
origin: glm-expand-cluster
source_cluster: pe-format-traversal-foundation
member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']
---

## Summary
A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.

## Technical Deep Dive
Five convergence/coverage notes across multiple atlas batches all identify PE parsing (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, Optional Header, DataDirectory, IMAGE_EXPORT_DIRECTORY) as a cross-cutting prerequisite for SSN resolution, export hijack, module stomping, and thread hijack.

Key technical anchor: IMAGE_DOS_HEADER.e_lfanew at offset 0x3C → IMAGE_NT_HEADERS64 → IMAGE_OPTIONAL_HEADER64.Magic = 0x20B (PE32+) → DataDirectory[0] (IMAGE_DIRECTORY_ENTRY_EXPORT) → IMAGE_EXPORT_DIRECTORY

## Evidence
- lgtm:pe-format-traversal-foundations: Highlights the gap or observation related to this tradecraft.
- lgtm:pe-parsing-foundational-utility: Highlights the gap or observation related to this tradecraft.
- lgtm:pe-format-parsing-foundation: Highlights the gap or observation related to this tradecraft.
- lgtm:pe-parsing-primitives-coverage: Highlights the gap or observation related to this tradecraft.
- lgtm:coverage-gap-pe-parsing-prerequisite: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-002 - related to PE Format Header Traversal as Foundational Primitive
- T-004 - related to PE Format Header Traversal as Foundational Primitive
- T-006 - related to PE Format Header Traversal as Foundational Primitive
- T-007 - related to PE Format Header Traversal as Foundational Primitive
- T-008 - related to PE Format Header Traversal as Foundational Primitive
- T-013 - related to PE Format Header Traversal as Foundational Primitive
- T-016 - related to PE Format Header Traversal as Foundational Primitive
- T-017 - related to PE Format Header Traversal as Foundational Primitive
- T-009 - related to PE Format Header Traversal as Foundational Primitive
- T-010 - related to PE Format Header Traversal as Foundational Primitive

## References
- Refer to internal research note pe-format-traversal-foundation for preliminary data.
