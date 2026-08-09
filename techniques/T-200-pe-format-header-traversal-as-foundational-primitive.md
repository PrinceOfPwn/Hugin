---
id: T-200
title: "PE Format Header Traversal as Foundational Primitive"
category: patterns
tier: C
tags: ['research-gap', 'pe-format-traversal-foundation']
mitre: []
origin: glm-expand-cluster
source_cluster: pe-format-traversal-foundation
member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']
---

## Summary

This technique card addresses the research gap identified in cluster `pe-format-traversal-foundation`.
A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.


## Technical Deep Dive

A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.


Technical anchor points:
```
IMAGE_DOS_HEADER.e_lfanew at offset 0x3C → IMAGE_NT_HEADERS64 → IMAGE_OPTIONAL_HEADER64.Magic = 0x20B (PE32+) → DataDirectory[0] (IMAGE_DIRECTORY_ENTRY_EXPORT) → IMAGE_EXPORT_DIRECTORY
```

## Evidence

- **lgtm:pe-format-traversal-foundations**: Extracted as a foundational reference note for this cluster.
- **lgtm:pe-parsing-foundational-utility**: Extracted as a foundational reference note for this cluster.
- **lgtm:pe-format-parsing-foundation**: Extracted as a foundational reference note for this cluster.
- **lgtm:pe-parsing-primitives-coverage**: Extracted as a foundational reference note for this cluster.
- **lgtm:coverage-gap-pe-parsing-prerequisite**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-002: Relates to the foundational mechanisms discussed in this gap.
- T-004: Relates to the foundational mechanisms discussed in this gap.
- T-006: Relates to the foundational mechanisms discussed in this gap.
- T-007: Relates to the foundational mechanisms discussed in this gap.
- T-008: Relates to the foundational mechanisms discussed in this gap.
- T-013: Relates to the foundational mechanisms discussed in this gap.
- T-016: Relates to the foundational mechanisms discussed in this gap.
- T-017: Relates to the foundational mechanisms discussed in this gap.
- T-009: Relates to the foundational mechanisms discussed in this gap.
- T-010: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `pe-format-traversal-foundation`
- Generated as part of batch processing to fill identified research gaps.
