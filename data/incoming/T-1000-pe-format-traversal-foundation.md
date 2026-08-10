---
id: T-1000
title: "PE Format Header Traversal as Foundational Primitive"
category: patterns
tier: C
tags: [research-gap, patterns]
mitre: []
origin: glm-expand-cluster
source_cluster: pe-format-traversal-foundation
member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']
---

## Summary
A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries.

## Technical Deep Dive
Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.

### Technical Anchor
IMAGE_DOS_HEADER.e_lfanew at offset 0x3C → IMAGE_NT_HEADERS64 → IMAGE_OPTIONAL_HEADER64.Magic = 0x20B (PE32+) → DataDirectory[0] (IMAGE_DIRECTORY_ENTRY_EXPORT) → IMAGE_EXPORT_DIRECTORY

## Evidence
- `lgtm:pe-format-traversal-foundations`: Contributed evidence for this cluster.
- `lgtm:pe-parsing-foundational-utility`: Contributed evidence for this cluster.
- `lgtm:pe-format-parsing-foundation`: Contributed evidence for this cluster.
- `lgtm:pe-parsing-primitives-coverage`: Contributed evidence for this cluster.
- `lgtm:coverage-gap-pe-parsing-prerequisite`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-002: Related technique identified during clustering.
- T-004: Related technique identified during clustering.
- T-006: Related technique identified during clustering.
- T-007: Related technique identified during clustering.
- T-008: Related technique identified during clustering.
- T-013: Related technique identified during clustering.
- T-016: Related technique identified during clustering.
- T-017: Related technique identified during clustering.
- T-009: Related technique identified during clustering.
- T-010: Related technique identified during clustering.

## References
- Internal cluster analysis
