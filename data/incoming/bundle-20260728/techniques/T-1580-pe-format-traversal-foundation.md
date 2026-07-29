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
A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.


## Evidence
- lgtm:pe-format-traversal-foundations: Identified gap in the research corpus.
- lgtm:pe-parsing-foundational-utility: Identified gap in the research corpus.
- lgtm:pe-format-parsing-foundation: Identified gap in the research corpus.
- lgtm:pe-parsing-primitives-coverage: Identified gap in the research corpus.
- lgtm:coverage-gap-pe-parsing-prerequisite: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

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
- To be added.
