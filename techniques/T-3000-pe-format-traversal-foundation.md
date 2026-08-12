---
id: T-3000
title: "PE Format Header Traversal as Foundational Primitive"
category: discovery
tier: C
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: pe-format-traversal-foundation
member_notes: ['lgtm:pe-format-traversal-foundations', 'lgtm:pe-parsing-foundational-utility', 'lgtm:pe-format-parsing-foundation', 'lgtm:pe-parsing-primitives-coverage', 'lgtm:coverage-gap-pe-parsing-prerequisite']
---
## Summary

This technique card covers PE Format Header Traversal as Foundational Primitive. It details mechanisms required to implement or understand pe-format-traversal-foundation operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

A foundational reference card documenting the PE format traversal required by T-002, T-004, T-006, T-007, T-008, T-013, T-016, and T-017. Walk the IMAGE_DOS_HEADER (e_magic 0x5A4D "MZ", e_lfanew at offset 0x3C), then IMAGE_NT_HEADERS64 (Signature "PE\0\0"), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64 (Magic 0x20B for PE32+), and DataDirectory entries. Critical offsets: IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) for export table traversal to resolve SSNs and function pointers; IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) for relocation-aware module stomping; IMAGE_DIRECTORY_ENTRY_IAT (index 12) for IAT hooking. The export table walk dereferences IMAGE_EXPORT_DIRECTORY.Name (RVAs to function names), NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals — required by both SysWhispers-style SSN resolution and export-hijack DLLs. Without this card, T-002 (syscalls) and T-013 (thread hijack) become hard to navigate for readers without prior PE internals background.



```c
// Example for PE Format Header Traversal as Foundational Primitive
PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)target_base;
if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) { ... }
```

## Evidence

- `lgtm:pe-format-traversal-foundations`: Referenced in internal atlas batches as a core component of pe-format-traversal-foundation.
- `lgtm:pe-parsing-foundational-utility`: Referenced in internal atlas batches as a core component of pe-format-traversal-foundation.
- `lgtm:pe-format-parsing-foundation`: Referenced in internal atlas batches as a core component of pe-format-traversal-foundation.
- `lgtm:pe-parsing-primitives-coverage`: Referenced in internal atlas batches as a core component of pe-format-traversal-foundation.
- `lgtm:coverage-gap-pe-parsing-prerequisite`: Referenced in internal atlas batches as a core component of pe-format-traversal-foundation.

## Detection & Mitigation

Detection relies on monitoring call stacks (e.g. via ETW-Ti) for indirect syscall patterns or anomalous RIP values outside ntdll.dll module boundaries. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on PE Format Header Traversal as Foundational Primitive
