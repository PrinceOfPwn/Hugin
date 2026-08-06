---
id: T-041
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: [gap-card]
mitre: []
origin: manual-script
source_cluster: iat-hooking-primitive
member_notes: ["lgtm:iat-hooking-as-technique"]
---

## Summary

Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


## Technical Deep Dive

Single coverage-gap note describing the complete 6-step IAT hooking primitive, currently absent from the vault despite being a foundational hooking technique.

## Evidence

- lgtm:iat-hooking-as-technique

## Detection & Mitigation

Pending integration of defensive countermeasures and log sources.

## Related Techniques

Pending cross-reference analysis.

## References

Pending external citation mapping.
