---
id: T-215
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: ['research-gap', 'iat-hooking-primitive']
mitre: []
origin: glm-expand-cluster
source_cluster: iat-hooking-primitive
member_notes: ['lgtm:iat-hooking-as-technique']
---

## Summary

This technique card addresses the research gap identified in cluster `iat-hooking-primitive`.
Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


## Technical Deep Dive

Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


Technical anchor points:
```
DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT = 12] → FirstThunk array; VirtualProtect to PAGE_READWRITE → overwrite pointer → restore PAGE_READONLY
```

## Evidence

- **lgtm:iat-hooking-as-technique**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `iat-hooking-primitive`
- Generated as part of batch processing to fill identified research gaps.
