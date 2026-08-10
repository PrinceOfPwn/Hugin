---
id: T-1015
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: [research-gap, edr-evasion]
mitre: []
origin: glm-expand-cluster
source_cluster: iat-hooking-primitive
member_notes: ['lgtm:iat-hooking-as-technique']
---

## Summary
Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.

## Technical Deep Dive
Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


### Technical Anchor
DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT = 12] → FirstThunk array; VirtualProtect to PAGE_READWRITE → overwrite pointer → restore PAGE_READONLY

## Evidence
- `lgtm:iat-hooking-as-technique`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-016: Related technique identified during clustering.

## References
- Internal cluster analysis
