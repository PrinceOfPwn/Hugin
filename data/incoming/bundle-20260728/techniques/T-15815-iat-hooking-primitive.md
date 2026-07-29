---
id: T-15815
title: "Import Address Table (IAT) Hooking Primitive"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "iat-hooking-primitive"
member_notes: ["lgtm:iat-hooking-as-technique"]
---

## Summary
This card covers the research gap identified as Import Address Table (IAT) Hooking Primitive. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


## Evidence
- lgtm:iat-hooking-as-technique: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-016: Related technique identified in gap analysis.

## References
- To be added.
