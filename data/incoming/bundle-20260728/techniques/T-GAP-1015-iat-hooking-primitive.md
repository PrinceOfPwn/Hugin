---
id: T-GAP-1015
name: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:iat-hooking-as-technique"]
---

# Import Address Table (IAT) Hooking Primitive

## Summary

Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


## Mechanism

DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT = 12] → FirstThunk array; VirtualProtect to PAGE_READWRITE → overwrite pointer → restore PAGE_READONLY

## Rationale

Single coverage-gap note describing the complete 6-step IAT hooking primitive, currently absent from the vault despite being a foundational hooking technique.

## Related To

T-016
