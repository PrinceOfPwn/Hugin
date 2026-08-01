---
id: T-1590
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: [iat, hooking, primitive]
mitre: []
origin: glm-expand-cluster
source_cluster: iat-hooking-primitive
member_notes: ['lgtm:iat-hooking-as-technique']
---

## Summary
Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.

## Technical Deep Dive
Single coverage-gap note describing the complete 6-step IAT hooking primitive, currently absent from the vault despite being a foundational hooking technique.

Key technical anchor: DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT = 12] → FirstThunk array; VirtualProtect to PAGE_READWRITE → overwrite pointer → restore PAGE_READONLY

## Evidence
- lgtm:iat-hooking-as-technique: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-016 - related to Import Address Table (IAT) Hooking Primitive

## References
- Refer to internal research note iat-hooking-primitive for preliminary data.
