---
id: T-227
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: iat-hooking-primitive
member_notes: ["lgtm:iat-hooking-as-technique"]
---

## Summary
This technique covers Import Address Table (IAT) Hooking Primitive, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT = 12] → FirstThunk array; VirtualProtect to PAGE_READWRITE → overwrite pointer → restore PAGE_READONLY
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:iat-hooking-as-technique: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on Import Address Table (IAT) Hooking Primitive
