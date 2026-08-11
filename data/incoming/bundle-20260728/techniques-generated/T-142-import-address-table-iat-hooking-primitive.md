---
id: T-142
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: ['iat-hooking-primitive']
mitre: ["T-016"]
origin: glm-expand-cluster
source_cluster: iat-hooking-primitive
member_notes: ["lgtm:iat-hooking-as-technique"]
---
## Summary

This technique covers Import Address Table (IAT) Hooking Primitive. It addresses a gap in knowledge for red-team operations related to edr-evasion.

## Technical Deep Dive

Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.


Technical anchor details:
```text
DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT = 12] → FirstThunk array; VirtualProtect to PAGE_READWRITE → overwrite pointer → restore PAGE_READONLY
```

## Evidence

- lgtm:iat-hooking-as-technique: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-016: Related technique for extended operations.

## References

- Internal Vault References
