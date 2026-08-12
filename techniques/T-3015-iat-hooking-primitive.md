---
id: T-3015
title: "Import Address Table (IAT) Hooking Primitive"
category: edr-evasion
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: iat-hooking-primitive
member_notes: ['lgtm:iat-hooking-as-technique']
---
## Summary

This technique card covers Import Address Table (IAT) Hooking Primitive. It details mechanisms required to implement or understand iat-hooking-primitive operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the IAT hooking primitive in 6 steps: (1) parse the target PE's IMAGE_NT_HEADERS → DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT (index 12)], or DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)] for the descriptor; (2) walk the IMAGE_IMPORT_DESCRIPTOR array (OriginalFirstThunk → INT, FirstThunk → IAT, Name → DLL name); (3) for each imported function, match by name or ordinal; (4) flip the IAT page protection from PAGE_READONLY to PAGE_READWRITE via VirtualProtect (the IAT is typically read-only at runtime); (5) overwrite the function pointer with the hook address; (6) restore PAGE_READONLY. Distinct from inline hooking (which patches function prologue bytes) — IAT hooking only affects calls routed through the IAT, not direct GetProcAddress returns.



```c
// Example for Import Address Table (IAT) Hooking Primitive
// Implementation specific to iat-hooking-primitive
void execute_iat_hooking_primitive() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:iat-hooking-as-technique`: Referenced in internal atlas batches as a core component of iat-hooking-primitive.

## Detection & Mitigation

Memory scanning (YARA) and runtime behavioral analysis focusing on manual memory traversal outside of typical OS loader behavior. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Import Address Table (IAT) Hooking Primitive
