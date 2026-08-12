---
id: T-3014
title: "Binary Patching as Standalone Offensive Capability"
category: edr-evasion
tier: B
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: binary-patching-memory-and-disk
member_notes: ['lgtm:binary-patching-as-standalone-capability', 'lgtm:binary-patching-as-distinct-technique']
---
## Summary

This technique card covers Binary Patching as Standalone Offensive Capability. It details mechanisms required to implement or understand binary-patching-memory-and-disk operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.



```c
// Example for Binary Patching as Standalone Offensive Capability
// Implementation specific to binary-patching-memory-and-disk
void execute_binary_patching_memory_and_disk() {
    // Setup and invoke appropriate APIs
}
```

## Evidence

- `lgtm:binary-patching-as-standalone-capability`: Referenced in internal atlas batches as a core component of binary-patching-memory-and-disk.
- `lgtm:binary-patching-as-distinct-technique`: Referenced in internal atlas batches as a core component of binary-patching-memory-and-disk.

## Detection & Mitigation

Memory scanning (YARA) and runtime behavioral analysis focusing on manual memory traversal outside of typical OS loader behavior. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Binary Patching as Standalone Offensive Capability
