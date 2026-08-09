---
id: T-214
title: "Binary Patching as Standalone Offensive Capability"
category: edr-evasion
tier: B
tags: ['research-gap', 'binary-patching-memory-and-disk']
mitre: []
origin: glm-expand-cluster
source_cluster: binary-patching-memory-and-disk
member_notes: ['lgtm:binary-patching-as-standalone-capability', 'lgtm:binary-patching-as-distinct-technique']
---

## Summary

This technique card addresses the research gap identified in cluster `binary-patching-memory-and-disk`.
Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.


## Technical Deep Dive

Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.


Technical anchor points:
```
Memory: AMSI patch (`AmsiScanBuffer` prologue → `ret 0x80070057`); Disk: IMAGE_OPTIONAL_HEADER.CheckSum field must be recomputed via RtlImageNtHeader + CheckSumMappedFile
```

## Evidence

- **lgtm:binary-patching-as-standalone-capability**: Extracted as a foundational reference note for this cluster.
- **lgtm:binary-patching-as-distinct-technique**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-016: Relates to the foundational mechanisms discussed in this gap.
- T-017: Relates to the foundational mechanisms discussed in this gap.
- T-020: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `binary-patching-memory-and-disk`
- Generated as part of batch processing to fill identified research gaps.
