---
id: T-1014
title: "Binary Patching as Standalone Offensive Capability"
category: edr-evasion
tier: B
tags: [research-gap, edr-evasion]
mitre: []
origin: glm-expand-cluster
source_cluster: binary-patching-memory-and-disk
member_notes: ['lgtm:binary-patching-as-standalone-capability', 'lgtm:binary-patching-as-distinct-technique']
---

## Summary
Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret).

## Technical Deep Dive
Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.

### Technical Anchor
Memory: AMSI patch (`AmsiScanBuffer` prologue → `ret 0x80070057`); Disk: IMAGE_OPTIONAL_HEADER.CheckSum field must be recomputed via RtlImageNtHeader + CheckSumMappedFile

## Evidence
- `lgtm:binary-patching-as-standalone-capability`: Contributed evidence for this cluster.
- `lgtm:binary-patching-as-distinct-technique`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-016: Related technique identified during clustering.
- T-017: Related technique identified during clustering.
- T-020: Related technique identified during clustering.

## References
- Internal cluster analysis
