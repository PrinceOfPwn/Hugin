---
id: T-15814
title: "Binary Patching as Standalone Offensive Capability"
category: "edr-evasion"
tier: "B"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "binary-patching-memory-and-disk"
member_notes: ["lgtm:binary-patching-as-standalone-capability", "lgtm:binary-patching-as-distinct-technique"]
---

## Summary
This card covers the research gap identified as Binary Patching as Standalone Offensive Capability. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.


## Evidence
- lgtm:binary-patching-as-standalone-capability: Identified gap in the research corpus.
- lgtm:binary-patching-as-distinct-technique: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-016: Related technique identified in gap analysis.
- T-017: Related technique identified in gap analysis.
- T-020: Related technique identified in gap analysis.

## References
- To be added.
