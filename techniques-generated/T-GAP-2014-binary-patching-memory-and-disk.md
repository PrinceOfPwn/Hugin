---
id: T-GAP-2014
title: "Binary Patching as Standalone Offensive Capability"
category: "edr-evasion"
tier: "B"
tags: [generated, gap, research]
mitre: []
origin: glm-expand-cluster
source_cluster: binary-patching-memory-and-disk
member_notes: ['lgtm:binary-patching-as-standalone-capability', 'lgtm:binary-patching-as-distinct-technique']
---

## Summary
Documents binary patching as a discrete operational concept: modifying binaries on disk or in memory to change execution behavior. Memory patching: NTDLL unhook (T-016 byte-level), AMSI patch (AmsiScanBuffer prologue → ret), ETW patch (NtTraceEvent prologue → ret). Disk patching: persisting a modified PE on disk (e.g., patching an Import Directory or adding an export to enable IAT hijack on next load), or modifying a signed-but-relaxed binary's checksum-adjusted bytes. SEC670 lists this as a discrete Red Team Tools capability; the vault references patching implicitly inside T-016 but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.


## Technical Deep Dive
The cluster represents a gap identified during automated research analysis. Two notes (one gap, one convergence) both treat binary patching — on disk or in memory — as a distinct operational concept currently buried inside T-016.

## Evidence
- lgtm:binary-patching-as-standalone-capability: See original note for details.
- lgtm:binary-patching-as-distinct-technique: See original note for details.

## Detection & Mitigation
Monitor for the aforementioned behaviors using standard EDR hooks and ETW telemetry.

## Related Techniques
- Placeholder: related techniques to be discovered

## References
- Internal vault references
