---
id: T-1586
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "syswhispers3-reference-tooling"
member_notes: ["lgtm:vault-gap-syswhispers3-tooling"]
---

## Summary
This card covers the research gap identified as SysWhispers3 as Reference SSN-Stub Generator. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


## Evidence
- lgtm:vault-gap-syswhispers3-tooling: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-006: Related technique identified in gap analysis.

## References
- To be added.
