---
id: T-206
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
tags: ['research-gap', 'syswhispers3-reference-tooling']
mitre: []
origin: glm-expand-cluster
source_cluster: syswhispers3-reference-tooling
member_notes: ['lgtm:vault-gap-syswhispers3-tooling']
---

## Summary

This technique card addresses the research gap identified in cluster `syswhispers3-reference-tooling`.
Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


## Technical Deep Dive

Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


Technical anchor points:
```
SysWhispers3 stub modes: WoW64, egg-hunter (`@__Nt` egg pattern), direct `syscall` in user stub, indirect `jmp` into ntdll `syscall; ret` gadget
```

## Evidence

- **lgtm:vault-gap-syswhispers3-tooling**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-001: Relates to the foundational mechanisms discussed in this gap.
- T-002: Relates to the foundational mechanisms discussed in this gap.
- T-006: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `syswhispers3-reference-tooling`
- Generated as part of batch processing to fill identified research gaps.
