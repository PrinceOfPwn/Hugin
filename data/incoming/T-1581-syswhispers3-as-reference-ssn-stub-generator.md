---
id: T-1581
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
tags: [syswhispers3, reference, tooling]
mitre: []
origin: glm-expand-cluster
source_cluster: syswhispers3-reference-tooling
member_notes: ['lgtm:vault-gap-syswhispers3-tooling']
---

## Summary
Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.

## Technical Deep Dive
Single coverage-gap note naming the canonical external tooling for SSN stub generation; operators will encounter this regardless of vault stance.

Key technical anchor: SysWhispers3 stub modes: WoW64, egg-hunter (`@__Nt` egg pattern), direct `syscall` in user stub, indirect `jmp` into ntdll `syscall; ret` gadget

## Evidence
- lgtm:vault-gap-syswhispers3-tooling: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-001 - related to SysWhispers3 as Reference SSN-Stub Generator
- T-002 - related to SysWhispers3 as Reference SSN-Stub Generator
- T-006 - related to SysWhispers3 as Reference SSN-Stub Generator

## References
- Refer to internal research note syswhispers3-reference-tooling for preliminary data.
