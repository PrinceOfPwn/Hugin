---
id: T-007
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
tags: [gap-card]
mitre: []
origin: manual-script
source_cluster: syswhispers3-reference-tooling
member_notes: ["lgtm:vault-gap-syswhispers3-tooling"]
---

## Summary

Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


## Technical Deep Dive

Single coverage-gap note naming the canonical external tooling for SSN stub generation; operators will encounter this regardless of vault stance.

## Evidence

- lgtm:vault-gap-syswhispers3-tooling

## Detection & Mitigation

N/A

## Related Techniques

N/A

## References

N/A
