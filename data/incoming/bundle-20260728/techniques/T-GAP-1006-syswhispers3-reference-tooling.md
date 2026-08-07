---
id: T-GAP-1006
name: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: []
origin: lgtm-cluster
member_notes: ["lgtm:vault-gap-syswhispers3-tooling"]
---

# SysWhispers3 as Reference SSN-Stub Generator

## Summary

Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


## Mechanism

SysWhispers3 stub modes: WoW64, egg-hunter (`@__Nt` egg pattern), direct `syscall` in user stub, indirect `jmp` into ntdll `syscall; ret` gadget

## Rationale

Single coverage-gap note naming the canonical external tooling for SSN stub generation; operators will encounter this regardless of vault stance.

## Related To

T-001, T-002, T-006
