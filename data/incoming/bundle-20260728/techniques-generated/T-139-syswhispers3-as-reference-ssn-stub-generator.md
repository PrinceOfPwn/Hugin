---
id: T-139
title: "SysWhispers3 as Reference SSN-Stub Generator"
category: syscalls
tier: A
tags: ['syswhispers3-reference-tooling']
mitre: ["T-001","T-002","T-006"]
origin: glm-expand-cluster
source_cluster: syswhispers3-reference-tooling
member_notes: ["lgtm:vault-gap-syswhispers3-tooling"]
---
## Summary

This technique covers SysWhispers3 as Reference SSN-Stub Generator. It addresses a gap in knowledge for red-team operations related to syscalls.

## Technical Deep Dive

Documents SysWhispers3 as the canonical external tooling for SSN-stub generation, with its supported evasion modes: WoW64 stubs (for Heaven's Gate-style transitions), egg-hunter SSN resolution (the `YW...` egg pattern scanned at runtime in ntdll .text), direct syscall jumps in WoW64 and x64, and indirect syscall jumps (calling into ntdll's own `syscall; ret` gadget to defeat kernel call-stack checks). Reference card rather than a how-to; vault's own T-002 implementation should be cross-referenced against SysWhispers3's feature set so operators know what capability parity exists.


Technical anchor details:
```text
SysWhispers3 stub modes: WoW64, egg-hunter (`@__Nt` egg pattern), direct `syscall` in user stub, indirect `jmp` into ntdll `syscall; ret` gadget
```

## Evidence

- lgtm:vault-gap-syswhispers3-tooling: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-001: Related technique for extended operations.
- T-002: Related technique for extended operations.
- T-006: Related technique for extended operations.

## References

- Internal Vault References
