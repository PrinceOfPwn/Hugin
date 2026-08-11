---
id: T-151
title: "SysWhispers3 Syscall Stub Code Generation"
category: syscalls
tier: A
tags: ['syswhispers3-stub-generation']
mitre: ["T-001","T-002","T-006"]
origin: glm-expand-cluster
source_cluster: syswhispers3-stub-generation
member_notes: ["lgtm:syswhispers3-vs-vault-stubs"]
---
## Summary

This technique covers SysWhispers3 Syscall Stub Code Generation. It addresses a gap in knowledge for red-team operations related to syscalls.

## Technical Deep Dive

SEC670 units 15-16 cover SysWhispers3 as the standard external tool for generating
syscall stubs, including the egg-hunter variant (searching ntdll memory for a known
byte pattern to locate a legitimate stub) and the random-jump variant (jumping into
the middle of a legitimate stub to avoid prologue-based detection). The vault implements
its own stubs (T-001 RecycledGate, which borrows a hooked function's stub; T-006
Picusstons, hand-rolled PIC stubs) rather than using SysWhispers3. A card should
document SysWhispers3's code-generation model (Python templates producing C/H files
with stub definitions), the egg-hunter pattern (scanning for {4C 8B D1 B8 ... 00 00 07
00} byte signature in ntdll), the random-jump approach (jumping to offset N within a
legitimate stub), and how these compare to the vault's T-001 and T-006 approaches in
terms of detection surface and maintainability.


Technical anchor details:
```text
SysWhispers3 egg-hunter: scan ntdll for byte signature {4C 8B D1 B8 ?? ?? ?? 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3} — random-jump: JMP to offset within legitimate stub
```

## Evidence

- lgtm:syswhispers3-vs-vault-stubs: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-001: Related technique for extended operations.
- T-002: Related technique for extended operations.
- T-006: Related technique for extended operations.

## References

- Internal Vault References
