---
id: T-148
title: "KUSER_SHARED_DATA Syscall Dispatch Flag in Stub Replication"
category: syscalls
tier: A
tags: ['kuser-shared-data-syscall-dispatch-flag']
mitre: ["T-001","T-006"]
origin: glm-expand-cluster
source_cluster: kuser-shared-data-syscall-dispatch-flag
member_notes: ["lgtm:kuser-shared-data-flag-handling"]
---
## Summary

This technique covers KUSER_SHARED_DATA Syscall Dispatch Flag in Stub Replication. It addresses a gap in knowledge for red-team operations related to syscalls.

## Technical Deep Dive

SEC670 unit 32 documents the 'test byte ptr [7FFE0308h],1' check inside every ntdll
syscall stub, which selects between the 'syscall' instruction (modern path) and legacy
'int 2Eh' dispatch. The byte at 0x7FFE0308 is within the KUSER_SHARED_DATA structure
(SystemCallPad field at offset 0x308). Techniques that fabricate or copy syscall stubs
(T-001 RecycledGate, T-006 Picusstons) must replicate this check correctly or risk
dispatching via the legacy interrupt path on systems where the flag is clear. The vault's
stub implementations use hardcoded 'mov eax, SSN; syscall' sequences that omit this
check. A card should document the KUSER_SHARED_DATA layout (shared at 0x7FFE0000,
user-mode mapped), the specific offset 0x308, the flag semantics, and the implications
for stub fabrication — including whether the omission produces detectable anomalies.


Technical anchor details:
```text
KUSER_SHARED_DATA at 0x7FFE0000 — SystemCallPad byte at offset 0x308 ('test byte ptr [7FFE0308h],1') in ntdll syscall stubs selecting syscall vs. int 2Eh dispatch
```

## Evidence

- lgtm:kuser-shared-data-flag-handling: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-001: Related technique for extended operations.
- T-006: Related technique for extended operations.

## References

- Internal Vault References
