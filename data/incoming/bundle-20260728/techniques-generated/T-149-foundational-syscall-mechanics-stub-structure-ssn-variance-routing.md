---
id: T-149
title: "Foundational Syscall Mechanics (Stub Structure, SSN Variance, Routing)"
category: syscalls
tier: A
tags: ['foundational-syscall-mechanics-convergence']
mitre: ["T-001","T-002","T-003","T-004","T-006"]
origin: glm-expand-cluster
source_cluster: foundational-syscall-mechanics-convergence
member_notes: ["lgtm:cross-source-syscall-foundations-convergence"]
---
## Summary

This technique covers Foundational Syscall Mechanics (Stub Structure, SSN Variance, Routing). It addresses a gap in knowledge for red-team operations related to syscalls.

## Technical Deep Dive

SEC670 units 24-34 cover the syscall stub structure (mov eax, SSN; test byte ptr
[7FFE0308h],1; syscall; ret), SSN version-variance across Windows builds (SSNs are
unstable across versions but stable within a build), and the native-vs-GUI routing
that motivates the entire HUGIN syscall-dispatch suite (T-001 through T-006). The
convergence across SEC670, MalDev Academy, and the vault's own implementation confirms
these as foundational prerequisites. A concept card should document the stub byte
sequence, the SSN assignment pattern (Nt* functions assigned sequential SSNs in
alphabetical order within each build), the SSN-without-hardcoding approaches (hell's
gate, halos gate, tartarus gate), and the relationship between direct syscall dispatch
and EDR hook evasion. This card would serve as the navigation hub for T-001 through
T-006.


Technical anchor details:
```text
ntdll syscall stub byte pattern: mov eax, SSN (4-byte immediate) + 'test byte ptr [7FFE0308h],1' + syscall + ret — SSNs assigned alphabetically per build
```

## Evidence

- lgtm:cross-source-syscall-foundations-convergence: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-001: Related technique for extended operations.
- T-002: Related technique for extended operations.
- T-003: Related technique for extended operations.
- T-004: Related technique for extended operations.
- T-006: Related technique for extended operations.

## References

- Internal Vault References
