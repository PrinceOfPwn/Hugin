---
id: T-147
title: "Thread Creation Internals (NtCreateThreadEx / PspCreateThread)"
category: discovery
tier: B
tags: ['thread-creation-internals-prerequisite']
mitre: ["T-007","T-008","T-012","T-013"]
origin: glm-expand-cluster
source_cluster: thread-creation-internals-prerequisite
member_notes: ["lgtm:thread-creation-internals-as-prerequisite"]
---
## Summary

This technique covers Thread Creation Internals (NtCreateThreadEx / PspCreateThread). It addresses a gap in knowledge for red-team operations related to discovery.

## Technical Deep Dive

SEC670 unit 10 explains the kernel-side thread creation path that all thread-based
injection techniques ultimately invoke: NtCreateThreadEx → PspCreateThread, including
parameter-to-flag conversion, Client ID and TEB insertion into an attribute list, and
the local vs. remote dispatch fork (PspCreateThread for current process vs. remote
process via the ThreadContext parameter). The vault's T-007 (NtCreateThreadEx Remote
Thread), T-008 (Thread Hijacking), T-012 (APC Injection), and T-013 (Shellcode Runner)
all terminate at this path but do not document the kernel internals as a shared
prerequisite. A concept card should map the CreateThread → NtCreateThreadEx →
PspCreateThread dispatch chain, the ETHREAD/InitialTeb fields populated, and how each
injection technique (remote thread, APC, thread hijack) diverges at the point of
thread-context construction.


Technical anchor details:
```text
NtCreateThreadEx → PspCreateThread — Client ID and TEB insertion into thread attribute list; local vs. remote dispatch via ThreadContext parameter
```

## Evidence

- lgtm:thread-creation-internals-as-prerequisite: Member note detailing operations.

## Detection & Mitigation

Monitor for specific API calls and telemetry related to this technique, such as ETW events or Sysmon IDs. Validate configurations or driver-signing enforcements to mitigate risks.

## Related Techniques

- T-007: Related technique for extended operations.
- T-008: Related technique for extended operations.
- T-012: Related technique for extended operations.
- T-013: Related technique for extended operations.

## References

- Internal Vault References
