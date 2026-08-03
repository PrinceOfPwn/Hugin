---
id: T-200
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: syscalls
tier: S
tags: ['tradecraft']
mitre: []
origin: glm-expand-cluster
source_cluster: direct-vs-indirect-syscall-callstack-detection
member_notes: ["lgtm:direct-vs-indirect-syscall-callstack-detection"]
---

## Summary
This technique covers Kernel Call-Stack Origin Check Defeating Direct Syscalls, focusing on the technical mechanisms and primitives involved. It is essential for offensive operations and red teaming due to its fundamental role in system exploitation and evasion.

## Technical Deep Dive
Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.


The implementation details involve specific API calls, structures, and offsets as highlighted below:

```c
// Example technical anchor mapping
// Kernel call-stack walk via RtlVirtualUnwind at syscall entry; frames outside ntdll.dll image base range (from RtlImageNtHeader on NtQueryInformationProcess(ProcessImageFileName)) are flagged
```

The process requires careful handling of prerequisites and system architecture constraints (assumed Windows 10/11 x64 unless stated otherwise).

## Evidence
- Note lgtm:direct-vs-indirect-syscall-callstack-detection: Contributed insights into the specific mechanism.

## Detection & Mitigation
Detection relies on monitoring relevant telemetry sources such as ETW providers, Sysmon event IDs, and EDR hooks. Mitigation involves applying preventive controls like ACL hardening, WDAC/AppLocker rules, and driver-signing enforcement.

## Related Techniques
- T-001: Relates conceptually based on evidence.
- T-002: Relates conceptually based on evidence.
- T-016: Relates conceptually based on evidence.

## References
- Internal vault documentation on Kernel Call-Stack Origin Check Defeating Direct Syscalls
