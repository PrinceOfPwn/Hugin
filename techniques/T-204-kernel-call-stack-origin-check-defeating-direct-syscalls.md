---
id: T-204
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: syscalls
tier: S
tags: ['research-gap', 'direct-vs-indirect-syscall-callstack-detection']
mitre: []
origin: glm-expand-cluster
source_cluster: direct-vs-indirect-syscall-callstack-detection
member_notes: ['lgtm:direct-vs-indirect-syscall-callstack-detection']
---

## Summary

This technique card addresses the research gap identified in cluster `direct-vs-indirect-syscall-callstack-detection`.
Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.


## Technical Deep Dive

Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.


Technical anchor points:
```
Kernel call-stack walk via RtlVirtualUnwind at syscall entry; frames outside ntdll.dll image base range (from RtlImageNtHeader on NtQueryInformationProcess(ProcessImageFileName)) are flagged
```

## Evidence

- **lgtm:direct-vs-indirect-syscall-callstack-detection**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-001: Relates to the foundational mechanisms discussed in this gap.
- T-002: Relates to the foundational mechanisms discussed in this gap.
- T-016: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `direct-vs-indirect-syscall-callstack-detection`
- Generated as part of batch processing to fill identified research gaps.
