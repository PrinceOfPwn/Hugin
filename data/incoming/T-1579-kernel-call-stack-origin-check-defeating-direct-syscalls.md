---
id: T-1579
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: syscalls
tier: S
tags: [direct, vs, indirect, syscall]
mitre: []
origin: glm-expand-cluster
source_cluster: direct-vs-indirect-syscall-callstack-detection
member_notes: ['lgtm:direct-vs-indirect-syscall-callstack-detection']
---

## Summary
Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.

## Technical Deep Dive
Single convergence note describing a defensive mechanism that breaks direct syscalls and motivates indirect syscalls (T-002); high operational relevance and not currently documented.

Key technical anchor: Kernel call-stack walk via RtlVirtualUnwind at syscall entry; frames outside ntdll.dll image base range (from RtlImageNtHeader on NtQueryInformationProcess(ProcessImageFileName)) are flagged

## Evidence
- lgtm:direct-vs-indirect-syscall-callstack-detection: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-001 - related to Kernel Call-Stack Origin Check Defeating Direct Syscalls
- T-002 - related to Kernel Call-Stack Origin Check Defeating Direct Syscalls
- T-016 - related to Kernel Call-Stack Origin Check Defeating Direct Syscalls

## References
- Refer to internal research note direct-vs-indirect-syscall-callstack-detection for preliminary data.
