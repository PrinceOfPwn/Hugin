---
id: T-1004
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: syscalls
tier: S
tags: [research-gap, syscalls]
mitre: []
origin: glm-expand-cluster
source_cluster: direct-vs-indirect-syscall-callstack-detection
member_notes: ['lgtm:direct-vs-indirect-syscall-callstack-detection']
---

## Summary
Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged.

## Technical Deep Dive
This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.

### Technical Anchor
Kernel call-stack walk via RtlVirtualUnwind at syscall entry; frames outside ntdll.dll image base range (from RtlImageNtHeader on NtQueryInformationProcess(ProcessImageFileName)) are flagged

## Evidence
- `lgtm:direct-vs-indirect-syscall-callstack-detection`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-001: Related technique identified during clustering.
- T-002: Related technique identified during clustering.
- T-016: Related technique identified during clustering.

## References
- Internal cluster analysis
