---
id: T-1584
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: "edr-evasion"
tier: "S"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "direct-vs-indirect-syscall-callstack-detection"
member_notes: ["lgtm:direct-vs-indirect-syscall-callstack-detection"]
---

## Summary
This card covers the research gap identified as Kernel Call-Stack Origin Check Defeating Direct Syscalls. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.


## Evidence
- lgtm:direct-vs-indirect-syscall-callstack-detection: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.

## References
- To be added.
