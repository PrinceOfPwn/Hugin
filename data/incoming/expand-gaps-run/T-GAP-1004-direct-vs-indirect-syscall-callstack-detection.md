---
id: T-GAP-1004
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
tier: "S"
category: "syscalls"
---

# Kernel Call-Stack Origin Check Defeating Direct Syscalls

## Description
Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.


## Rationale
Single convergence note describing a defensive mechanism that breaks direct syscalls and motivates indirect syscalls (T-002); high operational relevance and not currently documented.

## References
- lgtm:direct-vs-indirect-syscall-callstack-detection
