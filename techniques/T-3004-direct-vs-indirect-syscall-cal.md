---
id: T-3004
title: "Kernel Call-Stack Origin Check Defeating Direct Syscalls"
category: syscalls
tier: S
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: direct-vs-indirect-syscall-callstack-detection
member_notes: ['lgtm:direct-vs-indirect-syscall-callstack-detection']
---
## Summary

This technique card covers Kernel Call-Stack Origin Check Defeating Direct Syscalls. It details mechanisms required to implement or understand direct-vs-indirect-syscall-callstack-detection operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents why direct syscalls (executing `syscall` from implant-owned memory) defeat userland EDR hooks but still fail against kernel-mode components that verify the syscall's return address originates from inside ntdll.dll. EDR kernel drivers (via PsSetLoadImageNotifyRoutine or minifilter altitude registration) walk the call stack at syscall entry using NtQueryInformationThread(ThreadStackLimits) or RtlVirtualUnwind; if the frame immediately below the kernel transition is not within ntdll's image base range, the syscall is flagged. This is the operational reason for indirect syscalls (T-002): jumping into a genuine ntdll `syscall; ret` gadget makes the call stack appear legitimate. Concrete detection primitive: walk the frames, check RSP against the ntdll image range returned by NtQueryInformationProcess(ProcessImageFileName) + RtlImageNtHeader.



```c
// Example for Kernel Call-Stack Origin Check Defeating Direct Syscalls
HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
FARPROC pFunc = GetProcAddress(hNtdll, "NtQuerySystemInformation");
```

## Evidence

- `lgtm:direct-vs-indirect-syscall-callstack-detection`: Referenced in internal atlas batches as a core component of direct-vs-indirect-syscall-callstack-detection.

## Detection & Mitigation

Detection relies on monitoring call stacks (e.g. via ETW-Ti) for indirect syscall patterns or anomalous RIP values outside ntdll.dll module boundaries. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on Kernel Call-Stack Origin Check Defeating Direct Syscalls
