---
id: T-3007
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: syscalls
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: gui-syscall-path-win32u-win32k
member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']
---
## Summary

This technique card covers GUI Syscall Path via win32u.dll and win32k.sys. It details mechanisms required to implement or understand gui-syscall-path-win32u-win32k operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).



```c
// Example for GUI Syscall Path via win32u.dll and win32k.sys
HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
FARPROC pFunc = GetProcAddress(hNtdll, "NtQuerySystemInformation");
```

## Evidence

- `lgtm:win32u-gui-syscall-hook-coverage`: Referenced in internal atlas batches as a core component of gui-syscall-path-win32u-win32k.
- `lgtm:gui-vs-native-syscall-path-awareness`: Referenced in internal atlas batches as a core component of gui-syscall-path-win32u-win32k.

## Detection & Mitigation

Detection relies on monitoring call stacks (e.g. via ETW-Ti) for indirect syscall patterns or anomalous RIP values outside ntdll.dll module boundaries. Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on GUI Syscall Path via win32u.dll and win32k.sys
