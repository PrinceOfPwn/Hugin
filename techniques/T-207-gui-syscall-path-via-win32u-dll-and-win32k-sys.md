---
id: T-207
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: syscalls
tier: A
tags: ['research-gap', 'gui-syscall-path-win32u-win32k']
mitre: []
origin: glm-expand-cluster
source_cluster: gui-syscall-path-win32u-win32k
member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']
---

## Summary

This technique card addresses the research gap identified in cluster `gui-syscall-path-win32u-win32k`.
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


## Technical Deep Dive

Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


Technical anchor points:
```
win32u.dll → win32k.sys syscall routing; NtUserOpenClipboard as exemplar; thread's Win32Thread (THREADINFO) field must be non-NULL
```

## Evidence

- **lgtm:win32u-gui-syscall-hook-coverage**: Extracted as a foundational reference note for this cluster.
- **lgtm:gui-vs-native-syscall-path-awareness**: Extracted as a foundational reference note for this cluster.

## Detection & Mitigation

Concrete detection telemetry sources and mitigation controls will be expanded based on the structural references in the vault. Future iterations should incorporate Sysmon, ETW, and ACL hardening rules relevant to this gap.

## Related Techniques

- T-001: Relates to the foundational mechanisms discussed in this gap.
- T-002: Relates to the foundational mechanisms discussed in this gap.
- T-016: Relates to the foundational mechanisms discussed in this gap.
- T-023: Relates to the foundational mechanisms discussed in this gap.

## References

- Originating Cluster: `gui-syscall-path-win32u-win32k`
- Generated as part of batch processing to fill identified research gaps.
