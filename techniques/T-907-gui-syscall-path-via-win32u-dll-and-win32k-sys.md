---
id: T-907
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: syscalls
tier: A
tags: []
mitre: []
origin: manual-gap-extraction
source_cluster: gui-syscall-path-win32u-win32k
member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']
---

## Summary
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


## Technical Deep Dive
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


Technical anchor: win32u.dll → win32k.sys syscall routing; NtUserOpenClipboard as exemplar; thread's Win32Thread (THREADINFO) field must be non-NULL

## Evidence
- lgtm:win32u-gui-syscall-hook-coverage
- lgtm:gui-vs-native-syscall-path-awareness

## Detection & Mitigation
General mitigation strategies apply. Monitor API calls and anomalous behaviors.

## Related Techniques
- T-001
- T-002
- T-016
- T-023

## References
- Internal knowledge base.
