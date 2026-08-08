---
id: T-GAP-1007
title: "GUI Syscall Path via win32u.dll and win32k.sys"
tier: "A"
category: "syscalls"
---

# GUI Syscall Path via win32u.dll and win32k.sys

## Description
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


## Rationale
Two notes (one gap, one emerging-tradecraft) describe the same win32u.dll GUI syscall split; the vault's T-016 unhook documentation does not address this layer.

## References
- lgtm:win32u-gui-syscall-hook-coverage
- lgtm:gui-vs-native-syscall-path-awareness
