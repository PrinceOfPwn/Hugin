---
id: T-1582
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: syscalls
tier: A
tags: [gui, syscall, path, win32u]
mitre: []
origin: glm-expand-cluster
source_cluster: gui-syscall-path-win32u-win32k
member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']
---

## Summary
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).

## Technical Deep Dive
Two notes (one gap, one emerging-tradecraft) describe the same win32u.dll GUI syscall split; the vault's T-016 unhook documentation does not address this layer.

Key technical anchor: win32u.dll → win32k.sys syscall routing; NtUserOpenClipboard as exemplar; thread's Win32Thread (THREADINFO) field must be non-NULL

## Evidence
- lgtm:win32u-gui-syscall-hook-coverage: Highlights the gap or observation related to this tradecraft.
- lgtm:gui-vs-native-syscall-path-awareness: Highlights the gap or observation related to this tradecraft.

## Detection & Mitigation
Detection of this technique relies heavily on endpoint telemetry (Sysmon, ETW). Mitigation requires a combination of strict ACLs and execution control policies.

## Related Techniques
- T-001 - related to GUI Syscall Path via win32u.dll and win32k.sys
- T-002 - related to GUI Syscall Path via win32u.dll and win32k.sys
- T-016 - related to GUI Syscall Path via win32u.dll and win32k.sys
- T-023 - related to GUI Syscall Path via win32u.dll and win32k.sys

## References
- Refer to internal research note gui-syscall-path-win32u-win32k for preliminary data.
