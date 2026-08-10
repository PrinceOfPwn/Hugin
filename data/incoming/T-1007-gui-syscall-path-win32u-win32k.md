---
id: T-1007
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: syscalls
tier: A
tags: [research-gap, syscalls]
mitre: []
origin: glm-expand-cluster
source_cluster: gui-syscall-path-win32u-win32k
member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']
---

## Summary
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives.

## Technical Deep Dive
Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).

### Technical Anchor
win32u.dll → win32k.sys syscall routing; NtUserOpenClipboard as exemplar; thread's Win32Thread (THREADINFO) field must be non-NULL

## Evidence
- `lgtm:win32u-gui-syscall-hook-coverage`: Contributed evidence for this cluster.
- `lgtm:gui-vs-native-syscall-path-awareness`: Contributed evidence for this cluster.

## Detection & Mitigation
Detection strategies should focus on the technical anchors described above. Specifically, monitor for associated API calls, memory allocations, or specific thread creation behaviors as applicable.

## Related Techniques
- T-001: Related technique identified during clustering.
- T-002: Related technique identified during clustering.
- T-016: Related technique identified during clustering.
- T-023: Related technique identified during clustering.

## References
- Internal cluster analysis
