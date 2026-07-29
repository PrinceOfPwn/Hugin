---
id: T-1587
title: "GUI Syscall Path via win32u.dll and win32k.sys"
category: "edr-evasion"
tier: "A"
tags: [research, gap, generated]
mitre: []
origin: local-model-expand
source_cluster: "gui-syscall-path-win32u-win32k"
member_notes: ["lgtm:win32u-gui-syscall-hook-coverage", "lgtm:gui-vs-native-syscall-path-awareness"]
---

## Summary
This card covers the research gap identified as GUI Syscall Path via win32u.dll and win32k.sys. It represents an area of convergence that requires further investigation.

## Technical Deep Dive
Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


## Evidence
- lgtm:win32u-gui-syscall-hook-coverage: Identified gap in the research corpus.
- lgtm:gui-vs-native-syscall-path-awareness: Identified gap in the research corpus.

## Detection & Mitigation
To be determined based on specific technical implementation.

## Related Techniques
- T-001: Related technique identified in gap analysis.
- T-002: Related technique identified in gap analysis.
- T-016: Related technique identified in gap analysis.
- T-023: Related technique identified in gap analysis.

## References
- To be added.
