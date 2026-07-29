# Cluster Spec — T-118: GUI Syscall Path via win32u.dll and win32k.sys

- **T-NNN ID**: `T-118`
- **Canonical name**: GUI Syscall Path via win32u.dll and win32k.sys
- **Proposed category**: `syscalls`
- **Proposed tier**: `A`
- **Priority**: high — Two notes flag this as a real coverage gap in T-016; operational consequence for any GUI-touching client capability.
- **would_relate_to**: ['T-001', 'T-002', 'T-016', 'T-023']

## Consolidated Description

Documents that Windows splits syscall routing into native (ntdll.dll → ntoskrnl.exe / executive) and GUI (win32u.dll → win32k.sys) paths. EDRs hook both; GUI functions like NtUserOpenClipboard, NtUserFindWindowEx, NtUserMessageCall are dispatched through win32u, not ntdll, so a T-016 ntdll unhook does NOT restore clean access to GUI primitives. Thread type matters: a non-GUI thread (no Win32k attributed) issuing a win32k syscall will be rejected; this is enforced by the thread's Win32Thread (THREADINFO) field being NULL. Operators issuing clipboard, window, or input syscalls must ensure the calling thread is GUI-initialized (called User32!Win32InitializeThunk or otherwise have an associated W32THREAD).


## Member LGTM Notes (2)

### Note 1: win32u.dll GUI Syscall Hook Layer
- id: `lgtm:win32u-gui-syscall-hook-coverage`
- origin: atlas-edr-evasion-part2
- would_relate_to: ['T-016']
- tags: ['win32u', 'gui-syscalls', 'hook-surface', 'coverage-gap', 'edr']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-016
**Source units:** unit 23, unit 24, unit 25

SEC670 distinguishes between ntdll (Native) and win32u (GUI) syscall layers and notes that EDRs hook both, including functions like NtUserOpenClipboard. The vault's T-016 NTDLL unhook documentation does not address win32u.dll. An operator unhooking only ntdll will miss GUI-syscall hooks and remain visible to the EDR for windowing-related calls. Worth extending T-016 to enumerate win32u as a second hook surface.

### Note 2: GUI Syscall Path via win32u.dll and win32k.sys
- id: `lgtm:gui-vs-native-syscall-path-awareness`
- origin: atlas-edr-evasion-part4
- would_relate_to: ['T-001', 'T-002', 'T-023']
- tags: ['syscall', 'win32u', 'win32k', 'gui', 'edr-hooking', 'emerging-tradecraft']

**Kind:** emerging-tradecraft
**Origin:** atlas-edr-evasion-part4
**Would relate to:** T-001, T-002, T-023
**Source units:** unit 34, unit 35, unit 36

SEC670 documents that Windows splits syscalls into native (ntdll.dll → kernel/executive) and GUI (win32u.dll → win32k.sys) paths, with different thread types routing to different kernel components. EDR products must hook both ntdll.dll and win32u.dll to capture the full syscall surface. The vault's syscall dispatch techniques (T-001, T-002, T-003) appear to focus on native ntdll syscalls; documenting the win32u.dll GUI syscall path would expand coverage to cover GUI-related operations (clipboard, window manipulation) relevant to T-023 client capabilities.

---
Use `id: T-118`, canonical name above, and `member_notes: ['lgtm:win32u-gui-syscall-hook-coverage', 'lgtm:gui-vs-native-syscall-path-awareness']`.
Cross-reference `would_relate_to`: ['T-001', 'T-002', 'T-016', 'T-023'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.