---
id: T-118
name: GUI Syscall Path via win32u and win32k
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1106
tags: [syscalls, win32u, win32k, gui-syscall-path, edr-hooking, thread-initialization, w32thread]
origin: atlas-synthesis
member_notes: [lgtm:win32u-gui-syscall-hook-coverage, lgtm:gui-vs-native-syscall-path-awareness]
---

# GUI Syscall Path via win32u.dll and win32k.sys — Dual Syscall Surface and Thread Type Enforcement

## Summary

Windows splits the syscall routing architecture into two distinct paths: native syscalls dispatched through ntdll.dll into the executive (ntoskrnl.exe), and GUI syscalls dispatched through win32u.dll into the kernel's windowing subsystem (win32k.sys). EDR products hook both ntdll.dll and win32u.dll to capture the full syscall surface, but the vault's T-016 NTDLL unhook documentation only addresses the native path. GUI functions such as `NtUserOpenClipboard`, `NtUserFindWindowEx`, and `NtUserMessageCall` are routed through win32u.dll, so an operator who unhooks only ntdll remains visible to EDR for all windowing, clipboard, and input-related operations. Additionally, the calling thread must be GUI-initialized — a thread without an associated W32THREAD structure will be rejected by win32k.sys when issuing GUI syscalls.

## Mechanism

1. The Windows syscall surface is partitioned into two dispatch paths. Native syscalls (`NtCreateFile`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, etc.) are exported by ntdll.dll and transition to the executive via the `syscall` instruction, entering ntoskrnl.exe through `KiSystemServiceTable`.

2. GUI syscalls (`NtUserOpenClipboard`, `NtUserFindWindowEx`, `NtUserGetMessage`, `NtUserMessageCall`, `NtUserSetClipboardData`, `NtGdiBitBlt`, etc.) are exported by win32u.dll and transition to win32k.sys through a separate system service table (the shadow SSDT or win32k syscall table). On Windows 10 1703+, win32u.dll replaced the previous user32.dll direct syscall stubs.

3. EDR products that hook user-mode syscall stubs must hook both ntdll.dll and win32u.dll. Hooking only ntdll.dll leaves the entire GUI syscall surface unmonitored — an EDR cannot observe clipboard access, window enumeration, or input injection through ntdll hooks alone.

4. Thread type enforcement: win32k.sys rejects GUI syscalls from threads that have not been initialized for GUI use. A thread becomes GUI-initialized when it calls a function that triggers Win32k thread initialization — typically through `User32!Win32InitializeThunk` or by calling a win32k API that forces thread attribute initialization.

5. The kernel tracks per-thread GUI state via the THREADINFO structure (also called W32THREAD), accessed through the `ETHREAD→Tcb→Win32Thread` field. When this field is NULL, the thread has no associated W32THREAD and GUI syscalls return `STATUS_INVALID_THREAD`.

6. Operators issuing GUI syscalls (for clipboard access via T-023 capabilities, window enumeration, input injection) must ensure the calling thread has been GUI-initialized. This means either calling a user32.dll API that triggers thread initialization, or manually calling the internal initialization function.

## OS Internals Context

The win32u.dll module was introduced in Windows 10 version 1703 as part of the User32 subsystem refactoring. Prior to win32u.dll, GUI syscall stubs were embedded directly in user32.dll (and the internal user32full.dll). The refactoring extracted these stubs into win32u.dll, which contains only the `syscall` instruction sequences — no additional logic. This mirrors the ntdll.dll pattern where syscall stubs are minimal wrappers around the `syscall` instruction.

The win32k.sys driver is the kernel-mode component of the Windows GUI subsystem. It maintains the Desktop heap, window objects, message queues, clipboard, and input processing. GUI syscalls enter win32k.sys through the `KeServiceDescriptorTableShadow` (the shadow SSDT), which is distinct from the `KeServiceDescriptorTable` used by native syscalls. The shadow table is only accessible to GUI-initialized threads — this is the enforcement mechanism for the thread type check.

The THREADINFO (W32THREAD) structure is allocated by win32k.sys when a thread first calls a GUI API. It is stored in the ETHREAD's Tcb (KTHREAD) `Win32Thread` field. The structure contains per-thread GUI state: a pointer to the thread's message queue, a pointer to the thread's desktop, the window station handle, and clipboard-related state. When `Win32Thread` is NULL, the win32k syscall dispatcher (the internal `NtUserThunk` or `Win32kApiCallout`) rejects the call with `STATUS_INVALID_THREAD` before any work is performed.

EDR hooking on win32u.dll follows the same inline hook pattern used on ntdll.dll: the EDR overwrites the first bytes of the syscall stub with a JMP to the EDR's hook function. The hook function inspects the syscall parameters, logs the call, and either passes through to the original syscall or blocks it. An operator who restores ntdll.dll's .text section from a known-good on-disk copy (the T-016 NTDLL unhook technique) does not affect win32u.dll hooks — these are separate modules with separate .text sections.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the architectural distinction between native and GUI syscall paths. The HUGIN source tree's syscall techniques (`dark_crystal/crowd/src/sys_recycled.rs` for RecycledGate, `dark_crystal/crowd/src/veh_gate.rs` for VEH Gate, `dark_crystal/crowd/src/hells_gate.rs` for SSN resolution) all target the ntdll.dll native syscall surface. An implementation extending these to win32u.dll would require: (1) resolving win32u.dll's base address via the PEB `InMemoryOrderModuleList` walk (the existing `resolve.rs` PEB walker can find win32u.dll by module name), (2) parsing win32u.dll's export table to locate GUI syscall stubs by name (`NtUserOpenClipboard`, `NtUserFindWindowEx`, etc.), (3) applying the same SSN extraction and indirect dispatch techniques used for ntdll syscalls. The client_rust crate's GUI capabilities (`clipboard.rs`, `input.rs`, `cursor_hider.rs`, `overlay.rs`) all use Win32 APIs that eventually route through win32u.dll — these are the operations that remain visible to EDR even after ntdll unhooking.

## Why It Matters

The vault's syscall dispatch techniques (T-001 RecycledGate, T-002 Hell's Gate, T-003 VEH Gate) and evasion suite (T-016) all focus on the ntdll.dll native syscall surface. T-023's client capabilities (clipboard monitoring, input injection, screen capture, cursor hiding) depend on GUI APIs that route through win32u.dll. Without addressing win32u.dll hooks, an operator who unhooks ntdll to evade detection on native syscalls remains fully visible for all GUI operations. This card documents the gap and the architectural reason it exists: Windows has two syscall dispatch paths, and evading one does not evade the other.

## Detection Considerations

- **Telemetry sources**: EDR products hook win32u.dll syscall stubs for `NtUserOpenClipboard`, `NtUserGetMessage`, `NtUserSetClipboardData`, `NtUserFindWindowEx`, and other GUI functions. ETW providers (`Microsoft-Windows-Win32k`) emit events for GUI operations. The kernel's win32k.sys callbacks (`SetWinEventHook` callbacks, window hook callbacks) provide visibility into GUI operations from kernel mode.
- **Bypass options**: Applying the same indirect syscall technique (T-001 RecycledGate) to win32u.dll stubs — resolving the SSN from win32u.dll's stub bytes and dispatching through a gadget — bypasses user-mode hooks on win32u.dll. This requires extending the SSN extraction to parse win32u.dll's stub format, which may differ from ntdll.dll's stub layout. Restoring win32u.dll's .text section from a known-good on-disk copy mirrors the T-016 NTDLL unhook approach but targets a different module.
- **Residual artifacts**: Thread initialization for GUI use creates a W32THREAD structure visible in kernel thread objects. win32u.dll module resolution via PEB walk is visible to memory scanners that monitor module enumeration patterns. GUI operations produce kernel-level ETW events from win32k.sys that user-mode hook bypasses do not suppress.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall dispatch targeting ntdll.dll stubs; the same technique must be extended to win32u.dll for GUI syscall coverage.
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution cascade for ntdll syscalls; GUI syscall SSNs require similar extraction from win32u.dll stubs.
- **T-016 EDR Evasion Suite** — NTDLL unhook restores only the native syscall surface; win32u.dll remains hooked.
- **T-023 Client Capabilities** — Clipboard, input, screen capture, and cursor hiding capabilities route through win32u.dll GUI syscalls.

## References

- Atlas material: atlas-edr-evasion-part2.md, atlas-edr-evasion-part4.md
- MITRE ATT&CK: T1106 (https://attack.mitre.org/techniques/T1106)
- LGTM notes: lgtm:win32u-gui-syscall-hook-coverage, lgtm:gui-vs-native-syscall-path-awareness
- Public references: SEC670 EDR evasion module

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. The HUGIN source tree's syscall implementations (dark_crystal/crowd/src/sys_recycled.rs, src/veh_gate.rs, src/hells_gate.rs) target ntdll.dll; win32u.dll coverage requires extending the SSN extraction and dispatch to the GUI syscall module.