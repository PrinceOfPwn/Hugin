---
id: T-070
name: GUI Application Hook Injection via SetWindowsHookEx
category: process-injection
tier: B
crate: none
source_file: none
mitre: T1055.001
tags: [setwindowshookex, gui-injection, dll-injection, message-loop, win32k, global-hooks, kernel-user-callback]
origin: atlas-synthesis
member_notes: [lgtm:gui-application-hook-injection-distinction]
---

# GUI Application Hook Injection via SetWindowsHookEx — Kernel-Driven DLL Load on Message Dispatch

## Summary

`SetWindowsHookEx` injects a DLL into GUI processes by registering a hook whose procedure resides in that DLL; the window manager (win32k) then forces the module to map into every process owning a thread that pumps the hooked message class. SEC670 identifies this API specifically as the injection vector for GUI applications, distinct from `CreateRemoteThread`-based methods: no remote thread is created, no remote allocation occurs, and the load is driven by the kernel's message-dispatch path through a user-mode callback. The mechanism is conditional on the target running a message loop — console processes and non-GUI threads never load the hook DLL. The primary detection surface is the fan-out pattern of one unsigned DLL loading into many GUI processes simultaneously, plus API monitoring on `SetWindowsHookEx` itself.

## Mechanism

1. The operator builds a hook DLL exporting a hook procedure with the prescribed signature, e.g. `LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam)` for `WH_GETMESSAGE`, declared `extern "C"` so the name resolves undecorated (see T-069 for export mechanics).
2. The installer calls `SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId)`. With `dwThreadId = 0` and `hmod` naming the DLL, the hook registers globally for the current desktop; win32k (win32kfull.sys on modern builds) records a hook object containing the module path and the offset of `lpfn` relative to the module base.
3. When any GUI thread on that desktop next processes a message of the hooked class — retrieving one via `GetMessage`/`PeekMessage` for `WH_GETMESSAGE`, receiving a `SendMessage` for `WH_CALLWNDPROC`, or window activation events for `WH_CBT` — win32k must invoke the hook in that thread's context.
4. win32k performs a kernel-to-user transition via `KeUserModeCallback`, which dispatches through `ntdll!KiUserCallbackDispatcher` into the user32 callback table. The relevant callback, user32's client-side library loader, maps the hook DLL into the target process with `LoadLibrary` and resolves the hook procedure address as `MappedBase + storedOffset`. Storing an offset rather than an absolute pointer is what allows the DLL to land at different bases in different processes under ASLR.
5. `DllMain(DLL_PROCESS_ATTACH)` executes in the target under loader lock; the hook procedure then executes on each subsequent matching message. Payload code can live in either location, subject to the loader-lock constraints of `DllMain`.
6. The load repeats independently in every GUI process on the desktop that touches the hooked message class — one registration yields many compromised processes.
7. The operator can force immediate execution in a chosen target by posting a message to its thread (`PostThreadMessage`) rather than waiting for organic message traffic.
8. `UnhookWindowsHookEx` removes the registration; mappings already present in target processes are released during subsequent message processing, not instantaneously.
9. Constraints gate every step: the DLL architecture must match each target (separate x86 and x64 builds are required to cover WoW64 processes), User Interface Privilege Isolation blocks hooking processes at a higher integrity level than the installer, and hooks are scoped to the installing desktop/session — Session 0 services are unreachable from an interactive session.

## OS Internals Context

The hook registry lives in kernel address space: each thread's `tagTHREADINFO` points to desktop info (`tagDESKTOP`) whose structures hold the per-type hook chains (`WH_MIN`..`WH_MAX` indexed arrays of `tagHOOK`). Because the registry is kernel-resident and the mapping is performed by user32 code executing inside the *target*, the operation never touches the target with `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` — the call sequence most EDRs weight heaviest.

The delivery path runs through the PEB's `KernelCallbackTable` (populated by user32 at initialization) and `KiUserCallbackDispatcher`. This is the same kernel-user callback machinery that other techniques abuse directly, which means hardened products sometimes watch the callback table for tampering even though this technique uses it as designed. Only threads that have converted to GUI threads (by making their first win32k syscall, triggering `PsConvertToGuiThread`) and that actually pump messages participate; a GUI process that stops pumping messages delays the load indefinitely, which is both a reliability constraint and a dormancy property.

Hook-type selection changes behavior. `WH_GETMESSAGE` fires on queue retrieval, `WH_CALLWNDPROC` on sent-message dispatch, `WH_CBT` on window lifecycle events, `WH_SHELL` on shell notifications. The low-level variants `WH_KEYBOARD_LL` and `WH_MOUSE_LL` are architecturally different: their procedures execute in the *installer's* context on its own message loop and inject nothing. This distinction matters for attribution — the HUGIN client's input blocker and keylogger use low-level hooks and therefore are not instances of this technique.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The existing client-side hook modules (`client_rust/src/input_blocker.rs`, `client_rust/src/keylogger.rs`) install `WH_KEYBOARD_LL`/`WH_MOUSE_LL` hooks whose callbacks run in the installing process; they do not perform the cross-process DLL mapping this card describes. An implementation would consist of a `cdylib` crate exporting a `#[no_mangle] extern "system"` hook procedure, an installer that calls `SetWindowsHookExW(WH_GETMESSAGE, proc, hmod, 0)`, a trigger (`PostThreadMessageW` against a thread ID obtained via `CreateToolhelp32Snapshot`/`Thread32Next` enumeration), dwell, then `UnhookWindowsHookEx`. Thread-scoped registration (nonzero `dwThreadId`) narrows delivery to a single target process at the cost of requiring a known GUI thread ID.

## Why It Matters

This is the named injection variant for GUI-heavy environments where targets of opportunity (browsers, Electron applications, explorer.exe) are guaranteed to pump messages, and where avoiding the `CreateRemoteThread` call graph removes the highest-signal telemetry an implant would otherwise generate. Its kernel-mediated load path also produces a different module-load provenance than user-mode injection — the mapping call stack terminates in user32's callback dispatch rather than in the injector process. The same fan-out property that makes it powerful (one registration, many processes) makes it loud, which bounds its operational window and justifies its B tier.

## Detection Considerations

- **Telemetry sources**: EDR API monitoring of `SetWindowsHookEx` with global scope; Sysmon Event ID 7 showing an identical, unusual DLL loading across many GUI processes in a short window; ETW Threat-Intelligence coverage of module loads; integrity checks on the kernel callback table by hardened products.
- **Bypass options**: thread-scoped instead of global hooks to eliminate fan-out; prompt `UnhookWindowsHookEx` after first execution; a DLL signed or placed under a plausible system path; selecting a hook type that fires on the first organic message to avoid synthetic message traffic.
- **Residual artifacts**: the hook DLL on disk, module-list entries in every affected GUI process until unmap, the hook handle in the installer, and delayed-unload mappings that persist briefly after unhooking.

## Related Techniques

- **T-013 Remaining Injection Methods** — callback-based execution family; this technique is the callback-dispatch variant mediated by win32k rather than by explicit API callbacks.
- **T-007 Pool Party / Injection Suite** — contrast point: worker-factory and thread-based methods that do create threads, highlighting the different telemetry profile.
- **T-038 AppInit_DLLs Persistence** — the persistence analogue: user32 loads registered DLLs into GUI processes via the same load-into-message-pump principle.
- **T-023 Client Capabilities** — contains the low-level keyboard/mouse hooks that share the API name but execute in installer context without injection.

## References

- Atlas material: atlas-binary-analysis-part4.md
- MITRE ATT&CK: T1055.001 — Dynamic-link Library Injection (https://attack.mitre.org/techniques/T1055/001/)
- LGTM notes: lgtm:gui-application-hook-injection-distinction

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.