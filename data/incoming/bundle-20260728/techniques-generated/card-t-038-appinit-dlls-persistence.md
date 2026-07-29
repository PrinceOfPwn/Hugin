---
id: T-038
name: AppInit_DLLs Registry Persistence
category: persistence
tier: A
crate: none
source_file: "none"
mitre: T1546.010
mitre_secondary: [T1055.001]
tags: [appinit-dlls, registry-persistence, user32-loading, dll-injection, hklm-hive, loadappinit-gate, gui-process-scope, wow6432node]
origin: atlas-synthesis
member_notes: ['lgtm:appinit-dlls-persistence-card', 'lgtm:proposed-appinit-dlls-persistence-card', 'lgtm:proposed-appinit-dlls-persistence']
---

# AppInit_DLLs Registry Persistence — User32-Conditional DLL Loading via HKLM

## Summary

AppInit_DLLs is a registry-resident persistence mechanism that forces every newly created user-mode process linked against user32.dll to load a comma-separated list of operator-controlled DLLs. The mechanism lives in two values under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`: `LoadAppInit_DLLs` (REG_DWORD), the gate that must be set to 1, and `AppInit_DLLs` (REG_SZ), the DLL path list. Because the OS loader itself performs the LoadLibrary calls inside each new GUI process, the technique delivers code execution across the entire user32-linked process graph without any remote-thread creation, memory allocation, or injection API calls. Writing the values requires administrative privileges (HKLM hive), and the gate is documented as disabled by default on recent Windows builds, so the operator must explicitly enable it. The primary detection surface is the registry write itself, the on-disk DLL, and the resulting unsigned-module load events repeating in every GUI process.

## Mechanism

1. The operator drops a malicious DLL to a stable on-disk path (commonly under `%SystemRoot%\System32` or a directory whose ACL matches the intended execution context). AppInit_DLLs loads from disk — there is no memory-only variant.
2. The operator sets `LoadAppInit_DLLs` (REG_DWORD) to `1` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`. This requires administrative privileges, as the key resides in the HKLM hive. The material documents this value as the enable gate for the entire mechanism.
3. The operator sets `AppInit_DLLs` (REG_SZ) in the same key to the DLL path. Per the material, the list can be comma-separated when more than one DLL must be loaded.
4. On 64-bit Windows, 32-bit user32-linked processes read the WOW64-reflected key at `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`. An operator targeting both architectures mirrors both values there with a 32-bit build of the DLL.
5. A new process is created by any means (Explorer double-click, `CreateProcess`, service spawn). The kernel creates the EPROCESS, ntdll maps the image, and the user-mode loader resolves static imports.
6. If the process links against user32.dll — statically via its import table, or dynamically when it first creates a GUI thread — user32.dll's client initialization path reads the `AppInit_DLLs` value from the registry and calls `LoadLibrary` on each entry in the list.
7. The loaded DLL's `DllMain` executes with `DLL_PROCESS_ATTACH` inside the new process, under loader lock, before the process's own entry point runs meaningful application logic.
8. Steps 5-7 repeat for every subsequent user32-linked process created on the system, including elevated processes, installers, and browsers, until the values are removed or `LoadAppInit_DLLs` is set back to `0`.
9. Because the trigger is process creation itself, a DLL that spawns a user32-linked child process from `DllMain` re-enters the load path for the child. The material explicitly warns about these "infinite loading situations" (SEC670 Lab 4.5, InitToWinInit) — the DLL must detect it is already resident and return immediately.

## OS Internals Context

The registry key hosting the mechanism, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, is the Windows subsystem configuration key. It holds other win32 subsystem parameters (such as `SharedSection`, which sizes desktop heaps) that are read at subsystem initialization. The AppInit mechanism is not a notification callback or a Run-key-style logon trigger; it is a behavior compiled into the user32 client-side initialization contract: when a thread converts to a GUI thread and user32.dll initializes in the process, user32 reads the value and loads the listed DLLs through the normal loader.

This has two consequences that define the technique's profile. First, the module is loaded by the OS loader via `LoadLibrary`, which means it appears in the PEB loader lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`) as an ordinary `MEM_IMAGE` module in every affected process. This is the opposite OPSEC profile from the reflective loader in T-013, where the mapped image never appears in PEB lists. Second, execution happens under loader lock inside `DllMain`. Loader lock restricts `DllMain` to a narrow set of safe operations — no `LoadLibrary` of additional dependencies, no thread creation that waits on the new thread, no calls into DLLs that have not yet initialized. The recursion hazard the material names is a direct consequence: any action in `DllMain` that causes a new user32-linked process to spawn re-enters the AppInit load path for that child, and a DLL that lacks a self-residency check (for example, a named-mutex probe or a `GetModuleHandle` check against its own base) will recurse until resource exhaustion.

The "user32-conditional" scope is the technique's defining constraint, and the training material frames it as a selection criterion: in the SEC670 unit review, AppInit is presented as the correct technique specifically for processes linked against user32.dll, distinct from AppCert DLLs (which load via a different registry key and a different loader path into process creation) and from RunOnce (a one-shot logon trigger). Pure console processes and native applications that never load user32.dll never receive the DLL; processes that load user32.dll late (for example, a console binary that later calls `MessageBox`) receive it at that moment rather than at creation.

On version differences, the material documents that `LoadAppInit_DLLs` defaults to 0 on recent builds, which is why the enable write in step 2 is mandatory rather than optional. MSDN documentation for the AppInit_DLLs value additionally describes signing requirements and Secure Boot interactions on Windows 8 and later; the material does not elaborate on these, so the operational summary stands at: the gate must be explicitly set, and on hardened builds the mechanism may be constrained further by platform policy.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for the reference walk-through in SEC670 Book 4 (Lab 4.5, InitToWinInit) in C.

The three candidate files matched by keyword grep were verified and rejected: `browser_hook.rs` implements Run-key and shortcut persistence for a browser extension, not AppInit; `chain.rs` and `edo_tensei.rs` orchestrate the T-017 five-layer persistence suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist), which contains no AppInit layer.

An implementation consistent with the existing codebase would be a sixth module under `dark_crystal/crowd/src/persist/`, modeled on `com_hijack.rs`: the two registry writes issued via `NtSetValueKey` through RecycledGate rather than the Win32 `RegSetValueExW` path, the DLL dropped to a fixed path with a name blending into System32, and the DLL itself built with a `DllMain` whose first action is a residency check (named event via `NtOpenEvent`, mirroring the mutex pattern already used by the TLS-callback layer in T-017) before any payload logic runs, so the infinite-loading hazard documented in the material is structurally avoided. Integration into `persist::PersistConfig` would let the resilience monitor re-apply the values on its 30-minute sweep like the other layers.

## Why It Matters

T-017's five layers cover COM invocation, NTFS metadata, scheduled tasks, PE modification, and shutdown interception — none of them provide execution inside every newly created GUI process as a byproduct of ordinary user activity. AppInit_DLLs fills that gap with a different trigger profile: arbitrary process creation events, including elevated installers and admin tools, rather than logon or COM activation. The material surfaces the technique across four separate SEC670 units and a dedicated lab, and documents historical use by APT39, CherryPicker, and T9000, which establishes both its pedigree and the fact that defenders monitor it — an operator trades stealth for an execution reach that the T-017 layers do not offer.

## Detection Considerations

The training material does not discuss operator-side detection evasion for this technique. It documents only the defender-side mitigation: `LoadAppInit_DLLs = 0` disables the mechanism entirely, and the notes record that recent Windows builds ship with this default.

- **Telemetry sources**: The enabling registry writes are observable by Sysmon Event ID 13 (Registry Value Set) against the `...\CurrentVersion\Windows` key, and by kernel registry callbacks (`CmRegisterCallback`) used by EDRs. Every resulting `LoadLibrary` of the DLL is visible to kernel image-load notification routines (`PsSetLoadImageNotifyRoutine`) and to Sysmon Event ID 7 (Image Load), producing a repeating pattern of the same unsigned module loading into many GUI processes. Sysinternals Autoruns enumerates AppInit_DLLs entries.
- **Bypass options**: None described in the material. The notes frame `LoadAppInit_DLLs = 0` as the documented mitigation, not a bypass step.
- **Residual artifacts**: The `LoadAppInit_DLLs` and `AppInit_DLLs` values (plus the WOW6432Node mirror on x64), the DLL file on disk, the module's presence in the PEB loader lists of every user32-linked process, and the Autoruns entry. Because the loader maps the DLL as `MEM_IMAGE`, the module is visible to any tool that walks `InLoadOrderModuleList`.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — The sibling persistence suite. AppInit_DLLs is a registry-resident layer absent from T-017's five mechanisms, with a distinct trigger profile (user32-linked process creation) that complements rather than duplicates COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist.
- **T-013 Additional Injection Methods** — Contrast in injection posture. T-013 methods deliver memory-only payloads into chosen targets with no disk DLL and no registry footprint (the Reflective PE Loader never appears in PEB lists); AppInit_DLLs achieves graph-wide DLL execution through the OS loader at the cost of leaving a visible module in every GUI process and two HKLM values.

## References

- Atlas material: `atlas-edr-evasion-part6.md` (unit 14 — AppInit vs AppCert vs RunOnce for user32-linked processes), `atlas-exploit-dev-part24.md` (unit 22 — Lab 4.5 InitToWinInit, infinite loading warning), `atlas-misc-part1.md` (units 5, 6, 8, 9 — registry values, user32 linking requirement, admin requirement, APT39/CherryPicker/T9000 use)
- MITRE ATT&CK: T1546.010 — Event Triggered Execution: AppInit DLLs (https://attack.mitre.org/techniques/T1546/010/)
- LGTM notes: `lgtm:appinit-dlls-persistence-card`, `lgtm:proposed-appinit-dlls-persistence-card`, `lgtm:proposed-appinit-dlls-persistence`
- Public references: SANS SEC670 Book 4 "Persistence: Die Another Day" Lab 4.5 (InitToWinInit); documented use by APT39, CherryPicker, and T9000 per the material and the MITRE T1546.010 entry

## Source Reference

No current implementation. See atlas material (SEC670 Lab 4.5 reference implementation in C) and the MITRE T1546.010 entry for public tooling.