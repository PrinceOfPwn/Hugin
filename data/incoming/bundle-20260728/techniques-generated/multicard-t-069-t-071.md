<!-- BEGIN CARD T-069 -->
---
id: T-069
name: DLL Export Mechanics as Injection Prerequisite
category: process-injection
tier: C
crate: none
source_file: none
mitre: T1055.001
tags: [dll-exports, declspec-dllexport, def-file, export-table, dllmain, loader-resolution, injection-prerequisite]
origin: atlas-synthesis
member_notes: [lgtm:dll-export-for-injection-surface]
---

# DLL Export Mechanics as Injection Prerequisite — How Export Table Construction Enables DLL-Based Injection

## Summary

DLL export table construction determines which entry points an injected module exposes to the loader and to any remote invoker after it maps into a target process. SEC670 presents DLL construction with exported functions as a direct enabler of process injection: the export surface is what makes a DLL callable after `LoadLibrary` completes, whether invocation happens through `DllMain`, a remote thread pointed at an export, or an export-address hijack. The choice of export method — `__declspec(dllexport)`, a module-definition `.def` file, or `extern "C"` linkage — controls name decoration, ordinal assignment, and whether loader-side resolution via `GetProcAddress` by name or ordinal succeeds at all. This card documents that prerequisite layer rather than a standalone offensive capability. The primary detection surface is module-load telemetry combined with export-name and export-count heuristics applied to the loaded image.

## Mechanism

1. The linker emits an `IMAGE_EXPORT_DIRECTORY` into the PE and stores its RVA and size in `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` (index 0) of the optional header. The size field matters: it bounds the region in which EAT entries are interpreted as forwarder strings.
2. `__declspec(dllexport)` marks a symbol at compile time; the linker converts the mark into an Export Address Table (EAT) entry. Under C++ linkage the exported name carries the decorated form (`?Func@@YAHXZ`-style); adding `extern "C"` yields the undecorated name on x64.
3. A `.def` file `EXPORTS` section gives explicit control: the export name, the ordinal (`@N`), the `NONAME` attribute (ordinal-only export, no name string emitted), `PRIVATE`, and `DATA` for exporting variables. The linker `/EXPORT:name` flag is a third equivalent path.
4. The resulting directory contains three parallel arrays: `AddressOfFunctions` (EAT, RVAs of code), `AddressOfNames` (name pointer table, RVAs of ASCII strings), and `AddressOfNameOrdinals` (word indices mapping name position to EAT slot). `NumberOfFunctions` counts EAT entries; `NumberOfNames` counts named entries only.
5. When the loader maps the DLL — locally or inside a remote process via `LoadLibrary`/`LdrLoadDll` — it resolves the DLL's own imports, runs TLS callbacks, then calls `DllMain(DLL_PROCESS_ATTACH)` while holding the loader lock.
6. `GetProcAddress` resolves an export by binary-searching the sorted name table, indexing the ordinal array with the found position, and returning `ImageBase + EAT[index]`. Ordinal-based resolution subtracts `Base` from the ordinal and indexes the EAT directly, bypassing the name table entirely.
7. If the returned RVA falls inside the export directory's address range, it is a forwarder string (`NTDLL.RtlAllocHeap`-form) and the loader recursively loads and resolves the target.
8. Injection linkage, classic form: `CreateRemoteThread` (or `NtCreateThreadEx`) started on `LoadLibraryA`/`LdrLoadDll` with the DLL path executes `DllMain` in the target; the export table is what makes any *subsequent* step possible.
9. Injection linkage, export-invocation form: after the module maps, the operator resolves an export (by name or ordinal, remotely via `GetProcAddress` on a duplicated module handle or by parsing the export directory out-of-process) and redirects execution onto it — via a second remote thread, an APC, a thread-context hijack, or a callback registration.
10. Threadless injection (T-008) inverts the relationship: it patches the first bytes of a chosen *export* in an already-loaded module and self-restores, so the export table of the *victim* DLL is the targeting data.

## OS Internals Context

The PE specification requires the name pointer table to be sorted alphabetically; the loader's `LdrpFindExportedName` performs a binary search over it, so an unsorted table produces resolution failures that appear random to the caller. Ordinal-only exports created with `NONAME` shrink the string surface — the name table simply omits the entry while the EAT slot remains live — and `Base` (the ordinal bias, typically 1) defines the mapping between caller-supplied ordinals and EAT indices.

Name decoration is ABI-visible. On x86, `stdcall` exports acquire `_name@N` decoration and `GetProcAddress("name")` fails unless the `.def` file or a `#pragma comment(linker, "/EXPORT:...")` alias provides the undecorated alias. On x64 the single calling convention means `extern "C"` names are exported undecorated. C++ mangling makes exports unreachable by predictable string, which is sometimes desired and sometimes fatal depending on the invocation plan.

`DllMain` executes under `LdrpLoaderLock`. Inside it the module must not call `LoadLibrary`, must not call `GetProcAddress` on not-yet-initialized dependencies, and must not block on a thread it creates (thread initialization itself needs the loader lock — joining deadlocks the process). This contract is the principal reason export-invocation patterns exist: work performed from a separately-invoked export runs outside loader lock and may allocate, load further modules, and synchronize freely. Reflective loaders (T-046) replicate the loader's job manually and still must respect the same sequencing — their convention is to export a well-known entry (historically `ReflectiveLoader`) plus `DllMain`, so the export mechanics question does not disappear when the OS loader is bypassed; it is reimplemented.

WOW64 introduces a second consideration: a 32-bit DLL's exports are resolved by the 32-bit loader with 32-bit decoration rules, and architecture-mismatched modules cannot be loaded into a 64-bit process at all, which constrains which export surfaces a cross-architecture injection plan can use.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a build-side concern rather than a runtime module: a `cdylib` crate producing the payload DLL, exports declared with `#[no_mangle] pub extern "system" fn` (equivalent to `extern "C"` undecorated naming), optionally a build script emitting a minimal export surface with a single entry point (e.g., one `Run` export) so that loader-side resolution has exactly one target. A more aggressive variant would strip the name table entirely (ordinal-only, the `NONAME` equivalent) and hard-code the ordinal into the injector, removing export strings from memory scans at the cost of self-inflicted resolution complexity.

## Why It Matters

Every DLL-family injection method catalogued under T-013, the threadless export hijack of T-008, and the reflective loading of T-046 presuppose a correctly constructed export table; a malformed directory yields loader failure (`STATUS_INVALID_IMAGE_FORMAT`, error 0xC000007B) or an unresolvable entry point at the worst possible moment. The export surface also defines the detection surface: names, counts, and ordinals are static features visible to any scanner that parses the image. Documenting the mechanics as a prerequisite card prevents the details from being duplicated, shallowly, across every consuming technique card.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 7 (ImageLoaded) captures the DLL mapping into the target; ETW `Microsoft-Windows-Kernel-ImageLoad` and Threat-Intelligence providers expose module loads including remote-initiated ones. Static scanners parse `IMAGE_EXPORT_DIRECTORY` and flag anomalies: export names inconsistent with the DLL's claimed identity, single-export binaries, name/ordinal table mismatches.
- **Bypass options**: ordinal-only (`NONAME`) exports to remove name strings; export sets that mimic the legitimate DLL being impersonated; minimizing `DllMain` work so that module-load-time behavior matches benign DLLs; reflective loading to avoid the on-disk image entirely.
- **Residual artifacts**: the DLL file on disk for non-reflective variants, `InLoadOrderModuleLists` entries in the target PEB unless deliberately unlinked (see T-016), Prefetch and Amcache/ShimCache records of the module path.

## Related Techniques

- **T-013 Remaining Injection Methods** — callback, fiber, and PE-loader variants that consume a constructed DLL export surface as their invocation target.
- **T-008 Threadless Injection** — hijacks an export's first bytes in an already-loaded module; requires precise export-table parsing of the victim DLL.
- **T-046 Manual PE Loader and Reflective DLL Injection (sRDI)** — reimplements loader-side export resolution manually rather than relying on `GetProcAddress`.

## References

- Atlas material: atlas-exploit-dev-part14.md
- MITRE ATT&CK: T1055.001 — Dynamic-link Library Injection (https://attack.mitre.org/techniques/T1055/001/)
- LGTM notes: lgtm:dll-export-for-injection-surface

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-069 -->

<!-- BEGIN CARD T-070 -->
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
<!-- END CARD T-070 -->

<!-- BEGIN CARD T-071 -->
---
id: T-071
name: Hook Trampoline Infrastructure for Non-Reentrant Hooks
category: process-injection
tier: B
crate: none
source_file: none
mitre: T1055
mitre_secondary: [T1562.001]
tags: [trampoline, inline-hook, prologue-relocation, length-disassembler, hooking, unhooking, rip-relative, unwind-info]
origin: atlas-synthesis
member_notes: [lgtm:proposed-trampoline-infrastructure]
---

# Hook Trampoline Infrastructure for Non-Reentrant Hooks — Displaced-Prologue Preservation and Jump-Back

## Summary

A trampoline is a small executable stub that preserves the original prologue bytes displaced by an inline hook and returns control to the original function past the patch, making the hook non-reentrant. SEC670 presents trampolines as the infrastructure layer separating hook placement from original-function invocation: without the stub, a hook handler cannot call the function it replaced without recursing into itself. The construction problem is nontrivial because x86-64 instructions are variable-length and position-dependent instructions inside the copied prologue must be relocated. The same primitive serves offensive hooking (an implant intercepting APIs for its own purposes) and defensive-evasion unhooking (restoring bytes an EDR patched), which is why it warrants a standalone card rather than repeated treatment inside each consumer. Primary detection surface: memory scanners comparing in-memory `.text` against the on-disk image, and private executable pages that scanners attribute to trampoline storage.

## Mechanism

1. Read and save the original bytes at the target function entry; this copy serves both the trampoline and the eventual unhook/restore path.
2. Run a length-disassembler engine (hde64, Zydis, iced-x86 class) over the prologue to find the smallest instruction-aligned length greater than or equal to the patch size — 5 bytes for a near `E9 rel32` jump, 14 bytes for an absolute `FF 25 [rip+0]` indirect jump. Copying a partial instruction produces a corrupted stub that crashes on first call.
3. Allocate an executable trampoline buffer, ideally within ±2 GB of the target so 32-bit displacements remain usable; `NtAllocateVirtualMemory` accepts a base-address hint for this purpose.
4. Copy the whole instructions into the buffer, then relocate position-dependent ones:
   - RIP-relative memory operands (`mov rax, [rip+disp32]`): recompute `disp32 = OriginalTarget - (TrampolineBase + EndOfInstruction)`.
   - `E8`/`E9` rel32 call/jump: rewrite through an absolute indirect form with an embedded 64-bit pointer, or recompute the displacement if the destination remains in range.
   - Short jumps (`EB`, `70`–`7F`) and `loop`/`jrcxz`: promote to near conditional jumps (`0F 8x`) or absolute sequences, since rel8 cannot reach from the new location.
5. Append the jump-back: `E9 rel32` to `TargetFunction + DisplacedLength`, or the 14-byte absolute form if out of range.
6. Patch the target: change the containing page(s) to writable (`NtProtectVirtualMemory` → `PAGE_EXECUTE_READWRITE`), write the 5- or 14-byte redirect, restore protection, and call `FlushInstructionCache` so stale decoded lines are not executed.
7. The hook handler invokes the trampoline whenever it needs original semantics; control flows through the relocated prologue, jumps back past the patch, and the hook never re-enters itself.
8. Hotpatch variant: system DLLs compiled with `/hotpatch` begin with a 2-byte `mov edi, edi` (`8B FF`) preceded by five `0xCC` bytes. Overwrite the two bytes with `EB F9` (short jump back 5) and place the 5-byte far jump in the padding at `Function - 5`; only padding bytes are displaced, shrinking the trampoline to the 2-byte prologue plus jump-back.
9. Unhooking inverts step 6: write the saved original bytes back, restore protection, flush, and free the trampoline.

## OS Internals Context

The x86-64 ISA permits instructions of 1–15 bytes with legacy prefixes, REX, ModRM/SIB, and displacement fields; the length-disassembler pass is mandatory because instruction boundaries are not derivable from byte count. RIP-relative addressing is the default for x64 data references, which is why relocation is the common case rather than the exception — nearly every real prologue touching globals or IAT slots contains at least one RIP-relative operand.

Two failure modes receive little coverage elsewhere. First, unwind: the original prologue's addresses are covered by the module's `.pdata` `RUNTIME_FUNCTION` entries, but the relocated copy executes in private memory with no unwind registration. If an exception fires while a thread executes inside the trampoline, `RtlDispatchException` cannot build an unwind context for that RIP and the process terminates. Dynamically generated code is expected to call `RtlAddFunctionTable` or `RtlInstallFunctionTableCallback`; a correct trampoline implementation registers unwind metadata for its region. Second, concurrency: a multi-byte patch is not atomic, and a thread already executing the prologue mid-write observes torn bytes. Mitigations include suspending other threads during the write, staging with a single-byte `0xCC` plus a vectored handler, or using the 2-byte hotpatch short jump as an intermediate atomic step. Control-flow enforcement adds a further wrinkle on CET/IBT-enabled processes: jumping back into `Target+N` lands past the function's `ENDBR64`, which is legal for the jump-back path only because indirect-branch tracking applies to indirect branches taken through tracked call sites — implementations must verify the target process's CET policy before relying on this.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

Verification note: `dark_crystal/crates/core/src/experimental/evasion/veh/hooks.rs` defines a function named `syscall_trampoline`, but it is an empty `extern "C"` body used purely as a RIP-redirection landing pad so the VEH gate's single-step trace through ntdll maintains a benign call stack (T-003). It performs no prologue relocation and does not implement this card's mechanism. An actual implementation would be a standalone module exposing `hook_install(target, detour) -> trampoline` / `hook_remove(target)`: an iced-x86-based decoder pass for boundary detection and relocation, near-range allocation, unwind registration via `RtlAddFunctionTable`, and a restore path — consumed by the IAT camouflage, argument spoofing, and ntdll unhook logic currently catalogued under T-016 and T-020.

## Why It Matters

Trampoline construction is the shared, correctness-critical core beneath several techniques the vault already documents separately — inline hooking (T-030), ntdll restoration and the implant's own interception needs (T-016), and prologue-stepping evasions such as the KiUserExceptionDispatcher StepOver. Elevating it to its own card captures the relocation, unwind, and concurrency requirements once, at the depth they require, instead of as compressed asides. It is also the boundary between a functioning hook and an intermittent target crash: every consumer inherits whatever mistakes the trampoline layer makes.

## Detection Considerations

- **Telemetry sources**: EDR in-memory integrity checks diffing `.text` of loaded images against disk; scans for private pages with execute permissions (RWX or RX MEM_PRIVATE) hosting trampoline code; ETW Threat-Intelligence events for `NtProtectVirtualMemory`/`NtWriteVirtualMemory` against image memory; Sysmon Event ID 10 when patching is cross-process.
- **Bypass options**: hotpatch-preamble patching to minimize the byte diff; restore-original-after-use so the hook exists only for milliseconds; backing trampoline storage with MEM_IMAGE mappings in the style of T-006 rather than anonymous private memory; registering unwind metadata so scanner-triggered exceptions do not produce crash dumps pointing at the stub.
- **Residual artifacts**: modified page hashes while the hook is live, abandoned executable allocations after unhook, function-table registrations visible via `RtlEnumerateFunctionTableEntries`-style queries, and timing skew on the hooked API.

## Related Techniques

- **T-016 EDR Evasion Suite** — unhooking, argument spoofing, and KiUserException StepOver all consume or interact with trampoline infrastructure.
- **T-013 Remaining Injection Methods** — function-stomping and callback variants that overwrite code and require the same displaced-bytes preservation.
- **T-030 Inline Hook Implementation** — the hook-placement companion; the trampoline is its required counterpart for non-reentrancy.

## References

- Atlas material: atlas-edr-evasion-part5.md
- MITRE ATT&CK: T1055 — Process Injection (https://attack.mitre.org/techniques/T1055/); T1562.001 — Impair Defenses: Disable or Modify Tools (https://attack.mitre.org/techniques/T1562/001/)
- LGTM notes: lgtm:proposed-trampoline-infrastructure

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-071 -->