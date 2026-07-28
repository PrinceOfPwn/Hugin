Let me analyze each cluster spec and produce the three cards.

**T-069: DLL Export Mechanics as Injection Prerequisite**
- Category: process-injection
- Tier: C
- member_notes: ['lgtm:dll-export-for-injection-surface']
- origin: atlas-exploit-dev-part14
- would_relate_to: ['T-013']
- Tags: dll, export, declspec, injection
- Content: DLL construction with exported functions as enabler of process injection. Export-method choice (__declspec vs .def file vs EXTERN_C) and how it affects loader-side resolution.
- Source: No matching source file implements this specifically. The provided source files are hooks.rs (VEH), lib.rs, hypnosis.rs — none implement DLL export mechanics. So "No current implementation in the HUGIN source."
- MITRE: Best fit... DLL injection is T1055.001. Export mechanics for injection — T1055.001 (Dynamic-link Library Injection) seems right. Or T1129 (Shared Modules)? The technique is about building a DLL with exports for injection. T1055.001 is the best fit.

**T-070: GUI Application Hook Injection via SetWindowsHookEx**
- Category: process-injection
- Tier: B
- member_notes: ['lgtm:gui-application-hook-injection-distinction']
- origin: atlas-binary-analysis-part4
- would_relate_to: ['T-013', 'T-007']
- Content: SetWindowsHookEx for injecting DLLs into GUI applications. Forced DLL load on next GUI message processing. Different module-load pattern than CreateRemoteThread.
- Source: No matching source implements SetWindowsHookEx injection. client_rust/src/input_blocker.rs uses WH_KEYBOARD_LL/WH_MOUSE_LL hooks but those are low-level hooks that run in the installing process context (not injected into target). Actually low-level hooks are called in the installing process's context via message loop — they don't inject DLLs into other processes. So no implementation. Keylogger.rs also uses hooks similarly. So "No current implementation in the HUGIN source."
- MITRE: T1055.001 (DLL injection) — SetWindowsHookEx injection is generally mapped to T1055.001. Some map to T1056.001 for keylogging hooks, but as injection it's T1055.001.

**T-071: Hook Trampoline Infrastructure for Non-Reentrant Hooks**
- Category: process-injection
- Tier: B
- member_notes: ['lgtm:proposed-trampoline-infrastructure']
- origin: atlas-edr-evasion-part5
- would_relate_to: ['T-016', 'T-013']
- Content: Trampoline stub that executes displaced original bytes and jumps back past the hook. Variable-length x86 decoding considerations. Unifies IAT camouflage, argument spoofing, KiUserException StepOver.
- Source: hooks.rs is provided — need to verify if it implements trampoline infrastructure. Looking at hooks.rs: it's the VEH syscall gate. It has `syscall_trampoline` — an empty benign function used to keep a clean call stack ("Trampoline benigno para mantener un call stack limpio"). That's a RIP-redirect target for stack cleanliness, not a classic inline-hook trampoline (displaced prologue bytes + jump back). Per Rule 8: at least ONE function must implement the primary mechanism the card describes. The primary mechanism is: preserve displaced prologue bytes in a stub, execute them, jump back past the hook. `syscall_trampoline` is an empty function used as a clean-stack landing pad — not a displaced-bytes trampoline. So it does NOT implement the technique. However, I can mention that the VEH gate uses a distinct concept (a clean-stack landing pad named syscall_trampoline) but does not implement displaced-prologue trampolines. Actually, per the template: "If only a related keyword appears in a comment or unrelated function, the file does NOT implement the technique." So I should write "No current implementation" and describe what an implementation would look like. I could note the VEH gate's syscall_trampoline is a different pattern (named similarly but functionally distinct). I'll keep it accurate: no displaced-bytes trampoline implementation exists; the name collision in veh/hooks.rs refers to a stack-hygiene landing pad, not prologue relocation.

Wait — also `ki_step_over.rs` (KiUserException StepOver) is in the vault per manifest but not provided. I can't cite line ranges for files not provided. I'll not claim source implementation.

- MITRE for T-071: hooking is T1055 (Process Injection) generally; MITRE doesn't have a specific trampoline technique. T1055 fits. Could also use T1562.001 (impair defenses) but the card frames it as infrastructure for both offensive hooks and unhooking. The primary: T1055. Let me use T1055 with secondary T1027 (obfuscation)? Hmm. Actually for hooking infrastructure, MITRE T1055 is the standard mapping (T-030 inline hook implementation card uses T1055 per the index). I'll use T1055, secondary T1562.001 perhaps. Let me check the existing card T-030: "Inline Hook Implementation: Red-Team Hooking Mechanics · MITRE T1055". T-071 is closely related to T-030 but cluster spec says relate to T-016 and T-013. I should only cross-reference from provided inputs (Rule 9) — but the vault context includes the full technique index, so I can reference T-030 as it exists in the index? Rule 9: "Only cross-references you can justify from the provided inputs." The vault context (Technique Index) is provided input. T-030 Inline Hook Implementation is in the index. Trampoline infrastructure is directly related to inline hook implementation — that's a well-justified reference. I'll include T-016, T-013 (from would_relate_to) and possibly T-030. The instructions say cross-reference would_relate_to; T-030 is a strong addition. I'll add it.

For T-069: related T-013, and also T-046 (Manual PE Loader / Reflective DLL Injection sRDI) is in the index — very relevant since the note says "The vault's T-013 covers callback and fiber-based injection but does not have a dedicated technique card for reflective DLL injection or DLL injection via exported function invocation." T-046 exists in the index (Atlas Expansion). That's justifiable from provided inputs. I'll reference T-013 and T-046.

For T-070: T-013, T-007, and maybe T-023 (client capabilities include keylogger via hooks, input blocker with WH_KEYBOARD_LL/WH_MOUSE_LL). The keylogger uses hooks but LL hooks don't inject. T-023 mentions "keylogger, browser hook" — browser_hook is MV3 extension. I could reference T-023's hook usage as related-but-distinct. Keep it to T-013 and T-007 plus maybe a note. I'll stick with the would_relate_to two and possibly mention T-023's input blocker as the adjacent (non-injecting) hook usage. That's justified from the index description "WH_KEYBOARD_LL/WH_MOUSE_LL hooks". Actually the manifest says input_blocker.rs role: "WH_KEYBOARD_LL/WH_MOUSE_LL hooks". Justified.

Now for each card, I need 800+ words minimum, target 1200-1800. Let me write deep content.

---

**T-069 Card content:**

Mechanism of DLL exports:
1. PE optional header DataDirectory[0] (IMAGE_DIRECTORY_ENTRY_EXPORT) points to IMAGE_EXPORT_DIRECTORY.
2. Structure fields: Characteristics, TimeDateStamp, Major/MinorVersion, Name (RVA of DLL name), Base (ordinal base), NumberOfFunctions, NumberOfNames, AddressOfFunctions (EAT RVA array), AddressOfNames (name pointer table RVA array), AddressOfNameOrdinals (ordinal index array).
3. __declspec(dllexport) — compiler/linker directive; with C++ gets name decoration unless extern "C"; DEF file gives control over names, ordinals, NONAME attribute; EXTERN_C prevents mangling.
4. Loader-side resolution: GetProcAddress walks AddressOfNames with strcmp (or binary search — names are sorted alphabetically; GetProcAddress does binary search), ordinal table maps name index to EAT index, EAT gives function RVA. Forwarded exports: EAT entry points into export directory range → string "NTDLL.RtlAllocateHeap".
5. For injection: Classic DLL injection — CreateRemoteThread on LoadLibraryA/LdrLoadDll with DLL path; loader calls DllMain(DLL_PROCESS_ATTACH) under loader lock. Export-based invocation: after load, invoke an export via CreateRemoteThread on the export address (what T-013 callback patterns, thread hijacking, or tools like sRDI's exported entry do). Export name choice affects detection: tools scan for suspicious exports; NONAME exports (ordinal-only) reduce string surface but complicate resolution.
6. DllMain constraints: loader lock (LdrpLoaderLock) — can't call LoadLibrary, CreateThread synchronization etc. inside DllMain; standard practice: DllMain spawns thread or export invoked separately.

OS Internals:
- IMAGE_EXPORT_DIRECTORY layout, EAT/ENT/EOT triad
- ordinal base, named vs ordinal exports
- name decoration: _Function@N stdcall x86, C++ Itanium-style mangling (?name@@...)
- .def file EXPORTS section, NONAME, PRIVATE, DATA, CONSTANT
- link.exe /EXPORT
- Loader: LdrpSnapThunk, GetProcAddress binary search over sorted names (LdrpFindExportedName), forwarded exports resolved recursively by loader (LdrpForwarder)
- Loader lock and DllMain contract (DLL_PROCESS_ATTACH etc.)

Why it matters: prerequisite for T-013 methods (callback injection with DLLs, threadless export hijack — T-008 hijacks exports!). Actually T-008 Threadless is export hijack — very relevant. The note only says T-013, but T-008 exists in the index: "Threadless — Export hijack, self-restoring". Export mechanics is directly relevant to threadless injection which patches an export. Justified from index. I'll add T-008 reference. Hmm, rule says only cross-references justified from inputs — T-008 is in the provided index with description "Export hijack, self-restoring" — clearly justified.

Detection: module load events (Sysmon 7 ImageLoaded), ETW Microsoft-Windows-Kernel-ImageLoad / Threat-Intelligence, LoadLibrary in CreateRemoteThread telemetry, exports with no imports, DllMain thread creation, etc.

---

**T-070 Card content:**

SetWindowsHookEx mechanics:
1. SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId): global hooks (dwThreadId=0) with hmod pointing to DLL containing lpfn cause the DLL to be mapped into every process that processes the relevant messages (GUI threads with message loops).
2. Hook types: WH_GETMESSAGE, WH_CALLWNDPROC, WH_CBT, WH_SHELL, WH_KEYBOARD (non-LL), WH_MOUSE (non-LL) — require DLL injection into target. LL variants (WH_KEYBOARD_LL=13, WH_MOUSE_LL=14) execute in installer context — no injection.
3. Kernel side: win32k.sys (now win32kfull.sys) maintains hook tables per-desktop/global in the kernel tagDESKTOP/tagTHREADINFO structures (aphkStart arrays indexed by hook type). When a message event occurs, KeUserModeCallback calls back into user32!__ClientLoadLibrary / user32 dispatches; the hook DLL gets loaded into the target via user32's callback mechanism: the kernel calls into user32.dll in the target process, which calls LoadLibrary on the hook DLL path (from the shared section). Actually details: SetWindowsHookEx registers in win32k; when target thread retrieves message (GetMessage), win32k invokes KeUserModeCallback → user32!ClientCallWinEventProc / for hooks: user32!__ClientLoadLibrary gets invoked which loads the DLL and resolves the proc via GetProcAddress, then calls it.
4. Requirements: target must have a message loop (GUI thread); payload runs next time the thread processes a message of the hooked type. To force: PostThreadMessage/SendMessage to the target thread.
5. Same bitness: DLL architecture must match target (x64 hook DLL for x64 processes; separate x86 DLL needed for WoW64 targets). Also UIPI (User Interface Privilege Isolation): can't hook higher-integrity processes from lower integrity (integrity level check — hooks can't cross up).
6. Invocation: the hook proc executes in target context; DllMain(DLL_PROCESS_ATTACH) also runs on load. Cleanup: UnhookWindowsHookEx.
7. Alternative: use SetWinEventHook? No — that's different (EVENT hook can be out-of-context). Keep to SetWindowsHookEx.

OS internals:
- win32k hook tables, tagHOOK structures, global vs per-thread hooks
- KeUserModeCallback mechanism (kernel → user callback via KiUserCallbackDispatcher in ntdll)
- user32.dll ClientLoadLibrary behavior
- The hook DLL path and proc offset stored in kernel; the delta (offset of lpfn from hmod) stored so target can compute address after ASLR-aware mapping — actually kernel stores the offset of the function relative to module base; target loads DLL (may be at different base pre-Vista; modern with ASLR each process maps at different base, kernel computes target address as base + offset). For this to work reliably the DLL is typically loaded at same base — historically Windows required that; with ASLR, win32k handles by storing module path and offset.
- Message loop requirement: threads without message pump never load the DLL.
- UIPI/integrity restrictions, session isolation (hooks are per-desktop; can't cross sessions).

Implementation: no current implementation in HUGIN. The input_blocker uses WH_KEYBOARD_LL/WH_MOUSE_LL which are non-injecting. What implementation would look like: build hook DLL exporting a callback, SetWindowsHookEx(WH_GETMESSAGE,...), trigger with PostThreadMessage, UnhookWindowsHookEx.

Detection: 
- Sysmon 7 (image loaded into many processes from unusual path), Sysmon 1 commandline, Event for SetWindowsHookEx — ETW Microsoft-Windows-Threat-Intelligence? Actually hook installation telemetry: Sysmon doesn't have direct hook event; but EDRs monitor SetWindowsHookEx calls and cross-process DLL loads.
- Global hooks loading unsigned DLLs into many GUI processes is a strong anomaly.
- Persistence angle: AppCert_DLLs / AppInit_DLLs similar pattern (T-038 exists). Related: T-038 AppInit_DLLs (same load-into-GUI-processes mechanism via user32). Justified from index. I'll reference T-038 too? would_relate_to says T-013, T-007. Rule 9 restraint — 2-4 entries fine. I'll do T-013, T-007, T-038 maybe. Hmm — T-038 AppInit_DLLs: "AppInit_DLLs Registry Persistence" — the mechanism (user32 loads DLLs into GUI processes) is directly analogous. I'll include it. Actually let me keep Related Techniques focused: T-013, T-007 (required), plus T-038 justified. Fine.

---

**T-071 Card content:**

Trampoline mechanics:
1. Inline hook: overwrite first N bytes of target function with jmp [rip+0]/absolute jump (5-byte E9 relative or 14-byte FF 25 indirect).
2. Displaced prologue bytes must be relocated into a trampoline buffer (RX memory allocated via VirtualAlloc/NtAllocateVirtualMemory).
3. Length-disassembler engine (LDE) — hde32/hde64, Zydis, distorm — determines instruction boundaries so at least 5 (or 14) bytes are copied without splitting an instruction.
4. Relocation problem: position-dependent instructions in the copied prologue (RIP-relative addressing: mov rax,[rip+disp]; rel32 jumps/calls E8/E9, short jumps EB/70-7F, loop) must be fixed up or rewritten when moved to a new address.
5. Trampoline layout: [copied + relocated prologue][jmp back to target+N].
6. Hook function calls trampoline to invoke original → non-reentrant (hook doesn't re-enter itself).
7. Edge cases: prologue contains jump table targets, hot-patching stubs (mov edi,edi 2-byte NOPs in system DLLs for hotpatch — hooking at -5 with 0xEB 0xF9 short jump back), exception handling (.pdata / RUNTIME_FUNCTION unwind info for prologue region — executing relocated prologue outside registered function range breaks unwind), CFI/CET shadow stack concerns, XFG.
8. Use in HUGIN-adjacent ops: unhooking ntdll (T-016), implant's own hooks (IAT camouflage T-020, KiUserException StepOver T-016), AMSI/ETW patches.

OS internals:
- x86-64 variable-length ISA, instruction prefixes, ModRM/SIB, RIP-relative
- Hot-patch prologues: Windows system DLLs compiled with /hotpatch → 2-byte mov edi,edi and 5 bytes of CC padding before function — classic hook uses short jmp -5 + 5-byte jmp at preamble.
- VirtualProtectEx to make .text writable (PAGE_EXECUTE_READWRITE) — telemetry.
- .pdata unwind: RtlAddFunctionTable / RtlInstallFunctionTableCallback for dynamically generated code — trampoline in heap/allocated memory lacks unwind info; if an exception fires while executing trampoline, RtlDispatchException can't unwind → process crash. Fix: register function table entries for trampoline region.
- Memory scanners look for RWX private pages and jmp at function entries of ntdll.

Implementation status: The provided hooks.rs implements the VEH gate; it contains `syscall_trampoline`, an empty no-op function used as a RIP redirection target to keep a clean call stack while single-stepping into ntdll — a stack-hygiene landing pad, not a displaced-prologue trampoline. Per Rule 8, that does not implement the card's primary mechanism (prologue relocation + jump-back). So: No current implementation. Describe what implementation would look like: LDE-based prologue copy, relocation fixups, jump-back emission, unwind registration.

Hmm wait — should I mention the syscall_trampoline at all? In "Key Implementation Details" the template says if no source implements: write the "No current implementation" line plus one paragraph on what implementation would look like. I can add a sentence clarifying the naming collision to preempt confusion. That's verification-driven and honest. I'll include it.

Detection:
- Memory scanning for modified .text (comparing to on-disk image), hooks detection by EDRs themselves
- RWX allocations, VirtualProtect on image sections
- ETW Threat Intelligence (EtwTi) logs for VirtualProtect/WriteProcessMemory on remote/image memory
- Trampoline regions in private memory lacking unwind info → crash artifacts

MITRE: T1055 (matches T-030). Secondary: maybe T1562.001? The card covers both offensive hooking and unhooking support. I'll add mitre_secondary: [T1562.001, T1027]? Keep it modest: T1055 primary. Secondary T1562.001 (Impair Defenses: Disable or Modify Tools) — unhooking ntdll impairs EDR instrumentation. That's fine.

For T-069 MITRE: T1055.001 primary. Secondary: T1027.007 (DLL obfuscation?) no — T1027.007 is dynamic API resolution. For export mechanics maybe T1129 (Shared Modules)? Not needed. Just T1055.001. Actually also relevant: T1574.002 (DLL Side-Loading)? Not what this is. Keep single.

For T-070 MITRE: T1055.001. Secondary T1546? No — hooks as persistence via AppInit is T1546.010 (that's T-038). SetWindowsHookEx injection maps to T1055.001. Good.

Frontmatter requirements:
- crate: none for all three (no source implementation). Wait — for T-071, hooks.rs exists but doesn't implement; crate should be... the frontmatter `crate` field: dark_crystal|client_rust|none. Since no implementation, `none` with source_file: none. For T-071, although hooks.rs is in dark_crystal, it doesn't implement the technique, so crate: none, source_file: none. I'll note the naming-collision in the body.

Actually, let me reconsider T-071 more carefully. The `syscall_trampoline` function: "Trampoline benigno para mantener un call stack limpio" — benign trampoline to keep a clean call stack. In HandlerHwBp, when the hardware breakpoint at the syscall entry hits, the handler sets RIP = syscall_trampoline and enables single-step. The purpose: the original stub's stack frame... The VEH gate walks through ntdll single-stepping until it can invoke the syscall with a clean stack. syscall_trampoline is an empty function that executes a `ret`-less no-op... wait it's `pub unsafe extern "C" fn syscall_trampoline() {}` — compiles to just `ret`. So RIP jumps to a ret, which pops the return address off the stack and returns — this manipulates the call stack so the subsequent single-step trace through ntdll has a "clean" frame. It's a stack-hygiene gadget, related conceptually to trampolines (small stub that transfers control) but NOT the displaced-prologue trampoline of inline hooking. Confirmed: does not implement T-071's primary mechanism.

Also check crowd files in manifest: arg_spoof.rs, ki_step_over.rs, ntdll_unhook_inject.rs — none provided in inputs, so I can't cite them as implementing. I can mention them via index (T-016 covers arg spoofing, KiUserException StepOver) as consumers that benefit — the note itself says that.

Word count: each card 1200-1800 words body. Let me write carefully and richly, but no padding.

No banned words: elegant, beautiful, clever, textbook, impressive, clean (careful! "clean call stack" — banned word "clean". The source comment says "limpia/clean call stack" — I must avoid the word "clean". I can say "benign call stack" or "unmodified call stack" or "stack hygiene". Avoid "clean" entirely.), slick, neat, well-crafted, robust (avoid), solid, nice, brilliant, sophisticated, notable, remarkable.

Banned phrases: "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core".

Careful with "clean" — also "cleanly" — avoid.

Tags for T-069: ['dll', 'export', 'declspec', 'def-file', 'export-table', 'loader-resolution', 'injection-prerequisite', 'pe-format'] — 5-10 kebab-case. Include origin tags? member notes tags given: ['dll', 'export', 'declspec', 'injection', 'proposed-technique']. I can craft: [dll-exports, declspec-dllexport, def-file, export-table, dllmain, loader-resolution, injection-prerequisite]. 7 tags.

Tags T-070: [setwindowshookex, gui-injection, dll-injection, message-loop, win32k, hook-dll, global-hooks]. 7.

Tags T-071: [trampoline, inline-hook, prologue-relocation, length-disassembler, hooking, unhooking, rip-relative, unwind-info]. 8.

References section: Atlas material: atlas-exploit-dev-part14.md (for T-069), atlas-binary-analysis-part4.md (T-070), atlas-edr-evasion-part5.md (T-071). MITRE URLs. LGTM notes IDs.

Source Reference: "No current implementation..." for each.

Now let me draft each card fully.

---

### T-069 draft

Frontmatter:
```yaml
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
```

Summary: DLL export table construction determines how an injected module's entry points become resolvable inside a target process. SEC670 frames DLL construction with exported functions as a direct enabler of process injection — the export surface defines what the loader and any remote invoker can call after the module maps. Choice of export method (__declspec(dllexport), module-definition .def file, extern "C" linkage) controls name decoration, ordinal assignment, and whether loader-side resolution (GetProcAddress by name or ordinal) succeeds. Primary detection surface: module-load telemetry and export-name heuristics.

Mechanism steps:
1. Linker emits IMAGE_EXPORT_DIRECTORY; DataDirectory index 0 (IMAGE_DIRECTORY_ENTRY_EXPORT) in optional header points to it, size covers forwarder strings.
2. Export via __declspec(dllexport): compiler marks symbol; linker emits EAT entry. C++ mangling unless extern "C".
3. Export via .def EXPORTS section: name, @ordinal, NONAME, PRIVATE, DATA.
4. /EXPORT linker flag alternative.
5. Loader maps DLL, resolves imports, calls TLS callbacks then DllMain(DLL_PROCESS_ATTACH) under loader lock.
6. GetProcAddress resolution path: binary search over sorted AddressOfNames, ordinal table index, EAT RVA; forwarder handling.
7. Injection linkage: classic CreateRemoteThread(LoadLibrary) relies on DllMain; export-invocation patterns resolve LoadLibrary remotely then queue/redirect execution onto export address; threadless export hijack patches export bytes (T-008); sRDI reflective loader exports entry by convention (ReflectiveLoader / DllMain).

OS Internals Context:
- IMAGE_EXPORT_DIRECTORY fields (Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals), all RVAs.
- Name sorting requirement (PE spec: names sorted for binary search); LdrpFindExportedName binary search.
- Ordinal-only exports via NONAME: NumberOfNames < NumberOfFunctions; gaps; ordinal base.
- Name decoration: x86 stdcall _name@N, C++ mangling; extern "C" yields undecorated on x64.
- Forwarded exports: EAT entry RVA within export directory range = forwarder string "DLL.Func"; loader resolves recursively (LdrpLoadForwardedDLL) — can pull in additional dependencies at resolve time.
- Loader lock: DllMain constraints — no LoadLibrary, no thread join; CreateThread allowed but don't synchronize; violations deadlock (LdrpLoaderLock held). Export-invocation after load runs outside loader lock — one reason operators prefer invoking an export over doing work in DllMain.
- WOW64: x86 DLL exports visible via 32-bit loader; name decoration differences.

Key Implementation Details: No current implementation. Paragraph: what an implant-side builder would do — minimal export surface, ordinal-only NONAME exports, DllMain that defers to a worker thread, or a single exported Run invoked post-load.

Why It Matters: Every DLL-based injection in T-013 family and threadless export hijack T-008 presupposes correct export construction; malformed export directory → loader failure codes (STATUS_INVALID_IMAGE_FORMAT / 0xC000007B) or unresolvable entry. Export surface also dictates detection surface. Foundational, not standalone.

Detection Considerations:
- Telemetry: Sysmon EID 7 ImageLoaded; ETW Kernel-ImageLoad; Threat-Intelligence for remote loads; module load without corresponding import references; export names scanned.
- Bypass: ordinal-only exports, benign-looking names, mimicking legitimate DLL export sets, forwarders to legitimate DLLs? (careful — say what operators do per material: material says little; general: reduce export strings).
- Residual: DLL on disk (if not reflective), prefetch, Amcache/ShimCache entries, load in InLoadOrderModuleLists (unless unlinked — T-016 PEB unlink).

Related Techniques: T-013, T-008 (threadless export hijack), T-046 (sRDI reflective loader).

References: atlas-exploit-dev-part14.md; MITRE T1055.001 URL; lgtm note.

---

### T-070 draft

Frontmatter: tier B, category process-injection, crate none, mitre T1055.001, mitre_secondary maybe [T1056.001]? Hook injection can double as keylogging, but card is about injection. Keep single T1055.001. Hmm, MITRE maps SetWindowsHookEx under T1055.001. Yes.

Summary: SetWindowsHookEx forces a hook DLL into processes owning GUI message loops when a global (or cross-thread) hook of a non-low-level type is installed. Distinct API surface from CreateRemoteThread; kernel (win32k) drives the load on next message dispatch. Detection: unsigned DLL loading into many GUI processes, SetWindowsHookEx call telemetry.

Mechanism:
1. Build hook DLL exporting hook proc (e.g., GetMsgProc for WH_GETMESSAGE) with correct signature LRESULT CALLBACK(int, WPARAM, LPARAM).
2. SetWindowsHookExW(idHook, lpfn, hmod, 0) global; win32kfull stores hook in global hook table of the desktop.
3. Kernel stores module path + offset of lpfn; when a GUI thread in another process calls GetMessage/PeekMessage or receives a message, win32k issues KeUserModeCallback → ntdll!KiUserCallbackDispatcher → user32 dispatch → user32!__ClientLoadLibrary loads the DLL into the target and resolves the proc.
4. DllMain(DLL_PROCESS_ATTACH) then hook proc run in target context.
5. Trigger: any message of hooked type; operators force with PostThreadMessage/SendMessage to known thread, or wait.
6. Repeat per process — every GUI process on the desktop loads the DLL.
7. UnhookWindowsHookEx removes registration; already-mapped DLLs stay mapped (unhook doesn't unload existing mappings? Actually UnhookWindowsHookEx causes the DLL to be unloaded on next message processing? The DLL may be unloaded when no longer referenced — Windows unmaps hook DLL when unhooked and next message processed. Historically: UnhookWindowsHookEx frees the hook; the DLL gets unmapped in targets on their next call. I'll state: after unhook, the DLL is eligible for unmapping in target processes during subsequent message dispatch — but not guaranteed immediate; safer to say mapping persists until unhook + message processing).
8. Constraints: architecture match (separate x86 build for WoW64 targets), UIPI blocks hooking higher-integrity processes, per-session/per-desktop scope.

OS Internals:
- win32k tagTHREADINFO.pDeskInfo → aphkStart hook array (WH_MAX+1 entries), global hooks in tagDESKTOP or shared info; tagHOOK with offPfn (offset from module base) so address can be recomputed per-process after independent ASLR mappings.
- KeUserModeCallback (ApiNumber for __ClientLoadLibrary) — kernel-to-user transition through KiUserCallbackDispatcher; user32 initializes callback table (apfnDispatch in USER32!gSharedInfo / kernelcallbacktable in PEB). The PEB.KernelCallbackTable pointer — user32 populates it during initialization; win32k invokes callbacks through it. This is the same table abused by some injection techniques.
- Only threads that convert to GUI threads (make a win32k syscall — PsConvertToGuiThread) and pump messages are affected; console-only threads never load the DLL.
- Message types: WH_GETMESSAGE fires when GetMessage/PeekMessage removes message from queue; WH_CALLWNDPROC on SendMessage dispatch; WH_CBT on window activation/creation; WH_SHELL on shell events.
- Low-level hooks (WH_KEYBOARD_LL/WH_MOUSE_LL) run in the installer's context via its own message loop — no injection; distinguishes implant's existing hook usage (input blocker/keylogger) from this technique.
- Integrity/session: UIPI (mandatory integrity) prevents lower-IL from hooking higher-IL; hooks scoped to desktop; Session 0 isolation.

Key Implementation Details: No current implementation. Note client_rust input_blocker/keylogger use LL hooks which do not inject — verified distinction. What implementation would look like: Rust DLL crate-type cdylib exporting GetMsgProc with #[no_mangle] extern "system", installer calls SetWindowsHookExW(WH_GETMESSAGE, proc, hmod, 0), PostThreadMessage to force dispatch, sleep, UnhookWindowsHookEx.

Why It Matters: Provides module-load primitive driven by kernel message dispatch rather than user-mode thread creation; evades CreateRemoteThread-centric detections; loads into many GUI processes simultaneously, giving broad implant surface (also noisy). Conditional on GUI targets.

Detection Considerations:
- Telemetry: SetWindowsHookEx API monitoring; ETW-TI; Sysmon 7 (same DLL ImageLoaded across many GUI processes from odd path); user32 load events; EDR hooks on SetWindowsHookEx / kernel callback table integrity.
- Bypass: sign DLL / plausible path (system32 look-alike), scoped thread-targeted hook (dwThreadId set) reduces fan-out, prompt unhook after execution, use of WH_CBT etc. that require fewer messages.
- Residual: DLL file on disk, loaded module list entries in all GUI processes, hook handle, potential delayed unmap.

Related: T-013, T-007, T-038 (AppInit_DLLs analogous user32-driven load), maybe T-023 input blocker distinction? Keep three entries: T-013, T-007, T-038. And maybe mention T-023 in Detection/Implementation? The input_blocker is client_rust WH_KEYBOARD_LL — I verified only via manifest description, and the note's distinction is my own. I'll mention in Key Implementation Details that existing client hook modules use low-level hooks that execute in installer context, which is not this technique. That references T-023? T-023 is in the index; justified. I'll add T-023 as related with one-liner? Hmm — "2 well-justified entries beat 8". I'll do T-013, T-007, T-038, T-023 = 4 entries, each with clear one-line relationship. Acceptable.

### T-071 draft

Frontmatter: tier B, category process-injection, crate none, source_file none, mitre T1055, secondary [T1562.001]. Tags as above.

Summary: A trampoline is a small executable stub that preserves an inline hook's displaced prologue bytes and returns control to the original function past the patch, making the hook non-reentrant. SEC670 units 22/23 present trampolines as the infrastructure layer that separates hook placement from original-function invocation. The implant side uses the same construction for its own hooks; the inverse (unhooking) restores original bytes.

Mechanism:
1. Read and save original prologue bytes of target function.
2. Run LDE (hde64/Zydis) to find minimal instruction-aligned length ≥ patch length (5 for E9 rel32, 14 for FF 25 [rip+0] absolute).
3. Copy that many whole instructions into executable trampoline buffer (VirtualAlloc RX/RW→RX).
4. Relocate position-dependent instructions: RIP-relative operands (recompute disp32 = orig_target - (tramp_end_of_insn)), rel32 call/jmp (rewrite as absolute via FF 15/FF 25 with embedded pointer or extend), short jcc (convert to near jcc 0F 8x or JMP), loop/jrcxz.
5. Append jump-back: E9 rel32 to target+displaced_len (if within ±2GB — same module image so usually fine) or FF 25 absolute.
6. Write hook: VirtualProtect PAGE_EXECUTE_READWRITE on target .text, write patch (E9 or hotpatch-style), restore, FlushInstructionCache.
7. Hook handler calls trampoline to reach original → no recursion.
8. Hotpatch variant: overwrite 2-byte mov edi,edi with EB F9 (jmp short -5), place 5-byte E9 at preamble (function-5) — displaces only the CC padding, smaller trampoline.
9. Unhook: restore saved prologue.

OS Internals:
- Variable-length x86-64: 1-15 bytes, prefixes (REX, 66/67, F2/F3), ModRM/SIB, disp; instruction-boundary preservation mandatory.
- RIP-relative addressing: default for x64 data refs; disp32 signed; trampoline typically in ±2GB of image? VirtualAlloc near target (VirtualAllocEx with hint / NtAllocateVirtualMemory with BaseAddress) keeps fixups simple.
- System DLL hotpatch prologues (/hotpatch): mov edi,edi (8B FF) + 5 bytes CC before entry.
- Exception/unwind: .pdata RUNTIME_FUNCTION covers original prologue addresses; executing relocated prologue in private memory has no unwind entry → exception during trampoline execution → RtlDispatchException walks and fails (STATUS_STACK_BUFFER_OVERRUN? no — unhandled exception → crash). Fix: RtlAddFunctionTable/RtlInstallFunctionTableCallback for the trampoline region (as done for JIT code), or restrict to leaf-safe usage.
- CET/IBT: ENDBR64 (F3 0F 1E FA) at function entries; indirect jumps to mid-function (past ENDBR) can fault under IBT if enabled for the process — trampoline jump-back lands at target+N which may lack ENDBR; user-mode CET for images on Win11. Keep brief and careful: mention as consideration.
- Synchronization: patch write is not atomic for multi-byte; concurrent threads executing prologue mid-patch → torn execution; options: suspend threads, hardware breakpoint staging, or 8-byte atomic qword write with EB FE spin-style? Common: use int3 + VEH staging. Keep to material-general: thread suspension or single-byte short-jump staging.

Key Implementation Details: No current implementation of displaced-prologue trampolines. Clarify: dark_crystal's VEH gate (experimental/evasion/veh/hooks.rs) defines `syscall_trampoline`, an empty `extern "C"` function used as a RIP redirection target for stack hygiene during single-step dispatch — a control-transfer landing pad, not prologue relocation; it does not implement this card's mechanism. What implementation would look like: LDE crate (e.g., iced-x86), near allocation, relocation pass, unwind registration, patch/restore API consumed by IAT camouflage, arg spoofing, and unhook modules.

Why It Matters: single primitive unifies several card internals (T-016 unhooking restore path, KiUserException StepOver stepping over hooked prologue, implant self-hooking); correctness boundary between reliable hook and crash.

Detection Considerations:
- Telemetry: EDR in-memory .text comparison vs disk image; RWX/private-exec page scans; ETW-TI for VirtualProtect/WriteProcessMemory on image memory; Sysmon 8 (CreateRemoteThread n/a), 10 (ProcessAccess if remote).
- Bypass: hotpatch-preamble patching smaller diff, restore-bytes-after-use, executing trampoline from MEM_IMAGE (phantom-style backing, cf. T-006) rather than private RWX, register unwind info to avoid crash artifacts.
- Residual: modified page hashes, abandoned executable private pages, function-table registrations, timing artifacts.

Related: T-016, T-013, T-030 (inline hook implementation — trampoline is its required companion). 

References: atlas-edr-evasion-part5.md; MITRE T1055 URL + T1562.001; lgtm:proposed-trampoline-infrastructure.

Now word counts — need ≥800 body words each; target 1200-1800. Let me write with depth. I'll write the final output now, being careful about banned words (check: "clean" — avoid; I'll use "hygiene", "benign"). Also avoid "robust", "solid", "notable". Avoid "essentially", "at its core".

Frontmatter mitre_secondary for T-069: omit or add T1129? Omit. For T-070: omit secondary. For T-071: [T1562.001].

Length check: I'll write generously. Let me produce the cards.

One more check on T-069's "Related Techniques": T-013 (required), T-008 threadless export hijack (index: "Export hijack, self-restoring" — directly export mechanics), T-046 (Manual PE Loader and Reflective DLL Injection (sRDI) — the LGTM note explicitly mentions reflective DLL injection gap and T-046 covers sRDI). Good, 3 entries.

T-070 Related: T-013, T-007, T-038, T-023. Good.

T-071 Related: T-016, T-013, T-030. Good.

Write everything in third person declarative. Ensure each Summary first sentence is standalone complete.

Also format: `source_file: none` and `crate: none`.

Let me now write the full cards.

For T-069 Mechanism, aim ~10 steps. OS Internals rich. Body words target ~1400.

T-070 ~1400. T-071 ~1400.

Check the "Key Implementation Details" exact required sentence: `**No current implementation in the HUGIN source.** This card documents the technique for future implementation.`

Include that verbatim, then one paragraph on implementation shape (plus for T-071 the clarification about syscall_trampoline naming collision).

References format:
- Atlas material: atlas-exploit-dev-part14.md
- MITRE ATT&CK: T1055.001 — Dynamic-link Library Injection (https://attack.mitre.org/techniques/T1055/001/)
- LGTM notes: lgtm:dll-export-for-injection-surface

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling."

Now write it all out.