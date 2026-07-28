<!-- BEGIN CARD T-072 -->
---
id: T-072
name: PE Injection: Additional Image Loading (Non-Hollowing)
category: process-injection
tier: B
crate: none
source_file: none
mitre: T1055.002
tags: [pe-injection, additive-injection, non-hollowing, process-injection, manual-mapping, remote-image-load, memory-execution]
origin: atlas-synthesis
member_notes: [lgtm:pe-injection-additional-image-card]
---

# PE Injection: Additional Image Loading (Non-Hollowing) — Load a Second PE into a Live Process

## Summary

PE Injection, as distinguished from process hollowing in SEC670, loads an additional PE image into a target process without unmapping or replacing the original executable. The technique exploits the fact that Windows places no constraint on how many PE-formatted images a process address space may contain — only the loader-maintained module lists track the "official" set. Operators use it when the host process must remain intact and functional: the original binary stays mapped, its entry point and sections unmodified, while the injected image executes alongside it. The primary detection surface is the coexistence of two executable code regions in one process, where the second is either MEM_PRIVATE memory containing PE structure or MEM_IMAGE memory absent from the PEB loader lists.

## Mechanism

1. Open the target process via NtOpenProcess with PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ, plus an execution right (PROCESS_CREATE_THREAD for a new thread, or thread suspend/set-context rights for hijack-based entry).
2. Parse the payload PE locally: read IMAGE_NT_HEADERS64 to obtain OptionalHeader.SizeOfImage, SizeOfHeaders, ImageBase, AddressOfEntryPoint, and the data directories; walk the section table following the optional header.
3. Allocate memory in the target with NtAllocateVirtualMemory, size equal to SizeOfImage, MEM_COMMIT | MEM_RESERVE. The base is wherever the allocator places it — unlike hollowing, there is no requirement to land at the payload's preferred ImageBase, because the host image already occupies its own base.
4. Write the PE headers (SizeOfHeaders bytes) to the remote base via NtWriteVirtualMemory.
5. For each IMAGE_SECTION_HEADER, copy RawSize bytes from PointerToRawData to remote_base + VirtualAddress.
6. Apply base relocations: compute delta = remote_base − OptionalHeader.ImageBase, walk the IMAGE_DIRECTORY_ENTRY_BASERELOC blocks, and patch each IMAGE_REL_BASED_DIR64 entry in the remote image.
7. Resolve imports: walk IMAGE_DIRECTORY_ENTRY_IMPORT descriptors. For system DLLs, per-boot ASLR guarantees identical bases across processes, so addresses resolved locally (via export-table walking) are valid in the target; write them into the remote IAT at FirstThunk. Non-system dependencies require either a remote LoadLibraryW bootstrap call or recursive manual mapping.
8. Process TLS callbacks and delay-load descriptors if the payload requires them; shellcode-grade payloads typically skip this.
9. Set final per-section memory protections with NtProtectVirtualMemory (RW for .data, RX for .text), then NtFlushInstructionCache on any pages transitioned from writable to executable.
10. Trigger execution at remote_base + AddressOfEntryPoint, either by creating a thread (NtCreateThreadEx) or by redirecting an existing thread (CONTEXT modification or APC).
11. Leave the host image untouched: no NtUnmapViewOfSection, no PEB.ImageBaseAddress rewrite, no loader-list modification. The host resumes or continues normally.

## OS Internals Context

The loader tracks legitimately loaded images through three doubly-linked lists in the PEB (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList), each entry an LDR_DATA_TABLE_ENTRY. A manually mapped PE never receives an entry and is therefore invisible to EnumProcessModules and to any consumer of the loader lists — but also to legitimate unloaded-image bookkeeping, which is precisely the anomaly memory scanners look for. The memory classification determines the specific tell: an image delivered through NtAllocateVirtualMemory lives in MEM_PRIVATE pages and trips private-executable-memory heuristics; an image delivered through NtCreateSection with SEC_IMAGE followed by NtMapViewOfSection is MEM_IMAGE but unbacked by a loader entry, and requires the payload to exist as a file object (on disk, in an ADS, or in a delete-pending state — the delivery tricks documented in T-009 and T-010).

Relocations are mandatory in the additive case. Hollowing reuses the host's preferred base, so a payload with a stripped .reloc directory can work if written at that base; additive injection lands at an arbitrary ASLR-assigned address, so DIR64 fixups must be applied or the payload must be position-independent. Import resolution relies on the Windows per-boot ASLR model: kernel32, ntdll, and user32 load at identical bases in every process until reboot, making locally resolved export addresses directly usable in the remote IAT for system modules only.

The structural contrast with hollowing (bundled under T-013) defines the detection tradeoff. Hollowing unmaps the suspended host's image, writes the payload at the same base, and patches PEB.ImageBaseAddress — producing one image whose on-disk path no longer matches in-memory content. Additive injection produces a fully consistent host plus a second, unlisted code region. The hollowed-process heuristic (image path/base mismatch, modified original entry point) never fires; instead the two-image presence and loader-list inconsistency are the observable artifacts.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would assemble existing HUGIN components: the header/section parsing and relocation logic from `src/dark_crystal/crowd/src/pe_loader.rs` (currently used for in-process reflective loading), retargeted to a remote process via RecycledGate-routed NtAllocateVirtualMemory/NtWriteVirtualMemory calls; system-DLL import patching using addresses resolved by the T-002/T-050 walkers; and execution through `waiting_thread.rs` context redirection or `early_cascade.rs` APC dispatch rather than a new thread. None of the three source files provided with this cluster (browser_session.rs, fsm.rs, waiting_thread.rs) implement additive remote PE loading.

## Why It Matters

The vault's T-013 enumerates hollowing among the remaining injection methods but does not distinguish the additive variant, which SEC670 treats as a separate technique with a different operational profile: the host process remains stable and observable, there is no suspended-process window during setup, and the payload image can be re-entered after its first execution completes. The detection profile is correspondingly different — no image-path mismatch heuristic applies, and defenders must instead catch the loader-list-inconsistent image or the cross-process write sequence. Separating the two prevents operators from reasoning about one with the other's tradeoffs.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 8 (CreateRemoteThread) if execution uses a new thread; Sysmon Event ID 10 (ProcessAccess) for the handle acquisition; ETW Threat Intelligence cross-process NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory chains. Kernel image-load callbacks (PsSetLoadImageNotifyRoutine) do not fire for the private-memory variant because no SEC_IMAGE section backed by a real file is created by the loader.
- **Bypass options**: deliver the image as SEC_IMAGE from a legitimately named file (sacrificing the fileless property), stomp the DOS/NT headers after relocation and import resolution complete, reuse an existing thread for execution to avoid Sysmon 8, and encrypt sections between periods of use.
- **Residual artifacts**: the payload pages persist for the host's lifetime and are recoverable by memory acquisition; if SEC_IMAGE-backed, the backing file path or its delete-pending state is a disk-side artifact.

## Related Techniques

- **T-013 Remaining Injection Methods** — hollowing, the subtractive counterpart: same remote-image-writing mechanics, opposite treatment of the host image.
- **T-046 Manual PE Loader and Reflective DLL Injection** — the in-process analogue; identical parsing/relocation/import mechanics applied to the loader's own address space rather than a remote target.

## References

- Atlas material: atlas-exploit-dev-part19.md
- MITRE ATT&CK: [T1055.002 — Process Injection: Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/)
- LGTM notes: lgtm:pe-injection-additional-image-card

## Source Reference

No current implementation. Closest substrate for a future implementation: `src/dark_crystal/crowd/src/pe_loader.rs` (local PE mapping), `src/dark_crystal/crowd/src/mapping_inject.rs` (remote section mapping), `src/dark_crystal/crowd/src/waiting_thread.rs` (execution trigger).
<!-- END CARD T-072 -->

<!-- BEGIN CARD T-073 -->
---
id: T-073
name: Thread Context Hijack via CONTEXT Structure Modification
category: process-injection
tier: B
crate: dark_crystal
source_file: src/dark_crystal/crowd/src/waiting_thread.rs
mitre: T1055.003
tags: [thread-hijack, context-structure, rip-redirection, setthreadcontext, injection-primitive, waiting-thread, ntcontinue, rop-dispatch]
origin: atlas-synthesis
member_notes: [lgtm:proposed-thread-context-hijack-primitive]
---

# Thread Context Hijack via CONTEXT Structure Modification — Rip Rewriting as a Reusable Execution Primitive

## Summary

Thread context hijacking redirects an existing thread's execution by rewriting its CONTEXT structure — specifically the Rip register — through the NtGetContextThread / NtSetContextThread pair (exposed in Win32 as GetThreadContext / SetThreadContext). The technique exploits the OS contract that a suspended thread's complete register state is readable and writable by any handle holding THREAD_GET_CONTEXT and THREAD_SET_CONTEXT rights, with the kernel treating the saved trap frame as the authoritative source of user-mode state at resume. SEC670 establishes this as a primitive in its own right: it underlies remote thread hijack, initial-thread redirection in suspended sacrificial processes, and the Rip-redirected CONTEXT copies that Ekko-family sleep obfuscation dispatches through NtContinue. Operators use it to execute code on threads they never created, producing no thread-creation telemetry. The primary detection surface is cross-process context read/write sequences and threads resuming with Rip outside any loaded image.

## Mechanism

1. Locate a target thread: enumerate with Toolhelp Thread32First/Thread32Next, or parse NtQuerySystemInformation(SystemProcessInformation) output for per-thread SYSTEM_THREAD_INFORMATION records carrying ThreadState and WaitReason.
2. Open a handle via NtOpenThread with THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT (or THREAD_ALL_ACCESS, 0x1FFFFF).
3. Suspend the thread with NtSuspendThread. Context retrieval against a running thread returns stale, architecturally undefined state; suspension is what makes the register snapshot coherent.
4. Call NtGetContextThread with a CONTEXT whose ContextFlags field selects the register groups — CONTEXT_FULL (0x10000B on x64) captures control, integer, and segment registers.
5. Modify the structure: set Rip to the address of attacker-controlled code previously placed in the process; optionally load RCX/RDX/R8/R9 with arguments, align Rsp to 16 bytes, and reserve 0x20 bytes of shadow space if the payload expects standard calling-convention entry.
6. Call NtSetContextThread. The kernel copies the user-supplied structure into the thread's saved state.
7. Resume with NtResumeThread. The thread's next user-mode instruction executes at the new Rip; the original continuation is discarded unless the operator saved and later restores it.

## OS Internals Context

The x64 CONTEXT structure places ContextFlags at offset 0x30, Rsp at 0x98, and Rip at 0xF8, with the general-purpose registers Rax–R15 occupying 0x78–0xF0 and Dr0–Dr7 at 0x48–0x70. ContextFlags gates which fields the kernel honors: CONTEXT_CONTROL covers Rip/Rsp/EFlags, CONTEXT_INTEGER the GPRs, and CONTEXT_DEBUG_REGISTERS the Dr registers — the same field family manipulated by hardware-breakpoint tooling such as T-003's VEH gate and T-016's AMSI-HBP bypass.

The kernel path explains both the power and the timing semantics of the primitive. NtSetContextThread reaches PspSetContextThread, which writes the supplied values into the KTRAP_FRAME saved on the thread's kernel stack; when the thread resumes, the kernel-to-user exit path restores registers from that frame, so the redirect takes effect at the return to user mode. Because the trap frame is authoritative, a context set against a thread blocked inside a syscall takes effect when that syscall returns — which is why wait-state targeting works: the hijack lands at a defined wait-completion boundary instead of corrupting a thread mid-way through user code with live register dependencies. HUGIN's WaitingThread implementation selects threads in KTHREAD_STATE Waiting (5) whose KWAIT_REASON indicates deep sleeps — DelayExecution (4), WrUserRequest (13), WrQueue (15), WrLpcReply (17), WrAlertByThreadId (36) — and prefers the longest WaitTime as the safest candidate.

The primitive is dispatch-mechanism-agnostic and appears in three distinct operational shapes. First, remote hijack of an existing thread (WaitingThread). Second, initial-thread redirection in a suspended sacrificial process: CreateProcess with CREATE_SUSPENDED, then SetThreadContext on the initial thread instead of QueueUserAPC — the hollowing-family entry method. Third, in-process ROP dispatch: HUGIN's Ekko implementation captures the live thread's CONTEXT via RtlCaptureContext, then builds modified copies with Rip pointed at successive gadgets (VirtualProtect, SystemFunction032, WaitForSingleObject, SetEvent) and hands each copy to NtContinue through timer-queue callbacks. Same structure, same Rip rewrite, different consumer. The contrast with APC dispatch (T-012 Early Cascade) is the boundary condition: APCs require an alertable thread or the pre-LdrInitializeThunk window, while context hijack requires only suspend/set rights and works on non-alertable threads, at the cost of waiting for the target to vacate its current kernel wait.

On WoW64, a 32-bit thread requires WOW64_CONTEXT and the Wow64GetThreadContext/Wow64SetThreadContext variants; submitting an x64 CONTEXT against a WoW64 thread fails with STATUS_INVALID_PARAMETER.

## Key Implementation Details

`src/dark_crystal/crowd/src/waiting_thread.rs` implements the full primitive in its `inject()` function. Candidate selection runs through `query_process_threads()`, which calls NtQuerySystemInformation class 5 and manually walks the variable-length SYSTEM_PROCESS_INFORMATION list (fixed header 0x100 bytes on x86_64) to extract SYSTEM_THREAD_INFORMATION records; `find_waiting_thread()` filters for Waiting state and safe wait reasons, picks the maximum WaitTime, and opens the thread via NtOpenThread. Shellcode delivery uses section mapping — NtCreateSection with SEC_COMMIT, a local PAGE_READWRITE map for the copy, unmap, then a remote PAGE_EXECUTE_READ map — avoiding NtWriteVirtualMemory entirely. The hijack proper suspends the thread, zeroes a winapi CONTEXT, sets ContextFlags = CONTEXT_FULL, calls NtGetContextThread, saves the original Rip, assigns ctx.Rip = remote_base, and calls NtSetContextThread. The failure path restores the saved Rip and resumes, leaving the thread in its original state. Every NT call routes through `crate::recycled::invoke`, so the context operations themselves originate from ntdll gadgets (T-001).

`src/dark_crystal/crowd/src/fsm.rs` consumes the same primitive in-process inside `async_sleep_and_obfuscate()`: RtlCaptureContext snapshots the live thread through a timer-queue callback, then six heap-allocated CONTEXT copies receive Rip assignments to VirtualProtect (RW), SystemFunction032 (encrypt image), WaitForSingleObject (delay), SystemFunction032 (decrypt), VirtualProtect (RX), and SetEvent, each dispatched to NtContinue via CreateTimerQueueTimer.

## Why It Matters

Elevating CONTEXT modification to its own card separates the primitive from its consumers. WaitingThread, suspended-process initial-thread redirect, and Ekko's ROP dispatch all reduce to the same get/modify/set-Rip sequence; an operator who treats it as a primitive can assemble variants — pivoting a thread into a single gadget, or re-entering staged code — without introducing new APIs. It also carries a detection signature distinct from both thread creation (Sysmon 8 fires nowhere in the sequence) and APC queueing, which matters when choosing an execution trigger under a specific EDR's telemetry model.

## Detection Considerations

- **Telemetry sources**: ETW Threat Intelligence records cross-process NtSetContextThread; Sysmon Event ID 10 captures the OpenProcess/OpenThread access masks — THREAD_ALL_ACCESS (0x1FFFFF) from an unsigned or unsigned-path binary is a high-fidelity signal. No Sysmon Event ID 8 is generated because no thread is created.
- **Heuristics**: a thread resumed with Rip inside MEM_PRIVATE memory, or inside MEM_IMAGE memory absent from the PEB loader lists; suspend → get-context → set-context → resume sequences issued from a foreign process within a tight time window; observed execution addresses that never match the thread's recorded start address.
- **Bypass options**: target deeply waiting threads so the redirect coincides with a legitimate wait return; restore the original Rip after staging (the self-restoring philosophy of T-008); issue the context calls through indirect syscalls so their origin attributes to ntdll.
- **Residual artifacts**: none on disk. The operational artifact is host stability — the hijacked thread's original continuation is lost unless saved and restored, and careless hijacks of threads holding locks crash the host.

## Related Techniques

- **T-013 Remaining Injection Methods** — WaitingThread and the hollowing-family initial-thread redirect are consumers of this primitive.
- **T-005 Ekko ROP Sleep** — uses RtlCaptureContext plus Rip-redirected CONTEXT copies dispatched via NtContinue; the in-process ROP form of the same structure.
- **T-012 Early Cascade** — achieves the same goal, execution on an existing thread without creating one, through APC dispatch into the pre-LdrInitializeThunk window rather than context rewrite.

## References

- Atlas material: atlas-binary-analysis-part9.md
- MITRE ATT&CK: [T1055.003 — Process Injection: Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)
- LGTM notes: lgtm:proposed-thread-context-hijack-primitive

## Source Reference

`src/dark_crystal/crowd/src/waiting_thread.rs` — `inject()` (suspend/get-context/Rip-rewrite/set-context/resume block, with rollback on NtSetContextThread failure), `find_waiting_thread()`, `query_process_threads()`. In-process consumer: `src/dark_crystal/crowd/src/fsm.rs` — `async_sleep_and_obfuscate()` (RtlCaptureContext snapshot and six Rip-modified CONTEXT copies dispatched through NtContinue).
<!-- END CARD T-073 -->

<!-- BEGIN CARD T-074 -->
---
id: T-074
name: Sywshipers3: Random Syscall Dispatch via EGH
category: syscalls
tier: B
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1027]
tags: [syscalls, ssn, randomization, syswhispers, egg-hunter, indirect-syscall, wow64, edr-evasion]
origin: atlas-synthesis
member_notes: [lgtm:sywshipers3-random-syscall-dispatch]
---

# Sywshipers3: Random Syscall Dispatch via EGH — Randomized Dispatch Sites Against Static Signatures

## Summary

Sywshipers3, as named in the SEC670 training material (the publicly known SysWhispers3 generator), is a build-time syscall-stub generator whose dispatch philosophy is randomization rather than deterministic resolution. Its generated stubs use egg-hunter (EGH) style markers whose values are patched at generation time to the addresses of randomly selected `syscall; ret` gadgets inside ntdll, and it supports both x64 and WoW64 execution paths. Where HUGIN's syscall cards assume determinism — resolving the true SSN or routing through the matching function's gadget — this approach randomizes the dispatch site and stub byte shape per build so that static signatures on known stub sequences and call-site-to-syscall correlation fail. The primary detection surface is kernel-visible syscall-origin telemetry and consistency checks that compare the syscall's instruction pointer against the function its SSN implies.

## Mechanism

1. At build time, the generator emits per-function assembly stubs for the requested NT APIs, seeded with a per-build random value so that no two generations produce identical bytes.
2. Each stub embeds an egg: a placeholder constant marking the location where the address of a `syscall` instruction will be written. At generation time the egg is replaced with the address of a `syscall; ret` gadget belonging to a chosen ntdll export.
3. The jumper is randomized: rather than dispatching through the gadget of the function actually being invoked, the stub for one NT API may execute its `syscall` instruction from inside the body of an unrelated ntdll function. The training material describes this as direct syscall jumps to random syscall numbers, intended to defeat static pattern matching on syscall sequences.
4. The SSN loaded into eax remains the correct one for the intended function — randomizing eax itself would invoke the wrong syscall. The randomization covers the dispatch site and the stub shape, not the syscall identity.
5. For WoW64 callers, the generated code transitions from 32-bit to 64-bit execution via a far jump to code segment 0x33 (the Heaven's Gate transition documented in T-049), runs the same randomized stub in 64-bit mode, and returns to segment 0x23, allowing x86 payloads to issue native x64 syscalls without traversing the WoW64 sysenter layer.
6. At runtime the implant calls the stub as a normal function: arguments follow the Windows x64 ABI (RCX, RDX, R8, R9, stack spill for the remainder), the stub loads eax with the SSN, and control jumps through the egg-resolved gadget into the kernel.

## OS Internals Context

ntdll's .text section contains one `0F 05 C3` (syscall; ret) sequence per exported Zw*/Nt* stub — several hundred functionally identical gadgets on Windows 10/11, because the kernel dispatches purely on the value in eax. Any gadget can carry any SSN; pairing a gadget with its containing function is a convention the operating system never enforces. That convention is exactly what user-mode EDR hooks and naive origin attribution assume, and it is the assumption randomized dispatch violates deliberately.

Two defensive telemetry layers remain relevant. ETW Threat Intelligence (Microsoft-Windows-Threat-Intelligence) records syscall origin addresses and stack walks from kernel mode; a randomized jumper changes which ntdll function appears at the origin but preserves ntdll attribution overall — unlike direct syscalls (origin in the implant's own memory) or T-006 Phantom Stubs (origin in a forged MEM_IMAGE module). Second, an origin-consistency check — reading eax at syscall entry, mapping the instruction pointer to its containing export, and comparing the two — flags the mismatch this technique creates: NtAllocateVirtualMemory's SSN executing from inside NtCreateFile's body is anomalous under that model. The training material positions the randomization against static signature matching; against origin-consistency heuristics the technique trades one observable for another, which is why the deterministic matching-gadget discipline of T-001 RecycledGate exists as the alternative pole.

The WoW64 path matters for x86 payloads: 32-bit processes on 64-bit Windows normally reach the kernel through wow64cpu's TurboThunk dispatch, a layer defenders can instrument. A far jump to segment 0x33 bypasses that layer entirely and executes the native syscall instruction directly. Build-time seeding is the supply-side property: because stub bytes and gadget targets differ per generation, YARA rules written against published generator output fail against rebuilt implants — the evasion operates on the binary before it ever runs.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

HUGIN's existing dispatch modes are all deterministic: RecycledGate (`src/dark_crystal/crates/core/src/sys_recycled.rs`, `sys_indirect.rs`) routes each call through the matching function's own gadget, the T-002 cascade (`sys_resolve.rs`, `src/dark_crystal/crowd/src/hells_gate.rs`) resolves true SSNs via Zw* RVA sorting, and the T-003 VEH gate dispatches through hardware breakpoints with no stub in the call path. A randomized-jumper mode would reuse the T-002 enumeration substrate directly: the RVA-sorted Zw* table already yields the address of every `syscall; ret` gadget in ntdll, so the implementation would select a per-build or per-call random entry other than the matched one as the jump target while keeping eax as the resolved SSN, exposed as a fourth dispatch mode alongside RecycledGate, VEH, and Direct. WoW64 support would additionally require the 0x33 far-jump transition stubs.

## Why It Matters

This card documents a dispatch philosophy the vault's syscall coverage does not otherwise represent: randomization of the dispatch site as the primary evasion axis, accepted at the cost of IP/SSN inconsistency. It is also the documented WoW64-aware counterpart for x86 payloads, a population HUGIN's x64-focused gates do not serve. Recording the tradeoff explicitly — static-signature resistance versus origin-consistency exposure — lets an operator select the dispatch mode that matches the target EDR's telemetry model rather than defaulting to determinism.

## Detection Considerations

- **Telemetry sources**: ETW Threat Intelligence syscall-origin and stack-walk records; EDR kernel sensors that map syscall instruction pointers to containing ntdll exports; static AV and YARA signatures on known generator stub shapes (defeated by per-build seeds).
- **Bypass options**: when origin-consistency heuristics are in play, restrict the gadget pool to the same function's gadget — which collapses the technique into T-001 RecycledGate; combine with NTDLL unhooking (T-016) so the gadget pool itself is free of inline patches; per-build reseeding to defeat published byte signatures.
- **Residual artifacts**: none on disk at runtime — stubs live in the implant's .text. Build pipelines retain generated header and assembly files whose format is itself an indicator for known generator output.

## Related Techniques

- **T-001 RecycledGate** — the deterministic inverse: indirect dispatch through the matching function's gadget, preserving IP/SSN consistency instead of randomizing it.
- **T-002 Hell's/Halo's/Tartarus Gate + FreshyCalls** — shares the ntdll Zw* enumeration substrate that a random-gadget selector would draw its pool from.
- **T-003 VEH Syscall Gate** — an alternate dispatch mechanism with no stub bytes in the call path at all.
- **T-006 Phantom Stubs** — attacks syscall-origin attribution from a different angle by backing stubs with forged MEM_IMAGE modules.

## References

- Atlas material: atlas-edr-evasion-part3.md
- MITRE ATT&CK: [T1106 — Native API](https://attack.mitre.org/techniques/T1106/)
- LGTM notes: lgtm:sywshipers3-random-syscall-dispatch
- Public references: SysWhispers3 (klezVirus) — the publicly known tool matching the training material's description of Sywshipers3

## Source Reference

No current implementation. Deterministic counterparts in HUGIN: `src/dark_crystal/crates/core/src/sys_recycled.rs` (RecycledGate matching-gadget dispatch), `src/dark_crystal/crates/core/src/sys_resolve.rs` and `src/dark_crystal/crowd/src/hells_gate.rs` (SSN resolution cascade providing the Zw* gadget enumeration substrate a randomized mode would reuse).
<!-- END CARD T-074 -->