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