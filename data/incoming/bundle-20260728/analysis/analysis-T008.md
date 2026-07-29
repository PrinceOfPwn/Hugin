---
id: T-008
name: Threadless Injection (Export Hijacking)
category: process-injection
tier: A
mitre: T1055
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: medium
requires: [T-004, T-001]
enables: [T-005, T-016]
min_windows: Windows 7 x64
needs_admin: conditional
tags: [injection, export-hijack, self-restoring, xmm-preservation, threadless, trampoline, relative-call, suspend-write-resume]
---

# Threadless Injection (Export Hijacking) — Operator Playbook

## TL;DR
Threadless Injection overwrites the first bytes of an exported function in a remote process with a 5-byte relative `CALL` to a 121-byte shellcode stub you've placed in a nearby "memory hole." The stub runs when the export is naturally invoked, preserves XMM0–XMM5 with `MOVAPS` save/restore, executes your payload, **writes the original 8 function bytes back into place**, and returns — leaving the target export byte-identical to its on-disk image after a single invocation. No remote thread is created. Use this when you want post-injection stealth without the noise of `CreateRemoteThread`/QueueUserAPC and when you can either wait for, or trigger, the export to be called.

## How It Works

The card describes the operational shape; the OS-level mechanism is:

1. **Resolve the target export's address.** Using the PEB walker (T-004), walk `LDR` lists in the remote process context (or via `NtQueryVirtualMemory` + module list walk on a duplicated handle) to find the export's RVAs in the loaded DLL. You obtain a `*const u8` for the first byte of the export function inside the remote process VA space.
2. **Save the original 8 bytes** at the export's entrypoint. Eight bytes (not five) are saved so the self-restore can fully erase a 5-byte `CALL rel32` plus a 3-byte alignment pad (`90 90 90` or instruction-boundary fill) without leaving a torn instruction. These 8 bytes are embedded inside the PATCH_SHELLCODE payload so they ride with the stub.
3. **Find a memory hole within ±0x70000000 of the export VA.** The relative `CALL rel32` instruction encodes displacement as a signed 32-bit value (±2 GB range). The code conservatively searches within ±0x70000000 (~1.75 GB) to leave headroom for ASLR slide and to guarantee the displacement fits without overflow. The "hole" is typically an unmapped region between module bases — located by scanning the VAD tree (`NtQueryVirtualMemory` with `MemoryInformationClass=MemoryRegionInformation` or by walking `MEMORY_BASIC_INFORMATION` until a `State == MEM_FREE` region of adequate size is found in the right displacement window).
4. **Allocate the hole.** `NtAllocateVirtualMemory` on the target process handle, `AllocationType = MEM_RESERVE | MEM_COMMIT`, `Protection = PAGE_READWRITE` initially (RWX is a strong EDR signal; flip to RX after write). Size = 121 bytes rounded up to page granularity by NT.
5. **Write the PATCH_SHELLCODE (121 bytes).** `NtWriteVirtualMemory` copies the stub into the hole. The stub layout, per the card, is:
   - `MOVAPS` saves of XMM0–XMM5 into a local stack scratch area (prevents corruption of floating-point state in the host export, which would crash anything using SSE in the function — gdi32, directx, etc.).
   - The actual payload body (your shellcode — typically a small reflective loader or stager).
   - The self-restore: `NtProtectVirtualMemory` (or direct write if RX is still RW during first call) the export's first 8 bytes back to the saved originals.
   - `MOVAPS` restores of XMM0–XMM5.
   - `RET` to the caller of the export (the call site continues execution at the byte immediately after the patched 5-byte `CALL`, which is now the original instruction — meaning callers see a transparent pass-through after first hit).
6. **Flip hole to RX.** `NtProtectVirtualMemory` to `PAGE_EXECUTE_READ`.
7. **Suspend all target threads.** `NtGetNextThread` loop or enumerate via `NtQuerySystemInformation(SystemProcessInformation)` → `NtSuspendThread` each. This is the race window: if a thread is mid-execution in the export's first 5 bytes during the write, you'll generate an access violation in the remote process. Suspension eliminates this.
8. **Write the 5-byte `CALL rel32` trampoline.** `E8 <disp32>` where `disp32 = stub_va - (export_va + 5)`. The remaining 3 bytes (8 total saved bytes minus 5-byte CALL) are filled with `0x90` NOPs or instruction-boundary padding so a disassembler doesn't see a torn instruction during the brief window before first invocation.
9. **Resume threads.** `NtResumeThread` each.
10. **Wait for (or trigger) the export call.** The export is now a trampoline. On first invocation, the stub runs, restores the original bytes, and returns. The export is now byte-identical to disk. Subsequent calls execute the original code with no trace.
11. **Payload persistence.** The payload (now executing inside the legitimate thread context of the remote process) is on its own — it must establish its own persistence (e.g., T-005 Ekko sleep, T-016 PEB unlink) since the trampoline is gone after first run.

## Operational Profile

### When to Use
- Targets where `CreateRemoteThread` is heavily monitored by EDR (CrowdStrike, SentinelOne, Elastic) and you want to avoid that signal entirely.
- Long-running target processes with frequently-called exports (e.g., `explorer.exe`'s `SHGetFolderPathW`, browser processes' export tables, `svchost.exe` service entry points).
- Engagement goals emphasizing low post-compromise noise — the self-restore means memory scanners see a clean export after one call.
- When you have a reliability mechanism to invoke the export (e.g., COM instantiation, service trigger, file-open dialog) so you don't have to wait passively.
- Medium-IL to medium-IL injections where you don't have admin and don't need cross-IL.

### When NOT to Use
- Targets with no predictable export calls (background services with sparse RPC entry points, kernel-mode, idle processes). The stub sits dormant forever and the 5-byte trampoline stays exposed.
- EDRs that scan export .text sections on a timer (some Memory Scanning engines do this post-KernelCallbackTable-tamper detections). The trampoline is visible for the entire window before first invocation.
- Cross-architecture (x86 → x64 or vice versa). `rel32` displacement only works in the same bitness.
- High-reliability required with no ability to suspend threads cleanly (e.g., targets where `NtSuspendThread` is itself alerted).
- Targets where the export is called with `Microsoft Telemetry` enabled hooks that hash the first bytes — these can fire before the self-restore completes.

### Kill Chain Position
Position: **late-stage execution placement** after you've gained initial foothold and a syscall layer is in place. Comes after API resolution and syscall dispatch, before sleep obfuscation and persistence.

Example chain:
T-004 (PEB walk for export resolution) → T-001 (RecycledGate for NtOpenProcess/NtAllocateVirtualMemory/NtWriteVirtualMemory) → **T-008 (Threadless)** → T-005 (Ekko ROP sleep in injected thread context) → T-016 (PEB unlink + handle blocking to harden the now-resident payload) → T-017 (five-layer persistence) → T-018 (Edo Tensei resurrection for the persistence layers)

Sibling injection techniques in the vault that operators should compare against: T-007 Pool Party (TP worker manipulation, also threadless-feeling but uses existing threadpool worker), T-012 Early Cascade (pre-LdrInitializeThunk APC — better for fresh process spawn), T-013 Module/Func Stomp (overwrites existing module/function — similar self-cleaning property but no trigger needed).

### Trade-offs

| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 8 | No remote thread; export restored to disk-clean state after first call. Trampoline window is the only signature. Loses points because suspension of all threads is itself a behavioral anomaly. |
| Reliability | 7 | Depends on finding a memory hole within ±0x70000000 of the target export — usually easy in x64 processes with ASLR gaps, but not guaranteed on densely-mapped processes. Race window during trampoline write mitigated by thread suspension but suspension can fail (e.g., system thread hold). |
| Complexity | 6 | Straightforward conceptually; the moving parts are: hole-finding heuristics, XMM preservation correctness, and the 5-byte displacement math. Single .rs file (~389 lines) is tractable. |
| Version range | Win7 x64 → Win11 24H2 | Uses core NT APIs (NtAllocateVirtualMemory, NtSuspendThread, NtWriteVirtualMemory) available since Vista x64. Newer Windows doesn't break this — but increases telemetry density. |
| Privilege needed | conditional | Same-IL injection into processes you can OpenProcess(PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| SUSPEND_RESUME) is sufficient. Cross-IL or session-boundary requires SYSTEM or matching token elevation. |

## Rust Implementation Deep Dive

> **Source availability note:** The technique card was provided but the annotated source extract for `dark_crystal/crowd/src/threadless.rs` was not included in this request. The deep dive below is reconstructed from the card's specific details (121-byte stub, XMM0–XMM5 MOVAPS preservation, 8-byte self-restore, 5-byte CALL, ±0x70000000 hole range) and general Windows internals. Operators modifying the code should grep for the identifiers mentioned below and verify against the actual file.

### `unsafe` boundaries you'll encounter
- **`NtAllocateVirtualMemory` call site:** unsafe because it dereferences a `*mut PVOID` for the base address and a `*mut SIZE_T` for size — both must be valid pointers in your own process VA, and the resulting allocation is in the **remote** process. Failure to free this hole on error path leaks 64KB in the target.
- **`NtWriteVirtualMemory` writes (×2):** unsafe because the source buffer must outlive the call (the stub is a `static` byte array, so OK), and the destination pointer arithmetic must be correct. The trampoline write destination is `export_va + 0` (first byte of export); the displacement computation `(stub_va as i64 - (export_va as i64 + 5)) as i32` must fit in `i32` — the ±0x70000000 search bound guarantees this.
- **Inline `MOVAPS` save/restore:** `core::arch::asm!` with `"movaps [rsp+0x{off}], xmm0"` style constraints. `MOVAPS` requires 16-byte alignment; the stub's prologue must `SUB RSP, 0x??` to a 16-byte boundary before issuing the saves, otherwise `#GP` fault in the remote process. This is the failure mode that XMM preservation is meant to *prevent* — but a misaligned prologue *causes* it.
- **Self-restore write back to export VA:** This write happens *inside* the target process, executed by the target's own thread. It uses `NtProtectVirtualMemory` (or a direct store if the page is RX — in which case the stub must first flip protection to RW, write, flip back to RX). Watch for: this is a self-modifying code sequence and some hardened exports are in `CFG`-protected modules where the protection flip may need the `PROCESS_VM_OPERATION` right.

### `core::arch::asm!` usage (card implies MOVAPS save/restore)
- Register constraints: `xmm0`–`xmm5` are caller-saved per the Win x64 ABI; preserving them across the stub is necessary because the export being hijacked may use them.
- Clobbers: `rax` (scratch for MOVAPS pointer), `rcx`/`rdx`/`r8`–`r11` (volatile, OK to clobber without save), `rflags`.
- Calling convention: the stub ends with `RET`, not a JMP, so the caller of the export sees a normal return. The return address on the stack is the caller's `RIP+5` (after the patched CALL) — but since the self-restore wrote the original bytes back, the byte at `RIP+5` is the original instruction stream. The caller continues normally.
- Critical detail: `RET` returns to `RSP+0` which is the caller's return address pushed by the CALL. Good. But the stub must not corrupt `RSP` — every `SUB RSP` in the prologue must be paired with an `ADD RSP` of identical size in the epilogue before RET.

### FFI patterns
- Handle ownership: the opened process handle (`HANDLE` from `NtOpenProcess`) must be `CloseHandle`'d on all return paths including error paths. A RAII guard (`struct OwnedHandle(HANDLE); impl Drop`) is the standard pattern in this codebase per T-021's Rust patterns card — grep for it.
- NT types: `OBJECT_ATTRIBUTES`, `CLIENT_ID`, `MEMORY_BASIC_INFORMATION` are declared via `windows_targets::link!` macros in `wrappers.rs` (referenced in T-021). Sizes: `MEMORY_BASIC_INFORMATION` is 48 bytes on x64. Pointer arithmetic on `BaseAddress` should use `usize` casting.

### Initialization
- Constants `PATCH_SHELLCODE` (121 bytes) and trampoline byte sequence are likely `const`/`static` items — should be `include_bytes!` or raw byte arrays.
- The ±0x70000000 bound is likely a `const MAX_REL_CALL_SEARCH: usize = 0x70000000;` or similar.
- No `OnceLock` expected here — this is a one-shot injection routine, not a long-lived singleton.

### Error paths
- Card doesn't specify, but the operator-grade behavior would be:
  - **Hole-finding failure:** return `Err(InjectionError::NoSuitableHole)` without writing anything. No state mutation in target.
  - **Suspend partial failure (some threads couldn't suspend):** abort the write, resume what you did suspend, return error. *Critical:* never write the trampoline if suspension is incomplete — that's the race that crashes the target.
  - **Write failure (e.g., PAGE_GUARD):** abort, free the hole, resume threads, return error.
  - **`NtProtectVirtualMemory` RX flip failure:** leave the hole as RW (not RX) — stub won't execute, but you've not corrupted the export. Operator can inspect and remediate.
  - **Crash behavior:** Rust `Result` based; no `unwrap`/`panic` in production builds (panic in remote injection context = process crash of your *own* loader, catastrophic for OPSEC).

### Memory layout
- `PATCH_SHELLCODE`: 121 bytes total. Decomposition (operator's reconstruction, verify in source):
  - ~40 bytes XMM save (`MOVAPS [rsp+X], xmmN` × 6 = ~24 bytes plus stack adjustment).
  - ~8 bytes stack prologue/epilogue.
  - Payload body — but 121 bytes is too small for a real payload. Likely a small trampoline that calls into a larger stager located elsewhere, or a `JMP` to a longer shellcode in the same hole (so the 121 bytes is the *self-restoring wrapper*, not the full payload). Verify.
  - 8 bytes embedded original-export-bytes (used by self-restore).
  - ~10 bytes self-restore write sequence (`MOV`, store, `MOVAPS` restore, `RET`).
- The hole allocation will round up to page granularity (4KB) by NT — the stub occupies the first 121 bytes; the rest of the page is unused and a memory scanner can detect "RX page with only 121 bytes of code at the start" as anomalous. Consider filling or placing the hole in a less-suspicious location.

## Edge Cases & Failure Modes

1. **Target process has no memory hole within ±0x70000000 of the export.**
   - Scenario: Densely-mapped processes (e.g., a busy browser with many loaded extensions, or a server process with hundreds of loaded DLLs).
   - What goes wrong: Hole finder returns empty; injection aborts.
   - Symptom: `threadless_inject` returns `Err(NoSuitableHole)` (or equivalent) before any state mutation.
   - Workaround: Fall back to T-007 Pool Party (uses existing threadpool worker, no hole needed) or T-012 Early Cascade in a freshly-spawned suspended process where you control the VA layout. Alternatively, expand the search bound to ±0x7FFFFFFF (full signed 32-bit range) — but verify no displacement overflow.

2. **Target export's first 8 bytes contain a relative jump/call within the first 5 bytes.**
   - Scenario: Export starts with `Jcc rel32` or `CALL rel32` that spans byte 0–4.
   - What goes wrong: Your 5-byte `CALL` overwrites only the first instruction; the remaining 3 bytes of the saved "original" are the start of the *next* instruction. Self-restore works fine, but the brief trampoline window may execute mid-instruction if a thread enters the function during the write — but you've suspended threads, so this is OK. Real issue: callers using `JMP` into the export's middle (not entrypoint) bypass your trampoline entirely.
   - Symptom: Stub never executes; trampoline sits dormant.
   - Workaround: Verify the export is only entered via its entrypoint (check callgraph statically if possible, or pick a different export). Pick exports with hot call paths.

3. **CFG (Control Flow Guard) is enabled on the target module.**
   - Scenario: Target DLL was compiled with `/guard:cf`. Direct calls into the export from other CFG-protected modules go through `__guard_dispatch_icall_fptr` which validates the target is in the bitmap of valid call targets.
   - What goes wrong: The export's entrypoint *is* a valid target, so the trampoline IS called normally — CFG doesn't see your modification because it validates the target address (the export), not the bytes there. So this is usually fine. BUT: if your stub in the hole is called *directly* (e.g., from another injected component), CFG will block it.
   - Symptom: Indirect dispatch fails with FAST_FAIL somewhere; direct export calls work.
   - Workaround: Always enter via the export. Don't call the stub from anywhere else. If you must, use T-006 Phantom Stubs (MEM_IMAGE-backed) which satisfy CFG's bitmap check.

4. **XMM register corruption despite MOVAPS save/restore.**
   - Scenario: Stack misalignment in the stub prologue — `MOVAPS` requires 16-byte alignment; if the prologue `SUB RSP, X` produces a non-aligned `RSP`, `MOVAPS` faults with `#GP`.
   - What goes wrong: Target process crashes with access violation inside the hijacked export.
   - Symptom: Target process dies immediately after first export call. Event log shows AV at the stub address. SOC will see this.
   - Workaround: Use `MOVUPS` (unaligned) for the saves instead — slower but bulletproof. Or verify prologue alignment statically: after the `CALL` pushes return addr, `RSP` is 8 mod 16; prologue must `SUB RSP, 0x28` (or 0x38, 0x48...) to reach 0 mod 16. Adjust the immediate.

5. **SuspendThread races with a thread currently inside the export.**
   - Scenario: Thread is executing past the first 5 bytes of the export when you suspend. You overwrite the first 5 bytes. Thread resumes, instruction pointer is *past* the trampoline, runs original code — but you've now got a trampoline that nothing calls.
   - What goes wrong: Stub never runs (trampoline never entered from entrypoint). Self-restore never triggers.
   - Symptom: Payload doesn't execute; target process appears unaffected.
   - Workaround: After write, check if any thread's RIP is within the first 5 bytes of the export. If so, that thread won't trigger the trampoline. Either pick a different export, or trigger the export yourself (e.g., via COM) from another thread/context.

6. **Trampoline displacement overflows i32.**
   - Scenario: ASLR slide puts the export and the chosen hole >2 GB apart despite the ±0x70000000 search bound (shouldn't happen if bound is enforced, but a bug in the hole finder could).
   - What goes wrong: `disp as i32` truncates; `CALL` jumps to wrong address → crash on first invocation.
   - Symptom: Target crashes immediately after first export call.
   - Workaround: Assert `(stub_va as i64 - export_va as i64).abs() < 0x7000_0000` before writing. Bail if not.

7. **EDR hooks NtSuspendThread on remote processes.**
   - Scenario: CrowdStrike Falcon, Elastic Endpoint, Microsoft Defender for Endpoint all flag bulk thread suspension as anomalous process tampering.
   - What goes wrong: Alert fires; SOC investigates; injection may complete but you're already burned.
   - Symptom: SOC alert "Process X suspended all threads of process Y" within minutes.
   - Workaround: Use T-003 VEH Gate's hardware-breakpoint-mediated dispatch instead of thread suspension — set a HW BP on the export's first byte, write the trampoline without suspending, let the BP fire and rewrite from your VEH. Requires more setup but eliminates the suspension signal. Alternatively, pick exports so rarely-called that you can write during a quiescent period without suspending (risk: rare race).

8. **Target process exits before first export call.**
   - Scenario: Short-lived process (e.g., `conhost.exe`, `RuntimeBroker.exe` instance).
   - What goes wrong: Trampoline sits dormant, process exits, no execution, no telemetry of failure but no success either.
   - Symptom: Operator sees no callback from the injected payload.
   - Workaround: Pick long-lived processes (explorer, svchost, dllhost with COM activity) or use T-012 Early Cascade to spawn a controlled process that runs your payload pre-`LdrInitializeThunk`.

9. **Memory scanner catches the RX hole page.**
   - Scenario: EDR with periodic memory scanning (Defender, SentinelOne) scans pages; an RX page with 121 bytes of code at offset 0 and zeros after is anomalous.
   - What goes wrong: Flagged as suspicious shellcode region; process killed or blocked.
   - Symptom: SOC alert "Unbacked executable memory in process X".
   - Workaround: Use T-006 Phantom Stubs to back the stub with a MEM_IMAGE page (a mapped section from a legit DLL). Or use T-013 Module Stomp / Module Overloading to place the stub inside an existing module's slack space — fully backed by a legitimate image.

## Variant Ideas

- **VEH-mediated variant (no suspension).** Combine with T-003 VEH Gate: set a hardware breakpoint (`Dr0`) on the export's first byte; when it fires, your VEH runs, performs the write of the trampoline+stub, clears the BP, and lets the export proceed. Eliminates the `NtSuspendThread` signal entirely. The VEH Gate already provides the HW BP mechanism.

- **Phantom-backed stub.** Use T-006 Phantom Stubs to allocate the 121-byte stub inside a `MEM_IMAGE`-backed page (map a clean section from `ntdll.dll` or similar). The stub then has module backing and survives memory scanner "unbacked RX" checks. Combine with the existing T-008 logic — only the hole-finding needs to constrain itself to image-backed regions.

- **Multi-export fan-in.** Patch the same stub across 3+ exports in different modules. First call restores all of them (since the self-restore writes back the specific export's bytes via a passed token). Increases probability of trigger on slow targets and provides redundancy if one export's caller pattern is unpredictable. Signature: more bytes written to more places, but each individual write is the same shape.

- **Timer-rotating trampoline.** Don't self-restore on first call. Instead, write a different export's first 5 bytes every N seconds via a worker thread, cycling through a set of exports. The trampoline "moves" — scanners that hash export bytes won't match a stable signature. Trade-off: more suspension events, more noise, but harder to baseline.

- **JMP rel32 variant (E9 instead of E8).** Using `JMP` instead of `CALL` means the return address isn't pushed — but the stub's `RET` then returns to *the caller of the export's caller*. Generally wrong for hijacking exports, but useful if you're patching an export that's *only* called via `JMP` tail-call (common in import thunks). The 8-byte self-restore and XMM preservation logic stay the same; just the displacement arithmetic changes.

- **CFG-bypassing variant for hardened targets.** Wrap the stub in a `MEM_IMAGE` mapping whose base is registered as a CFG valid call target via `NtSetInformationVirtualMemory(VmCfgCallTargetInformation)`. Combined with Phantom Stubs (T-006), this gives you a CFG-blessed stub location even on hardened modules. Operators hitting Windows 11 22H2+ with strict CFG should consider this.

- **Late-bind the payload.** The 121-byte stub is too small for a real payload. Variant: the stub's body is a `MOV RAX, <ptr>; JMP RAX` to a larger payload loaded by a different mechanism (T-006 phantom, T-013 module overload, T-007 pool party). The T-008 trampoline becomes a clean trigger mechanism; payload delivery is decoupled. Cleaner separation of concerns.

- **Stack-spoofed stub entry.** Combine with T-016 advanced stack spoofing: have the stub pivot RSP to a fake stack frame mimicking a legitimate caller before invoking the payload. Defeats EDR stack-walking telemetry that would otherwise see "shellcode with no module-backed return address."

## OPSEC Notes

- **Suspension telemetry.** `NtSuspendThread` on every thread of a remote process is the highest-signal artifact. Detections exist in CrowdStrike (Process Suspension behavior), Elastic (suspended_thread_count > N), MDE (Tampering: Process Suspension). Cleanup: nothing to clean — it's a behavioral signal, not an artifact. Avoidance: see VEH variant above.
- **`OpenProcess` rights.** You need `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION`. Requesting `PROCESS_ALL_ACCESS` is a flag. Request the minimum set.
- **RWX allocation in remote.** If you skip the `RW→RX` protection flip and allocate RWX directly, every EDR with `NtAllocateVirtualMemory` hooks will flag it. Always allocate RW, write, flip to RX. The 2x `NtProtectVirtualMemory` calls are still less suspicious than a single RWX allocation.
- **Unbacked RX page.** The 121-byte stub in a 4KB hole leaves a tell-tale pattern. Memory scanners flag unbacked RX regions of any size. Mitigate via T-006 phantom backing.
- **Modified export bytes during trampoline window.** Brief window where the export's first 5 bytes are `E8 xx xx xx xx`. If a scanner hits during this window, signature. Cleanup: the self-restore handles this, but the window exists from trampoline-write to first-call. Minimize: trigger the export immediately after write (e.g., if injecting into `explorer.exe`'s `SHGetFolderPathW`, send a `WM_SETTINGCHANGE` to trigger it).
- **Hole allocation leak.** If your loader errors out after allocating the hole but before self-restore completes, you've left a 4KB RX page in the target. Always `NtFreeVirtualMemory` on error paths. Grep for every `?` in the function and verify the cleanup branch.
- **Event log artifacts.** None directly from this technique (no service creation, no registry writes). Indirect: if the export crashes (XMM misalignment, displacement overflow), Application Error event 1000 logs the faulting module — clean this if you have the chance.
- **Handle leak.** The opened process handle, if not closed, appears in `System`'s handle table and is detectable via `NtQuerySystemInformation(SystemHandleInformation)`. RAII close on all paths.
- **Post-injection hardening.** Once the payload is running (post-self-restore), the only artifact left in the target is the 121-byte RX hole (if payload is elsewhere) or the larger payload region. Pair with T-016 PEB unlink (if your payload is a reflective DLL) and T-016 handle blocking (so the SOC can't duplicate-handle into your process to inspect).
- **Target process choice.** Pick a process that won't be killed by EDR cleanup if flagged. `svchost.exe` is risky (EDR protects it heavily); `dllhost.exe` (COM Surrogate) is good — common, expected to load varied exports, less protected. `explorer.exe` is acceptable but high-churn.

## Reusable Patterns

### Pattern: Suspension-Bounded Remote Write
- **Use when**: You need to atomically modify code in a running remote process (export patching, IAT edit, .text stomp) where a mid-write thread hit would crash.
- **How**: Enumerate threads via `NtQuerySystemInformation(SystemProcessInformation)`, `NtSuspendThread` each, perform the write, `NtResumeThread` each. Wrap in a guard struct that resumes on `Drop` even if the write panics.
- **Code ref**: `dark_crystal/crowd/src/threadless.rs` — the suspension-then-write sequence (also reusable in T-013 Module Stomp, T-013 Func Stomp).

### Pattern: ±0x70000000 Hole Finder
- **Use when**: You need a relative-branch target within signed-32-bit displacement of a given VA (relative CALL/JMP, CFG-target locations).
- **How**: Walk `MEMORY_BASIC_INFORMATION` from `target_va - 0x70000000` to `target_va + 0x70000000` looking for `State == MEM_FREE` of adequate size. Allocate via `NtAllocateVirtualMemory` with the discovered `BaseAddress`. The conservative bound vs the full ±2 GB rel32 range leaves headroom for ASLR slide and displacement arithmetic.
- **Code ref**: `dark_crystal/crowd/src/threadless.rs` — hole finder (also applicable to T-013 Mapping inject, T-006 Phantom Stubs).

### Pattern: XMM Save/Restore in Inline Asm
- **Use when**: Your shellcode/stub runs in the context of a target thread whose floating-point state you must not corrupt — particularly when hijacking functions in `gdi32`, `d3d*`, `user32` (which may have XMM live at entry).
- **How**: Prologue `SUB RSP, 0x60` (96 bytes, room for XMM0–XMM5), `MOVAPS [rsp+0x00], xmm0` ... `MOVAPS [rsp+0x50], xmm5`. Epilogue reverses with `MOVAPS xmm0, [rsp+0x00]` etc., then `ADD RSP, 0x60`. Verify prologue produces 16-byte-aligned `RSP`.
- **Code ref**: `dark_crystal/crowd/src/threadless.rs` — PATCH_SHELLCODE prologue/epilogue (also reusable in T-005 Ekko ROP frames, T-007 Pool Party worker stubs).

### Pattern: Self-Restoring Trampoline
- **Use when**: You want to modify a code location briefly (for one-shot trigger) without leaving a persistent patch that scanners can hash-baseline.
- **How**: Save original N bytes (N = trampoline size rounded up to nearest instruction boundary, here 8 bytes for a 5-byte CALL + 3 pad). Embed the saved bytes inside the trampoline target. The trampoline's first action after payload execution is to write the saved bytes back to the original location, then return to the original instruction stream. Caller of the patched code sees a transparent pass-through on second-and-subsequent calls.
- **Code ref**: `dark_crystal/crowd/src/threadless.rs` — PATCH_SHELLCODE self-restore (also applicable to T-008 Threadless, T-013 Func Stomp, T-016 short-lived hooks).

### Pattern: Minimum-Rights Handle Acquisition
- **Use when**: Opening remote processes for injection — requesting `PROCESS_ALL_ACCESS` is a strong EDR signal.
- **How**: Compute the specific access mask for the operations you'll perform: `PROCESS_VM_OPERATION (0x8) | PROCESS_VM_WRITE (0x20) | PROCESS_SUSPEND_RESUME (0x800) | PROCESS_QUERY_LIMITED_INFORMATION (0x1000)`. Pass exactly this mask to `NtOpenProcess`. Avoids the `PROCESS_ALL_ACCESS (0x1FFFFF)` telemetry trigger.
- **Code ref**: `dark_crystal/crowd/src/threadless.rs` — process open call site (pattern applies to every injection technique in T-007 through T-015).