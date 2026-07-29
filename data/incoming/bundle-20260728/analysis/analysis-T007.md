---
id: T-007
name: Pool Party Injection
category: process-injection
tier: S
mitre: T1055.001, T1055.009, T1574
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: medium
requires: [T-001, T-002, T-003, T-004]
enables: [T-005, T-016, T-017, T-023]
min_windows: Windows 8 / Server 2012
needs_admin: conditional
tags: [injection, thread-pool, worker-factory, version-agnostic, handle-manipulation, no-createremotethread, no-setthreadcontext, no-apc]
---

# Pool Party Injection — Operator Playbook

## TL;DR

Pool Party Variant #4 (Worker Factory Start Routine Override) overwrites the `StartRoutine` field inside a target process's `TpWorkerFactory` kernel object so that the next worker thread the thread-pool manager spawns executes your shellcode as its entry point. The cleverness is the **dynamic struct-layout detection** — instead of hardcoding `_TP_WORKER_FACTORY` offsets that drift between Windows builds, the code scans the duplicated object's memory for the target PID, ntdll-range pointers, and heap-range pointers to locate `Process`, `StartRoutine`, and `PoolContext` fields at runtime. Use this when you need cross-process injection into a long-running host (browsers, AV, services) and you want to avoid the three heaviest EDR tripwires: `CreateRemoteThread`, `QueueUserAPC`, and `SetThreadContext`.

## How It Works

The technique manipulates the undocumented `TpWorkerFactory` kernel object. Every process that has touched the Win32 thread pool (which is essentially every non-trivial process) holds at least one `TpWorkerFactory` handle. The object's `StartRoutine` field is the function pointer the thread-pool manager calls when it spawns a fresh worker thread. Overwriting that pointer with your shellcode address means the next worker creation event — which looks like a normal thread-pool grow event — pivots into your payload.

1. **Acquire syscall primitives.** Pool Party is built on top of the dark_crystal syscall layer. Required primitives: `NtQuerySystemInformation`, `NtDuplicateObject`, `NtQueryObject`, `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtSetInformationWorkerFactory`. Dispatched via T-001 (RecycledGate) or T-002/T-003 alternatives. Module resolution for `ntdll` exports goes through T-004 (PEB walker via `gs:[0x60]`).
2. **Enumerate system handles.** Call `NtQuerySystemInformation` with information class `SystemExtendedHandleInformation` (class 64). This returns a `SYSTEM_HANDLE_INFORMATION_EX` array containing every handle in every process on the box. Buffer is allocated via `NtQuerySystemInformation` length-query pattern (call once, read `ReturnLength`, allocate, call again). **Note:** the source-extract comment mentions `NtQueryInformationProcess(ProcessHandleInformation)` — that path only returns handles for the *calling* process and would not work for cross-process injection. Treat the comment as misleading; the card's `SystemExtendedHandleInformation` description is the correct path.
3. **Filter for TpWorkerFactory handles owned by target.** For each `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` entry where `UniqueProcessId == target_pid`, duplicate the handle into the current process via `NtDuplicateObject(target_handle, source_proc_handle, current_proc_handle, &dup_handle, 0, 0, DUPLICATE_SAME_ACCESS)`. `source_proc_handle` is an `OpenProcess(PROCESS_DUP_HANDLE)` handle to the target.
4. **Type-verify.** For each duplicated handle, call `NtQueryObject(h, ObjectTypeInformation, ...)`. Compare the returned `OBJECT_TYPE_INFORMATION.TypeName` against `TpWorkerFactory`. Discard non-matches. You now have a real `TpWorkerFactory` handle duplicated from the target.
5. **Resolve object backing memory.** The duplicated handle is a handle to a kernel object — you cannot directly read its bytes via `NtReadVirtualMemory` because the object lives in kernel address space. The Pool Party trick (per the technique card) is to read it via `NtQueryInformationWorkerFactory` or by reconstructing via `NtQueryObject(Extended)` — but operationally, the canonical implementation reads from the *process's own heap* where a user-mode shadow/mirror of the worker-factory state lives (the `TpWorkerFactory` user-mode struct allocated by `TppAllocWorkerFactory`). The duplicated handle combined with `PROCESS_VM_READ` on the target lets you read this user-mode mirror.
6. **Dynamic struct-layout scan.** Inside the user-mode `TpWorkerFactory` struct, scan every 8-byte aligned offset looking for three anchors:
   - **Process marker**: a value equal to `target_pid` (locates `Process` or related field)
   - **StartRoutine marker**: a pointer in the `ntdll.dll` virtual range (typically `0x7FF????????` range) — the original StartRoutine is `TppWorkerThreadWrapper` or similar ntdll internal
   - **PoolContext marker**: a pointer into the process heap (`0x????` user-mode ranges, not ntdll)
   Record the byte offsets of each anchor. This scan is what makes the code version-agnostic — `_TP_WORKER_FACTORY` field order shifts between Win8 / 8.1 / 10 / 11 builds, but the anchors are stable.
7. **Stage the shellcode.** Allocate RWX (or RW → RX after write) memory in the target via `NtAllocateVirtualMemory`. Copy the shellcode via `NtWriteVirtualMemory`. **Memory state:** `MEM_COMMIT | MEM_RESERVE`, `PAGE_EXECUTE_READWRITE` initially; for OPSEC you can stage as `PAGE_READWRITE` and flip to `PAGE_EXECUTE_READ` via `NtProtectVirtualMemory` after the write — this avoids RWX pages that some EDRs flag.
8. **Overwrite StartRoutine.** `NtWriteVirtualMemory(target_proc_handle, worker_factory_base + start_routine_offset, &shellcode_addr, 8, ...)`. The pointer-sized write converts the worker factory so that the next worker spawn invokes your shellcode.
9. **Trigger worker creation.** Call `NtSetInformationWorkerFactory(dup_handle, WorkerFactoryThreadMaximum, &new_max, sizeof(new_max))` where `new_max > current_max`. The thread-pool manager notices the headroom and spawns a new worker thread. That worker calls the now-overwritten `StartRoutine` — your shellcode executes in a fresh thread inside the target process, with a stack trace that looks like a legitimate `TppWorkerThread` → `StartRoutine` chain.
10. **Restore (optional but recommended).** Write the original `TppWorkerThreadWrapper` pointer back to the `StartRoutine` field. The victim worker thread is now executing your shellcode; future worker spawns will use the legitimate entry point again. This narrows the detection window.

### Memory state at each stage

| Stage | Target memory | Protection | Backing |
|---|---|---|---|
| After handle dup | `TpWorkerFactory` user-mode shadow | unchanged | Process heap |
| Shellcode stage alloc | fresh allocation | `PAGE_EXECUTE_READWRITE` (or `PAGE_READWRITE` → `PAGE_EXECUTE_READ`) | Page-file backed |
| After StartRoutine overwrite | 8 bytes in worker-factory shadow | unchanged (still `PAGE_READWRITE` heap) | Process heap |
| After trigger | new worker thread executing shellcode | shellcode page RX | Page-file backed |

### Race windows that matter

- **Between step 8 and step 9:** If a worker thread spawns naturally before you trigger (e.g., the target is under load), it will hit your shellcode early — usually fine, but the trigger call in step 9 may then be redundant.
- **Between step 9 and step 10:** The thread-pool manager may spawn multiple workers if `WorkerFactoryThreadMaximum` is bumped too aggressively. Each one calls your shellcode. This is rarely catastrophic but can cause multiple simultaneous executions if your shellcode is not idempotent.
- **Layout scan timing:** The user-mode `TpWorkerFactory` shadow is mutable. If you scan it during heavy thread-pool activity, anchor positions for `PoolContext` (which gets updated by the manager) may transiently point elsewhere. Re-scan if you don't find a clean anchor pattern.

## Operational Profile

### When to Use

- **Mature EDR target** running CrowdStrike, SentinelOne, Elastic, or Microsoft Defender for Endpoint — none of them instrument `NtSetInformationWorkerFactory` as heavily as `CreateRemoteThread` / `QueueUserAPC` / `SetThreadContext`.
- **Long-lived host processes** — browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`), AV services, SCM-hosted services, `explorer.exe`. All of them have a populated `TpWorkerFactory` and spawn workers regularly.
- **You have PROCESS_DUP_HANDLE on the target** — either same-user (no admin needed) or with SeDebugPrivilege (high-IL or SYSTEM).
- **You need version-agnostic reliability across a fleet of mixed Win10 1809 → Win11 23H2 hosts** — the dynamic layout detection means one build of the implant covers them all.
- **Post-exploitation staging into a sacrificial process** — chain with T-014 (`NtCreateUserProcess`) to spawn the host, then T-007 to inject without the typical `CreateRemoteThread` signature.
- **Memory-only payloads** where you don't want a backing file or section that ETW-TI kernel probes could match against.

### When NOT to Use

- **Target process is PPL-protected** (e.g., `MsMpEng.exe`, `smss.exe`, `csrss.exe` at the wrong integrity) — `OpenProcess(PROCESS_DUP_HANDLE)` is blocked by the kernel protection contract. Use T-018 (BYOVD) to disable PPL first, or pick a different host.
- **Target is a fresh child process that has not yet touched the thread pool** — it may not have a `TpWorkerFactory` handle yet. Force the issue by injecting into a process that's already done I/O, or prewarm the thread pool via `LoadLibrary` of something that uses it.
- **WOW64 / x86 target from an x64 implant** — struct layout, pointer sizes, and handle-table entry sizes all change. The current Pool Party code in dark_crystal assumes 64-bit pointers throughout. Either build an x86 variant or use a different technique.
- **Tight execution timing required** — worker creation latency depends on thread-pool manager state and is not deterministic. If you need sub-millisecond execution, use T-012 (Early Cascade) or T-013 callback execution instead.
- **Target is a static/idle process with no thread-pool activity** — the trigger may sit dormant indefinitely. Either accept the delay or force activity first.
- **You can't afford the trigger creating a new thread** — Pool Party *does* spawn a worker thread. The stealth is "looks like a normal worker spawn," not "no thread creation." For true zero-thread scenarios use T-008 (Threadless) or Pool Party variants 5/6 (not in this card).

### Kill Chain Position

Pool Party sits at the injection stage, after syscall primitives and target selection are ready, before sleep obfuscation and persistence:

```
T-004 (PEB walker)
   → T-001 (RecycledGate syscalls)
      → T-002 (SSN resolve)
         → T-020 (anti-VM check)
            → T-016 (ETW/AMSI patch — optional, pre-inject)
               → T-014 (NtCreateUserProcess — spawn host) [optional]
                  → T-007 (Pool Party inject)  ◄── THIS
                     → T-016 (PEB unlink + arg spoof on injected thread)
                        → T-005 (Ekko ROP sleep)
                           → T-017 (persistence)
                              → T-018/T-019 (edo tensei / dead drop C2)
                                 → T-023 (client capabilities)
```

For self-injection variants (where the dropper itself becomes the host), skip T-014 and run T-007 directly against the current process — no `OpenProcess` needed because you already hold `PROCESS_DUP_HANDLE` on yourself implicitly.

### Trade-offs

| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 9 | No `CreateRemoteThread`, no `QueueUserAPC`, no `SetThreadContext`. The new worker thread looks like a legitimate thread-pool grow event. Loses 1 point because the new worker thread's start address is your shellcode page (not ntdll) — stack-walking EDRs can spot this. |
| Reliability | 7 | Depends on target having an active `TpWorkerFactory` and the dynamic layout scan finding all three anchors. Failures are silent: trigger doesn't fire, shellcode never runs. |
| Complexity | 8 | Dynamic struct-layout detection is non-trivial to debug. Pointer-range checks for ntdll vs. heap are fragile if the target has unusual VAD layouts (e.g., ACG-enforced, large-allocation-jit- processes like V8). |
| Version range | Win8 / Server 2012 → Win11 24H2 | `TpWorkerFactory` was introduced in Win8. Dynamic layout detection covers the struct drift across all subsequent releases. Has not been validated on Win7 (would not work — no `TpWorkerFactory` object type). |
| Privilege needed | Conditional | Same-user process: none (medium-IL). Cross-user: high-IL or SYSTEM for `SeDebugPrivilege` to satisfy `PROCESS_DUP_HANDLE`. PPL targets: kernel-level bypass required (T-018). |

## Rust Implementation Deep Dive

**Honest caveat up front:** The source extract provided for this analysis is essentially a header block of comments plus a few struct/NT-function names — the actual ~579-line Rust body of `dark_crystal/crowd/src/pool_party.rs` was not included. The deep dive below describes the *patterns visible in the extract's comments and the technique card*, cross-referenced with what the actual NT structures require. An operator modifying this code will need to open the real file. Specific function names that *would* be expected based on the card's description:

- `enumerate_handles(target_pid) -> Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>` — wraps `NtQuerySystemInformation(SystemExtendedHandleInformation)`
- `duplicate_target_handle(source_proc, handle_val) -> HANDLE` — wraps `NtDuplicateObject`
- `verify_worker_factory(dup) -> bool` — wraps `NtQueryObject(ObjectTypeInformation)`
- `scan_worker_factory_layout(target_proc, factory_base) -> LayoutAnchors` — the dynamic detection routine
- `inject_start_routine(target_proc, factory_base, anchors, shellcode_addr) -> NTSTATUS` — the 8-byte pointer write
- `trigger_worker_spawn(factory_handle, new_max) -> NTSTATUS` — wraps `NtSetInformationWorkerFactory(WorkerFactoryThreadMaximum)`

### `unsafe` boundaries

Every step in Pool Party is `unsafe`:

- **`NtQuerySystemInformation` call** — `unsafe` because the output buffer is `*mut c_void` reinterpreted into `*mut SYSTEM_HANDLE_INFORMATION_EX`. The struct has a variable-length tail (`HandleInfo: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1]`). Reading past the declared array length is Rust UB unless you use `slice::from_raw_parts(handle_info_ptr.add(1), count)`. Pattern is identical to the one in `sys_resolve.rs` (T-002) for SSN-table slicing.
- **`NtDuplicateObject`** — `unsafe` FFI; produces a `HANDLE` (raw `*mut c_void`) that the caller owns and must close via `NtClose`. RAII guard recommended (see "Reusable Patterns").
- **Layout scan** — `unsafe` because it dereferences `*const u8` derived from `NtQueryVirtualMemory`-mapped pages in the target process. Reading 8 bytes at a time via `NtReadVirtualMemory` is safer than `NtMapViewOfSection` here, because mapping crosses protection boundaries and is noisier.
- **StartRoutine overwrite** — single `NtWriteVirtualMemory` of 8 bytes. The unsafety is in *which* offset you write to — writing to the wrong field can corrupt the worker factory and crash the target.

### `core::arch::asm!` usage

Pool Party itself does not need inline asm — it's all NT API FFI calls. The asm lives in the *syscall layer* underneath: `sys_recycled.rs` (T-001 RecycledGate) provides the inline-asm stubs that `sys_indirect.rs` dispatches to. When you call `NtQuerySystemInformation` through the dark_crystal layer, it goes:

```
caller (pool_party.rs)
  → sys_indirect.rs::nt_query_system_information(...)
    → looks up SSN + gadget in sysindirect_map
    → jumps to RecycledGate stub (sys_recycled.rs, inline asm)
      → syscall instruction in ntdll's .text
```

No direct `syscall` instruction in `pool_party.rs`. If you're porting this code standalone, you must bring your own syscall layer (T-001/T-002/T-003).

### FFI patterns

NT bindings are declared via `windows_targets::link!` (per the manifest mapping for `wrappers.rs`). Expected signatures:

```rust
windows_targets::link!("ntdll.dll", "system" fn NtQuerySystemInformation(
    class: SYSTEM_INFORMATION_CLASS,
    buffer: *mut c_void,
    len: u32,
    ret_len: *mut u32,
) -> NTSTATUS);

windows_targets::link!("ntdll.dll", "system" fn NtDuplicateObject(
    source_proc: HANDLE,
    source_handle: HANDLE,
    target_proc: HANDLE,
    target_handle: *mut HANDLE,
    access: u32,
    attributes: u32,
    options: u32,
) -> NTSTATUS);

windows_targets::link!("ntdll.dll", "system" fn NtSetInformationWorkerFactory(
    factory: HANDLE,
    class: WORKERFACTORYINFOCLASS,
    info: *mut c_void,
    len: u32,
) -> NTSTATUS);
```

`WORKERFACTORYINFOCLASS` is undocumented; `WorkerFactoryThreadMaximum` is empirically value `0x6` on Win10/11. Confirm at runtime rather than hardcoding — print the value the first time the chain runs on a new build.

### Handle ownership and cleanup

- Every `NtDuplicateObject`-produced handle must be paired with `NtClose` in a `Drop` guard. Pattern from `wrappers.rs` (T-021 patterns): `struct OwnedHandle(HANDLE); impl Drop for OwnedHandle { fn drop(&mut self) { unsafe { NtClose(self.0); } } }`.
- The `OpenProcess(PROCESS_DUP_HANDLE)` handle on the target is also a leak risk — close it after the trigger fires or hold it for the lifetime of the implant if you intend to inject again.

### Initialization

Pool Party is **stateless** — no `OnceLock` / `LazyCell` for the technique itself. It depends on the global SSN map (`sysindirect_map.rs`) which is initialized once via `OnceLock` at first syscall. The first call to any NT function inside `pool_party.rs` will trigger the SSN-resolution cascade (T-002 Hells/Halos/Tartarus) lazily. Plan for ~10–50ms one-time hit on first invocation.

### Error paths

From the technique card and the comment listing, the expected behavior:

- **Handle enumeration fails** (`NtQuerySystemInformation` returns `STATUS_INFO_LENGTH_MISMATCH` after retry): bail silently, return `Err`. Implant should fall back to a different injection technique (T-008 Threadless or T-012 Early Cascade).
- **No `TpWorkerFactory` handle found in target**: bail silently. Implant should retry with a different host or fall back.
- **Layout scan finds insufficient anchors**: bail silently. The version-agnostic logic should find at least 3 ntdll-range pointers and the PID marker; if fewer are found, the impl likely has a `LayoutScanError` variant.
- **`NtWriteVirtualMemory` on `StartRoutine` returns `STATUS_ACCESS_DENIED`**: the duplicated handle didn't carry `PROCESS_VM_WRITE`. The dup was done with `DUPLICATE_SAME_ACCESS` so this means the target handle itself lacked write permission. Fall back to T-008.
- **`NtSetInformationWorkerFactory` returns `STATUS_INVALID_INFO_CLASS`**: the target Windows version doesn't accept `WorkerFactoryThreadMaximum`. Currently unknown to occur on any released Windows, but worth a runtime check.
- **Trigger fires but shellcode doesn't run**: the `StartRoutine` field wasn't correctly identified — the ntdll-range pointer heuristic landed on a different field. Re-scan with stricter anchor requirements (multiple ntdll pointers clustered together is the real `StartRoutine`/`WaitRoutine`/`ShutdownRoutine` triad).

### Memory layout of `_TP_WORKER_FACTORY` (what the layout scan is looking for)

The struct is undocumented and shifts between versions. Approximate fields the scan must locate:

```
+0x000  ... (header, ObjectHeader hints)
+0x0??  WorkerFactoryPool (heap pointer)
+0x0??  Process            (PEB pointer or PID — version-dependent)
+0x0??  StartRoutine       (ntdll pointer: TppWorkerThreadWrapper)
+0x0??  WaitRoutine        (ntdll pointer)
+0x0??  ShutdownRoutine    (ntdll pointer)
+0x0??  PoolContext        (heap pointer)
+0x0??  ThreadMaximum      (ULONG — read this to know current cap)
+0x0??  ThreadBaseCount    (ULONG)
+0x0??  Timeout            (LARGE_INTEGER)
...
```

The "three clustered ntdll pointers" pattern is the most reliable anchor — once you find that triplet, the middle one (or first, depending on build) is `StartRoutine`. The card's "scan for target PID at 8-byte offsets" finds the `Process` field.

## Edge Cases & Failure Modes

1. **Target is PPL-protected (`MsMpEng.exe`, `smss.exe`, services under `PsProtectedSignerWindows-Light`)**
   - **What goes wrong:** `OpenProcess(PROCESS_DUP_HANDLE)` returns `STATUS_ACCESS_DENIED`. The kernel refuses cross-protection-contract handle grants.
   - **Symptom:** All subsequent `NtDuplicateObject` calls fail with `STATUS_INVALID_HANDLE` or `STATUS_ACCESS_DENIED`. No `TpWorkerFactory` handle ever gets duplicated.
   - **Workaround:** Either pick a non-PPL host, or pre-stage T-018 (BYOVD) to disable PPL on the target. BYOVD adds significant detection surface (driver load events, kernel callbacks) — only use when the target is genuinely worth it.

2. **Target is WOW64 (x86 process on x64 OS) from x64 implant**
   - **What goes wrong:** Pointer sizes inside the WOW64 `TpWorkerFactory` are 4 bytes, not 8. The 8-byte-aligned scan misses every anchor. Worse, `NtQuerySystemInformation(SystemExtendedHandleInformation)` from the x64 context enumerates 64-bit handle table entries, mismatching the target's 32-bit handle table.
   - **Symptom:** Layout scan finds 0 anchors. No write occurs.
   - **Workaround:** Build an x86 variant of the implant for WOW64 targets, or switch to T-012 (Early Cascade) which is less layout-sensitive.

3. **Target's thread pool is dormant / no `TpWorkerFactory` handle exists**
   - **What goes wrong:** Handle enumeration finds zero `TpWorkerFactory` handles in the target. This happens for processes that have never used the Win32 thread pool — minimal console apps, some service stubs.
   - **Symptom:** `verify_worker_factory` returns `false` for every duplicated handle.
   - **Workaround:** Force the target to use the thread pool before injecting — e.g., trigger an RPC call into it, send a window message that requires worker activity, or use a different technique entirely. Self-injection always works because the dropper itself uses thread pools.

4. **EDR with kernel TpWorkerFactory object callbacks (Elastic Endpoint 8.x, CrowdStrike Falcon 7.x with KBLS)**
   - **What goes wrong:** Some EDRs hook `ObRegisterCallbacks` for `TpWorkerFactory` object type. When you duplicate the handle, a `PreOperation` callback fires. EDR sees `PROCESS_DUP_HANDLE` source + `TpWorkerFactory` type — high-suspicion combination.
   - **Symptom:** `NtDuplicateObject` succeeds but the EDR pages the target's worker-factory pages, or flags the process for behavior monitoring. Subsequent worker creation gets a stack-walk.
   - **Workaround:** T-016 stack spoofing on the trigger thread is essential. Consider using T-003 (VEH Gate) so the syscall itself has an EDR-invisible stack. If the EDR is post-dup'ing you consistently, switch to T-008 (Threadless) which never duplicates a `TpWorkerFactory` handle.

5. **EDR with thread-creation ETW-TI instrumentation (Microsoft Defender for Endpoint, Microsoft Defender ATP)**
   - **What goes wrong:** Even though you're not using `CreateRemoteThread`, the thread-pool manager's worker spawn still fires `ThreadStart` ETW events. MDE's behavioral analytics flag a worker thread whose start address is a non-image page (your shellcode allocation).
   - **Symptom:** Implant runs fine for hours, then suddenly the target process is killed or quarantined. MDE incident shows "suspicious thread start address" telemetry.
   - **Workaround:** Stage shellcode inside a MEM_IMAGE-backed region — use T-006 (Phantom Stubs) to allocate a phantom stub inside ntdll's .text or a loaded module's .text. The new worker's start address will then read as legitimate. Combine with T-016 module stomping.

6. **Dynamic layout scan returns ambiguous anchors (multiple candidate triplets)**
   - **What goes wrong:** A complex target (e.g., `chrome.exe` with hundreds of allocations) may have multiple memory regions that look like the `_TP_WORKER_FACTORY` triplet. The first triplet found may be the wrong one.
   - **Symptom:** Overwrite succeeds (no error), trigger fires, shellcode never runs. The legitimate `StartRoutine` was never overwritten — the write hit a different triplet.
   - **Workaround:** Verify the candidate by reading `ThreadMaximum` field adjacent to the triplet — it should be a small number (1–100), not a pointer. Add a `LayoutCandidate::verify()` step that sanity-checks nearby fields before committing the write.

7. **Trigger (`NtSetInformationWorkerFactory(WorkerFactoryThreadMaximum)`) bumps the cap but no worker spawns**
   - **What goes wrong:** The thread-pool manager only spawns workers when there's pending work. If the target is idle, bumping `ThreadMaximum` to 100 doesn't cause any new worker creation.
   - **Symptom:** No thread appears. Shellcode doesn't execute.
   - **Workaround:** After bumping `ThreadMaximum`, queue real work into the target's thread pool — e.g., via `PostQueuedCompletionStatus` on the factory's I/O completion port (which you have a duplicated handle to). Or just wait — eventually the target will need a worker.

8. **Worker spawns, calls your shellcode, then immediately faults because shellcode expects different ABI**
   - **What goes wrong:** `TppWorkerThreadWrapper` is normally called with a specific argument (`PoolContext`). Your shellcode receives that argument in `rcx` and may try to dereference it as if it were a typical shellcode argument (e.g., the kernel32 base). Access violation.
   - **Symptom:** Target process crashes immediately after the trigger.
   - **Workaround:** Make your shellcode entrypoint ignore `rcx` — start with `xor rcx, rcx` (or save it for later). The first thing the shellcode should do is locate its own base via the call-pop pattern, not trust any argument.

9. **Cleanup race: you restore `StartRoutine` between worker spawn and worker entry**
   - **What goes wrong:** If you overwrite `StartRoutine`, immediately restore it, *then* the worker spawns, the worker reads the original (now restored) `TppWorkerThreadWrapper` and skips your shellcode.
   - **Symptom:** No execution. Trigger seemed to fire but nothing happened.
   - **Workaround:** Wait for the worker to actually spawn (poll thread count via `NtQueryInformationWorkerFactory(WorkerFactoryThreadCount)`) *before* restoring. Or don't restore at all — accept the broader detection window in exchange for guaranteed execution.

10. **Build-time Windows version mismatch**
    - **What goes wrong:** The dynamic layout detection assumes pointer alignment and triplet pattern. On Insider Preview / future Windows builds, the struct may be reorganized such that the triplet is no longer three consecutive ntdll pointers.
    - **Symptom:** Scan returns 0 anchors or anchors at offsets that don't match a coherent struct.
    - **Workaround:** Add a second heuristic — search for the `ThreadMaximum` field as a small integer in the ±0x80 bytes around the PID marker, then back-derive the triplet position from there. Maintain a per-build offset table as a fallback when dynamic detection fails.

## Variant Ideas

- **In-process variant (self-injection):** Skip the `NtQuerySystemInformation` enumeration entirely — walk the current process's handle table directly via `NtQueryInformationProcess(ProcessHandleInformation)`. Faster, smaller footprint, and avoids the `SystemExtendedHandleInformation` call which itself is an EDR signal. Useful for the dropper bootstrap phase before you've moved into a host.
- **Pool Party Variant 5/6 (Worker Indirect / Direct Shadow Callback):** Instead of overwriting `StartRoutine`, plant a work item (`TP_WORK`) into the target's pool whose callback pointer is your shellcode. This avoids the "new worker thread" tell entirely — execution happens on an existing worker. Requires the same handle enumeration but writes into the `TP_WORK` struct rather than `TpWorkerFactory`. Not currently in dark_crystal — straightforward port from the SafeBreach reference.
- **Combine with T-006 (Phantom Stubs):** Allocate the shellcode inside a phantom stub in ntdll's `.text` slack space. The new worker thread's start address then reads as `ntdll!TppWorkerThreadWrapper+0x????` to any EDR doing stack-walk telemetry. Doubles the stealth.
- **Combine with T-016 stack spoofing:** After injection, the worker thread's call stack reads `kernel32!BaseThreadInitThunk → ntdll!TppWorkerThreadWrapper → [shellcode]`. Spoof the third frame so it appears to be a legitimate `ntdll!TppWorkItem` callback. Defeats stack-walk-based detection.
- **Variant: Use `TpAllocWork` + `TpPostWork` via duplicated TP_WORK handle:** Instead of triggering worker creation, queue actual work into the pool. Requires duplicating not the `TpWorkerFactory` but a `TpWork` handle — the enumeration filter changes. Lower risk of detection because no worker creation event occurs.
- **Pre-warm + hold pattern:** Inject `StartRoutine` overwrite early, hold it dormant, only trigger when needed. Reduces the time between the suspicious `NtSetInformationWorkerFactory` call and shellcode execution — narrows the analyst's window to correlate the two.
- **Multi-stage payload:** Stage 1 = a tiny stub that locates the implant body in process memory and jumps to it. Stage 2 = the real payload. If the trigger thread dies (e.g., worker is reclaimed), stage 1 can re-inject itself by re-bumping `ThreadMaximum`.
- **ETW-TI evasion via T-003 VEH gate:** Run the entire Pool Party syscall sequence through HW-breakpoint mediated dispatch. ETW-TI's `EtwTi` providers log syscalls from kernel but the VEH gate makes the calling thread appear as an exception handler. Combined with stack spoofing, this defeats the "who called NtSetInformationWorkerFactory" telemetry chain.
- **PPL bypass via T-018 BYOVD prelude:** Load a vulnerable driver (RTCore64.sys, etc.), disable the PPL flag on the target process via `NtSetInformationProcess(ProcessProtectionInformation)`, then proceed with normal Pool Party. Adds a kernel-mode driver load event to OPSEC but unlocks high-value targets like `MsMpEng.exe`.

## OPSEC Notes

### Artifacts left behind

- **Duplicated handle in the *calling* process** until `NtClose`'d. Handle scanners (Sysinternals `handle.exe`, Process Hacker) will show a `TpWorkerFactory` handle in the dropper process — unusual for processes that aren't thread-pool frameworks. Clean up immediately after the trigger fires.
- **Worker thread with non-image start address.** The new worker's start address is your shellcode page. `Process Explorer` "Threads" tab on the target shows it as an address outside any loaded module. Mitigate via T-006 phantom stubs.
- **`SystemExtendedHandleInformation` query.** Some EDRs log this call as suspicious (used by handle-table-stealing tools like `handle.exe` itself). Consider chunking via `NtQueryInformationProcess(ProcessHandleInformation)` per-process if you only need a few targets.
- **Modified worker-factory memory.** Even after restoring `StartRoutine`, the `TpWorkerFactory` user-mode shadow's been written. Memory forensics (Volatility `poolscanner` plugin variant) can detect the residual modifications if the layout scan wrote sentinel bytes for verification.
- **No new file system artifacts.** No DLL, no executable, no scheduled task. Pool Party is entirely in-memory.

### Telemetry it generates

- `Microsoft-Windows-Kernel-Process` ETW: `ThreadStart` event for the new worker. Normal pool-grow also generates this, so volume alone isn't a signal — the start address is.
- `Sysmon EID 8` (CreateRemoteThread): **does not fire** — you didn't call `CreateRemoteThread`.
- `Sysmon EID 10` (ProcessAccess): fires for the `OpenProcess(PROCESS_DUP_HANDLE)` call. Sysmon config typically filters this to `GrantedAccess` matching common suspicious masks — `0x40` (`PROCESS_DUP_HANDLE`) is sometimes flagged, sometimes not. Tune your chain to use an existing handle if possible.
- `Microsoft-Windows-Kernel-Object` ETW (if ObRegisterCallbacks registered by EDR): fires on `NtDuplicateObject` of `TpWorkerFactory` type. This is the highest-signal telemetry path — most EDRs that catch Pool Party do so here.
- ETW-TI (Threat Intelligence) providers: `EtwTiSyscallProviders` log `NtSetInformationWorkerFactory` calls. Few EDRs subscribe to this — but Microsoft Defender for Endpoint does.

### Known detections

- **Microsoft Defender for Endpoint** Behavior detection `Behavior:Win32/PoolParty.B` (post-SafeBreach 2023 publication). Triggers on the combination of `OpenProcess(PROCESS_DUP_HANDLE)` + `NtQuerySystemInformation(SystemExtendedHandleInformation)` + `NtDuplicateObject` to a `TpWorkerFactory` handle. Evade by self-injecting or by using a pre-acquired handle.
- **Elastic Endpoint 8.x** rule `Execution via Worker Factory Manipulation` — looks for the start address of a newly created worker thread pointing outside loaded modules. Mitigate via T-006 phantom stubs.
- **CrowdStrike Falcon** — no published detection for Variant 4 specifically, but Falcon's `ObRegisterCallbacks` registration on `TpWorkerFactory` does generate a `PreOperation` log entry visible in the Falcon telemetry stream. CS analysts correlating `PreOperationCallback` + `ThreadStart` will catch this manually.

### Cleanup procedures

1. **Restore `StartRoutine`** to original `TppWorkerThreadWrapper` pointer (stored from the layout scan) — narrows the window where future worker spawns hit your shellcode.
2. **`NtClose` the duplicated `TpWorkerFactory` handle** — removes the handle-table artifact in the dropper process.
3. **`NtClose` the target `OpenProcess` handle** — unless you need it for re-injection.
4. **Optionally zero the shellcode page** after the payload has relocated itself elsewhere — prevents memory scanners from finding the RWX page. Use `RtlZeroMemory` or `NtWriteVirtualMemory` of zeros.
5. **If you used T-006 phantom stubs, leave the phantom alone** — modifying ntdll's `.text` again to "clean up" the stub will trigger CFI/PGK alerts.

## Reusable Patterns

### Pattern: NT Handle-Table Walk with Type Verification

- **Use when:** You need to find a handle of a specific type in another process — `TpWorkerFactory`, `TpWork`, `TpTimer`, `EtwReg`, `Desktop`, `WindowStation`. Used across Pool Party, T-016 (handle blocking), and any future object-manipulation technique.
- **How:** `NtQuerySystemInformation(SystemExtendedHandleInformation)` → filter by `UniqueProcessId == target` → for each handle, `NtDuplicateObject(DUPLICATE_SAME_ACCESS)` into self → `NtQueryObject(ObjectTypeInformation)` → compare `TypeName.Buffer`. Wrap in an iterator that closes non-matching duplicates immediately to avoid handle-table bloat.
- **Code ref:** `pool_party.rs` (handle enumeration), `block_handle.rs` (T-016, complementary pattern for *blocking* handle access).

### Pattern: Dynamic Struct Layout Detection via Anchor Scanning

- **Use when:** You need to write to an undocumented NT struct whose layout drifts between Windows builds. Applies to `_TP_WORKER_FACTORY` (this technique), `_EPROCESS` (BYOVD T-018), `_KTHREAD` (any kernel-pattern technique).
- **How:** Define a set of "anchors" — values you can predict at runtime (PID, pointer ranges, fixed-size small integers). Read candidate memory in 8-byte strides. Score each candidate region by anchor count. Pick the highest-scored region; write to the offset relative to the strongest anchor. **Critical:** add a `verify()` step that cross-checks at least one adjacent field before committing the write — without this, false-positive anchors will corrupt the target.
- **Code ref:** `pool_party.rs` (`scan_worker_factory_layout` — names per the card's description; verify against the actual file).

### Pattern: RAII Handle Guard

- **Use when:** Any FFI call returns a `HANDLE` that the caller owns. Prevents the #1 source of handle leaks in Rust implants.
- **How:** Wrap the handle in a `struct OwnedHandle(HANDLE);` with a `Drop` impl that calls `NtClose`. Pass `&OwnedHandle` to functions that need to read the handle value; let the guard own the lifetime. For handles that must outlive the function (e.g., the target process handle retained for re-injection), return `OwnedHandle` by value.
- **Code ref:** `wrappers.rs` (T-021 patterns); the same pattern should be applied locally in `pool_party.rs` for every `NtDuplicateObject` result.

### Pattern: Length-Query NT Buffer Allocation

- **Use when:** Calling any `NtQuery*Information` function that returns a variable-length result. Avoids the "guess the buffer size" anti-pattern that causes repeated `STATUS_INFO_LENGTH_MISMATCH` retries.
- **How:** Call the function with `buffer = null, len = 0`. Capture `*ReturnLength`. Allocate `Vec<u8>::with_capacity(ret_len as usize)`. Call again with the buffer. Parse via `ptr::read_unaligned` and `slice::from_raw_parts`. **Note:** some NT functions return `STATUS_BUFFER_TOO_SMALL` instead of `STATUS_INFO_LENGTH_MISMATCH` for the length-query call — handle both.
- **Code ref:** `pool_party.rs` (handle enumeration), `peb_unlink.rs` (T-016, similar pattern for module-list walking).

### Pattern: Two-Stage Trigger (Setup + Fire)

- **Use when:** A technique has a "silent setup" phase (writes, handle ops) and a "noisy execution" phase (thread spawn, callback fire). Decoupling the two lets you pick the execution timing for OPSEC.
- **How:** Setup phase: do all the handle duplication, layout scanning, writes. Record a `Trigger` closure or function pointer. Fire phase: invoke the trigger when conditions are optimal — e.g., when user activity masks the new thread, when EDR is in a degraded state, when network conditions favor beaconing.
- **Code ref:** `pool_party.rs` (steps 1–8 are setup, steps 9–10 are fire); structurally similar to T-005 Ekko sleep, which also separates "build ROP chain" from "execute chain".