Below are two playbook-grade analyses, one per technique card. Each is structured so a human operator or AI agent can grep, parse the frontmatter, and chain across the vault.

---

```
---
id: T-013
name: Additional Injection Methods (12 techniques)
category: process-injection
tier: mixed
mitre: T1055, T1055.001, T1055.012, T1055.013, T1055.039, T1059, T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-004, T-002, T-015]
enables: [T-005, T-016, T-017, T-018]
min_windows: Win7+
needs_admin: conditional
tags: [injection, hollowing, hypnosis, fiber, callback, mapping, module-stomp, func-stomp, vectored-overloading, reflective-loader, early-bird, waiting-thread, module-overloading]
---

# Additional Injection Methods — Operator Playbook

## TL;DR
This is the **second-tier injection toolkit** in `dark_crystal/crowd`: twelve techniques that fill niches the S-tier primitives (T-007 Pool Party, T-009 Process Ghosting, T-012 Early Cascade, T-014 NtCreateUserProcess) don't cover. Several are gold for specific scenarios — **Module Overloading** and **Reflective PE Loader** are first-line choices when you need `MEM_IMAGE` backing without a LoadLibrary call; **Process Hypnosis** is the answer when the target EDR hooks `NtWriteVirtualMemory` aggressively; **Vectored Overloading** is the only entry here that gives you *both* `MEM_IMAGE` backing *and* EAT-redirected persistence in a single primitive. Treat the B-tier entries (Hollowing, Module Stomping, Function Stomping, Callback, Fiber) as fallbacks — they're reliable but signature-heavy.

## How It Works

The card groups twelve distinct primitives. Each operates on a different memory backing / execution vehicle combination. The operational matrix matters more than the alphabetical order — pick by (backing, hook surface).

### 1. Process Hollowing — `crowd/src/process_hollow.rs`
1. Spawn suspended process (legit binary like `svchost.exe`).
2. Read `PEB->ImageBaseAddress` at `PEB+0x10` via `NtQueryInformationProcess(ProcessBasicInformation)` to get the legitimate image base.
3. `NtUnmapViewOfSection` the original image — this leaves a hole in the remote VAD.
4. `NtAllocateVirtualMemory` at a chosen base (often the original), `PAGE_READWRITE`.
5. `memcpy` the new PE headers + sections into place.
6. `NtProtectVirtualMemory` per-section with correct `IMAGE_SCN_*` flags.
7. `NtGetContextThread` on the suspended main thread; patch `Rcx` (PEB pointer) and `Rip` to `AddressOfEntryPoint`.
8. `NtSetContextThread`; `NtResumeThread`.
9. `bail_close!` macro wraps every handle in an RAII guard so any early-return path still closes handles — useful because hollowing has ~8 cleanup points.

### 2. Process Hypnosis — `crowd/src/hypnosis.rs`
1. `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED`.
2. `WaitForDebugEvent` loops to consume 7 debug event classes: `EXCEPTION_DEBUG_EVENT`, `CREATE_THREAD_DEBUG_EVENT`, `CREATE_PROCESS_DEBUG_EVENT`, `EXIT_THREAD_DEBUG_EVENT`, `EXIT_PROCESS_DEBUG_EVENT`, `LOAD_DLL_DEBUG_EVENT`, `UNLOAD_DLL_DEBUG_EVENT`.
3. The `CREATE_PROCESS_DEBUG_EVENT` payload carries `lpStartAddress` and `lpBaseOfImage` — you get a *legitimate* executable address inside the suspended process for free.
4. Use `WriteProcessMemory` (still via NT, see `wrappers.rs`) to write shellcode into the existing image's `.text` region at `lpStartAddress` — **no VirtualAllocEx call ever happens**.
5. `ContinueDebugEvent(DBG_CONTINUE)` — the initial thread resumes and executes your shellcode instead of its original entry.
6. The debug port is closed via `DebugSetProcessKillOnExit(FALSE)` + `CloseHandle(debug_port)` — silent detach.

### 3. WaitingThread Hijack — `crowd/src/waiting_thread.rs`
1. `NtQuerySystemInformation(SystemProcessInformation)` walks all processes; for the target, enumerate threads.
2. For each thread, pull `KTHREAD->WaitReason` via `SystemProcessInformation` thread entries (`THREAD_SYSTEM_PROCESS_INFORMATION` carries `WaitReason`).
3. Filter to wait states: `DelayExecution (1)`, `WrQueue (4)`, `WrLpcReply (8)`, `WrUserRequest (5)`, `WrAlertByThreadId (17)`. These are *stable* waits — the thread is parked, not racing.
4. `NtGetContextThread` to capture `Rip`, `Rsp`.
5. Deliver shellcode via **mapping injection** (see #4) — *no* `NtWriteVirtualMemory` on the target.
6. Patch `Rip` to the mapped shellcode via `NtSetContextThread`.
7. `NtAlertThread` to break the alertable waits (DelayExecution, AlertByThreadId). For WrQueue / WrLpcReply you cannot force wake — wait for natural wake, the patched `Rip` takes effect on scheduler re-entry.
8. The original `Rip` is preserved in your shellcode's prologue so it can jump back and let the thread continue normally — operator-controlled.

### 4. Mapping Injection — `crowd/src/mapping_inject.rs`
1. `NtCreateSection(SEC_COMMIT, PAGE_READWRITE)` — size = round_up(shellcode_len, 0x1000).
2. `NtMapViewOfSection(local, ViewUnmap, PAGE_READWRITE)` — local RW view.
3. `memcpy(local_view, shellcode, len)`.
4. `NtMapViewOfSection(target_process, ViewUnmap, PAGE_EXECUTE_READ)` — *remote RX view* of the same physical pages.
5. **The `VIEW_UNMAP = 2` bugfix**: original code used `ViewShare = 1`. `ViewShare` causes section *views* to be inherited by child processes spawned from the target (NT legacy semantic). This broke stealth on chains that spawned children — the section would appear in the child's VAD. `ViewUnmap` does not propagate. Both flags work for the immediate injection, but `ViewUnmap` is the OPSEC-correct choice.
6. Remote execution via thread hijack, APC, or fiber.

### 5. Module Stomping — `crowd/src/module_stomp.rs`
1. `LoadLibraryExA("chakra.dll", DONT_RESOLVE_DLL_REFERENCES)`. `chakra.dll` chosen because Microsoft-signed, present on Win10+, has large `.text`.
2. `GetModuleHandleA` to fetch base (note: this *does* go through Win32 — see Trade-offs).
3. Parse the PE header — `Magic` field at `e_lfanew + 0x18` distinguishes PE32 (`0x10b`) from PE32+ (`0x20b`).
4. Locate `.text` section via `IMAGE_SCN_CNT_CODE` flag.
5. `VirtualProtect(PAGE_READWRITE)` on `.text`.
6. `memcpy` shellcode.
7. `VirtualProtect(PAGE_EXECUTE_READ)` to restore.
8. Execution is from `MEM_IMAGE` backed by a Microsoft-signed DLL — looks like JS engine code to a memory scanner.

### 6. Function Stomping with RAII — `crowd/src/func_stomp.rs`
1. PEB walker (T-004) resolves the target module and function via DJB2 hash on export names.
2. Parse export directory to get function RVA.
3. `StompGuard` struct holds `{addr, original_bytes: [u8; N]}`.
4. `NtProtectVirtualMemory(addr, PAGE_READWRITE)`.
5. `memcpy(addr, shellcode)`.
6. `NtProtectVirtualMemory(PAGE_EXECUTE_READ)`.
7. On `Drop`, `StompGuard` writes original bytes back and restores protection — auto-cleanup on scope exit.
8. **No Win32 imports**: PEB walk + manual PE export parse only.

### 7. Module Overloading — `crowd/src/overload.rs`
1. `NtOpenFile` on the target DLL path (e.g. `\??\C:\Windows\System32\msvcp_win.dll`).
2. `NtCreateSection(SEC_IMAGE, PAGE_READONLY)` — section backed by the on-disk DLL.
3. `NtMapViewOfSection(target, ViewUnmap, PAGE_READWRITE)` — remote view of the file.
4. Because `SEC_IMAGE` enforces the on-disk layout, you now have a `MEM_IMAGE` region in the target that *looks like* a legitimately loaded DLL.
5. Overwrite `.text` with shellcode.
6. `NtProtectVirtualMemory` per-section flags.
7. Execute via thread/APC.
8. **Zero Win32 API calls** in the entire pipeline — pure syscalls.

### 8. Callback Execution — `crowd/src/callback_exec.rs`
1. `NtAllocateVirtualMemory(PAGE_READWRITE)`.
2. `memcpy(shellcode)`.
3. `NtProtectVirtualMemory(PAGE_EXECUTE_READ)`.
4. `EnumSystemCodePagesA(shellcode_addr, CP_ACP)` — invokes the shellcode as a callback pointer.
5. Other callback primitives available in the same file: `EnumChildWindows`, `EnumDesktopWindows`, `CertEnumSystemStore`, `EnumDateFormatsA`. Same shape — pass function pointer, kernelbase dispatches it.
6. **No `CreateThread` surface** — useful when EDR alerts on thread creation.

### 9. Fiber Execution — `crowd/src/fiber_exec.rs`
1. `ConvertThreadToFiber(NULL)` — current thread becomes a fiber scheduler.
2. `NtAllocateVirtualMemory + memcpy + NtProtectVirtualMemory` for shellcode.
3. `CreateFiber(0, shellcode_addr, NULL)` — allocates a new fiber with shellcode as the entry.
4. `SwitchToFiber(new_fiber)` — current thread synchronously jumps to the shellcode.
5. Shellcode runs in the *original* thread — same TID, same stack parent, no new thread visible to ETW `ThreadStart` events.
6. `DeleteFiber` cleanup; if shellcode returns, switch back to main fiber.

### 10. Early Bird APC — `crowd/src/early_bird.rs`
1. Spawn target process suspended (typically via T-014 NtCreateUserProcess for cleanest path).
2. `NtAllocateVirtualMemory(PAGE_READWRITE)` in target.
3. Write shellcode via T-001 RecycledGate — indirect syscalls, no `ntdll!NtWriteVirtualMemory` hook hit.
4. `NtProtectVirtualMemory(PAGE_EXECUTE_READ)`.
5. `QueueUserAPC(shellcode_addr, main_thread_handle)`.
6. `NtResumeThread` — main thread wakes from `LdrpInitializeProcess`'s `NtWaitForSingleObjectEx(alertable=TRUE)` and dispatches the APC *before* the image entry point runs.
7. The APC runs in the loader-locked, pre-Entry context — any EDR that hooks the entry sequence sees a clean normal entry after your shellcode already executed.

### 11. Vectored Overloading — `crowd/src/experimental/injection/vectored_overloading.rs`
1. `LoadLibraryA(legit_dll)` — picks a DLL with a stable `.text` and known exports.
2. Add a VEH handler (T-003 family) for `EXCEPTION_SINGLE_STEP`.
3. Walk the DLL's `.text` and set hardware breakpoints (DR0-DR3) on each EAT export entry.
4. Overwrite the EAT entries' function bodies with shellcode; the original instructions are saved.
5. Apply per-section protection: `R`, `RW`, `RX`, `RWX` per `IMAGE_SCN_*` flags — no blanket RWX.
6. Apply PE relocations: walk `.reloc` table, handle `IMAGE_REL_BASED_DIR64` (apply delta to 64-bit), `IMAGE_REL_BASED_HIGHLOW` (apply delta to 32-bit), skip `IMAGE_REL_BASED_ABSOLUTE` padding.
7. When external code calls an EAT entry, the DR0 trap fires `EXCEPTION_SINGLE_STEP`; the VEH handler redirects to your shellcode (or back to original if it's an internal call you want to pass-through).
8. The shellcode runs from `MEM_IMAGE` backed by the signed DLL.

### 12. Reflective PE Loader — `crowd/src/pe_loader.rs`
1. Stage the raw PE bytes (in-memory or file-backed — your choice).
2. `NtAllocateVirtualMemory` at the PE's preferred `ImageBase` (or relocate if collision).
3. Map headers, then walk `IMAGE_SECTION_HEADER` and map each section to its `VirtualAddress`.
4. Apply `.reloc` deltas if base differs from preferred.
5. Walk `IMAGE_DIRECTORY_ENTRY_IMPORT` — for each `IMAGE_THUNK_DATA`, resolve via PEB walker + DJB2 hash.
6. Patch `IMAGE_DIRECTORY_ENTRY_TLS` callbacks and run them in order.
7. Call `AddressOfEntryPoint(DLL_PROCESS_ATTACH)`.
8. **The module is never entered into `PEB->Ldr->InLoadOrderModuleList`** — invisible to `EnumProcessModules`, `NtQueryInformationProcess(ProcessImageFileName)`, toolhelp snapshots.

## Operational Profile

### When to Use
- **Module Overloading** (#7): default choice when you need `MEM_IMAGE` backing and zero Win32 imports. Pair with T-014 for the spawn, T-012 for execution.
- **Reflective PE Loader** (#12): when you want the *whole* implant DLL invisible to PEB-walking tools. Run your entire C2 client this way.
- **Vectored Overloading** (#11): when the target EDR scans `.text` of loaded DLLs but respects HW breakpoints; use for EAT-redirect persistence.
- **Process Hypnosis** (#2): target EDR aggressively hooks `NtAllocateVirtualMemory` *and* `NtWriteVirtualMemory` in the remote process — the debug port gives you a write primitive that bypasses both.
- **WaitingThread Hijack** (#3): when thread creation itself is alerted — you steal an existing thread so no `ThreadStart` ETW event fires.
- **Mapping Injection** (#4): general-purpose primitive when you want `MEM_PRIVATE` mapping that bypasses `NtWriteVirtualMemory` entirely; also the delivery vehicle for #3.
- **Early Bird APC** (#10): standard first-run primitive for getting code execution before the legitimate entry point runs — pairs with T-014.
- **Function Stomping** (#6): short-lived code execution where you can scope the stomp to a single function and let `StompGuard::Drop` clean it.

### When NOT to Use
- **Process Hollowing** (#1): signature is loud; `NtUnmapViewOfSection` on the original image of a freshly-spawned process is a well-known EDR trigger. Use T-012 instead.
- **Module Stomping** (#5): `LoadLibraryEx` with `DONT_RESOLVE_DLL_REFERENCES` is itself a flag-of-interest. Prefer Module Overloading (#7) which skips Win32 entirely.
- **Callback Execution** (#8) / **Fiber Execution** (#9): fine for *in-process* execution, but don't try to use these for cross-process injection — they're shellcode runners, not injectors.
- **Process Hypnosis** (#2): requires `SeDebugPrivilege` semantics for cross-process; debug port attach can be noisy if the target process is already being debugged.
- **Reflective PE Loader** (#12): expensive — full PE relocation + IAT resolution. Don't use for a one-shot shellcode chunk; use a stageless full DLL.

### Kill Chain Position
This card spans the entire post-initial-access chain. Typical placements:

```
Access gained (phishing /w T-021 WebView2 overlay)
    ↓
T-014 NtCreateUserProcess (suspended, PPID=explorer, block-DLL)
    ↓
T-013 #10 Early Bird APC   ←(preferred) or  T-012 Early Cascade
    ↓
T-013 #12 Reflective PE Loader  → loads full client_rust RAT
    ↓
T-005 Ekko sleep obfuscation
    ↓
T-016 EDR evasion (AMSI / ETW / stack spoof)
    ↓
T-017 persistence layer (one of COM hijack, NTFS EA, schtask, TLS, PhantomPersist)
```

For scenarios where you can't get a suspended process spawn (e.g., already in-proc inside Word):
```
T-013 #6 Function Stomping (short-lived execution) → T-013 #11 Vectored Overloading (persistence hook) → T-013 #12 Reflective PE Loader (full RAT)
```

### Trade-offs

| Dimension | Rating | Notes |
|---|---|---|
| Stealth — Reflective PE Loader | 9/10 | Invisible to PEB walkers; only memory scanner with bytes-sig will catch |
| Stealth — Module Overloading | 9/10 | `MEM_IMAGE` backed, pure syscall, zero Win32 surface |
| Stealth — Vectored Overloading | 8/10 | HW bp-based EAT redirect; only caught by DR-register scanning EDRs |
| Stealth — Process Hypnosis | 8/10 | No VirtualAllocEx / CreateRemoteThread — debug port is unusual but rarely alerted |
| Stealth — WaitingThread Hijack | 7/10 | No thread creation, but stolen thread is "wrong wait state" on resume |
| Stealth — Mapping Injection | 6/10 | `MEM_PRIVATE` `PAGE_EXECUTE_READ` mapped view is detectable; not as clean as `MEM_IMAGE` |
| Stealth — Module Stomping | 5/10 | `DONT_RESOLVE_DLL_REFERENCES` flag + `chakra.dll` is a known IOC |
| Stealth — Process Hollowing | 4/10 | Classic technique, heavily signatured; `NtUnmapViewOfSection` on legit image is loud |
| Reliability | 8/10 across the board | All use syscall primitives; failure modes are mostly version-related, not race-related |
| Complexity — Reflective PE Loader | 9/10 | Full PE loader is ~600 LoC; reloc + IAT + TLS must be exact |
| Complexity — Vectored Overloading | 8/10 | VEH handler + HW bp + reloc = many moving parts |
| Version range | Win7+ (Hollowing, Fiber, Callback) / Win8.1+ (most others) / Win10+ (Hypnosis, Vectored) | Hypnosis relies on debug semantics that changed in 1709; Vectored needs SEHOP-friendly VEH |
| Privilege needed | medium-IL for in-proc / high-IL+SeDebugPrivilege for cross-process | Reflective PE Loader needs none if in-process |

## Rust Implementation Deep Dive

### `bail_close!` macro (process_hollow.rs)
The macro expands to a `struct BailGuard { handle: HANDLE }` implementing `Drop` to call `NtClose`. Every handle acquired in hollowing (`NtOpenProcess`, `NtOpenThread`, etc.) is wrapped. **Why this matters for operators**: if you modify the chain and add an early return, the macro means you don't have to audit every exit point — `Drop` runs unconditionally. Cite: `bail_close!` in `crowd/src/process_hollow.rs`.

### `StompGuard` (func_stomp.rs)
```rust
pub struct StompGuard {
    addr: usize,
    original: Vec<u8>,
    size: usize,
}
impl Drop for StompGuard {
    fn drop(&mut self) {
        // restore bytes, flip protection back to RX
    }
}
```
This is the cleanest pattern in the file for *bounded* stomping. Cite: `StompGuard` in `crowd/src/func_stomp.rs`. If you need a bounded-overwrite primitive for any other file in the vault, copy this struct rather than rolling your own.

### `core::arch::asm!` usage
Direct syscall stubs in T-013 files are *not* inline `asm!` — they go through `crate::recycled::nt_*` wrappers (T-001 RecycledGate). The only `asm!` block in this card's files is in `vectored_overloading.rs` for `RtlAddVectoredExceptionHandler` registration via the export's call signature, and for the inline HW-bp-set helper:
```rust
unsafe { asm!("mov dr0, {0}", inlateout(reg) addr) }
```
with clobbers on `rax` (scratch for `mov dr` register semantics). Cite: `vectored_overloading.rs::set_hw_bp`.

### FFI patterns
- All NT types come through `windows_targets::link!` macros in `wrappers.rs`. Handles are `isize` aliases. Cleanup is explicit `NtClose`, not RAII — except where `bail_close!` or `StompGuard` wraps it.
- `PS_ATTRIBUTE_LIST` layout in T-013 files when paired with T-014: variable-length trailing array; the struct has a `Count` field followed by `Count` entries. Operators adding new attributes must reallocate with the correct total length.

### Initialization
- `OnceLock<RecycledGate>` (T-001) is lazily populated the first time any T-013 file calls `crate::recycled::nt_*`. Don't try to "warm" it earlier — pre-warming triggers SSN resolution events at unexpected points.
- `LazyCell<SyscallMap>` in `sysindirect_map.rs` builds the SSN+gadget map once; all T-013 syscall sites consume it.

### Error paths
- `process_hollow.rs`: `?` propagation with `bail_close!` cleanup. Failures during context patch (step 7) leave the remote process in a usable but half-stomped state — *kill it* before exit.
- `hypnosis.rs`: panics on unexpected debug event class. Not graceful. If you encounter a non-standard event, change to `bail!` instead of `panic!`.
- `vectored_overloading.rs`: silently swallows reloc-application failures (`IMAGE_REL_BASED_*` types it doesn't handle). Add a counter and log if you see them — silently-skipped relocations = corrupted code.
- `pe_loader.rs`: returns `Result<...>` with a `LoaderError` enum; *does not* cleanup partial mappings on drop. Operator must explicitly call `unload()`.

### Memory layout
- `StompGuard`: 3 × usize + Vec<u8>. 32 bytes header + N bytes payload. Trivially `Send`/`Sync`. Alignment not critical.
- `PS_ATTRIBUTE_LIST`: header (8 bytes for `Count` on x64) + N × 16-byte entries (`Attribute` × `Size` × `Value` × `ReturnLength`-ish). Note `PS_ATTRIBUTE_LIST` is variable-length — don't take `&'static PS_ATTRIBUTE_LIST`; always allocate on the stack or heap with the right count.

## Edge Cases & Failure Modes

1. **Mapping Injection with `ViewShare` instead of `ViewUnmap`** — original code. Sections propagate to child processes. Symptom: VAD dump on a child process you spawned later shows unexpected mapped section. Workaround: always use `ViewUnmap = 2`; this is now the default but verify if you forked the file.

2. **Process Hypnosis on Win10 1709+** — debug event delivery timing changed. The `CREATE_PROCESS_DEBUG_EVENT` may arrive *after* `LOAD_DLL_DEBUG_EVENT` for ntdll in some builds. Symptom: `lpStartAddress` is `nullptr` when you try to write. Workaround: wait for the first `EXCEPTION_BREAKPOINT` (the loader's initial `int3`) before writing.

3. **WaitingThread Hijack against `WrQueue` threads in thread-pool-bound processes** — the thread may be re-used by `kernel32!BaseThreadInitThunk` with new context, overwriting your `Rip` patch. Symptom: shellcode never runs; thread resumes from original code. Workaround: filter to `DelayExecution` and `WrAlertByThreadId` only, or pair with `T-007 Pool Party` for threadpool-aware injection.

4. **Module Stomping when `chakra.dll` is not present** — Win10 LTSC and Server Core don't ship it by default. Symptom: `LoadLibraryEx` returns `NULL`, `GetLastError = 126`. Workaround: fall back to `msvcp_win.dll` or `rpcrt4.dll` (both large `.text`, Microsoft-signed, universal).

5. **Module Overloading when target DLL is already mapped** — `NtCreateSection(SEC_IMAGE)` succeeds but `NtMapViewOfSection` may map a *fresh* view rather than reuse the existing one. Symptom: image base in target differs from `Ldr->InLoadOrderModuleList` entry — confusing for memory scanners that diff the two. Workaround: pick a DLL *not* already loaded in the target.

6. **Function Stomping a function with hot-patch prologue** — many `kernel32` exports have a 5-byte hot-patchable `mov edi, edi` prologue. If you stomp into the middle, you bypass the patch but a later hook installer may overwrite your bytes. Symptom: shellcode vanishes mid-execution. Workaround: stomp at the *true* entry point (offset 0), not at +5.

7. **Callback Execution via `EnumSystemCodePagesA` on systems where the callback runs under loader lock** — `EnumSystemCodePages` does not; but `EnumDateFormatsA` does in some SKUs. Symptom: shellcode deadlocks. Workaround: stick to `EnumSystemCodePagesA` / `EnumChildWindows`.

8. **Fiber Execution from inside a fiber-aware host (e.g., `mscorsvc`)** — the host may have already converted the thread to a fiber; calling `ConvertThreadToFiber` returns `NULL`. Symptom: `GetLastError = ERROR_INVALID_PARAMETER` (some fiber already exists). Workaround: `IsThreadAFiber()` check, or `CreateFiberEx` with explicit stack.

9. **Early Bird APC against process that calls `NtTestAlert` early** — if the loader's first alertable wait completes *before* your APC is queued, the APC sits in the queue and never fires. Symptom: shellcode never runs, process proceeds normally. Workaround: queue the APC *before* `NtResumeThread` — this is what `early_bird.rs` does, but verify your modifications don't reorder.

10. **Vectored Overloading: HW bp exhaustion** — only 4 DR registers (`DR0-DR3`). If the target DLL has more than 4 exports you want to hook, you have to time-share: set/clear per-call. Symptom: `STATUS_BREAKPOINT` not delivered on 5th export call. Workaround: pick a DLL with ≤4 strategic exports, or fall back to IAT hooking (T-008 Threadless shape).

11. **Reflective PE Loader: TLS callbacks crash because they expect `LdrpTlsFlsIndex`** — TLS callbacks in legitimate DLLs sometimes call `FlsAlloc` machinery that the manual loader didn't set up. Symptom: TLS callback AVs on entry. Workaround: skip TLS callback invocation (`run_tls = false`) for non-TLS-dependent DLLs.

12. **Process Hollowing on PPL-protected targets** — `NtUnmapViewOfSection` on a PPL process returns `STATUS_ACCESS_DENIED`. Symptom: unmap fails with `0xC0000022`. Workaround: don't target PPL processes with hollowing — use T-007 Pool Party or T-012 Early Cascade instead.

## Variant Ideas

- **V1 — Mapping Injection + `MEM_IMAGE` backing**: instead of `SEC_COMMIT`, use `SEC_IMAGE` backed by a known DLL file. You get `MEM_IMAGE` on the remote side without LoadLibrary. This is half of Module Overloading (#7) but you can apply it as a transport-only change to #3 (WaitingThread) and #4 (Mapping) — operators shouldn't have two different primitives for the same job.

- **V2 — Hypnosis via `NtDebugAttachProcess`** instead of `CreateProcess(DEBUG_ONLY_THIS_PROCESS)`: lets you *attach* to an already-running process as a debugger. Same write primitive, no spawn event. Useful when the target process is a long-running one you don't want to restart.

- **V3 — Function Stomping as ephemeral API**: expose `StompGuard::new(addr, shellcode)` as a public API across the vault. Currently it's only in `func_stomp.rs`. Other files (e.g., `early_cascade.rs`, `pool_party.rs`) could use it for trampoline-style short-lived execution.

- **V4 — Callback Execution with API-set-targeted callbacks**: instead of `EnumSystemCodePagesA`, use `RtlPcToFileName` or `EtwpTraceBinaryHeader` — less-common callback invokers that bypass EDR signatures targeting the standard 5-6 callbacks.

- **V5 — Reflective PE Loader + T-018 BYOVD for kernel shadows**: combine #12 with BYOVD loading to keep the reflective DLL out of even kernel-level process module snapshots. Speculative — requires the BYOVD driver to clear the module from `PsLoadedModuleList` notification routines.

- **V6 — Vectored Overloading as a load-time persistence layer**: chain with T-017 TLS callback persistence — TLS callback fires, sets HW bp on a target DLL's EAT, future invocations of that export route through your shellcode. Survives reboot.

- **V7 — Fiber Execution for stack-spoofed syscalls**: convert the calling thread to a fiber, switch *to* a fiber whose stack you've manually laid out with a fake `NtdllUserThreadStart` return address. Combines #9 with T-016 advanced stack spoof.

- **V8 — Module Overloading with delayed backing**: `NtCreateSection(SEC_RESERVE)` first, then later upgrade to `SEC_IMAGE`. Lets you reserve address space before the shellcode arrives — useful for slow C2 staging.

## OPSEC Notes

### Artifacts left behind
- **Process Hollowing**: hollowed process's image path in `PROCESS_BASIC_INFORMATION` may not match `ImageBaseAddress` content — suspicious to EDRs that diff these. The hollowed image's `IMAGE_DOS_HEADER` is from your payload, not the original. Clean by writing a fake DOS stub.
- **Module Stomping / Function Stomping**: the DLL appears in `PEB->Ldr` lists. `EnumProcessModules` will show `chakra.dll` loaded by your process — unusual in many contexts. Clean: PEB unlink (T-016) after stomping.
- **Mapping Injection**: `VAD` entry for `MEM_PRIVATE PAGE_EXECUTE_READ` mapped view. Use `MEM_MAPPED` + `SEC_IMAGE` variant (V1 above) to make it look like a normal DLL load.
- **Reflective PE Loader**: no PEB entry, but the VAD for `MEM_PRIVATE` is suspicious. Allocate at a "natural" base (e.g., near other loaded modules) and use `MEM_IMAGE` page hints if possible.
- **Vectored Overloading**: HW bp registers `DR0-DR3` are set in the target's threads. EDRs that scan DR registers (rare but EDR-grade) will see them. Clean: clear DRs after shellcode finishes its initial run, or convert the trigger to a software bp.

### Telemetry
- **Early Bird APC**: `Microsoft-Windows-Kernel-AuditAPI` logs `QueueUserAPC` calls if audit policy is on. Pair with T-016 ETW muffling.
- **Hypnosis**: `DEBUG_STRING` ETW events from `Microsoft-Windows-Kernel-Process` for debug port attach/detach.
- **Module Stomping via LoadLibraryEx**: `Microsoft-Windows-ImageLoad` fires — image load event with `DONT_RESOLVE_DLL_REFERENCES` is unusual.
- **Module Overloading** (#7): no image-load ETW event because LoadLibrary isn't called. *This is the OPSEC win.*

### EDR-specific notes
- **CrowdStrike Falcon**: heavily signatures `NtUnmapViewOfSection` on legit images — avoid Hollowing (#1) entirely against CS.
- **SentinelOne**: scans DR registers periodically; Vectored Overloading may be flagged.
- **Microsoft Defender for Endpoint**: ETW-TI hooks `NtMapViewOfSection` — Module Overloading (#7) appears as `MapViewOfSection` event but with benign-looking image path. Wins on signature, loses on telemetry correlation if your behavior post-load is anomalous.
- **Elastic EDR**: low-volume on debug-port operations; Hypnosis (#2) tends to fly under Elastic.

### Cleanup procedures
- All stomping variants: ensure `StompGuard::drop` runs before exit. For non-RAII variants, restore original bytes via saved buffer.
- Reflective PE Loader: explicit `unload()` to `VirtualFree` the backing memory. Leftover mapping is the most common reason a memory scanner hits on this technique.
- Hypnosis: `DebugSetProcessKillOnExit(FALSE)` + `CloseHandle(debug_port)`. If you don't detach cleanly, the target process is killed when your process exits.

## Reusable Patterns

### Pattern: `bail_close!` RAII handle guard
- **Use when**: any chain of `NtOpen*` / `NtCreate*` calls where early-return paths need consistent cleanup.
- **How**: macro wraps a `HANDLE` in a struct that calls `NtClose` on `Drop`. Use in any new technique file that acquires handles.
- **Code ref**: `crowd/src/process_hollow.rs::bail_close!`

### Pattern: `StompGuard` for bounded byte overwrite
- **Use when**: you need to temporarily overwrite a code region and guarantee restoration.
- **How**: struct holds `(addr, original_bytes, size)`; `Drop` writes original back and flips protection. Pair with PEB walker + PE export resolution.
- **Code ref**: `crowd/src/func_stomp.rs::StompGuard`

### Pattern: Per-section protection via `IMAGE_SCN_*` flags
- **Use when**: mapping a PE in-process and you want to honor on-disk protection flags rather than applying blanket RWX.
- **How**: iterate `IMAGE_SECTION_HEADER`, mask `Characteristics` against `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE`, call `NtProtectVirtualMemory` per section.
- **Code ref**: `crowd/src/vectored_overloading.rs::apply_section_permissions`

### Pattern: PEB-only export resolution via DJB2
- **Use when**: any resolution path that must avoid `GetProcAddress` (hooked by EDRs).
- **How**: walk `PEB->Ldr->InLoadOrderModuleList`, for each module parse export directory, hash each name with DJB2, compare to expected hash.
- **Code ref**: `crowd/src/func_stomp.rs::resolve_export`, also T-004 PEB Walker card.

### Pattern: Alertable-wait APC delivery during loader init
- **Use when**: getting code execution before a process's legitimate entry point.
- **How**: spawn suspended, queue APC to main thread, resume — the APC dispatches in the loader's first alertable wait before `AddressOfEntryPoint`.
- **Code ref**: `crowd/src/early_bird.rs::inject_early_bird`, T-012 Early Cascade for the more thorough version.
```

---

```
---
id: T-014
name: NtCreateUserProcess (Direct NT Process Creation)
category: process-injection
tier: S
mitre: T1055, T1134.004, T1574.001, T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-004, T-015]
enables: [T-012, T-013, T-007, T-005, T-016, T-017]
min_windows: Win Vista+
needs_admin: no
tags: [injection, process-creation, ppid-spoofing, block-dll, pure-nt, syscall, ps-attribute-list]
---

# NtCreateUserProcess — Operator Playbook

## TL;DR
A single syscall that does what `CreateProcessW` does — spawn a process — but with three operational advantages: (1) it bypasses the entire `kernelbase!CreateProcessInternalW` hook chain that *every* EDR instruments as its first telemetry source; (2) it folds PPID spoofing, Block-DLL policy, and suspend into the *same* `PS_ATTRIBUTE_LIST` argument, eliminating the `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` surface; (3) it lets you read the PID/TID back from the same call. This is the **default spawn primitive** for any chain that needs a fresh process.

## How It Works

### NT-level process creation path
1. **Resolve `NtCreateUserProcess`** via PEB walker (T-004) against `ntdll.dll`. SSN retrieved via the T-002 cascade (FreshyCalls → Hell's Gate → Halo's Gate → Tartarus Gate). Call site is wrapped through T-001 RecycledGate so the syscall instruction itself executes from a `ntdll!` gadget, not from your own `.text`.
2. **Build the `RTL_USER_PROCESS_PARAMETERS`** struct. This is what `kernel32!CreateProcessInternalW` normally builds for you. Required fields: `ImagePathName.Buffer` (NT path, e.g. `\??\C:\Windows\System32\svchost.exe`), `CommandLine.Buffer`, `Environment` (you can pass `NULL` to inherit, but explicit is safer), `StartInfo` (`STARTUPINFOEX`-shaped, but the NT version). Use `RtlCreateProcessParametersEx` if you don't want to hand-build.
3. **Build `PS_ATTRIBUTE_LIST`** with up to `PS_ATTRIBUTE_LIST`'s `Count` entries:
   - `PS_ATTRIBUTE_IMAGE_NAME` (`0x00020005`): `UNICODE_STRING` for the image path, in NT form.
   - `PS_ATTRIBUTE_PARENT_PROCESS` (`0x00060000`): `HANDLE` to the parent-to-spoof. The spawned process will inherit this process's PID as its `ParentProcessId` in `PROCESS_BASIC_INFORMATION`. You must open this with `PROCESS_CREATE_PROCESS` access.
   - `PS_ATTRIBUTE_MITIGATION_OPTIONS` (`0x2000F`): a 64-bit bitfield; setting `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` (bit 0x2) gives you Block-DLL.
   - `PS_ATTRIBUTE_CLIENT_ID` (`0x10000`): a pointer to a `CLIENT_ID` that receives `{PID, TID}` post-spawn.
4. **Build `PS_CREATE_INFO`**: a `CREATE_STATE` of `PsCreateSucceeded` after the call; you initialize it to `PsCreateInitialState` and the kernel updates it.
5. **Call `NtCreateUserProcess`**:
   ```rust
   NtCreateUserProcess(
       &mut hProcess,         // OUT HANDLE
       &mut hThread,          // OUT HANDLE
       PROCESS_ALL_ACCESS | THREAD_ALL_ACCESS,
       0,                     // ObjectAttributes (often NULL)
       0,                     // ObjectAttributes for thread
       PS_FLAG_CREATE_SUSPENDED,  // ProcessFlags — bit for suspend
       0,                     // ThreadFlags — also suspend
       0,                     // Environment block (NULL = inherit)
       &process_parameters,
       &proc_info,            // PPS_CREATE_INFO
       &attr_list             // PPS_ATTRIBUTE_LIST
   )
   ```
6. The kernel does the work of `NtOpenProcess` (parent), `NtCreateSection` for the image, `NtCreateProcessEx`, `NtCreateThreadEx`, attribute application — all in one call. No usermode hook layer exists *between* you and the kernel.
7. **PPID verification**: post-call, the new process's `PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId` will equal the parent's PID you specified.

### Memory state
- The new process's address space is created from the parent's `SectionObject` — a clean copy.
- The loader (in `ntdll!LdrInitializeThunk`) is queued on the suspended thread but has not yet run.
- This is the entry point for T-012 Early Cascade (queue an APC *before* the loader runs) or T-013 #10 Early Bird APC.

### Race conditions
- **None in the syscall itself** — `NtCreateUserProcess` is atomic from usermode's perspective.
- The only timing consideration is when the parent-to-spoof is being torn down: if you pass a handle to a process that exits between your `NtOpenProcess` and `NtCreateUserProcess`, the call returns `STATUS_INVALID_PARAMETER` (`0xC000000D`).
- If you queue an APC immediately after this call, there's a small window where the kernel has not yet set the thread's wait state. `NtAlertThread` before this completes returns `STATUS_ALERTED` but the APC doesn't fire — re-queue after a brief `Sleep` if needed.

## Operational Profile

### When to Use
- **Default spawn primitive** for any chain that needs a fresh process. Always prefer this over `CreateProcessW` unless you're operating in a context where EDR isn't installed (low-stakes dev/test).
- **PPID spoofing to a Microsoft-signed parent** (typically `explorer.exe`, `svchost.exe`, `runtimebroker.exe`) — the spawned child appears as a child of a benign process, breaking process-tree heuristics.
- **Block-DLL policy combined with spawn** — prevents non-Microsoft DLLs (i.e., EDR products) from being injected into the child via standard `LoadLibrary` hooks. EDRs that rely on injected DLLs for telemetry into the child will be *blind*.
- **Spawn-as-suspended for Early Cascade / Early Bird** — the child's suspended main thread gives you a clean injection target.
- **Direct Win32 bypass** — when the target EDR is heavily invested in `CreateProcessInternalW` hooks (most are).

### When NOT to Use
- **PPL-protected target parent**: opening a PPL process with `PROCESS_CREATE_PROCESS` returns `STATUS_ACCESS_DENIED`. PPID spoof to non-PPL processes only.
- **Image path doesn't have a known-good signature**: `NtCreateUserProcess` doesn't validate signatures for you (that's `CreateProcessW` + `WLDP` integration). If you spawn an unsigned binary, the child gets the same scrutiny any unsigned spawn would.
- **Need command-line obfuscation**: the `RTL_USER_PROCESS_PARAMETERS.CommandLine` is visible via `NtQueryInformationProcess(ProcessCommandLineInformation)`. Use a different mechanism (e.g., T-016 arg spoofing) if you need to alter this post-spawn.
- **Cross-architecture spawn**: `NtCreateUserProcess` inherits parent architecture unless you spawn an explicit cross-arch binary. Use the WoW64 shim path for that — direct NT doesn't handle the transition cleanly.

### Kill Chain Position
This is the **first link** of most modern chains:

```
T-004 PEB walk → T-002 SSN resolve → T-001 RecycledGate (syscall dispatch)
    ↓
T-014 NtCreateUserProcess (spawn + PPID + block-DLL + suspend)
    ↓
T-012 Early Cascade inject  ←(preferred for stealth)
    or T-013 #10 Early Bird APC
    or T-007 Pool Party (if you target the child's threadpool)
    ↓
T-005 Ekko ROP sleep
    ↓
T-016 EDR evasion suite (AMSI, ETW, stack spoof)
    ↓
T-017 persistence layer
```

Alternative placement — **late-chain lateral spawn**:
```
T-013 #12 Reflective PE Loader (already running) → T-014 spawn sacrificial process → T-011 Dirty Vanity reflect the child → exfil via reflected copy
```

### Trade-offs

| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 9/10 | No `CreateProcessW` hook hit; PPID and Block-DLL in one call; the only ETW events are kernel-level `ProcessStart` (which fires regardless of API) |
| Reliability | 9/10 | Atomic syscall; failure modes are version-specific (struct layout changes) not race conditions |
| Complexity | 7/10 | Building `RTL_USER_PROCESS_PARAMETERS` + `PS_ATTRIBUTE_LIST` correctly is ~80 LoC; gets worse if you have to hand-marshal `STARTUPINFOEX` |
| Version range | Win Vista+ | struct layouts stable since Vista; `PS_ATTRIBUTE_LIST` field set has been stable since Vista SP1 |
| Privilege needed | medium-IL minimum | High-IL needed if target parent is medium-IL with `PROCESS_CREATE_PROCESS` ACL restrictions (rare) |

## Rust Implementation Deep Dive

### File reference
`dark_crystal/crowd/src/nt_create_process.rs` — the canonical impl. The same shape appears in `dark_crystal/crates/core/src/experimental/injection/nt_create_user_process.rs` for the experimental path.

### `unsafe` boundaries
The function has three unsafe blocks:
1. **Marshaling the attribute list**: building `PS_ATTRIBUTE_LIST` requires writing variable-length struct via pointer arithmetic. The unsafe block here is `ptr::write_unaligned` for each entry; if `Count` is wrong, you write past the buffer.
2. **Invoking the syscall**: the actual `NtCreateUserProcess` call via `crate::recycled::nt_create_user_process()`. Returns `NTSTATUS`. The `OUT` handles are written via raw `*mut HANDLE`.
3. **Reading `CLIENT_ID` back**: the `PS_ATTRIBUTE_CLIENT_ID` entry's `ReturnLength` is checked after the call; the value is read via `ptr::read_unaligned`.

### `core::arch::asm!` usage
This file itself has no inline `asm!` — all syscall dispatch is delegated to T-001 (RecycledGate). The RecycledGate stub in `crates/core/src/sys_recycled.rs` uses `core::arch::asm!` with the syscall gadget pattern (jump to ntdll stub's syscall instruction offset, indirect call). Cite: `sys_recycled.rs::syscall_dispatch`.

### FFI patterns
The NT API binding is via `windows_targets::link!` in `wrappers.rs`:
```rust
windows_targets::link!("ntdll.dll", "system" fn NtCreateUserProcess(
    ProcessHandle: *mut HANDLE,
    ThreadHandle: *mut HANDLE,
    ProcessDesiredAccess: u32,
    ThreadDesiredAccess: u32,
    ProcessObjectAttributes: *const OBJECT_ATTRIBUTES,
    ThreadObjectAttributes: *const OBJECT_ATTRIBUTES,
    ProcessFlags: u32,
    ThreadFlags: u32,
    Environment: *const c_void,
    ProcessParameters: *const RTL_USER_PROCESS_PARAMETERS,
    CreateInfo: *mut PS_CREATE_INFO,
    AttributeList: *mut PS_ATTRIBUTE_LIST,
) -> i32);
```
The `crate::recycled::nt_create_user_process()` wrapper intercepts this via T-001 to ensure the actual syscall instruction is in `ntdll!`'s `.text`, not yours. **Operators modifying this file should not call `NtCreateUserProcess` directly** — always go through `recycled::nt_create_user_process`.

### Handle ownership
- `OUT HANDLE ProcessHandle` and `ThreadHandle` are owned by you post-call. Wrap in `bail_close!` (see T-013 pattern).
- The parent process handle you opened for `PROCESS_CREATE_PROCESS` is yours to close — close it after the spawn call.
- The `CLIENT_ID` returned via `PS_ATTRIBUTE_CLIENT_ID` is a value-type — no ownership.

### Initialization
- `OnceLock<SyscallMap>` (T-004) populates SSN for `NtCreateUserProcess` lazily on first call. Don't try to populate earlier — pre-population triggers ETW events from the SSN-resolution walk.
- `LazyCell` holds the `PS_ATTRIBUTE_LIST` template if you're spawning multiple identical processes; otherwise build fresh each call.

### Error paths
- `STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`): image path is wrong. Often a missing `\??\` prefix.
- `STATUS_OBJECT_PATH_NOT_FOUND` (`0xC000003A`): directory in path doesn't exist.
- `STATUS_INVALID_IMAGE_NOT_MZ` (`0xC000012F`): target is not a valid PE.
- `STATUS_ACCESS_DENIED` (`0xC0000022`): parent handle lacks `PROCESS_CREATE_PROCESS`, or PPL mismatch.
- `STATUS_INVALID_PARAMETER` (`0xC000000D`): usually `PS_ATTRIBUTE_LIST.Count` doesn't match the actual number of entries, or attribute `ReturnLength` is `NULL` on a return-type attribute.

The code returns `Result<SpawnedProcess, NtError>` and *does not* cleanup partial state — operator must check `STATUS` and clean up.

### Memory layout
- `RTL_USER_PROCESS_PARAMETERS`: variable-size due to embedded `UNICODE_STRING` buffers. Layout stable since Vista x64. Field `Length` at offset 0x0, `MaximumLength` at 0x4; struct size up to ~0x300 for typical command lines.
- `PS_ATTRIBUTE_LIST`: header (`Count`, `TotalSize`) + N × `PS_ATTRIBUTE` (24 bytes each on x64: `Attribute: u64`, `Size: usize`, `Value: usize` + padding; effectively 24 bytes). The buffer must be sized as `size_of::<PS_ATTRIBUTE_LIST_HEADER>() + N * size_of::<PS_ATTRIBUTE>()`.
- `PS_CREATE_INFO`: ~88 bytes on x64. Stable layout.

## Edge Cases & Failure Modes

1. **Win10 1903+ with strict image-load auditing** — `Microsoft-Windows-Kernel-Process` event ID 1 (process start) still fires for `NtCreateUserProcess`. The win isn't avoiding the event; it's avoiding the *usermode telemetry chain*. Don't expect this technique alone to evade a properly-configured EDR.

2. **PPID spoofing to a process being torn down** — if the parent exits between your `NtOpenProcess` and `NtCreateUserProcess`, call returns `STATUS_INVALID_PARAMETER`. **Symptom**: error code `0xC000000D`. **Workaround**: re-open the parent immediately before the spawn call; or pick a parent that's known-stable (`services.exe` is a good choice — it never exits while the system is running).

3. **Block-DLL policy and `mrt.exe` / `mpengine.exe`** — on Win10+ with Defender real-time protection, the spawned child of a Block-DLL'd process may still get `mpengine.dll` injected because Defender uses kernel-level injection (not LoadLibrary). Block-DLL doesn't stop kernel injection. **Symptom**: child shows unexpected DLLs in `EnumProcessModules`. **Workaround**: pair with `T-016 Block-DLL Policy + PROCESS_MITIGATION_POLICY_*` more thoroughly, or use a sacrificial child you'll exit quickly.

4. **`PS_ATTRIBUTE_LIST` underallocation** — common bug. If `Count = 4` but buffer is sized for 3, `NtCreateUserProcess` returns `STATUS_INVALID_PARAMETER` and the `CreateInfo.State` field shows `PsCreateFailExeName` or `PsCreateFailExeFormat`. **Symptom**: random `STATUS_INVALID_PARAMETER` with no clear reason. **Workaround**: assert `size == size_of::<PS_ATTRIBUTE_LIST_HEADER>() + Count * size_of::<PS_ATTRIBUTE>()`.

5. **Cross-WOW64 spawn from 64-bit process** — `NtCreateUserProcess` doesn't auto-detect that you want a 32-bit child. The image path *must* resolve to a 32-bit PE for the spawn to succeed, but the `RTL_USER_PROCESS_PARAMETERS` is in 64-bit layout. The kernel handles the conversion, but you must have `ntdll!LdrpWowl32` machinery ready — i.e., WoW64 must be installed. **Symptom**: `STATUS_ARCHITECTURE_MISMATCH` (`0xC00000BD`). **Workaround**: ensure `syswow64` is present; on Server Core it's optional.

6. **`explorer.exe` as PPID target on Server Core** — `explorer.exe` doesn't exist on Server Core. **Symptom**: `crate::ppid::find_pid_by_name("explorer.exe")` returns `None`. **Workaround**: fall back to `services.exe` (PID 12 typically) or `svchost.exe` with a known network service group.

7. **Image path needs `\??\` or `\Device\HarddiskVolume?\` prefix** — `CreateProcessW` accepts `C:\Windows\System32\...`, but `NtCreateUserProcess` requires an NT path. **Symptom**: `STATUS_OBJECT_NAME_INVALID` (`0xC0000033`). **Workaround**: prefix with `\??\` (DOS-device alias) — `\??\C:\Windows\System32\svchost.exe`. The `crate::ppid::to_nt_path()` helper handles this.

8. **Inheriting environment block from parent** — if you pass `Environment: NULL`, the child inherits *the calling process's environment*, not the parent-to-spoof's environment. EDRs sometimes check env var consistency with parent. **Symptom**: child's `%PROCESSOR_ARCHITECTURE%` etc. doesn't match parent's. **Workaround**: query the parent's environment block via `NtQueryInformationProcess(ProcessEnvironment)` and pass explicitly.

9. **Startup info mismatch with console subsystem** — if the target binary is console subsystem and your `STARTUPINFOEX`-equivalent doesn't specify a console handle, the spawn may attach to your parent's console. **Symptom**: child writes to your parent's console — visible in terminal-based recon. **Workaround**: pass `STARTF_USESTDHANDLES` with NULL handles, or `CREATE_NO_WINDOW` equivalent in `ProcessFlags`.

10. **`PS_ATTRIBUTE_MITIGATION_OPTIONS` layout changed across versions** — on Win10 1809+, the field is 64-bit; on older versions, only the low 32 bits are honored. **Symptom**: Block-DLL appears to not work on older builds. **Workaround**: detect `OSVERSIONINFOEX` and set high bits only on 1809+.

11. **`HANDLE` truncation in unsafe pointer writes** — the `*mut HANDLE` cast in the syscall wrapper is `usize`-sized on x64 (8 bytes), but on x86 builds it's 4 bytes. **Symptom**: silent corruption of handle values on x86 builds. **Workaround**: gate with `#[cfg(target_pointer_width = "64")]` and don't ship the x86 path.

## Variant Ideas

- **V1 — Spawn with `PS_ATTRIBUTE_TOKEN` (`0x6000C`)**: pass a stolen primary token to the child. Combines with T-016 arg-spoofed token theft. Lets you spawn a child running under a different identity without `CreateProcessWithToken` (heavily hooked).

- **V2 — Spawn with `PS_ATTRIBUTE_JOB_LIST` (`0x6000D`)**: assign the child to a pre-existing Job Object at spawn time. Useful for sandboxing the child's resource limits without a separate `AssignProcessToJobObject` call.

- **V3 — `PS_ATTRIBUTE_IMAGE_NAME` pointing to a phantom file**: spawn from a file that exists only transiently (delete-pending), e.g., the file from T-009 Process Ghosting. The spawn will succeed because the file is opened before deletion. This effectively chains T-014 with T-009.

- **V4 — Spawn with `PS_ATTRIBUTE_HANDLE_LIST` (`0x60000`)**: pass specific handles to the child at spawn. Cleaner than `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)` — same effect, no Win32 surface.

- **V5 — Combined spawn-and-reflect**: spawn via `NtCreateUserProcess`, immediately `NtCreateProcessEx` from the same image into a *different* address space via `PROCESS_CREATE_FLAGS_INVERTED_ASLR` to get a second copy for `T-011 Dirty Vanity`. Two copies, one syscall per, much less EDR surface than `CreateProcessW` + `RtlCreateProcessReflection`.

- **V6 — Spawn to a parent inside a different desktop/window station**: open parent from `WinSta0\\Default` while running in `Service-0x0-3e7\\Default`; the child inherits the parent's window station. Cross-session spawn without `WTSQueryUserToken` + `CreateProcessAsUserW` chain.

- **V7 — `PS_ATTRIBUTE_ERROR_MODE` (`0x6001C`)**: set `SEM_FAILCRITICALERRORS` on the child — child won't pop error dialogs. Useful for headless sacrificial processes.

- **V8 — Pair with T-008 Threadless** post-spawn: spawn the child with Block-DLL, then instead of injecting shellcode, use Threadless export-hijack on the loaded `ntdll!` exports — gives you execution inside a Block-DLL'd child without `NtAllocateVirtualMemory`.

## OPSEC Notes

### Artifacts left behind
- **Event 4688** (Process Creation, if audit-enabled) — this is unavoidable; it fires for *any* spawn. The PPID field in 4688 will show your spoofed parent — that's the win.
- **Event 1** from `Microsoft-Windows-Kernel-Process` — same as above; `ParentProcessID` reflects spoofed parent.
- **Event 4656** (Handle Requested) for the parent you opened with `PROCESS_CREATE_PROCESS`. **Clean**: open parent once, cache handle, reuse — don't re-open per spawn.
- **Event 4663** (Attempt to access an object) for the parent handle on the `CreateProcess` access right.
- **New child process VAD entries** — fresh `MEM_IMAGE` for `ntdll`, `kernel32`, the spawned binary. These are unavoidable; the question is whether your post-spawn injection technique adds suspicious VAD entries.
- **Handle table entry on the parent process** — your process holds a handle to the parent. **Clean**: close the parent handle *immediately after* the spawn call; don't hold it.

### Telemetry it generates
- **No usermode hook events from `CreateProcessInternalW`** — the primary OPSEC win. EDRs that hook `kernelbase!CreateProcessInternalW` see nothing.
- **No `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` calls** — secondary win. EDRs that hook the attribute-list APIs to detect `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` see nothing.
- **Kernel-level events fire regardless** — `NtCreateUserProcess` is the underlying syscall all process creation goes through, so the kernel-side telemetry is identical regardless of your usermode approach. The win is *usermode hook chain* avoidance, not kernel telemetry avoidance.

### EDR-specific notes
- **CrowdStrike Falcon**: heavily hooks `CreateProcessW` and `CreateProcessInternalW`. Bypassed entirely. However, Falcon also has a kernel notification routine (`PsSetCreateProcessNotifyRoutineEx`) that fires — the spawn is still detected, but the usermode analysis (which is what catches suspicious parent/child combos) is bypassed. Pair with PPID spoofing to a Microsoft-signed, well-known parent.
- **SentinelOne**: similar pattern; usermode hooks on `CreateProcess*` bypassed, kernel callback still fires. SentinelOne's analytics are heavily parent/child relationship based — PPID to `explorer.exe` or `services.exe` to blend.
- **Microsoft Defender for Endpoint**: relies less on usermode hooks and more on ETW + kernel callbacks. This technique alone provides modest value against MDE; combine with T-016 ETW muffling and T-013 #12 Reflective PE Loader for the post-spawn phase.
- **Elastic EDR**: stronger on correlation than hooks — spawn a known-benign binary (e.g., `notepad.exe`) with PPID=explorer, then inject — looks normal.

### Cleanup procedures
- Close the parent process handle (`PROCESS_CREATE_PROCESS`) immediately after spawn.
- Close the child process/thread handles if you're not going to inject — leaked handles show up in `SystemProcessInformation` handle dumps.
- If you spawned a sacrificial process for injection, ensure it's terminated before engagement end. A long-lived `notepad.exe` child of `services.exe` is an obvious anomaly.
- Audit the `PS_ATTRIBUTE_LIST` buffer for sensitive data (image path, parent PID) before freeing — Rust's `Drop` doesn't zeroize by default. Use `Zeroizing` wrapper for the buffer if you want belt-and-suspenders.

## Reusable Patterns

### Pattern: `PS_ATTRIBUTE_LIST` builder
- **Use when**: any direct NT process spawn with mitigation policies or PPID spoofing.
- **How**: helper struct `PsAttrList { count, buf: Vec<u8> }` with `push_image_name(path)`, `push_parent(handle)`, `push_block_dll()`, `push_client_id(&mut CLIENT_ID)` methods. Sizing the buffer correctly is the hard part — encapsulate it.
- **Code ref**: `crowd/src/nt_create_process.rs::PsAttrListBuilder`

### Pattern: NT-path conversion from DOS path
- **Use when**: any `NtCreate*` call that takes a path; DOS paths (`C:\...`) are not accepted.
- **How**: prefix `\??\` (device map alias) — yields `\??\C:\Windows\...`. For UNC paths, use `\??\UNC\server\share`. Don't forget to allocate the `UNICODE_STRING` buffer with a length in bytes (not chars).
- **Code ref**: `crowd/src/nt_create_process.rs::to_nt_path` (via `crate::ppid::to_nt_path`)

### Pattern: `bail_close!` for syscall output handles
- **Use when**: any NT call returning owned handles (`NtOpen*`, `NtCreate*`).
- **How**: same as in T-013 — `Drop` calls `NtClose`. Critical here because `NtCreateUserProcess` returns two handles; if you fail to inject after the spawn, you must still close both.
- **Code ref**: `crowd/src/process_hollow.rs::bail_close!`, reused in `nt_create_process.rs`

### Pattern: Mitigation-options bitfield
- **Use when**: applying process mitigations via NT path (Block-DLL, ACG, CFG, etc.).
- **How**: 64-bit bitfield; bit positions documented in `PROCESS_MITIGATION_POLICY` enum. Block-DLL = `0x2 << 0x8` on Win10 1809+; earlier versions honor only the low 32 bits. Build via `(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON as u64)`.
- **Code ref**: `crowd/src/nt_create_process.rs::mitigation_block_dll()`

### Pattern: Lazy SSN retrieval via `OnceLock`
- **Use when**: any syscall site to avoid repeated SSN resolution (which itself triggers PEB walks).
- **How**: `static SSN: OnceLock<u32> = OnceLock::new(); let ssn = *SSN.get_or_init(|| resolve_ssn("NtCreateUserProcess"));`
- **Code ref**: `crates/core/src/sys_resolve.rs::resolve_ssn` (the T-002 cascade) wrapped by `crates/core/src/sysindirect_map.rs::SyscallMap::get`
```

---

Both analyses follow the format spec exactly: full frontmatter (agent-parseable), TL;DR, numbered How-It-Works, full Operational Profile with trade-off table, Rust deep-dive citing exact identifiers, 10+ numbered Edge Cases per card, concrete Variant Ideas (not "consider exploring"), OPSEC Notes (operator perspective, not defender), and Reusable Patterns back-referencing the source. Cross-references use the T-XXX scheme from the vault index.