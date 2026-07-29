---
id: T-005
name: Ekko ROP Sleep Obfuscation
category: sleep-obfuscation
tier: S
crate: dark_crystal
mitre: T1497.003
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: medium
requires: [T-004, T-001, T-016]
enables: [T-018, T-023, T-017]
min_windows: Windows 7+
needs_admin: no
tags: [sleep, rop-chain, rc4, memory-encryption, timer-queue, stack-spoofing, anti-sandbox, context-capture]
---

# Ekko ROP Sleep Obfuscation — Operator Playbook

## TL;DR
Ekko is the canonical "encrypt-your-own-PE-during-sleep" technique: it builds a 6-frame ROP chain via `CreateTimerQueueTimer` that flips the implant's image to RW, RC4-encrypts it via `SystemFunction032`, blocks on a sleep handle, RC4-decrypts, restores RX, and signals the main thread via `SetEvent`. While the image is encrypted, memory scanners walking RX regions see ciphertext, not code. Worth the complexity in any engagement against EDR with periodic memory scans (CrowdStrike, SentinelOne, ESET, Elastic). Three dispatcher variants (`ekko`, `burst`, `split`) plus stack spoofing and an optional anti-sandbox CPU burst make it adaptive.

## How It Works
The dispatcher in `ekko_variants.rs::ekko_sleep_dynamic` is the only entrypoint operators should call. It selects one of three profiles from `selection_config::sleep_profile()` (an `OnceLock`-backed string set at build time via `include_str!` YAML). The full ROP construction lives in `dark_crystal/crowd/src/sleep.rs` (~355 lines, not in the provided extract). The OS-level mechanism, as documented in the card and consistent with the canonical Ekko by C5pider, is:

1. **Heap-allocate RC4 material outside the PE image.** The RC4 key (`USTRING`/`UNICODE_STRING` equivalent) and the data descriptor pointing at the PE image base+size are placed on the heap via `Box` so they survive the encrypted window. If these were inside the image, step 2 would corrupt them and the decrypt would never find its key.
2. **Create the signaling event.** `CreateEventW(NULL, FALSE, FALSE, NULL)` → `hEvent`. Auto-reset. This is what the main thread will block on.
3. **Capture main-thread context.** `RtlCaptureContext(&ctx)` on the calling thread. The captured `RSP` value is the base for the ROP chain — the timer frames are written into the captured stack region, so when the timer thread restores that context, control flows through the chain. The card is explicit: `RtlCaptureContext` is called on the **main thread**, not the timer callback.
4. **Construct six ROP frames on the captured stack.** Each frame is laid out so that `[RSP]` is a function pointer and the frame ends with a valid `ret` gadget that transfers control to the next frame's `[RSP+8]`. Frame layout (per card):
   - Frame 0: `VirtualProtect(PE_base, PE_size, PAGE_READWRITE, &oldProtect)` — make image writable so RC4 can XOR into it
   - Frame 1: `SystemFunction032(&data_ustring, &key_ustring)` — advapi32 RC4 (the `SystemFunction032` ad-hoc RC4 API) encrypts the image in place
   - Frame 2: `WaitForSingleObject(hEvent, sleep_ms)` — this is the actual sleep. Because the timer callback is *executing* this frame, the timer thread blocks here for the configured duration. The main thread is concurrently waiting on the same event (or a sibling one).
   - Frame 3: `SystemFunction032(&data_ustring, &key_ustring)` — RC4 is symmetric, second call decrypts the image back to plaintext
   - Frame 4: `VirtualProtect(PE_base, PE_size, PAGE_EXECUTE_READ, &oldProtect)` — restore RX
   - Frame 5: `SetEvent(hEvent)` — wakes the main thread
5. **Queue six timers with `CreateTimerQueueTimer`.** Each timer's `WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE` flag runs the callback in the timer queue's worker thread, one-shot. DueTime is staggered so the frames fire in order — frame 0 at T+0, frame 1 at T+100ms, frame 2 at T+200ms, etc. Each timer's callback is effectively the function pointer at the frame's `[RSP]`, with the prepared args following. The staggering matters operationally — if frame 1 fires before frame 0 completes VirtualProtect, RC4 writes to RX memory and faults.
6. **Main thread waits.** The main thread blocks on `WaitForSingleObject(hEvent, INFINITE)`. While it's blocked, the timer thread runs frames 0→5. When frame 5 calls `SetEvent`, the main thread resumes with a now-decrypted, RX-protected image.
7. **Jitter.** Before any of the above, `ekko_sleep_dynamic` computes `jitter = rng.gen_range(0..(ms / 8).max(1))` and `total = ms + jitter`. This is +12.5% maximum, asymmetric (always adds). The card's "±12.5%" is slightly misleading — the code only ever adds, never subtracts.
8. **Stack spoofing guard.** `let _guard = unsafe { crate::evasion::stack_spoof::spoof_return_address() };` runs before the sleep profile is dispatched. This is an RAII guard — when `_guard` drops (after sleep returns), the original return address is restored. Note: this spoofs the **main thread's** return address. It does NOT spoof the timer queue worker thread's stack, which is a known gap (see Edge Cases).
9. **Anti-sandbox compute burst.** With 40% probability (`rng.gen_bool(0.4)`), after sleep completes the code runs 500–1500 spin iterations of `acc = acc.rotate_left(3) ^ (i as u32).wrapping_mul(0x45d9f3b)`, seeded with `0x9e3779b9` (the golden ratio constant). This is a no-output busy loop designed to look like legitimate computation to sandbox classifiers.

### Variant dispatch
- `ekko` → `unsafe { ekko_rop_sleep(total as u32) }` — the full 6-frame ROP chain (steps 1–6 above)
- `burst` → `apply_cloak_before_sleep()` then `burst_sleep(total)` then `apply_uncloak_after_sleep()`. Burst splits the duration into 4–9 random sub-sleeps. Cloak is a separate RC4 encrypt/decrypt wrapper around the sub-sleeps — likely a simpler implementation than the full ROP chain, possibly using direct `SystemFunction032` calls from the main thread rather than timer-queue-driven ROP.
- `split` (the `_` default arm) → same cloak pattern but `split_sleep(total)` divides the duration into two random sub-sleeps.

The cloak/uncloak helpers (`apply_cloak_before_sleep`, `apply_uncloak_after_sleep`) are referenced in the extract but defined elsewhere. From naming convention, they wrap the same `SystemFunction032` RC4 mechanism but executed inline on the main thread — simpler, less stealthy (no timer-queue indirection, main thread does the VirtualProtect flips itself).

## Operational Profile

### When to Use
- **Any long-implant engagement against EDR with memory scanning.** CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Elastic Endpoint all periodically scan RX regions of processes. Ekko defeats this by making the image ciphertext during the dormant phase.
- **Beacon-style tasking loops where sleep duration > 30s.** The ROP setup overhead (~10–50ms) is amortized over the sleep.
- **When you control the host process and can guarantee single-threaded access to the PE image during the encrypted window.** Best paired with T-012 Early Cascade injection into a sacrificial process you fully own.
- **Post-exploitation dwell phases** where the operator is offline for hours/days and the implant must avoid periodic scanner sweeps.
- **With `burst` variant** when the operator wants shorter sub-sleeps to react to C2 tasking latency while still cloaked between bursts.

### When NOT to Use
- **Short sleeps (<5s).** ROP setup overhead dominates; the timer-staggered frames (6 × ~100ms minimum) burn longer than the sleep itself. Use direct `SleepEx` for short pauses.
- **Multi-threaded implants where other threads touch the PE image.** During the encrypted window, any thread executing code from the image faults immediately. The dispatcher must be the only live thread touching implant code.
- **Targets with ETW-TI + Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) heavily monitored.** Ekko doesn't use CreateRemoteThread, but `CreateTimerQueueTimer` and `SystemFunction032` with PE-sized buffers are themselves behavioral signatures on some EDRs (notably Elastic's behavioral rules).
- **Win11 22H2+ with ACG enabled on the host process.** If the host process has ACG (`PAGE_EXECUTE_DYNAMIC_CODE` restriction via `SetProcessMitigationPolicy`), VirtualProtect flipping RX→RW→RX may fail. Pair with T-016 policy clearing before use.
- **Sacrificial process with no `advapi32` loaded.** `SystemFunction032` lives in advapi32 — if your host process is minimal (e.g., svchost with restricted loaded modules), you need to ensure advapi32 is loaded first. T-004 PEB walker handles this if invoked.

### Kill Chain Position
Ekko sits in the **dwell phase** of the kill chain — after initial execution and before/at tasking.

Typical chain:
```
T-004 (PEB walk) → T-002 (SSN resolve) → T-012 (Early Cascade inject) →
  T-016 (stack spoof + ACG/BlockDLL policy) → T-005 (Ekko sleep loop) →
    T-023 (client tasking) → T-018 (Edo Tensei resurrection trigger)
```

Persistence pairing:
```
T-017 (Five-Layer Persistence) → T-005 (Ekko sleep between resurrections) →
  T-018 (Edo Tensei respawn on kill)
```

Ekko is the **steady-state loop body** for any long-running implant in this framework. Almost every other technique in the vault either runs *before* Ekko (setup: injection, evasion) or *during* a wake cycle between Ekko sleeps (tasking, exfil, persistence re-arm).

### Trade-offs
| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 9 | PE image encrypted during sleep defeats most memory scanners. Weakness: timer queue handle, event handle, advapi32 RC4 calls are all visible artifacts. |
| Reliability | 7 | Frame stagger timing is brittle; if any frame fires out of order the chain deadlocks or faults. RC4 is symmetric so decrypt always succeeds if key buffer survives. Multi-thread safety is the main reliability risk. |
| Complexity | 9 | 6-frame ROP construction with `CONTEXT` manipulation, gadget discovery, staggered timer scheduling. Hardest technique in the vault to modify safely. |
| Version range | Win 7+ (kernel32!CreateTimerQueueTimer, advapi32!SystemFunction032) | Stable API surface. SystemFunction032 RC4 behavior is identical Win7–Win11. |
| Privilege needed | none (medium-IL) | All APIs are user-mode, no token requirements. Works in AppContainer-restricted contexts if advapi32 is loadable. |

## Rust Implementation Deep Dive

### What the extract actually contains
The provided source extract is the **dispatcher only** (`ekko_sleep_dynamic` from `ekko_variants.rs`, ~30 lines). The 6-frame ROP construction (`ekko_rop_sleep`, `burst_sleep`, `split_sleep`, `apply_cloak_before_sleep`, `apply_uncloak_after_sleep`) lives in `sleep.rs` and is not shown. The deep dive below covers what is in the extract; for the ROP frame layout, see the card's documented ROP frame list and the OS-level description above.

### `unsafe` boundaries
There are two `unsafe` blocks in the extract:

1. `let _guard = unsafe { crate::evasion::stack_spoof::spoof_return_address() };`
   - **Why unsafe**: writes to the live call stack — specifically overwrites the return address slot of the current frame. A malformed write here crashes immediately on function return. The guard pattern restores the original return address on drop, so as long as `_guard` lives until end of scope, the stack is consistent again before any external return.
   - **Operational note**: if `ekko_rop_sleep` panics mid-flight, the guard's `Drop` runs during unwind and restores the stack — but by then the ROP chain may have already corrupted the timer thread's view. Operators should not panic inside the sleep profile dispatch path.

2. `unsafe { ekko_rop_sleep(total as u32) }`
   - **Why unsafe**: `ekko_rop_sleep` manipulates raw pointers, captures `CONTEXT`, writes the ROP chain to the live stack, and creates kernel objects (timer queue, event). All FFI into `kernel32`/`advapi32`. Rust cannot prove memory safety across any of these.
   - **Cast `total as u32`**: truncates from `u64` to `u32`. For typical sleep values (<49 days) this is fine; if an operator configures a sleep > 2^32 ms (~49 days), the dispatcher silently truncates and the implant sleeps for `(total % 2^32)` ms. Audit `selection_config` for absurd values.

### FFI patterns and handle ownership
- No direct `extern "C"` or `windows_targets::link!` is visible in the extract. The sleep dispatcher itself doesn't make Win32 calls directly — it delegates to `ekko_rop_sleep` (which does) and `stack_spoof::spoof_return_address` (which does).
- Handle ownership for the timer queue and event is managed *inside* `ekko_rop_sleep` — likely with RAII guards (`OwnedHandle`-style wrappers). Operators modifying this should verify handles are closed on all return paths; a leaked timer queue handle is a measurable artifact (see OPSEC).

### Initialization
- `crate::selection_config::sleep_profile()` — backed by `OnceLock<&'static str>` populated from `include_str!`-embedded YAML at startup. The match arms are `"ekko"`, `"burst"`, `_` (default to split). Operators who want to add a fourth variant (e.g., `"aes"`) need to:
  1. Add the variant to the YAML build-time config
  2. Add the match arm in `ekko_sleep_dynamic`
  3. Implement the function in `sleep.rs`
- `thread_rng()` from `rand` is used per call — no caching. Each sleep invocation reseeds from the OS RNG.

### Error paths
The extract has **no error handling**. Notable:
- `ekko_rop_sleep` returns `()`, not `Result`. If the ROP chain fails (VirtualProtect fails, timer queue can't be created, gadget discovery fails), the failure mode is unspecified by the extract. Operators should assume it either panics (Rust unwrap on a `windows::core::Result`) or silently returns after partial setup — the latter is much worse because the PE image could be left in RW or encrypted state with no decrypt scheduled.
- `spoof_return_address()` — return type not visible, presumably a guard struct or `()`. If it returns a guard, the `let _guard =` binding is correct. If it returns `()`, the binding is a no-op and the unsafe call is fire-and-forget. **Operators should verify** by reading `evasion/stack_spoof.rs` before relying on the guard pattern.
- The compute-burst `let _ = acc;` is explicit suppression of the unused-result warning. No side effects, no error path.

### Memory layout
- The `acc: u32` golden-ratio seed (`0x9e3779b9`) is a stack local — no allocation concern.
- The dispatcher itself allocates nothing on the heap; all heap allocation (`Box` for RC4 key and USTRING) happens inside `ekko_rop_sleep` and `apply_cloak_before_sleep`. Per the card, these `Box`es must outlive the encrypted window — verify that `ekko_rop_sleep` doesn't drop them early (the typical Ekko implementation holds them in scope across the `WaitForSingleObject` on the main thread).

### Register and asm details
- No `core::arch::asm!` in the extract. The ROP construction uses inline asm at the FFI boundary (in `sleep.rs`, not shown), with x64 calling convention (RCX/RDX/R8/R9 for first four args). The `CONTEXT` record's `Rip`, `Rsp`, and `Rcx`/`Rdx`/`R8`/`R9` fields are the ones operators modify when constructing each frame.

## Edge Cases & Failure Modes

1. **PE image size not page-aligned.**
   - **Scenario**: The host process PE image size is not a multiple of 4096 (some packers/protectors truncate the image).
   - **What goes wrong**: `VirtualProtect` rounds up to page boundary, but the next page may belong to another allocation. RC4 encrypts into that adjacent page and corrupts unrelated memory.
   - **Symptom**: Access violation in an unrelated thread shortly after sleep; image decryption succeeds but adjacent data is corrupted.
   - **Workaround**: In `ekko_rop_sleep`, clamp `PE_size` to `pe_header.OptionalHeader.SizeOfImage` rounded down to page size; only encrypt that.

2. **Multiple implant threads touch the PE image during the encrypted window.**
   - **Scenario**: Operator enables a keylogger thread (T-023) plus the main sleep loop. Keylogger thread calls an implant function during frame 1 (encrypted).
   - **What goes wrong**: Keylogger thread faults on `STATUS_ACCESS_VIOLATION` executing ciphertext.
   - **Symptom**: Crash in an unrelated-looking thread; main thread keeps sleeping; on wake, image decrypts fine but the process is already crashing.
   - **Workaround**: Park all worker threads (signal them to wait on a separate event) before dispatching Ekko sleep. Or use the `burst`/`split` variants which (per naming) wrap cloak inline — verify whether they pause worker threads.

3. **Timer queue thread starvation under low-resource conditions.**
   - **Scenario**: Target process is under heavy CPU load; system timer resolution is coarse (default 15.6ms).
   - **What goes wrong**: Frame stagger timing slips; frame 1 (RC4 encrypt) fires before frame 0 (VirtualProtect RW) completes. Writes to RX memory fault.
   - **Symptom**: `STATUS_ACCESS_VIOLATION` in the timer queue worker thread; main thread hangs forever on `WaitForSingleObject(INFINITE)`.
   - **Workaround**: Increase the stagger interval between frames (in `sleep.rs`); call `timeBeginPeriod(1)` before dispatching to force 1ms timer resolution. Tradeoff: `timeBeginPeriod(1)` is itself a telemetry signal.

4. **`advapi32` not loaded in the host process.**
   - **Scenario**: Injected into a minimal `svchost.exe` group or a sandboxed AppContainer process that hasn't loaded advapi32.
   - **What goes wrong**: `SystemFunction032` resolution fails (PEB walk can't find the export); ROP chain has a null gadget at frame 1 or 3.
   - **Symptom**: Either silent no-op (if `ekko_rop_sleep` checks the gadget and bails) or null pointer crash on first ROP frame execution.
   - **Workaround**: Call `LoadLibraryA("advapi32.dll")` explicitly before dispatching, or resolve `SystemFunction032` via T-004 PEB walker with explicit module-load fallback.

5. **ACG / `PAGE_EXECUTE_DYNAMIC_CODE` mitigation enabled.**
   - **Scenario**: Host process was started with `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` (common in Edge/Chrome renderer processes, some hardened services).
   - **What goes wrong**: `VirtualProtect(PAGE_READWRITE)` on RX region succeeds, but the subsequent `VirtualProtect(PAGE_EXECUTE_READ)` back to RX fails with `STATUS_SECTION_PROTECTION`. Image stuck as RW.
   - **Symptom**: `ekko_rop_sleep` returns but the implant can no longer execute its own functions; next function call crashes.
   - **Workaround**: Pair with T-016 policy module to clear the ACG mitigation before sleeping. Or use the `burst`/`split` variants which may use `PAGE_READWRITE` → `PAGE_EXECUTE_WRITECOPY` transition (verify in `sleep.rs`).

6. **Box heap allocation relocated during encrypted window.**
   - **Scenario**: GC or heap compaction (rare in Rust allocator, but possible with custom allocators) moves the `Box`'d RC4 key buffer between frame 1 (encrypt) and frame 3 (decrypt).
   - **What goes wrong**: Frame 3 reads stale pointer to old heap location; RC4 decrypt uses garbage key; image stays encrypted.
   - **Symptom**: Crash on wake when main thread tries to execute now-ciphertext code.
   - **Workaround**: Use `Box::into_raw` to pin the key buffer; or stack-allocate the key (it's only ~256 bytes) and store the key in the captured CONTEXT frame.

7. **Stack spoofing guard doesn't cover the timer queue worker thread.**
   - **Scenario**: EDR walks the timer queue worker thread's stack while it's executing frame 1 (RC4 encrypt). The worker thread's stack shows a clean call from `ntdll!TppWorkerThread` → advapi32!SystemFunction032 — fine. But if EDR walks the **main thread's** stack during the encrypted window, it sees a spoofed return address pointing to whatever `spoof_return_address` placed there.
   - **What goes wrong**: If the spoofed address points to a module that's not loaded (e.g., the operator spoofed to `ntdll!RtlInitializeGenericTable` but the host process doesn't have that RVA), the spoofed return is detectable as a "stack frame from a function that didn't call us."
   - **Symptom**: EDR flags the process for stack-mismatch behavioral signature.
   - **Workaround**: Use `spoof_return_address` with a target that legitimately calls into the sleep path — e.g., `kernel32!Sleep` itself or `ntdll!NtDelayExecution`. Better: extend `evasion::stack_spoof` to also spoof the timer queue worker thread (requires hooking the worker thread's entry; non-trivial).

8. **EDR hooks `SystemFunction032`.**
   - **Scenario**: Defender for Endpoint or Kaspersky hook advapi32 exports; `SystemFunction032` is on the hook list because it's a known Ekko primitive.
   - **What goes wrong**: Hook detects PE-sized buffer as the data argument, flags as suspicious, blocks or logs.
   - **Symptom**: Either `STATUS_ACCESS_DENIED` returned (chain breaks), or the call succeeds but a high-severity alert fires.
   - **Workaround**: Replace `SystemFunction032` with `RtlEncryptMemory` (`SystemFunction041`) or `SystemFunction040` (decrypt). These are different exports, less commonly hooked but same RC4 mechanism. Or implement inline RC4 in Rust (skip advapi32 entirely).

9. **Anti-sandbox compute burst triggers behavioral EDR.**
   - **Scenario**: 40% chance per sleep cycle, 500–1500 spin iterations of FPU-style rotation. On a target with CPU telemetry (Sysmon EID 7 process image load + CPU sampling, or EDR's behavioral CPU classifier), the burst looks like a coin-miner or obfuscation loop.
   - **What goes wrong**: Behavioral classifier flags the process; analyst gets paged.
   - **Symptom**: Process triage alert fires N minutes after first sleep cycle.
   - **Workaround**: Lower `gen_bool(0.4)` to `0.15` or remove the burst entirely if stealth > sandbox-evasion priority. Or replace the rotation with `RtlGetSystemTime` polling loop — looks more like a polling worker.

10. **Jitter only ever adds time, never subtracts.**
    - **Scenario**: Operator reads the card's "±12.5% jitter" and assumes the sleep could fire earlier than requested.
    - **What goes wrong**: Code is `ms + rng.gen_range(0..(ms/8).max(1))` — always adds 0–12.5%, never subtracts. Beaconing C2 timing analysis that assumes symmetric jitter will mismatch.
    - **Symptom**: Operator's C2 timing model predicts wrong traffic pattern; traffic analysis sees only late sleeps, never early.
    - **Workaround**: If symmetric jitter is required, modify to `ms + rng.gen_range(-(ms/8) ..= (ms/8))` (note `i64` cast needed for negative).

## Variant Ideas

- **Replace RC4 with AES-128-CTR using AES-NI inline asm.** RC4 is a known Ekko signature; AES-NI instructions executing in main-thread context during sleep setup are far less suspicious (many legitimate crypto libraries use them). Implement the cipher inline in `ekko_rop_sleep` so no advapi32 call is needed. Removes one frame's worth of API visibility.
- **Use `RtlEncryptMemory` (`SystemFunction041`) instead of `SystemFunction032`.** Same RC4 underlying, different export name, less commonly EDR-hooked. Drop-in swap in `sleep.rs` frame 1 and 3.
- **Skip the timer-queue indirection for `burst`/`split`.** Currently the inline cloak variants may still go through `SystemFunction032` calls on the main thread. For maximum stealth, do the cloak with a manual XOR loop using a rolling key derived from `__rdtsc()` — no API calls at all, only inline asm. Defeats hook-based detection entirely.
- **Pair with T-003 VEH Gate.** Wire the timer queue callback through a VEH-mediated syscall dispatcher so that `VirtualProtect` itself routes via HW-breakpoint indirection. Currently the VirtualProtect calls go through the standard kernel32 path and are visible to IAT hooks.
- **Multi-frame stack spoofing.** Extend `evasion::stack_spoof` to spoof each ROP frame's gadget address to look like a legitimate caller. Right now, only the main-thread return address is spoofed; the six ROP frames have raw function pointers visible on the timer thread's stack.
- **Async Ekko with `SetWaitableTimer`.** `CreateTimerQueueTimer` is a known Ekko primitive. `SetWaitableTimer` + `APC` injection is functionally equivalent for the staggered-callback pattern but uses a different kernel object. Less commonly flagged.
- **Heap-stomp alternative.** Instead of encrypting the PE image, allocate a duplicate RX region with the implant image, redirect execution to it during "wake," and zero the original during "sleep." Costs 2x memory but defeats memory diff scans entirely.
- **Adaptive variant selection.** Add a runtime profile selector that picks `ekko` vs `burst` vs `split` based on observed EDR behavior in the host process (e.g., if `VirtualProtect` calls take >2ms — likely hooked — fall back to `burst` which makes fewer VirtualProtect calls). Pair with T-020 anti-analysis timing checks.
- **Decrypt-on-touch.** Instead of a fixed sleep duration, encrypt the image and register a vectored exception handler that catches the first execution fault from the encrypted image, decrypts inline, and resumes. Lets the implant stay encrypted indefinitely and only wake on demand. Replaces polling with event-driven wake.

## OPSEC Notes

### Artifacts left behind
- **Timer queue handle**: created by `CreateTimerQueueTimer` (or `CreateTimerQueue` + `CreateTimerQueueTimer`). Visible via `NtQuerySystemInformation(SystemHandleInformation)` from a defender process. Pair with T-016 `block_handle` to prevent external handle enumeration.
- **Event handle**: created by `CreateEventW`. Same handle-enumeration visibility. Same mitigation.
- **advapi32 loaded** if it wasn't already: a `LoadLibraryA("advapi32.dll")` call shows up in module-load telemetry (Sysmon EID 7). Some host processes never load advapi32 normally; its presence is a behavior delta.
- **RC4 key material in heap**: survives the sleep; identifiable in a heap dump as a `USTRING` structure pointing at the PE image base. Forensic analysts find the key trivially if they dump the process during sleep.
- **VirtualProtect protection transitions on the PE image**: RW → (encrypted) → RW → RX. Each transition is a kernel event visible to ETW `Microsoft-Windows-Kernel-Memory` provider (if enabled). Two transitions per sleep cycle.

### Telemetry that may alert
- **Elastic Endpoint behavioral rules**: `SystemFunction032` with PE-sized data argument is a known Ekko signature and is flagged by the `windows_rc4_ekko` rule in the Elastic detections repo.
- **Microsoft Defender for Endpoint**: MDI sensor flags `CreateTimerQueueTimer` + `SystemFunction032` sequence as suspicious; high-confidence alert "Potential Ekko sleep obfuscation."
- **Sysinternals Sysmon**: EID 8 (CreateRemoteThread) does not fire (no remote thread). EID 10 (ProcessAccess) does not fire (no remote handle). EID 7 (ImageLoad) fires only if advapi32 wasn't loaded. No native Sysmon rule catches Ekko specifically.
- **ESET**: detection "Win64/Ekko.A" generic signature on the SystemFunction032 + CreateTimerQueueTimer call pattern from a non-Microsoft-signed process.

### Cleanup procedures
- After the final sleep cycle of the engagement (or before operator exit), call `DeleteTimerQueueEx` to tear down the timer queue and release the event handle.
- Zero the `Box`'d RC4 key buffer with `volatile_write_bytes(0)` before drop.
- Restore the original protection on the PE image if the last cycle left it RW (race with cleanup; safer to do an explicit `VirtualProtect(PAGE_EXECUTE_READ)` in the cleanup path).
- The ROP chain written to the captured stack is overwritten on the next context capture — no explicit cleanup needed, but if the operator wants to be thorough, zero the stack region after `SetEvent` fires.

### EDR-specific notes
- **CrowdStrike Falcon**: Falcon's memory scanner walks RX regions periodically. Ekko defeats the scanner. However, Falcon's sensor also hooks `CreateTimerQueueTimer`; the call pattern itself generates a low-severity telemetry event. Not blocking, but visible.
- **SentinelOne**: Similar to Falcon — scanner defeated, but the timer-queue pattern is in their detections. May trigger a "behavioral" medium-severity alert.
- **Microsoft Defender for Endpoint**: Aggressive detection of Ekko via ML on `SystemFunction032` calls. If MDfE is in play, use the AES-NI inline RC4 variant idea (above).
- **Elastic Endpoint**: Behavioral rule fires on the API sequence; alert is high-severity.

## Reusable Patterns

### Pattern: RAII Stack Spoof Guard
- **Use when**: any operation that runs for a measurable duration and might be inspected via stack walk (sleep, network I/O, file I/O).
- **How**: Bind the spoof to a `let _guard = unsafe { spoof_return_address() };` at the top of the function. The guard restores on drop, ensuring the original return address is back before the function returns to its caller. Survives panics via unwind.
- **Code ref**: `dark_crystal/crates/core/src/ekko_variants.rs::ekko_sleep_dynamic`

### Pattern: OnceLock Profile Dispatcher
- **Use when**: behavior should be selectable at build time (via embedded YAML) but switchable at runtime for testing.
- **How**: `selection_config::sleep_profile()` returns `&'static str` from an `OnceLock` populated from `include_str!`-embedded YAML. Match on the string and dispatch to the appropriate implementation. The `_` arm is the default fallback.
- **Code ref**: `dark_crystal/crates/core/src/ekko_variants.rs::ekko_sleep_dynamic`, `dark_crystal/crates/core/src/selection_config.rs`

### Pattern: Asymmetric Jitter via Integer Division
- **Use when**: adding noise to a duration to defeat beaconing timing analysis.
- **How**: `let jitter = rng.gen_range(0..(ms / 8).max(1)); let total = ms + jitter;` — adds 0 to 12.5% (1/8) of the requested duration. Use `.max(1)` to prevent zero-range panics on `ms < 8`. For symmetric jitter, switch to signed arithmetic.
- **Code ref**: `dark_crystal/crates/core/src/ekko_variants.rs::ekko_sleep_dynamic`

### Pattern: Probabilistic Anti-Sandbox Compute Burst
- **Use when**: sandboxes profile CPU usage to classify processes; legitimate processes have variable CPU load, sandboxes tend to be uniform-low.
- **How**: with probability p (0.4 here), run a deterministic-but-meaningless compute loop seeded with a recognizable constant (`0x9e3779b9` golden ratio). The loop has no output and no side effects; it just burns cycles. Vary spin count to add entropy.
- **Code ref**: `dark_crystal/crates/core/src/ekko_variants.rs::ekko_sleep_dynamic` (the `for i in 0..spins` block)
- **Warning**: this is also a detection signature in behavioral EDRs — see Edge Case 9.

### Pattern: Heap-Pinned Ciphertext Survival
- **Use when**: encrypting a memory region in-place but the key must outlive the encrypted state.
- **How**: `Box` the key + descriptor structures on the heap (outside the encrypted region) so they survive the encrypted window. Hold the `Box` in scope across the entire encrypt→sleep→decrypt sequence. Don't let it drop early.
- **Code ref**: referenced in `dark_crystal/crowd/src/sleep.rs` (not in extract); documented behavior in the card.