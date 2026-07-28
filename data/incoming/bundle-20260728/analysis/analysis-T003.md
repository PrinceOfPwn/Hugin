---
id: T-003
name: VEH Syscall Gate
category: syscalls
tier: S
crate: dark_crystal
mitre: T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: medium
requires: [T-004, T-002]
enables: [T-005, T-007, T-012, T-013, T-016, T-017]
min_windows: Windows 7 x64 (VEH + per-thread DR registers via NtSetContextThread)
needs_admin: no
tags: [syscalls, veh, hardware-breakpoints, exception-handling, single-step, debug-registers, dr7, indirect-syscalls, ki-user-exception-dispatcher]
source_file: dark_crystal/crowd/src/veh_gate.rs
---

# VEH Syscall Gate — Operator Playbook

## TL;DR
VEH Gate uses two Vectored Exception Handlers and per-thread hardware breakpoints (DR0/DR1) to single-step through a real `ntdll!Zw*` stub, find the actual `0F 05` SYSCALL instruction, and redirect execution there with the correct SSN. The kernel sees a syscall transition originating from legitimate `ntdll` code with a clean call stack — direct syscalls from your own allocation never appear. Use this when the target EDR walks `RIP`-origin stacks or performs `StackWalk64`/ETW `KernelStackCallback` correlation against the syscall site. It is the most opsec-expensive dispatch mode in the framework but the cleanest against stack-trace-based detection.

## How It Works

The card describes a five-step hardware-breakpoint flow. The OS-level mechanics are subtle; here is the precise sequence.

### Step 1 — VEH handler registration
`veh_gate::initialize()` calls `AddVectoredExceptionHandler(1, handler)` **twice** to register two handlers in the per-process VEH list (head of queue, `FirstHandler=1`). VEH handlers run *before* SEH/`__try` frames via `KiUserExceptionDispatcher` → `RtlDispatchException` → `VEH` list walk.

Two handlers are needed because the flow produces two distinct exception types that the dispatcher cannot distinguish by code alone — both `STATUS_SINGLE_STEP (0x80000004)`:
- **Handler A** — DR0 execution-breakpoint hit (hardware BP at the ntdll stub entry).
- **Handler B** — DR1 execution-breakpoint hit at stub+`ret_offset` (post-SYSCALL RET).

Distinguishing which DR fired is done by reading `DR6` bits (B0–B3) in the `CONTEXT` passed to the handler. The two handlers are technically interchangeable; the card's "two handler" model is one way to keep state machines isolated.

### Step 2 — Trigger
`veh_gate::set_hw_bp(addr, extended, ssn)` triggers an initial `STATUS_ACCESS_VIOLATION (0xC0000005)` via inline asm — typically an intentional dereference of an invalid pointer (e.g., `mov rax, [0]`). The trap enters the kernel via `#PF`, the kernel fault handler detects `KiUserExceptionDispatcher` eligibility, and dispatches back to user mode. The VEH list is walked; the relevant handler runs *synchronously on the faulting thread* in the faulting thread's context.

### Step 3 — Stub scan, set DR0/DR1
Inside the VEH handler (now executing in the caller's context), the handler:
1. Reads `addr` (the `ntdll!Zw*` stub address resolved by `get_ssn_by_name` — itself backed by T-004 PEB walk + DJB2 hash lookup).
2. Scans a small forward window of bytes looking for the `0F 05` opcode pair (SYSCALL; SYSCALL) — this is the actual syscall site in the stub.
3. Computes `ret_offset` = offset of the `C3` (RET) that follows the SYSCALL.
4. Mutates the incoming `CONTEXT`'s debug registers:
   - `DR0 = stub_entry_addr` (execution breakpoint)
   - `DR1 = stub_entry_addr + ret_offset` (post-SYSCALL RET execution breakpoint)
   - `DR7` set so that both DR0 and DR1 are **local enable** (L0=1, L1=1), length=1 byte, condition=00 (execution break).
   - `DR6` cleared to avoid stale B-bit state.
5. Sets `RIP` in the CONTEXT to the stub entry so resumption enters the stub.
6. Returns `EXCEPTION_CONTINUE_EXECUTION`.

When `NtContinue` is called by `KiUserExceptionDispatcher`, the kernel writes the modified `CONTEXT` (including DR0/DR1/DR7) back to the thread via `NtSetContextThread` semantics. The thread resumes at the stub entry.

### Step 4 — DR0 fires → SINGLE_STEP
Execution at the stub entry immediately hits the DR0 execution breakpoint. The CPU raises a `#DB` (debug exception, vector 1), which the kernel reports as `STATUS_SINGLE_STEP`. The VEH handler fires again. This time:

1. Verifies `DR6.B0` is set (DR0 fired), clears B0.
2. Saves the **current CONTEXT** (registers as they were at stub entry) — this is the saved state that will be restored after the stub walk.
3. Sets `EFlags.TF` (bit 8) in the CONTEXT — the **trap flag**. This causes the CPU to raise a `#DB` after every subsequent instruction.
4. Returns `EXCEPTION_CONTINUE_EXECUTION`.

The thread now single-steps instruction-by-instruction through the prologue of the `Zw*` stub. Each instruction generates `STATUS_SINGLE_STEP` → VEH handler → re-arms TF → continue.

### Step 5 — Pattern match → redirect RIP
For each single-step, the handler reads `RIP` and disassembles (byte-pattern match, not a full disassembler) the upcoming instructions. The trigger is the canonical Windows `Zw*` stub prologue:

```
mov  r10, rcx        ; 4C 8B D1
mov  eax, <ssn>      ; B8 ?? ?? 00 00
test byte ptr [0x7FFE02C4], 1   ; (Win10+ only)
jne  ...             ; branch to KiUserSystemCall
syscall              ; 0F 05
ret                  ; C3
```

The card's pattern ("`sub rsp, >=0x58` + `call`") describes an older variant. On modern Win10/11 builds, the stub is shorter and uses the `test byte ptr [SharedUserData+0x2C4], 1` form, branching to `KiUserSystemCall` (`int 0x2E` legacy path on systems where the syscall instruction is patched out). The handler matches the actual byte signature present on the host.

When the SYSCALL instruction is located:
1. Restore the saved CONTEXT from step 4 (so register state matches what the caller passed).
2. **Set `R10 = RCX`** (Windows x64 syscall convention: first arg goes to R10, not RCX).
3. **Set `EAX = ssn`** (the SSN resolved in step 3).
4. **Set `RIP = syscall_instr_addr`** (the exact `0F 05` byte address).
5. **Clear `DR0`** in DR7 (disable, so the execution BP at stub entry doesn't refire).
6. **Clear `TF`** in EFLAGS (stop single-stepping — we want the syscall to execute atomically).
7. Leave `DR1` armed (it will fire post-RET).
8. Return `EXCEPTION_CONTINUE_EXECUTION`.

The thread now executes `SYSCALL` from inside `ntdll`'s `.text` section. The kernel's `KiSystemCall64` entry sees a return address pointing into `ntdll`, and the syscall-origin stack walk shows `ntdll!Zw* → <caller>`. This is the opsec win.

### Step 6 — DR1 fires after RET → capture NTSTATUS
After `SYSCALL` returns to user mode, the stub executes `RET`. DR1 fires (post-SYSCALL RET execution breakpoint). The VEH handler runs a third time:

1. Verifies `DR6.B1` set, clears it.
2. Reads `RAX` — this is the NTSTATUS returned by the kernel.
3. Stores RAX in process-global state (consumed via `take_last_rax()` — a single-shot atomic read, hence "take").
4. Clears `DR0, DR1, DR7` (full debug register cleanup) so subsequent threads/operations aren't affected.
5. Sets `RIP` past the RET so the stub doesn't re-execute.
6. Returns `EXCEPTION_CONTINUE_EXECUTION`.

Control returns to the original caller site (the macro), which calls `take_last_rax() as i32` and returns it as the `NTSTATUS`.

### Memory state at each stage
| Stage | Active allocations | Stack | RIP origin |
|---|---|---|---|
| Macro entry | None VEH-specific | caller stack | operator code |
| Trigger AV | none | caller stack | operator code |
| DR0 fires | DR0/DR7 set on thread | caller stack | ntdll!Zw* entry |
| Single-step loop | TF set, DR0/DR7 set | caller stack (returns from VEH) | ntdll!Zw* prologue |
| SYSCALL fires | TF cleared, DR0 cleared, DR1 armed | caller stack | ntdll!Zw* `0F 05` |
| DR1 post-RET | DR0/DR1/DR7 cleared | caller stack | ntdll!Zw* after RET |

### Timing / race notes
- All execution is **synchronous on the calling thread** — no cross-thread signaling.
- The only race window is between `set_hw_bp` arming DR registers and another thread on the same process issuing a syscall. DR registers are per-thread, so other threads' syscalls don't trip DR0/DR1. **Global state is the actual race** (`take_last_rax()` returns whatever was last written; if two threads call the macro concurrently, results cross-pollinate). Serialize VEH syscalls if you spawn worker threads.
- The `take_last_rax()` consume pattern implies single-threaded use by default. If you need concurrency, wrap with a per-thread slot or thread-local storage.

## Operational Profile

### When to Use
- **Target EDR performs stack-origin correlation on syscalls.** CrowdStrike Falcon, Elastic Endpoint, SentinelOne Singularity, and Microsoft Defender for Endpoint all sample `RtlVirtualUnwind` / `RtlLookupFunctionEntry` against the syscall return address. VEH Gate makes the return address live inside `ntdll`, defeating that check.
- **You need a "perfect" ntdll-only call stack for an operation that itself allocates/protects memory.** Pair with T-012 Early Cascade injection — the target process sees a syscall-origin stack composed entirely of `ntdll` frames.
- **You're post-exploitation in a sensitive process** (e.g., `lsass.exe`'s sibling, a签 protected PPL, etc.) where telemetry granularity is higher.
- **EDR has hooked `Nt*` stubs** (userland hooks in `ntdll!.text`): VEH Gate executes the stub *as-is*, but jumps over the hook prologue by setting RIP directly at SYSCALL. Note: if the stub is hooked, the `0F 05` scan still finds the legitimate SYSCALL byte (hooks patch `mov r10, rcx` / `mov eax, ssn` prefix, not the SYSCALL byte itself), so VEH Gate transparently bypasses userland hooks. This is a significant secondary benefit.
- **You're doing T-005 Ekko sleep obfuscation** in a long-haul implant and need every syscall in the ROP frame to look legitimate.

### When NOT to Use
- **High-throughput syscall paths** (e.g., screen capture polling, keylogger event loops). Each VEH syscall raises 3+ exceptions; ETW Debug channel saturates and SOC anomaly alerts fire on exception-rate spikes.
- **Single-threaded implant that doesn't need stack hygiene.** If your chain already uses T-001 RecycledGate or T-006 Phantom Stubs and the target EDR doesn't stack-walk syscalls, VEH is wasted complexity.
- **Targets with kernel-mode debuggers / EDR kernel callbacks.** `PtSetProcessInstrumentationCallbacks`, `ObRegisterCallbacks` for handle access, and `PsSetCreateProcessNotifyRoutineEx` don't catch VEH directly, but EDRs that install `KiUserExceptionDispatcher` hooks (some build of BitDefender, older Kaspersky) intercept the AV → handler transition and see the manipulation.
- **Anti-debug-protected target.** If the process you're running in does its own `IsDebuggerPresent` / DR-register self-checks (DRM'd processes, games, some EDR agents themselves), you'll trip their anti-tamper.
- **Win10 1709 and earlier** (pre-`KiUserSystemCall` refactor): the stub layout differs and the pattern match in step 5 needs adjustment. Validate the byte signature on your target build before deploying.
- **Concurrent multi-threaded syscalls** without per-thread serialization. The shared `take_last_rax()` slot will return wrong NTSTATUS values.

### Kill Chain Position
VEH Gate is a **syscall dispatch layer**. It sits below every technique that issues NT syscalls. Typical chains:

**Standard chain (medium-IL access, EDR present):**
T-004 (PEB walker resolves ntdll) → T-002 (Hells/Halos/Tartarus Gate extracts SSNs) → **T-003 VEH Gate (dispatch)** → T-012 (Early Cascade inject into svchost) → T-005 (Ekko ROP sleep) → T-017 (Persistence)

**Stealth-first chain (high-value target):**
T-004 → T-002 → **T-003 VEH dispatch** → T-007 (Pool Party) or T-008 (Threadless) into `explorer.exe`/`RuntimeBroker.exe` → T-005 (Ekko sleep) → T-016 (EDR evasion: stack spoof + ETW patch) → T-017 (Persistence) → T-019 (Edo Dead Drop C2)

**Pure-injection chain where stack origin matters:**
T-004 → T-002 → **T-003 VEH** → T-012 (Early Cascade) → T-006 (Phantom Stubs for follow-up syscalls) → T-013 (Module overloading for payload body)

VEH Gate and T-001 RecycledGate are **interchangeable dispatch layers**. Pick T-003 when the operation needs `ntdll`-origin syscall frames; pick T-001 when you need raw speed (RecycledGate is direct-jmp indirect, ~2-3x faster).

### Trade-offs
| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 9/10 | Syscall-origin frame lives in `ntdll!Zw*`; DR-register manipulation is invisible to non-kernel EDR; userland hook bypass is incidental. Loses 1 pt: ETW Debug channel sees elevated `STATUS_SINGLE_STEP` rate. |
| Reliability | 7/10 | Per-thread DR-register ownership is solid; failure modes are (1) concurrent VEH syscalls on shared state, (2) another debugger present, (3) stub byte-pattern mismatch on patched ntdll builds. |
| Complexity | 8/10 | Inline asm + CONTEXT manipulation + multi-step exception flow + global state. Highest implementation burden of the three dispatch modes. |
| Version range | Win7 x64+ | VEH since XP SP2; x64 hardware debug registers stable since CPU debut. Pattern match needs version-aware stub parsing (Win10 1709 vs. 1809+ differs). |
| Privilege needed | none | Works at medium-IL. Per-thread `NtSetContextThread` is permitted on your own thread with no `THREAD_SET_CONTEXT` privilege escalation needed. |
| Throughput | 3/10 | ~3-5 exceptions per syscall = ~5-10x slower than direct. Avoid in hot paths. |

## Rust Implementation Deep Dive

### Macro surface — `veh_syscall!`

```rust
veh_syscall!("NtAllocateVirtualMemory", OrgNtAllocateVirtualMemory,
    process_handle, &mut base, 0usize, &mut size, alloc_type, protect);
```

- `$name: expr` — compile-time string literal of the NT API. Hashed via `$crate::resolve::djb2_hash($name.as_bytes())` (DJB2 from T-004). The string literal is **not** obfuscated by default; if your build doesn't apply the `obf` crate's `obfstr!` on the call site, the literal goes into the binary's `.rdata` and a string sweep finds `"NtAllocateVirtualMemory"`. **Wrap calls in `obfstr!()` or pre-compute the hash at build time.**
- `$fn_type: ty` — a type alias (`pub type OrgNtAllocateVirtualMemory = unsafe extern "system" fn(...) -> NTSTATUS`). The macro itself **does not invoke** this type — it's there for IDE type-checking and to document the expected signature. The actual call is `set_hw_bp(addr, extended, ssn)`, which doesn't go through this signature; arguments are pushed via inline asm inside `set_hw_bp`.
- `$($arg: expr),*` — variadic args. `$crate::count_args!($($arg),*)` is a `tt`-muncher macro that counts comma-separated expressions to determine if `extended` is true (more than 4 args means RCX/RDX/R8/R9 aren't enough → stack shadow space + spilled args needed). The `extended` flag toggles stack-frame setup in `set_hw_bp`.

### Initialization — `veh_gate::initialize()`

- Uses `OnceLock<()>` (or similar) to register the VEH handlers exactly once. Idempotent across multiple calls; safe to call from each module's `init()`.
- `AddVectoredExceptionHandler(1, ...)` is called via the `windows_targets::link!` binding in `wrappers.rs`. Handle to the registration is stored in a `OnceCell<PVOID>` so `destroy()` can call `RemoveVectoredExceptionHandler` cleanly.
- Cleanup `veh_gate::destroy()` is **mandatory** before process exit if you want to avoid an `EXCEPTION_INVALID_HANDLER` fault during `RtlpRemoveVectoredHandler` walking — leaving a stale handler pointing at unmapped module memory will crash on the next exception.

### State machine — `take_last_rax()`

```rust
pub fn take_last_rax() -> u64
```

- Atomic single-shot read: backed by `AtomicU64` with `Ordering::Acquire` load + `Ordering::Release` store of 0. The "take" naming means **subsequent reads return 0** until the next syscall completes.
- This is the **concurrency hazard**: if two threads call `veh_syscall!` back-to-back, thread A's NTSTATUS can be consumed by thread B's macro. If you spawn worker threads via T-007 Pool Party, serialize the dispatch or replace with thread-local storage (`thread_local! { static LAST_RAX: Cell<u64> = Cell::new(0) }`).

### `set_hw_bp(addr, extended, ssn)`

Card says it "triggers ACCESS_VIOLATION via inline asm". The likely implementation:

```rust
unsafe fn set_hw_bp(addr: usize, extended: bool, ssn: u32) {
    // Stage the parameters somewhere reachable by the handler
    STATE.set_target(addr, extended, ssn);
    
    // Trigger an AV that the VEH handler will intercept
    core::arch::asm!(
        "xor rax, rax",
        "mov rax, [rax]",      // #PF → STATUS_ACCESS_VIOLATION
        "nop",                 // landing pad after handler resumes
        out("rax") _,
        options(nostack, preserves_flags),
    );
}
```

- The `xor rax, rax; mov rax, [rax]` is the classic 2-byte NULL deref. The `nop` afterwards is the implicit landing pad; `EXCEPTION_CONTINUE_EXECUTION` with restored RIP re-enters at this `nop` because the handler set RIP back to a continuation address.
- `extended=true` causes the handler to set up additional stack shadow space (32 bytes for the home area) and copy spilled args 5+ onto the stack before arming the breakpoint at the stub. Without this, syscalls with >4 args corrupt the stack.
- `options(preserves_flags)` should **not** be set on this asm block — the handler mutates `RFLAGS` via TF and you need the compiler to spill them. The actual code likely uses `options(nostack)` only.

### CONTEXT manipulation — unsafe boundary

The handler receives `*mut EXCEPTION_POINTERS`. Accessing `(*ep).ContextRecord` is `unsafe` because:
- Raw pointer dereference (no borrow guarantee).
- The CONTEXT must be modified in place; `NtContinue` reads back the same pointer the kernel passed.
- Fields touched: `Rip`, `EFlags` (bit 8 = TF), `Dr0`, `Dr1`, `Dr6`, `Dr7`, `R10`, `Rax`, `Rcx` (indirectly, via R10 swap).
- Alignment: `CONTEXT` on x64 is 16-byte aligned; the pointer arrives aligned from the kernel. Don't construct a `CONTEXT` on a misaligned stack slot — use `#[repr(C, align(16))]`.

### DR7 bit layout (for operators modifying the code)

For each of DR0–DR3 (two pairs per 8 bits in DR7):
- Bits 0/2/4/6: **Local enable** (L0, L1, L2, L3) — per-task, cleared on task switch.
- Bits 1/3/5/7: **Global enable** (G0–G3) — system-wide, privileged only.
- Bits 16-17/20-21/24-25/28-29: condition (00=execution, 01=data write, 10=I/O, 11=read/write).
- Bits 18-19/22-23/26-27/30-31: length (00=1B, 01=2B, 10=8B, 11=4B).

To enable DR0 + DR1 as execution breakpoints (1 byte each, local): `DR7 = (1<<0) | (1<<2) | (1<<16) | (1<<20)` = `0x100010`. Clear DR0 while keeping DR1: `DR7 = (1<<2) | (1<<20)` = `0x100004`.

### `get_ssn_by_name(name, hash)` — T-002 dependency

Delegates to the FreshyCalls/Hells/Halo/Tartarus cascade in `sys_resolve.rs`. Returns `(ssn: u32, addr: usize)` where `addr` is the `ntdll!Zw*` export's first byte. If `get_ssn_by_name` returns `None`, the macro `.expect()`s and **panics**. In an engagement, either replace with `?`-style error propagation or pre-validate SSN resolution at `veh_gate::initialize()` and fail fast with a known list of resolved stubs.

### Error paths

| Failure | Behavior |
|---|---|
| `get_ssn_by_name` returns None | `.expect()` panics with `VEH: failed to resolve <name>`. Catastrophic. |
| `AddVectoredExceptionHandler` fails | Likely `initialize()` returns `Err` — verify in source. |
| Handler raises during exception dispatch | Recursive exception → `KiUserExceptionDispatcher` raises `STATUS_INVALID_DISPOSITION` → process terminates. |
| `take_last_rax()` called when no syscall completed | Returns 0 → cast to `i32` → `STATUS_SUCCESS (0)` — silently wrong. The caller can't distinguish "syscall succeeded" from "VEH didn't fire". |
| DR register write blocked by VBS/HVCI | Not blocked — DR registers are user-accessible per-thread even under VBS. Only `CR4.DE` clear (debugging extensions disabled) blocks them; that's a CPU feature flag, not a Windows mitigation. |

## Edge Cases & Failure Modes

1. **Another debugger or EDR with hardware breakpoints present**
   - Scenario: A second agent (e.g., EDR's own integrity checker) is using DR0/DR1.
   - What goes wrong: VEH Gate overwrites DR0/DR1 with its own values. The other agent either misses its breakpoint (silent failure on its side) or crashes the process with an unhandled `STATUS_SINGLE_STEP` when its own handler isn't called for our BP.
   - Symptom: Random process crashes or "inexplicable" behavior shifts in the host (e.g., EDR telemetry stops emitting for a few seconds).
   - Workaround: Before arming, read the current DR0–DR7 via `NtGetContextThread`. If any are set, fall back to T-001 RecycledGate or T-006 Phantom Stubs for this syscall.

2. **Target process self-checks DR registers (DRM / anti-tamper)**
   - Scenario: Office with macros, games, signed-isolated services.
   - What goes wrong: Process calls `__readdr(0)` or `NtGetContextThread(GetCurrentThread())` periodically and detects our DR0/DR1 values, raising an integrity fault.
   - Symptom: Process terminates itself with a non-standard exit code, or trips an anti-tamper alert to the EDR.
   - Workaround: Use T-001 RecycledGate (no DR manipulation) or T-006 Phantom Stubs. Don't deploy VEH Gate inside DRM'd processes.

3. **Concurrent `veh_syscall!` from multiple threads**
   - Scenario: You've migrated into a thread-pool host (T-007 Pool Party) and the framework dispatches commands from worker threads.
   - What goes wrong: Shared `take_last_rax()` returns the last-written NTSTATUS across all threads. Thread A's `NtAllocateVirtualMemory` returns STATUS_SUCCESS; thread B's `NtProtectVirtualMemory` returns STATUS_CONFLICTING_ADDRESSES; thread B reads A's value, treats failure as success, proceeds against an unallocated buffer.
   - Symptom: Silent data corruption. Hard to detect in the field.
   - Workaround: Mutex around `set_hw_bp` + `take_last_rax`, or replace global with `thread_local!`.

4. **Stale DR values on thread reuse**
   - Scenario: Pool Party worker thread returns to the pool with DR0/DR1 still set (cleanup missed).
   - What goes wrong: Next syscall issued by an unrelated caller (the host's own logic) trips DR0, your handler fires for someone else's syscall, and `take_last_rax` gets overwritten with garbage.
   - Symptom: Spurious exceptions in unrelated code, NTSTATUS values that don't match the called API.
   - Workaround: Always clear DR0–DR7 in the final handler stage, even on error paths. Audit `set_hw_bp` cleanup with `__writedr(0, 0); __writedr(1, 0); __writedr(6, 0); __writedr(7, 0)` on every exit.

5. **Patched ntdll stub byte signature**
   - Scenario: Win10 1709 and earlier, or some hardened builds where `ntdll!Zw*` stub uses `int 0x2E` instead of `syscall`.
   - What goes wrong: `0F 05` byte scan fails. Handler loops forever single-stepping or hits the end-of-stub boundary and bails.
   - Symptom: VEH Gate hangs the calling thread.
   - Workaround: Update the pattern scanner to also accept `CD 2E` (int 0x2E) and the Win10+ `test byte ptr [0x7FFE02C4], 1` form. Cache the discovered SYSCALL offset per stub and skip the scan on subsequent calls.

6. **EDR hook on `AddVectoredExceptionHandler`**
   - Scenario: Defender for Endpoint with ETW-TI and userland hook on `ntdll!AddVectoredExceptionHandler` (less common now, but some vendors still hook it).
   - What goes wrong: Handler registration is logged; EDR tags the process as "Vectored Exception Handler registration by non-debugger" and raises an alert.
   - Symptom: Process gets killed or quarantined shortly after `initialize()`.
   - Workaround: Register the handler before EDR hooks land (very early in payload unpack stub), or use `RtlAddVectoredExceptionHandler` directly via T-004 PEB resolution (avoids the hooked export). Alternative: use T-016 PEB unlink + NTDLL unhook first.

7. **EDR hooks `KiUserExceptionDispatcher`**
   - Scenario: Some vendors patch the dispatcher's prologue to log every exception.
   - What goes wrong: Every VEH syscall generates 3+ log entries (AV trigger, DR0 hit, possibly DR1 hit). EDR sees anomalous exception rate.
   - Symptom: Process gets flagged on exception-rate anomaly detection.
   - Workaround: Use T-001 RecycledGate (zero exceptions). VEH Gate is fundamentally incompatible with `KiUserExceptionDispatcher` hooks.

8. **HVCI / VBS with stack strictness**
   - Scenario: Win11 22H2+ with VBS + HVCI + Intel CET enabled.
   - What goes wrong: Not a DR-register issue (those work), but the single-step through `ntdll!Zw*` crosses shadow-stack validations. Generally CET-enforcement allows exceptions to manipulate RIP via `NtContinue` (it's a privileged restore). Should still work; if it doesn't, the symptom is `STATUS_STACK_CHECK_VIOLATION (0xC0000333)`.
   - Workaround: None — fall back to T-001 RecycledGate or T-006 Phantom Stubs on HVCI+CET hosts.

9. **`set_hw_bp` continues into an unintended landing pad**
   - Scenario: Inline asm emits `nop` as a landing pad after the AV-triggering deref. The VEH handler returns RIP to this `nop`, but if the asm block was inlined into a hot caller, the `nop` may overlap with adjacent instructions.
   - What goes wrong: Return-from-handler continues at the wrong instruction.
   - Symptom: Random crashes after the first VEH syscall in a session.
   - Workaround: Make `set_hw_bp` `#[inline(never)]` and ensure the asm block has a clean `nop` sequence at the end. Mark `options(nostack, noreturn)` if appropriate, but be careful — the macro expects to return.

10. **`veh_gate::destroy()` called while a syscall is mid-flight**
    - Scenario: Operator issues a teardown during an active operation.
    - What goes wrong: `RemoveVectoredExceptionHandler` removes the handler while DR0 is still armed. Next instruction hits DR0, no handler is present, `KiUserExceptionDispatcher` raises `STATUS_UNHANDLED_EXCEPTION`, process crashes.
    - Symptom: Clean shutdown followed by sudden death.
    - Workaround: Drain pending syscalls before `destroy()`. Add a "no syscall in progress" flag (atomic) and busy-wait if set.

## Variant Ideas

- **Per-thread state slot**: Replace the global `take_last_rax` with `thread_local! { static LAST_RAX: Cell<u64> = Cell::new(0); }`. Unlocks safe concurrent VEH dispatch from Pool Party workers (T-007) without serialization overhead. ~30 LOC change.

- **DR0-only mode**: Use a single execution breakpoint at the SYSCALL instruction (no DR1, no single-step loop). Lose the stub-scan → SSN-injection step; just resolve SSN via T-002 and arm DR0 at the `0F 05` byte. Trade reliability for fewer exceptions: 2 exceptions per syscall instead of 3+. Useful for high-throughput paths that still need `ntdll`-origin frames.

- **Phantom stub hybrid (T-003 + T-006)**: Allocate a Phantom Stub (T-006, MEM_IMAGE-backed) that mirrors the ntdll stub layout exactly. Arm DR0/DR1 on the Phantom Stub instead of the real `ntdll!Zw*`. The kernel still sees a syscall-origin frame in a MEM_IMAGE section (looks like a legitimate module), but you can rotate stubs without touching `ntdll`. Reduces coupling to `ntdll` byte patterns and resists EDR that monitors `ntdll` reads specifically.

- **Win10+ KiUserSystemCall path**: On systems where `KUSER_SHARED_DATA.SystemCall` bit is set, the stub branches to `ntdll!KiUserSystemCall` which itself contains the `syscall` instruction. Scan should follow the Jcc and arm DR0 at the `KiUserSystemCall` SYSCALL byte. This is cleaner because the syscall-origin frame lives in a single function in ntdll that the kernel implicitly trusts. Update the pattern matcher to follow the Jcc first; falls back to direct stub SYSCALL on systems where the bit is clear.

- **Combine with stack spoof (T-016)**: VEH Gate produces `ntdll!Zw*` as the syscall-origin frame. Pair with the advanced multi-frame stack spoof (T-016) so the *caller* frame also points into a legitimate module (e.g., `kernel32!BaseThreadInitThunk`). The full stack walk looks like `kernel32!BaseThreadInitThunk → ntdll!Zw* → SYSCALL → kernel`. Undetectable by stack-based detection.

- **VEH on a hijacked thread (T-008 WaitingThread + T-003)**: Register VEH handlers on a hijacked waiting thread inside `svchost.exe`/`RuntimeBroker.exe`. Syscalls issue from that thread with a call stack originating in the host's own DLLs. Maximum stealth — looks like the host is making the syscall, not the implant.

- **Argument spoofing (T-016 arg spoof)**: After the VEH-redirected SYSCALL completes, the caller stack still has your operator-side arguments (e.g., `PROCESS_HANDLE`, `BaseAddress` pointer values). Pair with argument-spoof so the stack dump shows benign-looking values, defeating memory snapshotting.

- **Replace inline-asm AV trigger with `NtRaiseHardError`-mediated exception**: Instead of `xor rax, rax; mov rax, [rax]`, use a legitimate-looking `int 3` (BREAKPOINT) or `int 2D` (kernel- mediated debug service). Less suspicious in static analysis — looks like a debugger-aware binary rather than an intentional fault.

- **Cache discovered SYSCALL offsets**: First call to a given `Zw*` stub does the full scan. Subsequent calls skip the scan — just set DR0 to the cached SYSCALL address. Halves the exception count per call after warmup.

## OPSEC Notes

### Artifacts left behind
- **Debug registers**: cleared by the final handler stage, but a kernel-mode EDR with `NtSetContextThread` callback (via `ObRegisterCallbacks` on `DebugObject`-adjacent types, or `PsSetContextThread`-style notification) sees every DR7 write. Treat as **fully observable** by kernel EDR.
- **VEH list entry**: `AddVectoredExceptionHandler` registers a node in the process's `LdrpVectorHandlerList`. `RemoveVectoredExceptionHandler` removes it on `destroy()`. If you don't call destroy, the node persists in process memory and a memory scanner finds your handler's address pointing into your module — **always destroy before exit**.
- **ETW Debug channel events**: `Microsoft-Windows-Kernel-Process` / `Microsoft-Windows-IE/DCOM-Launcher`-adjacent telemetry may log `STATUS_SINGLE_STEP` exceptions at a rate of 3-5 per syscall. SOC alert on "exception rate anomaly per process" is a known heuristic in mature SOCs.
- **`ntdll` read pattern**: Your code reads `ntdll!Zw*` bytes during the scan. Some EDRs (Carbon Black, Elastic) monitor for unusual read patterns against `ntdll`'s `.text` section from non-loader modules.

### Telemetry it generates that a SOC might alert on
- High exception rate (`STATUS_SINGLE_STEP`) per process — catch-all for VEH-based evasion.
- `AddVectoredExceptionHandler` from a non-Microsoft signed module — alerts in Defender for Endpoint with `Exploit Guard` enabled.
- Hardware-breakpoint writes via `NtSetContextThread` from non-debugger processes — Elastic's `BehavesLike` rule family has a heuristic for this.
- `STATUS_ACCESS_VIOLATION` at NULL address from a non-faulting-context module — looks like a crash; some SOCs alert on "process crash followed by recovery" because that's a known evasion pattern.

### Known detections by EDR product
- **CrowdStrike Falcon**: Does not natively alert on VEH, but `SensorHealth` heuristic flags processes with sustained exception rates. Pair with sleep obfuscation (T-005) to lower the visible window.
- **Microsoft Defender for Endpoint**: ASR rule "Block executable files from running unless the integrity level is equal to or higher than the parent process" does not fire on VEH itself, but Exploit Protection's "Validate heap integrity" + "Control flow guard" can catch stack-spoof mismatches if you're not careful with the caller frame.
- **Elastic Endpoint**: Custom rule `exception_count_per_min > 50` would fire on a syscall-heavy phase. Throttle or batch syscalls.
- **SentinelOne**: Patented "Behavioral AI" trains on VEH-mediated evasion samples; treat as potentially detected. Use T-001 RecycledGate on S1-protected hosts.

### Cleanup procedures
- **Before process exit**: Call `veh_gate::destroy()`. Removes VEH list entries; no orphaned pointers remain.
- **Per-syscall**: Final handler stage already clears DR0/DR1/DR7 and DR6.B0/B1. Audit this in source — if DR7 isn't zeroed, future syscalls from the same thread will spuriously fault.
- **On detection**: If a kernel EDR flag appears during engagement, the thread context reveals the DR-register state at exception time — you cannot "rollback" the DR writes. Eject the thread (T-005 Ekko + thread migration) and resume operations from a clean thread.

## Reusable Patterns

### Pattern: OnceLock-initialized global syscall subsystem
- **Use when**: Any subsystem that must be initialized exactly once and shared across modules (VEH, indirect dispatch, PEB walker cache).
- **How**: Wrap `initialize()` in a `OnceLock<()>` + `OnceCell<PVOID>` for the VEH handle. Subsequent calls become no-ops; `destroy()` consumes the cell.
- **Code ref**: `dark_crystal/crowd/src/veh_gate.rs` — `initialize()` / `destroy()`; mirror pattern in `dark_crystal/crates/core/src/sys_resolve.rs`.

### Pattern: Macro-dispatched syscall surface
- **Use when**: You want call-site ergonomics (`veh_syscall!("Nt*", Type, args...)`) while hiding the underlying dispatch complexity.
- **How**: `$name:expr` → DJB2 hash → `get_ssn_by_name`. `$fn_type:ty` documents the signature without being invoked (compiler checks it at the call site). `count_args!` decides whether extended stack handling is needed. Use `concat!` for compile-time error messages (e.g., `"VEH: failed to resolve ", $name`).
- **Code ref**: `veh_syscall!` macro, `dark_crystal/crowd/src/veh_gate.rs`. Same pattern usable for `recycled_syscall!` (T-001) and `phantom_syscall!` (T-006).

### Pattern: Take-style atomic single-shot read
- **Use when**: A consumer must retrieve a result exactly once (handler → caller for syscall NTSTATUS, completion port style signaling).
- **How**: `AtomicU64` with `store(v, Release)` on the producer side and `swap(0, AcqRel)` on the consumer side. Naming convention `take_*` makes the single-shot semantics obvious at the call site.
- **Code ref**: `veh_gate::take_last_rax()`.

### Pattern: `tt`-muncher arg counter
- **Use when**: A macro needs to count variadic arguments to decide stack-frame layout (e.g., 4-arg vs 5+-arg Windows x64 calling convention).
- **How**: Recursive macro that matches one expression + comma + tail, recursing with `1 + count!(tail)`. Base case `() => { 0 }`.
- **Code ref**: `dark_crystal/crowd/src/` (referenced as `$crate::count_args!`).

### Pattern: CONTEXT in-place mutation for `NtContinue`
- **Use when**: Any VEH/SEH handler that needs to redirect execution or modify register state post-exception.
- **How**: Receive `*mut EXCEPTION_POINTERS`, deref to `ContextRecord: *mut CONTEXT`, write fields directly. Don't clone the CONTEXT — `NtContinue` reads the kernel's pointer back. Use `#[repr(C, align(16))]` if constructing your own.
- **Code ref**: VEH handler body in `dark_crystal/crowd/src/veh_gate.rs`; mirror in T-005 Ekko ROP (`ekko_variants.rs`) which also manipulates CONTEXTs.

### Pattern: Debug-register bit-layout constants
- **Use when**: Manipulating DR7 directly (any hardware-breakpoint technique, anti-debug checks, VEH-mediated single-step).
- **How**: Define `const DR7_L0: usize = 1 << 0; const DR7_L1: usize = 1 << 2; const DR7_COND_EXEC: usize = 0;` etc. Compose with bitwise OR. Clear by AND-with-NOT.
- **Code ref**: `dark_crystal/crowd/src/veh_gate.rs` (implicit in DR7 writes). Extract to a shared `dr.rs` module to reuse in T-016 AMSI HW breakpoint bypass (`amsi_hbp.rs`).