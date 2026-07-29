---
id: T-001
name: RecycledGate Indirect Syscalls
category: syscalls
tier: S
mitre: T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-004, T-002]
enables: [T-005, T-006, T-007, T-008, T-009, T-010, T-011, T-012, T-013, T-014, T-015, T-016, T-017]
min_windows: Windows 7 x64
needs_admin: no
tags: [syscalls, inline-asm, etw-evasion, djb2-hash, indirect-syscall, ntdll-gadget, cet-sensitive]
---

# RecycledGate Indirect Syscalls — Operator Playbook

## TL;DR
Eleven hand-rolled inline-asm stubs (`recycled_1` through `recycled_11`) that dispatch 1-11 argument NT syscalls by `jmp`-ing into a `syscall; ret` (`0F 05 C3`) gadget cached from ntdll's `.text`. The syscall instruction executes with RIP inside ntdll, and the `ret` returns directly to the Rust caller, so ETW Threat Intelligence stack walks see only legitimate ntdll frames. This is the foundation that every other dark_crystal technique stands on — if you skip RecycledGate, you have no stealthy path into the kernel.

## How It Works

1. **Module resolution via PEB walk (T-004 dependency).** `gs:[0x60]` reads the TEB→PEB pointer, then walks `PEB->Ldr->InLoadOrderModuleList` to locate `ntdll.dll` base. No `GetModuleHandle`/`LoadLibrary` call is made; EDR's `GetProcAddress`-style hook never fires.

2. **Export table enumeration + DJB2 hash match.** Parse `IMAGE_DIRECTORY_ENTRY_EXPORT` from ntdll. For each `IMAGE_EXPORT_ENTRY`, compute DJB2 hash of the export name and compare against pre-baked hash constants embedded in the implant binary (no string literals, no ` WideCharToMultiByte`, no RIFF-like IAT entries). The hash constants cover 40+ NT functions.

3. **SSN extraction (T-002 cascade dependency).** At the resolved export VA, read the canonical stub bytes: `4C 8B D1 B8 SSN_LO SSN_HI 00 00 0F 05 C3`. The SSN is the `mov eax, imm32` immediate at offset `+4`. Read 4 bytes as a `u32`.

4. **Halo's/Tartarus fallback.** If the leading bytes are not `4C 8B D1` (hooked by EDR), walk backwards in `-0x20` strides (Halo's Gate) looking for an intact stub. The SSN delta from the expected slot is added back: `ssn = nearby_ssn + (expected_offset - actual_offset)`. Tartarus Gate then sorts all `Zw*` exports by RVA and infers SSNs for any stub still hooked after Halo's pass.

5. **Gadget location.** Scan ntdll `.text` for `0F 05 C3`. Because every `Nt*` export ends with exactly those three bytes, a single scan finds hundreds of gadgets. Pick one (current implementation: deterministic, first match). Cache its VA as `usize`.

6. **Cache entry.** Insert `(SSN, gadget_addr)` into `OnceLock<HashMap<u32, (u32, usize)>>` keyed by the function's DJB2 hash. First call resolves + caches; subsequent calls hit the HashMap in O(1).

7. **Dispatch via `recycled_N(ssn, gadget, args...)`.** Rust's calling convention spills args 5–11 onto the shadow stack at `[rsp+0x28]`, `[rsp+0x30]`, … before calling `recycled_N`. The stub then:
   - Loads `rcx = a1` via `in("rcx") a1` constraint
   - Loads `rdx`, `r8`, `r9` for args 2–4 via `in("rdx")`, `in("r8")`, `in("r9")`
   - In asm: `mov r10, rcx` — moves arg1 into the NT syscall ABI register (because `syscall` itself clobbers `rcx`)
   - In asm: `mov eax, {ssn:e}` — loads SSN as 32-bit immediate into `eax`
   - In asm: `jmp {gadget}` — transfers control to the ntdll gadget

8. **Gadget execution.** The gadget at the ntdll VA executes `0F 05` (`syscall`). At the kernel boundary:
   - RIP is inside `\KnownDlls\ntdll.dll`'s `.text`
   - The return address on the stack points one byte past the `jmp` site, which is still inside `recycled_N`'s body — but the *immediate* caller frame on the kernel side is `ntdll!+0xN` (the gadget address).
   - Kernel reads `r10` as arg1, `rdx`/`r8`/`r9` as args 2–4, `[rsp+0x28]`/`[rsp+0x30]` as args 5–6 (these are spilled by Rust ABI to the caller's stack frame).

9. **Return path.** Gadget executes `C3` (`ret`). Because `jmp` did not push a return address, `ret` pops the *original* caller-of-`recycled_N` return address. Stack unwinds cleanly back to the Rust caller. `options(nostack)` on the asm block guarantees `rsp` was not modified by the stub.

10. **ETW-TI stack walk view.** When ETW Threat Intelligence samples the call stack at the `syscall` instruction, the topmost return address points to `ntdll+N` (the gadget). The next frame up is `recycled_N` inside the implant's `.text`. Pair this with `advanced_stack` (T-016) to replace the implant frame with a synthetic return chain through `kernel32`/`kernelbase`/`ntdll` so even deep stack walks look benign.

## Operational Profile

### When to Use
- **Default syscall path on any engagement.** RecycledGate is the baseline dispatch for dark_crystal; everything else (`sys_indirect.rs` mode selection, VEH Gate, direct syscalls) is a variant for special cases.
- **Targets with ETW-TI enabled.** Defender for Endpoint, SentinelOne, CrowdStrike Falcon, Elastic EDR — they all walk the stack at syscall time and flag return addresses outside loaded module ranges. RecycledGate puts the syscall RIP inside ntdll, satisfying this check.
- **Memory-constrained injection chains.** No allocations required for syscall stubs; they live in implant `.text` and need zero runtime backing.
- **AV/EDR with userland hooking but no kernel callbacks.** Bypasses userland IAT/EAT hooks entirely because no `ntdll!Nt*` export is called through its prologue — execution jumps straight to the syscall body.
- **Situations where you must avoid creating threads/sections that look like direct syscalls.** Combined with T-016 stack spoofing, the entire syscall surface area looks like normal ntdll traffic.

### When NOT to Use
- **CET-enforced targets (Win11 22H2+, Intel Tiger Lake+ with CET on).** The `jmp {gadget}` lands on a non-`ENDBR64` byte and raises `#CP` (Control-flow Protection exception). Use the VEH Gate path (T-003) or the `sys_recycled.rs` CET-compatible variant instead.
- **EDRs that scan ntdll `.text` for gadget re-use patterns.** If the EDR fingerprints "syscall; ret followed by external jmp" as a known Indirect Syscall pattern, the cached gadget becomes a signature.
- **One-shot droppers where build complexity isn't justified.** If you're running a single `NtAllocateVirtualMemory` + `NtCreateThreadEx` chain with no need to hide from ETW-TI, direct syscalls via `sys_indirect.rs` mode `"direct"` are simpler.
- **Anti-cheat environments (EAC, BattlEye, Vanguard).** These run kernel callbacks that hook `PsSetCreateProcessNotifyRoutine` semantics and patch ntdll in nonstandard ways; Halo's Gate fallback may not find an intact stub.

### Kill Chain Position
RecycledGate is **infrastructure**, not a payload. It sits between module/SSN resolution and any concrete NT API call:

`T-004 (PEB walk for ntdll)` → `T-002 (Hell's/Halo's/Tartarus Gate SSN cascade)` → **`T-001 (RecycledGate dispatch)`** → `T-012 (Early Cascade APC inject via NtQueueApcThread)` → `T-005 (Ekko ROP sleep obfuscation)` → `T-017 (NTFS EA persistence via NtSetEaFile)`

Everything from T-005 onward in the vault depends on this dispatch layer. The only techniques that bypass it are: pure Win32 API calls (T-022 networking via WinHTTP/Winsock), pure Rust stdlib (TLS callback persistence path in T-017), and VEH Gate alternative dispatch (T-003).

### Trade-offs
| Dimension | Rating | Notes |
|---|---|---|
| Stealth | 9.5 | syscall RIP in ntdll, return address in ntdll. Combined with T-016 advanced stack, becomes a 10. Weakness: caller-of-recycled_N frame still in implant .text. |
| Reliability | 8.5 | Depends on T-002 cascade finding an intact stub. Fails if entire neighborhood of ntdll is hooked (rare on modern Windows). |
| Complexity | 6 | Inline asm + DJB2 + OnceLock cache is straightforward. The 11-stub matrix and arg-spill conventions require care to extend. |
| Version range | Win7 SP1 x64 – Win11 24H2 | SSN mechanism is stable since Win7 x64. CET (Win11 22H2+ on CET hardware) breaks the `jmp` variant — use the crates/core `sys_recycled.rs` path or fall back to VEH Gate. |
| Privilege needed | none | Dispatch layer; works at any IL. The *syscalls themselves* may require privileges (e.g., `NtCreateProcessEx` needs SeAssignPrimaryToken for some operations). |

## Rust Implementation Deep Dive

### Source location
- **Primary**: `dark_crystal/crowd/src/recycled.rs` (~793 lines) — production path used by `dark_crystal/crowd` chains.
- **Alt**: `dark_crystal/crates/core/src/sys_recycled.rs` — core-crate variant with CET compatibility notes, used by `sys_indirect.rs` when `syscall_mode == "indirect"`.

### `unsafe` boundaries
The `recycled_N` functions are entirely `unsafe fn` because:
1. They dereference arbitrary `usize` arguments that the caller claims are valid NT API argument pointers.
2. `core::arch::asm!` with `clobber_abi("system")` allows the asm block to clobber all caller-saved registers without Rust knowing.
3. The `jmp` to a cached `usize` gadget is a raw control-flow transfer; if the gadget cache was poisoned, control flow goes anywhere.
4. `options(nostack)` is a claim to the compiler that `rsp` is unchanged — if a future edit adds `push`/`sub rsp` to the asm template, this becomes UB silently.

### `core::arch::asm!` constraints
```rust
asm!(
    "mov r10, rcx",
    "mov eax, {ssn:e}",
    "jmp {gadget}",
    ssn = in(reg) ssn,        // compiler picks a GPR, as 32-bit operand
    gadget = in(reg) gadget,  // compiler picks a GPR, full 64-bit
    in("rcx") a1,             // arg1 placed in rcx before block
    lateout("rax") status,    // syscall return value captured into `status`
    clobber_abi("system"),    // declare Win x64 syscall ABI clobbers
    options(nostack),         // rsp is not modified
);
```

- `{ssn:e}` uses the `:e` modifier to force 32-bit register name (`eax`) instead of `rax`.
- `in(reg)` for `ssn` and `gadget` lets the compiler pick any free GPR; the asm template uses `mov` to move them into the final destination.
- `in("rcx") a1` is direct register placement — the compiler emits code to put `a1` in `rcx` before the asm.
- `lateout("rax") status` captures the syscall return (NTSTATUS) into a local `i32`. `lateout` means the register is written *after* all inputs are consumed, so it doesn't conflict with `eax`-related input moves.
- `clobber_abi("system")` declares the Windows x64 system ABI, meaning rax/rcx/rdx/r8/r9/r10/r11 and xmm0–5 may be clobbered. The compiler saves/restores callee-saved registers (rbx/rbp/rdi/rsi/r12–r15) as needed for the surrounding Rust code.
- `options(nostack)` is *correct* for this specific template — `mov` and `jmp` don't touch `rsp`. The `ret` inside the gadget pops the frame the *Rust caller* set up when calling `recycled_N`, not a frame the asm block pushed.

### Why `jmp` not `call`
The card mentions a `call r11` pattern in the description, but the actual source uses `jmp`. This is more elegant:
- A `call` would push an implant-`.text` return address onto the stack, which the gadget's `ret` would pop — defeating the entire stealth purpose (the syscall's return address would be the implant).
- A `jmp` leaves the original caller-of-`recycled_N` return address on the stack. The gadget's `ret` pops it, returning directly to Rust. The kernel-side stack walk sees: top frame = ntdll gadget, next frame = Rust caller (implant .text).

If you need an implant-`.text`-free stack, combine with T-016 `advanced_stack` which fakes the next-up frame.

### Function signature convention
```rust
pub unsafe fn recycled_1(ssn: u32, gadget: usize, a1: usize) -> i32
pub unsafe fn recycled_6(
    ssn: u32, gadget: usize,
    a1: usize, a2: usize, a3: usize,
    a4: usize, a5: usize, a6: usize,
) -> i32
```
- `usize` for all args. Pointers, handles, and integer args all fit. The caller is responsible for casting `*mut c_void`, `HANDLE`, etc. to `usize`.
- Returns `i32` — the NTSTATUS. Callers must check `< 0` for errors (`NT_SUCCESS` macro equivalent).
- 11 stubs (`recycled_1` through `recycled_11`) cover all NT syscalls in the inventory. The largest argument count actually used by covered functions is 11 (`NtCreateUserProcess`).

### Shadow stack / args 5+
The comment in `recycled_6` says "a5, a6 already on shadow stack (pushed by Rust ABI)." This is critical:
- Rust's x64 system ABI spills args 5+ to the stack at offsets `[rsp+0x28]`, `[rsp+0x30]`, etc. relative to the *callee* entry (i.e., after the 0x20 shadow space and the return address).
- When `recycled_6` does `jmp {gadget}`, the syscall instruction reads args 5+ from the same offsets — because Rust already placed them there.
- This means **no additional stack manipulation is needed in the asm block**. The `options(nostack)` is correct.
- Caveat: the syscall instruction itself doesn't read args — the kernel does, after the syscall transition. But the kernel reads from the user stack at the same offsets relative to `rsp` at the moment of `syscall`. Since `jmp` didn't change `rsp`, the offsets are identical to what Rust's caller set up.

### `#[inline(never)]` rationale
The stubs are marked `#[inline(never)]` for three reasons:
1. Preserves the call/ret frame structure so the gadget's `ret` has a valid return address to pop.
2. Makes the stubs individually addressable — the OnceLock cache can reference them by symbol.
3. Allows the stubs to be grep'd / debugged. *Downside*: in debug builds the symbol `recycled_6` leaks. Use the `obf` crate (T-021) to rename symbols in release builds, or compile with `panic=abort` + `strip=true` + `--remap-path-prefix`.

### Initialization: `OnceLock<HashMap<u32, (u32, usize)>>`
- `u32` key = DJB2 hash of function name (computed at build time via `const fn`).
- `(u32, usize)` value = `(SSN, gadget_address)`.
- Lazy initialization on first call to a `recycled_*` wrapper. Wrappers like `recycled_nt_allocate_virtual_memory()` exist in `recycled.rs` that look up the SSN+gadget for their hash, then call `recycled_6(ssn, gadget, ...)`.
- `OnceLock::get_or_init` ensures thread-safe one-shot initialization — important because dark_crystal chains may spawn worker threads via T-007 Pool Party.

### Error paths
- If the gadget scan fails: returns `STATUS_NOT_FOUND` (`0xC0000225`) up the chain. Currently the wrapper bails silently — the operator sees the syscall return a non-`NT_SUCCESS` code.
- If the SSN resolution fails entirely: `recycled_*` is never called because the wrapper returns early.
- If the syscall itself returns an error NTSTATUS: the stub faithfully returns it as `i32`. The Rust caller must check.

No retry, no degrade, no logging — failure surfaces as a negative NTSTATUS.

## Edge Cases & Failure Modes

1. **CET-enabled Windows 11 22H2+ with hardware CET (Intel 12th gen+)**
   - The `jmp {gadget}` transfers control to a non-`ENDBR64` address. The CPU raises `#CP` (Exception 0x100).
   - Symptom: the calling process dies silently or via `STATUS_STACK_BUFFER_OVERRUN` (`0xC0000409`).
   - Workaround: switch `syscall_mode` to `"veh"` (T-003 VEH Gate) or use `crates/core/src/sys_recycled.rs` which has CET-compatible variants using `call` to `ENDBR64`-marked targets. Alternatively, disable CFG/CET for the host process via `SetProcessValidCallTargets` on a fake CFG bitmap that whitelists the gadget address.

2. **EDR hooks ntdll (Defender, SentinelOne, ESET, Kaspersky)**
   - The leading `4C 8B D1` of the target export is overwritten with `jmp <trampoline>` or `push <return_addr>; ret`.
   - T-002 Halo's Gate fallback walks `±0x20` strides looking for intact stubs. If the EDR hooks *every* `Nt*` export (uncommon but seen with Kaspersky), Halo's Gate fails.
   - Tartarus Gate then sorts `Zw*` exports by RVA and infers SSNs from the sorted order — this works even if all `Nt*` stubs are hooked, because `Zw*` exports are usually not patched.
   - Symptom: `recycled_*` returns `0` SSN or returns garbage NTSTATUS like `0xC0000005` (ACCESS_VIOLATION) because the SSN is wrong.
   - Workaround: verify SSN by cross-checking against the `Zw*` sorted order before caching. Add a sanity check that the gadget bytes are exactly `0F 05 C3`.

3. **Halo's Gate walks off the end of `.text`**
   - If the hooked stub is near the boundary of ntdll's `.text` section, walking `±0x20*N` strides can land in `.data` or `.pdata`, where the bytes look like a valid stub by coincidence.
   - Symptom: SSN resolves to a wild value (e.g., `0x80000000`), syscalls fail with `STATUS_INVALID_SYSTEM_SERVICE` (`0xC000001C`).
   - Workaround: bound the walk to the section's virtual range. Check `IMAGE_SECTION_HEADER::VirtualAddress` and `SizeOfRawData`.

4. **Args 5+ alignment with Rust ABI on `recycled_7` through `recycled_11`**
   - Rust's x64 system ABI passes args 7+ on the stack at `[rsp+0x38]`, `[rsp+0x40]`, etc. *However*, the Rust compiler may add padding for struct alignment if any arg is a struct.
   - Symptom: syscall reads garbage for arg 7+ because Rust placed padding where the syscall expects the arg.
   - Workaround: ensure all args are `usize` (8-byte aligned). Never pass structs directly — pass `&raw const` pointers.

5. **OnceLock cache poisoning**
   - If an anti-malware product injects a thread into the implant process *before* the first syscall, it can hook `OnceLock::get_or_init` (unlikely but possible on systems with kernel instrumentation).
   - Symptom: SSN+gadget cache returns `(0, 0)` or invalid addresses; syscalls crash.
   - Workaround: initialize the cache eagerly at loader entry (TLS callback in T-017) before any other code runs.

6. **`#[inline(never)]` symbol leak in release builds**
   - In `--release` without `strip=true`, `recycled_1` through `recycled_11` appear in the binary's symbol table. Yara rules can match `recycled_1` ... `recycled_11` as a sequence.
   - Symptom: AV/EDR Yara signature hits.
   - Workaround: build with `-C strip=true -C panic=abort` and use `--remap-path-prefix` to strip paths. Use `obf` proc-macro to rename the stubs at compile time.

7. **NTDLL unhooking by EDR post-init**
   - Some EDRs (CrowStrike Falcon 6.x+) periodically re-hook ntdll in a worker thread. After RecycledGate caches a gadget address, the EDR may overwrite the `0F 05 C3` bytes with `jmp <trampoline>`.
   - Symptom: cached gadget address now points to `jmp <trampoline>` instead of `syscall; ret`. The `jmp` transfers control into the EDR's hook code, which then logs the syscall arguments.
   - Workaround: re-scan the gadget on each call (perf cost), or use T-016 `ntdll_unhook_inject` to keep ntdll clean.

8. **Stack alignment on `recycled_*` callers compiled with `panic=unwind`**
   - If the caller of `recycled_N` is itself in a function that may unwind, Rust may insert landing pads that adjust `rsp` non-trivially. The `options(nostack)` claim may then be inaccurate.
   - Symptom: rare crashes when a syscall happens inside a `?`-returning function.
   - Workaround: build with `panic=abort`, or ensure all `recycled_*` callers are `#[inline(never)]` themselves.

## Variant Ideas

1. **Multi-gadget rotation.** Cache a *Vec<usize>* of valid gadget addresses per SSN, and pick one at random per call. Defeats EDR pattern matching on a single gadget address. Implementation: extend the gadget scan to collect all `0F 05 C3` hits, store as `Vec`, use `thread_local_rng` to pick.

2. **Call-based variant with synthetic ntdll return frame.** Replace `jmp {gadget}` with `call {gadget}` and pre-push a synthetic ntdll return address so the syscall's return address points *two* frames into ntdll. Combined with T-016 `advanced_stack`, the entire stack walk above the syscall becomes indistinguishable from a real `ntdll!Nt*` call chain.

3. **CET-compatible indirect call via `__guard_check_icall_fptr`.** Use the CFG (Control Flow Guard) dispatcher to validate the gadget address before jumping. The gadget address must be added to the CFG bitmap via `SetProcessValidCallTargets`. This makes `jmp {gadget}` CET-legal because the gadget is then a CFG-whitelisted target.

4. **Cross-module gadget diversity.** Pull gadgets from `win32u.dll` (which also contains `0F 05 C3` sequences for `NtUser*` syscalls), `kernelbase.dll`, and any other loaded module. Vary the gadget source per syscall category — `Nt*` calls go through ntdll gadgets, `NtUser*` through win32u, etc. Breaks the "single return-address module" heuristic.

5. **Per-call stub mutation.** At init, generate 11 randomized stubs in `MEM_RWX` memory (or `MEM_IMAGE` via Phantom Stubs T-006) with the same semantics but different register scheduling, different junk `nop`/`xchg` instructions between the moves. Each call dispatches via a different stub. Defeats code-pattern signatures.

6. **VEH Gate hybrid.** Combine with T-003: use RecycledGate for *normal* syscalls but VEH Gate (HW breakpoint mediated) for *sensitive* syscalls like `NtCreateThreadEx` or `NtAllocateVirtualMemory`. The HW breakpoint path leaves no syscall instruction in the implant's `.text` at all, even transiently.

7. **Argument spoofing integration.** Wire T-016 `arg_spoof` into the stub. Before the `jmp {gadget}`, swap the caller's stack frame with a synthetic argument set so that if the EDR inspects the stack *after* the syscall completes, the args look like a benign call (e.g., `NtClose(handle_to_notepad)` instead of `NtClose(handle_to_lsass)`).

8. **Win11 24H2 `KUSER_SHARED_DATA` SSN verification.** Newer Windows builds may eventually expose syscall numbers via `KUSER_SHARED_DATA` or a similar read-only page (currently used for time, but Microsoft has been extending it). Add a sanity check that the T-002 cascade SSN matches the system-published SSN, if such a mechanism ever ships.

## OPSEC Notes

- **Artifacts in memory**: 11 `recycled_N` functions in implant `.text`, each ~30 bytes. No allocations, no files, no registry writes from the dispatch layer itself.
- **Artifacts in ntdll**: none. RecycledGate reads ntdll but does not write to it. If you wire T-016 `ntdll_unhook_inject` to run *before* RecycledGate init, you guarantee the cached gadget is from a clean ntdll.
- **ETW-TI telemetry**: the syscall boundary stack walk sees `ntdll+N` as the return address — *passes* the standard ETW-TI check for "non-image return address at syscall". Combined with T-016 `advanced_stack`, even the next frame up is faked to be a real ntdll/kernel32 frame.
- **EDR product-specific**:
  - **Microsoft Defender for Endpoint** (with ETW-TI + AMSI): passes the return-address check. May still catch via `MpClient.dll` behavioral rules on the *called* syscall (e.g., `NtAllocateVirtualMemory` in a foreign process). Pair with T-007 Pool Party or T-012 Early Cascade to defeat the behavioral check.
  - **CrowdStrike Falcon**: kernel-side `nt!PsSetCreateProcessNotifyRoutine` callbacks fire regardless of syscall path. RecycledGate doesn't help with kernel callbacks — it only defeats userland ETW-TI.
  - **SentinelOne**: hooks ntdll. Halo's Gate fallback handles this. Watch for re-hooking.
  - **Elastic EDR**: stack-based detection ("return address outside loaded modules") passes.
- **Cleanup**: none required for the dispatch layer. The gadget cache in `OnceLock` is destroyed when the process exits. If you've initialized eagerly via a TLS callback (T-017), the cache exists from process start — acceptable.
- **Forensic traces**: if a memory image is captured while the implant is loaded, the `recycled_*` stubs are recoverable from `.text`. Their pattern (`mov r10, rcx; mov eax, ...; jmp ...`) is distinctive. Mitigate with stub mutation (variant #5 above).

## Reusable Patterns

### Pattern: OnceLock-Cached Syscall Dispatch
- **Use when**: any wrapper around an NT API that resolves SSNs at runtime.
- **How**: Declare `static SYSCALL_CACHE: OnceLock<HashMap<u32, (u32, usize)>> = OnceLock::new();`. On first call, run T-002 cascade to populate the map. Subsequent calls do `let (ssn, gadget) = CACHE.get().unwrap().get(&hash).copied()?;` then dispatch via `recycled_N(ssn, gadget, ...)`.
- **Code ref**: `dark_crystal/crowd/src/recycled.rs` — wrapper functions like `pub fn nt_allocate_virtual_memory(...) -> Result<NTSTATUS, ...>` look up by `djb2(b"NtAllocateVirtualMemory")` constant.

### Pattern: Argument-Spilling Inline Asm
- **Use when**: implementing a custom dispatch that needs the syscall to read args 5+ from the stack.
- **How**: declare the Rust function with the full arg count. Rust's x64 system ABI will spill args 5+ onto the shadow stack automatically. Use `in("rcx")`/`in("rdx")`/`in("r8")`/`in("r9")` constraints for the first four. The asm template can be just `mov r10, rcx; mov eax, {ssn:e}; jmp {gadget}` with `options(nostack)` — no manual stack manipulation needed.
- **Code ref**: `recycled_6` in `dark_crystal/crates/core/src/sys_recycled.rs`.

### Pattern: DJB2 Hash Constants for Export Resolution
- **Use when**: any path that needs to resolve NT API by name without string literals in the binary.
- **How**: declare `const NT_ALLOCATE_VIRTUAL_MEMORY_HASH: u32 = djb2(b"NtAllocateVirtualMemory");` where `djb2` is a `const fn`. Pass the constant to the resolver. The resolver walks the export table and computes DJB2 on each name, comparing against the constant. No `&str` lookup, no `GetProcAddress`, no string in `.rdata`.
- **Code ref**: `dark_crystal/crowd/src/resolve.rs` — PEB walker + DJB2 hash resolution.

### Pattern: `lateout("rax") status` for NTSTATUS Capture
- **Use when**: any inline-asm syscall stub.
- **How**: declare `let status: i32;` before the asm block. Use `lateout("rax") status` — `lateout` means the register is written *after* inputs are consumed, avoiding conflicts with `eax`-related input moves. After the block, return `status`. Caller checks `< 0` for `NT_ERROR`/`NT_WARNING`.
- **Code ref**: all 11 `recycled_N` stubs in `sys_recycled.rs`.

### Pattern: `clobber_abi("system")` for Win x64 Syscall Stubs
- **Use when**: any inline asm that calls into the Windows kernel via `syscall`.
- **How**: add `clobber_abi("system")` to the `asm!` call. This tells the compiler that the asm block follows the Windows x64 system ABI, so all caller-saved registers (rax, rcx, rdx, r8, r9, r10, r11, xmm0–5) may be modified. The compiler will save/restore callee-saved registers as needed for the surrounding Rust code. Without this, the compiler may incorrectly assume registers are preserved across the asm block, leading to subtle corruption.
- **Code ref**: all `recycled_N` stubs.