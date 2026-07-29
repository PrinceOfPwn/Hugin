---
id: T-120
name: x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs
category: syscalls
tier: B
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1055]
tags: [x64-abi, shadow-space, calling-convention, syscall-stub, parameter-home-area, argument-spilling, rop-frame, intel-cet]
member_notes: ['lgtm:x64-calling-convention-stub-constraint', 'lgtm:x64-abi-syscall-stub-construction', 'lgtm:cross-source-convergence-shadow-store-and-rop']
origin: atlas-synthesis
---

# x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs — The contract every Windows syscall path obeys

## Summary

The Microsoft x64 calling convention is the unbreakable contract under which every Windows syscall path — the canonical `ntdll!Nt*` stub, a hand-rolled direct-syscall stub, or a synthetic `syscall; ret` gadget reached through a ROP frame — exchanges arguments with the kernel. Integer and pointer arguments flow in RCX, RDX, R8, R9 in order; arguments five and beyond spill to the user stack at RSP+0x28 (callee post-call view), RSP+0x30, RSP+0x38, and so on, pushed right-to-left and cleaned by the caller. The caller must reserve a 32-byte parameter home area ("shadow space") at RSP+0..RSP+0x1F (pre-call caller view) — four 8-byte slots, one per register-passed argument — into which the callee is permitted (but not obligated) to spill RCX, RDX, R8, R9. The ABI requires RSP to be 16-byte aligned immediately before `call`; after the 8-byte return-address push RSP is misaligned by 8, which is why function prologues subtract odd multiples of 8 (e.g. `sub rsp, 0x28` = 32 shadow + 8 realign) to restore 16-byte alignment inside their frame. The Windows NT syscall ABI diverges from the Microsoft ABI in exactly one place: the `syscall` instruction destroys RCX (the return RIP is stored there), so the first user argument is re-homed into R10 before `syscall` executes, while the service number (SSN) is loaded into EAX. RAX returns the NTSTATUS. This card documents the ABI contract, the canonical ntdll stub byte pattern, and the implications for direct-syscall stubs (T-002), SSN harvesters of the Hells Gate family (T-003), and ROP-frame syscall invocation in Ekko-class sleep obfuscation (T-005). It is the prerequisite that makes the syscalls category legible: T-001, T-002, T-003, T-005, T-006, and T-016 all assume the shadow store is present and writable before their stubs execute. The vault's T-095 (NTDLL Unhook typology) documents the broader PE-side mechanics of ntdll stub patching but does not cover the ABI contract those stubs must satisfy even when patched. This card also explicitly disambiguates the ABI "shadow space" from Intel CET's hardware "Shadow Stack" — they share a name and nothing else.

## Mechanism

### Variant 1: Canonical ntdll syscall stub

1. Caller loads arguments per Microsoft x64 ABI: RCX ← arg1, RDX ← arg2, R8 ← arg3, R9 ← arg4; arguments 5+ are placed at RSP+0x20, RSP+0x28, RSP+0x30 (caller's pre-call frame view), in left-to-right order with arg5 nearest to the top of stack.
2. Caller reserves 32 bytes of shadow space at RSP+0..RSP+0x1F before invoking `call ntdll!Nt*`. The four slots need not be initialized; they must be writable because the callee may spill RCX, RDX, R8, R9 into them.
3. Caller ensures RSP mod 16 == 0 immediately before `call`. If the caller's frame has consumed an odd number of 8-byte stack slots since the last 16-byte boundary, it must `sub rsp, 8` (or align-equivalent) before the call.
4. Caller executes `call Nt*`, pushing the 8-byte return RIP onto the stack. RSP is now misaligned by 8 mod 16.
5. ntdll stub begins: `4C 8B D1` (`mov r10, rcx`) — copies arg1 from RCX into R10. This is mandatory because the `syscall` instruction will overwrite RCX with the return RIP in the next few cycles.
6. Stub executes `B8 <SSN> 00 00 00` (`mov eax, <SSN>`) — loads the syscall service number into the lower 32 bits of RAX. The `mov eax, imm32` encoding (opcode `B8` + 4-byte immediate) zero-extends into RAX, so the upper 32 bits are cleared automatically; if a previous operation left stale high bits in RAX, `mov rax, imm64` would leave them, but `mov eax` does not.
7. Stub executes `F6 04 25 08 03 FE 7F 01` (`test byte ptr [0x7FFE0308], 1`) — reads `KUSER_SHARED_DATA.SystemCall` flag at user-accessible address `0x7FFE0308` to select between the `syscall` fast path (modern CPU) and the legacy `int 2Eh` interrupt-gate path.
8. On all modern x64 systems the byte at `0x7FFE0308` is `0`, so `test` sets ZF=1. The stub's `75 03` (`jne short +3`) does not branch; execution falls through to `syscall`.
9. Stub executes `0F 05` (`syscall`). CPU saves RFLAGS to R11, saves next-instruction RIP to RCX, loads CS from `IA32_STAR[47:32]`, loads SS from `IA32_STAR[47:32]+8`, loads RIP from `IA32_LSTAR` MSR (pointing at `nt!KiSystemCall64`). The CPU is now in ring 0 with the kernel's GDT/IDT active.
10. `KiSystemCall64` performs `swapgs` (loads kernel GSBase from `IA32_KERNEL_GS_BASE` MSR), reads the kernel RSP from the per-CPU TSS (`MSR_GS_BASE + offset to KPCR.SPR0`), copies the user-mode trap frame, and indexes `KeServiceDescriptorTable` (or `KeServiceDescriptorTableShadow` for Win32k syscalls) by the lower 12 bits of EAX. The argument count for the dispatched syscall is read from the encoded SSDT entry (lower 4 bits of the function-pointer entry); KiSystemService copies that many additional stack arguments from the user stack into the kernel-side argument buffer.
11. Kernel syscall body executes with R10/RDX/R8/R9 + the kernel-side argument copies; returns NTSTATUS in RAX.
12. `sysret` returns control to user mode at the return RIP (restored from RCX), RFLAGS restored from R11. CS/SS are reloaded from `IA32_STAR[63:48]`.
13. Stub executes `C3` (`ret`), popping the 8-byte return address from RSP. The caller's RSP is now back to its pre-call state. The caller sees RAX = NTSTATUS.

### Variant 2: Direct-syscall stub (T-002 family)

1. Operator (or tool author) constructs a stub in executable memory at a chosen base address. The minimal pattern is 12 bytes:
   ```
   4C 8B D1           mov  r10, rcx
   B8 <SSN> 00 00 00  mov  eax, <SSN>
   0F 05              syscall
   C3                 ret
   ```
2. Caller loads arguments identically to Variant 1: RCX ← arg1, RDX ← arg2, R8 ← arg3, R9 ← arg4, args 5+ at RSP+0x20.
3. Caller still reserves 32 bytes of shadow space at RSP+0..RSP+0x1F, even though this minimal stub never spills to it. The reservation preserves 16-byte alignment post-`call`, prevents accidental writes into the caller's own frame data if a future stub variant adds spill code, and avoids tripping stack-touch sanity checks that some EDRs run on the home area.
4. Caller executes `call <stub_base>`. The 8-byte return address is pushed, RSP misaligns by 8.
5. Stub executes `mov r10, rcx; mov eax, <SSN>; syscall; ret` — runtime behavior identical to Variant 1, with the `test byte ptr [0x7FFE0308]` branch elided because the operator has already validated the host uses `syscall` rather than `int 2Eh`.
6. `sysret` returns; `ret` pops the return address; RAX = NTSTATUS.

### Variant 3: ROP-frame syscall invocation (Ekko-class)

1. Operator locates a `0F 05 C3` byte sequence (`syscall; ret`) inside an existing loaded module. The cleanest source is `ntdll!Nt*` stubs themselves, since every such stub contains `0F 05 C3` at stub_base+0x12. Other modules (any module with `syscall`-instruction byte sequences in dead code or alignment padding) also work.
2. Operator locates a `mov r10, rcx; ret` gadget — bytes `4C 8B D1 C3` — or arranges to set R10 through `pop r10; ret` (`41 5A C3`) if RCX is loaded separately.
3. Operator locates an SSN-load gadget. Either `mov eax, imm32; ret` is searched (5 bytes: `B8 ?? ?? ?? ?? C3`, common but stub-specific) or, more flexibly, `pop rax; ret` (`58 C3`) is used with the SSN pre-staged on the ROP stack.
4. Operator prepares the synthetic ROP stack inside an executable+readable+writable page (typically VirtualAlloc'd with `PAGE_EXECUTE_READWRITE = 0x40` or staged via section mapping). Each gadget's 8-byte return address occupies one stack slot; the chain is RSP[0]=gadget1_ret, RSP[8]=gadget2_ret, RSP[0x10]=gadget3_ret, ...
5. Operator's ROP frame must include 32 bytes of writable shadow space at the offsets any intervening gadget prologue expects. For pure leaf gadgets (`pop rax; ret`, `mov r10, rcx; ret`, `syscall; ret`) the shadow space is not strictly required because the gadgets do not spill. For function-call-shaped gadgets that begin with a typical prologue (`mov [rsp+8], rcx; mov [rsp+0x10], rdx; ...`), the shadow space must be at RSP+0..RSP+0x1F (post-`call` callee view) of the gadget's perspective, which translates to the synthetic stack region immediately preceding the gadget's RSP slot.
6. Ekko (T-005) constructs precisely this kind of synthetic stack inside a VirtualAlloc'd page; the page is delivered to a queued timer via `CreateTimerQueueTimer` or to an APC via `NtQueueApcThread` so that `NtContinue`'d threads execute it from a benign-looking origin. The shadow space allocation sits within the synthetic stack at offsets expected by `NtSetContextThread`, `NtWaitForSingleObject`, and `NtSetInformationThread` (PagePriority class) — the three syscalls Ekko uses for sleep obfuscation.
7. ROP chain executes: gadget sequence sets R10/RAX/RCX/RDX/R8/R9, the `syscall; ret` gadget triggers the syscall, the next frame slot is the chain's continuation address (often the address to return execution to a context-restore gadget or to the original loader).
8. Result: syscall invoked without ever touching `ntdll!Nt*` code. User-mode hooks installed on `Nt*` stubs do not fire. ETW Threat Intelligence (raised inside the kernel syscall body) still fires — see Detection Considerations.

## OS Internals Context

The Microsoft x64 ABI is enforced by code generation, not by hardware. The hardware cares only about RSP being 16-byte aligned when an aligned SSE/AVX instruction executes (`movaps`, `movdqa`, etc. fault with `#GP` on misalignment). Everything else — RCX/RDX/R8/R9 argument order, the 32-byte parameter home area, caller-cleanup of stack arguments, the `xor eax, eax` return convention — is convention shared between the C/C++ compiler, the Windows headers, and `ntdll`/`kernel32` stubs. There is no architectural gatekeeper; misaligned argument passing produces silent corruption rather than a fault.

**Shadow space provenance**: The 32-byte home area exists for two reasons. First, it gives the callee a known-writable place to spill the four register arguments if it needs to take their address (`&arg1` must yield a stable pointer) or if register pressure forces a spill. Second, it preserves 16-byte alignment across the call boundary: the `call` instruction pushes 8 bytes, so a frame that was 16-byte aligned before `call` is 8 mod 16 after; reserving 32 bytes (an even multiple of 16) plus an additional 8 bytes (the canonical `sub rsp, 0x28` prologue) restores 16-byte alignment inside the callee. This is why even leaf functions that don't touch their arguments still subtract `0x28` from RSP — the alignment is the actual requirement, the shadow space is a useful side allocation.

**`syscall` instruction microarchitecture**: When the `syscall` instruction executes, the CPU does the following in a single architectural step: (1) saves RFLAGS to R11; (2) saves next-RIP (the instruction after `syscall`) to RCX; (3) loads CS from `IA32_STAR[47:32]`; (4) loads SS from `IA32_STAR[47:32] + 8`; (5) loads RIP from `IA32_LSTAR` MSR (`0xC0000082`); (6) clears IF in RFLAGS (interrupts disabled in kernel). The kernel entry `nt!KiSystemCall64` immediately executes `swapgs` (swaps `IA32_KERNEL_GS_BASE` into GSBase, pushing user GSBase into `IA32_KERNEL_GS_BASE`), reads the kernel RSP from the per-CPU `KPCR.SPR0` (offset within the GS-relative per-CPU region), and copies a `KTRAP_FRAME` onto the new kernel stack. The trap frame (384 bytes on x64) preserves all volatile registers, segment registers, the original user RSP, the previous-mode field (`PreviousMode = UserMode`), and the saved exception frame. The KiServiceTable index lookup uses the lower 12 bits of EAX (the SSN); bit 12 of EAX selects `KeServiceDescriptorTable` (0, NT syscalls) versus `KeServiceDescriptorTableShadow` (1, includes Win32k entries for `NtUser*`/`NtGdi*` syscalls).

**`KUSER_SHARED_DATA.SystemCall` flag**: The user-shared data page at `0x7FFE0000` (mapped read-only into every user-mode process at the fixed virtual address) contains, at offset `0x300`, a `SystemCall` field. The flag byte at offset `0x308` is what the canonical ntdll stub tests: if bit 0 is set, the system uses `int 2Eh` (legacy interrupt-gate dispatch through `nt!KiSystemService`); if bit 0 is clear, the system uses `syscall` (modern fast-path through `nt!KiSystemCall64`). The kernel sets this flag at boot based on CPU feature detection; on every x64 CPU since roughly the Pentium 4 (2005+), the flag is 0 and `syscall` is used. Direct-syscall stubs (Variant 2) elide the test entirely, accepting that they will not run on pre-2005 hardware.

**SSDT encoding**: Each `KeServiceDescriptorTable` entry is a `ULONG_PTR` (8 bytes on x64). The lower 4 bits encode the stack-argument count for that syscall (in 8-byte units; e.g. a value of 3 means 24 bytes of stack arguments beyond the four register-passed args). The upper 60 bits encode the kernel function's address, with the lower 4 bits cleared and the result sign-extended. The kernel's `KiSystemService` reads the entry, masks off the argument count, sign-extends the upper bits, and jumps to the function. This encoding is why SSDT patching was a popular rootkit technique in the x86 era: replacing an entry with `(HookFunction & ~0xF) | RealArgCount` redirected the syscall without changing the user-mode stub.

**`KTRAP_FRAME` layout**: The trap frame that `KiSystemCall64` builds on the kernel stack contains, at well-known offsets, the saved volatile registers (`R11`, `R10`, `R9`, `R8`, `RDX`, `RCX`), the original user-mode RAX (which becomes the SSN, then the saved value), the user-mode RIP, CS, RSP, SS, and the `PreviousMode` (set to `UserMode` for syscalls originating in user space). The trap frame is the data structure that any kernel-mode caller of `Nt*` functions must synthesize correctly to invoke a syscall from within the kernel — the `PreviousMode` field is what `SeAccessCheck` consults to enforce `OBJ_KERNEL_HANDLE` and `ExGetPreviousMode()`-gated security checks. For user-mode callers the trap frame is automatic.

**Intel CET Shadow Stack — explicit disambiguation**: Intel Control-flow Enforcement Technology (CET), available on Tiger Lake (2020+) and later Intel CPUs and on AMD Zen 3+ (2022+), provides a *hardware shadow stack*: a per-thread, hardware-protected parallel stack that stores only return addresses. On every `call`, the CPU pushes the return address to both the regular stack and the shadow stack; on every `ret`, the CPU compares the regular stack's popped value to the shadow stack's top and raises `#CP` (Control Protection exception) on mismatch. This is unrelated to the x64 ABI's parameter home area, despite the lexical overlap ("shadow space" vs. "shadow stack"). The ABI shadow space is software convention, no hardware enforcement, 32 bytes, lives at RSP+0..RSP+0x1F, holds spilled arguments. The CET shadow stack is hardware-enforced, ~8 bytes per return address, lives in a separate memory region pointed to by `IA32_PL0_SSP`/`IA32_PL3_SSP` MSRs. Tools and operators must not conflate them.

## Byte-Level Layout

Canonical ntdll syscall stub (e.g. `ntdll!NtAllocateVirtualMemory` on Windows 10 21H2, with SSN `0x18` chosen for illustration; SSNs vary by build):

```
+0x00:  4C 8B D1                  mov  r10, rcx                  ; (3 bytes)
+0x03:  B8 18 00 00 00            mov  eax, 18h                  ; (5 bytes) SSN = 0x18
+0x08:  F6 04 25 08 03 FE 7F 01  test byte ptr [7FFE0308h], 1   ; (8 bytes) KUSER_SHARED_DATA.SystemCall flag
+0x10:  75 03                     jne  short loc_+0x15           ; (2 bytes) branch to int 2Eh path
+0x12:  0F 05                     syscall                       ; (2 bytes)
+0x14:  C3                        ret                           ; (1 byte)
+0x15:  CD 2E                     int  2Eh                      ; (2 bytes) legacy interrupt-gate path
+0x17:  C3                        ret                           ; (1 byte)
; total stub size: 0x18 (24) bytes
```

Disassembly notes:
- `mov r10, rcx` (`4C 8B D1`): REX prefix `4C` = `0100 1 [W=1] [R=0] [B=0]` (W=1 for 64-bit operand, R selects r10 over rcx in the reg field). Opcode `8B` (`MOV r64, r/m64`), ModRM `D1` = `11 010 001` (mod=11 register-direct, reg=010 = R10 with REX.R=0, rm=001 = RCX). 3 bytes total.
- `mov eax, imm32` (`B8 + imm32`): opcode `B8` is `MOV eAX, imm32` (the accumulator short-form). The 4-byte immediate is little-endian, so `18 00 00 00` decodes to `0x00000018`. The `mov eax` encoding zero-extends into RAX (clears upper 32 bits); `mov rax, imm64` (REX.W + `B8 + imm64`, 10 bytes) would not.
- `test byte ptr [0x7FFE0308], 1` (`F6 04 25 08 03 FE 7F 01`): opcode `F6` is `TEST r/m8, imm8` with `/0` extension. ModRM `04` indicates SIB follows with no displacement. SIB `25` = `00 100 101` (scale=1, index=none, base=disp32-only). The 4-byte displacement `08 03 FE 7F` is little-endian for `0x7FFE0308`. The 1-byte immediate `01` is the mask. 8 bytes total.
- `jne short +3` (`75 03`): opcode `75` is `JNE rel8`, immediate `+3` means jump 3 bytes past the byte after `75 03` — i.e. to `+0x15`, which is the `int 2Eh` instruction. 2 bytes total.
- `syscall` (`0F 05`): 2 bytes, no operands.
- `ret` (`C3`): 1 byte, near return (pops 8 bytes from RSP into RIP on x64).
- `int 2Eh` (`CD 2E`): 2 bytes, software interrupt vector `0x2E` (the legacy system-service interrupt, still present on x64 for the `test`-flag fallback path).

Minimal direct-syscall stub (12 bytes, no `int 2Eh` fallback):

```
+0x00:  4C 8B D1            mov  r10, rcx
+0x03:  B8 <SSN> 00 00 00   mov  eax, <SSN>
+0x08:  0F 05               syscall
+0x0A:  C3                  ret
```

ROP-frame gadget sequence (Ekko-style, hypothetical chain invoking `NtSetInformationThread` for `PagePriority` info class):

```
[synthetic stack, bottom to top]
RSP+0x00: <return address of "pop rax; ret" gadget>      ; loads RAX = SSN
RSP+0x08: <SSN of NtSetInformationThread>                 ; 8-byte slot consumed by pop rax
RSP+0x10: <return address of "mov r10, rcx; ret" gadget>  ; copies RCX (thread handle) to R10
RSP+0x18: <return address of "pop rdx; ret" gadget>       ; loads RDX = &ThreadInformation
RSP+0x20: <pointer to ThreadInformation struct>           ; consumed by pop rdx
RSP+0x28: <return address of "pop r8; ret" gadget>       ; loads R8 = ThreadInformationLength
RSP+0x30: <ThreadInformationLength, e.g. 0x0A>             ; consumed by pop r8
RSP+0x38: <return address of "syscall; ret" gadget>       ; trigger syscall
RSP+0x40: <return address of continuation gadget>         ; e.g. NtContinue-style frame restore
; RCX, RDX, R8 loaded by preceding gadgets; R9 unused for this 4-arg syscall
; shadow space reservation: the synthetic stack at RSP+0..RSP+0x1F must be writable
; in case any gadget prologue spills — for pure pop/mov/syscall gadgets above, no spill occurs
```

## Variant Comparison Table

| Variant | Stub size | Shadow space touched by stub? | `int 2Eh` fallback? | Detection exposure |
|---|---|---|---|---|
| Canonical ntdll stub (Variant 1) | 24 bytes (`0x18`) | Sometimes (depends on Windows build; some versions add `mov [rsp+8], rcx` prologue for ETW logging) | Yes (dead code on modern CPUs) | ntdll-layer hooks fire; ETW-TI fires |
| Direct-syscall stub (Variant 2) | 12 bytes (minimal) | No (minimal stub) | No (assumes modern CPU) | ntdll hooks bypassed; ETW-TI fires; stub in non-module memory is detectable via VAD scan |
| ROP-frame syscall (Variant 3) | 0 bytes (chain reuses existing gadgets) | Optional (only if non-leaf gadgets present) | N/A | ntdll hooks bypassed; ETW-TI fires; ROP stack in `MEM_PRIVATE` RWX page is detectable via Moneta/PE-sieve |

## Key Implementation Details

**Stack alignment is non-negotiable.** The Microsoft x64 ABI requires RSP to be 16-byte aligned at the `call` site. The `call` instruction itself pushes 8 bytes (the return RIP), so inside the callee RSP is misaligned by 8 mod 16. Any function that uses aligned SSE instructions (`movaps`, `movdqa`, `movaps`) in its body will fault with `#GP` if RSP is misaligned when those instructions execute. This is why ntdll stubs and any well-formed direct-syscall stub work even without an explicit alignment prologue: they don't use SSE instructions. But the caller of an `Nt*` function, if that caller uses SSE in its own body, must ensure 16-byte alignment at the `call Nt*` site. ROP chains must additionally account for the fact that each `ret` in the chain pops 8 bytes — so a chain that starts at a 16-byte-aligned RSP and consumes one gadget per `ret` will alternate between 16-byte and 8-mod-16 alignment. Most leaf gadgets don't care; function-call-shaped gadgets do.

**Shadow space is caller-reserved, callee-optional.** The caller must reserve 32 bytes at RSP+0..RSP+0x1F. The callee may write to it (some Windows builds of ntdll stubs spill RCX/RDX/R8/R9 into the home area for ETW logging) or may not (the minimal stub above does not). The reservation is enforced by convention only; if a caller does not reserve shadow space, the syscall will typically still work — until either (a) a Windows build that does spill runs and corrupts the caller's frame, or (b) an EDR that inspects the home area post-call flags the anomalous layout. The conservative rule: always reserve, even for direct stubs.

**WOW64 boundary is a separate ABI.** A 32-bit process on a 64-bit Windows kernel goes through `wow64.dll!Nt*` thunks that translate `stdcall` (32-bit x86 ABI: args on stack, no registers) to x64 ABI via the WOW64 emulator (`wow64cpu.dll`'s `TurboDispatch` path, `Boristro` thunk). The 32-bit caller does not see RCX/RDX/R8/R9; the thunk performs the register load on its behalf. Operators targeting WOW64 should not hand-roll x64 stubs in the 32-bit process — they should either transition to a 64-bit process or use the WOW64 transition APIs (`NtWow64ReadVirtualMemory64`, etc.) for cross-bitness syscalls.

**`syscall` clobbers RCX and R11.** After `sysret` returns, RCX holds the return RIP (next instruction after `syscall` in the user stub) and R11 holds the return RFLAGS. Any caller that depends on values in RCX or R11 surviving the `call Nt*` must save them in registers other than RAX/RCX/R11 (RAX is also clobbered — it holds the NTSTATUS return). The Microsoft ABI marks RAX, RCX, RDX, R8, R9, R10, R11 as caller-saved (volatile); RBX, RBP, RDI, RSI, R12-R15 are callee-saved. For direct-syscall stubs and ROP frames, this means: do not stash a value in RCX across a `syscall` expecting it to survive.

**SSN must be in EAX, not RAX with stale high bits.** The `mov eax, imm32` encoding (opcode `B8` + 4 bytes) zero-extends into RAX. If a previous operation used `mov rax, imm64` (REX.W + `B8` + 8 bytes) to load a full 64-bit value into RAX, the upper 32 bits would persist. The kernel's `KiSystemService` reads only the lower 32 bits of RAX as the SSN, but some anti-emulation and instrumentation check the upper bits for anomaly detection. Always use `mov eax, <SSN>`, never `mov rax, <SSN>` (which would also fail if the SSN exceeds 32 bits — it never does, SSNs are 12-bit indices).

## Common Mistakes

1. **Forgetting `mov r10, rcx`.** The `syscall` instruction stores the return RIP in RCX, destroying whatever was there. If the stub does not move arg1 from RCX to R10 before `syscall`, the kernel sees garbage in the first argument. Some operators copying the ntdll stub omit the `mov r10, rcx` instruction thinking it is decorative — it is not. The kernel dispatch reads R10 as the first argument, not RCX.

2. **Reserving no shadow space "because the stub doesn't use it".** The minimal direct stub in Variant 2 does not spill, but reserving the 32 bytes is still required for 16-byte alignment across the `call`/`ret` boundary, for compatibility with future Windows builds that may add spill code, and for EDR-side shadow-space sanity checks that flag callers with no home area as anomalous.

3. **Wrong stack alignment.** The canonical prologue is `sub rsp, 0x28` (40 bytes = 32 shadow + 8 to realign). If a chain's RSP is misaligned when calling into a stub, subsequent aligned FP ops will fault with `#GP` (`EXCEPTION_ACCESS_VIOLATION` / `STATUS_ACCESS_VIOLATION` from the VEX-encoded SSE path). ROP chains that alternate `pop rax; ret` gadgets consume 16 bytes per gadget (return address + popped value), preserving alignment; chains with odd-sized gadgets drift.

4. **Using `mov rax, imm64` for the SSN.** Loads a 64-bit value into RAX, leaves the upper bits set to whatever the immediate specified. The kernel reads only the lower 32 bits, so the syscall succeeds, but anomaly-detection tools that inspect RAX after `syscall` return (e.g. to verify RAX holds a plausible NTSTATUS) can flag the odd high bits. Always use `mov eax, <SSN>`.

5. **Conflating ABI shadow space with Intel CET Shadow Stack.** They share a lexical element ("shadow") and nothing else. The ABI shadow space is a software convention, 32 bytes, lives in the regular stack at RSP+0..RSP+0x1F, holds spilled arguments. The CET shadow stack is hardware-enforced, holds return addresses only, lives in a separate per-thread memory region pointed to by `IA32_PL3_SSP` (user mode) / `IA32_PL0_SSP` (kernel mode) MSRs. Operators who treat them as the same mechanism misread both detection telemetry and mitigation behavior.

6. **Forgetting that stack-passed args sit at callee RSP+0x28, not RSP+0x20.** The `call` instruction's 8-byte return-address push shifts everything by 8 bytes. Arg5 — the first stack-passed argument — is at RSP+0x20 in the caller's pre-call frame but at RSP+0x28 in the callee's post-`call` frame. Operators hand-crafting syscall frames (especially ROP variants) routinely miscompute this offset and pass arg5 one slot too low, where it lands in the shadow space and gets clobbered if the stub spills.

7. **Reusing a hooked ntdll stub as a `syscall; ret` gadget source.** T-095 documents unhooking ntdll; until that is done, `ntdll!Nt*` stubs may have been replaced by an EDR with a `jmp <emulation>` trampoline at the function prologue. The byte sequence `0F 05 C3` may still be present at `stub_base+0x12` (the original `syscall; ret` is preserved), but the surrounding bytes — and the path actually taken when the stub is invoked as a function — may have been altered. ROP gadgets extracted from hooked stubs work (they're just byte sequences); function-call invocation of hooked stubs does not.

## Why It Matters

This card is the prerequisite that makes the entire syscalls category legible. Without it, every direct-syscall implementation becomes a confusing exercise in "where does R10 come from and why?", every SSN harvester becomes "why parse the byte at stub+4 and not stub+0?", and every ROP-frame syscall invocation becomes "why does the synthetic stack have a 32-byte gap before the gadget chain?". The answers are all here: R10 is the syscall-ABI surrogate for RCX; the SSN is at stub+3+1=stub+4 because the `mov eax, imm32` instruction's immediate begins at offset +4 of the stub (after `mov r10, rcx` consumes +0..+2 and `mov eax`'s opcode `B8` consumes +3); the 32-byte gap is the parameter home area that any gadget with a spill prologue expects to find at RSP+0..RSP+0x1F.

For ROP-frame syscall invocation (Ekko T-005, Foliage, Nighthawk variants, the broader sleep-obfuscation family), the ABI is the spine of the chain layout. Ekko's `NtSetContextThread`/`NtWaitForSingleObject`/`NtSetInformationThread` chain places each syscall's arguments in registers via preceding gadgets, with shadow space reserved within the synthetic stack region. The same ABI underpins Halo's Gate (T-003 variant) SSN harvesters, which parse the byte at ntdll stub offset +4 (`B8 <SSN> 00 00 00`) to extract the service number without ever invoking the stub — the byte pattern is itself the ABI fingerprint.

This card also clarifies a frequent misconception: direct syscalls bypass ntdll-layer user-mode hooks, but they do **not** bypass ETW Threat Intelligence. EtwTi events are raised inside the kernel syscall body (e.g. `EtwThreatIntProvOpcodeAllocateVirtualMemory` inside `NtAllocateVirtualMemory`), so they fire regardless of how the syscall was invoked — ntdll stub, direct stub, or ROP gadget. The only way to bypass EtwTi is kernel-mode instrumentation removal (patching `EtwpEventLogger` or unregistering the EtwTi GUID `F4E1557E-9256-4C5B-9CD0-915A4D5C0FF9` from `EtwGuidEnableInfo`), which is out of scope for a user-mode technique.

## Detection Considerations

- **Telemetry sources**: `EtwThreatIntLogger` (provider GUID `F4E1557E-9256-4C5B-9CD0-915A4D5C0FF9`) raises kernel-side events for a defined set of sensitive syscalls — `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` (with `PAGE_EXECUTE_*` target protections), `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtSetContextThread`, `NtQueueApcThread`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtOpenProcess` (with `PROCESS_VM_*` access masks). These fire on every invocation regardless of whether the caller used an ntdll stub, a direct stub, or a ROP gadget — the event is raised inside the kernel body. The user-mode return address captured in the event reflects whatever was in RSP+0 at the `call` site, so direct syscalls yield a non-ntdll return address (detectable as anomaly). `Microsoft-Windows-Kernel-Process` event ID 1 captures thread start (including `StartAddress` for threads created via `NtCreateThreadEx`); a StartAddress in `MEM_PRIVATE` `PAGE_EXECUTE_READWRITE` memory is a strong signal. `Microsoft-Windows-Kernel-AuditAPI` covers a smaller set of explicitly audited syscalls.

- **Bypass options**: User-mode ntdll stub hooks are entirely bypassed by direct syscalls and ROP-frame invocation — these techniques never execute `ntdll!Nt*` code. Kernel-raised ETW-TI cannot be bypassed from user mode; full bypass requires kernel-mode access (an exploit primitive or a signed driver) to patch `EtwpEventLogger` or to unregister the EtwTi provider from `EtwGuidEnableInfo`. EDRs that read the parameter home area at RSP+0..RSP+0x1F after an `Nt*` call to verify the caller laid out shadow space can be evaded by reserving the 32 bytes (per Variant 2 step 3) and optionally initializing them with plausible spilled-argument values. Stack-based return-address inspection (looking for return addresses outside loaded modules) is evaded by indirect syscall techniques (T-001) that spoof the return address to an ntdll stub.

- **Residual artifacts**: Direct-syscall stubs leave a 12-24 byte executable pattern (`4C 8B D1 B8 ?? 00 00 00 0F 05 C3`) in non-module memory — detectable by scanning `MEM_PRIVATE` `PAGE_EXECUTE_READWRITE` regions for the signature (PE-sieve, Moneta, Hunt-Peaking). ROP-frame invocation leaves the synthetic ROP stack in a VirtualAlloc'd page — detectable as `MEM_PRIVATE` `PAGE_EXECUTE_READWRITE` or `PAGE_READWRITE` with anomalous gadget-return-address sequences (return addresses pointing into multiple distinct modules, or all into one module at non-export offsets). The kernel-side `KTRAP_FRAME` for direct-syscall-invoked calls still records `PreviousMode = UserMode` and the original user RSP — kernel-mode memory forensics can recover the synthetic stack. No on-disk artifacts are left by direct syscalls or ROP frames (the stub and chain live in process memory only); persistence requires a separate technique.

## Composition with Other Techniques

A representative kill chain using this card:

1. **Initial bypass of EDR user-mode hooks (T-002)**: Operator loads a direct-syscall stub into RWX memory (the 12-byte minimal stub from Variant 2). All subsequent sensitive syscalls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) route through this stub. The EDR's `ntdll!Nt*` inline hooks never fire. ETW-TI does fire (kernel-side), but the operator accepts this — the events are noisy and many EDRs under-prioritize them.

2. **SSN harvest (T-003, Hells Gate family)**: Operator parses `ntdll.dll` in-memory (`PEB.Ldr.InLoadOrderModuleList` walk to find `ntdll`'s base, then walk the export directory `DataDirectory[0]` for `Nt*` exports). For each `Nt*` function, the operator reads byte at stub offset +4 (`B8 ?? ?? ?? ??`), which is the `mov eax, imm32` immediate — the SSN. If the byte at offset +0..+2 is not `4C 8B D1` (the `mov r10, rcx` prologue) — i.e. the stub has been hooked by an EDR with a `jmp <emulation>` trampoline — the operator walks neighboring stubs and uses SSN+offset heuristics (Halo's Gate variant). The SSNs are then baked into the direct-syscall stub from step 1.

3. **Sleep obfuscation via ROP-frame syscall (T-005 Ekko)**: Operator allocates a synthetic stack page (`PAGE_READWRITE`, then `VirtualProtect` to `PAGE_EXECUTE_READWRITE = 0x40` after ROP chain construction). The page contains the ROP frame from Variant 3 of this card — `pop rax; ret`/`mov r10, rcx; ret`/`pop rdx; ret`/`pop r8; ret`/`syscall; ret`/continuation gadgets, with 32 bytes of shadow space allocated at the offsets any non-leaf gadget expects. The chain invokes `NtSetInformationThread(ThreadPagePriority)` to lower the working set, `NtWaitForSingleObject` on an event handle (set by a timer APC), and `NtSetContextThread` to restore the original thread context. The page is delivered via `CreateTimerQueueTimer` so the chain executes from a benign-looking origin (the timer callback) rather than the operator's main thread. Result: the operator's main thread is suspended (evading memory scanners that look at active threads), and the ROP-driven syscalls are invoked without ever touching ntdll stubs.

4. **Detection of the chain**: EDRs that scan `MEM_PRIVATE` `PAGE_EXECUTE_READWRITE` regions (Moneta, PE-sieve) flag the synthetic ROP stack page. The `0F 05 C3` byte sequence in non-module memory is a strong signal. ETW-TI fires for `NtSetInformationThread` and `NtSetContextThread` (if the EDR subscribes). The chain's return addresses, captured by ETW-TI, point into multiple modules' gadget-rich regions — a non-ntdll return address on a syscall is the canonical signature of direct/indirect syscall use.

## Related Techniques

- **T-001** — Indirect syscalls compose with this card: T-001's stubs spoof their return address to an ntdll address to defeat stack-based return-address inspection, but the stub itself still obeys the ABI documented here.
- **T-002 Direct Syscalls** — Variant 2 of this card is the canonical 12-byte stub format that T-002 deployments use; the SSN substitution (`mov eax, <SSN>`) and R10 substitution (`mov r10, rcx`) are both specified here.
- **T-003** — SSN harvesters of the Hells Gate family parse the `mov eax, imm32` byte at ntdll stub offset +4; the byte pattern is documented in Variant 1 of this card. Halo's Gate and Tartarus' Gate variants extend the parser for hooked stubs.
- **T-005 Ekko Sleep Obfuscation** — Variant 3 of this card (ROP-frame syscall invocation) is the engine behind Ekko's timer-driven `NtSetContextThread`/`NtWaitForSingleObject`/`NtSetInformationThread` chain. Ekko's synthetic stack layout is the shadow-space-respecting ROP frame documented here.
- **T-006** — Composes with this card wherever T-006 invokes syscalls from synthetic stacks or non-ntdll origins; the ABI contract applies identically.
- **T-016** — Same; this card specifies the calling convention any T-016 syscall path must satisfy.
- **T-095 NTDLL Unhook typology** — Documents the PE-side mechanics of ntdll stub patching (refreshing ntdll from disk, restoring clean stub bytes). This card documents the ABI contract that those clean stubs must satisfy — and that hooked stubs, despite their trampolines, still satisfy at the byte level (the `0F 05 C3` sequence at stub+0x12 is usually preserved even when the prologue is hooked).