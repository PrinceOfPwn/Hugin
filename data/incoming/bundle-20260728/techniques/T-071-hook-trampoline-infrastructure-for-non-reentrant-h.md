---
id: T-071
name: Hook Trampoline Infrastructure for Non-Reentrant Hooks
category: process-injection
tier: B
crate: none
source_file: none
mitre: T1055
mitre_secondary: [T1562.001]
tags: [trampoline, inline-hook, prologue-relocation, length-disassembler, hooking, unhooking, rip-relative, unwind-info]
origin: atlas-synthesis
member_notes: [lgtm:proposed-trampoline-infrastructure]
---

# Hook Trampoline Infrastructure for Non-Reentrant Hooks — Displaced-Prologue Preservation and Jump-Back

## Summary

A trampoline is a small executable stub that preserves the original prologue bytes displaced by an inline hook and returns control to the original function past the patch, making the hook non-reentrant. SEC670 presents trampolines as the infrastructure layer separating hook placement from original-function invocation: without the stub, a hook handler cannot call the function it replaced without recursing into itself. The construction problem is nontrivial because x86-64 instructions are variable-length and position-dependent instructions inside the copied prologue must be relocated. The same primitive serves offensive hooking (an implant intercepting APIs for its own purposes) and defensive-evasion unhooking (restoring bytes an EDR patched), which is why it warrants a standalone card rather than repeated treatment inside each consumer. Primary detection surface: memory scanners comparing in-memory `.text` against the on-disk image, and private executable pages that scanners attribute to trampoline storage.

## Mechanism

1. Read and save the original bytes at the target function entry; this copy serves both the trampoline and the eventual unhook/restore path.
2. Run a length-disassembler engine (hde64, Zydis, iced-x86 class) over the prologue to find the smallest instruction-aligned length greater than or equal to the patch size — 5 bytes for a near `E9 rel32` jump, 14 bytes for an absolute `FF 25 [rip+0]` indirect jump. Copying a partial instruction produces a corrupted stub that crashes on first call.
3. Allocate an executable trampoline buffer, ideally within ±2 GB of the target so 32-bit displacements remain usable; `NtAllocateVirtualMemory` accepts a base-address hint for this purpose.
4. Copy the whole instructions into the buffer, then relocate position-dependent ones:
   - RIP-relative memory operands (`mov rax, [rip+disp32]`): recompute `disp32 = OriginalTarget - (TrampolineBase + EndOfInstruction)`.
   - `E8`/`E9` rel32 call/jump: rewrite through an absolute indirect form with an embedded 64-bit pointer, or recompute the displacement if the destination remains in range.
   - Short jumps (`EB`, `70`–`7F`) and `loop`/`jrcxz`: promote to near conditional jumps (`0F 8x`) or absolute sequences, since rel8 cannot reach from the new location.
5. Append the jump-back: `E9 rel32` to `TargetFunction + DisplacedLength`, or the 14-byte absolute form if out of range.
6. Patch the target: change the containing page(s) to writable (`NtProtectVirtualMemory` → `PAGE_EXECUTE_READWRITE`), write the 5- or 14-byte redirect, restore protection, and call `FlushInstructionCache` so stale decoded lines are not executed.
7. The hook handler invokes the trampoline whenever it needs original semantics; control flows through the relocated prologue, jumps back past the patch, and the hook never re-enters itself.
8. Hotpatch variant: system DLLs compiled with `/hotpatch` begin with a 2-byte `mov edi, edi` (`8B FF`) preceded by five `0xCC` bytes. Overwrite the two bytes with `EB F9` (short jump back 5) and place the 5-byte far jump in the padding at `Function - 5`; only padding bytes are displaced, shrinking the trampoline to the 2-byte prologue plus jump-back.
9. Unhooking inverts step 6: write the saved original bytes back, restore protection, flush, and free the trampoline.

## OS Internals Context

The x86-64 ISA permits instructions of 1–15 bytes with legacy prefixes, REX, ModRM/SIB, and displacement fields; the length-disassembler pass is mandatory because instruction boundaries are not derivable from byte count. RIP-relative addressing is the default for x64 data references, which is why relocation is the common case rather than the exception — nearly every real prologue touching globals or IAT slots contains at least one RIP-relative operand.

Two failure modes receive little coverage elsewhere. First, unwind: the original prologue's addresses are covered by the module's `.pdata` `RUNTIME_FUNCTION` entries, but the relocated copy executes in private memory with no unwind registration. If an exception fires while a thread executes inside the trampoline, `RtlDispatchException` cannot build an unwind context for that RIP and the process terminates. Dynamically generated code is expected to call `RtlAddFunctionTable` or `RtlInstallFunctionTableCallback`; a correct trampoline implementation registers unwind metadata for its region. Second, concurrency: a multi-byte patch is not atomic, and a thread already executing the prologue mid-write observes torn bytes. Mitigations include suspending other threads during the write, staging with a single-byte `0xCC` plus a vectored handler, or using the 2-byte hotpatch short jump as an intermediate atomic step. Control-flow enforcement adds a further wrinkle on CET/IBT-enabled processes: jumping back into `Target+N` lands past the function's `ENDBR64`, which is legal for the jump-back path only because indirect-branch tracking applies to indirect branches taken through tracked call sites — implementations must verify the target process's CET policy before relying on this.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

Verification note: `dark_crystal/crates/core/src/experimental/evasion/veh/hooks.rs` defines a function named `syscall_trampoline`, but it is an empty `extern "C"` body used purely as a RIP-redirection landing pad so the VEH gate's single-step trace through ntdll maintains a benign call stack (T-003). It performs no prologue relocation and does not implement this card's mechanism. An actual implementation would be a standalone module exposing `hook_install(target, detour) -> trampoline` / `hook_remove(target)`: an iced-x86-based decoder pass for boundary detection and relocation, near-range allocation, unwind registration via `RtlAddFunctionTable`, and a restore path — consumed by the IAT camouflage, argument spoofing, and ntdll unhook logic currently catalogued under T-016 and T-020.

## Why It Matters

Trampoline construction is the shared, correctness-critical core beneath several techniques the vault already documents separately — inline hooking (T-030), ntdll restoration and the implant's own interception needs (T-016), and prologue-stepping evasions such as the KiUserExceptionDispatcher StepOver. Elevating it to its own card captures the relocation, unwind, and concurrency requirements once, at the depth they require, instead of as compressed asides. It is also the boundary between a functioning hook and an intermittent target crash: every consumer inherits whatever mistakes the trampoline layer makes.

## Detection Considerations

- **Telemetry sources**: EDR in-memory integrity checks diffing `.text` of loaded images against disk; scans for private pages with execute permissions (RWX or RX MEM_PRIVATE) hosting trampoline code; ETW Threat-Intelligence events for `NtProtectVirtualMemory`/`NtWriteVirtualMemory` against image memory; Sysmon Event ID 10 when patching is cross-process.
- **Bypass options**: hotpatch-preamble patching to minimize the byte diff; restore-original-after-use so the hook exists only for milliseconds; backing trampoline storage with MEM_IMAGE mappings in the style of T-006 rather than anonymous private memory; registering unwind metadata so scanner-triggered exceptions do not produce crash dumps pointing at the stub.
- **Residual artifacts**: modified page hashes while the hook is live, abandoned executable allocations after unhook, function-table registrations visible via `RtlEnumerateFunctionTableEntries`-style queries, and timing skew on the hooked API.

## Related Techniques

- **T-016 EDR Evasion Suite** — unhooking, argument spoofing, and KiUserException StepOver all consume or interact with trampoline infrastructure.
- **T-013 Remaining Injection Methods** — function-stomping and callback variants that overwrite code and require the same displaced-bytes preservation.
- **T-030 Inline Hook Implementation** — the hook-placement companion; the trampoline is its required counterpart for non-reentrancy.

## References

- Atlas material: atlas-edr-evasion-part5.md
- MITRE ATT&CK: T1055 — Process Injection (https://attack.mitre.org/techniques/T1055/); T1562.001 — Impair Defenses: Disable or Modify Tools (https://attack.mitre.org/techniques/T1562/001/)
- LGTM notes: lgtm:proposed-trampoline-infrastructure

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.