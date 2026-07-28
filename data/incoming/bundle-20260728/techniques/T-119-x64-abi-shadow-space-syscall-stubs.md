---
id: T-119
name: x64 ABI Shadow Space Syscall Stubs
category: syscalls
tier: B
crate: none
source_file: none
mitre: T1106
tags: [x64-abi, calling-convention, shadow-space, fastcall, syscall-stubs, rop-frames, argument-spilling]
origin: atlas-synthesis
member_notes: [lgtm:x64-calling-convention-stub-constraint, lgtm:x64-abi-syscall-stub-construction, lgtm:cross-source-convergence-shadow-store-and-rop]
---

# x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs — Register and Stack Layout Constraints

## Summary

The x64 Application Binary Interface (ABI) on Windows constrains how syscall stubs and Return-Oriented Programming (ROP) frames must be constructed. Integer arguments flow in RCX, RDX, R8, R9 in order, with remaining arguments on the stack. The caller must reserve a 32-byte shadow store at RSP+0 through RSP+0x1F for the callee to spill the first four register arguments into. Syscall stubs that load a System Service Number (SSN) into EAX and execute the `syscall` instruction must honor this convention even when they do not explicitly use the shadow store — the kernel's syscall dispatcher and any intervening hook functions expect the layout. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back spilled arguments. The shadow store is distinct from the Intel CET Hardware Shadow Stack, which is a separate security feature enforcing return address integrity.

## Mechanism

1. The x64 calling convention (Microsoft x64 ABI) assigns the first four integer arguments to RCX, RDX, R8, R9 in left-to-right order. Floating-point arguments use XMM0 through XMM3. Arguments beyond the fourth are placed on the stack at RSP+0x28, RSP+0x30, RSP+0x38, etc. (relative to the caller's RSP before the CALL instruction).

2. Before executing a CALL instruction, the caller must allocate a 32-byte (0x20) region on the stack at RSP+0 through RSP+0x1F. This shadow store exists so the callee can spill RCX, RDX, R8, R9 into memory if it needs to use those registers for other purposes. The callee is not required to spill — the space is reserved whether or not it is used.

3. After the CALL instruction pushes the 8-byte return address, the callee's RSP points to the return address at RSP+0x0, and the caller's shadow store spans RSP+0x8 through RSP+0x27 (from the callee's perspective). Stack arguments begin at RSP+0x28.

4. Syscall stubs in ntdll.dll follow a consistent pattern: `mov r10, rcx` (copy the first argument to R10 because the `syscall` instruction clobbers RCX), `mov eax, <SSN>` (load the system service number), `syscall` (transition to kernel), `ret` (return to caller). The `mov r10, rcx` instruction exists because the kernel's syscall entry (`KiSystemCall64`) reads the first argument from R10, not RCX — this is an ABI convention specific to the syscall interface.

5. An indirect syscall stub (T-001 RecycledGate) must replicate this pattern: load the SSN into EAX, move RCX to R10, and execute `syscall` — but from a non-ntdll address (a gadget in a legitimate module). The stub must not corrupt the shadow store because the caller (the operator's code) expects to find its spilled arguments intact after the stub returns.

6. ROP frame construction for sleep obfuscation (T-005 Ekko) builds virtual call frames for `RtlCaptureContext`, `SetWaitableTimerEx`, and `WaitForSingleObjectEx`. Each frame must include the 32-byte shadow store in the correct position relative to the simulated return address, because the target function's prologue may spill RCX/RDX/R8/R9 into it. If the shadow store is not allocated or is positioned incorrectly, the function overwrites adjacent stack data, corrupting the ROP chain.

7. Stack alignment: the x64 ABI requires RSP to be 16-byte aligned before a CALL instruction. Since CALL pushes an 8-byte return address, the callee's entry RSP is misaligned by 8 bytes (RSP mod 16 == 8). The callee's prologue typically includes a `SUB RSP,` instruction that realigns the stack to 16 bytes. ROP frames must account for this: the RSP value at the simulated call site must be 16-byte aligned, and the gadget's return address must be placed at the aligned RSP.

## OS Internals Context

The Microsoft x64 ABI is documented in the Windows SDK and the AMD64 Software Developer's Manual. The 32-byte shadow store is a design decision from the x64 ABI specification: it simplifies code generation by giving the callee a guaranteed scratch area for the first four arguments without requiring a stack frame allocation in leaf functions. The shadow store is distinct from the hardware Shadow Stack introduced with Intel Control-flow Enforcement Technology (CET). The hardware Shadow Stack is a separate hardware-managed stack that stores return addresses separately from the data stack, providing hardware-enforced return address integrity. The x64 ABI shadow store is a software convention for argument spilling — it has no hardware enforcement.

The `syscall` instruction (opcode 0F 05) transitions to the kernel's `KiSystemCall64` handler, which reads the SSN from EAX and the first argument from R10. The R10 register is used instead of RCX because the `SYSCALL` instruction does not push a return address (it stores it in RCX) and does not save the stack pointer (it stores it in R11). By moving the first argument to R10 before the `SYSCALL` instruction, the stub preserves the argument across the kernel transition. This is an x64-specific convention: on x86, the `SYSENTER` instruction uses different register conventions.

The CONTEXT structure (used by `RtlCaptureContext`, exception handling, and `GetThreadContext`) stores the full x64 register state, including RAX, RCX, RDX, R8, R9, RSP, RIP, and the XMM registers. When a VEH handler or exception handler modifies the CONTEXT to redirect execution (as in T-003 VEH Gate), the handler must set RIP, RSP, and any argument registers according to the x64 ABI. The shadow store in the CONTEXT's stack frame must be writable because the redirected function will spill its arguments there.

## Key Implementation Details

The provided source files do not implement syscall stub construction. The `amsi_page_guard.rs` file in `dark_crystal/crowd/src/` demonstrates shadow space awareness in its VEH handler implementation. The `return_address_from_ctx` helper reads the return address from `[RSP]` after an exception (`*(ctx.Rsp as *const u64)`), and the handler comment documents that "arg6 is at [RSP + 0x30] (shadow space + 5th slot)" — this correctly identifies that the 6th argument of `AmsiScanBuffer` sits at the callee's RSP+0x30, which accounts for the 8-byte return address at RSP+0x0, the 32-byte shadow store spanning RSP+0x8 through RSP+0x27, the 5th argument at RSP+0x28, and the 6th argument at RSP+0x30. The handler code uses `(ctx.Rsp as *const u64).add(6)` to access this offset, correctly applying the ABI layout.

The HUGIN source tree contains the actual syscall stub implementations in `dark_crystal/crowd/src/sys_recycled.rs` (RecycledGate inline assembly stubs), `dark_crystal/crates/core/src/sys_indirect.rs` (universal syscall dispatcher), and `dark_crystal/crowd/src/veh_gate.rs` (VEH syscall dispatch). These files construct inline assembly that must honor the x64 ABI's shadow store convention. An implementation honoring the ABI would: allocate 32 bytes of shadow space before each simulated CALL in the ROP frame (`SUB RSP, 0x20`), place arguments in RCX/RDX/R8/R9 for the first four and on the stack for the rest, ensure RSP is 16-byte aligned before the target address, and preserve R10 for the syscall argument convention.

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

## Why It Matters

The x64 ABI is the foundational constraint that governs every syscall stub and ROP frame in the vault. T-001 (RecycledGate), T-002 (Hell's Gate), T-003 (VEH Gate), T-005 (Ekko ROP Sleep), and T-006 (Phantom Stubs) all construct inline assembly or ROP chains that implicitly depend on the shadow store being correctly allocated. The SEC670 material explains why stack arguments start at RSP+0x28 (the callee's shadow store plus return address), why syscall stubs copy RCX to R10, and why Ekko's ROP frames must include 32 bytes of padding before each target function — knowledge that source code alone does not convey. Documenting the ABI as an explicit concept node lets operators cross-navigate from any stub implementation back to the underlying convention that makes it work. The convergence between calling-convention fundamentals and the vault's ROP/sleep-obfuscation techniques is implicit in the source code but never surfaced as a shared concept.

## Detection Considerations

Training material does not discuss detection for this technique. The x64 ABI is a specification, not an evasion technique. Memory scanners that analyze ROP frame layouts may flag anomalous stack frame constructions that deviate from ABI-compliant patterns — for example, missing shadow store allocation or incorrect stack alignment before function pointers.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall stubs must allocate and preserve the shadow store for the caller's argument spill.
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution reads syscall stub bytes that include the `mov r10, rcx` convention.
- **T-003 VEH Syscall Gate** — Exception handler CONTEXT modification must set argument registers and RSP according to the x64 ABI.
- **T-005 Ekko ROP Sleep** — ROP frame construction allocates 32-byte shadow stores for `RtlCaptureContext`, `SetWaitableTimerEx`, and `WaitForSingleObjectEx`.
- **T-006 Phantom Stubs** — MEM_IMAGE-backed syscall stubs must replicate the ntdll stub layout including shadow store preservation.
- **T-016 EDR Evasion Suite** — Argument spoofing must place spoofed arguments in the correct registers and stack positions per the x64 ABI.

## References

- Atlas material: atlas-binary-analysis-part6.md, atlas-binary-analysis-part7.md, atlas-binary-analysis-part9.md
- MITRE ATT&CK: T1106 (https://attack.mitre.org/techniques/T1106)
- LGTM notes: lgtm:x64-calling-convention-stub-constraint, lgtm:x64-abi-syscall-stub-construction, lgtm:cross-source-convergence-shadow-store-and-rop
- Public references: SEC670 binary analysis module, Microsoft x64 ABI documentation, AMD64 Software Developer's Manual

## Source Reference

No current implementation in the provided source files. The amsi_page_guard.rs file demonstrates shadow space awareness in its VEH handler (`return_address_from_ctx` function, arg6-at-[RSP+0x30] comment). Actual syscall stub implementations reside in dark_crystal/crowd/src/sys_recycled.rs and dark_crystal/crates/core/src/sys_indirect.rs (not provided in this batch for verification).