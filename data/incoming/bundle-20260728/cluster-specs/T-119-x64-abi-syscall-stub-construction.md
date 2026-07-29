# Cluster Spec — T-119: x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs

- **T-NNN ID**: `T-119`
- **Canonical name**: x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs
- **Proposed category**: `syscalls`
- **Proposed tier**: `B`
- **Priority**: high — Three convergence notes; the prerequisite that makes syscall stubs and ROP frames legible across the syscalls category.
- **would_relate_to**: ['T-001', 'T-002', 'T-003', 'T-005', 'T-006', 'T-016']

## Consolidated Description

Reference card documenting the x64 ABI as it constrains syscall stubs and ROP frames. Arguments flow in RCX, RDX, R8, R9, then stack; the caller must reserve a 32-byte shadow store at RSP+0..RSP+20h (eight 8-byte slots) for the callee to spill those four register arguments into. Syscall stubs must respect this even when they merely load the SSN into EAX and execute `syscall` — Ekko (T-005) and direct-syscall stubs from T-002 both rely on the shadow store being writable. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back the spilled arguments. Note this is distinct from the hardware Shadow Stack (Intel CET) enforcement.


## Member LGTM Notes (3)

### Note 1: x64 Calling Convention as Syscall Stub Design Constraint
- id: `lgtm:x64-calling-convention-stub-constraint`
- origin: atlas-binary-analysis-part6
- would_relate_to: ['T-001', 'T-002', 'T-003', 'T-006', 'T-016']
- tags: ['x64', 'calling-convention', 'syscall-stub', 'abi', 'cross-source-convergence']

**Kind:** cross-source-convergence
**Origin:** atlas-binary-analysis-part6
**Would relate to:** T-001, T-002, T-003, T-006, T-016
**Source units:** unit 8, unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15

SEC670 documents the x64 calling convention (RCX/RDX/R8/R9 + stack) in foundational form. MalDev Academy and CRTO both reference the same convention when explaining why direct syscall stubs must preserve the caller's register layout and why argument spoofing (T-016) must respect shadow-space placement. The vault's T-001 RecycledGate, T-003 VEH Gate, and T-006 Phantom Stubs all implicitly depend on this. Surfacing it as an explicit concept node would let readers cross-navigate from any stub implementation back to the ABI constraint.

### Note 2: x64 ABI and Shadow Space for Syscall Stub Construction
- id: `lgtm:x64-abi-syscall-stub-construction`
- origin: atlas-binary-analysis-part7
- would_relate_to: ['T-001', 'T-002', 'T-003']
- tags: ['x64-abi', 'shadow-space', 'fastcall', 'syscall-stub', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part7
**Would relate to:** T-001, T-002, T-003
**Source units:** unit 28, unit 29, unit 30, unit 31, unit 32, unit 33

The SANS material covers x64 calling conventions (fastcall register assignment, the 32-byte shadow store at RSP+20h) that directly govern how syscall stubs must be constructed. The vault's T-001 (RecycledGate), T-002 (Hell's Gate), and T-003 (VEH Gate) all construct inline assembly stubs that must honor the shadow space convention. The material's explanation of why stack arguments start at RSP+20h (the callee's shadow store, not shadow stack enforcement) clarifies a subtle point about stub layout that source code alone does not convey.

### Note 3: x64 Shadow Store as Foundation for ROP Frame Construction
- id: `lgtm:cross-source-convergence-shadow-store-and-rop`
- origin: atlas-binary-analysis-part9
- would_relate_to: ['T-001', 'T-002', 'T-005']
- tags: ['x64', 'calling-convention', 'shadow-store', 'rop', 'cross-source']

**Kind:** cross-source-convergence
**Origin:** atlas-binary-analysis-part9
**Would relate to:** T-001, T-002, T-005
**Source units:** unit 4, unit 5

SEC670 documents the x64 calling convention's 32-byte shadow store at RSP+0..RSP+20h, distinguishing it from Hardware Shadow Stack enforcement. This same reservation is the structural reason Ekko (T-005) ROP chains can construct valid caller frames for RtlCaptureContext, SetWaitableTimerEx, and WaitForSingleObjectEx, and is the reason Hell's Gate stubs leave the shadow store intact when invoking syscall stubs. The convergence between calling-convention fundamentals and the vault's ROP/sleep-obfuscation techniques is implicit in the source code but never surfaced as a shared concept. Documenting the shadow store as a concept node connected to both T-001 and T-005 would close that gap.

---
Use `id: T-119`, canonical name above, and `member_notes: ['lgtm:x64-calling-convention-stub-constraint', 'lgtm:x64-abi-syscall-stub-construction', 'lgtm:cross-source-convergence-shadow-store-and-rop']`.
Cross-reference `would_relate_to`: ['T-001', 'T-002', 'T-003', 'T-005', 'T-006', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.