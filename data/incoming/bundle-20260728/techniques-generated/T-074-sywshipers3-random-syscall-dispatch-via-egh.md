---
id: T-074
name: 'Sywshipers3: Random Syscall Dispatch via EGH'
category: syscalls
tier: B
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1027]
tags: [syscalls, ssn, randomization, syswhispers, egg-hunter, indirect-syscall, wow64, edr-evasion]
origin: atlas-synthesis
member_notes: [lgtm:sywshipers3-random-syscall-dispatch]
---

# Sywshipers3: Random Syscall Dispatch via EGH — Randomized Dispatch Sites Against Static Signatures

## Summary

Sywshipers3, as named in the SEC670 training material (the publicly known SysWhispers3 generator), is a build-time syscall-stub generator whose dispatch philosophy is randomization rather than deterministic resolution. Its generated stubs use egg-hunter (EGH) style markers whose values are patched at generation time to the addresses of randomly selected `syscall; ret` gadgets inside ntdll, and it supports both x64 and WoW64 execution paths. Where HUGIN's syscall cards assume determinism — resolving the true SSN or routing through the matching function's gadget — this approach randomizes the dispatch site and stub byte shape per build so that static signatures on known stub sequences and call-site-to-syscall correlation fail. The primary detection surface is kernel-visible syscall-origin telemetry and consistency checks that compare the syscall's instruction pointer against the function its SSN implies.

## Mechanism

1. At build time, the generator emits per-function assembly stubs for the requested NT APIs, seeded with a per-build random value so that no two generations produce identical bytes.
2. Each stub embeds an egg: a placeholder constant marking the location where the address of a `syscall` instruction will be written. At generation time the egg is replaced with the address of a `syscall; ret` gadget belonging to a chosen ntdll export.
3. The jumper is randomized: rather than dispatching through the gadget of the function actually being invoked, the stub for one NT API may execute its `syscall` instruction from inside the body of an unrelated ntdll function. The training material describes this as direct syscall jumps to random syscall numbers, intended to defeat static pattern matching on syscall sequences.
4. The SSN loaded into eax remains the correct one for the intended function — randomizing eax itself would invoke the wrong syscall. The randomization covers the dispatch site and the stub shape, not the syscall identity.
5. For WoW64 callers, the generated code transitions from 32-bit to 64-bit execution via a far jump to code segment 0x33 (the Heaven's Gate transition documented in T-049), runs the same randomized stub in 64-bit mode, and returns to segment 0x23, allowing x86 payloads to issue native x64 syscalls without traversing the WoW64 sysenter layer.
6. At runtime the implant calls the stub as a normal function: arguments follow the Windows x64 ABI (RCX, RDX, R8, R9, stack spill for the remainder), the stub loads eax with the SSN, and control jumps through the egg-resolved gadget into the kernel.

## OS Internals Context

ntdll's .text section contains one `0F 05 C3` (syscall; ret) sequence per exported Zw*/Nt* stub — several hundred functionally identical gadgets on Windows 10/11, because the kernel dispatches purely on the value in eax. Any gadget can carry any SSN; pairing a gadget with its containing function is a convention the operating system never enforces. That convention is exactly what user-mode EDR hooks and naive origin attribution assume, and it is the assumption randomized dispatch violates deliberately.

Two defensive telemetry layers remain relevant. ETW Threat Intelligence (Microsoft-Windows-Threat-Intelligence) records syscall origin addresses and stack walks from kernel mode; a randomized jumper changes which ntdll function appears at the origin but preserves ntdll attribution overall — unlike direct syscalls (origin in the implant's own memory) or T-006 Phantom Stubs (origin in a forged MEM_IMAGE module). Second, an origin-consistency check — reading eax at syscall entry, mapping the instruction pointer to its containing export, and comparing the two — flags the mismatch this technique creates: NtAllocateVirtualMemory's SSN executing from inside NtCreateFile's body is anomalous under that model. The training material positions the randomization against static signature matching; against origin-consistency heuristics the technique trades one observable for another, which is why the deterministic matching-gadget discipline of T-001 RecycledGate exists as the alternative pole.

The WoW64 path matters for x86 payloads: 32-bit processes on 64-bit Windows normally reach the kernel through wow64cpu's TurboThunk dispatch, a layer defenders can instrument. A far jump to segment 0x33 bypasses that layer entirely and executes the native syscall instruction directly. Build-time seeding is the supply-side property: because stub bytes and gadget targets differ per generation, YARA rules written against published generator output fail against rebuilt implants — the evasion operates on the binary before it ever runs.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

HUGIN's existing dispatch modes are all deterministic: RecycledGate (`src/dark_crystal/crates/core/src/sys_recycled.rs`, `sys_indirect.rs`) routes each call through the matching function's own gadget, the T-002 cascade (`sys_resolve.rs`, `src/dark_crystal/crowd/src/hells_gate.rs`) resolves true SSNs via Zw* RVA sorting, and the T-003 VEH gate dispatches through hardware breakpoints with no stub in the call path. A randomized-jumper mode would reuse the T-002 enumeration substrate directly: the RVA-sorted Zw* table already yields the address of every `syscall; ret` gadget in ntdll, so the implementation would select a per-build or per-call random entry other than the matched one as the jump target while keeping eax as the resolved SSN, exposed as a fourth dispatch mode alongside RecycledGate, VEH, and Direct. WoW64 support would additionally require the 0x33 far-jump transition stubs.

## Why It Matters

This card documents a dispatch philosophy the vault's syscall coverage does not otherwise represent: randomization of the dispatch site as the primary evasion axis, accepted at the cost of IP/SSN inconsistency. It is also the documented WoW64-aware counterpart for x86 payloads, a population HUGIN's x64-focused gates do not serve. Recording the tradeoff explicitly — static-signature resistance versus origin-consistency exposure — lets an operator select the dispatch mode that matches the target EDR's telemetry model rather than defaulting to determinism.

## Detection Considerations

- **Telemetry sources**: ETW Threat Intelligence syscall-origin and stack-walk records; EDR kernel sensors that map syscall instruction pointers to containing ntdll exports; static AV and YARA signatures on known generator stub shapes (defeated by per-build seeds).
- **Bypass options**: when origin-consistency heuristics are in play, restrict the gadget pool to the same function's gadget — which collapses the technique into T-001 RecycledGate; combine with NTDLL unhooking (T-016) so the gadget pool itself is free of inline patches; per-build reseeding to defeat published byte signatures.
- **Residual artifacts**: none on disk at runtime — stubs live in the implant's .text. Build pipelines retain generated header and assembly files whose format is itself an indicator for known generator output.

## Related Techniques

- **T-001 RecycledGate** — the deterministic inverse: indirect dispatch through the matching function's gadget, preserving IP/SSN consistency instead of randomizing it.
- **T-002 Hell's/Halo's/Tartarus Gate + FreshyCalls** — shares the ntdll Zw* enumeration substrate that a random-gadget selector would draw its pool from.
- **T-003 VEH Syscall Gate** — an alternate dispatch mechanism with no stub bytes in the call path at all.
- **T-006 Phantom Stubs** — attacks syscall-origin attribution from a different angle by backing stubs with forged MEM_IMAGE modules.

## References

- Atlas material: atlas-edr-evasion-part3.md
- MITRE ATT&CK: [T1106 — Native API](https://attack.mitre.org/techniques/T1106/)
- LGTM notes: lgtm:sywshipers3-random-syscall-dispatch
- Public references: SysWhispers3 (klezVirus) — the publicly known tool matching the training material's description of Sywshipers3

## Source Reference

No current implementation. Deterministic counterparts in HUGIN: `src/dark_crystal/crates/core/src/sys_recycled.rs` (RecycledGate matching-gadget dispatch), `src/dark_crystal/crates/core/src/sys_resolve.rs` and `src/dark_crystal/crowd/src/hells_gate.rs` (SSN resolution cascade providing the Zw* gadget enumeration substrate a randomized mode would reuse).