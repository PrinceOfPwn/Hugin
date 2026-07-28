---
id: T-049
name: 'Heaven''s Gate: 32-to-64-Bit Syscall Transition'
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1106
tags: [heavens-gate, wow64, cross-bitness, hook-evasion, segment-selector-0x33, wow64cpu, dual-ntdll, x86-to-x64]
origin: atlas-synthesis
member_notes: ['lgtm:heavens-gate-wow64-syscall-bridge', 'lgtm:heavens-gate-wow64-syscalls', 'lgtm:heavens-gate-wow64-bypass-as-standalone-technique']
---

# Heaven's Gate — 32-Bit WoW64 Processes Issuing Native 64-Bit Syscalls

## Summary

Heaven's Gate is the transition mechanism by which 32-bit (WoW64) processes on 64-bit Windows cross into 64-bit code and issue native 64-bit syscalls, entered through the `Wow64Transition` export of the 32-bit ntdll.dll and a far jump to code segment selector `0x33`. A 32-bit implant that drives this transition manually executes syscalls from the 64-bit ntdll.dll stubs rather than the 32-bit SysWOW64 stubs, so user-mode hooks placed in the 32-bit ntdll never observe them. The technique reuses the WoW64 subsystem's own architecture — the dual ntdll mapping inside every WoW64 process and the CPU's documented compatibility-mode to long-mode switch — and crosses no privilege boundary at the moment of transition: the bitness change is a pure user-mode CPU state change. Its principal detection surface is the instrumentation gap it creates, because EDR tooling that hooks only the 32-bit ntdll of a WoW64 process is blind to every syscall dispatched through the gate.

## Mechanism

1. Deploy the payload as an x86 (32-bit) binary on 64-bit Windows. The loader brings the process up under WoW64, which maps two distinct ntdll images into the address space: the 32-bit ntdll.dll from `%SystemRoot%\SysWOW64` that services normal 32-bit code, and the 64-bit ntdll.dll from `%SystemRoot%\System32` used by the WoW64 layer itself. The 64-bit support libraries wow64.dll, wow64cpu.dll, and wow64win.dll are also present.
2. Resolve the transition entry point in the 32-bit ntdll. The SEC670 slide renders the x86 side as `mov eax, <SSN>` / `mov edx, ntdll+offset` / `call edx` — the computed offset lands on `jmp ntdll.Wow64Transition`, the 32-bit ntdll's published gate entry.
3. Follow the forwarder into the WoW64 transition layer. wow64cpu.dll executes the mode switch as `jmp 033:wow64cpu+offset` — a far jump whose destination uses segment selector `0x33` — followed by `jmp qword ptr [offset]` (steps 1–3 on the training slide). Loading CS with `0x33` switches the processor from 32-bit compatibility mode into 64-bit long mode.
4. Arrive at the 64-bit ntdll.dll syscall stub for the requested service (step 4 on the slide). The stub is the standard x64 sequence: `mov r10, rcx` / `mov eax, <SSN>` / a test of a flag byte in shared memory selecting between the `syscall` instruction and the legacy `int 2e` path / `syscall` / `ret`.
5. Marshal arguments to the x64 ABI before the stub runs. The kernel reads the first argument from r10 (hence `mov r10, rcx`), the next three from rdx, r8, r9, and the remainder from the 64-bit stack; a 32-bit caller must widen all pointers and handle values to 64-bit size, because 32-bit code cannot address the full 64-bit register file or address space directly.
6. Execute `syscall` from inside the genuine 64-bit ntdll image. From the kernel's perspective this is an ordinary 64-bit syscall transition arriving from a MEM_IMAGE-backed ntdll region of a WoW64 thread.
7. Unwind the transition. The stub's `ret` returns through the transition layer, which performs the far return to selector `0x23` (the 32-bit user code segment), restoring compatibility mode; the 32-bit caller resumes with eax holding the NTSTATUS. An offensive implementation replicates steps 2–6 with its own trampoline rather than relying on the WoW64 layer's normal thunking path.

## OS Internals Context

WoW64 is the Windows subsystem that hosts 32-bit processes on 64-bit kernels. The training material states that ntdll.dll effectively "contains both 32-bit and 64-bit versions of functions" in this environment — concretely, two separate ntdll mappings with separate `.text` sections exist in every WoW64 process. Hooks written into one mapping do not exist in the other. This duality is the entire basis of the technique: the material presents Heaven's Gate from the defender's side as "the challenge of hooking functions in a Wow64 environment," because instrumentation placed in the SysWOW64 ntdll observes nothing that executes from the System32 ntdll.

The mode switch rides on documented x86-64 segmentation behavior. Segment selector `0x23` is the user-mode 32-bit code segment (compatibility mode); `0x33` is the user-mode 64-bit code segment, whose descriptor has the long-mode bit set. Any far control transfer — far jump, far call, or far return — that loads CS with `0x33` puts the logical processor into 64-bit mode, and loading `0x23` returns it to 32-bit mode. wow64cpu.dll performs exactly this transfer every time a WoW64 thread needs a syscall; Heaven's Gate performs the identical transfer from arbitrary 32-bit code. No kernel involvement, privilege change, or syscall occurs at the moment of the far jump — the thread simply continues executing at CPL=3 in a wider register and address space.

Once in 64-bit mode, the thread sees the full 64-bit environment of the process. WoW64 threads carry both a 32-bit TEB (reached via fs in 32-bit mode) and a 64-bit TEB; in 64-bit mode `gs:[0x60]` yields the 64-bit PEB, whose loader lists enumerate the 64-bit modules — including the 64-bit ntdll — with no Win32 API calls. This is the resolution substrate a gate implementation uses to find 64-bit stubs (and it is the same primitive T-004 documents for native 64-bit processes). The 64-bit syscall stub itself matches the canonical layout already relied on by the vault's dispatch cards: `mov r10, rcx` then `mov eax, SSN`, with the shared-user-data flag test selecting `syscall` versus `int 2e`, exactly as rendered on the SEC670 transition slide.

The material does not discuss Windows-version differences for this transition; the mechanism is a property of the WoW64 architecture rather than of any specific build. One member note references modern descendants that operate without the classic WoW64 subsystem path, but the atlas material does not elaborate on them.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/MASM (SEC670) and generated WoW64 stubs (Syswhispers3).

The dispatcher in `dark_crystal/crates/core/src/sys_indirect.rs` reserves a `"hgate"` syscall-mode string documented as "Heaven's Gate (WOW64 -> x64 transition)," but that branch calls `execute_syscall_direct` — the same x64 inline-asm stubs (`syscall1`–`syscall11`, built around `mov r10, rcx; syscall`) used as the plain direct-syscall fallback. Those stubs address 64-bit registers, compile only for x86_64, and cannot execute in a 32-bit process; no function in the crate performs a segment-`0x33` transition. The string is a reserved mode, not an implementation.

An implementation would take one of two shapes: an i686-pc-windows-msvc build of the implant, or a 32-bit position-independent blob injected into an existing WoW64 process. Either way it needs three components: resolution of `Wow64Transition` from the 32-bit ntdll's export table (or of the 64-bit ntdll base via a 64-bit PEB walk after transitioning); a transition trampoline containing the far jump to selector `0x33` and the matching far return to `0x23`; and a 64-bit stub region that marshals arguments into r10/rdx/r8/r9 and the 64-bit stack, loads the SSN into eax, and executes `syscall`. SSNs can come from any T-002 stage run against the 64-bit ntdll mapping.

## Why It Matters

Every other syscall-dispatch card in the vault — T-001, T-002, T-006 — assumes the implant already executes as 64-bit code, which makes their stubs, gadgets, and phantom regions unreachable from a 32-bit payload. T-049 is the only card covering the 32-bit deployment context, and it is an orthogonal evasion layer rather than another dispatch method: it changes *which* ntdll the EDR can hook instead of *how* the syscall is issued, and it composes with any SSN-resolution or gadget-dispatch technique run against the 64-bit mapping. Operationally it answers the case where the payload must live inside a 32-bit process — a 32-bit target application or a WoW64-constrained drop — while still requiring kernel access that 32-bit ntdll hooks cannot observe.

## Detection Considerations

- **Telemetry sources**: The training material covers this technique from the hooking side only. User-mode inline hooks on the 32-bit SysWOW64 ntdll are the defensive control the gate defeats; tooling that also hooks the 64-bit ntdll inside the WoW64 process retains visibility, which is why the material frames WoW64 hooking as requiring attention to both bitnesses. Because the `syscall` instruction executes from the genuine 64-bit ntdll image, return-address-based telemetry of the kind described for T-001 (ETW Threat Intelligence stack walks) observes an ntdll-backed frame rather than implant memory. The material names no ETW provider GUIDs and no Sysmon event IDs for this technique.
- **Bypass options**: The technique is itself the bypass of 32-bit ntdll hooking. Combined with SSN resolution against the 64-bit mapping (the T-002 cascade), the 32-bit stub set is never read or executed at all, so hooks, breakpoint scans, and stub-integrity checks aimed at the SysWOW64 ntdll find nothing.
- **Residual artifacts**: Training material does not document residual artifacts for this technique.

## Related Techniques

- **T-001 RecycledGate Indirect Syscalls** — RecycledGate selects where inside the 64-bit ntdll the kernel transition originates (a `syscall;ret` gadget); Heaven's Gate is the layer that gets a 32-bit process into the 64-bit ntdll at all. The two operate on different axes and compose.
- **T-002 Hell's Gate / Halo's Gate / Tartarus Gate + FreshyCalls** — the SSN-resolution cascade assumes a 64-bit ntdll; under WoW64 the same stub-pattern scans and RVA sorts run against the 64-bit ntdll mapping reached through the gate. T-049 is the bitness layer applied beneath any SSN-resolution method.
- **T-004 PEB Walker via gs:[0x60]** — in 64-bit mode inside a WoW64 process, `gs:[0x60]` yields the 64-bit PEB; the walker primitive resolves the 64-bit ntdll base and its exports without Win32 APIs.
- **T-006 Phantom Stubs** — Phantom Stubs manufacture MEM_IMAGE-backed 64-bit syscall stubs from a signed DLL section; the gate instead reaches the authentic 64-bit ntdll stubs. Both answer the same requirement — clean 64-bit stubs when the visible stub set is hooked — from different directions.

## References

- Atlas material: atlas-exploit-dev-part3.md (unit 26 — the transition slide: Wow64Transition, `jmp 033:wow64cpu+offset`, 64-bit stub layout), atlas-exploit-dev-part12.md (units 6–7 — WoW64 hooking problem and dual ntdll; units 15–16 — Syswhispers3 WoW64 direct syscalls), atlas-binary-analysis-part1.md (unit 7 — the transition slide)
- MITRE ATT&CK: T1106 Native API — https://attack.mitre.org/techniques/T1106/
- LGTM notes: lgtm:heavens-gate-wow64-syscall-bridge, lgtm:heavens-gate-wow64-syscalls, lgtm:heavens-gate-wow64-bypass-as-standalone-technique
- Public references: Syswhispers3 (WoW64 and x64 direct-syscall generation, named in atlas-exploit-dev-part12 units 15–16)

## Source Reference

No current implementation. The `"hgate"` branch in `dark_crystal/crates/core/src/sys_indirect.rs` is a dispatcher placeholder that delegates to the plain x64 direct-syscall stubs and performs no segment-`0x33` transition; the crate compiles only for x86_64. See the atlas material (SEC670 Heaven's Gate units) and the Syswhispers3 WoW64 mode for public reference implementations.