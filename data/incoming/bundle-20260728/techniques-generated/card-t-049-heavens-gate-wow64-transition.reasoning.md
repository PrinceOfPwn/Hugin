Let me analyze the inputs carefully.

The task: produce a technique card for T-049 — Heaven's Gate: 32-to-64-Bit Syscall Transition.

Key inputs:
1. Cluster spec: T-049, category `syscalls`, tier `A`, would_relate_to ['T-001', 'T-002', 'T-004', 'T-006'], 3 member notes.
2. Related cards: T-001 (RecycledGate), T-002 (Hell's/Halo's/Tartarus), T-004 (PEB Walker), T-006 (Phantom Stubs).
3. Rust source files: sys_indirect.rs, sys_recycled.rs, early_cascade.rs.
4. Atlas material: atlas-binary-analysis-part1.md (unit 7), atlas-exploit-dev-part12.md (units 6, 7, 15, 16), atlas-exploit-dev-part3.md (unit 26).

Let me verify the Rust source. sys_indirect.rs has a "hgate" syscall_mode branch:

```rust
"hgate" => {
    // Heaven's Gate: transición WoW64 -> x64
    execute_syscall_direct(ssn, arg_count, args)
}
```

Hmm — this is a mode named "hgate" in the dispatcher, but it calls `execute_syscall_direct`, which uses x86_64 inline asm (`mov r10, rcx; syscall`) with `#[cfg(target_arch = "x86_64")]`-style code (the stubs are not cfg-gated in sys_indirect.rs actually, but they use r10/rax 64-bit registers, so they only compile on x86_64). There is NO actual Heaven's Gate implementation here — no segment 0x33 far jump, no Wow64Transition resolution, no wow64cpu.dll interaction. The "hgate" mode just falls through to the same direct syscall path. This is a mislabeled stub, not an implementation of the technique.

Per rule 8: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes." The primary mechanism is the 32→64 bit transition via far jump to 64-bit code segment (0x33), through ntdll.Wow64Transition → wow64cpu.dll → 64-bit ntdll syscall stub. The Rust code does not implement this — the file is compiled for x86_64 only (the asm uses 64-bit registers and would not compile as 32-bit), and the "hgate" mode is just a name that calls the direct syscall path. So the honest verdict: **no current implementation in the HUGIN source**. I should mention sys_indirect.rs's "hgate" mode string as a dispatcher placeholder but clearly state it does not implement the transition — it delegates to execute_syscall_direct, which is a plain x64 direct syscall. Actually, wait — should I even reference the file? The rule says false attribution is worse than "no current implementation". I can note that `sys_indirect.rs` contains a `"hgate"` syscall_mode branch that is a placeholder only (it delegates to the x64 direct-syscall stubs, which cannot execute from a 32-bit process), so the transition itself is unimplemented. That's accurate and useful.

So `source_file: none` and `crate: none`? Hmm. The crate enum is `dark_crystal|client_rust|none`. Since no implementation exists, `crate: none` and `source_file: none` seem right. But wait — let me check what existing cards do for unimplemented techniques... The system prompt says `source_file: <relative path from repo root, or "none">`. So `none` is acceptable. And `crate: dark_crystal|client_rust|none` — for a technique not implemented, `none` is the right choice.

Actually, let me reconsider. The "hgate" string in sys_indirect.rs is in dark_crystal/crates/core. It's a dispatcher mode placeholder. Claiming `source_file: dark_crystal/crates/core/src/sys_indirect.rs` would be false attribution since the file doesn't implement the primary mechanism. The verified-test: "at least ONE function in it must implement the primary mechanism the card describes." No function implements the 32→64 transition. So `source_file: none`, `crate: none`.

Hmm, but should I mention the placeholder in Key Implementation Details? Yes — the template says if no source implements the technique, write the "No current implementation" statement and describe what an implementation would look like. I can add a note that a `"hgate"` mode string exists in the dispatcher but is a non-functional placeholder that falls through to the direct x64 syscall path — that's factual and grounded in the provided source.

MITRE ID: Heaven's Gate is typically mapped to... There's no perfect ATT&CK technique. Candidates:
- T1106 Native API — execution via native APIs. The existing syscall cards (T-001, T-002, T-004) use T1106. Heaven's Gate is a syscall invocation mechanism, so T1106 fits.
- T1620 Reflective Code Loading — no.
- T1055 Process Injection — no.
- T1562.001 Impair Defenses: Disable or Modify Tools — the purpose is hook evasion, which is defense impairment. But the mechanism is native API execution.
- T1134? No.
- T1106 is the best fit, matching the other syscall cards. I could add mitre_secondary: [T1562.001] since the purpose is evading EDR hooks (impairing defenses). Actually T1562.001 is "Disable or Modify Tools" — hook evasion is more like "Impair Defenses" broadly. Hmm, hook bypass could be T1562.001. Some mappings use T1055 for Heaven's Gate... Actually MITRE doesn't have a specific Heaven's Gate entry. T1106 "Native API" is what T-001/T-002 use and is the best single fit. I'll use T1106 primary, and consider whether to add a secondary. The technique is fundamentally about evading user-mode hooks → T1562.001 (Impair Defenses: Disable or Modify Tools). Hmm, T1562.001 is about disabling/modifying security tools; bypassing hooks without modifying them is arguably different. To be safe per rule 4 ("pick one you are confident about"), I'll use T1106 alone. Actually the note tags mention "hook-evasion" and "bitness-evasion" — the defensive interaction is evasion of EDR hooks. I think adding `mitre_secondary: [T1562.001]` is defensible... but is T1562.001 right? "Adversaries may modify and/or disable security tools to avoid possible detection" — bypassing hooks isn't disabling tools. There's no "evade hooks" sub-technique under T1562. I'll omit the secondary line to be safe. Actually, let me include just T1106.

Now the technical content. What does the material say?

From atlas-exploit-dev-part3.md unit 26 (the most detailed):

"Heaven's Gate: The Transition — With just a few jumps, 32-bit code can get back to 64-bit code."

The slide diagram shows:
```
mov eax, INT
mov edx, ntdll+offset
call edx
ret
nop
```
x86 program → `jmp ntdll.Wow64Transition` (ntdll+offset) → `jmp 033:wow64cpu+offset` / `jmp qword ptr [offset]` in wow64cpu.dll (steps 1, 2, 3) → then in 64-bit ntdll.dll:
```
mov r10, rcx
mov eax, INT
test byte ptr [], 01
jne ntdll._offset
syscall
ret
int 2e
```
(step 4)

So the chain per the material:
1. 32-bit (x86) program calls into the 32-bit ntdll.dll at a specific offset (`mov eax, INT; mov edx, ntdll+offset; call edx`).
2. That offset is the export `ntdll.Wow64Transition` — a jump target.
3. `jmp 033:wow64cpu+offset` — a far jump with segment selector 0x33 into wow64cpu.dll. The 0x33 code segment selector switches the CPU from compatibility mode (32-bit) to 64-bit long mode.
4. wow64cpu.dll (the 64-bit WoW64 emulation layer) transitions to the 64-bit ntdll.dll syscall stub.
5. The 64-bit ntdll stub does the standard `mov r10, rcx; mov eax, SSN; ...; syscall; ret` with a `test byte ptr [], 01; jne` branch — that's the WoW64 check inside the 64-bit stub? Actually the `test byte ptr [0x7ffe0308], 1; jne` is the SharedUserData check for `int 2e` vs `syscall` (that's the classic ntdll stub pattern on x64: it tests SharedUserData!SystemCall and uses int 2e if set). The slide shows exactly the canonical 64-bit stub with the int 2e fallback. 

From atlas-exploit-dev-part12.md units 6-7:

"Heaven's Gate — Hooking Wow64 and the gate to 64-bit code. 32-bit processes on 64-bit systems have an interesting method when it comes to making syscalls. Thanks to Windows 32 on Windows 64 [WoW64], this is all made possible. The transition from 32-bit code to 64-bit code has been dubbed Heaven's Gate. There might come a time when you need to implement some hooks in a 32-bit application, or more technically speaking, a Wow64 application. Ntdll.dll implements the logic for the system loader and thus is responsible for initializing the user mode portion of the..."

Key point: "ntdll.dll contains both 32-bit and 64-bit versions of functions, and highlights the challenge of hooking functions in a Wow64 environment" — the dual ntdll mapping.

Unit 15-16 (part12): Syswhispers3 supports "WoW64, EGGs, direct syscall jumps in both WoW64 and x64, direct syscall jumps to random syscalls". This is a public tooling reference — Syswhispers3 supports WoW64 direct syscalls. Good for References section (named in material).

From atlas-binary-analysis-part1.md unit 7: "Heaven's Gate: The Transition — x86 program; ntdll.dll - offset" — same slide, confirms entry via ntdll offset.

Now Windows internals grounding (from well-established documentation — allowed):

- WoW64 subsystem: on 64-bit Windows, 32-bit processes run under WoW64. The process address space contains:
  - 32-bit ntdll.dll (from %SystemRoot%\SysWOW64\ntdll.dll) mapped below 4GB.
  - 64-bit ntdll.dll (from %SystemRoot%\System32\ntdll.dll) mapped in the 64-bit address space (above 4GB).
  - wow64.dll, wow64cpu.dll, wow64win.dll — the 64-bit emulation/thunking layer.
- Segment selectors: 0x23 = 32-bit code segment (compatibility mode), 0x33 = 64-bit code segment (long mode). A far jump/call/ret to selector 0x33 switches the CPU to 64-bit mode; 0x23 switches back. This is documented behavior on x86-64 (the CS descriptor's L bit determines long mode).
- The 32-bit TEB (fs:[0]) and 64-bit TEB (gs:[0]) both exist in a WoW64 process; the 64-bit PEB is accessible at gs:[0x60]. The 32-bit PEB is at fs:[0x30].
- The 32-bit ntdll exports `Wow64Transition` — actually it's a pointer exported by the 32-bit ntdll (at a fixed offset), which points into wow64cpu.dll's `TurboThunkDispatch` area or the transition code. The classic Heaven's Gate implementation reads `fs:[0xC0]` — the TEB32 offset 0xC0 holds a pointer (WOW32Reserved / the "Heaven's Gate" pointer) to the 64-bit transition routine in wow64cpu.dll. Hmm — the material says "jmp ntdll.Wow64Transition" — the export in 32-bit ntdll named Wow64Transition. Both are documented: the export Wow64Transition in 32-bit ntdll.dll is the canonical entry. I'll follow the material (ntdll.Wow64Transition) and can mention the well-documented mechanism: executing a far jump with CS=0x33.

Careful about fabricating. What's well-established Windows internals:
- 0x23/0x33 segment selectors: well-established.
- Dual ntdll mapping in WoW64: well-established and confirmed by material ("Ntdll.dll contains both 32-bit and 64-bit versions of functions" — hmm, actually that phrasing says ntdll has both versions; the material means both 32-bit and 64-bit ntdll.dll are mapped in a Wo64 process. I'll phrase it as dual mapping).
- wow64cpu.dll: named in the material slide.
- The 64-bit syscall stub pattern (mov r10,rcx / mov eax,SSN / syscall / ret / int 2e): shown in the material.
- x64 syscall ABI: rcx→r10, args in rdx, r8, r9, stack; SSN in eax; well established (matches T-001 card).

Detection: The material frames Heaven's Gate from the defender's hooking perspective — "the challenge of hooking functions in a Wow64 environment" — i.e., 32-bit-only hooks on the SysWOW64 ntdll do not observe syscalls issued through the 64-bit ntdll. The material doesn't give explicit ETW providers or Sysmon IDs for detection of Heaven's Gate itself. Per rule: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.'" The material DOES discuss the detection-evasion implication: hooks placed in the 32-bit ntdll are bypassed because execution transitions to the 64-bit ntdll stubs, which the 32-bit-only instrumentation never sees. That's a detection-relevant statement from the material (units 6-7 part12 discuss hooking in WoW64 being challenging). I can structure Detection Considerations as:
- Telemetry sources: material frames it as user-mode inline hooks on 32-bit ntdll (SysWOW64) being the primary defensive instrumentation defeated. It does not name ETW providers or Sysmon IDs. I should say what the material covers and explicitly note what it doesn't.
- Bypass options: the technique IS the bypass (32-bit implant issues 64-bit syscalls, skipping hooked 32-bit stubs).
- Residual artifacts: material doesn't cover. I can note none documented in material. Careful not to invent.

I can add well-established context (allowed: "well-established Windows internals documentation"): e.g., an EDR that hooks only the SysWOW64 ntdll misses the transitions; an EDR hooking the 64-bit ntdll inside the WoW64 process sees them. Kernel-side (ETW-TI, kernel callbacks) still observes the syscalls — but wait, is that in the material? No. Is it well-established? The kernel sees the syscall regardless — that's definitional (it's still a syscall into the kernel). I can state that carefully as internals context rather than detection claims. Hmm, the detection section instruction: "Detection surface the training material describes for this technique" — and "If the material does not cover detection... write: 'Training material does not discuss detection for this technique.' Do not invent detections." The material DOES discuss the hook-evasion aspect (that IS detection-relevant: it defeats 32-bit EDR hooking per lgtm note 3 and units 6-7). So I'll cover what the material covers (user-mode hook visibility), and state that specific ETW/Sysmon telemetry for the transition itself is not documented in the material. That's honest.

Mechanism steps (numbered, concrete):

1. The implant runs as a 32-bit (x86) process on 64-bit Windows, i.e., a WoW64 process. Two ntdll.dll images are mapped: the 32-bit SysWOW64 copy (used by normal 32-bit code) and the 64-bit System32 copy (used by the WoW64 layer).
2. Resolve the Wow64Transition pointer: read the exported `Wow64Transition` address from the 32-bit ntdll.dll (per the material: "ntdll.dll - offset" — the x86 program does `mov edx, ntdll+offset; call edx`).
3. Prepare the 64-bit syscall arguments per the x64 ABI before transitioning? Actually in classic Heaven's Gate, you set up 64-bit registers after the transition (32-bit code can't address 64-bit registers). The flow: transition to 64-bit mode first, then execute 64-bit code that sets r10=rcx equivalent... but rcx in 32-bit mode is ecx which maps to rcx. Standard HG shellcode: far call to 0x33:64bit_stub, the 64-bit stub moves args (passed via 32-bit registers, zero-extended) into the x64 syscall convention, loads SSN into eax, executes syscall, then far returns to 0x23. I'll describe:
   - Step: load SSN into eax and stage arguments (classic approach passes args via the 32-bit stack/registers, then the 64-bit trampoline marshals them).
   - Step: execute the transition: `jmp far 0x33:<address>` — via Wow64Transition → wow64cpu.dll (`jmp 033:wow64cpu+offset` per the slide). The far jump to segment selector 0x33 switches the processor from 32-bit compatibility mode to 64-bit mode.
   - Step: wow64cpu.dll (64-bit) continues into the 64-bit ntdll.dll syscall stub.
   - Step: the 64-bit stub executes `mov r10, rcx; mov eax, <SSN>; test byte ptr [SharedUserData], 1; jne <int 2e path>; syscall; ret` — per the slide which shows the stub with both syscall and int 2e.
   - Step: after the syscall returns, control returns through the transition path back to 32-bit mode (far return to selector 0x23), and the 32-bit implant continues with eax holding the NTSTATUS.

I should be careful: the slide's flow is: x86 program → (1) jmp ntdll.Wow64Transition → (2) jmp 033:wow64cpu+offset in wow64cpu.dll → (3) jmp qword ptr [offset] → (4) 64-bit ntdll stub with syscall. Numbered steps on the slide are 1,2,3 (in wow64cpu) and 4 (ntdll 64-bit). Let me re-read:

```
mov eax, INT
mov edx, ntdll+offset
call edx
ret
nop
x86 program
jmp ntdll.Wow64Transition   <- at ntdll+offset
jmp 033:wow64cpu+offset     <- step 1/2?
jmp qword ptr [offset]      <- step 3, wow64cpu.dll
1 2 3
mov r10, rcx
mov eax, INT
test byte ptr [], 01
jne ntdll._offset
syscall
ret
int 2e
ntdll.dll (64-bit)          <- step 4
```

So: x86 program sets eax=SSN, edx = ntdll+offset (the Wow64Transition address), calls it. At that address: `jmp ntdll.Wow64Transition`. Then into wow64cpu.dll: `jmp 033:wow64cpu+offset` and `jmp qword ptr [offset]` (steps 1-3), finally arriving at the 64-bit ntdll stub (step 4): mov r10, rcx; mov eax, SSN; test byte ptr [SharedUserData.SystemCall?], 01; jne → int 2e fallback; syscall; ret.

Good — I can describe this faithfully.

OS Internals Context:

- WoW64 subsystem architecture: three 64-bit support DLLs (wow64.dll, wow64cpu.dll, wow64win.dll) plus the dual ntdll mapping. The 32-bit ntdll (SysWOW64) services 32-bit code; when a syscall is needed, normal WoW64 flow thunks through wow64.dll/wow64cpu.dll to the 64-bit ntdll.
- Segment selectors 0x23 and 0x33: the x86-64 GDT entries for user-mode 32-bit compatibility code (0x23) and 64-bit code (0x33). The L (long) bit in the 0x33 code segment descriptor puts the CPU into 64-bit mode on a far control transfer. This is documented Intel/Windows behavior. Heaven's Gate abuses that a far jump/call/ret with CS=0x33 from within a WoW64 process lands in 64-bit code with full access to the 64-bit address space, including the 64-bit ntdll mapping.
- TEB/PEB duality: WoW64 processes have both a 32-bit TEB (fs base) and a 64-bit TEB (gs base, gs:[0x60] → 64-bit PEB). Hmm — careful: in WoW64, does gs hold the 64-bit TEB when in 64-bit mode? Yes — on transition to 64-bit mode, the gs base points to the 64-bit TEB (this is documented behavior used by wow64cpu). The 64-bit PEB walks reveal the 64-bit ntdll. This connects to T-004 (PEB walker) — a PEB walk in 64-bit mode within a WoW64 process resolves the 64-bit ntdll. But is this in the material? The material doesn't discuss TEB/PEB in the HG units. It's well-established internals though; allowed. I'll keep it brief and factual.
- The kernel/user boundary: the CPU mode switch happens in user mode — no privilege change. The actual privilege crossing is the same `syscall` instruction; from the kernel's view, the thread is a WoW64 thread executing a 64-bit syscall. The kernel cannot distinguish a 64-bit syscall issued via Heaven's Gate from one issued by the WoW64 layer itself — both arrive via 64-bit ntdll stubs. Hmm, is that claim supportable? The kernel sees a syscall from a thread in a WoW64 process; threads can switch modes freely (the OS supports it — that's how the WoW64 layer works). The claim "the kernel sees a normal 64-bit syscall transition" is reasonable internals grounding. But the material doesn't say it; I'll phrase carefully: "the transition itself is a user-mode CPU mode switch; no syscall or kernel transition occurs at the moment of the far jump."
- Which ntdll is hookable: EDRs typically inject hooks into the 32-bit ntdll of a WoW64 process (that's where the 32-bit code executes Win32/NT calls). Hooks placed there never observe syscalls dispatched through the 64-bit ntdll stubs. The material's hooking-focused units (part12 units 6-7) frame exactly this: "the challenge of hooking functions in a Wow64 environment" — ntdll contains both 32-bit and 64-bit versions of functions.
- Version note: Syswhispers3 supports WoW64 direct syscalls (material units 15-16 part12). Also note 3 mentions "modern WoW64-subsystem-less descendants" — that's vague; I could mention that the LGTM note references descendants but the material doesn't elaborate. Maybe skip or one clause.

Key Implementation Details:
- State: No current implementation in the HUGIN source. The `sys_indirect.rs` dispatcher contains a `"hgate"` syscall_mode string, but that branch calls `execute_syscall_direct`, which emits a plain x64 `syscall` from implant code — it performs no segment-0x33 transition and cannot run in a 32-bit process (the crate targets x86_64 only). So the string is a reserved dispatcher mode, not an implementation.
- Then describe what an implementation would look like: a 32-bit build target (i686-pc-windows-msvc or a 32-bit shellcode blob), resolve Wow64Transition from the 32-bit ntdll export table (PEB walk on the 32-bit loader list), far-jump stub `jmp 0x33:offset` written in raw bytes or inline asm (Rust inline asm on i686 can emit the far jump bytes via `.byte` sequences or a global_asm trampoline), marshal arguments into the x64 convention (r10=rcx etc.) inside the 64-bit trampoline, execute `syscall`, then `retf`/far return to 0x23. One paragraph per template.

Why It Matters:
- T-001/T-002/T-006 assume 64-bit execution; T-049 covers the deployment context where the implant is 32-bit (e.g., injected into a 32-bit process, or a 32-bit binary for compatibility) and still wants hook-free syscalls. It changes WHICH ntdll is visible and hookable. It defeats EDRs that instrument only the SysWOW64 ntdll. It is an evasion layer orthogonal to SSN resolution: any of the resolution methods (Hell's Gate etc.) can be run against the 64-bit ntdll mapping to get SSNs, then dispatched via the gate. Also a 32-bit payload gains access to the full 64-bit address space (64-bit PEB, 64-bit modules).

Hmm wait — does the 32-bit ntdll export Wow64Transition? Yes, well-established: 32-bit ntdll.dll exports Wow64Transition. The material confirms the name "ntdll.Wow64Transition". Good.

Detection Considerations:
- Telemetry sources: the material's coverage is from the hooking side: user-mode inline hooks on the 32-bit (SysWOW64) ntdll are the defensive instrumentation this defeats; hooks on the 64-bit ntdll in the same process would observe the stubs. The material does not name ETW providers, GUIDs, or Sysmon event IDs for this technique. State that.
- Bypass options: the technique is itself the bypass — issue syscalls via the 64-bit stub set so that 32-bit-only hooks never execute. Note from material: hooking in WoW64 is described as challenging precisely because of the dual ntdll.
- Residual artifacts: not covered by material → say so. I might note (as internals fact, carefully) that the far-jump trampoline code must live in executable memory in the 32-bit address space — that's an implementation fact rather than a detection claim. Keep it minimal.

Related Techniques (only from would_relate_to: T-001, T-002, T-004, T-006):
- T-001 RecycledGate — RecycledGate dispatches through a `syscall;ret` gadget inside the 64-bit ntdll of a 64-bit process; Heaven's Gate is the path that lets a 32-bit process reach an equivalent 64-bit stub at all. Orthogonal dispatch layers; HG determines which ntdll, RecycledGate determines where in ntdll the transition originates.
- T-002 Hell's/Halo's/Tartarus — SSN resolution methods assume 64-bit ntdll; in a WoW64 deployment the same stub-pattern scans and RVA sorts can be run against the 64-bit ntdll mapping reached through the gate. HG is the bitness layer applied on top of any SSN resolution method (per note 3).
- T-004 PEB Walker — in a WoW64 process there are two loader lists (32-bit and 64-bit); after transitioning, a 64-bit PEB walk (gs:[0x60]) resolves the 64-bit ntdll. The PEB-walker primitive is how the 64-bit module base would be resolved API-free in the 64-bit context.
- T-006 Phantom Stubs — phantom stubs build MEM_IMAGE-backed syscall stubs; for a 32-bit implant, stubs in 64-bit-reachable memory would be the phantom analogue behind the gate. Hmm, is this justified? The would_relate_to list includes T-006 (note 2 relates to T-001, T-002, T-006). The relationship: T-006 constructs syscall stubs backed by a signed DLL image; Heaven's Gate instead reaches the genuine 64-bit ntdll stubs — an alternative source of "clean" 64-bit stubs when the 32-bit ones are hooked. That's a fair one-line relationship grounded in both cards' content.

References:
- Atlas material: atlas-binary-analysis-part1.md (unit 7), atlas-exploit-dev-part12.md (units 6, 7, 15, 16), atlas-exploit-dev-part3.md (unit 26).
- MITRE ATT&CK: T1106 Native API — https://attack.mitre.org/techniques/T1106/
- LGTM notes: the three IDs.
- Public references: Syswhispers3 (named in atlas-exploit-dev-part12 units 15-16 — "Syswhispers3: WoW64, EGGs, direct syscall jumps in both WoW64 and x64"). Also "j00ru research" is mentioned in unit 2 of part12 but that's for Hell's Gate syscall tables, not HG. Keep Syswhispers3 only. The material also credits no one else for HG. Fine.

Source Reference: "No current implementation. The `hgate` branch in `dark_crystal/crates/core/src/sys_indirect.rs` is a dispatcher placeholder that delegates to the x64 direct-syscall stubs and performs no WoW64 transition. See atlas material and MITRE reference for public tooling (Syswhispers3 WoW64 mode)."

Frontmatter:
```yaml
---
id: T-049
name: Heaven's Gate: WoW64 32-to-64-Bit Syscall Transition
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1106
tags: [heavens-gate, wow64, cross-bitness, segment-0x33, hook-evasion, syscall-transition, wow64cpu, dual-ntdll]
origin: atlas-synthesis
member_notes: ['lgtm:heavens-gate-wow64-syscall-bridge', 'lgtm:heavens-gate-wow64-syscalls', 'lgtm:heavens-gate-wow64-bypass-as-standalone-technique']
---
```

Name: canonical is "Heaven's Gate: 32-to-64-Bit Syscall Transition" — 4-8 words. "Heaven's Gate: 32-to-64-Bit Syscall Transition" — count words: Heaven's(1) Gate(2) 32-to-64-Bit(3) Syscall(4) Transition(5) = 5 words plus colon. Fine, use canonical name exactly.

Category: syscalls ✓. Tier: A ✓.

Tags 5-10 kebab-case: [heavens-gate, wow64, cross-bitness, hook-evasion, segment-selector-0x33, wow64cpu, dual-ntdll, x86-to-x64] — 8 tags, all kebab-case.

H1: `# Heaven's Gate — 32-Bit WoW64 Processes Issuing Native 64-Bit Syscalls` — one-line purpose.

Now write the body. Target 1200-1800 words.

Summary (3-5 sentences, first sentence standalone):
"Heaven's Gate is the mechanism by which 32-bit (WoW64) processes on 64-bit Windows transition into 64-bit code to issue native 64-bit syscalls, entered through the Wow64Transition export of the 32-bit ntdll.dll and a far jump to code segment selector 0x33. A 32-bit implant that drives this transition manually executes syscalls from the 64-bit ntdll.dll stubs instead of the 32-bit SysWOW64 stubs, so user-mode hooks placed in the 32-bit ntdll never observe them. The technique exploits the WoW64 subsystem's own architecture — the dual ntdll mapping and the CPU's documented compatibility-mode/long-mode switch — and requires no privilege escalation because the bitness change is a pure user-mode CPU state transition. Its primary detection surface is the instrumentation gap it creates: EDRs that hook only the 32-bit ntdll of a WoW64 process are blind to everything dispatched through the gate."

Mechanism steps — concrete:

1. Deploy as an x86 (32-bit) binary on 64-bit Windows; the loader maps the process as WoW64, giving it two ntdll images: 32-bit ntdll from SysWOW64 and 64-bit ntdll from System32, plus wow64.dll/wow64cpu.dll/wow64win.dll.
2. Resolve the transition entry: locate Wow64Transition in the 32-bit ntdll (material: the x86 program computes ntdll+offset, loads it into edx, and calls it: `mov eax, <SSN>; mov edx, ntdll+offset; call edx`).
3. At that ntdll offset sits `jmp ntdll.Wow64Transition`, which forwards into the WoW64 transition layer.
4. wow64cpu.dll executes the mode switch: `jmp 033:wow64cpu+offset` — a far jump with segment selector 0x33 — followed by `jmp qword ptr [offset]` (steps 1-3 on the SEC670 slide). The 0x33 selector flips the CPU from 32-bit compatibility mode to 64-bit long mode.
5. Control arrives at the 64-bit ntdll.dll syscall stub for the requested service (step 4 on the slide): `mov r10, rcx; mov eax, <SSN>; test byte ptr [SharedUserData], 1; jne <int 2e path>; syscall; ret`. The stub executes the 64-bit syscall with the x64 ABI.
6. On return, the path unwinds through the transition layer and a far return to selector 0x23 restores 32-bit mode; the 32-bit caller resumes with eax holding the NTSTATUS.

Hmm, on step 6 — the slide doesn't show the return path explicitly, but `ret` in the stub and the x86 program's `call edx` imply a return; the return to 32-bit mode is well-established (far return / wow64cpu handling). Fine as internals grounding.

Also worth one step or note: for a manual/offensive use (vs. the normal WoW64 path), the implant replicates this transition itself — stages arguments per x64 convention, executes a far call to 0x33:<64-bit trampoline>, runs the stub, far-returns. The material describes the OS path; the offensive use is "the same few jumps" — note 2 says "a 32-bit implant can issue 64-bit syscalls to bypass 32-bit ntdll hooks entirely." Good.

OS Internals Context:
- WoW64 subsystem composition: wow64.dll (thunking), wow64cpu.dll (CPU mode switching/emulation), wow64win.dll (win32k thunks), and the dual ntdll. From material units 6-7 part12.
- Segment selectors: 0x23 = 32-bit user code (compatibility mode), 0x33 = 64-bit user code (long mode). The far control transfer to 0x33 performs the switch; this is how wow64cpu itself crosses, and Heaven's Gate reuses the same documented CPU behavior from arbitrary 32-bit code.
- Dual ntdll and hook visibility: the 32-bit ntdll (SysWOW64) and 64-bit ntdll (System32) are separate mappings with separate .text; hooks written into one do not exist in the other. The material states ntdll "contains both 32-bit and 64-bit versions of functions" and that this makes hooking in WoW64 challenging (part12 units 6-7).
- x64 syscall ABI in the stub: mov r10, rcx (kernel reads arg1 from r10), eax = SSN; the SharedUserData test selects syscall vs int 2e (shown on the slide). Args beyond four on the stack, 8-byte wide. A 32-bit caller must marshal pointers/values to 64-bit width.
- TEB/PEB duality (well-established): fs addresses the 32-bit TEB; in 64-bit mode gs:[0x60] yields the 64-bit PEB, which enumerates the 64-bit modules — this is how a gate implementation finds the 64-bit ntdll without Win32 APIs (ties to T-004). Is this safe to include? Yes — well-established Windows internals; WoW64 processes have both TEBs and PEBs. The 64-bit PEB is at gs:[0x60] when executing 64-bit code. The 32-bit PEB at fs:[0x30]. Confirmed by Windows Internals. Keep brief.
- No privilege change: the gate is CPL=3 throughout; only the `syscall` instruction crosses into kernel mode, exactly as in a 64-bit process.
- Version differences: material doesn't discuss version deltas; note 3 references "modern WoW64-subsystem-less descendants" without elaboration — I can say the material does not detail version differences. Maybe one line.

Key Implementation Details:
- No current implementation statement + the sys_indirect.rs "hgate" observation.
- Implementation sketch paragraph: 32-bit target or 32-bit PIC blob; resolve Wow64Transition via export walk of the 32-bit ntdll (or the 64-bit ntdll base via a 64-bit PEB walk post-transition); trampoline bytes for the far jump `jmp far 0x33:addr` (opcode EA or FF 2D encoding — careful, do I want to specify opcodes? The far jump with m16:32 ptr is FF /5 or EA; in 32-bit code `jmp 0x33:offset` assembles to EA <off32> <sel16>. This is well-established; one clause is fine but I don't need opcode-level detail. I'll keep it at the instruction level: a far jump/call with selector 0x33.) Then in 64-bit mode: marshal args into r10/rdx/r8/r9/stack, eax=SSN, syscall, far return to 0x23. Rust specifics: requires i686-pc-windows-msvc target or a standalone 32-bit shellcode crate; inline asm via core::arch::asm! on i686 or a naked global_asm trampoline; the existing dark_crystal syscall crates are cfg'd to x86_64 and would need an i686 path. Wait — rule 3 says no suggestions/variant ideas. "Do not include variant ideas, improvements, or extensions." The template itself instructs: "Then briefly describe what an implementation would look like (data structures, syscalls, roughly one paragraph)." So the implementation sketch is mandated by the template when no source exists. Keep it descriptive of the technique's implementation shape, not "future improvements" framed as roadmap. One paragraph.

Why It Matters (2-4 sentences):
- Every other dispatch card (T-001, T-002, T-006) assumes the implant executes as 64-bit code; T-049 is the only card covering the 32-bit deployment context, where those stubs and gadgets are unreachable without a bitness transition. It earns its own card because it is an orthogonal evasion layer: it changes which ntdll the EDR can hook rather than how the syscall is dispatched, and it composes with any SSN-resolution or gadget-dispatch method run against the 64-bit mapping. Operationally it matters when the payload must live in a 32-bit process (32-bit target application, WOW64-only drop constraints) while still requiring hook-free kernel access.

Detection Considerations:
- Telemetry sources: material covers user-mode inline hooks on the 32-bit SysWOW64 ntdll as the defeated control; EDRs that also hook the 64-bit ntdll within the WoW64 process retain visibility (the material frames WoW64 hooking as requiring attention to both bitnesses — "the challenge of hooking functions in a Wow64 environment"). The material names no ETW providers, GUIDs, or Sysmon event IDs for this technique — state that explicitly.
- Bypass options: the technique is itself the bypass of 32-bit ntdll hooking; combined with resolving SSNs from the 64-bit mapping (T-002 methods), the 32-bit stub set is never touched at all.
- Residual artifacts: material does not document residual artifacts for this technique.

Hmm, one more internals nugget that's safe and valuable: hooking in WoW64 — the EDR must hook both ntdlls; most 32-bit-targeted tooling hooks only the SysWOW64 copy. And from kernel/ETW-TI's perspective, the syscall still originates from a MEM_IMAGE 64-bit ntdll region, so return-address heuristics see a legitimate ntdll frame — wait, is that inventing? T-001's card says ETW-TI checks return addresses against known module images. For Heaven's Gate, the syscall executes from the genuine 64-bit ntdll, so the same statement follows: the transition RIP is inside ntdll. That's a defensible synthesis using the related card's documented telemetry model, not a fabricated provider. I can include one sentence: because the syscall instruction executes from the genuine 64-bit ntdll image, return-address-based telemetry (as described for T-001) observes an ntdll-backed frame. Cite it as following from the same telemetry model. That's grounded in provided cards. OK.

Related Techniques section (format: "- **T-NNN Name** — one line"):
- **T-001 RecycledGate Indirect Syscalls** — RecycledGate picks where inside the 64-bit ntdll the syscall originates (a `syscall;ret` gadget); T-049 is the layer that gets a 32-bit process into the 64-bit ntdll at all. Orthogonal and composable.
- **T-002 Hell's Gate / Halo's Gate / Tartarus Gate + FreshyCalls** — SSN-resolution cascade; in a WoW64 deployment the stub scans and RVA sorts are run against the 64-bit ntdll mapping reached through the gate. T-049 is the bitness layer applied beneath any SSN resolution method.
- **T-004 PEB Walker via gs:[0x60]** — in 64-bit mode inside a WoW64 process, gs:[0x60] yields the 64-bit PEB; the walker primitive resolves the 64-bit ntdll base and its exports API-free.
- **T-006 Phantom Stubs** — Phantom Stubs manufacture MEM_IMAGE-backed 64-bit stubs; the gate instead reaches the authentic 64-bit ntdll stubs — alternative answers to "clean 64-bit syscall stubs" when the 32-bit stubs are hooked.

References:
- Atlas material: atlas-exploit-dev-part3.md (unit 26 — the transition slide), atlas-exploit-dev-part12.md (units 6, 7 — WoW64 hooking; units 15, 16 — Syswhispers3 WoW64 support), atlas-binary-analysis-part1.md (unit 7).
- MITRE ATT&CK: T1106 Native API — https://attack.mitre.org/techniques/T1106/
- LGTM notes: the three.
- Public references: Syswhispers3 (WoW64 direct-syscall generation; named in atlas-exploit-dev-part12 units 15-16).

Source Reference:
"No current implementation. The `"hgate"` branch of the dispatcher in `dark_crystal/crates/core/src/sys_indirect.rs` is a mode string that delegates to the plain x64 direct-syscall stubs and performs no segment-0x33 transition; the crate compiles only for x86_64. See atlas material (SEC670 Heaven's Gate units) and the Syswhispers3 WoW64 mode for public reference implementations."

Word count: aim ~1400-1600 body words. Let me draft.

Also double-check rule: no banned words — avoid "elegant", "clever", "textbook", "notably", "interesting" etc. Avoid "essentially", "at its core". Watch "key insight" etc.

Check frontmatter rules: id T-049 ✓, category syscalls ✓, tier A ✓, crate none ✓, source_file none ✓, mitre T1106 ✓, tags 8 kebab-case ✓, member_notes exact ✓.

One consideration on `crate: none` — the placeholder exists in dark_crystal. But since source_file is none, crate none is consistent.

Let me also double check the claim about Wow64Transition export: The material literally shows "jmp ntdll.Wow64Transition" at "ntdll+offset" in the 32-bit ntdll. So "the Wow64Transition export of the 32-bit ntdll.dll" is supported by the material. Good.

The slide's stub shows `test byte ptr [], 01 / jne ntdll._offset / syscall / ret / int 2e` — the SharedUserData system-call test. I'll describe it as the stub's documented branch selecting `syscall` versus the legacy `int 2e` path, "shown on the SEC670 slide as a test of a byte in shared user data." The empty brackets in the OCR — I'll say `test byte ptr [SharedUserData], 1` with the caveat it's the shared-user-data check shown in the material. Hmm, to be safe: "a test of a flag byte (the material's slide renders the operand as a shared-memory byte) selecting between `syscall` and the legacy `int 2e` path." That's faithful.

Mechanism numbering — I'll write 7 steps including the manual/offensive replication step.

Now, length check on sections. Let me write it out.

Draft:

---

Summary (~110 words)
Mechanism (7 steps, ~350 words)
OS Internals Context (~450 words)
Key Implementation Details (~220 words)
Why It Matters (~110 words)
Detection Considerations (~180 words)
Related Techniques (~150 words)
References/Source — lists

Total ~1600 words body. 

Write carefully, declarative, technical. No first person. No rhetorical questions.

One more check on the "hgate" claim — re-reading sys_indirect.rs:

```rust
"hgate" => {
    // Heaven's Gate: transición WoW64 -> x64
    execute_syscall_direct(ssn, arg_count, args)
}
```

And the doc comment at top: `/// - "hgate": Heaven's Gate (WOW64 -> x64 transition)`. So the dispatcher names the mode but routes it to execute_syscall_direct — the same x64 inline-asm syscall stubs used as the last-resort fallback. These stubs (`syscall1`..`syscall11`) use r10/rax and would only compile on x86_64 (file has no target_arch cfg on them in sys_indirect.rs, but 64-bit register asm requires x86_64). A WoW64 (32-bit) process cannot execute them. Therefore: placeholder, not implementation. My characterization is accurate and verifiable from the provided source.

early_cascade.rs and sys_recycled.rs — provided but irrelevant to HG (they're x64 APC injection and x64 indirect syscalls). I won't reference them except... no need. They don't implement HG. Mentioning them isn't required; rule says ignore files that don't implement. I'll just not mention them (or could mention sys_recycled only in passing — no, keep clean).

Final structure per template exactly. Write it.