Let me analyze the inputs carefully.

The cluster spec asks for T-030: "Inline Hook Implementation: Red-Team Hooking Mechanics" — category edr-evasion, tier B. The technique is about implant-side inline hooking: byte-patching function prologues, trampoline construction, x64 hook stubs with `mov rax, addr; jmp rax`. The member note is `lgtm:inline-hook-implementation-side` from atlas-exploit-dev-part12, units 1, 8, 9, 10, 11.

Key material from the atlas:
- Unit 1: Inline hooking steps — obtain memory address of function, read and save 5+ bytes of the function, patch in the jump, your function executes, clean up patched bytes, execute original function. Hook can be at beginning, mid, or end of function.
- Unit 8: 64-bit inline hook example — `mov rax, 1122334455667788` followed by `jmp rax` then nops. Compares 32-bit vs 64-bit: no typical prologue like x86; JMP used similarly. The mov rax/jmp rax overcomes relative jump limitations in 64-bit (JMP rel32 is ±2GB range; x64 needs absolute indirect jump).
- Unit 9: Trampolines — jump points to redirect execution flow after hooked function; avoiding infinite loops when hooking NtQuerySystemInformation.
- Unit 10: Trampoline details — hooked NtQuerySystemInformation with mov rax/jmp rax; hook code calls original NtQuerySystemInformation which re-enters the hook → infinite loop. Need a jump to bypass overwritten hook bytes to reach original function's code.
- Unit 11: Trampoline Steps — execution flows between original function and hook function via trampoline.

Units 6-7 (Heaven's Gate / Wow64 hooking) are related but the member note only lists units 1, 8-11. I can mention Wow64 briefly in OS Internals if relevant, but the note specifies units 1, 8-11. The note says "Units 1, 8-11 cover inline hooking from the implementer's perspective". I'll primarily use those units, though unit 1 mentions "Hook beginning of function; Hook mid function; Hook end of function".

Now — do any of the provided Rust files implement inline hooking?

1. `amsi_page_guard.rs` — PAGE_GUARD + VEH interception, explicitly states "No inline hooks (zero byte writes to amsi.dll .text)". Does NOT implement inline hooking.
2. `ki_step_over.rs` — hardware breakpoint-based stepover of EDR hooks; explicitly avoids unhooking/patching. It does patch the `Wow64PrepareForException` callback pointer in .rdata (pointer overwrite, not code byte patching). That's a data pointer hook, not an inline code hook with trampoline. Does NOT implement the primary mechanism described (byte-patching prologue + trampoline).
3. `overload.rs` — module overloading/manual map. Not inline hooking.

Per rule 8: "at least ONE function in it must implement the primary mechanism the card describes" — byte-patching a function prologue with a jump and building a trampoline. None of the files do this. So: `crate: none`, `source_file: none`, and state no current implementation.

Wait — frontmatter `crate` enum: dark_crystal|client_rust|none. Since no implementation, `none`.

MITRE: best fit. Inline hooking — T1574.007? No wait. Let me think. ATT&CK:
- T1055 Process Injection includes "Process Hollowing" etc. Actually T1055.001 is "Dynamic-link Library Injection".
- Inline hooking for intercepting API calls... The closest ATT&CK technique: T1574 "Hijack Execution Flow"? There is a sub-technique... Hmm. Actually "Hooking" is T1055? Let me recall properly.

MITRE ATT&CK has:
- T1055 Process Injection (sub-techniques .001 DLL injection, .002 PE injection, .003 thread execution hijacking, .004 asynchronous procedure call, .005 thread local storage, .008 extra window memory injection, .009 process hollowing, .011 extra window memory?, .012 process hollowing, .013 process doppelgänging, .014 VDSO hijacking...). Inline hooking isn't quite there.
- T1574 Hijack Execution Flow — sub-techniques include .001 DLL search order hijacking, .002 DLL side-loading, ... .007 Path interception? .008? Hmm, "ServicesFile Permissions Weakness"... Actually T1574 sub-techniques: .001 DLL Search Order Hijacking, .002 DLL Side-Loading, .003 Dylib Hijacking, .004 Dylib Search Order Hijacking, .005 Executable Installer File Permissions Weakness, .006 Dynamic Linker Hijacking, .007 Path Interception by PATH Environment Variable, .008 Path Interception by Search Order Hijacking, .009 Path Interception by Unquoted Path, .010 Services File Permissions Weakness, .011 Services Registry Permissions Weakness, .012 COR_PROFILER, .013 KernelCallbackTable. Hmm — .013 KernelCallbackTable is a callback table hook. Not inline hooking.
- T1103? No that's AppInit DLLs.
- T1134? Access token manipulation. No.
- T1112 Modify registry. No.
- T1562 Impair Defenses — sub-technique .001 Disable or Modify Tools. Hooking security tools' functions could be T1562.001.

Actually, what about T1055? The classic "hooking" for credential theft... There's T1056 Input Capture, .001 Keylogging. No.

The best fit for inline hooking as an interception primitive: MITRE actually lists "Process Injection: Process Hollowing" etc., but there is a technique specifically for API hooking? Hmm, historically "Hooking" was a technique T1179 in ATT&CK! Yes — T1179 "Hooking" — it's deprecated/revoked. T1179 Hooking was revoked and merged. Let me recall: T1179 Hooking was deprecated in ATT&CK v8 (October 2020), merged into... I believe it was revoked without a direct replacement, with guidance pointing to T1055 Process Injection or T1574 Hijack Execution Flow. 

The rule says: "pick one you are confident about; if genuinely unsure, use the closest parent technique ID". I'm confident T1179 existed but was revoked. Using a revoked ID is risky. The closest current technique: T1055 Process Injection — since inline hooking requires modifying another (or same) process's memory and redirecting execution. But if the hook is in the implant's own process (self-hooking for ETW/AMSI muffling), it's more like T1562.001 Impair Defenses: Disable or Modify Tools.

Given the card covers red-team inline hooking generally — for credential theft, API interception, process hiding (hooking NtQuerySystemInformation), and ETW muffling — the primary use described in the material is intercepting function calls. T1055 (Process Injection) is the commonly cited mapping for user-mode API hooking. I'll use `mitre: T1055` with `mitre_secondary: [T1562.001]` since impairing defensive tools (ETW muffle hooks) is a documented use. That seems defensible.

Hmm, but let me reconsider. The vault INDEX mentions T-016 maps ETW muffling etc. The technique card here is about the hooking primitive itself. MITRE: T1055 is "Process Injection" — adversaries inject code into processes. Inline hooking modifies in-memory code (of own process or another). Many public write-ups map userland hooking to T1055. I'll go with T1055, secondary T1562.001. Actually the instructions say "pick the single best-fit ATT&CK technique ID" for `mitre`, and secondary list optional. I'll do mitre: T1055, mitre_secondary: [T1562.001].

Tags (5-10 kebab-case): inline-hook, trampoline, byte-patching, api-interception, mov-rax-jmp-rax, prologue-patch, function-hooking, x64-hook-stub, self-hooking, edr-evasion. Maybe: [inline-hook, trampoline, byte-patching, api-interception, x64-hook-stub, prologue-patching, etw-muffling, process-hiding]. Let me pick 7-8: ['inline-hook', 'trampoline', 'byte-patching', 'api-interception', 'x64-hook-stub', 'prologue-patching', 'etw-muffling', 'process-hiding'].

Tier: B (from spec). Category: edr-evasion — hmm. Is edr-evasion the right category? The enum includes edr-evasion. The spec says proposed category edr-evasion. The technique enables interception of API calls — used for self-hiding and telemetry muffling which is EDR evasion-adjacent, but it's also a general post-exploitation primitive. The spec says "You may adjust if the atlas material clearly supports a different choice — explain in Why It Matters". I think edr-evasion is acceptable as default per spec directive ("Use the canonical name and category above as strong defaults"). I'll keep edr-evasion.

Now the body sections:

# Inline Hook Implementation: Red-Team Hooking Mechanics — <purpose line>

Title format: `# <Technique Name> — <One-Line Purpose>`. E.g. "# Inline Hook Implementation — Byte-Level Function Interception via Prologue Patching".

## Summary
3-5 sentences. First sentence standalone. E.g.: "Inline hooking overwrites the first bytes of a target function with an unconditional jump to an implant-controlled function, redirecting every subsequent call through attacker code before (optionally) reaching the original implementation." Mention: primitive = direct modification of executable code in memory (VirtualProtect + byte patch); operators use it for credential theft, API logging, process hiding (NtQuerySystemInformation), ETW/telemetry muffling from within the implant itself; primary detection surface = in-memory code integrity checks comparing module .text against disk image (e.g., pe-sieve, EDR memory scanners) and the VirtualProtect call turning code pages writable.

## Mechanism
Numbered steps from unit 1 (read and save 5+ bytes, patch in jump, hook executes, clean up patched bytes, execute original), unit 8 (mov rax, imm64; jmp rax), units 9-11 (trampoline to avoid infinite loop when calling original NtQuerySystemInformation).

Steps:
1. Resolve target function address (PEB walk / GetProcAddress / export table walk).
2. Change memory protection of the target page to writable (VirtualProtect / NtProtectVirtualMemory — code pages are PAGE_EXECUTE_READ by default).
3. Read and save the original bytes at the hook site (material says 5+ bytes; for x64 absolute jump stub, 12 bytes: 48 B8 <8-byte imm> FF E0). Note: material says "Read and save 5+ bytes of the function" — for 32-bit E9 rel32 it's 5 bytes; for the x64 mov rax/jmp rax stub it's 12 bytes. I should note both, grounded: unit 1 says 5+ bytes; unit 8 shows the x64 stub mov rax + jmp rax. The 12-byte length of `mov rax, imm64; jmp rax` (48 B8 xx*8 = 10 bytes, FF E0 = 2 bytes = 12 bytes) is well-established. Careful about instruction-boundary alignment — the material doesn't discuss disassembly length explicitly. Well-established knowledge: you must save whole instructions; a length-disassembler is typically used. I can state this as established practice without attributing to material? Rule 4 allows well-established documentation. I'll phrase carefully: "The saved byte count must cover whole instructions — patching 12 bytes that split an instruction boundary corrupts the trampoline." That's established knowledge.
4. Write the jump stub over the prologue: for x64, `mov rax, <hook addr>` (48 B8 + 8 bytes) then `jmp rax` (FF E0), 12 bytes total, padding any remainder with NOPs (unit 8 shows nop nop nop after jmp rax). For 32-bit, E9 rel32 (5 bytes).
5. Build the trampoline: allocate executable memory; copy the saved original bytes; append a jump back to target_func + N (the first byte after the patched region). 
6. Hook function executes on every call; it can inspect/modify arguments, call the trampoline to invoke the original, then inspect/modify the return value (e.g., unlink a process entry from the SYSTEM_PROCESS_INFORMATION linked list returned by NtQuerySystemInformation).
7. Cleanup/unhook: restore saved bytes and original protection (unit 1: "Clean up patched bytes; Execute original function").

Also mention hook placement options from unit 1: beginning (prologue), mid-function, or end of function (return-value interception).

## OS Internals Context
- Code pages of loaded DLLs are PAGE_EXECUTE_READ (copy-on-write image pages); writing requires NtProtectVirtualMemory to add write — this triggers VAD/protection-change telemetry and makes the page private (copy-on-write), which memory scanners detect because the in-memory .text diverges from the disk image.
- x64 JMP rel32 (E9) has ±2GB range — a remote hook buffer may be beyond that from the target, hence the material's mov rax, imm64; jmp rax absolute stub (unit 8). RAX is volatile in the Microsoft x64 ABI (caller-saved, not used for argument passing — args are RCX, RDX, R8, R9), so clobbering RAX in the prologue is safe.
- ntdll function prologue: `mov r10, rcx; mov eax, <SSN>` (4C 8B D1 B8 xx xx xx xx) — 8 bytes before `syscall`. Unit 8's slide shows this: "mov r10, rcx / mov eax, 41" replaced by the hook stub. This matters: hooking at func+0 overwrites the SSN load, so the trampoline must execute those saved bytes before jumping back.
- Infinite loop mechanics: the hook function calling the original re-enters the hook (unit 10) — the trampoline exists to execute the overwritten prologue bytes and jump past the patched region into func+N.
- PEB walking / export resolution to obtain the function address (unit 1 "Obtain memory address of function").
- Wow64: units 6-7 mention hooking in Wow64 processes requires dealing with Heaven's Gate and separate 32-bit ntdll — but the member note scopes to units 1, 8-11. I can mention Wow64 briefly since units 6-7 are in the same atlas part and discuss hooking Wow64 — the member note's source_units are ['unit 1', 'unit 8', 'unit 9', 'unit 10', 'unit 11'] though. The note text only describes units 1, 8-11. I should stay within the member notes' scope for claims, but OS Internals Context may include established knowledge. I'll mention Wow64 hooking briefly as a boundary consideration flagged by the atlas part (units 6-7 exist in the provided atlas material, so a passing mention is grounded). Actually rule says member notes are what the card is built from, but the atlas material is provided in full for factual grounding. Units 6-7 discuss Heaven's Gate hooking: 32-bit processes on 64-bit systems transition to 64-bit code; ntdll has both versions; hooking in a Wow64 environment requires handling both. I can include a short paragraph on this, citing it as from the same atlas part. That adds depth. Good.
- Detection-adjacent internals: EDRs place exactly these hooks on ntdll; the implant performing the same writes triggers the same integrity telemetry (PatchGuard is kernel-only; user-mode has no integrity enforcement, which is why it works at all).

## Key Implementation Details
None of the provided Rust files implement byte-patching inline hooks:
- amsi_page_guard.rs explicitly avoids inline hooks ("No inline hooks (zero byte writes to amsi.dll .text)") — PAGE_GUARD one-shot.
- ki_step_over.rs bypasses EDR inline hooks via DR0-DR3 hardware breakpoints and a Wow64PrepareForException callback pointer overwrite — a data-pointer patch in .rdata, not a code-prologue patch with a trampoline. It verifies `0xE9` at func+3 to detect EDR hooks.
- overload.rs is module overloading/manual mapping.
So: `**No current implementation in the HUGIN source.**` Then a paragraph on what an implementation would look like: resolve target via crate::resolve::find_module_base + resolve_export_by_name; allocate RX trampoline via NtAllocateVirtualMemory (RecycledGate); save N bytes; patch via NtProtectVirtualMemory + memcpy; hook stub `mov rax, imm64; jmp rax` as a const byte array; store original bytes in a struct with RAII restore.

## Why It Matters
T-016 documents defeating EDR-side hooks (unhooking, hardware-breakpoint stepover, PAGE_GUARD); none of those implement implant-side hooking. The vault has no card describing how to place a hook — yet hooking is the primitive behind process hiding (NtQuerySystemInformation), credential interception, and in-implant ETW/AMSI muffling at call sites other than the ones T-016's techniques cover. This card fills that gap: the mechanics of byte-patching, trampoline construction, and x64 stub layout that any future implant-side interception feature requires. Keep 2-4 sentences.

## Detection Considerations
Material: unit 1 lists the steps but does not discuss detection explicitly. The provided source files (though not implementations) contain relevant OPSEC notes: amsi_page_guard.rs says "No inline hooks (zero byte writes to amsi.dll .text)" as an OPSEC property — implying byte writes to DLL .text are a detection surface. T-016's NTDLL unhooking entry implies EDRs detect/are affected by .text divergence... hmm, actually T-016 NTDLL unhooking is implant-side restoring. The ki_step_over.rs comment: "Instead of unhooking (which alerts telemetry)" — implies patch/unpatch operations on hooked code alert telemetry.

The rule: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.' Do not invent detections." The atlas units 1, 8-11 don't discuss detection. But the provided inputs (source file comments, T-016 card) do touch on detection of byte-patching: ki_step_over exists precisely because unhooking alerts telemetry; amsi_page_guard markets "no inline hooks" as an OPSEC win. These are in my inputs, so referencing them is grounded — they're "related T-NNN cards provided" and "source provided". I can say: training material (atlas units) does not discuss detection for this technique; however, the HUGIN source's OPSEC comments characterize byte writes to DLL .text as a detection surface (amsi_page_guard.rs, ki_step_over.rs). I'll structure it as: the atlas material doesn't cover detection; note the in-input evidence that .text patching is the surface the rest of the vault works to avoid. That stays honest.

Telemetry sources: none documented in atlas — I'll say so. I can mention that T-016's NTDLL unhooking entry implies integrity comparison against disk copies as a defensive capability, but careful — T-016 documents unhooking as evasion, which implies EDRs check. Actually the T-016 card text for NTDLL unhooking says "Reads fresh ntdll.dll from disk / Copies clean .text over hooked in-memory version" — that's implant-side restoration, doesn't state detection. The KiStepOver entry says "instead of unhooking, which triggers telemetry" — that IS a detection claim in the provided T-016 card. And "Sets HW breakpoint on hooked instruction (instead of unhooking, which triggers telemetry)". Good, grounded.

I'll write Detection Considerations with: training material does not discuss detection directly; cross-vault evidence: ki_step_over's premise is that byte-patch/unpatch cycles on ntdll .text trigger EDR telemetry; amsi_page_guard's OPSEC header lists "No inline hooks (zero byte writes to amsi.dll .text)" as a property. Residual artifacts: writable-then-restored code pages (page protection change), private (copy-on-write) pages in image .text, trampoline allocation (RX/RWX private memory). Hmm — are those "inventing detections"? The rule is strict: "Do not invent detections." I'll keep to: state material doesn't cover detection, then cite the two in-input OPSEC statements as the only detection-related guidance, and stop. Maybe a conservative line that hook restoration requires the saved original bytes to be kept in memory. That's an artifact of the mechanism, not a detection claim. Keep it minimal and clearly attributed.

Actually, I can frame: "The atlas units covering this technique do not discuss detection. The only detection-relevant statements in the provided material come from the HUGIN source's OPSEC notes on adjacent techniques: ..." That's fully grounded.

## Related Techniques
- T-016 EDR Evasion Suite — inverse relationship: T-016 defeats EDR-placed inline hooks (KiStepOver steps over them, NTDLL unhook restores them); T-030 documents placing hooks implant-side. Also T-016's ETW muffling fallback "patches EtwEventWrite to xor eax,eax;ret" is itself a byte patch of a function — a degenerate inline hook without a trampoline. That's a nice grounded connection: T-016 already contains one primitive byte-patch (EtwEventWrite → xor eax,eax;ret) but no trampoline-based interception. Good.

Only T-016 is in would_relate_to. Keep to that one entry. Rule 9: restraint.

## References
- Atlas material: atlas-exploit-dev-part12.md (units 1, 8-11; adjacent Wow64 hooking context in units 6-7)
- MITRE ATT&CK: T1055 URL https://attack.mitre.org/techniques/T1055/ ; secondary T1562.001 https://attack.mitre.org/techniques/T1562/001/
- LGTM notes: lgtm:inline-hook-implementation-side
- Public references: SANS SEC670 "Red Teaming Tools: Developing Custom Tools for Windows" (named in atlas as the source). The material names SANS SEC670. Good.

## Source Reference
"No current implementation. See atlas material and MITRE reference for public tooling." Plus maybe note the adjacent files. The template: `<If no source: "No current implementation. See atlas material and MITRE reference for public tooling.">` — I can add a sentence noting ki_step_over.rs/amsi_page_guard.rs deliberately avoid this technique. That's useful and grounded.

Frontmatter details:
- id: T-030
- name: Inline Hook Implementation: Red-Team Hooking Mechanics — name field "4-8 words". "Inline Hook Implementation: Red-Team Hooking Mechanics" — with colon. Count words: Inline(1) Hook(2) Implementation(3) Red-Team(4) Hooking(5) Mechanics(6) — 6 words plus colon. Fine.
- category: edr-evasion
- tier: B
- crate: none
- source_file: "none"
- mitre: T1055
- mitre_secondary: [T1562.001]
- tags: [inline-hook, trampoline, byte-patching, api-interception, x64-hook-stub, prologue-patching, etw-muffling, process-hiding] — 8 tags.
- origin: atlas-synthesis
- member_notes: ['lgtm:inline-hook-implementation-side']

Word count: need 800+ body words, target 1200-1800. Let me draft thoroughly.

Banned words check: avoid elegant, beautiful, clever, textbook, impressive, clean (careful — "AMSI_RESULT_CLEAN" appears in quotes from source which is fine, but don't use "clean" descriptively; also T-016 quote "Copies clean .text" — quoting is fine but better to avoid), slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Avoid "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". No first person, no rhetorical questions.

Careful with "textbook" — I need to refer to "the 'textbook' implementation" — banned. Use "reference implementation" or "canonical implementation" instead.

Draft the card.

Title: `# Inline Hook Implementation — Redirecting Function Execution via Prologue Byte Patching`

Summary draft:
"Inline hooking redirects execution of an existing function by overwriting its opening bytes with an unconditional jump into implant-controlled code, which runs on every subsequent call before the original logic executes. The primitive exploited is the writability of user-mode code pages: Windows enforces no integrity check on a loaded module's .text section, so any process with write access to its own (or another process's) address space can repoint a function's first instructions. The training material walks the implementer-side workflow — resolving the target address, saving the original bytes, patching in a jump, running hook code, and restoring bytes on cleanup — including the x64-specific `mov rax, imm64; jmp rax` stub and the trampoline required to call the original function without infinite recursion. Operators use inline hooks to intercept API calls for logging, credential theft, return-value manipulation such as hiding processes from NtQuerySystemInformation results, or muffling telemetry from within the implant itself. The primary detection surface is in-memory code integrity: a patched .text section diverges from the module's on-disk image, and the protection change required to write the patch is itself observable."

That's 5 sentences. Good.

Mechanism steps (numbered, concrete):

1. Resolve the target function's address. Material: "Obtain memory address of function" — via export table of the containing DLL (PEB walk + export parsing, or GetProcAddress in reference code).
2. Read and save the original bytes at the hook site. Material: "Read and save 5+ bytes of the function". For a 32-bit E9 rel32 patch, 5 bytes; for the x64 stub from unit 8, 12 bytes (10-byte mov rax, imm64 + 2-byte jmp rax). Must not split instructions — saved region must end on an instruction boundary (established requirement; a partial instruction in the trampoline corrupts execution). Also any leftover bytes before the next instruction boundary are padded with NOP — unit 8 shows three NOPs following jmp rax.
3. Make the target page writable. Image .text pages are PAGE_EXECUTE_READ; patching requires NtProtectVirtualMemory/VirtualProtect to add write access (PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY), restored afterward.
4. Write the jump stub over the prologue. x64 per unit 8: `48 B8 <imm64>` (mov rax, hook_addr) then `FF E0` (jmp rax), followed by NOP padding to the saved-length boundary. 32-bit: `E9 <rel32>`.
5. Allocate the trampoline: executable memory containing (a) a copy of the saved original bytes, (b) an absolute jump to target+N (first instruction after the patched region).
6. Hook function runs on each call: inspect/modify arguments, optionally invoke the trampoline to call the original, then inspect/modify the return value before returning to the real caller.
7. Call the original through the trampoline, never through the patched entry point — unit 10's example: hook code calling NtQuerySystemInformation directly re-enters the hook ("Could get stuck in a loop").
8. On cleanup, restore the saved bytes over the patched region and restore original page protection ("Clean up patched bytes; Execute original function").
9. Hook placement is not restricted to the prologue: unit 1 lists hooking at the beginning, mid-function, or end (end-of-function placement intercepts return values after original logic runs).

OS Internals Context:

- Image pages & COW: DLL .text mapped from SEC_IMAGE sections; pages are shareable read-only/execute with copy-on-write semantics when written. Writing through a writable mapping makes the page private — the divergence between private page and disk image is what integrity scanners compare. (Windows Internals established.)
- Why mov rax/jmp rax on x64: E9 rel32 reaches only ±2GB; the x64 address space places allocations arbitrarily far apart, so a 5-byte relative jump cannot reliably reach an allocated hook buffer. RAX is volatile under the Microsoft x64 calling convention and carries no incoming arguments (RCX, RDX, R8, R9), so clobbering it in a prologue hook preserves the call contract. Unit 8's example shows the stub replacing the first instructions of the function, padded with NOPs to the next boundary.
- ntdll stub layout: unit 8's slide shows the hooked function's original start as `mov r10, rcx; mov eax, 41` — the standard ntdll syscall stub prologue (SSN 0x41). A prologue hook overwrites the SSN load itself; the trampoline must replay `mov r10, rcx; mov eax, 41` before jumping back, or the subsequent syscall executes with the wrong service number. This is the exact layout EDR hooks occupy (the 0xE9 at func+3 that crowd's ki_step_over.rs checks for sits immediately after `mov r10, rcx` — the EDR preserves the SSN load and hooks after it).
- Return-value manipulation via end-of-function hooks: unit 1 lists hook-end placement; combined with unit 10's NtQuerySystemInformation example, the canonical use is post-processing the SYSTEM_PROCESS_INFORMATION chain to unlink a process.
- Wow64 boundary: the same atlas part (units 6-7) covers hooking from a Wow64 process: 32-bit ntdll transitions through Heaven's Gate into 64-bit code, so a 32-bit inline hook placed on wow64 ntdll functions intercepts before the transition; hooking 64-bit ntdll from a 32-bit implant requires crossing the gate. The member note scopes T-030 to the native x64 workflow; the Wow64 variant is flagged here as a boundary consideration only.

Key Implementation Details:

State no implementation. Verify each provided file:
- amsi_page_guard.rs: installs PAGE_GUARD + VEH; its OPSEC header explicitly states "No inline hooks (zero byte writes to amsi.dll .text)". Not an implementation.
- ki_step_over.rs: bypasses EDR-placed inline hooks using DR0-DR3 hardware breakpoints and a Wow64PrepareForException callback pointer overwrite in .rdata. The only patch it performs is an 8-byte data pointer swap in a read-only data section — no code-byte patching, no trampoline. Not an implementation. Its `is_hooked` check (`*(func+3) == 0xE9`) detects EDR inline hooks.
- overload.rs: module overloading / manual map; not an implementation.

Then the required sentence: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (SANS SEC670)."

Then one paragraph describing what an implementation would look like: a Hook struct holding target address, saved byte array (up to 16 bytes), patched length, trampoline pointer, and original page protection; resolution through crate::resolve::find_module_base + resolve_export_by_name to avoid GetProcAddress surface; trampoline allocation via crate::recycled::nt_allocate_virtual_memory; patch and restore through crate::recycled::nt_protect_virtual_memory; the 12-byte stub as a const byte template with the hook address patched in; Drop impl restoring bytes (matching the vault's RAII guard pattern used by stack_spoof's SpoofGuard).

Why It Matters:
T-016 documents how to defeat hooks an EDR placed (KiStepOver, NTDLL unhook) but not how an implant places its own; the only implant-side byte patch in the vault is T-016's ETW fallback (EtwEventWrite → xor eax,eax;ret), which severs the function outright rather than intercepting it. Trampoline-based inline hooking is the missing primitive for interception use cases the material names — filtering NtQuerySystemInformation to hide processes, logging or stealing credentials from authentication APIs, modifying arguments in flight — and for muffling telemetry at call sites that T-016's zero-write techniques do not cover. It earns its own card because the x64 stub layout, trampoline construction, and instruction-boundary constraints are reusable mechanics independent of any single evasion target.

Detection Considerations:
Atlas units do not discuss detection. Per inputs: two grounded statements. T-016's KiStepOver entry states the premise "instead of unhooking, which triggers telemetry" — patch/restore cycles on ntdll .text are observable to EDRs. amsi_page_guard.rs's OPSEC header lists "No inline hooks (zero byte writes to amsi.dll .text)" as a deliberate property, characterizing byte writes to DLL .text as a detection surface. Residual artifacts implied by the mechanism itself: the saved-bytes buffer and trampoline allocation must persist for the hook's lifetime, and the target page's protection must be changed twice (patch and restore). I'll phrase these carefully as mechanism artifacts rather than detection claims... Hmm. The rule says don't invent detections. Listing "residual artifacts" that follow mechanically from the technique (a persistent executable trampoline allocation, COW-private .text pages) — the COW page private thing is established Windows behavior and the detection relevance is a direct mechanical consequence. I think it's fine if framed as "the technique leaves" rather than "sensors detect X". Keep it tight and clearly bounded.

Let me write: 
- "Training material does not discuss detection for this technique." — then say: The provided inputs contain two adjacent data points: ... 
- Residual artifacts: per the mechanism — writable→restored code page transitions, a persistent executable trampoline buffer, saved-bytes storage.

Actually to be safest: lead with the exact sentence "Training material does not discuss detection for this technique." Then a short paragraph: "Two detection-relevant statements exist elsewhere in the provided inputs..." This satisfies the rule (the sentence appears) while adding grounded context. I think that's the best approach.

Related Techniques:
- T-016 EDR Evasion Suite — inverse and complement: T-016's KiStepOver and NTDLL unhook defeat EDR-placed inline hooks on ntdll; T-030 documents placing the same class of hook implant-side. T-016's ETW fallback (patching EtwEventWrite to xor eax,eax;ret) is a byte patch without a trampoline — T-030 supplies the general interception mechanics that patch lacks.

References:
- Atlas material: atlas-exploit-dev-part12.md (units 1, 8, 9, 10, 11; Wow64 hooking context in units 6-7)
- MITRE ATT&CK: T1055 Process Injection — https://attack.mitre.org/techniques/T1055/ ; T1562.001 Impair Defenses: Disable or Modify Tools — https://attack.mitre.org/techniques/T1562/001/
- LGTM notes: lgtm:inline-hook-implementation-side
- Public references: SANS SEC670, "Red Teaming Tools: Developing Custom Tools for Windows" (source document named in atlas units)

Source Reference:
No current implementation. Adjacent files crowd/src/ki_step_over.rs and crowd/src/amsi_page_guard.rs deliberately avoid this technique. See atlas material and MITRE reference for public tooling.

Hmm wait, about `mitre` — let me double-check T1055 is reasonable. MITRE T1055 Process Injection: "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges." Inline hooking within one's own process isn't classic injection, but hooking another process's functions (credential theft in lsass/browser) involves write to another process's memory. Public tooling mappings: many map "API hooking" to T1055 or to revoked T1179. Given rule 4 ("if genuinely unsure, use the closest parent technique ID"), T1055 is the defensible pick, with T1562.001 secondary for the telemetry-muffling use. Good.

Name in frontmatter: "Inline Hook Implementation: Red-Team Hooking Mechanics" — hmm, frontmatter name field should match canonical name. OK.

Now let me count approximate body words as I draft — aim ~1300-1500.

One more check on the x64 stub bytes: `mov rax, imm64` = REX.W + B8 + imm64 = 48 B8 + 8 bytes = 10 bytes. `jmp rax` = FF E0 = 2 bytes. Total 12 bytes. Correct. The unit 8 slide shows "mov rax, 1122334455667788 / jmp rax / nop nop nop" — 12 bytes then 3 NOPs suggests patching over a 15-byte span? Or NOPs to fill out to an instruction boundary after 12 bytes — if the first three instructions total 15 bytes, pad with 3 NOPs. I'll describe it as NOP padding to the saved-length boundary, consistent with the slide.

Also unit 1: "Read and save 5+ bytes" — I'll present 5 bytes as the 32-bit E9 case and 12 for x64 mov rax/jmp rax, both grounded (unit 1's 5+ and unit 8's stub).

Regarding "hook beginning / mid / end of function" — unit 1. Include.

Also mention thread-safety? Not in material. Skip — rule 3 (no variants/suggestions) and material authority. Actually a brief mention that patching a function while another thread executes it can crash — not in material; skip. Keep to material + established internals.

The trampoline flow per unit 11: "Original func → Hook func → Trampoline" — execution: caller → original func entry (patched) → jump to hook func → hook calls trampoline → trampoline replays saved bytes → jumps to original+N → original completes → returns to hook → hook returns to caller. Describe in Mechanism.

Also the infinite-loop explanation: units 9-10: hooked NtQuerySystemInformation; hook calls original NtQuerySystemInformation; enters loop. The trampoline bypasses the overwritten hook bytes and reaches the original function's code.

Now, write the final card. Ensure exact section order and headers. Frontmatter tags 8 items. Ensure no banned words. Check: "textbook" — avoid. "clean" — avoid except inside quoted identifiers like AMSI_RESULT_CLEAN if needed (not needed here). "notable" — avoid. "robust" — avoid. "essentially" — avoid.

Watch the Key Implementation Details required sentence: the template says write exactly that sentence with the blank filled: "This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>." — source language: C/C++ (SANS SEC670 course code). Good.

Let me also double check frontmatter `tier: B` — spec proposes B. Fine.

Length: let me write generously, ~1400 words body.

Write it now.