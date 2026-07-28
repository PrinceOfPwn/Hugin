---
id: T-030
name: 'Inline Hook Implementation: Red-Team Hooking Mechanics'
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1055
mitre_secondary: [T1562.001]
tags: [inline-hook, trampoline, byte-patching, api-interception, x64-hook-stub, prologue-patching, etw-muffling, process-hiding]
origin: atlas-synthesis
member_notes: ['lgtm:inline-hook-implementation-side']
---

# Inline Hook Implementation — Redirecting Function Execution via Prologue Byte Patching

## Summary

Inline hooking redirects execution of an existing function by overwriting its opening bytes with an unconditional jump into implant-controlled code, which then runs on every subsequent call before the original logic executes. The primitive exploited is the absence of any user-mode integrity enforcement on a loaded module's `.text` section: any code that can obtain write access to the page can repoint a function's first instructions. The training material documents the implementer-side workflow — resolve the target address, read and save the original bytes, patch in the jump, run the hook function, restore the bytes on cleanup — along with the x64-specific `mov rax, imm64; jmp rax` stub and the trampoline required to invoke the original function without infinite recursion. Operators use inline hooks to intercept API calls for logging, credential theft, return-value manipulation such as hiding processes from `NtQuerySystemInformation` results, or muffling telemetry from inside the implant's own process. The primary detection surface is in-memory code integrity: a patched `.text` diverges from the module's on-disk image, and the page-protection change required to write the patch is itself observable.

## Mechanism

1. Resolve the target function's address. The material's first listed step is "Obtain memory address of function" — in reference implementations this is an export-table lookup against the containing DLL (PEB walk plus export parsing, or `GetProcAddress` in course code).
2. Read and save the original bytes at the hook site. The material specifies "Read and save 5+ bytes of the function." Five bytes covers a 32-bit `E9 rel32` patch; the x64 stub from the material (`mov rax, imm64` — 10 bytes, `48 B8` + 8-byte immediate; `jmp rax` — 2 bytes, `FF E0`) consumes 12 bytes. The saved region must end on an instruction boundary: a partial instruction replayed in the trampoline corrupts execution. Any gap between the stub length and the next instruction boundary is padded with NOPs — the material's x64 slide shows three `nop` instructions following `jmp rax`.
3. Make the target page writable. Loaded image `.text` pages are execute-read; the patch requires a protection change via `NtProtectVirtualMemory`/`VirtualProtect` before the write and a restore afterward.
4. Write the jump stub over the prologue. On x64, per the material: `48 B8 <hook_address>` followed by `FF E0`, then NOP padding to the saved-length boundary. On 32-bit, `E9 <rel32>`.
5. Build the trampoline in allocated executable memory: a copy of the saved original bytes, followed by an absolute jump back to `target + N`, where N is the length of the patched region (the first instruction past the overwritten bytes).
6. Redirected flow on each call: caller invokes the target, the patched prologue jumps to the hook function, the hook inspects or modifies arguments, then invokes the trampoline to reach the original logic. The trampoline replays the saved prologue bytes and jumps into the original function past the patch. The original returns to the hook, which can inspect or modify the return value before returning to the real caller. The material's "Trampoline Steps" diagram shows exactly this triangle: Original func → Hook func → Trampoline.
7. Call the original only through the trampoline. The material's example is explicit: hook code inside a hooked `NtQuerySystemInformation` that calls `NtQuerySystemInformation` directly re-enters the hook — "Could get stuck in a loop." The trampoline exists to bypass the overwritten hook bytes and reach the original function's code.
8. On cleanup, restore the saved bytes over the patched region and restore the original page protection ("Clean up patched bytes; Execute original function").
9. Hook placement is not restricted to the prologue. The material lists hooking at the beginning of the function, mid-function, or end of function; end-of-function placement intercepts the return value after the original logic has run, which suits result-filtering use cases.

## OS Internals Context

DLL `.text` pages are mapped from `SEC_IMAGE` sections as shareable execute-read pages. Writing to such a page through a writable mapping triggers copy-on-write: the affected page becomes private to the process, and its contents diverge from the backing image on disk. Windows enforces no user-mode code integrity — PatchGuard protects kernel structures only — which is why the technique works at all, and why the private-page divergence is the artifact integrity scanners compare against.

The x64 stub shape is dictated by addressing range. A relative `E9` jump reaches only ±2 GB from the patch site; in a 64-bit address space an allocated hook buffer can lie far outside that window. The material's `mov rax, imm64; jmp rax` sequence encodes a full 64-bit absolute target and is therefore position-independent. RAX is safe to clobber in a prologue hook: under the Microsoft x64 calling convention the first four integer arguments arrive in RCX, RDX, R8, and R9, and RAX is caller-saved with no incoming argument role.

The material's x64 slide shows the hooked function's original start as `mov r10, rcx; mov eax, 41` — the standard ntdll syscall stub prologue with SSN 0x41. A prologue hook placed at offset zero overwrites the SSN load itself, so the trampoline must replay `mov r10, rcx; mov eax, <SSN>` before jumping back; otherwise the subsequent `syscall` executes with a corrupted service number. This is the same real estate EDR user-mode hooks occupy: crowd's `ki_step_over.rs` detects EDR hooks by testing for `0xE9` at `func + 3`, immediately after the 3-byte `mov r10, rcx` (`4C 8B D1`) — the EDR preserves the SSN load and hooks after it, whereas the material's implant-side example replaces the prologue outright.

The material's canonical interception target is `NtQuerySystemInformation`: the hook calls the original through the trampoline, then post-processes the returned `SYSTEM_PROCESS_INFORMATION` linked list to unlink a chosen process entry before returning to the caller. This is return-path manipulation — the original executes fully, and only its output is altered.

The same atlas part flags a boundary consideration for Wow64. A 32-bit process on a 64-bit system transitions into 64-bit code through Heaven's Gate, and a Wow64 process carries both a 32-bit and a 64-bit ntdll. An inline hook placed on the 32-bit ntdll intercepts before the transition; hooking the 64-bit ntdll from a 32-bit implant requires crossing the gate first. The member note scopes this card to the native x64 workflow; the Wow64 variant changes only which module copy and which stub encoding the patch targets.

## Key Implementation Details

Verification of the provided Rust sources:

- `crowd/src/amsi_page_guard.rs` installs a PAGE_GUARD plus VEH interception on `AmsiScanBuffer`. Its OPSEC header explicitly states "No inline hooks (zero byte writes to amsi.dll .text)." It does not implement this technique.
- `crowd/src/ki_step_over.rs` bypasses EDR-placed inline hooks via DR0–DR3 hardware breakpoints and a `Wow64PrepareForException` callback pointer overwrite in ntdll's `.rdata`. Its only patch is an 8-byte data-pointer swap in a read-only data section — no code-byte patching, no trampoline. Its `0xE9`-at-`func+3` check detects inline hooks rather than placing them. It does not implement this technique.
- `crowd/src/overload.rs` implements module overloading and manual mapping. Unrelated.

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (SANS SEC670 course code).

An implementation consistent with vault patterns would center on a hook struct holding the target address, a saved-bytes buffer (16 bytes covers the 12-byte x64 stub plus boundary padding), the patched length, the trampoline pointer, and the original page protection. Target resolution would go through `crate::resolve::find_module_base` plus `crate::resolve::resolve_export_by_name` to avoid the `GetProcAddress` surface; trampoline allocation and the two protection changes would go through `crate::recycled` indirect syscalls (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`). The stub would be a 12-byte constant template with the hook address written into the immediate field, and a `Drop` implementation restoring the saved bytes, matching the RAII guard pattern used by `stack_spoof.rs`'s `SpoofGuard`.

## Why It Matters

T-016 documents defeating hooks an EDR placed — KiStepOver steps over them, NTDLL unhook restores the original `.text` — but no vault card documents placing a hook implant-side. The only implant-side byte patch in T-016 is the ETW fallback (`EtwEventWrite` → `xor eax,eax;ret`), which severs the function outright rather than intercepting it; it cannot filter results, modify arguments in flight, or steal credentials, because it has no trampoline and no call path to the original. Trampoline-based inline hooking supplies that missing interception primitive for the use cases the material names — process hiding via `NtQuerySystemInformation` result filtering, API logging, credential capture — and its x64 stub layout, instruction-boundary constraints, and recursion-avoidance mechanics are reusable independent of any single target.

## Detection Considerations

Training material does not discuss detection for this technique.

Two detection-relevant statements exist elsewhere in the provided inputs. T-016's KiStepOver entry is premised on "instead of unhooking, which triggers telemetry" — patch and restore cycles on ntdll `.text` are observable to EDRs. The `amsi_page_guard.rs` OPSEC header lists "No inline hooks (zero byte writes to amsi.dll .text)" as a deliberate design property, characterizing byte writes to DLL `.text` as the surface that alternative was built to avoid.

Residual artifacts follow from the mechanism itself: the trampoline and saved-bytes buffer must persist in allocated memory for the hook's lifetime; the target page's protection is changed twice (patch, restore); and the patched page becomes copy-on-write private, diverging from the module's disk image for as long as the hook is installed.

## Related Techniques

- **T-016 EDR Evasion Suite** — Inverse and complement: T-016's KiStepOver and NTDLL unhook defeat EDR-placed inline hooks on ntdll, while this card documents placing the same class of hook implant-side. T-016's ETW muffling fallback (patching `EtwEventWrite` to `xor eax,eax;ret`) is a byte patch without a trampoline — this card supplies the general interception mechanics that patch lacks.

## References

- Atlas material: atlas-exploit-dev-part12.md (units 1, 8, 9, 10, 11; Wow64 hooking context in units 6–7)
- MITRE ATT&CK: T1055 Process Injection — https://attack.mitre.org/techniques/T1055/ ; T1562.001 Impair Defenses: Disable or Modify Tools — https://attack.mitre.org/techniques/T1562/001/
- LGTM notes: lgtm:inline-hook-implementation-side
- Public references: SANS SEC670, "Red Teaming Tools: Developing Custom Tools for Windows" (source document named in the atlas units)

## Source Reference

No current implementation. Adjacent files `crowd/src/ki_step_over.rs` and `crowd/src/amsi_page_guard.rs` deliberately avoid this technique. See atlas material and MITRE reference for public tooling.