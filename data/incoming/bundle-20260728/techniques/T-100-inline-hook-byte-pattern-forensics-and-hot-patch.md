---
id: T-100
name: Inline Hook Byte-Pattern Forensics and Hot-Patch
category: edr-evasion
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/hells_gate.rs
mitre: T1055
tags: [inline-hook, byte-pattern, forensics, hot-patch, mov-edi-edi, hook-detection, unhooking, x86, x64, ntdll]
origin: atlas-synthesis
member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']
---

# Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue — Recognizing EDR Hook Signatures Before Unhooking

## Summary

Inline hook byte-pattern forensics is the discipline of recognizing the exact byte sequences EDR products write into ntdll syscall stubs when installing inline hooks, enabling an operator to enumerate which functions are hooked before deciding what to unhook. On x64, EDRs typically install a 15-byte trampoline consisting of `MOV rax, imm64` (`48 B8` followed by an 8-byte absolute address) and `JMP rax` (`FF E0`), using RAX as the intermediate register because x64 lacks a direct 8-byte immediate JMP instruction. On x86 (Wow64), EDRs exploit the `MOV EDI, EDI` hot-patch prologue and the five-NOP padding that precedes 32-bit exported functions: the 2-byte hot-patch slot is overwritten with a 2-byte short jump back into the 5-NOP pad, and the pad itself is patched with a 5-byte `JMP rel32` into the trampoline. The detection surface is minimal — reading ntdll stub bytes is a local memory read that does not trigger ETW or kernel callbacks.

## Mechanism

1. The operator enumerates all `Nt*` exports from ntdll by walking the PE export directory. The export directory is located via `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` in the optional header. `AddressOfNames`, `AddressOfNameOrdinals`, and `AddressOfFunctions` arrays provide name-to-address mapping.

2. For each `Nt*` export, the operator reads the first bytes of the stub to classify it as clean or hooked:

3. **64-bit clean stub detection**: A clean 64-bit syscall stub begins with the canonical 8-byte sequence `4C 8B D1 B8 XX XX 00 00` — `MOV r10, rcx` (`4C 8B D1`) followed by `MOV eax, imm32` (`B8` + 4-byte SSN). The high 2 bytes of the SSN immediate are `00 00` because syscall numbers are always less than 0x10000.

4. **64-bit hook detection**: If the first byte is `0xE9` (`JMP rel32`), the stub has been hooked with a 5-byte relative jump. Some EDRs use a 15-byte absolute trampoline instead: `MOV rax, <8-byte-address>` (`48 B8` + 8 bytes) followed by `JMP rax` (`FF E0`). The operator checks for the `48 B8` prefix to identify this hook variant. RAX is the intermediate register because x64 has no `JMP imm64` instruction — the architecture cannot encode an 8-byte immediate in a JMP opcode. The closest alternative, `JMP [rip+0]` (`FF 25 00 00 00 00`), is 6 bytes but requires a memory dereference and is less commonly used by EDRs.

5. **32-bit clean stub detection (Wow64)**: A clean 32-bit syscall stub begins with `MOV EDI, EDI` (`8B FF`), a 2-byte NOP-equivalent instruction that Microsoft placed at the start of all 32-bit exported functions as a hot-patch slot. This is followed by the function body. The 5 bytes preceding the function entry point (in the preceding function's padding or in inter-function alignment) are filled with `CC CC CC CC CC` (five INT 3 / NOP-equivalent padding bytes).

6. **32-bit hook detection (Wow64)**: The EDR overwrites the 2-byte hot-patch slot (`MOV EDI, EDI` at bytes [0..2]) with a 2-byte short jump (`EB FC` or similar) that jumps backward into the 5-byte NOP pad preceding the function. The EDR then overwrites the 5-NOP pad with a 5-byte `JMP rel32` (`E9` + 4-byte relative offset) that jumps into the EDR's trampoline. This technique preserves the original function body — only the hot-patch slot and preceding pad are modified — which means unhooking requires restoring both the 5-NOP pad and the `MOV EDI, EDI` prologue. Restoring only one leaves the function in a corrupted state.

7. The operator catalogs each hooked function, the hook variant (5-byte JMP, 15-byte absolute trampoline, or 32-bit hot-patch hijack), and the original bytes that must be restored during unhooking.

8. Before unhooking, the operator validates that the hook is an EDR hook and not a legitimate Microsoft patch (e.g., CVE hot-patches). Microsoft hot-patches use a different mechanism and should not be reverted.

## OS Internals Context

The `MOV EDI, EDI` hot-patch prologue is a design decision from the Windows XP SP2 / Windows Server 2003 SP1 era. Microsoft instructed compiler teams to insert a 2-byte `MOV EDI, EDI` instruction at the start of every exported function and pad 5 bytes before the function with `CC` (INT 3) instructions. This creates a 7-byte patch zone: the 5-byte pad can hold a `JMP rel32` instruction, and the 2-byte `MOV EDI, EDI` can be patched to a 2-byte short jump (`EB FC`) that jumps backward into the pad. This allows runtime patching of a function's execution flow without modifying the function body itself — the original instructions remain intact, and the patch can be atomically applied or reverted by swapping 2 bytes at the function entry.

On x64, the hot-patch prologue was abandoned because the 15-byte trampoline (`MOV rax, imm64; JMP rax`) is too large to fit in a hot-patch zone, and the architecture's RIP-relative addressing makes relative jumps more practical. EDRs on x64 typically overwrite the first 5 bytes of the stub with a `JMP rel32` or use a 14-byte `MOV rax, imm64; JMP rax` trampoline that overwrites the entire prologue.

The ntdll syscall stub layout on x64 is: `MOV r10, rcx` (2 bytes, `4C 8B D1`) — moves the Win32 API parameter from RCX to R10 because the syscall instruction uses RCX for the return address in the kernel. Then `MOV eax, imm32` (5 bytes, `B8 XX XX 00 00`) — loads the syscall service number (SSN) into EAX. Then `syscall` (2 bytes, `0F 05`) — transitions to kernel mode. Then `ret` (1 byte, `C3`). Total: 10 bytes minimum. SSN assignment is sequential by RVA order of the `Nt*` exports, which the Hell's Gate / Halo's Gate / Tartarus Gate SSN resolution cascade exploits.

## Key Implementation Details

The HUGIN source file `dark_crystal/crowd/src/hells_gate.rs` implements a simplified form of byte-pattern forensics for hook detection. Two functions are relevant:

- **`is_hooked(addr: *const u8) -> bool`**: Checks if the first byte at `addr` is `0xE9` (`JMP_REL32`). This is a single-byte check that detects the 5-byte relative jump hook variant on x64 but does not detect the 15-byte `MOV rax, imm64; JMP rax` trampoline variant (which begins with `48 B8`, not `E9`).

- **`read_ssn_from_stub(addr: *const u8) -> Option<u16>`**: Checks for the clean 64-bit stub prefix `4C 8B D1 B8` (`CLEAN_STUB_PREFIX`) and verifies the high 2 bytes of the SSN immediate are `00 00`. Returns `None` if the stub does not match, indicating a hook is present. This function implements the clean-stub recognition half of the forensics but does not classify the hook variant.

The implementation does not cover 32-bit (Wow64) hook detection. All functions in `hells_gate.rs` are gated on `#[cfg(target_arch = "x86_64")]` — the 32-bit variants return null or empty results. The `MOV EDI, EDI` hot-patch prologue, 5-NOP pad inspection, and 2-byte short jump detection are not implemented. An operator needing full 32-bit forensics would need to add a parallel implementation that checks the `8B FF` prologue and scans the preceding 5 bytes for a `JMP rel32` opcode.

## Why It Matters

T-016 documents the ntdll unhook operation but is implicitly x64-centric and does not document the byte-pattern fingerprints that identify hooked stubs before unhooking. This pre-unhook enumeration step has operational value: an operator who knows exactly which functions an EDR has hooked can selectively unhook only the functions needed for the current operation, reducing the detection surface of the unhook itself. The 32-bit hot-patch prologue protocol is critical because unhooking on Wow64 requires restoring both the 5-NOP pad and the `MOV EDI, EDI` prologue — restoring only one leaves the function corrupted and will cause crashes when the function is called.

## Detection Considerations

- **Telemetry sources**: Reading ntdll stub bytes is a local memory read via the process's own virtual address space. It does not trigger `NtReadVirtualMemory` (which is a cross-process API) or any ETW-TI event. No kernel callback fires for reading memory within the same process. Memory-scan heuristics that compare in-memory ntdll bytes against on-disk ntdll (e.g., PE-sieve's `.text` section diff) detect the hooks themselves, not the act of reading them.
- **Bypass options**: The byte-pattern read is inherently stealthy. The operator should avoid using `NtReadVirtualMemory` or `VirtualQuery` for the read — direct pointer dereference (`*(addr as *const u8)`) is sufficient and generates no system call.
- **Residual artifacts**: None from the forensics step itself. The subsequent unhooking operation (restoring original bytes) modifies ntdll `.text` section, which is detectable by PE-sieve, Moneta, and HollowsHunter via disk-versus-memory byte comparison.

## Related Techniques

- **T-016 EDR Evasion Suite** — ntdll unhook operation that this forensics step precedes; unhooking restores original bytes identified by these patterns
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution cascade that uses `is_hooked` and `read_ssn_from_stub` to detect and bypass hooked stubs

## References

- Atlas material: atlas-edr-evasion-part3 (units 1, 2, 3), atlas-edr-evasion-part2 (units 39, 40)
- MITRE ATT&CK: T1055 (Process Injection) — https://attack.mitre.org/techniques/T1055
- LGTM notes: lgtm:inline-hook-byte-forensics, lgtm:32-bit-hot-patch-prologue-coverage

## Source Reference

`dark_crystal/crowd/src/hells_gate.rs` — `is_hooked()` (line ~120) and `read_ssn_from_stub()` (line ~130) implement simplified 64-bit-only hook detection via byte-pattern checks. 32-bit hot-patch prologue forensics is not implemented.