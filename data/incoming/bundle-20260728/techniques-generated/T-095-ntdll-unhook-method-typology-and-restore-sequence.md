---
id: T-095
name: NTDLL Unhook Method Typology and Restore Sequence
category: edr-evasion
tier: A
crate: dark_crystal
source_file: none
mitre: T1562.001
mitre_secondary: [T1055]
tags: [ntdll-unhook, fresh-copy, suspended-copy, byte-patch, syscall-stubs, edr-hooks, restore-sequence, typology, decision-tree]
origin: atlas-synthesis
member_notes: [lgtm:coverage-gap-ntdll-restore-api-sequence, lgtm:cross-source-ntdll-unhook-convergence, lgtm:cross-source-unhook-method-typology]
---

# NTDLL Unhook Method Typology and Restore Sequence — Three Variants for Restoring EDR-Patched ntdll .text

## Summary

NTDLL unhooking removes EDR vendor inline hooks from ntdll.dll's `.text` section to restore the original syscall stub bytes. SEC670 documents three canonical variants: byte-level prologue patch (per-function search-and-replace of trampoline bytes), fresh-copy file mapping (whole `.text` restoration from on-disk ntdll via `CreateFileMapping` + `MapViewOfFile`), and suspended-copy snapshot (spawning a `CREATE_SUSPENDED` child process to harvest a clean `.text` section). All three variants are partial countermeasures: kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallback`) continue to observe operations after userland hooks are removed, so unhooking must be paired with operations that do not trigger callbacks. The fresh-copy variant is operationally preferred because it requires no per-function signature knowledge, no cross-process handle, and no SCM interaction — it uses only on-disk bytes that match the running build. The vault's T-016 card documents NTDLL unhook as part of the evasion suite but does not surface the three-method typology as a decision tree for variant selection.

## Mechanism

### Variant 1: Byte-Level Prologue Patch (Per-Function)

1. Identify the set of Nt* functions that the EDR has hooked. Detection: read the first bytes of each function and check for a `JMP` (0xE9) or `MOV RAX, [rip+offset]; JMP RAX` (0x48 0xB8 ... 0xFF 0xE0) prologue instead of the canonical `mov r10, rcx; mov eax, <SSN>; syscall` sequence.
2. For each hooked function, locate the original prologue bytes. Source: the on-disk ntdll.dll file — parse the PE headers to find the export RVA, translate RVA to file offset, read the original bytes from the file.
3. Calculate the number of bytes to restore: the EDR trampoline is typically 5 bytes (JMP rel32) or 12 bytes (MOV RAX, imm64; JMP RAX). The original prologue is also variable length depending on the SSN encoding.
4. Call `VirtualProtect` to change the `.text` page protection from `PAGE_EXECUTE_READ` to `PAGE_READWRITE`.
5. Call `RtlCopyMemory` (or `memcpy`) to overwrite the trampoline bytes with the original prologue bytes.
6. Call `VirtualProtect` to restore `PAGE_EXECUTE_READ`.

### Variant 2: Fresh-Copy File Mapping (Whole .text)

1. Call `CreateFileA` with `\\??\\C:\\Windows\\System32\\ntdll.dll` (or the appropriate NT path) to open the on-disk ntdll with `GENERIC_READ` access.
2. Call `CreateFileMappingW` with `PAGE_READONLY` and `SEC_IMAGE` (or `SEC_COMMIT`) to create a file mapping object.
3. Call `MapViewOfFile` to map the file into the current process's address space. The mapped view is a fresh copy of the on-disk ntdll image with the loader's relocations applied (if `SEC_IMAGE` is used) or as raw file data (if `SEC_COMMIT` is used).
4. Parse the mapped image's `IMAGE_NT_HEADERS` to locate the `.text` section: read `e_lfanew` from the DOS header, navigate to `IMAGE_NT_HEADERS->FileHeader->NumberOfSections`, iterate `IMAGE_SECTION_HEADER` entries to find the section named `.text`.
5. Extract the `.text` section's `VirtualAddress`, `VirtualSize`, and `PointerToRawData` from the `IMAGE_SECTION_HEADER`.
6. Calculate the source address: mapped view base + `PointerToRawData` (for `SEC_COMMIT`) or mapped view base + `VirtualAddress` (for `SEC_IMAGE`).
7. Calculate the destination address: loaded ntdll base + `.text` `VirtualAddress`.
8. Call `VirtualProtect` on the destination `.text` region to change protection to `PAGE_READWRITE`.
9. Call `RtlCopyMemory` to copy the entire `.text` section from the fresh mapping to the loaded ntdll.
10. Call `VirtualProtect` to restore `PAGE_EXECUTE_READ`.
11. Call `UnmapViewOfFile` and `CloseHandle` to release the mapping.

### Variant 3: Suspended-Copy Snapshot (Child Process)

1. Create a `CREATE_SUSPENDED` instance of a legitimate process (e.g., `notepad.exe` or `svchost.exe`) via `CreateProcessW` with `CREATE_SUSPENDED` flag.
2. The suspended process has a pristine ntdll.dll loaded (the EDR's hooks in the parent process are not inherited because the child gets its own fresh ntdll mapping from the section object).
3. Locate the child process's ntdll base address by reading its PEB via `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` → `PEB->Ldr->InLoadOrderModuleList` walk.
4. Call `NtReadVirtualMemory` (or `ReadProcessMemory`) to read the child's ntdll `.text` section bytes.
5. Call `VirtualProtect` on the parent's ntdll `.text` to change protection to `PAGE_READWRITE`.
6. Call `RtlCopyMemory` to copy the clean `.text` from the buffer (read from child) to the parent's ntdll.
7. Call `VirtualProtect` to restore `PAGE_EXECUTE_READ`.
8. Call `NtTerminateProcess` on the child process to clean up.

## OS Internals Context

The ntdll.dll `.text` section is mapped as `PAGE_EXECUTE_READ` in every process. EDR products that use inline hooks modify this region by calling `VirtualProtect` to temporarily set `PAGE_EXECUTE_READWRITE`, writing the trampoline bytes, then restoring `PAGE_EXECUTE_READ`. The `VirtualProtect` call on ntdll's `.text` section generates a `MiSetPageProtection` kernel event that some EDRs monitor via kernel callbacks — but the protection change is transient and the EDR itself performs it, so it is not flagged.

The three variants differ in their source of clean bytes. Variant 1 (byte-level) reads individual function prologues from the on-disk file. This requires knowledge of the trampoline layout (how many bytes to replace) which varies by EDR vendor and version. Variant 2 (fresh-copy) reads the entire `.text` section from the on-disk file via a mapped section. This requires no per-function knowledge — the entire `.text` is replaced. The on-disk file is the canonical source because the Windows loader reads ntdll.dll from `C:\Windows\System32\ntdll.dll` at process creation and the file is not modified by the EDR (the EDR hooks the in-memory copy, not the on-disk file). Variant 3 (suspended-copy) reads the `.text` from a freshly spawned process's memory. This requires a cross-process handle (`OpenProcess` with `PROCESS_VM_READ`) and a process creation event that triggers `PsSetCreateProcessNotifyRoutine` — some EDRs flag `CREATE_SUSPENDED` process creation as suspicious.

The `SEC_IMAGE` flag in `CreateFileMapping` tells the memory manager to interpret the mapped file as a PE image and apply relocations based on the image's `IMAGE_BASE_RELOCATION` table. This produces a mapped view where the `.text` section is at the same relative offset as in a loaded image, simplifying the copy operation. Without `SEC_IMAGE`, the mapping is a raw file view where the `.text` section is at `PointerToRawData` offset, which may differ from `VirtualAddress` due to `FileAlignment` versus `SectionAlignment` padding.

All three variants leave the kernel's `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, and `CmRegisterCallback` active. Operations performed after unhooking (process creation, handle manipulation, registry access) are still observed by the EDR's kernel-mode components. Unhooking must therefore be paired with indirect execution (syscalls that bypass the hooked stubs) and with operations that minimize kernel callback triggering.

## Key Implementation Details

The HUGIN file manifest references two source files that implement NTDLL unhooking:

- `dark_crystal/crates/core/src/experimental/evasion/ntdll_unhook.rs` — documented role: "NTDLL unhook via suspended process." This file implements Variant 3 (suspended-copy).
- `dark_crystal/crowd/src/ntdll_unhook_inject.rs` — documented role: "NTDLL .text restoration." This file implements a restoration variant.

These files were not provided in the current batch's source inputs for verification. Based on the file manifest's role descriptions, the suspended-copy variant (Variant 3) is implemented in the `dark_crystal/crates/core/` path. The file-mapping variant (Variant 2) is documented in SEC670 material with the exact `CreateFileA` → `CreateFileMapping` → `MapViewOfFile` → NT header lookup → `.text` `memcpy` sequence but its implementation in the HUGIN source requires verification against the actual file contents.

The `ki_step_over.rs` file in `dark_crystal/crowd/src/` implements an alternative to unhooking: rather than restoring ntdll's `.text`, it sets hardware breakpoints on the hooked instructions and intercepts the resulting single-step exceptions via a `Wow64PrepareForException` callback hook, redirecting execution to the `syscall` instruction past the hook. This approach avoids modifying ntdll's `.text` entirely, eliminating the `VirtualProtect` events and byte-comparison artifacts that PE-sieve (T-094) detects.

## Why It Matters

The vault's T-016 card documents NTDLL unhook as a single technique within the evasion suite. SEC670 material establishes that three distinct variants exist with different operational tradeoffs: byte-level patching requires per-function signature knowledge and is fragile across EDR version updates; fresh-copy file mapping is the operational default because it requires no signature knowledge and no cross-process handle; suspended-copy requires a process creation event that may trigger kernel callbacks. Operators selecting an unhook variant need this typology to choose the method appropriate to the target EDR's telemetry posture and the operator's knowledge of the EDR's hook layout.

## Detection Considerations

- **Telemetry sources**: `VirtualProtect` calls on ntdll's `.text` section generate `MiSetPageProtection` kernel events. Some EDRs monitor for protection changes on ntdll's `.text` pages. PE-sieve (T-094) can detect unhooking by comparing in-memory `.text` bytes against a cached baseline. `CreateFileA` on `ntdll.dll` may trigger file-system minifilter callbacks.
- **Bypass options**: The `ki_step_over.rs` approach avoids modifying ntdll's `.text` entirely by using hardware breakpoints to skip over hooks at execution time. This eliminates the `VirtualProtect` events and byte-comparison artifacts. The tradeoff is that DR0-DR3 registers are occupied and unavailable for other hardware breakpoint uses.
- **Residual artifacts**: The `MapViewOfFile` mapping (Variant 2) creates a VAD entry that Volatility can identify as a second mapping of ntdll.dll. The suspended child process (Variant 3) creates a process creation event and a handle in the parent process that handle-scanning EDRs may flag.

## Related Techniques

- **T-016 EDR Evasion Suite** — T-016 documents NTDLL unhook as part of the evasion suite; this card surfaces the three-method typology as a decision tree for variant selection based on EDR telemetry posture and hook layout knowledge

## References

- Atlas material: atlas-binary-analysis-part1, atlas-edr-evasion-part3, atlas-edr-evasion-part5
- MITRE ATT&CK: T1562.001 (https://attack.mitre.org/techniques/T1562/001)
- LGTM notes: lgtm:coverage-gap-ntdll-restore-api-sequence, lgtm:cross-source-ntdll-unhook-convergence, lgtm:cross-source-unhook-method-typology
- Public references: SEC670 EDR evasion module (Units 4-10, 24-28)

## Source Reference

File manifest references: `dark_crystal/crates/core/src/experimental/evasion/ntdll_unhook.rs` (suspended-copy variant), `dark_crystal/crowd/src/ntdll_unhook_inject.rs` (.text restoration). These files were not provided in the current batch for source verification. The `dark_crystal/crowd/src/ki_step_over.rs` file (provided and verified) implements an alternative bypass that avoids modifying ntdll's .text.