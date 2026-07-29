---
id: T-096
name: Binary Patching as Standalone Offensive Capability
category: edr-evasion
tier: B
crate: dark_crystal
source_file: dark_crystal/crates/core/src/experimental/pe_header_stomp.rs
mitre: T1562.001
mitre_secondary: [T1027]
tags: [binary-patching, memory-patch, disk-patch, pe-header-stomp, amsi-patch, etw-patch, checksum-adjustment, eat-modification, cfg-bitmap]
origin: atlas-synthesis
member_notes: [lgtm:binary-patching-as-standalone-capability, lgtm:binary-patching-as-distinct-technique]
---

# Binary Patching as Standalone Offensive Capability — Memory and Disk Modification of PE Images

## Summary

Binary patching is the practice of modifying PE image bytes in memory or on disk to change execution behavior, disable security monitoring, or create persistent redirection. Memory patching includes NTDLL unhooking (restoring original `.text` bytes over EDR trampolines), AMSI patching (overwriting `AmsiScanBuffer`'s prologue with a `ret` instruction to force an `AMSI_RESULT_CLEAN` return), and ETW patching (overwriting `NtTraceEvent`'s prologue to suppress event emission). Disk patching includes modifying an import directory to enable IAT hijacking on next load, adding export entries to redirect function resolution, or adjusting the checksum field after byte modifications to maintain PE integrity. SEC670 lists binary patching as a discrete capability in the Red Team Tools module. The vault references patching implicitly inside T-016 (NTDLL unhook, AMSI patch, ETW patch) but does not document it as a unified capability with the byte-alignment, checksum, and signature-discipline considerations that distinguish memory from disk patching.

## Mechanism

### Memory Patching

1. Locate the target function's virtual address. For ntdll functions, use `GetModuleHandleA("ntdll.dll")` + `GetProcAddress` or walk the PEB loader list. For `amsi.dll!AmsiScanBuffer`, load `amsi.dll` via `LoadLibraryA` and resolve the export.
2. Read the first N bytes of the function prologue to determine the current state (hooked versus unhooked, patched versus original).
3. Call `VirtualProtect` on the page containing the target bytes, changing protection from `PAGE_EXECUTE_READ` to `PAGE_EXECUTE_READWRITE`.
4. Overwrite the target bytes:
   - AMSI patch: write `ret` (`0xC3`) or `mov eax, AMSI_RESULT_CLEAN; ret` (`0xB8 0x00 0x00 0x00 0x00 0xC3`) at the function start, causing the function to return immediately without scanning.
   - ETW patch: write `ret` (`0xC3`) at `NtTraceEvent`'s start, suppressing event emission.
   - NTDLL unhook: write the original prologue bytes (see T-095 for the three unhook variants).
   - PE header stomp: write zeros (`0x00`) over the MZ magic, DOS stub, NT headers, and section table of a mapped PE image.
5. Call `VirtualProtect` to restore `PAGE_EXECUTE_READ`.
6. Call `FlushInstructionCache` to ensure the modified bytes are visible to the instruction pipeline (required on some architectures to invalidate stale I-cache lines).

### Disk Patching

1. Open the target PE file with `CreateFileA` using `GENERIC_READ | GENERIC_WRITE`.
2. Read the file into a buffer.
3. Parse the PE headers (`IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS`).
4. Modify the target bytes:
   - IAT hijack preparation: locate the `IMAGE_IMPORT_DESCRIPTOR` array in the `.idata` section. Modify the `Name` RVA to point to a different DLL name, or modify the `FirstThunk` entries to point to different function names. This redirects import resolution on next load.
   - EAT modification: locate the `IMAGE_EXPORT_DIRECTORY` in the `.edata` section. Add a new export entry by modifying `NumberOfFunctions`, inserting a name pointer in `AddressOfNames`, and adding the function RVA to `AddressOfFunctions`.
   - CFG bitmap editing: locate the `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` directory, read the `GuardCFCheckFunctionPointer` and `GuardCFFunctionTable`. Modify the bitmap entries to mark specific indirect call targets as valid, suppressing CFG violations.
5. Recalculate the PE checksum: read `OptionalHeader.CheckSum`, compute the new checksum via `CheckSumMappedFile` or manual calculation (sum of all 16-bit words in the file, added to the file size), and write the updated checksum to `OptionalHeader.CheckSum`.
6. Write the modified buffer back to the file.
7. Close the file handle.

## OS Internals Context

Memory patching targets the `.text` section of a loaded PE image. The `.text` section is mapped with `PAGE_EXECUTE_READ` protection by the Windows loader. The `VirtualProtect` call to change this to `PAGE_EXECUTE_READWRITE` generates a `MiSetPageProtection` kernel event. EDR products that monitor for protection changes on executable pages may detect this event. The modification itself is a user-mode write to the process's own address space — it does not trigger a kernel callback (`ObRegisterCallbacks` monitors handle-based cross-process access, not self-modification). PE-sieve (T-094) can detect memory patching by comparing in-memory `.text` bytes against the on-disk `.text` bytes.

Disk patching operates on the file before it is loaded. The PE checksum field in `OptionalHeader.CheckSum` is a 32-bit value computed as the sum of all 16-bit words in the file, added to the file size. Windows verifies this checksum for kernel-mode drivers (via `KeLoadImage`) and for some user-mode binaries (those compiled with `/INTEGRITYCHECK`). For most user-mode DLLs and executables, the loader does not verify the checksum, so patching the file without recalculating the checksum does not prevent loading. However, Authenticode signature verification checks the checksum: if the file is signed, modifying any byte invalidates the signature unless the signature is stripped or re-signed. Windows Defender's real-time protection scans files on write, so disk patching a file in a protected directory (like `C:\Windows\System32\`) triggers a real-time scan event.

The `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` directory contains the `IMAGE_LOAD_CONFIG_DIRECTORY` structure, which includes `GuardCFCheckFunctionPointer` (points to the CFG check function) and `GuardCFFunctionTable` (points to the CFG bitmap). Modifying the CFG bitmap to mark additional indirect call targets as valid allows patched code to make indirect calls to addresses that would otherwise trigger a CFG violation (`FAST_FAIL_CFG_CALL_TARGET_INVALID`). The bitmap is located in the `.data` section of the image and is writable in the loaded image.

## Key Implementation Details

The file `dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` implements a specific variant of memory patching: PE header stomping. The `stomp_pe_header` function takes a `base_address` and `header_size`, and calls `ptr::write_bytes(base_address, 0u8, header_size)` to zero the entire header region. The `stomp_own_pe_header` function reads the `IMAGE_DOS_HEADER` at the image base, validates the MZ magic (`0x5A4D`), reads `e_lfanew` at offset 0x3C to locate the NT headers, validates the PE signature (`0x00004550`), reads the `SizeOfHeaders` field from the `IMAGE_OPTIONAL_HEADER` (at offset 56 from the optional header start for both PE32 and PE32+), and calls `stomp_pe_header` with that size.

The `stomp_self_header` function locates the current process's image base via `gs:[0x60]` (PEB) and reads `PEB->ImageBaseAddress` at offset 0x10. It calls `VirtualProtect` to change the header region (0x1000 bytes) to `PAGE_EXECUTE_READWRITE`, calls `stomp_own_pe_header`, then restores the original protection. The function is gated behind the `pe_stomp` Cargo feature.

The `dark_crystal/crowd/src/ki_step_over.rs` file implements another form of memory patching: it overwrites the `Wow64PrepareForException` callback pointer in ntdll's `.rdata` section with a pointer to a custom exception handler. The `hook_exception_dispatcher` function locates the callback pointer by scanning `.rdata` for an `ANSI_STRING` pointing to "Wow64PrepareForException", then takes the next qword as the function pointer slot. It calls `VirtualProtect` to make the slot writable, writes the custom handler's address, and restores the protection.

## Why It Matters

The vault references binary patching implicitly across T-016 (NTDLL unhook, AMSI patch, ETW patch), T-017 (persistence via DLL modification), and T-020 (IAT camouflage). Each of these is a specific instance of the broader pattern of modifying PE bytes to change execution behavior. Documenting binary patching as a unified capability surfaces the shared operational considerations that span these techniques: byte alignment for multi-byte instruction replacement, checksum recalculation for disk-patched images, signature invalidation for signed binaries, and the distinction between self-modification (which does not trigger kernel callbacks) and cross-process modification (which triggers `ObRegisterCallbacks`). Operators who understand these shared constraints can transfer knowledge between AMSI patching, NTDLL unhooking, and IAT modification without re-deriving the constraints for each technique.

## Detection Considerations

- **Telemetry sources**: `VirtualProtect` calls on executable pages generate `MiSetPageProtection` kernel events. File-system minifilter callbacks detect disk writes to protected directories. Windows Defender real-time protection scans files on write. PE-sieve (T-094) detects in-memory `.text` modification via on-disk comparison.
- **Bypass options**: PE header stomping prevents PE-sieve from locating the `.text` section by zeroing the headers. Self-modification (writing to the current process's own `.text`) does not trigger `ObRegisterCallbacks`. The `ki_step_over.rs` approach avoids modifying `.text` by using hardware breakpoints instead of byte replacement.
- **Residual artifacts**: The `VirtualProtect` call creates a protection change event in the VAD entry. Disk-patched files have a modified last-write timestamp and may fail Authenticode signature verification. The patched bytes are recoverable from the process memory dump for forensic analysis.

## Related Techniques

- **T-016 EDR Evasion Suite** — NTDLL unhook, AMSI patch, and ETW patch are specific instances of in-memory binary patching; this card documents the shared operational considerations across all three
- **T-017 Five-Layer Persistence** — Disk patching of DLLs or binaries enables persistent modifications that survive process restart; import directory and EAT modification enable IAT hijack persistence
- **T-020 Anti-Analysis Suite** — IAT camouflage modifies import table entries, a form of binary patching for anti-analysis; CFG bitmap editing falls under binary patching for execution flow modification

## References

- Atlas material: atlas-binary-analysis-part4, atlas-binary-analysis-part7
- MITRE ATT&CK: T1562.001 (https://attack.mitre.org/techniques/T1562/001)
- LGTM notes: lgtm:binary-patching-as-standalone-capability, lgtm:binary-patching-as-distinct-technique
- Public references: SEC670 Red Team Tools module (binary patching capability)

## Source Reference

`dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` (lines 1-127): implements `stomp_pe_header`, `stomp_own_pe_header`, and `stomp_self_header` — memory patching variant for PE header zeroing. `dark_crystal/crowd/src/ki_step_over.rs` (lines 1-320): implements `hook_exception_dispatcher` and `unhook_exception_dispatcher` — memory patching of ntdll's `.rdata` callback pointer.