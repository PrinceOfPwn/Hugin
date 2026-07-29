---
id: T-050
name: Manual GetProcAddress via Export Table Walking
category: syscalls
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/persist/tls_cb.rs
mitre: T1027.007
mitre_secondary: [T1106]
tags: [api-resolution, export-table-walk, import-hiding, pe-format, rva, edr-hook-evasion, kernel32-exports, djb2-hash]
origin: atlas-synthesis
member_notes: ['lgtm:manual-loader-api-reimplementation', 'lgtm:manual-getprocaddress-as-standalone-primitive']
---

# Manual GetProcAddress via Export Table Walking — Function Resolution Without the Loader API

## Summary

Manual GetProcAddress resolves a function pointer by parsing the target module's `IMAGE_EXPORT_DIRECTORY` directly from its mapped image in memory, traversing the `AddressOfNames`, `AddressOfNameOrdinals`, and `AddressOfFunctions` arrays, instead of calling `GetProcAddress`. The technique exploits the fact that every loaded DLL carries a complete self-describing export table in its PE headers, making the loader API an optional convenience rather than a necessity. Operators use it because the training material flags `LoadLibrary`/`LoadLibraryEx` and `GetProcAddress` as APIs commonly monitored by security products, and explicit linking alone still transits those monitored entry points. The resolution itself is pure user-mode memory reads on already-mapped MEM_IMAGE pages, so it produces no API call telemetry at all.

## Mechanism

1. Obtain the target module base (kernel32.dll, ntdll.dll) without calling `LoadLibrary`. The standard input is a PEB/InLoadOrderModuleList walk (T-004); a SEC_IMAGE mapping also works since the export directory is part of the mapped image.
2. Read `e_lfanew` at `base + 0x3C` and locate the NT headers at `base + e_lfanew`. Validate the `PE\0\0` signature.
3. Read `OptionalHeader.Magic` at `NT + 0x18`. For PE32+ (`0x20B`) the DataDirectory begins at `NT + 0x88`; for PE32 (`0x10B`) it begins at `NT + 0x78`.
4. Read `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` (index 0): a `VirtualAddress`/`Size` pair. A zero RVA means the module exports nothing.
5. Compute `export_dir = base + export_rva`. The structure is 40 bytes: `Base` at `+0x10`, `NumberOfFunctions` at `+0x14`, `NumberOfNames` at `+0x18`, `AddressOfFunctions` at `+0x1C`, `AddressOfNames` at `+0x20`, `AddressOfNameOrdinals` at `+0x24`. All three AddressOf* fields are RVAs; convert each to a VA by adding the module base.
6. Iterate `i` from 0 to `NumberOfNames - 1`. For each index, read the name RVA at `AddressOfNames + 4*i`, then compare the null-terminated ASCII string at `base + name_rva` against the target — either byte-for-byte or by hashing each candidate (DJB2) and comparing a precomputed constant, which keeps plaintext API names out of the binary.
7. On a match at index `i`, read the 16-bit name ordinal at `AddressOfNameOrdinals + 2*i`. This ordinal is the index into the function table, linking the name to its address.
8. Read the 32-bit function RVA at `AddressOfFunctions + 4*ordinal`. The resolved address is `base + function_rva`.
9. For ordinal-based resolution (imports by ordinal, or functions with no name entry), compute the table index as `ordinal - Base`, then read `AddressOfFunctions[index]` directly. `Base` is the ordinal base value stored in the export directory, typically 1.
10. Check for forwarded exports: if the function RVA from step 8 falls inside `[export_rva, export_rva + export_size)`, the entry is not code but a forwarder string of the form `TargetDll.TargetFunc`. A complete implementation parses the string and recurses into the named DLL; a minimal implementation treats it as resolution failure.

## OS Internals Context

The export directory exists so the Windows loader can bind imports without knowing anything about a DLL's internals. `IMAGE_EXPORT_DIRECTORY` is defined in `winnt.h` as an 11-field, 40-byte structure: `Characteristics`, `TimeDateStamp`, `MajorVersion`, `MinorVersion`, `Name`, `Base`, `NumberOfFunctions`, `NumberOfNames`, `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals`. The training material walks a real hex dump of kernel32.dll's export directory with concrete annotations: `Name` RVA `0x090058` points at the string `KERNEL32.DLL`, `Base` is 1, `NumberOfFunctions` and `NumberOfNames` are both `0x650`, `AddressOfFunctions` RVA `0x08C138` begins with function RVAs `0x9007D`, `0x900B3`, `0x1E310`, and `AddressOfNames` RVA `0x08DA78` begins with name RVA `0x90065` (`AcquireSRW...`). The material uses this dump to show that the table is fully parseable with nothing more than RVA arithmetic.

The three arrays exist because the two lookup modes have different shapes. `AddressOfFunctions` is indexed by ordinal and contains one entry per exported function; walking it alone yields anonymous addresses with no way to know which is `GetProcAddress` versus `TerminateProcess`. `AddressOfNames` holds RVAs to the name strings and is sorted alphabetically, which is what permits fast lookup. Because the names are sorted but the functions are not, a third array — `AddressOfNameOrdinals` — maps each name position to its function-table index. The name index and ordinal index are not interchangeable; skipping the ordinals array and indexing `AddressOfFunctions` directly by name position resolves the wrong address. `NumberOfNames` can be smaller than `NumberOfFunctions` because functions exported purely by ordinal have no name entry at all.

On the kernel/user boundary, this technique is unremarkable by design. Every page touched is part of the target DLL's MEM_IMAGE mapping, already present in the process address space under `\KnownDlls` for system modules. There is no syscall, no kernel transition, no handle creation. The monitored surface sits one layer up: `GetProcAddress` is a kernel32 export that funnels into ntdll's `LdrGetProcedureAddress`, and EDR userland hooks patch those function prologues. A manual walker replicates exactly the name-to-ordinal-to-RVA logic `LdrGetProcedureAddress` performs, minus the loader lock and minus forwarder resolution, so the hook on the API entry point never executes. Forwarded exports are the one place the real loader does more work: a large share of kernel32's modern exports forward into KernelBase.dll, and `LdrGetProcedureAddress` follows those forwarders recursively while a naive walker returns the string address as if it were code.

## Key Implementation Details

`dark_crystal/crowd/src/persist/tls_cb.rs` contains a verified implementation inside `build_tls_stub`. The function emits a position-independent x64 stub as raw bytes, and the stub performs the full export walk at runtime: it obtains kernel32's base via the PEB (`gs:[0x60]` → `Ldr` at `+0x18` → third `InLoadOrderModuleList` entry's `DllBase` at `+0x30`), reads `e_lfanew` at `[rbx+0x3C]`, the export directory RVA at `[rbx+rax+0x88]`, then `NumberOfNames` at `+0x18`, `AddressOfNames` at `+0x20`, `AddressOfNameOrdinals` at `+0x24`, and `AddressOfFunctions` at `+0x1C`. The name comparison is a single 8-byte `cmp [rdi], rsi` against the immediate `WinExec\0`, the ordinal is loaded with `movzx eax, word [r10+r9*2]`, the function RVA with `mov eax, [r10+rax*4]`, and the base added before `call rax`. Two deviations from the general pattern: it resolves one hardcoded export rather than taking a parameter, and it compares a literal name instead of a DJB2 hash, so the string `WinExec` appears in the emitted stub.

`dark_crystal/crowd/src/overload.rs` is a consumer, not an implementation. Its `fixing_iat` resolves imports by calling `crate::resolve::resolve_export_by_name` and `crate::resolve::resolve_export_by_ordinal` against module bases returned by `crate::resolve::find_module_base` (the T-004 PEB walker), then patches each `FirstThunk` entry. The ordinal path masks `IMAGE_ORDINAL_FLAG64` and passes the low 16 bits. The general-purpose export-walking resolver those functions live in is `resolve.rs`, documented under T-004. The file's own comments state the rationale: `LoadLibraryA` and `GetProcAddress` are hooked by EDR products and would break the syscall-only stealth claim.

`dark_crystal/crowd/src/pe_loader.rs` does not implement this technique. Its `resolve_imports` calls `LoadLibraryA` and `GetProcAddress` for every thunk — the explicit-linking path the material identifies as monitored. It is the counter-example this technique replaces.

## Why It Matters

PEB walking (T-004) terminates at a module base; this technique is the second half that turns a base address into a callable function pointer, completing the zero-API resolution chain. Explicit linking already keeps the target DLL out of `dumpbin /dependents` and the import table, but the material explicitly notes the remaining problem — the `LoadLibrary`/`GetProcAddress` calls themselves transit monitored APIs — and names manual reimplementation of those APIs as the follow-on step. Every downstream syscall capability in the vault (T-001 stub location, T-006 phantom stub construction, manual-map IAT fixup) depends on this primitive to bootstrap without imports.

## Detection Considerations

- **Telemetry sources**: The training material states that `LoadLibrary`/`LoadLibraryEx` and `GetProcAddress` are commonly monitored by security products; userland hooks on those exports (and on ntdll's `LdrGetProcedureAddress`) are the telemetry this technique avoids. The manual walk itself emits no API telemetry because it consists entirely of reads on MEM_IMAGE pages. The material does not name ETW providers, Sysmon event IDs, or memory-scan heuristics specific to export walking.
- **Bypass options**: Resolving by DJB2 hash instead of plaintext comparison removes API name strings from the binary; this is the approach used by the vault's general resolver path (T-004, T-001).
- **Residual artifacts**: The material discusses the static side of the trade only for the explicit-linking baseline: an explicitly linked DLL is absent from the import table and from `dumpbin /dependents` output. Manual resolution additionally removes the `GetProcAddress` import itself. No other artifacts are discussed.

## Related Techniques

- **T-001 RecycledGate Indirect Syscalls** — consumes resolved ntdll export addresses as the starting point for scanning `syscall;ret` gadgets and SSN extraction.
- **T-004 PEB Walker via gs:[0x60]** — produces the module base that is the required input to export table walking; `resolve.rs` hosts both the PEB walk and the export resolution functions.
- **T-006 Phantom Stubs** — requires resolved ntdll addresses to construct MEM_IMAGE-backed syscall stubs; export walking is the resolution layer beneath it.

## References

- Atlas material: atlas-exploit-dev-part8.md (units 24–40: PE format, `IMAGE_EXPORT_DIRECTORY`, kernel32 export hex dump), atlas-exploit-dev-part17.md (units 25, 28: explicit linking and monitored loader APIs)
- MITRE ATT&CK: T1027.007 Dynamic API Resolution — https://attack.mitre.org/techniques/T1027/007/
- LGTM notes: lgtm:manual-loader-api-reimplementation, lgtm:manual-getprocaddress-as-standalone-primitive
- Public references: SANS SEC670 Red Teaming Tools, Book 1 — Windows Tool Development (PE format and DLL linking modules); `winnt.h` structure definitions

## Source Reference

- `dark_crystal/crowd/src/persist/tls_cb.rs` — `build_tls_stub` emits a PIC x64 export-table walker resolving `WinExec` from kernel32 without `GetProcAddress`.
- `dark_crystal/crowd/src/overload.rs` — `fixing_iat` consumes `resolve_export_by_name`/`resolve_export_by_ordinal` from `resolve.rs` (general resolver documented under T-004).
- `dark_crystal/crowd/src/pe_loader.rs` — does not implement this technique; uses the monitored `LoadLibraryA`/`GetProcAddress` path.