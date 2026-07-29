---
id: T-102
name: Position-Independent C Shellcode Build Pipeline
category: exploit-primitive
tier: A
crate: none
source_file: none
mitre: T1027
tags: [shellcode, pic, position-independent, build-config, visual-studio, crt-free, intrinsics, compiler-settings, no-entry-point]
origin: atlas-synthesis
member_notes: ['lgtm:pic-shellcode-build-config-coverage', 'lgtm:pic-c-shellcode-build-pipeline', 'lgtm:pic-c-shellcode-tradecraft', 'lgtm:gap-shellcode-position-independence-discipline']
---

# Position-Independent C Shellcode Build Pipeline and Discipline — Producing Raw PIC Bytes from C Source

## Summary

Position-independent C shellcode is produced by compiling standard C source code with a specific Visual Studio linker and compiler configuration that strips all CRT dependencies, fixed entry points, and absolute address references, yielding a raw blob of position-independent machine code. The build pipeline requires `/GS-` (no stack canary), `/NODEFAULTLIB` (no CRT linkage), `/SUBSYSTEM:NATIVE` (no Windows subsystem binding), `/NOENTRY` (no default entry), a custom `/ENTRY:` specification, `/SDL-` (no security checks), and `/MT` (static CRT, which is then excluded by `/NODEFAULTLIB`). The authoring discipline mandates avoiding the heap (no `malloc`/`new`), avoiding external references (no imports resolved by the loader), and avoiding the `.data`/`.rdata` sections (using stack-allocated constants or runtime-resolved strings instead). Compiler intrinsics (`__readgsqword`, `__readmsr`, `#pragma intrinsic` for `memset`/`strcmp`/`__movsb`) replace their CRT-wrapped equivalents.

## Mechanism

1. The operator creates a C source file with a custom entry point function. The entry point is specified via the `/ENTRY:function_name` linker flag. The function signature is `void entry(void)` — no parameters, no return value. The function must not return to the caller (it should call `ExitProcess` or terminate via a `jmp` to a known address).

2. The build configuration is set in Visual Studio project properties or directly in the `cl.exe` / `link.exe` command line:

3. **`/GS-`**: Disables the `/GS` buffer security check. The `/GS` flag inserts a stack canary (`__security_cookie`) check at function entry and exit. When enabled, the compiler generates a call to `__security_init_cookie` and references to the `__security_cookie` global variable, which lives in the `.data` section. This creates an absolute address reference that breaks position independence.

4. **`/NODEFAULTLIB`**: Instructs the linker to ignore all default library directives (`/DEFAULTLIB:` entries embedded in the CRT object files). Without this flag, the linker attempts to resolve `mainCRTStartup` and pulls in the entire CRT initialization chain, which depends on fixed IAT entries and the `.data` section.

5. **`/SUBSYSTEM:NATIVE`**: Marks the PE subsystem as `IMAGE_SUBSYSTEM_NATIVE_BOOT` (value 3) or `IMAGE_SUBSYSTEM_NATIVE` (value 16). This prevents the Windows loader from treating the binary as a Win32 application and avoids subsystem-specific initialization. When the shellcode is extracted from the PE and injected into a remote process, the subsystem field is irrelevant, but during build time it prevents the linker from adding Win32 startup code.

6. **`/NOENTRY`**: Tells the linker that the image has no standard entry point and should not generate `_main` or `mainCRTStartup` references. Combined with `/ENTRY:custom_entry`, this gives full control over the execution start point.

7. **`/SDL-`**: Disables Security Development Lifecycle checks — no `/GS`, no control flow guard, no safe exception handlers. These checks generate metadata in the `.rdata` section and `IMAGE_LOAD_CONFIG_DIRECTORY` entries that create absolute references.

8. **No C++ exceptions**: Exceptions require CRT runtime support (`__CxxFrameHandler`, `_CxxThrowException`) and generate unwind data in the `.pdata` section. The code must be compiled with `/EHs-` or simply authored in C rather than C++.

9. The source code must adhere to position-independence discipline:

10. **No heap allocation**: `malloc`, `calloc`, `new`, and `LocalAlloc` all resolve to external imports (either CRT wrappers or direct Win32 calls). The shellcode cannot rely on the loader resolving imports. Memory must come from stack allocation (local variables), inline buffer allocation via `alloca`/`_alloca` (which compiles to a `SUB RSP, imm` instruction — position independent), or manual calls to `NtAllocateVirtualMemory` after the shellcode has manually resolved the function pointer.

11. **No external references**: The shellcode cannot use any import that the PE loader would resolve via the IAT. All API calls must be manually resolved: the shellcode walks the PEB to find `ntdll.dll`, parses its export table, and resolves `Nt*` functions by DJB2 hash matching. From `ntdll`, the shellcode can resolve `LdrLoadDll` to load additional modules and `LdrGetProcedureAddress` to resolve their exports.

12. **No `.data` section references**: String literals and global variables placed in `.data` or `.rdata` are accessed via RIP-relative addresses that are fixed at link time. When the shellcode is extracted and placed at an arbitrary address, these references point to the wrong memory. The discipline requires stack-allocated string construction:
    ```c
    char str[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
    ```
    This compiles to `MOV` instructions that build the string on the stack byte-by-byte, which is position independent.

13. **Compiler intrinsics**: The `#pragma intrinsic` directive instructs the compiler to emit inline code for functions that are normally CRT library calls. `#pragma intrinsic(memset, strcmp, memcpy, __movsb)` generates inline `REP STOSB`, `REP MOVSB`, and comparison loops instead of calls to the CRT. The `<intrin.h>` header provides access to compiler intrinsics like `__readgsqword` (reads from `GS:` segment — used to access the PEB on x64), `__readmsr` (reads model-specific register), `__readcr2`, `__writecr3`, and other privileged operations.

14. After compilation, the raw shellcode bytes are extracted from the `.text` section of the produced PE. The `.text` section's `VirtualAddress` and `SizeOfRawData` fields in the section header identify the offset and size of the position-independent code blob. The operator copies these bytes into the encoding format required by the delivery mechanism (IPv4/IPv6/MAC/UUID/words encoding as documented in T-021).

## OS Internals Context

The Windows PE loader (`LdrpMapDllNtFileName` → `LdrpMapViewOfSection` → `LdrpProcessRelocationDirectory` → `LdrpProcessImportDirectory`) performs base relocation and IAT resolution when loading a PE. Position-independent shellcode must function correctly without any of these loader services. The PE's base relocation table (`DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]`) contains entries that the loader patches when the image loads at a non-preferred base address. Position-independent code avoids the need for relocation by using only RIP-relative addressing (x64) or call/pop instruction sequences (x86) to determine the current instruction pointer.

The PEB (Process Environment Block) is accessed on x64 via `GS:[0x60]` (the `gs` segment base is set to the TEB, and `TEB.ProcessEnvironmentBlock` is at offset 0x60 on x64, 0x30 on x86). The `__readgsqword(0x60)` intrinsic returns the PEB address. From the PEB, `PEB.Ldr` (offset 0x18 on x64) points to the `PEB_LDR_DATA` structure, whose `InLoadOrderModuleList` (offset 0x10) / `InMemoryOrderModuleList` (offset 0x20) doubly-linked lists enumerate all loaded modules. Each `LDR_DATA_TABLE_ENTRY` contains `DllBase`, `BaseDllName` (UNICODE_STRING), and `FullDllName`. The shellcode walks this list to find `ntdll.dll` by hash comparison, then parses its export directory to resolve `Nt*` functions by name hash.

## Key Implementation Details

**No current implementation in the HUGIN source.** The HUGIN shellcode is Rust-based and uses a different toolchain (`rustc` with `panic=abort`, `#![no_std]`, custom linker scripts). The Visual Studio C build pipeline documented here produces raw PIC blobs for embedding in Rust-based payloads (e.g., donut-style loaders or specific shellcode snippets that must be authored in C for compatibility with existing tooling or for access to compiler intrinsics not available in Rust). An implementation in the HUGIN context would be a build script (`build.rs`) that invokes `cl.exe` with the documented flags against a C source file, extracts the `.text` section via PE parsing, and embeds the resulting byte blob via `include_bytes!` or `include_str!` with runtime hex decoding.

## Why It Matters

The vault's T-021 (Crypto & Obfuscation) covers shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) and T-016 covers PE stomping, but neither documents the build pipeline that produces the raw position-independent shellcode blob in the first place. This build pipeline is a prerequisite for every shellcode-encoding technique in T-021 — encoded shellcode that internally uses the heap, references the `.data` section, or relies on CRT initialization will fail when injected into a cross-process context where the loader does not process relocations or resolve imports. The discipline of avoiding these dependencies is the difference between shellcode that works reliably across injection contexts and shellcode that crashes silently.

## Detection Considerations

- **Telemetry sources**: The build pipeline itself runs on the operator's development machine, not the target. No target-side telemetry is generated. The resulting shellcode blob's detection surface depends on the encoding and injection technique used to deliver it.
- **Bypass options**: The shellcode should use manual PEB walking and DJB2 hash-based API resolution (as documented in T-004 PEB Walker) to avoid generating an IAT that reveals intended API usage. Stack-allocated string constants avoid `.rdata` references that static analysis tools use to fingerprint shellcode purpose.
- **Residual artifacts**: The compiled PE file on the development machine. The `.text` section extraction leaves a PE with a `.text` section that contains the shellcode — this PE itself may be flagged by AV if left on disk. The raw extracted `.bin` blob is not a valid PE and will not be scanned by PE-aware AV, but may be detected by byte-pattern signature matching.

## Related Techniques

- **T-013 Remaining Injection Methods** — injection techniques that consume the raw shellcode bytes produced by this pipeline
- **T-020 Anti-Analysis Suite** — IAT camouflage and self-deletion that apply to the final payload, not the shellcode build
- **T-021 Crypto & Obfuscation** — shellcode encoding formats (IPv4/IPv6/MAC/UUID/words) that encode the raw bytes produced by this pipeline
- **T-016 EDR Evasion Suite** — PE stomping technique that receives the compiled shellcode as payload

## References

- Atlas material: atlas-exploit-dev-part1 (unit 17), atlas-exploit-dev-part13 (units 25, 27, 28, 29, 30, 33, 34, 38), atlas-exploit-dev-part19 (units 31, 32, 33, 34, 37, 40), atlas-exploit-dev-part20 (units 1, 2)
- MITRE ATT&CK: T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027
- LGTM notes: lgtm:pic-shellcode-build-config-coverage, lgtm:pic-c-shellcode-build-pipeline, lgtm:pic-c-shellcode-tradecraft, lgtm:gap-shellcode-position-independence-discipline

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.