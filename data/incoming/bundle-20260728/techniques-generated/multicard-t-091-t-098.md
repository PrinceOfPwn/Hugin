<!-- BEGIN CARD T-091 -->
---
id: T-091
name: SAL Annotation Literacy as API-Contract Reading Skill
category: discovery
tier: C
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1055]
tags: [sal-annotations, api-contract, sdk-headers, ffi, nt-api, parameter-direction, buffer-ownership, binding-safety]
origin: atlas-synthesis
member_notes: [lgtm:sal-annotations-as-graph-concept, lgtm:sal-annotation-literacy-coverage-gap]
---

# SAL Annotation Literacy as API-Contract Reading Skill — Reading NT API Parameter Contracts for FFI Binding

## Summary

Microsoft's Source Annotation Language (SAL) provides structured metadata on Windows API function signatures that declares the direction, ownership, and size constraints of each parameter. Operators hand-binding NT APIs via Rust FFI or C must read these annotations to correctly determine buffer allocation obligations, parameter directionality, and return-value contracts before translating a function signature into a binding. Misreading SAL annotations produces FFI declarations that cause silent buffer truncation, null pointer dereferences, or memory corruption when the NT API is actually invoked. The HUGIN vault documents PEB walking (T-004), SSN resolution (T-002), and multiple injection primitives (T-013, T-014, T-015) that call NT functions directly but does not surface the annotation literacy required to bind new APIs without introducing defects.

## Mechanism

1. Open the Windows SDK header file or MSDN documentation page for the target NT API.
2. Read each parameter's SAL annotation to determine the caller obligation:
   - `_In_` — caller provides an initialized value; the callee reads only.
   - `_Out_` — caller allocates the buffer; the callee writes the result.
   - `_Inout_` — caller provides an initialized value; the callee may read and write back.
   - `_In_opt_` — caller may pass NULL; the callee must handle the null case.
   - `_Out_opt_` — caller may pass NULL for the output pointer; the callee must handle it.
   - `_In_reads_(N)` — caller provides a buffer of N elements, all initialized.
   - `_Out_writes_(N)` — caller allocates a buffer for N elements; callee writes up to N.
   - `_In_bytecount_(cb)` — caller provides a buffer of cb bytes, initialized.
   - `_Out_writes_bytes_all_(N)` — callee writes exactly N bytes, not partial.
   - `_deref_out_` — callee writes through a pointer-to-pointer (double indirection).
   - `_Success_(expr)` — defines the return-value contract for success versus failure.
   - `_Must_inspect_result_` — caller must check the return value.
   - `_Check_return_` — compiler emits a warning if the return value is ignored.
   - `_Ret_maybenull_` — the return pointer may be NULL; caller must check.
3. Translate the SAL-annotated signature into the target language's FFI binding.
4. For Rust specifically: map `_In_` to a value parameter or immutable reference, `_Out_` to a mutable reference, `_In_opt_` to `Option<T>` or a nullable raw pointer, `_Out_opt_` to `Option<*mut T>`.
5. Verify that buffer size parameters match the annotation's element count or byte count specification at the call site.
6. Check the `_Success_` annotation to determine the correct return-value validation pattern (NTSTATUS >= 0 for most NT APIs).

## OS Internals Context

SAL annotations encode the memory contract between caller and callee at the Win32/NTAPI boundary. The annotations are not enforced at runtime — they function as compile-time directives consumed by the MSVC C/C++ compiler's static analysis engine (the `/analyze` flag). When an operator hand-binds an NT API via Rust FFI using `extern "system"` declarations, the SAL metadata is stripped entirely because Rust's foreign function interface does not parse SAL attributes. The FFI binding must manually encode the annotation contract through Rust's type system or through disciplined documentation.

For `NtQueryInformationProcess` called with `ProcessBasicInformation`, the SDK signature is:

```c
NTSTATUS NtQueryInformationProcess(
    _In_      HANDLE ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_      ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);
```

The `_Out_writes_bytes_(ProcessInformationLength)` annotation declares that the callee writes up to `ProcessInformationLength` bytes into the caller-allocated `ProcessInformation` buffer. An operator who misreads this as `_In_` would pass an uninitialized buffer and the callee would write to uninitialized memory. An operator who allocates a buffer smaller than `ProcessInformationLength` and passes a mismatched length would cause silent truncation — the API returns `STATUS_INFO_LENGTH_MISMATCH` (0xC0000004), but only if the caller checks the NTSTATUS return value.

The `_Out_opt_` on `ReturnLength` means the caller may pass NULL. This supports a probe pattern: the caller passes NULL for `ProcessInformation` and a zero length, receives the required buffer size in `ReturnLength` on a subsequent call, then allocates and re-invokes. Misreading `_Out_opt_` as `_Out_` would cause the caller to always allocate a `ULONG` even when the probe pattern does not need it; misreading it as `_In_opt_` would cause a null pointer dereference if the API attempts to write through it.

The implicit `_Success_(return >= 0)` on most NT APIs declares that a non-negative NTSTATUS indicates success. The `_Must_inspect_result_` annotation (present on many NT APIs) instructs the caller to check the return value. Operators who ignore the return value and assume success will silently use partially-written output buffers, producing data corruption that manifests as intermittent failures in dependent code.

The `_In_reads_(N)` family is particularly important for APIs like `NtCreateThreadEx` where the `CLIENT_ID` structure must be initialized by the caller before the call. An operator who treats `_In_reads_` as `_Out_writes_` would pass an uninitialized structure and the callee would read garbage values.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the reading skill for future application across all hand-bound NT API cards.

The HUGIN source uses `windows_targets::link!` macros in `dark_crystal/crates/core/src/wrappers.rs` to bind NT APIs. These macros generate Rust `extern "system"` declarations that strip SAL annotations at compile time. An operator adding a new NT API binding must read the SAL from the SDK header and manually encode the parameter directionality in the Rust function signature. For example, `_Out_writes_bytes_(N)` maps to a `*mut u8` parameter with a comment documenting the buffer size contract, and `_Out_opt_` maps to `Option<*mut u32>` or a nullable raw pointer. The `wrappers.rs` file currently binds APIs like `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtQueryInformationProcess` — each requiring the operator to have translated SAL direction annotations into correct Rust parameter types before the binding was written.

## Why It Matters

The vault documents 15 injection methods, 13 evasion techniques, and multiple syscall dispatch modes that call NT APIs directly. Each of these cards assumes the operator can correctly read the API contract from the SDK header. Without SAL literacy, an operator wrapping `NtCreateSection`, `NtMapViewOfSection`, or `NtCreateUserProcess` for the first time will produce FFI bindings that either crash on null dereference (misreading `_Out_opt_`), silently corrupt memory (wrong buffer direction on `_Inout_`), or truncate results (mismatched length on `_Out_writes_bytes_`). This card provides the reading framework that gates correct hand-binding for every NT API referenced in the vault.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution reads Nt* stub prologues whose function signatures carry SAL-defined parameter contracts
- **T-004 PEB Walker** — Module resolution via PEB->Ldr requires correct LdrLoadDll and LdrGetProcedureAddress FFI bindings derived from SAL headers
- **T-013 Remaining Injection Methods** — PE loader and injection primitives require NtAllocateVirtualMemory, NtWriteVirtualMemory, and NtCreateThreadEx bindings whose parameter direction follows SAL
- **T-014 NtCreateUserProcess** — Direct NT process creation requires reading the SAL to distinguish required versus optional struct fields and output pointers
- **T-015 PPID Spoofing** — Parent spoofing via NtCreateProcessEx requires correct struct initialization per SAL parameter direction
- **T-016 EDR Evasion Suite** — NTDLL unhook and AMSI/ETW patching require reading target API prologue bytes whose location and size are defined by the SAL-annotated function signature

## References

- Atlas material: atlas-exploit-dev-part4, atlas-exploit-dev-part6
- MITRE ATT&CK: T1106 (https://attack.mitre.org/techniques/T1106)
- LGTM notes: lgtm:sal-annotations-as-graph-concept, lgtm:sal-annotation-literacy-coverage-gap
- Public references: Microsoft Source Annotation Language documentation (MSDN SAL reference)

## Source Reference

No current implementation. See atlas material and MITRE reference for context.
<!-- END CARD T-091 -->

<!-- BEGIN CARD T-092 -->
---
id: T-092
name: Windows API Fundamentals as Prerequisite Layer
category: discovery
tier: C
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1055]
tags: [calling-convention, win32-api, typedef-chain, x64-abi, windef, ntapi-translation, pe-format, dll-linking, prerequisite]
origin: atlas-synthesis
member_notes: [lgtm:foundational-windows-programming-concepts-coverage-gap, lgtm:coverage-gap-windows-fundamentals-prerequisite]
---

# Windows API Fundamentals as Prerequisite Layer — Calling Conventions, Type Aliases, and Win32-to-NT Translation

## Summary

Windows API fundamentals comprise the prerequisite knowledge layer that gates comprehension of every syscall dispatch, PE manipulation, and EDR evasion card in the vault. The x64 calling convention dictates register-based argument passing (RCX, RDX, R8, R9) with a 32-byte shadow space allocation, which determines whether a hand-built syscall stub correctly balances the stack. Windows data type aliases (DWORD, LPVOID, HANDLE) and WinDef.h macros (DECLARE_HANDLE, MAKEINTRESOURCE, HIWORD/LOWORD) form the typedef chain that maps C types to their underlying integer widths. The Win32-to-NTAPI translation layer (OpenProcess to NtOpenProcess, CreateFile to NtCreateFile) defines the relationship between the user-facing API surface and the native system calls that the vault's techniques invoke directly. Operators coming from a pure Rust background without Win32 or C experience will lack the context to understand why ntdll stubs use the `__stdcall` convention, why `RtlCopyMemory` appears instead of `memcpy`, or what buffer size annotations mean in NT API signatures.

## Mechanism

1. Identify the calling convention for the target platform. On x64 Windows, the default convention for all Win32 and NT API functions is `__fastcall` (Microsoft x64 calling convention): the first four integer or pointer arguments are passed in RCX, RDX, R8, R9; floating-point arguments go in XMM0-XMM3; additional arguments go on the stack. The caller allocates a 32-byte (0x20) shadow space above the return address for the callee to spill RCX-R9.
2. Translate Windows data type aliases to their underlying C types:
   - `DWORD` = `uint32_t` (4 bytes, unsigned)
   - `WORD` = `uint16_t` (2 bytes, unsigned)
   - `BYTE` = `uint8_t` (1 byte, unsigned)
   - `LPVOID` = `void*` (pointer-sized)
   - `HANDLE` = `PVOID` = `void*` (pointer-sized)
   - `NTSTATUS` = `LONG` = `int32_t` (signed, 4 bytes)
   - `PULONG` = `uint32_t*`
   - `UNICODE_STRING` = struct with `USHORT Length`, `USHORT MaximumLength`, `PWSTR Buffer`
3. Map WinDef.h macros to their expansion:
   - `DECLARE_HANDLE(name)` — defines `typedef struct name##__{int unused;} *name` (opaque handle type)
   - `MAKEINTRESOURCE(i)` — casts integer to resource pointer via `(LPTSTR)((ULONG_PTR)((WORD)(i)))`
   - `HIWORD(l)` — extracts high 16 bits via `((WORD)((DWORD_PTR)(l) >> 16) & 0xFFFF)`
   - `LOWORD(l)` — extracts low 16 bits via `((WORD)((DWORD_PTR)(l)))`
4. Trace the Win32-to-NTAPI translation for a given user-mode API:
   - `OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)` → `NtOpenProcess(&Handle, DesiredAccess, ObjectAttributes, ClientId)` — the Win32 wrapper allocates the object attributes and client ID from the Win32 parameters.
   - `CreateFile(lpFileName, ...)` → `NtCreateFile(&Handle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)` — the Win32 wrapper translates the filename to an NT path and fills the OBJECT_ATTRIBUTES.
   - `VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)` → `NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits, RegionSize*, AllocationType, Protect)` — the Win32 wrapper passes `NtCurrentProcess()` as the handle and adjusts the size pointer indirection.
5. For DLL linking, distinguish explicit linking (LoadLibrary + GetProcAddress at runtime, used by the vault's PEB walker T-004) from implicit linking (IAT entry resolved by the loader at process startup, visible in the PE's Import Directory).
6. For PE format, identify the PE32 versus PE32+ distinction by the Optional Header Magic field: `0x010B` for PE32 (32-bit), `0x020B` for PE32+ (64-bit). The vault's injection and loader code operates on PE32+ images on x64 targets.

## OS Internals Context

The x64 calling convention on Windows is documented in the AMD64 Software Conventions section of the Microsoft documentation. The 32-byte shadow space (4 × 8 bytes) at `RSP+0x00` through `RSP+0x18` allows the callee to spill RCX, RDX, R8, R9 without allocating additional stack space. The caller is responsible for cleaning up stack-passed arguments after the call returns. Stack must be 16-byte aligned at the point of the `CALL` instruction, meaning RSP mod 16 == 0 before the `CALL` pushes the return address (so RSP mod 16 == 8 at function entry).

NT API stubs in ntdll.dll follow this convention. The canonical ntdll stub layout is:

```asm
mov r10, rcx        ; copy RCX to R10 because the syscall instruction clobbers RCX
mov eax, <SSN>      ; load syscall service number
syscall              ; transition to kernel
ret                 ; return to caller
```

The `mov r10, rcx` instruction exists because the syscall instruction destroys RCX (the kernel uses it for the return address). The convention requires that the first argument, originally in RCX, is preserved in R10 before the syscall transition. An operator building a hand-crafted syscall stub (as in T-001 RecycledGate or T-006 Phantom Stubs) must replicate this instruction sequence or the kernel receives garbage in its first argument.

The Win32-to-NTAPI translation layer exists in `kernelbase.dll` and `kernel32.dll`. These DLLs implement the Win32 API surface by translating parameters into NT structures and calling the corresponding `Nt*` function in ntdll. The vault's techniques bypass this translation layer by calling `Nt*` functions directly via syscall stubs, which means the operator must construct the NT structures (OBJECT_ATTRIBUTES, CLIENT_ID, IO_STATUS_BLOCK) that the Win32 wrapper would have filled.

The typedef chain means that `HANDLE` and `PVOID` are both `void*` on x64 — 8 bytes. The `UNICODE_STRING` structure is 16 bytes on x64: 2 bytes Length, 2 bytes MaximumLength, 4 bytes padding, 8 bytes Buffer pointer. The `OBJECT_ATTRIBUTES` structure is 48 bytes on x64: 4 bytes Length, 4 bytes padding, 8 bytes RootDirectory, 8 bytes ObjectName (pointer to UNICODE_STRING), 4 bytes Attributes, 4 bytes padding, 8 bytes SecurityDescriptor, 8 bytes SecurityQualityOfService. An operator initializing these structures in Rust must use `#[repr(C)]` and account for the alignment padding.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents prerequisite knowledge for navigating the vault's existing cards.

The HUGIN source uses `#[repr(C)]` on all structures that interface with NT APIs, and the `extern "system"` calling convention in Rust maps to `__stdcall` on x86 and the Microsoft x64 calling convention on x64. The `windows_targets::link!` macro in `dark_crystal/crates/core/src/wrappers.rs` generates bindings that respect the platform calling convention. Operators reading this source should understand that `extern "system"` is Rust's equivalent of the `__stdcall`/`__fastcall` convention on Windows, and that the 32-byte shadow space is allocated automatically by the Rust compiler for `extern "system"` calls.

## Why It Matters

The vault's syscall dispatch cards (T-001, T-002, T-003, T-006) build and execute machine code stubs that must conform to the x64 calling convention. The PEB walker (T-004) traverses `LIST_ENTRY` structures and reads `LDR_DATA_TABLE_ENTRY` fields whose offsets depend on the typedef chain. The injection methods (T-013) and evasion suite (T-016) call NT APIs that require `OBJECT_ATTRIBUTES`, `CLIENT_ID`, and `IO_STATUS_BLOCK` initialization. An operator who does not understand these fundamentals will produce code that crashes due to stack misalignment, structure padding errors, or incorrect parameter indirection.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall stubs dispatch through ntdll gadgets whose execution follows the x64 calling convention
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN extraction reads Nt* stub prologues whose instruction layout follows the x64 ABI register mapping
- **T-003 VEH Syscall Gate** — Hardware breakpoint exception handlers require shadow space and register mapping per x64 ABI for CONTEXT manipulation
- **T-004 PEB Walker** — PEB->Ldr traversal uses HANDLE, LIST_ENTRY, and LDR_DATA_TABLE_ENTRY typedefs from ntdef headers
- **T-006 Phantom Stubs** — MEM_IMAGE-backed syscall stubs must respect the x64 calling convention for stack frame layout and shadow space
- **T-013 Remaining Injection Methods** — PE loader and injection methods translate Win32 CreateProcess calls to NtCreateUserProcess via the Win32-to-NTAPI translation layer
- **T-016 EDR Evasion Suite** — Evasion techniques patch ntdll functions whose signatures follow the __stdcall convention and SAL parameter direction

## References

- Atlas material: atlas-exploit-dev-part23, atlas-exploit-dev-part5
- MITRE ATT&CK: T1106 (https://attack.mitre.org/techniques/T1106)
- LGTM notes: lgtm:foundational-windows-programming-concepts-coverage-gap, lgtm:coverage-gap-windows-fundamentals-prerequisite
- Public references: Microsoft x64 Calling Convention documentation, WinDef.h, Windows Data Types (MSDN)

## Source Reference

No current implementation. See atlas material and MITRE reference for context.
<!-- END CARD T-092 -->

<!-- BEGIN CARD T-093 -->
---
id: T-093
name: Memory Forensics Tooling Volatility PE-sieve Moneta
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1055]
tags: [memory-forensics, volatility, pe-sieve, moneta, detection-surface, fileless-execution, unbacked-memory, vad-tree, memory-scan]
origin: atlas-synthesis
member_notes: [lgtm:pe-sieve-as-detection-reference, lgtm:memory-forensics-as-fileless-counter, lgtm:memory-forensics-detection-coverage, lgtm:gap-memory-forensics-detection-coverage]
---

# Memory Forensics Tooling (Volatility, PE-sieve, Moneta) — Post-Capture Detection Surface for In-Memory Implants

## Summary

Volatility, PE-sieve, and Moneta are three open-source memory forensics tools that detect in-memory and fileless execution artifacts independent of any installed EDR product. SEC670 explicitly identifies these tools as the defensive counter to fileless execution, citing WannaCry and EternalBlue as canonical examples where memory forensics succeeded where on-disk AV failed. Each tool applies a distinct detection heuristic: Volatility performs full-process analysis of EPROCESS blocks, VAD trees, and PEB structures from a captured memory image; PE-sieve scans a live process's address space for PE images and compares in-memory headers and .text section bytes against on-disk counterparts; Moneta scans for unbacked executable memory (VirtualAlloc'd regions without file backing) and suspicious RWX permission patterns. The vault's injection and evasion cards document techniques that bypass EDR runtime monitoring (ETW-TI, kernel callbacks, userland hooks) but do not address the post-capture detection surface that these three scanners define. An operator who defeats the EDR's runtime monitoring can still be caught by a post-capture memory forensic scan performed by a defender who acquires a process memory dump or a full-system memory image.

## Mechanism

1. **Volatility** — The defender acquires a full-system memory image (via a hypervisor snapshot, a crash dump, or a tool like winpmem). Volatility parses the kernel's `EPROCESS` list to enumerate all processes, including hidden or unlinked processes that DKOM techniques may have removed from the active list. For each process, Volatility walks the VAD (Virtual Address Descriptor) tree to identify all committed memory regions and their protection flags. VAD entries with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_READ` protection that lack a corresponding `FILE_OBJECT` backing store indicate unbacked executable regions — the signature of shellcode or a manually mapped PE. Volatility also reads the PEB of each process and cross-references the `PEB->Ldr->InLoadOrderModuleList` against the VAD tree to identify modules present in memory but absent from the loader list, or modules whose on-disk file does not match the in-memory image.

2. **PE-sieve** — The defender runs PE-sieve against a live process or a process memory dump. PE-sieve enumerates all memory regions in the target process and identifies those that contain PE headers (the MZ magic at the region start). For each identified PE image, PE-sieve extracts the in-memory headers and section bytes, then locates the corresponding on-disk file (using the path from `PEB->Ldr` entries or from VAD `FILE_OBJECT` references). PE-sieve compares the in-memory `.text` section bytes against the on-disk `.text` section bytes. Mismatches indicate that the module has been patched, hollowed, or stomped. PE-sieve also flags memory regions that contain a valid PE image but have no corresponding entry in the PEB loader list — the signature of a manually mapped (reflectively loaded) DLL or shellcode that was not loaded through the standard loader. The tool classifies findings as: hollowed (in-memory image differs from on-disk), unmapped (present in memory but not in PEB loader list), or replaced (on-disk file changed since the module was loaded).

3. **Moneta** — The defender runs Moneta against a live process. Moneta scans all committed memory regions and applies a filter for executable protection flags (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`). For each executable region, Moneta checks whether the region is backed by a file on disk (via `GetMappedFileName` or `NtQueryVirtualMemory` with `MemoryMappedFileNameInformation`). Regions with executable protection that are not backed by a file are flagged as suspicious — these correspond to `VirtualAlloc` allocations used for shellcode execution or manually mapped PE images. Moneta also flags regions with `PAGE_EXECUTE_READWRITE` protection specifically, as legitimate modules typically have `PAGE_EXECUTE_READ` (write-protected after loading) rather than writable-and-executable. The tool produces a list of suspicious memory addresses, their sizes, protection flags, and backing file status.

## OS Internals Context

The VAD tree is a kernel data structure that tracks the virtual address space layout of each process. Each `MMVAD` node describes a range of virtual addresses with attributes including starting virtual address, ending virtual address, protection flags, and a pointer to the `FILE_OBJECT` for mapped files. The VAD tree is the kernel's authoritative record of what memory regions exist in a process and how they were created. Volatility reads VAD entries from the kernel's `EPROCESS->VadRoot` field in the memory image. A `VirtualAlloc`-based allocation creates a VAD entry with no `FILE_OBJECT` — the absence of a file backing store is the detection signal. A `NtCreateSection` + `NtMapViewOfSection` call with `SEC_IMAGE` creates a VAD entry with a `FILE_OBJECT` pointing to the section's backing file — this appears as a legitimate mapped module.

The PEB loader list (`PEB->Ldr->InLoadOrderModuleList`) is a doubly-linked list of `LDR_DATA_TABLE_ENTRY` structures, one per loaded module. Each entry contains the module's base address, size, full path, and timestamps. PE-sieve walks this list to build an inventory of modules that the process's loader has registered. A manually mapped PE (loaded via `RtlImageNtHeader` and manual section copying, as in the vault's reflective loader) does not appear in this list — the absence is the detection signal. Module stomping (overwriting a legitimate module's .text section) produces a PEB loader entry that matches a valid module path, but the in-memory .text bytes differ from the on-disk .text bytes — the mismatch is the detection signal.

The `MEMORY_BASIC_INFORMATION` structure (28 bytes on x64) returned by `VirtualQuery` contains `AllocationProtect`, `State`, `Protect`, and `Type` fields. The `Type` field distinguishes `MEM_IMAGE` (mapped from a section backed by a file), `MEM_MAPPED` (mapped from a section backed by the pagefile or a non-image file), and `MEM_PRIVATE` (committed via `VirtualAlloc`). Moneta uses this structure to identify `MEM_PRIVATE` regions with executable protection — the combination indicates shellcode or a manually mapped PE that was not loaded through the section object mechanism.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the defensive detection surface against which the vault's offensive techniques are measured.

The HUGIN source implements several techniques that specifically target the heuristics these tools apply. The `pe_header_stomp.rs` file in `dark_crystal/crates/core/src/experimental/` zeroes the MZ/PE headers and section table of a mapped PE image, preventing PE-sieve from locating and parsing the in-memory PE. The `ghost.rs` file in `dark_crystal/crowd/src/` creates a process backed by a `SEC_IMAGE` section, producing a VAD entry with a `FILE_OBJECT` reference that appears legitimate to Volatility's VAD analysis. The `ki_step_over.rs` file bypasses EDR inline hooks without modifying ntdll's .text section, avoiding the in-memory versus on-disk .text mismatch that PE-sieve detects. These implementations demonstrate operational awareness of the memory forensics detection surface, but the vault does not document the scanner capabilities that motivate these countermeasures.

## Why It Matters

The vault's detection narrative is weighted toward EDR runtime telemetry: ETW-TI providers, kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallback`), and userland inline hooks. These represent the real-time detection surface. Memory forensics tools represent a fundamentally different detection surface: post-capture, offline analysis that operates on a memory image or process dump after the operator's techniques have already executed. An operator who successfully bypasses all EDR runtime monitoring can still be identified by a defender who captures a memory image and runs Volatility, PE-sieve, or Moneta against it. SEC670 treats this as a first-class detection category, and the vault's evasion cards should document which scanner catches which technique by what heuristic to enable operators to select countermeasures that address both surfaces.

## Detection Considerations

- **Telemetry sources**: Volatility operates on captured memory images (hypervisor snapshots, crash dumps, winpmem captures). PE-sieve operates on live process memory or process dumps. Moneta operates on live process memory. None of these tools generate ETW events or trigger kernel callbacks — they are offline or passive scanners that the EDR does not observe.
- **Bypass options**: PE header stomping defeats PE-sieve's PE-image identification. `SEC_IMAGE` section mapping defeats Moneta's unbacked-executable heuristic. PEB loader list registration (via `LdrLoadDll` or manual list insertion) defeats PE-sieve's unmapped-module detection. Sleep-time encryption (T-005 Ekko ROP Sleep) encrypts the .text section during sleep windows, making a captured memory image during sleep show encrypted bytes that do not match any known module pattern.
- **Residual artifacts**: VAD tree entries persist for the lifetime of the process and cannot be removed without kernel-level DKOM. PEB loader list entries persist until explicitly unlinked. `MEMORY_BASIC_INFORMATION` `Type` and `Protect` fields are kernel-managed and cannot be spoofed from user mode.

## Related Techniques

- **T-007 Pool Party** — Thread pool injection creates unbacked executable regions that Moneta detects via MEMORY_BASIC_INFORMATION Type=MEM_PRIVATE with executable protection
- **T-008 Threadless** — Export hijack modifies in-memory module .text bytes, detectable by PE-sieve's module-versus-disk comparison
- **T-013 Remaining Methods** — Process hollowing and mapping injection produce artifacts detectable by Volatility VAD tree analysis and PEB loader list cross-referencing
- **T-016 EDR Evasion Suite** — NTDLL unhooking restores .text bytes from a fresh copy, but PE-sieve can detect the restoration if the tool compares against a cached hash of the original .text
- **T-020 Anti-Analysis Suite** — Anti-VM and API hammering techniques do not address post-capture memory forensic scanning
- **T-005 Ekko ROP Sleep** — ROP-based PE encryption during sleep produces temporarily encrypted .text that a Volatility memory snapshot captured during the sleep window would show as non-matching bytes

## References

- Atlas material: atlas-methodology-part9, atlas-post-exploit-part1, atlas-post-exploit-part11, atlas-post-exploit-part14
- MITRE ATT&CK: T1518.001 (https://attack.mitre.org/techniques/T1518/001)
- LGTM notes: lgtm:pe-sieve-as-detection-reference, lgtm:memory-forensics-as-fileless-counter, lgtm:memory-forensics-detection-coverage, lgtm:gap-memory-forensics-detection-coverage
- Public references: PE-sieve (hasherezade), Volatility (Volatility Foundation), Moneta (forrest-orr)

## Source Reference

No current implementation. See atlas material and public tool repositories for scanner capabilities. HUGIN source files `pe_header_stomp.rs`, `ghost.rs`, and `ki_step_over.rs` implement countermeasures against specific scanner heuristics documented in this card.
<!-- END CARD T-093 -->

<!-- BEGIN CARD T-094 -->
---
id: T-094
name: Memory Forensics Detection Layer PE-sieve Moneta Volatility
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1518.001
mitre_secondary: [T1055]
tags: [memory-forensics, pe-sieve, moneta, volatility, vad-tree, peb-loader, unbacked-memory, detection-layer, huntress, cross-reference]
origin: atlas-synthesis
member_notes: [lgtm:memory-forensics-tooling, lgtm:convergence-pe-sieve-vs-vault-injection]
---

# Memory Forensics Detection Layer (PE-sieve, Moneta, Volatility) — Scanner Heuristics Cross-Referenced to Injection Methods

## Summary

PE-sieve (Hasherzade), Moneta (forrest-orr), and Volatility (Volatility Foundation) detect in-memory implants through distinct heuristics that target different Windows data structures and memory properties. PE-sieve walks the PEB Loader list and cross-checks each `LDR_DATA_TABLE_ENTRY` against the on-disk image via `MEMORY_BASIC_INFORMATION`, flagging modules where the `ImageBase` mismatches or the MZ/PE headers indicate shadow copies or stomped .text sections. Moneta targets unbacked `PAGE_EXECUTE_READWRITE` and `PAGE_EXECUTE_READ` regions in a generic scan that does not depend on PE header presence. Volatility performs full-memory-image analysis of `EPROCESS` blocks, VAD trees, and PEB structures to identify injected code, hollowed processes, and unbacked executable regions from a captured snapshot. The vault documents multiple injection methods that specifically aim to evade these heuristics — module stomping (T-007) produces a PEB loader entry that matches a valid module, Threadless injection (T-008) modifies export function bytes within a legitimately loaded module, and Dirty Vanity (T-011) creates a reflected process copy. The convergence between SEC670's defender-side scanner presentation and the vault's attacker-side injection coverage indicates that operators must model these specific tools as named adversaries, not merely as generic "memory scanning."

## Mechanism

1. **PE-sieve module-walk detection** — PE-sieve enumerates the target process's PEB by reading `PEB->Ldr->InLoadOrderModuleList`. For each `LDR_DATA_TABLE_ENTRY`, it extracts the `DllBase` (module base address), `SizeOfImage` (module size), and `FullDllName` (on-disk path). It then calls `VirtualQuery` on the `DllBase` to obtain a `MEMORY_BASIC_INFORMATION` structure. The `Type` field must be `MEM_IMAGE` for a legitimately loaded module. If `Type` is `MEM_PRIVATE`, the region was allocated via `VirtualAlloc` and manually populated — the signature of a reflectively loaded DLL that was inserted into the PEB loader list without a corresponding section object. PE-sieve then reads the in-memory PE headers at `DllBase`, extracts the `.text` section RVA and size from the `IMAGE_SECTION_HEADER`, and reads the on-disk `.text` bytes from `FullDllName`. A byte-by-byte comparison of in-memory `.text` against on-disk `.text` reveals module stomping (the .text was overwritten with different code) or hooking (individual bytes patched for inline hooks).

2. **PE-sieve unbacked-region detection** — PE-sieve scans all committed memory regions in the process via `VirtualQuery` walks. For each region with executable protection (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`), PE-sieve checks whether the region contains a valid MZ header. If a valid PE image is found in a region that is not listed in the PEB loader list, PE-sieve flags it as an unmapped module — the signature of a manually mapped PE or large shellcode block that was not registered with the loader.

3. **Moneta unbacked-executable scan** — Moneta walks the process's virtual address space via `VirtualQuery`. For each committed region, it checks the `Protect` field for executable flags and the `Type` field for backing status. Regions with `Type == MEM_PRIVATE` and executable protection are flagged as suspicious — these correspond to `VirtualAlloc` allocations used for shellcode. Regions with `Type == MEM_IMAGE` and `PAGE_EXECUTE_READWRITE` protection are flagged as anomalous — legitimate modules are typically `PAGE_EXECUTE_READ` after the loader applies write-protect. Moneta does not require a valid PE header to flag a region, making it effective against headerless shellcode and PE-header-stomped images.

4. **Volatility VAD tree analysis** — Volatility reads the `EPROCESS->VadRoot` field from the kernel's process record in the memory image. Each `MMVAD` node describes a virtual address range with `StartingVa`, `EndingVa`, protection flags (`u.VadFlags.Protection`), and a `Subsection` pointer to the `FILE_OBJECT` for file-backed mappings. Volatility flags VAD nodes with `PAGE_EXECUTE_READWRITE` protection and no `Subsection` (no `FILE_OBJECT`) as unbacked executable regions. It also cross-references the VAD tree against the PEB loader list to identify modules present in the VAD but absent from the loader list, or modules whose VAD protection flags indicate `PAGE_EXECUTE_READWRITE` when they should be `PAGE_EXECUTE_READ`.

## OS Internals Context

The PEB Loader list is anchored at `PEB->Ldr->InLoadOrderModuleList`, a `LIST_ENTRY` doubly-linked list. Each node is a `LDR_DATA_TABLE_ENTRY` (also accessible via `InMemoryOrderModuleList` and `InInitializationOrderModuleList` in the same structure). The `LDR_DATA_TABLE_ENTRY` on x64 contains `InLoadOrderLinks` (16 bytes), `InMemoryOrderLinks` (16 bytes), `InInitializationOrderLinks` (16 bytes), `DllBase` (8 bytes), `EntryPoint` (8 bytes), `SizeOfImage` (4 bytes + 4 padding), `FullDllName` (16 bytes, UNICODE_STRING), `BaseDllName` (16 bytes, UNICODE_STRING), followed by flags, load count, and timestamp fields. The total structure size is approximately 0x98 bytes on x64.

When a module is loaded via `LdrLoadDll`, the loader creates a section object (`NtCreateSection` with `SEC_IMAGE`), maps it via `NtMapViewOfSection`, and inserts a `LDR_DATA_TABLE_ENTRY` into all three loader lists. The VAD entry for the mapped region has `Type == MEM_IMAGE` and the `Subsection` pointer references the `FILE_OBJECT` for the DLL file. A manually mapped PE that calls `VirtualAlloc` and copies sections manually creates a `MEM_PRIVATE` VAD entry with no `Subsection` — the absence is what Moneta and Volatility detect. A manually mapped PE that uses `NtCreateSection` + `NtMapViewOfSection` with `SEC_IMAGE` creates a `MEM_IMAGE` VAD entry with a `Subsection`, but the PEB loader list does not contain an entry for it — PE-sieve detects this as an unmapped module.

Module stomping (T-007) overwrites the `.text` section of a legitimately loaded module. The VAD entry remains `MEM_IMAGE` with a valid `Subsection`, and the PEB loader list contains the entry. PE-sieve's in-memory versus on-disk `.text` comparison detects the byte mismatch. The countermeasure is PE header stomping (zeroing the MZ/PE headers), which prevents PE-sieve from locating the `.text` section RVA — but Moneta still flags the region as `PAGE_EXECUTE_READWRITE` if the protection was not reset to `PAGE_EXECUTE_READ` after writing.

Threadless injection (T-008) modifies bytes within an export function of a loaded module. The modified bytes are within the module's `.text` section. PE-sieve's `.text` comparison detects the mismatch if the modified bytes fall within the `.text` section range. The countermeasure in Threadless is that the modification is small (a trampoline jump) and the original bytes are restored after execution — but during the execution window, the `.text` mismatch is detectable.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the defensive detection layer against which the vault's injection methods are measured.

The HUGIN source implements countermeasures against specific scanner heuristics. The `pe_header_stomp.rs` file in `dark_crystal/crates/core/src/experimental/` zeroes the PE headers (MZ magic, DOS stub, NT headers, section table) of a mapped image, preventing PE-sieve from extracting the `.text` section RVA. The function `stomp_own_pe_header` reads the `SizeOfHeaders` field from the `IMAGE_OPTIONAL_HEADER` and zeroes that many bytes from the image base. The `stomp_self_header` function uses `gs:[0x60]` to locate the PEB, reads `PEB->ImageBaseAddress` at offset 0x10, calls `VirtualProtect` to make the header region writable, then zeroes it. This defeats PE-sieve's header-based identification but does not defeat Moneta's executable-protection-based scan.

The `ghost.rs` file in `dark_crystal/crowd/src/` implements Process Ghosting, which creates a process backed by a `SEC_IMAGE` section. The resulting VAD entry has `Type == MEM_IMAGE` and a valid `Subsection` pointer, making it appear as a legitimately loaded module to Volatility's VAD analysis. The file was delete-pending before the payload was written, so the on-disk file does not exist for PE-sieve to compare against — but PE-sieve can still flag the module as anomalous if it has no corresponding `FILE_OBJECT` at scan time.

## Why It Matters

The vault documents injection methods that specifically target the unbacked-executable heuristic. Module stomping (T-007) produces a PEB loader entry backed by `MEM_IMAGE`. Threadless injection (T-008) modifies bytes within an existing module's `.text`. Dirty Vanity (T-011) creates a reflected process copy. These techniques are designed against specific scanner heuristics, but the vault does not document which scanner catches which technique by what mechanism. This card provides the cross-reference that enables operators to select injection methods based on the expected forensic tooling on the target, not merely on the EDR product.

## Detection Considerations

- **Telemetry sources**: PE-sieve operates on live process memory or dumps. Moneta operates on live process memory. Volatility operates on full-system memory images. None generate ETW events. Huntress Labs deploys PE-sieve-based scanning at scale across endpoints, making it a realistic adversary on Huntress-managed targets.
- **Bypass options**: PE header stomping defeats PE-sieve's header-based identification. `SEC_IMAGE` section mapping defeats Moneta's unbacked-executable heuristic. PEB loader list registration defeats PE-sieve's unmapped-module detection. `.text` byte restoration after execution defeats PE-sieve's in-memory versus on-disk comparison (used by Threadless injection's self-restoring trampoline).
- **Residual artifacts**: VAD tree entries are kernel-managed and persist for process lifetime. PEB loader list entries persist until unlinked. `MEMORY_BASIC_INFORMATION` fields (`Type`, `Protect`) are kernel-managed and cannot be spoofed from user mode. A memory image captured during a sleep window (when Ekko ROP Sleep has encrypted `.text`) shows non-matching bytes, but a capture during the active window shows the decrypted `.text`.

## Related Techniques

- **T-007 Pool Party** — Thread pool injection creates unbacked executable regions that PE-sieve flags via MEMORY_BASIC_INFORMATION Type=MEM_PRIVATE with executable protection
- **T-008 Threadless** — Export function byte modification within a loaded module is detectable by PE-sieve's in-memory versus on-disk .text comparison during the execution window
- **T-011 Dirty Vanity** — Process reflection via RtlCreateProcessReflection creates a cloned process whose memory state Volatility can diff against the parent to identify reflected implants
- **T-013 Remaining Methods** — Module stomping and mapping injection produce artifacts that PE-sieve detects via PEB->Ldr->InLoadOrderModuleList cross-referencing and .text byte comparison
- **T-016 EDR Evasion Suite** — NTDLL unhooking restores .text bytes from a fresh copy, but PE-sieve can detect the restoration if the tool maintains a baseline hash of the original .text
- **T-003 VEH Syscall Gate** — VEH-based syscall dispatch does not create unbacked executable memory, reducing Moneta's detection surface relative to VirtualAlloc-based stub methods

## References

- Atlas material: atlas-post-exploit-part5, atlas-recon-part2
- MITRE ATT&CK: T1518.001 (https://attack.mitre.org/techniques/T1518/001)
- LGTM notes: lgtm:memory-forensics-tooling, lgtm:convergence-pe-sieve-vs-vault-injection
- Public references: PE-sieve (hasherezade), Moneta (forrest-orr), Volatility (Volatility Foundation), Huntress Labs

## Source Reference

No current implementation. See atlas material and public tool repositories. HUGIN source files `dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` and `dark_crystal/crowd/src/ghost.rs` implement countermeasures against specific scanner heuristics documented in this card.
<!-- END CARD T-094 -->

<!-- BEGIN CARD T-095 -->
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

1. Call `CreateFileA` with `\\??\\C:\\Windows\\System32\
tdll.dll` (or the appropriate NT path) to open the on-disk ntdll with `GENERIC_READ` access.
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

The three variants differ in their source of clean bytes. Variant 1 (byte-level) reads individual function prologues from the on-disk file. This requires knowledge of the trampoline layout (how many bytes to replace) which varies by EDR vendor and version. Variant 2 (fresh-copy) reads the entire `.text` section from the on-disk file via a mapped section. This requires no per-function knowledge — the entire `.text` is replaced. The on-disk file is the canonical source because the Windows loader reads ntdll.dll from `C:\Windows\System32
tdll.dll` at process creation and the file is not modified by the EDR (the EDR hooks the in-memory copy, not the on-disk file). Variant 3 (suspended-copy) reads the `.text` from a freshly spawned process's memory. This requires a cross-process handle (`OpenProcess` with `PROCESS_VM_READ`) and a process creation event that triggers `PsSetCreateProcessNotifyRoutine` — some EDRs flag `CREATE_SUSPENDED` process creation as suspicious.

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
<!-- END CARD T-095 -->

<!-- BEGIN CARD T-096 -->
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
<!-- END CARD T-096 -->

<!-- BEGIN CARD T-097 -->
---
id: T-097
name: Capability Staging OPSEC Reflective vs Disk
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1620
mitre_secondary: [T1027]
tags: [opsec, reflective-loading, disk-staging, capability-loss, detection-surface, fileless, payload-staging, minifilter, defender-realtime]
origin: atlas-synthesis
member_notes: [lgtm:coverage-gap-payload-staging-opsec, lgtm:capability-staging-opsec-convergence]
---

# Capability Staging OPSEC — Reflective vs Disk — The Dual Failure Model for Payload Placement

## Summary

SEC670 frames dropping a capability to disk as risking two equivalent operational failures: detection by file-system minifilter drivers or Windows Defender real-time protection, and loss of the capability itself because the staged binary becomes a recoverable artifact for defenders to reverse-engineer. The convergence across SEC670, MalDev Academy, and CRTO tradecraft is that capabilities should prefer reflective loading (manual PE mapping via `RtlImageNtHeaders` and in-process section copying) over disk staging on systems with unknown security products. The vault documents fileless execution techniques (T-009 Process Ghosting, T-010 Process Herpaderping, T-013 reflective PE loader) and artifact management (T-016 evasion suite) but does not frame the staging decision as an explicit OPSEC tradeoff with dual failure modes. SEC670's framing — detection and capability loss as equivalent failures — changes the operator's risk calculus: a staged capability that is detected is not merely burned, it is actively counterproductive because it provides the defender with a recoverable sample of the operator's tooling.

## Mechanism

1. Assess the target environment's detection surface for disk writes:
   - File-system minifilter drivers intercept `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION` operations. EDR products register minifilters that scan files on creation, modification, and rename.
   - Windows Defender real-time protection uses a minifilter (`WdFilter.sys`) that scans files on write (` real-time protection`) and on execution (`behavior monitoring`). The scan triggers when a file with an executable extension (`.exe`, `.dll`, `.sys`) is written to disk.
   - Sysmon Event ID 11 (FileCreate) and Event ID 23 (FileDelete) log file creation and deletion events if Sysmon is configured with file event monitoring.

2. Assess the target environment's detection surface for in-memory execution:
   - ETW-TI (Threat Intelligence) providers emit events for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`, `NtMapViewOfSection` with executable protection, and `WriteProcessMemory` across process boundaries.
   - Kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `MmProtectExecutableSection`) observe process creation and executable page protection changes.
   - Memory forensics tools (Volatility, PE-sieve, Moneta — see T-093, T-094) scan for unbacked executable regions and module mismatches in post-capture analysis.

3. Select a staging strategy based on the dual failure model:
   - **Reflective loading** (preferred on unknown targets): the payload PE is embedded in the loader's `.data` or `.rsrc` section, decrypted in memory, and manually mapped via `NtAllocateVirtualMemory` + section copying + import resolution + relocation fixing. No file is written to disk. Detection surface: ETW-TI events for `VirtualAlloc` with executable protection, Moneta's unbacked-executable scan. Capability loss: none — the payload exists only in volatile memory and is lost when the process exits or is terminated.
   - **Disk staging** (acceptable on known-permissive targets): the payload PE is written to disk, then loaded via `LoadLibrary` or executed via `CreateProcess`. Detection surface: file-system minifilter scan on write, Windows Defender real-time scan, Sysmon file events. Capability loss: high — the file persists on disk and is recoverable by forensics even after deletion (NTFS journal, Volume Shadow Copy, file carving on unallocated clusters).
   - **Process Ghosting** (T-009): the payload is written to a delete-pending file, mapped as a `SEC_IMAGE` section, then the file is closed (disappears from disk). The section persists in memory as a file-backed executable region. Detection surface: the file exists on disk only during the write-to-close window (milliseconds), reducing minifilter scan exposure. Capability loss: low — the file is marked for deletion before the EDR can scan it, and the section is backed by a file that no longer exists.
   - **Process Herpaderping** (T-010): the payload is written to a file, a process is created from the file, then the file content is overwritten with a legitimate binary. The process executes the original payload, but the on-disk file shows the legitimate binary. Detection surface: file-system minifilter sees the original write and the subsequent overwrite. Capability loss: the overwritten content may be recoverable via NTFS journaling.

4. Execute the selected staging strategy.
5. Verify that no recoverable artifact remains: for reflective loading, confirm that the embedded payload bytes in the loader's `.data` section are overwritten or encrypted after mapping. For disk staging, confirm that the file is deleted and optionally overwritten with random bytes before deletion.

## OS Internals Context

The file-system minifilter model operates at the IRP (I/O Request Packet) layer. When a user-mode application calls `CreateFileW` followed by `WriteFile`, the I/O Manager constructs an `IRP_MJ_CREATE` followed by an `IRP_MJ_WRITE` IRP and sends it down the device stack. Minifilter drivers register callbacks via `FltRegisterFilter` for pre-operation (`FLT_PRE_OPERATION_CALLBACK`) and post-operation (`FLT_POST_OPERATION_CALLBACK`) notification on specific IRP types. EDR minifilters intercept `IRP_MJ_CREATE` to scan files before they are opened and `IRP_MJ_WRITE` to scan content before it is written. The scan occurs synchronously — the minifilter can return `FLT_PREOP_COMPLETE` to deny the operation, preventing the file write from completing.

Windows Defender's real-time protection uses the `MpFilter` (WdFilter.sys) minifilter driver. It registers pre-operation callbacks on `IRP_MJ_CREATE` (to scan files being opened for execution), `IRP_MJ_WRITE` (to scan content being written), and `IRP_MJ_CLEANUP` (to scan files being closed after modification). The scan engine checks file content against signature databases, heuristics, and cloud-delivered definitions. A PE file written to disk triggers the `IRP_MJ_WRITE` callback, which extracts the file content and runs the signature engine against it.

Reflective loading avoids the file-system minifilter entirely because no `IRP_MJ_CREATE` or `IRP_MJ_WRITE` IRPs are generated — the payload exists as an in-memory buffer and is mapped via `NtAllocateVirtualMemory` (which does not involve the file system). The detection surface shifts to ETW-TI (which monitors `VirtualAlloc` with executable protection) and memory forensics (which scans for unbacked executable regions). The `NtAllocateVirtualMemory` call with `PAGE_EXECUTE_READWRITE` generates a `Microsoft-Windows-Kernel-Process` ETW event (event ID 1 for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`) that ETW-TI consumers can process.

Process Ghosting exploits the file system's delete-pending state. When `NtSetInformationFile` is called with `FileDispositionInformation` and `DeleteFile = TRUE`, the file is marked for deletion when the last handle is closed. The file remains open and writable — `NtWriteFile` succeeds on a delete-pending file — but the file is invisible to new `CreateFile` callers (they receive `STATUS_DELETE_PENDING`). Minifilter drivers that intercept `IRP_MJ_CREATE` cannot open the file for scanning because the create operation fails. The `NtCreateSection` call with `SEC_IMAGE` succeeds because the section references the file object via the existing open handle, not via a new create operation. When the file handle is closed, the file is deleted from the filesystem — but the section object persists, backed by the file data that was written before deletion.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the OPSEC decision framework that governs payload placement across multiple vault techniques.

The HUGIN source implements several staging strategies referenced in this card. The `dark_crystal/crowd/src/ghost.rs` file implements Process Ghosting (T-009), which stages the payload via a delete-pending file and `SEC_IMAGE` section mapping. The `dark_crystal/crowd/src/payload_cfg.rs` file contains the configuration constants that select the staging strategy: `INJECTION_TYPE` (set to `"module_overload"` in the provided configuration), `PAYLOAD` (empty, indicating runtime payload acquisition rather than embedding), `GHOST_MASQUERADE` (the masquerade path for ghosted processes), and `OVERLOAD_DLL` (the target DLL for module overloading). The configuration supports selecting between process ghosting, module overloading, function stomping, and thread hijacking as staging strategies, each with a different detection and capability-loss profile.

## Why It Matters

The vault documents four staging strategies (T-009 Process Ghosting, T-010 Process Herpaderping, T-013 reflective PE loader, T-016 evasion suite) without surfacing the unifying OPSEC rationale that motivates their existence. SEC670's framing of detection and capability loss as equivalent failures changes the operator's risk assessment: a staged binary that triggers a Defender scan is not merely detected — it is seized by the defender, who now possesses a sample of the operator's malware that can be reverse-engineered, signatured, and distributed to other endpoints. This dual failure model means that disk staging is never a neutral choice; it is always a calculated risk that the operator must evaluate against the target's file-system monitoring posture. Documenting this rationale as a cross-cutting OPSEC framework enables operators to select staging strategies by intent (avoid disk write) rather than by mechanism (ghosting versus herpaderping versus reflective loading).

## Detection Considerations

- **Telemetry sources**: File-system minifilter callbacks (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`) detect disk writes. ETW-TI `VirtualAlloc` events detect in-memory allocation with executable protection. Sysmon Event ID 11 detects file creation. Windows Defender real-time protection scans files on write.
- **Bypass options**: Reflective loading avoids file-system minifilter callbacks. Process Ghosting reduces the minifilter exposure window to the write-to-close interval. Module overloading (mapping into a legitimately loaded module's address space) avoids `VirtualAlloc` with executable protection by using the module's existing `PAGE_EXECUTE_READ` region. PE header stomping (T-096) prevents PE-sieve from identifying the in-memory payload.
- **Residual artifacts**: Reflective loading leaves no disk artifact but leaves an unbacked executable VAD entry. Process Ghosting leaves no disk artifact (file is deleted) but leaves a `SEC_IMAGE`-backed VAD entry. Module overloading leaves no unbacked VAD entry but modifies a legitimately loaded module's `.text` bytes (detectable by PE-sieve). Disk staging leaves a recoverable file artifact even after deletion (NTFS journal, Volume Shadow Copy, file carving).

## Related Techniques

- **T-009 Process Ghosting** — Delete-pending file execution avoids persisting a scannable artifact on disk, reducing both detection and capability-loss risk
- **T-010 Process Herpaderping** — File content race avoids leaving a recoverable payload sample on disk by overwriting the file after process creation
- **T-013 Remaining Methods** — Reflective PE loader implements in-memory mapping to avoid disk staging entirely
- **T-016 EDR Evasion Suite** — Evasion techniques assume the payload is already in memory; staging to disk would create a recoverable artifact that defeats the evasion posture
- **T-020 Anti-Analysis Suite** — Anti-VM and API hammering do not address the disk-write avoidance rationale that motivates fileless execution

## References

- Atlas material: atlas-post-exploit-part15, atlas-post-exploit-part17
- MITRE ATT&CK: T1620 (https://attack.mitre.org/techniques/T1620)
- LGTM notes: lgtm:coverage-gap-payload-staging-opsec, lgtm:capability-staging-opsec-convergence
- Public references: SEC670, MalDev Academy, CRTO tradecraft (reflective loading preference on unknown targets)

## Source Reference

No current implementation. See atlas material for the OPSEC decision framework. HUGIN source files `dark_crystal/crowd/src/ghost.rs` (Process Ghosting) and `dark_crystal/crowd/src/payload_cfg.rs` (staging strategy configuration) implement specific staging strategies referenced in this card.
<!-- END CARD T-097 -->

<!-- BEGIN CARD T-098 -->
---
id: T-098
name: Custom Loader Development and Unhook Bypass C2 Arc
category: edr-evasion
tier: A
crate: dark_crystal
source_file: dark_crystal/crowd/src/ghost.rs
mitre: T1620
mitre_secondary: [T1055]
tags: [custom-loader, manual-pe-mapping, unhook-bypass-arc, c2-callback, phase-sequence, dropper, tradecraft-arc, reflective-loading]
origin: atlas-synthesis
member_notes: [lgtm:cross-source-convergence-custom-loader-to-callback-arc, lgtm:custom-loader-development-tradecraft]
---

# Custom Loader Development and Unhook→Bypass→C2 Callback Arc — Integrated Operational Sequence from Execution to C2

## Summary

SEC670 Section 5 sequences custom loader development, NTDLL unhooking, AV/EDR bypass, AMSI patching, and C2 callback establishment as a single training arc that mirrors the operational reality of implant deployment. The loader is the initial execution vehicle — a custom PE that manually maps and executes the implant payload without invoking the standard Windows loader (`LdrLoadDll`). The loader must establish execution (manual PE mapping), defeat runtime monitoring (unhook ntdll, patch `amsi.dll!AmsiScanBuffer`, muffle ETW), and then establish C2 callback registration before the implant can initiate network communication. The vault's `dark_crystal` crate contains loader infrastructure (phase runner, transport, injection modules) but T-016 does not document the full arc from loader development through C2 callback as an integrated discipline. The arc's ordering — loader first, then in-process evasion, then callback — reflects a hard dependency chain: the implant cannot phone home until evasion is in place, and evasion cannot be applied until the implant is executing in memory.

## Mechanism

1. **Loader execution** — The loader is the initial binary that the operator delivers to the target. It may be embedded with the payload (static linking via `include_bytes!`) or acquire it at runtime (remote download via WinHTTP, read from an alternate data stream, or receive via a stager protocol). The loader's first action is to decrypt the payload in memory (AES-256-GCM decryption in the HUGIN implementation) and prepare it for manual mapping.

2. **Manual PE mapping** — The loader maps the payload PE into the current process's address space without calling `LoadLibrary` or `LdrLoadDll`:
   - Parse the PE headers: read `IMAGE_DOS_HEADER` from the payload base, follow `e_lfanew` to `IMAGE_NT_HEADERS`, read `OptionalHeader.SizeOfImage`.
   - Allocate memory: call `NtAllocateVirtualMemory` with `MEM_COMMIT | MEM_RESERVE` and `PAGE_READWRITE` (writable during mapping; protection is changed to `PAGE_EXECUTE_READ` after all fixups).
   - Copy sections: iterate `IMAGE_SECTION_HEADER` entries, copy each section from `PointerToRawData` to `VirtualAddress` relative to the allocated base.
   - Resolve imports: iterate `IMAGE_IMPORT_DESCRIPTOR` entries, for each DLL call `LdrLoadDll` (or manually resolve via PEB walk T-004), for each function resolve via `LdrGetProcedureAddress` (or manual export table walk T-050), write function pointers to the IAT.
   - Fix relocations: iterate `IMAGE_BASE_RELOCATION` blocks, apply `IMAGE_REL_BASED_DIR64` relocations by adding the delta between the allocated base and the PE's preferred `ImageBase`.
   - Execute TLS callbacks: iterate `IMAGE_DIRECTORY_ENTRY_TLS` callbacks if present.
   - Call entry point: invoke `AddressOfEntryPoint` with `DLL_PROCESS_ATTACH`.
   - Change protection: call `NtProtectVirtualMemory` to set the `.text` section to `PAGE_EXECUTE_READ`.

3. **In-process evasion** — After the payload is mapped and executing, the loader applies evasion techniques:
   - NTDLL unhook: restore original `.text` bytes (see T-095 for variant selection).
   - AMSI patch: overwrite `amsi.dll!AmsiScanBuffer` prologue with `ret` or `mov eax, 0; ret`.
   - ETW muffle: overwrite `ntdll!NtTraceEvent` or `ntdll!EtwTraceEvent` prologue with `ret`.
   - Block DLL policy: set `ProcessDynamicCodePolicy` via `NtSetInformationProcess` to prevent non-Microsoft DLL injection.
   - PEB unlink: remove the payload's `LDR_DATA_TABLE_ENTRY` from the PEB loader list (if registered).
   - PE header stomp: zero the payload's PE headers to prevent PE-sieve identification.

4. **C2 callback establishment** — After evasion is in place, the implant establishes its C2 channel:
   - Register a callback timer (e.g., `CreateTimerQueueTimer` or `SetTimer`) that periodically invokes the C2 check-in function.
   - Initialize the transport layer (TCP, HTTP long-poll, or peer relay in the HUGIN implementation).
   - Perform the initial check-in: send a beacon with system information, receive tasking or configuration updates.
   - Enter the command dispatch loop: the callback receives C2 messages and dispatches them to handler functions (keylogger, screen capture, browser hook, etc.).

## OS Internals Context

The manual PE mapping step replaces the functionality of `LdrLoadDll` and the loader-side `LdrpInitializeProcess` routine. The Windows loader (`ntdll!LdrpInitializeProcess`) performs the same sequence — section mapping, import resolution, relocation application, TLS callback execution, and entry point invocation — but it also registers the module in the PEB loader list (`LdrpHashTable`, `LdrpModuleBaseAddressIndex`), applies security checks (CFG, ASLR, SafeSEH), and notifies ETW providers (`Microsoft-Windows-Kernel-Process` for image load events). By performing manual mapping, the loader avoids generating the ETW image-load event (`EventID = 4` in the `Microsoft-Windows-Kernel-Process` provider) and avoids registering the module in the PEB loader list, making the payload invisible to `EnumProcessModules` and `Module32First`/`Module32Next` enumeration APIs.

The ordering of the arc — loader, then evasion, then C2 — reflects hard dependencies. The AMSI and ETW patches must be applied before the payload executes any code that might be scanned (e.g., PowerShell commands, .NET assembly loading) or that emits ETW events (e.g., network connections via WinHTTP). The NTDLL unhook must be applied before the payload makes any `Nt*` calls that would traverse the EDR's inline hook trampolines. The C2 callback must be established after evasion to ensure that the initial beacon does not trigger ETW network events or AMSI content scans.

The `dark_crystal` crate's phase runner structure mirrors this arc. The `payload_cfg.rs` file configures the phases: `ANTI_VM` and `HAMMER_ENABLED` (pre-execution anti-analysis), `AMSI_HBP` and `ETW_PATCH` (in-process evasion), `INJECTION_TYPE` (payload staging), `SLEEP_MS` (sleep obfuscation timing), and persistence configuration (`PERSIST_ENABLED`, `PERSIST_METHODS`). The phase runner executes these in an ordered sequence that matches the SEC670 arc.

## Key Implementation Details

The `dark_crystal/crowd/src/ghost.rs` file implements the loader component of the arc via Process Ghosting. The `spawn_ghosted` function accepts a decrypted PE payload, a masquerade path (e.g., `C:\Windows\System32\svchost.exe`), and an optional PPID for parent spoofing. It creates a delete-pending temp file, writes the payload, creates a `SEC_IMAGE` section, closes the file (removing it from disk), creates a process via `NtCreateProcessEx` with the section handle, reads the ghosted process's PEB via `NtQueryInformationProcess(ProcessBasicInformation)`, constructs `RTL_USER_PROCESS_PARAMETERS` with the masquerade path via `RtlCreateProcessParametersEx`, writes the parameters into the ghosted process, and creates a thread at the payload's `AddressOfEntryPoint` via `NtCreateThreadEx`.

The `dark_crystal/crowd/src/ki_step_over.rs` file implements the bypass component of the arc. The `install_step_over` function accepts a list of NT function names, resolves their SSNs via the `resolve.rs` PEB walker, checks whether each function is hooked (presence of `0xE9` JMP at offset +3 from the function start), registers the function in an internal SSN table, and sets hardware breakpoints (DR0-DR3) on the hooked instructions. The `exception_handler` function intercepts the resulting single-step exceptions via a `Wow64PrepareForException` callback hook, sets `RAX` to the resolved SSN, sets `RIP` to the `syscall` instruction (skipping the EDR's trampoline), and resumes via `NtContinue`.

The `dark_crystal/crowd/src/payload_cfg.rs` file contains the configuration constants that wire the arc together: `INJECTION_TYPE = "module_overload"` (staging strategy), `ANTI_VM = true` (pre-execution check), `HAMMER_ENABLED = true` (sandbox delay), `AMSI_HBP = ON` (AMSI bypass via hardware breakpoint), `ETW_PATCH = true` (ETW muffle), `BLOCK_DLL = true` (process mitigation policy), `PPID_AUTO = true` (parent spoofing), `SLEEP_MS = 3000` (sleep obfuscation timing), and `PERSIST_ENABLED = true` with `PERSIST_METHODS = "com_hijack"` (persistence layer).

## Why It Matters

The vault documents loader infrastructure (T-022 architecture overview), evasion techniques (T-016), and networking (T-022) as separate capability areas. SEC670 material establishes that these are phases of a single operational arc with hard ordering dependencies: the loader must map the payload before evasion can be applied, and evasion must be applied before the C2 callback can beacon safely. Documenting this arc as an integrated discipline surfaces the ordering constraints that determine whether an operator's deployment succeeds or fails. An operator who establishes C2 before patching AMSI will have their beacon content scanned. An operator who patches AMSI before the payload is mapped will have the mapping operation itself scanned. The arc's ordering is not a recommendation — it is a dependency chain enforced by the runtime behavior of Windows security components.

## Detection Considerations

- **Telemetry sources**: The manual PE mapping step generates `NtAllocateVirtualMemory` ETW events. The evasion step generates `VirtualProtect` events on executable pages. The C2 step generates network connection ETW events (`Microsoft-Windows-Kernel-Network` provider) and DNS query events. Kernel callbacks (`PsSetCreateProcessNotifyRoutine`) fire during the `NtCreateProcessEx` call in the Ghosting variant.
- **Bypass options**: The `ki_step_over.rs` approach bypasses EDR hooks without modifying ntdll's `.text`, avoiding the `VirtualProtect` events that unhooking generates. Indirect syscalls (T-001 RecycledGate) avoid the ntdll stub entirely, reducing the ETW surface. Sleep obfuscation (T-005 Ekko ROP Sleep) encrypts the payload during sleep windows, making memory captures during sleep show encrypted bytes.
- **Residual artifacts**: The ghosted process appears in the process list with the masquerade path. The PEB loader list does not contain the payload (it was mapped via `NtCreateProcessEx` from a section, not via `LdrLoadDll`). The VAD tree contains a `SEC_IMAGE`-backed entry for the ghosted process. The C2 network connections produce traffic that network monitoring (IDS, proxy logs) can detect.

## Related Techniques

- **T-016 EDR Evasion Suite** — The unhook, AMSI patch, and ETW patch phases follow the loader phase in the operational arc; this card documents the ordering dependency between loading and evasion
- **T-022 Network Suite** — C2 callback establishment is the terminal phase of the arc; the transport layer (TCP, HTTP long-poll, peer relay) is configured after evasion is in place
- **T-013 Remaining Methods** — The manual PE loader implements the reflective loading component of the arc, mapping the payload without invoking the standard Windows loader

## References

- Atlas material: atlas-methodology-part8, atlas-methodology-part9
- MITRE ATT&CK: T1620 (https://attack.mitre.org/techniques/T1620)
- LGTM notes: lgtm:cross-source-convergence-custom-loader-to-callback-arc, lgtm:custom-loader-development-tradecraft
- Public references: SEC670 Section 5 (Custom Loaders, units 27-29, 32-37)

## Source Reference

`dark_crystal/crowd/src/ghost.rs` (lines 1-340): implements `spawn_ghosted` — the loader component via Process Ghosting, including `NtCreateProcessEx`, PEB reading, process parameter construction, and entry point thread creation. `dark_crystal/crowd/src/ki_step_over.rs` (lines 1-320): implements `install_step_over` — the bypass component via hardware breakpoint interception. `dark_crystal/crowd/src/payload_cfg.rs` (lines 1-120): configuration constants wiring the arc phases.
<!-- END CARD T-098 -->