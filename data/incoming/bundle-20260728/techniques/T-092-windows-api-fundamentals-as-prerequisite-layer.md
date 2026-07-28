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