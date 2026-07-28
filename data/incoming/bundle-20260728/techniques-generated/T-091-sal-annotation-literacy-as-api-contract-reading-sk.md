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