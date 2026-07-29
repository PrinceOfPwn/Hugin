# Cluster Spec — T-091: SAL Annotation Literacy as API-Contract Reading Skill

- **T-NNN ID**: `T-091`
- **Canonical name**: SAL Annotation Literacy as API-Contract Reading Skill
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: medium — 2 member notes from different atlas batches; unblocks multiple syscall/API hand-binding cards.
- **would_relate_to**: ['T-002', 'T-004', 'T-013', 'T-014', 'T-015', 'T-016']

## Consolidated Description

SEC670 dedicates a section to Microsoft's Source Annotation Language as the
canonical method for reading Windows SDK header signatures when hand-binding
NT APIs (vs FFI declarations or dumpbin /exports). The annotation set
includes _In_, _Out_, _Inout_, _In_opt_, _In_reads_(N), _Out_writes_(N),
_In_bytecount_(cb), _deref_out_. The card should document each annotation's
caller obligation: _In_ = caller provides initialized buffer; _Out_ = callee
writes, caller allocates; _Inout_ = callee may read+write; _In_reads_(N) =
caller-provided buffer of N elements; _In_opt_ = NULL permitted. Specific
examples from T-004/T-013/T-016 hand-bound APIs:
NtQueryInformationProcess(ProcessBasicInformation) expects _In_ HANDLE
ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass,
_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
_In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength.
Misreading these contracts causes silent truncation or buffer overflow.


## Member LGTM Notes (2)

### Note 1: SAL Annotations as an API-Contract Reading Skill
- id: `lgtm:sal-annotations-as-graph-concept`
- origin: atlas-exploit-dev-part4
- would_relate_to: ['T-004', 'T-002']
- tags: ['sal', 'win32-api', 'sdk-headers', 'ffi', 'api-contract']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part4
**Would relate to:** T-004, T-002
**Source units:** unit 14, unit 15

SEC670 dedicates a section to Microsoft's Source Annotation Language (_In_, _Out_, _Inout_, _In_opt_, _deref_out_) as the way to read Windows SDK header signatures when hand-binding NT APIs. This matters for T-004 PEB Walker and T-002 SSN resolution where the operator copies NT function prototypes from the SDK. The vault documents the PEB walker and SSN resolver implementations but does not document the skill of reading SAL to know whether an NT API parameter is consumed, produced, or optional — which determines how to lay out the FFI signature in Rust.

### Note 2: SAL Annotation Literacy as Foundational Vault Coverage
- id: `lgtm:sal-annotation-literacy-coverage-gap`
- origin: atlas-exploit-dev-part6
- would_relate_to: ['T-013', 'T-014', 'T-015', 'T-016']
- tags: ['sal', 'api-documentation', 'coverage-gap', 'foundational']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part6
**Would relate to:** T-013, T-014, T-015, T-016
**Source units:** unit 1, unit 2, unit 3, unit 4, unit 6, unit 9, unit 11, unit 12, unit 15, unit 17, unit 18, unit 21, unit 23, unit 25

SEC670 devotes substantial material to teaching SAL annotations (_In_, _Out_, _Inout_, _In_reads_, _Out_writes_bytes_all_, _Success_, _When_, _Must_inspect_result_, _Check_return_, _Ret_maybenull_) as the documented contract for every Win32/NT API. The vault uses windows_targets::link! bindings in Rust and documents the resulting API surface, but does not currently document how an operator should read the SAL annotations on the MSDN page for an API they want to call directly. Operators wrapping a new NT API need this literacy to correctly identify which parameters are optional, which buffers are read-only vs. read-write, and what the success return-value contract is. This would be cross-cutting reference material rather than a technique card.

---
Use `id: T-091`, canonical name above, and `member_notes: ['lgtm:sal-annotations-as-graph-concept', 'lgtm:sal-annotation-literacy-coverage-gap']`.
Cross-reference `would_relate_to`: ['T-002', 'T-004', 'T-013', 'T-014', 'T-015', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.