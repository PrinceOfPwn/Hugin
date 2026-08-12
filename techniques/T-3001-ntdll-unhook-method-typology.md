---
id: T-3001
title: "NTDLL Unhook Method Typology and Restore Sequence"
category: edr-evasion
tier: A
tags: [generated]
mitre: []
origin: glm-expand-cluster
source_cluster: ntdll-unhook-method-typology
member_notes: ['lgtm:coverage-gap-ntdll-restore-api-sequence', 'lgtm:cross-source-ntdll-unhook-convergence', 'lgtm:cross-source-unhook-method-typology']
---
## Summary

This technique card covers NTDLL Unhook Method Typology and Restore Sequence. It details mechanisms required to implement or understand ntdll-unhook-method-typology operations, serving as a critical primitive for advanced operators.

## Technical Deep Dive

Documents the three canonical NTDLL unhook variants and their concrete API sequences. (1) Byte-level prologue patch: per-function search-and-replace of the EDR's trampoline bytes with the original Nt* prologue (the inverse of the inline-hook byte forensics pattern). (2) Fresh-copy file mapping: CreateFileA(L"\\??\\C:\\Windows\\System32\\ntdll.dll") → CreateFileMapping(PAGE_READONLY | SEC_IMAGE) → MapViewOfFile → walk IMAGE_NT_HEADERS to locate .text section → memcpy the clean .text over the hooked .text in the loaded ntdll. (3) Per-function stub restore via RtlPcToFileHeader + the on-disk ntdll .text RVA. All three are partial: kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallback) continue to observe operations after userland hooks are removed, so unhooking must be paired with operations that do not trigger callbacks. The fresh-copy variant is operationally preferred because it does not require per-function signature knowledge.



```c
// Example for NTDLL Unhook Method Typology and Restore Sequence
HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
FARPROC pFunc = GetProcAddress(hNtdll, "NtQuerySystemInformation");
```

## Evidence

- `lgtm:coverage-gap-ntdll-restore-api-sequence`: Referenced in internal atlas batches as a core component of ntdll-unhook-method-typology.
- `lgtm:cross-source-ntdll-unhook-convergence`: Referenced in internal atlas batches as a core component of ntdll-unhook-method-typology.
- `lgtm:cross-source-unhook-method-typology`: Referenced in internal atlas batches as a core component of ntdll-unhook-method-typology.

## Detection & Mitigation

Routine verification of in-memory `.text` sections of core DLLs (e.g., `ntdll.dll`) against their on-disk counterparts to identify inline hooks (JMP/E9 instructions). Mitigations should involve strict WDAC policies and EDR hooks prioritizing anomalous memory accesses or abnormal API execution paths.

## Related Techniques

- T-002: Mentioned or implied foundation (e.g. System Calls)
- T-013: Mentioned or implied foundation (e.g. Thread Hijacking)

## References

- Internal Vault Research on NTDLL Unhook Method Typology and Restore Sequence
