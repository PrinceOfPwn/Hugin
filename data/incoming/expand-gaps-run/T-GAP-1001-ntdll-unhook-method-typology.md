---
id: T-GAP-1001
title: "NTDLL Unhook Method Typology and Restore Sequence"
tier: "A"
category: "edr-evasion"
---

# NTDLL Unhook Method Typology and Restore Sequence

## Description
Documents the three canonical NTDLL unhook variants and their concrete API sequences. (1) Byte-level prologue patch: per-function search-and-replace of the EDR's trampoline bytes with the original Nt* prologue (the inverse of the inline-hook byte forensics pattern). (2) Fresh-copy file mapping: CreateFileA(L"\\??\\C:\\Windows\\System32\\ntdll.dll") → CreateFileMapping(PAGE_READONLY | SEC_IMAGE) → MapViewOfFile → walk IMAGE_NT_HEADERS to locate .text section → memcpy the clean .text over the hooked .text in the loaded ntdll. (3) Per-function stub restore via RtlPcToFileHeader + the on-disk ntdll .text RVA. All three are partial: kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks, CmRegisterCallback) continue to observe operations after userland hooks are removed, so unhooking must be paired with operations that do not trigger callbacks. The fresh-copy variant is operationally preferred because it does not require per-function signature knowledge.


## Rationale
Three notes (one gap, two convergence) describe the same three-variant NTDLL unhook technique; consolidating them produces one canonical typology card rather than three fragments.

## References
- lgtm:coverage-gap-ntdll-restore-api-sequence
- lgtm:cross-source-ntdll-unhook-convergence
- lgtm:cross-source-unhook-method-typology
