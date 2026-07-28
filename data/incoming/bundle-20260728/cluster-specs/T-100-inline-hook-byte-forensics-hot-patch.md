# Cluster Spec — T-100: Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue

- **T-NNN ID**: `T-100`
- **Canonical name**: Inline Hook Byte-Pattern Forensics and Hot-Patch Prologue
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `A`
- **Priority**: medium — Two notes, single operational context (unhooking); merges to round out T-016's x86 coverage.
- **would_relate_to**: ['T-016']

## Consolidated Description

Documents the exact byte patterns EDRs leave when inline-hooking ntdll, which an operator must recognize before unhooking. 64-bit hooks: 15-byte trampoline `MOV rax, imm64 (48 B8 ...); JMP rax (FF E0)`. 32-bit hooks exploit the `MOV EDI, EDI` hot-patch prologue slot and the five-NOP padding that precedes 32-bit functions — the EDR overwrites the 2-byte hot-patch slot with a 2-byte short jump back into the 5-NOP pad, then patches the pad with a 5-byte `JMP rel32` into the trampoline. The 32-bit pattern is critical because unhooking must restore both the 5-NOP pad and the `MOV EDI, EDI` prologue, not just one. The vault's T-016 ntdll_unhook documentation is implicitly x64-centric; this card adds the 32-bit prologue protocol.


## Member LGTM Notes (2)

### Note 1: Inline Hook Byte-Pattern Forensics
- id: `lgtm:inline-hook-byte-forensics`
- origin: atlas-edr-evasion-part3
- would_relate_to: ['T-016']
- tags: ['inline-hook', 'byte-pattern', 'forensics', 'enumeration', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part3
**Would relate to:** T-016
**Source units:** unit 1, unit 2, unit 3

SEC670 documents the exact byte patterns EDRs leave when inline-hooking ntdll — 32-bit `MOV EDI, EDI` hot-patch slot followed by 5-byte `JMP rel32`, and 64-bit 15-byte `MOV rax, imm64; JMP rax` (48 B8 ... FF E0) — and explains *why* RAX is the intermediate register (x64 lacks a direct 8-byte immediate JMP). The vault's T-016 documents the unhook operation but not the byte-forensic fingerprint operators can scan for to enumerate which functions an EDR has hooked before deciding what to unhook. This pre-unhook enumeration step has operational value.

### Note 2: 32-bit Wow64 Hot-Patch Prologue and MOV EDI, EDI Hook Detection
- id: `lgtm:32-bit-hot-patch-prologue-coverage`
- origin: atlas-edr-evasion-part2
- would_relate_to: ['T-016']
- tags: ['32-bit', 'wow64', 'hot-patch', 'mov-edi-edi', 'hook-detection', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-016
**Source units:** unit 39, unit 40

The vault's T-016 NTDLL unhook documentation is implicitly x64-centric. SEC670 devotes a unit to the 32-bit MOV EDI, EDI hot-patch prologue and the five-NOP padding that precedes 32-bit functions, explaining how this layout enables inline jmp rel32 hook installation and how the byte signature identifies hooked vs unhooked stubs on Wow64. The vault lacks explicit 32-bit hook detection coverage; a concept node or extension to T-016 would surface this.

---
Use `id: T-100`, canonical name above, and `member_notes: ['lgtm:inline-hook-byte-forensics', 'lgtm:32-bit-hot-patch-prologue-coverage']`.
Cross-reference `would_relate_to`: ['T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.