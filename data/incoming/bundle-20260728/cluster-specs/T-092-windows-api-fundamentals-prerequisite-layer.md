# Cluster Spec — T-092: Windows API Fundamentals as Prerequisite Layer

- **T-NNN ID**: `T-092`
- **Canonical name**: Windows API Fundamentals as Prerequisite Layer
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: medium — 2 member notes spanning multiple batches; unblocks multiple operational cards.
- **would_relate_to**: ['T-001', 'T-002', 'T-003', 'T-004', 'T-006', 'T-013', 'T-016']

## Consolidated Description

SEC670 devotes an entire module to Win32 programming prerequisites that the
vault assumes but does not document: x64 calling convention (RCX/RDX/R8/R9 +
shadow space 0x20 bytes), WinDef.h macros (DECLARE_HANDLE, MAKEINTRESOURCE,
HIWORD/LOWORD), Windows data type aliases (DWORD=uint32_t, LPVOID=void*,
HANDLE=PVOID), and the Win32 → NTAPI translation layer (OpenProcess →
NtOpenProcess, CreateFile → NtCreateFile). This material directly gates
T-001/T-002 (syscalls), T-003 (API hashing), T-004 (PEB walk), T-013 (PE
loader), and T-016 (evasion suite). A standalone reference card with the
typedef chain and the user32→ntdll call-down diagram would make those cards
navigable without prior Windows programming background.


## Member LGTM Notes (2)

### Note 1: Foundational Windows Programming Concepts Underrepresented in Vault
- id: `lgtm:foundational-windows-programming-concepts-coverage-gap`
- origin: atlas-exploit-dev-part23
- would_relate_to: ['T-001', 'T-002', 'T-003', 'T-004', 'T-013', 'T-016']
- tags: ['foundational', 'calling-conventions', 'pe-format', 'sal-annotations', 'coverage-gap', 'onboarding']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part23
**Would relate to:** T-001, T-002, T-003, T-004, T-013, T-016
**Source units:** unit 1, unit 7, unit 10, unit 12, unit 16, unit 17, unit 19, unit 20, unit 21, unit 22, unit 25, unit 26, unit 39, unit 40

The SEC670 material dedicates an entire module to foundational Windows programming concepts — calling conventions (__stdcall/__cdecl/__fastcall), the Win32 type-to-CRT typedef chain, SAL annotations on API signatures, explicit vs implicit DLL linking, and PE32/PE32+ format. The vault's technique cards assume the reader already knows these concepts. Operators coming from pure Rust backgrounds without Win32/C experience may not understand why ntdll stubs are __stdcall, why RtlCopyMemory is used instead of memcpy, or what _Out_writes_bytes_all_ means in NT API signatures. A concept-node cluster documenting these fundamentals would improve onboarding to the syscall dispatch and PE-manipulation cards.

### Note 2: Windows API Fundamentals as Prerequisite Layer
- id: `lgtm:coverage-gap-windows-fundamentals-prerequisite`
- origin: atlas-exploit-dev-part5
- would_relate_to: ['T-001', 'T-002', 'T-003', 'T-006']
- tags: ['coverage-gap', 'calling-convention', 'sal', 'winapi', 'fundamentals', 'prerequisite']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part5
**Would relate to:** T-001, T-002, T-003, T-006
**Source units:** unit 1, unit 13, unit 14, unit 15, unit 17, unit 20, unit 25, unit 32, unit 37, unit 40

SEC670 devotes substantial material to calling conventions, WinDef.h macros, Windows data type aliases, and SAL annotations — the prerequisite literacy for reading IDA disassembly of syscall stubs and correctly binding NT APIs via FFI. The vault documents T-001 (RecycledGate), T-003 (VEH Gate), and T-006 (Phantom Stubs) without surfacing the calling-convention context that determines whether a hand-built stub correctly balances the stack. A reference node capturing these fundamentals would help readers moving from Rust source to low-level understanding.

---
Use `id: T-092`, canonical name above, and `member_notes: ['lgtm:foundational-windows-programming-concepts-coverage-gap', 'lgtm:coverage-gap-windows-fundamentals-prerequisite']`.
Cross-reference `would_relate_to`: ['T-001', 'T-002', 'T-003', 'T-004', 'T-006', 'T-013', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.