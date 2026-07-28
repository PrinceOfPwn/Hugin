---
id: RTO-pe-threads
name: PE Format & Thread Internals
source: Red Team Ops / SANS SEC670
category: winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-002, T-004, T-006, T-007, T-013, T-016, T-020]
tags: [pe-format, pe-parsing, dos-header, nt-headers, exports, imports, getprocaddress, threads, thread-context, thread-states, context-switching, rva, datadirectory, iat, ilt, image-base]
---

# PE Format & Thread Internals — Training Reference

## TL;DR
SANS SEC670.3 modules 1–2 build the foundation every operator needs before touching injection or evasion: PE file structure (DOS/NT/File/Optional headers, DataDirectory, exports, imports) and Windows thread internals (states, scheduling, context switching). This is the prerequisite knowledge the vault's `dark_crystal/crates/core/src/pe.rs` and SSN resolution cascade (T-002) build on, and the thread context material is the literal substrate for `ThreadHijacker`-style injection (T-013) and APC methods (T-007, T-012).

## Key Concepts

1. **PE Format is Architecture-Agnostic**
   The Portable Executable format serves both executable images (PE) and object files (COFF). The system loader parses every byte of the format before mapping the image. Understanding this is non-negotiable for writing reflective loaders (T-013 `pe_loader.rs`), export-table walks (T-002 SSN resolution), and module-stomping checks (T-007/T-013).

2. **Three Address Types: VA, RVA, ImageBase**
   - VA = address in virtual address space (not subtracted from base)
   - RVA = VA − ImageBase (relative to module base)
   - ImageBase preferred = `0x400000` (EXE) / `0x10000` (DLL)
   All DataDirectory entries are RVAs — add module base to dereference. Vault code (T-002, T-004) repeatedly does `base + rva` arithmetic.

3. **DOS Header (`IMAGE_DOS_HEADER`)**
   64-byte struct. Two fields matter: `e_magic` (offset 0x00 = `0x5A4D` "MZ") and `e_lfanew` (offset 0x3C, DWORD) → RVA to NT headers. **OPSEC tip from training**: signature scanners looking only for "MZ" produce false positives; check byte 3 = `0x90` and byte 4 = `0x00` to reduce noise. Relevant to vault's PEB walker (T-004) when scanning loaded module list.

4. **NT Headers (`IMAGE_NT_HEADERS64`)**
   - `Signature` (DWORD `0x00004550` "PE\0\0")
   - `FileHeader` (`IMAGE_FILE_HEADER`)
   - `OptionalHeader` (`IMAGE_OPTIONAL_HEADER64` for PE32+)
   Use `#ifdef _WIN64` to typedef to the correct struct.

5. **File Header — Two Fields That Unlock Section Walking**
   - `NumberOfSections` (WORD): iteration count for `IMAGE_SECTION_HEADER` array
   - `SizeOfOptionalHeader` (WORD): the jump distance from end of FileHeader to start of Section Headers (no direct pointer exists)
   Used by vault's `pe.rs` (T-007 role) to locate sections for stomping/overloading.

6. **Optional Header — Magic Discriminates PE32 vs PE32+**
   - `Magic` = `0x10B` (PE32) or `0x20B` (PE32+)
   - `AddressOfEntryPoint` — entry RVA, critical for thread context manipulation (T-013)
   - `DataDirectory[16]` — array of 16 `IMAGE_DATA_DIRECTORY{VirtualAddress, Size}` entries
   Index 0 = `IMAGE_DIRECTORY_ENTRY_EXPORT` (exports), Index 1 = `IMAGE_DIRECTORY_ENTRY_IMPORT` (imports). Vault SSN resolvers (T-002) target index 0 exclusively.

7. **Export Directory — The GetProcAddress Algorithm**
   `IMAGE_EXPORT_DIRECTORY` exposes three parallel arrays:
   - `AddressOfFunctions[NumberOfFunctions]` — RVAs to function bodies
   - `AddressOfNames[NumberOfNames]` — RVAs to ASCII names
   - `AddressOfNameOrdinals[NumberOfNames]` — indexes into AddressOfFunctions
   
   Algorithm: loop `AddressOfNames` comparing strings; on match, take loop index `x` into `AddressOfNameOrdinals[x]` → ordinal `o`; take `o` into `AddressOfFunctions[o]` → RVA; add base → VA. **This is the literal algorithm the vault's PEB Walker (T-004) + Hell's Gate (T-002) implements to resolve `Nt*`/`Zw*` symbols without `GetProcAddress`.**
   
   **OPSEC**: ordinal-only exports are rare for legit DLLs — use them sparingly when crafting malicious DLLs.

8. **Import Descriptor — ILT vs IAT**
   `IMAGE_IMPORT_DESCRIPTOR` fields:
   - `OriginalFirstThunk` → RVA to Import Lookup Table (ILT, persists on disk)
   - `FirstThunk` → RVA to Import Address Table (IAT, overwritten by loader with resolved VAs)
   - `Name` → RVA to DLL name string
   - `TimeDateStamp` = 0 (not bound) / -1 (bound)
   - `ForwarderChain` = -1 (no forwarders)
   Array is NULL-terminated. On disk ILT == IAT; in memory only IAT is patched.

9. **Thread Definition & States**
   Thread = smallest schedulable execution entity tied to a process. Three operationally relevant states:
   - **Ready**: queued, awaiting dispatcher selection
   - **Running**: in quantum on CPU
   - **Waiting**: blocked on event (e.g., `WaitForSingleObject`); becomes alertable here — this is the prerequisite state for **APC injection** (T-007 Early Bird, T-012 Early Cascade)

10. **Thread Context & CR3**
    `GetThreadContext`/`SetThreadContext` retrieve/save register state including `RIP`, `RSP`. The CR3 register holds the PML4 table physical address (x64) — it's the per-process address-space root. Context manipulation is the substrate for **Thread Hijack injection** (T-013 `waiting_thread.rs`) and `ThreadHijacker` lab (3.4).

11. **Quantum Scheduling**
    Preemptive priority-based dispatcher. Default quantum: 2 clock intervals (endpoints), 12 (servers). Higher-priority threads preempt running threads — relevant when timing async injection primitives (T-007 Pool Party, T-012 Early Cascade).

## Operational Techniques

### Manual GetProcAddress Implementation (Lab 3.1: GetFunctionAddress)
- **What**: Walk a loaded module's export table to resolve a function VA without calling `GetProcAddress` / `LoadLibrary`.
- **When to use**: Position-independent shellcode that cannot touch IAT; building T-002 SSN resolvers; OPSEC-driven environments where `GetProcAddress` is hooked.
- **How**:
  1. Acquire module base (PEB walk — see T-004) or via `GetModuleHandleA`.
  2. Parse DOS header; read `e_lfanew` at offset 0x3C → NT headers.
  3. From NT headers, read `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` (index 0).
  4. Treat `VirtualAddress` as RVA, add to base → `IMAGE_EXPORT_DIRECTORY*`.
  5. Read `NumberOfNames`, `AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions`.
  6. Loop `AddressOfNames` with index `x`; compare target string against `base + AddressOfNames[x]`.
  7. On match: `ordinal = AddressOfNameOrdinals[x]`; `rva = AddressOfFunctions[ordinal]`; `va = base + rva`.
- **Vault link**: **T-004 PEB Walker** + **T-002 Hell's/Halo's/Tartarus Gate**. The vault implements the same algorithm but layered with: (a) PEB traversal via `gs:[0x60]` to avoid `GetModuleHandle`, (b) DJB2 hash comparison instead of `strcmp` to avoid plaintext function names, (c) 4-stage SSN cascade with `Zw*` RVA sort (Tartarus). The SANS version is the *pedagogical core* the vault extends.
- **Tool/code**: `winnt.h` structs (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS64`, `IMAGE_EXPORT_DIRECTORY`); WinDbg `dt`/`dx` commands; Total PE (Pavel Yosifovich) for visualization; PE-bear / PE Explorer.
- **OPSEC**: Calling `GetProcAddress` directly leaves a telemetry footprint (ETW `Kernel32!GetProcAddress`). Manual walks via PEB (T-004) avoid this entirely.

### Thread Context Manipulation (Pre-Lab 3.4 Setup)
- **What**: Suspend a target thread, save its `CONTEXT`, redirect `RIP` to shellcode, resume.
- **When to use**: Covert execution inside an existing legitimate thread; avoids `CreateThread`/`CreateRemoteThread` telemetry.
- **How**:
  1. Identify a thread in the `Waiting` state (alertable, will accept APCs) or a thread in `Ready` state.
  2. `SuspendThread` to bring it to a stable snapshot.
  3. `GetThreadContext(thread, &ctx)` with `CONTEXT_CONTEXT_FULL`.
  4. Save original `RIP` for restoration.
  5. `ctx.Rip = (DWORD64)shellcode_addr;`
  6. `SetThreadContext(thread, &ctx)`.
  7. `ResumeThread`.
- **Vault link**: **T-013 Remaining Methods** (`waiting_thread.rs`) implements WaitingThread hijack. Vault coverage extends this with restore-stub routines and stack-spoofed variants under T-016 (`stack_spoof.rs`). The SANS material is foundational; the vault operationalizes it for EDR-evasive variants.
- **Tool/code**: `GetThreadContext` / `SetThreadContext` / `SuspendThread` / `ResumeThread`; `CONTEXT` struct (`winnt.h`); `CONTEXT_CONTEXT_FULL` flag.
- **OPSEC**: `SuspendThread` on a foreign process thread is observable; consider `NtSuspendThread` via indirect syscall (T-001 RecycledGate) to bypass userland hooks. The vault's T-001/T-002/T-003 dispatchers exist for exactly this.

### DataDirectory Parsing (Foundation for Injection Methods)
- **What**: Index into `OptionalHeader.DataDirectory[16]` to locate export/import/resource/exception tables.
- **When to use**: Building any custom PE loader; reflective loading (T-013 `pe_loader.rs`); module stomping target selection (T-007 `module_stomp.rs`); vectored overloading (T-013 `vectored_overloading.rs`).
- **How**:
  ```
  OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]   // 0 — exports
  OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]   // 1 — imports
  OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] // 2
  OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]// 3
  OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]// 5
  ```
  Each entry: `VirtualAddress` (RVA, not VA — must add base) + `Size`.
- **Vault link**: Foundational to T-007 (Pool Party), T-008 (Threadless — needs export hijack target), T-013 (`pe_loader.rs` reflective loader). Vault's `pe.rs` parses this directly.
- **Tool/code**: WinDbg `dx -r1 (*((module!_IMAGE_DATA_DIRECTORY (*)[16])addr))`; `dt IMAGE_IMPORT_DESCRIPTOR`.
- **OPSEC**: Avoid magic numbers; use `IMAGE_DIRECTORY_ENTRY_*` `#define`s.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `winnt.h` | Canonical struct definitions for all PE structures | Reference only; no execution footprint |
| Total PE (Pavel Yosifovich) | PE structure visualization | Static analysis only; offline tool |
| PE-bear / PE Explorer | PE inspection alternatives | Static; careful with cloud-upload features |
| WinDbg `dt combase!IMAGE_IMPORT_DESCRIPTOR <addr>` | Live dump import descriptor | Live debug session; do not run on hardened target |
| WinDbg `dx -r1 (*((...!_IMAGE_DATA_DIRECTORY (*)[16])addr))` | Dump DataDirectory array | As above |
| `? module + 0x<rva>` | Resolve RVA to VA in WinDbg | As above |
| `dc <addr>` | Display chars at VA (read DLL name string) | As above |
| `e_magic` = `0x5A4D` ("MZ") | DOS signature | Scanner check; pair with bytes 3-4 (`0x90 0x00`) to reduce FP |
| `Signature` = `0x00004550` ("PE\0\0") | NT signature | Scanner check |
| `OptionalHeader.Magic` `0x10B` / `0x20B` | PE32 vs PE32+ discriminator | Use to select correct struct typedef |
| `GetThreadContext` / `SetThreadContext` | Read/modify thread registers | Userland hooked by EDR; prefer indirect syscall path |
| `WaitForSingleObject` | Induce alertable wait state | prerequisite for APC injection (T-007, T-012) |
| `IMAGE_DOS_SIGNATURE 0x5A4D` | Win32 `#define` for MZ | — |
| `IMAGE_DIRECTORY_ENTRY_EXPORT` (= 0) | DataDirectory export index `#define` | Avoid magic number 0 |
| `IMAGE_DIRECTORY_ENTRY_IMPORT` (= 1) | DataDirectory import index `#define` | Avoid magic number 1 |

## Gaps & Extensions

### What this training covers that the vault does not document pedagogically
- **Walk-through of GetProcAddress internals**: The vault's T-004 implements the algorithm but does not document the export directory's three-array structure (`AddressOfFunctions`/`AddressOfNames`/`AddressOfNameOrdinals`) in its operator reference. SANS provides the visual/structural explanation operators need to *understand* the vault code.
- **PE32 vs PE32+ discrimination**: The vault assumes 64-bit; SANS explicitly covers the `#ifdef _WIN64` typedef path and `Magic` values `0x10B` vs `0x20B`. Operators porting vault techniques to legacy 32-bit environments will need this.
- **Imports / IAT structure**: The vault focuses exclusively on exports (for SSN resolution). SANS covers `IMAGE_IMPORT_DESCRIPTOR`, ILT vs IAT distinction, bound imports (`TimeDateStamp`), forwarders. Operators building proxy DLLs (T-016 `proxy_dll.rs`) need the import-side knowledge SANS provides.
- **Hexdump walkthroughs with WinDbg**: WinDbg `dt`/`dx`/`?` syntax for live PE inspection is not in the vault reference. Useful for target-side triage.
- **Thread state taxonomy (Ready/Running/Waiting)**: The vault assumes this knowledge; SANS explicitly enumerates which states matter for which injection primitive (alertable wait → APC; suspended → context hijack).

### What the vault covers that this training does not
- **PEB-based module resolution** (T-004): SANS assumes you already have the module base via `GetModuleHandle`. The vault implements the entire chain from `gs:[0x60]` (PEB) → `InLoadOrderModuleList` → walking to `ntdll.dll`/`kernel32.dll`. This is the EDR-evasive equivalent of what SANS teaches.
- **DJB2 hash-based export name comparison** (T-002/T-004): SANS uses `strcmp`. The vault uses compile-time DJB2 hashes so plaintext API names never appear in the binary — a critical static-analysis evasion SANS does not address.
- **4-stage SSN cascade** (T-002 Hell's/Halo's/Tartarus Gate + FreshyCalls): SANS's PE parsing lab resolves a single arbitrary function VA. The vault extends this specifically to `Nt*`/`Zw*` syscall stubs with: Halo's Gate (hook-detection via stub inspection), Tartarus Gate (RVA sort across `Nt` and `Zw` exports), FreshyCalls (functional sorting).
- **VEH-based syscall dispatch** (T-003): not in scope of SANS 670.3 modules 1-2.
- **Phantom stubs** (T-006) for MEM_IMAGE-backed execution: not covered.
- **Reflective PE loader** (T-013 `pe_loader.rs`): SANS teaches PE *parsing* but not in-memory loader implementation.
- **Module stomping / overloading / herpaderping** (T-007/T-013): require the PE section-walking knowledge SANS provides, but the operational techniques themselves are vault-only.
- **Ekko ROP sleep** (T-005) and the broader sleep-obfuscation suite: not in this material.
- **Stack spoofing during context manipulation** (T-016 `advanced_stack.rs`): SANS teaches bare `SetThreadContext`; the vault wraps it with multi-frame stack spoofing to defeat `RtlVirtualUnwind`-based EDR telemetry.

### Honest assessment
SANS SEC670.3 modules 1-2 are **prerequisite pedagogy** for the vault. An operator who has internalized this material will understand *why* the vault's `pe.rs`, `resolve.rs` (T-004), and `hells_gate.rs` (T-002) do what they do. The vault code alone is opaque without this foundation. Treat this as the canonical reading assignment before touching any T-001 through T-013 technique card.

The SANS material is not outdated — it is the substrate. The vault's contribution is to operationalize this knowledge into EDR-evasive implementations.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `IMAGE_DOS_HEADER->e_lfanew` walking | T-004 PEB Walker | Vault uses same field; walks PEB Ldr list instead of file |
| Export directory three-array structure | T-004 PEB Walker, T-002 Hell's/Halo's/Tartarus | Vault implements same algorithm with DJB2 hashing |
| `GetProcAddress` algorithm | T-002 SSN resolution cascade | Vault reimplements without `GetProcAddress` to avoid ETW telemetry |
| `OptionalHeader.DataDirectory[0]` exports | T-002 Hells Gate | Vault targets `ntdll.dll` export table specifically for `Nt*`/`Zw*` stubs |
| `IMAGE_IMPORT_DESCRIPTOR` parsing | T-016 EDR Evasion Suite (proxy_dll.rs) | Vault uses import-side knowledge for proxy DLL construction — not in SANS scope of operator reference |
| Thread states (Ready/Running/Waiting) | T-007 Pool Party, T-012 Early Cascade, T-013 WaitingThread | Vault relies on this taxonomy implicitly for APC and hijack timing |
| Alertable wait (via `WaitForSingleObject`) | T-007 Early Bird, T-012 Early Cascade | Vault injects APCs into threads entering alertable wait |
| `GetThreadContext` / `SetThreadContext` | T-013 WaitingThread hijack | Vault wraps with stack spoofing (T-016) for EDR evasion |
| `SuspendThread` prerequisite | T-013 `waiting_thread.rs` | Vault calls via indirect syscall (T-001 RecycledGate) to bypass hooks |
| PE32 vs PE32+ `Magic` discrimination | T-002, T-007 (pe.rs) | Vault hardcodes 64-bit (PE32+); SANS covers 32-bit portability |
| CR3 / PML4 address-space isolation | T-020 Anti-Analysis | Foundation for understanding why `ReadProcessMemory` across processes requires CR3 swap; not operationally detailed in SANS |
| DOS header MZ signature + `0x90 0x00` bytes 3-4 | T-004 PEB Walker | Used as module-base scanner signature |
| `IMAGE_FILE_HEADER->SizeOfOptionalHeader` for section walking | T-007 pe.rs, T-013 module_stomp.rs | Vault uses this to locate section table for stomping |
| Hexdump inspection of `kernel32.dll`/`kernelbase.dll` exports | T-002 (ntdll) | Same approach applied to ntdll for syscall stubs |
| Lab 3.1 GetFunctionAddress | T-004 + T-002 combined | Vault provides end-to-end operationalized version with no `GetProcAddress` dependency |
| WinDbg `dt`/`dx` PE inspection commands | (Diagnostic tooling in framework/runtime/) | Vault has `diag_mp_otp.rs` diagnostic harness but does not document WinDbg triage syntax |