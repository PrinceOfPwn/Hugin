---
id: RTO-sec670-windows-dlls
name: Windows DLLs — Anatomy, Linking, and Export Tradecraft
source: Red Team Ops / SANS SEC670 — Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control
category: winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-004, T-007, T-008, T-009, T-010, T-012, T-013, T-016, T-020, T-021]
tags: [pe-format, dll-exports, dumpbin, loadlibrary, getprocaddress, def-file, rva, peb, ntdll, calling-conventions, windows-data-types, sec670, foundational]
---

# Windows DLLs — Training Reference

## TL;DR
SEC670's "Windows DLLs" module is a foundational PE-anatomy lesson covering the DLL file format, the .lib/.dll relationship, four export mechanisms, and the implicit/explicit linking dichotomy. It is the prerequisite mental model an operator needs before understanding *why* the vault's PEB Walker (T-004), Threadless injection (T-008), Proxy DLL evasion (T-016), and Module Stomping (T-013) work the way they do — every one of those techniques is built on the loader behavior and PE structure taught here.

## Key Concepts

1. **DLLs are PE files** — A `.dll` is structurally identical to an `.exe` (PE32/PE32+) and differs only by `IMAGE_FILE_DLL` set in the Characteristics field of the COFF header. The companion `.lib` (import library) carries only the DLL name + exported symbol names; it is what the linker consumes at build time. Operator relevance: every reflective loader, module stomper, or proxy DLL in the vault (T-008, T-013, T-016) manipulates this exact structure, so manual PE parsing skills are non-negotiable.

2. **PE Section Layout (the canonical map)** — `DOS stub` → `PE\0\0` signature → `COFF/File header` → `Optional header` → `Section headers` → `Sections`. Key characteristics bits to remember: `IMAGE_FILE_EXECUTABLE_IMAGE (0x2)`, `IMAGE_FILE_RELOCS_STRIPPED (0x1)`, `IMAGE_FILE_LARGE_ADDRESS_AWARE (0x20)`, `IMAGE_FILE_DEBUG_STRIPPED (0x200)`, `IMAGE_FILE_32BIT_MACHINE (0x100)`. The Optional Header's `Magic` field disambiguates PE32 (`0x10B`) vs PE32+ (`0x20B`). The `SizeOfOptionalHeader` field is the arithmetic pivot for jumping to the first section header — directly leveraged by vault `pe.rs` (T-007) and `dynamic_resolver/template.rs` (T-004).

3. **RVA / VA arithmetic** — `VA = Base + RVA`, `RVA = VA − Base`. This is the foundational operation behind every export-table walk, EAT hook (T-008 Threadless), export hijack, GetProcAddress replacement (T-004 PEB Walker), and IAT camouflage (T-020). Operators must internalize this; the vault's `pe.rs` and `resolve.rs` are essentially RVA math wrapped in RAII guards.

4. **The Data Directories** — 16 directories (`0x10`); most are NULL. The two an operator cares about 90% of the time: **Export Directory** (EAT — used by GetProcAddress and Threadless injection's EAT hijack) and **Base Relocation Directory** (used when ASLR forces a rebase — relevant to understanding `ntdll` unhooking via fresh ntdll load, T-016). Both live inside `.rdata` by convention.

5. **Section Permissions are Invariants** — `.text` is `Execute | Read` (no Write); any executable page that *also* has Write is an instant EDR flag. The loader enforces `PAGE_EXECUTE_READ` for `.text`. Understanding this is why the vault's Module Stomping / Function Stomping / PE Header Stomping variants (T-013) must reprotect sections with `VirtualProtect` — the original permissions don't allow in-place code replacement.

6. **System DLL Hierarchy** — `ntdll.dll` (required, always mapped, syscall gateway), `kernel32.dll` (re-exports much of ntdll + Win32 wrappers), `kernelbase.dll` (Windows 7+ replacement for kernel32 internals), `user32.dll` (GUI). ASLR randomizes per-process for app modules and per-boot for system modules. This is the foundational context for vault T-002 (Hell's/Halo's/Tartarus Gate operates on ntdll's `.text`), T-016 (NTDLL unhook via fresh suspended process), and T-004 (PEB walker resolves these modules without calling any loader API).

7. **Implicit vs Explicit Linking** — Implicit: `#pragma comment(lib, "X")` or VS Project → Linker → Input → Additional Dependencies; the `.lib` is consumed at build time, function names appear in the IAT, missing DLL = process termination. Explicit: runtime `LoadLibraryEx` + `GetProcAddress` + `FreeLibrary`; nothing in the IAT except those three APIs. The training explicitly notes that "later in the course" they will manually reimplement `LoadLibrary` and `GetProcAddress` — this is the *exact* handoff to vault T-004 (PEB Walker) and T-002/T-003 (syscall dispatch that never touches kernel32).

8. **Four Export Mechanisms** (in Microsoft's recommended order): `__declspec(dllexport)`, `.def` file `EXPORTS` section, linker `/EXPORT:` flag, and `#pragma comment(linker, "/export:")`. `.def` files support `NONAME` (ordinal-only export — used to hide export names from static analysis) and `PRIVATE` (don't add to import table — useful for proxy-DLL OPSEC, vault T-016). Cross-reference forward: vault T-008 Threadless Injection abuses *another* DLL's EAT entries; understanding how exports land in the EAT is the prerequisite.

9. **Windows Data Types & Calling Conventions** — `INT`, `DWORD`, `BOOL`, `LPVOID`, `HMODULE` are all `typedef`s over C types. Win32 standardizes `__stdcall` (callee-clean) vs C's `__cdecl` (caller-clean). The vault's `wrappers.rs` (T-021 patterns) uses `windows_targets::link!` to declare extern "C" with the correct ABI; mismatching conventions is the #1 silent-corruption bug when hand-rolling FFI.

10. **DLL Injection (concept)** — Forcing a target process to load a DLL so its `DllMain` (or exports) execute in the target's context, with full VA access. The training only introduces the *concept*; the vault operationalizes 15+ distinct methods under T-007 through T-013.

## Operational Techniques

### PE Inspection with dumpbin
- **What**: SDK-shipped CLI utility to enumerate headers, sections, exports, imports, and disassemble sections.
- **When to use**: Pre-engagement RE of a target binary; verifying your own DLL's exports; confirming IAT camouflage (vault T-020) doesn't leak suspicious imports; checking that Threadless Injection target DLLs have a usable EAT.
- **How**:
  1. Open "x64 Native Tools Command Prompt for VS" (or `vcvarsall.bat x64`).
  2. `dumpbin /headers hello.dll` — full PE header dump (look for `File Type: DLL`, `Magic`, `entry point`, `size of optional header`).
  3. `dumpbin /exports hello.dll` — ordinals, hints, RVAs, names. (Use `NONAME` exports to confirm ordinal-only OPSEC.)
  4. `dumpbin /imports callhello.exe` — IAT; verify your evasion build doesn't leak `LoadLibrary`/`GetProcAddress`.
  5. `dumpbin /dependents callhello.exe` — list of statically required DLLs (should be minimal for an implant).
  6. `dumpbin /disasm /section:.text hello.dll` — disassemble a specific section.
  7. `dumpbin /rawdata /section:.text hello.dll` — raw hex of a section.
- **Vault link**: T-020 (Anti-Analysis / IAT Camouflage) — `dumpbin /imports` is the operational verifier for whether your IAT-camo profile actually removes suspicious imports. T-004 (PEB Walker) — when verifying a module is loaded before resolving via DJB2 hash.
- **Tool/code**: `dumpbin` (ships with Windows SDK / VS Build Tools).
- **OPSEC**: Running dumpbin on the operator dev box leaves no artifact on target. On-target execution is loud; prefer copying binaries off-target for analysis.

### PE Inspection with WinDbg `!dh`
- **What**: In-debugger PE header parser; takes a loaded module base address.
- **When to use**: Live debugging of an injected/loaded implant where you need to confirm in-memory layout (e.g., verifying a vault-injected Phantom Stub (T-006) or stomped module (T-013) looks legitimate to a debugger-driven EDR).
- **How**:
  1. `!dh 00007ff6`29240000` (substitute actual base from `lm` or `.imgdir`).
  2. Inspect `FILE HEADER VALUES`, `OPTIONAL HEADER VALUES`, sections, directories — output mirrors dumpbin but reflects the *in-memory* (post-relocation, post-ASLR) image.
- **Vault link**: T-016 (NTDLL unhook verification — confirm restored `.text` matches known-good). T-013 (Module/Function Stomping — confirm the stomped section now contains your payload).
- **Tool/code**: WinDbg (or WinDbg Preview / WinDbgX).
- **OPSEC**: Debugger presence is itself detectable via `IsDebuggerPresent`, PEB `BeingDebugged`, and hardware breakpoint registers. Not for in-engagement use on hardened targets; this is dev-box tradecraft.

### Explicit DLL Linking (LoadLibraryEx + GetProcAddress)
- **What**: Runtime DLL load and symbol resolution — no compile-time dependency, no IAT entry for the loaded DLL's exports.
- **When to use**: Loading stage-2 payloads dynamically; loading a proxy DLL that re-exports victim functions (vault T-016); loading an NT API surface DLL on demand.
- **How**:
  ```cpp
  HMODULE helloDll = LoadLibraryExW(L"hello.dll", nullptr, 0);
  using t_PrintHello = PCSTR (__cdecl*)();
  t_PrintHello PrintHello = reinterpret_cast<t_PrintHello>(
      GetProcAddress(helloDll, "PrintHello"));
  puts(PrintHello());
  FreeLibrary(helloDll);
  ```
- **Vault link**: T-004 (PEB Walker) — the vault's replacement for `LoadLibrary`+`GetProcAddress` walks `PEB->Ldr->InLoadOrderModuleList` and hashes export names with DJB2; nothing is logged in the IAT. T-002/T-003 — once an export address is resolved, the vault calls it via RecycledGate / VEH Gate rather than the direct function pointer, hiding the syscall origin. T-016 (Proxy DLL) — a proxy DLL's `DllMain` typically uses explicit linking to forward to the real victim DLL.
- **Tool/code**: `kernel32!LoadLibraryExW`, `kernel32!GetProcAddress`, `kernel32!FreeLibrary`.
- **OPSEC**: **`LoadLibrary` + `GetProcAddress` are heavily monitored by AV/EDR** (training explicitly flags this). Mitigations: (a) vault T-004 PEB Walker for resolution; (b) vault T-002/T-003 indirect syscall dispatch for `NtMapViewOfSection` / `LdrLoadDll` equivalents; (c) `LdrLoadDll` direct via PEB-walked `ntdll!LdrLoadDll` is lower-noise than `LoadLibraryExW`.

### Implicit DLL Linking (#pragma comment)
- **What**: Compile-time linkage against an import library; function symbols appear in the IAT; missing DLL = process won't start.
- **When to use**: Generally **avoid for implants** — the IAT reveals every Windows API your implant uses, which is precisely the static-signal EDRs pivot on. Useful for *tooling* (loader stubs, dev utilities) but not the operational payload.
- **How**:
  ```cpp
  // implicit_callhello.cpp
  #pragma comment(lib, "hello")
  EXTERN_C PCHAR __cdecl PrintHello();
  INT main() { puts(PrintHello()); }
  ```
  Compile: `cl /c implicit_callhello.cpp` then `link implicit_callhello.obj hello.lib`.
- **Vault link**: T-020 (IAT Camouflage) — the vault's three IAT-camo profiles exist precisely to *defeat* the operational risk this technique creates. T-021 (Crypto & Obfuscation) — `windows_targets::link!` in `wrappers.rs` is a controlled form of implicit linking that the vault uses sparingly, only for APIs that must be in the IAT for OPSEC-acceptable reasons.
- **Tool/code**: `#pragma comment(lib, "...")`, VS Project Properties → Linker → Input → Additional Dependencies.
- **OPSEC**: IAT contents are static-scan gold. **Never ship an implant with an un-obfuscated IAT referencing `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `SetWindowsHookEx`, `QueueUserAPC`.** Use vault T-020 camo or T-004 PEB Walker.

### DLL Export via `__declspec(dllexport)`
- **What**: Microsoft-recommended way to mark functions for export from a DLL.
- **When to use**: Building proxy DLLs (T-016), building custom Reflective PE loaders' test payloads, writing the host DLL for Threadless injection (T-008) — although Threadless abuses *victim* DLLs' exports, your own test harness should export cleanly.
- **How**:
  ```cpp
  #define DLLEXPORT __declspec(dllexport)
  DLLEXPORT DWORD CALLBACK MyExport(LPVOID ctx) { /* ... */ }
  ```
- **Vault link**: T-016 (Proxy DLL) — proxy DLLs forward exports to the real victim DLL, then add their own. T-008 (Threadless) — the operator must enumerate victim DLL exports; `__declspec`-exported functions have predictable name-mangling.
- **Tool/code**: MSVC `__declspec(dllexport)` / `__declspec(dllimport)`.
- **OPSEC**: Export names are visible in the EAT and trivially scraped by `dumpbin /exports` or PE-bear. Use `NONAME` (ordinal-only) for sensitive exports; consider `PRIVATE` for exports only used internally.

### DLL Export via `.def` File
- **What**: Module-definition file with explicit export ordinals, names, and forwarding directives.
- **When to use**: When you need **ordinal-only exports** (no name in EAT — common in evasion DLLs), when you need to **forward exports to another DLL** (`GetSysInfo=another_dll.GetSystemInformation` syntax), or when exporting hundreds of functions (cleaner than `__declspec`).
- **How**:
  ```def
  LIBRARY Evil32
  EXPORTS
      ExecShellcode    @1 NONAME
      GetComputerName @3 PRIVATE
      GetNetAdapter    @5
      GetSysInfo=another_dll.GetSystemInformation
  VERSION 2.1
  ```
  - `LIBRARY` — declares DLL + creates import library
  - `EXPORTS` — section header for exports
  - `@N` — assign ordinal N
  - `NONAME` — export by ordinal only (name stripped from EAT)
  - `PRIVATE` — don't add to import library (internal use only)
  - `name=otherdll.function` — forwarder export (the call goes straight to the other DLL without executing your code; used by proxy DLLs)
- **Vault link**: T-016 (Proxy DLL) — the `.def` forwarder syntax is *exactly* what a proxy DLL uses to transparently re-export victim functions while your `DllMain` runs first. T-008 (Threadless Injection) — the technique hijacks a victim DLL's EAT entry; understanding ordinals vs names matters because some victim exports are ordinal-only.
- **Tool/code**: MSVC linker `/DEF:mydef.def` or VS Project Properties → Linker → Input → Module Definition File.
- **OPSEC**: `NONAME` exports are detectable by anomaly (DLL with ordinals but no names is unusual in legitimate software). Use sparingly. Forwarder exports are perfectly normal-looking (system DLLs use them heavily) — preferred for proxy DLLs.

### RVA Calculation
- **What**: Convert between file-relative offsets and in-memory virtual addresses once a DLL is loaded at an arbitrary base.
- **When to use**: Every time you parse an export directory, walk an EAT, find a function pointer, or verify a vault technique's correctness in WinDbg.
- **How**:
  - `VA = Base + RVA` (e.g., `0x9F002040 = 0x9F000000 + 0x2040`)
  - `RVA = VA − Base` (e.g., `0xFFC90 = 0x743AFC90 − 0x742B0000`)
  - To go from on-disk file offset to RVA: find the section whose `RawDataOffset ≤ file_offset < RawDataOffset + RawDataSize`, then `RVA = section.VirtualAddress + (file_offset − section.PointerToRawData)`.
- **Vault link**: T-004 (PEB Walker) — every export lookup is RVA→VA math against the in-memory image. T-007 (Pool Party, Threadless, etc.) — section-relative addressing for stomping. T-013 (Module Stomping, Function Stomping) — must compute exact RVA of victim function before overwriting.
- **Tool/code**: Manual arithmetic; `pe.rs` in vault automates this.
- **OPSEC**: Pure computation, no OPSEC impact.

### DLL Injection (Concept)
- **What**: Forcing a foreign process to load a DLL so its code executes in the target's address space with full VA access.
- **When to use**: Persistence, in-process API hooking (legitimate AV use), credential theft from a process that holds secrets, evasion by blending into a legitimate signed process.
- **How**: The training only introduces the concept — "several popular DLL injection methods out there today and we will explore a few of them later in the course." Operational implementations are in the vault.
- **Vault link**: T-007 (Pool Party), T-008 (Threadless), T-009 (Process Ghosting), T-010 (Herpaderping), T-011 (Dirty Vanity), T-012 (Early Cascade), T-013 (Hollowing, Hypnosis, WaitingThread, Mapping, Module/Func Stomp, Overloading, Vectored Overloading, Callback, Fiber, Early Bird, PE Loader), T-014 (NtCreateUserProcess), T-015 (PPID Spoofing). The training is the prerequisite mental model; the vault is the operational catalog.
- **Tool/code**: N/A in this module.
- **OPSEC**: Generic — every injection method has a different signature; see individual vault cards.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `dumpbin /headers <file>` | Full PE header dump (machine, sections, optional header, directories) | Dev-box only; SDK-shipped, no target footprint |
| `dumpbin /exports <file>` | List EAT (ordinals, hints, RVAs, names) | Dev-box only; verify `NONAME`/`PRIVATE` OPSEC |
| `dumpbin /imports <file>` | List IAT (DLL + function imports) | Dev-box only; **operational IAT audit** for evasion builds |
| `dumpbin /dependents <file>` | List statically required DLLs | Dev-box only; minimal-dependency audit |
| `dumpbin /disasm /section:.text <file>` | Disassemble a single section | Dev-box only |
| `dumpbin /all <libfile>` | Full dump of a `.lib` import library (symbol resolution) | Dev-box only |
| `PE-bear` | Multi-file GUI PE browser with high-level nav bar | Dev-box only; GUI |
| `PEview` | Minimalist GUI PE structure browser | Dev-box only |
| `CFF Explorer` | Full-featured GUI PE editor | Dev-box only; can edit PE fields |
| `WinDbg !dh <base>` | In-memory PE header dump at runtime | Debugger presence detectable; dev-box only |
| `#pragma comment(lib, "X")` | Implicit linking via source directive | Adds to IAT — **avoid for implants** |
| `LoadLibraryExW` / `GetProcAddress` / `FreeLibrary` | Explicit runtime linking | Heavily EDR-monitored — prefer vault T-004 PEB Walker |
| `__declspec(dllexport)` | Mark function for export | Export name visible in EAT |
| `.def` file `EXPORTS` | Module-definition export list with `NONAME`/`PRIVATE`/forwarders | `NONAME` = ordinal-only (anomalous); forwarders = normal-looking |
| `dlopen` / `dlsym` / `dlclose` | Linux equivalents of `LoadLibrary` / `GetProcAddress` / `FreeLibrary` | Linux side only |
| `windows.h`, `WinNt.h`, `WinDef.h`, `WinReg.h`, `WinSvc.h` | Core Windows header files | Include minimally to reduce implant footprint |
| `RtlCopyMemory` (= `memcpy`) | Windows API wrapper over CRT | Prefer Windows-named APIs for forward-compat |

## Gaps & Extensions

### What the vault covers that this training does NOT
- **Indirect syscalls & SSN resolution cascade** (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate, T-006 Phantom Stubs) — the training mentions "we will implement LoadLibrary/GetProcAddress manually later" but the vault has already productionized this as PEB Walker (T-004) + multi-stage SSN resolution (T-002) + MEM_IMAGE-backed syscall stubs (T-006). The training's promise is the vault's delivered feature.
- **Sleep obfuscation** (T-005 Ekko ROP Sleep) — entirely absent from this module.
- **15 specific injection methods** (T-007 through T-015) — the training only mentions "several popular DLL injection methods" exist.
- **Full EDR evasion suite** (T-016) — AMSI/ETW patching, stack spoofing (basic + multi-frame), PEB unlink, NTDLL unhook (the training's "unloading all system DLLs even ntdll" project is mentioned but not operationalized), Block-DLL policy, ACG, handle blocking, KiUserException StepOver, arg spoofing, **proxy DLL** (which builds directly on the `.def` forwarder syntax taught here), PE stomping.
- **Persistence** (T-017 Five-Layer, T-018 Edo Tensei) — COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist.
- **Autonomous C2 / Dead Drop** (T-019) — Google Translate, blockchain, steganography.
- **Anti-analysis** (T-020) — 10-check anti-VM, API hammering, IAT camouflage (directly relevant to the IAT risk this module's implicit-linking technique creates), self-deletion, Kaguya LOtL.
- **Crypto & obfuscation** (T-021) — string obfuscation proc macro, AES-GCM+zstd, Ethereum TX signing, shellcode encoding (IPv4/IPv6/MAC/UUID/words), UAC bypass.
- **Networking & protocol** (T-022) — SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, NT sockets, BYOVD.
- **Client capabilities** (T-023) — BOF execution, keylogger, browser hook, screen capture, H.264, dirty rect, credential harvest, HTML/Win32 overlays, cursor hider, sysinfo.

### What this training covers that the vault does NOT explicitly document
- **Detailed PE header field semantics** — `IMAGE_FILE_*` characteristic bit values, `Magic` field meaning (`0x10B`/`0x20B`), `SizeOfOptionalHeader` as a section-table offset pivot, `SizeOfImage`/`SizeOfHeaders` distinctions. The vault's `pe.rs` performs these computations but does not document the field-level semantics; this module is the missing reference.
- **`.def` file syntax in detail** — `LIBRARY`, `EXPORTS`, `VERSION`, `@N` ordinals, `NONAME`, `PRIVATE`, and the forwarder syntax `name=otherdll.function`. The vault's proxy-DLL module (T-016) uses these but does not teach the syntax; this module is the prerequisite primer.
- **`dumpbin` switch catalog** — `/headers`, `/exports`, `/imports`, `/dependents`, `/disasm /section:`, `/rawdata /section:`, `/all`. The vault assumes operator familiarity with at least one PE inspection tool but does not document the CLI syntax.
- **WinDbg `!dh` command** — runtime in-memory PE inspection; not documented in the vault.
- **Windows-vs-Linux developer bridging** — `dlopen↔LoadLibrary`, `dlsym↔GetProcAddress`, `dlclose↔FreeLibrary`, `.so↔.dll`, `.a↔.lib`, SO not needing `__declspec`. Useful for operators transitioning from Linux tradecraft.
- **Windows data type catalog** — `INT`/`DWORD`/`BOOL`/`LPVOID`/`HMODULE` are `typedef`s over C types; the vault uses these freely without explanation.
- **Calling convention distinction** — `__cdecl` (caller-clean, used by C runtime, returns in `EAX`) vs `__stdcall` (callee-clean, Win32 default). The vault's `extern "C"` declarations assume this knowledge.
- **`Rtl*` wrappers over CRT** — `RtlCopyMemory` = `memcpy` etc.; use Windows-named APIs for forward compatibility.

### Operational handoffs from training → vault
The training explicitly tees up several "later in the course" topics that the vault has already implemented:
- "we will be talking about hooks later in the course" → vault T-016 (NTDLL unhook, AMSI/ETW patching)
- "later in the course, we will go even further by eliminating the import entries for `GetProcAddress` and `LoadLibraryExW` by implementing those APIs manually" → vault T-004 (PEB Walker)
- "DLL injection methods ... we will explore a few of them later in the course" → vault T-007 through T-015 (15 methods)
- "NOENTRY is something that will be discussed in greater detail when we start to build shellcode" → vault T-021 (shellcode encoding suite) and the position-independent-code patterns in `pe.rs` / `runner.rs`

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| PE structure (DOS stub, COFF, Optional Header, Sections, Directories) | T-004 PEB Walker, T-007 Pool Party, T-013 Module/Func Stomp | Training provides field-level reference; vault consumes via `pe.rs` without re-teaching |
| RVA/VA arithmetic | T-004 PEB Walker, T-008 Threadless, T-013 Stomping suite | Foundational math used by every vault export/EAT walk |
| `.text` is Execute-Read (no Write) | T-013 Module/Func Stomp, T-016 PE Stomping | Explains why stomping requires `VirtualProtect` reprotect |
| Export Directory (EAT) location in `.rdata` | T-008 Threadless (EAT hijack), T-016 Proxy DLL | EAT is the operational surface both techniques manipulate |
| Base Relocation Directory | T-016 NTDLL unhook (fresh ntdll load relocates) | Understanding relocations explains why a freshly-loaded ntdll differs from the in-process hooked one |
| System DLL hierarchy (ntdll required, kernel32/kernelbase re-export) | T-002 Hells/Halo/Tartarus Gate, T-016 NTDLL unhook | ntdll is the syscall-gateway surface the vault hooks |
| ASLR randomizes app modules per-process, system per-boot | T-002 SSN resolution, T-004 PEB Walker | Motivates dynamic resolution — addresses can't be hardcoded |
| `LoadLibraryEx` + `GetProcAddress` (explicit linking) | T-004 PEB Walker (replacement), T-016 Proxy DLL | Vault's PEB Walker is the OPSEC-hardened replacement |
| `#pragma comment(lib,...)` (implicit linking) → IAT pollution | T-020 IAT Camouflage (3 profiles), T-021 wrappers.rs `windows_targets::link!` | Training flags the risk; vault provides the mitigation |
| `__declspec(dllexport)` | T-008 Threadless (victim EAT enumeration), T-016 Proxy DLL | Common export syntax — must be recognized when walking EATs |
| `.def` file `EXPORTS` with `NONAME`/`PRIVATE`/forwarders | T-016 Proxy DLL | Forwarder syntax = proxy-DLL mechanism; `NONAME` = EAT OPSEC |
| 16 PE data directories | T-016 (NTDLL unhook via BaseRelocDir), T-013 (stomping uses ExportDir) | Most are NULL; vault cares about Export + BaseReloc + Debug |
| DLL injection (concept) | T-007–T-015 (15 methods) | Training = concept; vault = operational catalog |
| Windows data types (DWORD, HMODULE, LPVOID) | All vault cards (FFI surface) | Implicit vocabulary used throughout vault |
| `__stdcall` vs `__cdecl` | T-021 wrappers.rs (`extern "C"` ABI) | ABI correctness for FFI; mismatch = silent corruption |
| `RtlCopyMemory` = `memcpy` | T-021 patterns (Rust FFI prefers native calls) | Windows-named APIs preferred for forward-compat |
| "implementing `GetProcAddress`/`LoadLibrary` manually" (forward reference) | T-004 PEB Walker (delivered) | Training promise → vault delivered feature |
| "unloading all system DLLs even ntdll" (forward reference) | T-016 NTDLL unhook (delivered) | Training mention → vault operationalization |
| WinDbg `!dh` in-memory PE dump | T-016 (unhook verification), T-013 (stomp verification) | Dev-box verifier for in-memory image state |
| `dumpbin /imports` IAT audit | T-020 IAT Camouflage verification | Operational test for evasion builds |
| `dumpbin /exports` EAT audit | T-008 Threadless victim selection, T-016 proxy DLL verification | Identify exportable victim functions |