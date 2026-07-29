```
---
id: RTO-winapi-foundations
name: Windows API Foundations — Data Types, Calling Conventions, SAL
source: SEC670 / SANS Red Teaming Tools: Developing Windows Implants, Shellcode, Command and Control
category: winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-001, T-002, T-003, T-004, T-006, T-007, T-012, T-016, T-020, T-023]
tags: [win32, data-types, calling-conventions, sal, x64-abi, peb, fundamental, c-plus-plus, smart-pointers, handles]
---

# Windows API Foundations — Training Reference

## TL;DR
Foundational SEC670 module covering Win32 data types (BOOL/BOOLEAN/HANDLE/VOID/PVOID family), the four x86/x64 calling conventions, and Microsoft's SAL annotation language. None of this is directly a "technique" — it is the substrate every vault syscall stub, injection primitive, and API resolver stands on. Operators writing or auditing Rust FFI to ntdll/kernel32 must internalize the x64 ABI (RCX/RDX/R8/R9 + shadow space RSP+0x20) and the `HANDLE == PVOID` equivalence, both of which appear verbatim in vault code (T-001 RecycledGate stubs, T-004 PEB walker, T-016 handle blocking).

## Key Concepts

1. **Windows data types vs. CRT types** — Microsoft aliases (`DWORD`, `BOOL`, `HANDLE`, `LPVOID`) decouple sizes from compiler defaults; `DWORD` is always `unsigned long` (32-bit) regardless of target. Critical for portability of syscall stubs and PE parsing code across architectures. Vault's `wrappers.rs` (T-021 patterns) binds these via `windows_targets::link!`.
2. **`BOOL` vs. `BOOLEAN`** — `BOOL` = `int` (4 bytes); `BOOLEAN` = `BYTE` (1 byte). Mixing them wastes stack or causes misreads when interpreting `NTSTATUS`-style return fields. Operators must verify which is in play when a Win32 API returns a status.
3. **`HANDLE` is `PVOID`** — Every `HMODULE`, `HINSTANCE`, `HKEY`, `HRSRC`, `LPHANDLE` resolves to `void*`. This is why T-016's handle-blocking and T-004's PEB walk can treat module base addresses uniformly; why `GetModuleHandleW` returns `HMODULE` but is used as a raw pointer to walk EATs.
4. **`HMODULE == HINSTANCE`** — Both are simply the base address of a loaded module. Operationally: anything accepting `HINSTANCE` accepts an `HMODULE`. Used implicitly when vault passes module base to `RtlImageNtHeaders` or walks the InLoadOrderModuleList.
5. **x64 ABI: RCX/RDX/R8/R9 + shadow space** — First four integer/pointer args go in registers; remaining args spill to stack at `RSP+0x20` onward (32-byte shadow store reserved for the callee to spill RCX–R9). Floating point uses XMM0–XMM3. **This is the rule that makes RecycledGate (T-001) and VEH Gate (T-003) possible** — operator controls the stack frame layout to spoof return addresses.
6. **`WINAPI`/`APIENTRY`/`CALLBACK` all expand to `__stdcall`** — Win32 API calling convention. On x64 this collapses to the Microsoft x64 ABI; on x86 it is genuine `__stdcall` (callee-cleaned, right-to-left). Direct relevance: thread start routines (`LPTHREAD_START_ROUTINE`), APC procs, enum callbacks, and VEH handlers must be declared with this convention.
7. **`__cdecl` for variadic** — Caller cleans stack; only option for VARARG functions like `printf`. Implies any implant that uses CRT `printf`-style logging pulls in cleanup code per call site — a binary-size and signature consideration.
8. **`__fastcall` (x86 only)** — First two DWORD-or-smaller args in ECX/EDX; name-decorated as `@Func@<bytes>`. Largely irrelevant on x64 but encountered when reading 32-bit shellcode or legacy PEs.
9. **`__thiscall` (x86 C++ only)** — `this` pointer in ECX; rest on stack. Useful when reverse engineering vtable-driven code or hijacking class methods in target processes (e.g., T-007 Pool Party vtable hijack).
10. **SAL annotations** — `_In_`, `_Out_`, `_Inout_`, `_In_opt_`, `_Out_writes_bytes_(s)`, `_Success_(expr)`, `_When_(expr, anno)`, `_Check_return_`, `_Ret_maybenull_`. The annotation language is how MSDN and `winnt.h` express contracts; vault technique cards repeatedly reference `InitializeProcThreadAttributeList`, `CreateThread`, `CreateProcessW`, `RtlFirstEntrySlist` — all heavily SAL-annotated.
11. **C++ smart pointers** — `std::make_shared<T>` / `std::make_unique<T>` should replace raw `new`. Direct relevance to vault's **Rust RAII guards** (T-021 patterns): same philosophy (`Drop` trait ≈ smart-pointer destructor). `std::bit_cast<T>` is the C++20 safe alternative to `reinterpret_cast` for type punning — Rust uses `transmute`/`zerocopy`.
12. **`__readgsqword(0x60)` / `__readfsdword(0x30)`** — Direct PEB access on x64 and x86 respectively. This is the literal primitive T-004 PEB Walker is built on.

## Operational Techniques

### Reading Win32 API Signatures Correctly
- **What**: Decode a Win32 API prototype (with SAL) into "what to allocate, what to pass, what to check".
- **When to use**: Every time you write FFI bindings, shellcode, or BOF output.
- **How**:
  1. Scan the signature for `_Out_` / `_Inout_` parameters — these require caller-allocated buffers.
  2. Look at any `_<x>_writes_<y>_(s)` annotation — that is your required buffer size in elements/bytes.
  3. Check for `_Success_(expr)` — defines what return value actually means success (e.g., `GetExitCodeThread` returns BOOL, `TRUE` = success).
  4. Check for `_Ret_maybenull_` / `_Must_inspect_result_` — caller MUST NULL-check; skipping this is a CVE class.
  5. For `_When_(expr, anno-list)` parameters, branch your buffer setup on the condition.
- **Vault link**: T-004 PEB Walker uses this exact reading discipline when resolving `LdrLoadDll`/`LdrGetProcedureAddress` prototypes; T-007 Pool Party leans on it for `TpAllocWork`/`StartThreadpoolIo` parameter handling.
- **Tool/code**: MSDN, `winnt.h`, `winreg.h`, `sal.h` (also mirrored at `github.com/dotnet/corert/.../sal.h`).
- **OPSEC**: Skipping SAL-implied buffer checks causes AV-detectable access violations; gets caught by EDR's `KiUserExceptionDispatcher` telemetry unless T-016's StepOver primitive is in play.

### Declaring Callback / Thread Start Routines
- **What**: Use `WINAPI` (`__stdcall`) decoration on any function pointer Win32 will call back into.
- **When to use**: Thread creation (`CreateThread`/`RtlCreateUserThread`), APC injection (T-012 Early Cascade, Early Bird), timer callbacks, enum callbacks, `LdrRegisterDllNotification` (COM hijack), VEH handlers.
- **How**:
  1. Prototype: `DWORD WINAPI ThreadProc(_In_ LPVOID lpThreadParameter)` (or `VOID CALLBACK` for APC/timer).
  2. Cast function pointer with `std::bit_cast<decltype(CreateThread)*>` (C++20) or a C-style cast.
  3. On x64, `__stdcall` collapses into the Microsoft x64 ABI — no special handling needed.
  4. On x86, ensure the callee cleans `4 * arg_count` bytes — a missed `WINAPI` on a 32-bit target corrupts the stack.
- **Vault link**: T-012 Early Cascade (pre-`LdrInitializeThunk` APC), T-013 Early Bird APC, T-011 Dirty Vanity reflection callback, T-003 VEH Gate exception handler. The vault's `rustvehsyscalls` library and `experimental/evasion/veh/hooks.rs` rely on these conventions.
- **Tool/code**:
  ```c
  DWORD WINAPI WorkerThread(LPVOID ctx) { /* ... */ return 0; }
  HANDLE h = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
  ```
- **OPSEC**: A callback with the wrong calling convention crashes loudly — EDR flags the `KiUserExceptionDispatcher` event. Pair with T-016 KiUserException StepOver to suppress.

### Direct PEB Access for Module Resolution
- **What**: Read the PEB via `gs:[0x60]` (x64) or `fs:[0x30]` (x86) without calling any API.
- **When to use**: API hash resolution, `ntdll`/`kernel32` base discovery in shellcode, pre-`LoadLibrary` module enumeration (T-004, T-001, T-002 all need this).
- **How**:
  ```c
  DWORD peb32 = __readfsdword(0x30);     // x86 only
  QWORD peb64 = __readgsqword(0x60);     // x64 only
  // PEB->Ldr->InLoadOrderModuleList walks ntdll, kernel32, etc.
  ```
- **Vault link**: T-004 PEB Walker implements the full walk via `gs:[0x60]` + DJB2 hashing of module/export names; T-001/T-002/T-003 all depend on this base resolution before syscall SSN discovery.
- **Tool/code**: MSVC intrinsics `__readgsqword`/`__readfsdword`; Rust equivalent via `core::arch::asm!` reading `gs`/`fs` segment base.
- **OPSEC**: No API call = no ETW `KernelProc`/`ImageLoad` event. The cleanest module-discovery path.

### Type-Punning Handles and Module Bases
- **What**: Treat `HMODULE`, `HINSTANCE`, `HRSRC`, `HKEY` as the `PVOID` they are.
- **When to use**: PE header parsing (T-007 module stomping, T-008 Threadless export hijack), `GetProcAddress` replacement, custom EAT walking.
- **How**:
  ```c
  PVOID base = (PVOID)GetModuleHandleW(L"ntdll.dll");   // HMODULE → PVOID
  PIMAGE_NT_HEADERS nt = RtlImageNtHeader(base);         // accepts PVOID
  ```
- **Vault link**: T-008 Threadless injection walks EAT of a host module using this cast; T-016 unhook does the same to locate `ntdll!.text` for restoration.
- **Tool/code**: `RtlImageNtHeaders`, `ImageDirectoryEntryToData`, manual `IMAGE_DOS_HEADER`/`IMAGE_NT_HEADERS` walk.
- **OPSEC**: Reading an in-memory module's headers does not trip `VirtualQuery` telemetry; safer than re-`LoadLibrary`.

### Smart Pointer / RAII Buffer Management
- **What**: Use `std::vector<BYTE>` for buffers, `std::make_unique`/`make_shared` for owned allocations; never raw `new`.
- **When to use**: Any C++ implant logic holding decrypted payloads, IPC buffers, or PE images.
- **How**:
  ```c
  std::vector<BYTE> payload(pDecrypted, pDecrypted + cbDecrypted);
  auto sp = std::make_shared<Session>(...);
  auto raw = sp.get();           // only when a Win32 API demands a raw ptr
  ```
- **Vault link**: Vault uses Rust's RAII (Drop guards, `OnceLock`) as the equivalent — see T-021 Rust Patterns. Conceptually identical: scope-bound cleanup, no `delete` calls.
- **Tool/code**: `<memory>`, `<vector>`, `std::string_view` for non-owning string references.
- **OPSEC**: Memory that auto-zeroizes on scope exit (`vector<BYTE>` with custom allocator + memset) reduces forensic residue; vault accomplishes same with `Zeroizing` wrappers.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `__readgsqword(0x60)` / `__readfsdword(0x30)` | Read PEB address on x64/x86 | No API call — invisible to ETW user-mode providers |
| `windows_targets::link!` (Rust) | Bind Win32/NT API with correct calling convention | Vault's standard binding macro (T-021 patterns) |
| `std::bit_cast<T>` (C++20) | Safe type punning for function pointers | Avoids `reinterpret_cast` UB; not all toolchains on C++20 yet |
| `std::make_unique<T>` / `std::make_shared<T>` | Smart pointer allocation | Avoid `new`/`delete`; pairs with `Zeroizing` allocator |
| `sal.h` (or dotnet/corert mirror) | Reference for SAL annotation semantics | Required reading when hand-translating Win32 prototypes to Rust |
| IDA Pro disassembly view | Verify calling convention of unknown function | Look for `@Func@<n>` (fastcall), `retn N` (stdcall), `add rsp,N` after call (cdecl) |
| `winnt.h`, `windef.h`, `winreg.h` | Source-of-truth typedefs (`HANDLE`, `WINAPI`, `HMODULE`) | Cross-check against `windows-rs` crate when in doubt |
| `RtlImageNtHeader` / `ImageDirectoryEntryToData` | PE header / directory walking | Accept PVOID — works on in-memory modules without `LoadLibrary` |

## Gaps & Extensions

**What the training adds that the vault under-documents:**
- A consolidated C++ data-type reference table (`UCHAR/BYTE/BOOLEAN → unsigned char`, `ULONG/DWORD → unsigned long`, `QWORD → unsigned __int64`). Vault assumes this literacy.
- An explicit comparison of `BOOL` (4-byte) vs. `BOOLEAN` (1-byte) — a recurring source of subtle bugs when interfacing `NTSTATUS` (LONG) with `BOOL` returns.
- A naming-convention reading key: the `H` prefix = HANDLE family; the `LP` prefix = long pointer (now identical to `P`); the `C` infix = const.
- The shadow-space explanation (`RSP+0x20`) — vault T-001/T-003 inline-asm stubs assume this knowledge but don't restate it. An operator hand-editing a stub can break a stack frame by miscomputing spill offsets.
- SAL annotation grammar at intermediate (`_In_reads_`, `_Out_writes_bytes_all_`) and advanced (`_When_`, `_Success_`, `_Ret_writes_to_`) tiers — useful when reading undocumented or only-header-documented NT APIs.

**What the vault covers that this training does not:**
- Direct NT syscall dispatch (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate, T-006 Phantom Stubs) — the training stops at the Win32 API layer; the vault goes one level below into `int 0x2E`/`syscall` instruction emission.
- Sleep obfuscation with stack spoofing (T-005 Ekko ROP) — the training's calling-convention coverage is necessary background for crafting the ROP frames.
- All 15 injection methods (T-007 through T-015), 13 EDR-evasion primitives (T-016), persistence suite (T-017), and polymorphic resurrection (T-018) — far beyond the foundational scope here.
- Rust-specific patterns: `OnceLock` singletons, `Drop` RAII guards, `zerocopy::FromBytes`, `core::arch::asm!` — the vault's implementation language; this training is C++-centric.

**Concrete overlap and where training is superseded:**
- The training's `__readgsqword(0x60)` example is the seed of T-004 PEB Walker but only the *first instruction* of it. The vault's full implementation includes DJB2 module-name hashing, `InLoadOrderModuleList` walking, and export-table resolution.
- The training's `HMODULE == HINSTANCE` equivalence is assumed silently throughout the vault; this is the first explicit statement of it in the corpus.
- The training's smart-pointer advocacy maps to T-021's RAII guard pattern in Rust — same operational intent, different syntax. Operators porting C++ to Rust should anchor on this equivalence.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `__readgsqword(0x60)` PEB access | T-004 PEB Walker | Training shows the seed instruction; vault implements the full module/export resolution cascade on top |
| `HANDLE == PVOID` equivalence | T-016 EDR Evasion (handle blocking), T-007 Process Injection | Foundation for handle-table manipulation and module-base type punning |
| `HMODULE == HINSTANCE` | T-008 Threadless, T-016 NTDLL unhook | Used implicitly when stomping/unhooking modules by base address |
| x64 ABI: RCX/RDX/R8/R9 + shadow RSP+0x20 | T-001 RecycledGate, T-003 VEH Gate | Required to author the inline-asm syscall stubs and stack-spoofing frames |
| `WINAPI == __stdcall` callback decoration | T-012 Early Cascade, T-013 Early Bird, T-011 Dirty Vanity, T-017 TLS callback | Thread/APC/reflection callback prototypes must use it |
| `__thiscall` (x86 C++ vtable) | T-007 Pool Party (vtable hijack) | Background for understanding the target's `this` pointer in vtable-driven hijacks |
| SAL `_Out_writes_bytes_all_(s)` | T-015 PPID Spoofing (`InitializeProcThreadAttributeList`), T-007 all injection | Reading the attribute-list API contract |
| SAL `_Success_(expr)` | All Win32 API consumption | Defining the success condition before checking return — operational correctness |
| `std::bit_cast<T>` for function pointers | T-021 Rust Patterns | C++20 analog of Rust `transmute`/`zerocopy` |
| `std::make_unique` / RAII | T-021 Rust Patterns (Drop guards, `OnceLock`) | Same philosophy in C++ vs. Rust; vault enforces it via compiler |
| `std::vector<BYTE>` buffers | T-021 Crypto (`AES-256-GCM + zstd` pipeline), T-020 Crypto | Pattern mirrored as Rust `Vec<u8>` with `Zeroizing` wrapper |
| `BOOL` vs. `BOOLEAN` size | T-016 EDR Evasion (arg spoofing) | Required when spoofing stack args of different widths |
| `std::string_view` non-owning view | T-023 Client Capabilities (string handling), T-021 obf strings | Avoids copying obfuscated strings at function boundaries |
```

This consolidated reference distills the foundational Win32 / C++ material from SEC670 into operator-grade notes. The training content itself is introductory — its value to the vault is **cross-cutting**: every T-001 through T-023 card assumes mastery of these data types, the x64 ABI, and SAL grammar. Operators should treat this document as the prerequisite reading list before touching any syscall stub, injection primitive, or evasion module in the vault.