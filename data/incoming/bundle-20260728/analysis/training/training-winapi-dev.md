---
id: RTO-winapi-fundamentals
name: WinAPI, P/Invoke & D/Invoke Fundamentals
source: Red Team Ops / Zero-Point Security
category: winapi
analyzed_by: glm-5.2
analysis_date: 2025-01-15
vault_references: [T-001, T-002, T-004, T-006, T-007, T-013, T-016]
tags: [winapi, native-api, pinvoke, dinvoke, ordinals, vba, csharp, cpp, marshalling, createprocess, api-resolution, edr-evasion, pestudio, peview]
---

# WinAPI, P/Invoke & D/Invoke Fundamentals — Training Reference

## TL;DR
Foundational module covering the Windows API hierarchy (Win32 → Native/NT), and the three primary ways an operator calls them from offensive tooling: C/C++ direct calls, .NET P/Invoke, and D/Invoke dynamic dispatch. Introduces ordinals for static-signature evasion and VBA `Declare` for Office macro tradecraft. This material is the prerequisite mental model for everything in the vault — every syscall dispatch (T-001/T-002/T-003), injection technique (T-007–T-014), and evasion primitive (T-016) sits on top of these APIs.

## Key Concepts

1. **WinAPI vs Native API Layering**
   The Win32 API surface (kernel32.dll, advapi32.dll, user32.dll, etc.) is a higher-level wrapper that ultimately calls the Native API exported from ntdll.dll, which itself transitions into ntoskrnl.exe via syscalls. `OpenProcess` (kernel32) → `NtOpenProcess` (ntdll) → syscall. Calling the Native variant directly bypasses userland API hooks placed by EDR products — this is the operational justification for every syscall technique in the vault (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate).

2. **ANSI ("A") vs Unicode ("W") Variants**
   Each string-accepting WinAPI ships in two flavors: `*A` takes LPCSTR (ANSI), `*W` takes LPCWSTR (Unicode). The bare macro (e.g. `MessageBox`) maps to the `*W` form by default since Unicode is the Windows-preferred encoding. Operational rule: always use `*W` variants and prefix string literals with `L""` (C++) or pass Unicode strings (C# `CharSet.Unicode`).

3. **STARTUPINFO / PROCESS_INFORMATION Structs**
   The two structures underpinning every `CreateProcess`-family call. STARTUPINFOW members control window station/desktop, stdio handle inheritance, and window show state; PROCESS_INFORMATION returns hProcess, hThread, dwProcessId, dwThreadId. `cb` must hold `sizeof(STARTUPINFO)` and the structs must be zero-initialised (ZeroMemory / default constructor) before use. This is the load-bearing primitive for T-007 (Pool Party), T-009 (Process Ghosting), T-010 (Herpaderping), T-011 (Dirty Vanity), T-012 (Early Cascade), T-014 (NtCreateUserProcess), T-015 (PPID Spoofing).

4. **Managed vs Unmanaged Code**
   C/C++ compiles to native machine code (unmanaged). C# / .NET compiles to IL, JITted by the CLR, which provides GC, runtime checks, and abstractions. The CLR hides P/Invoke under its own abstractions (e.g. `System.Diagnostics.Process.Start`) but does not expose knobs like `CREATE_SUSPENDED` — forcing offensive .NET operators to P/Invoke manually for VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, and friends.

5. **P/Invoke Mechanism**
   `[DllImport("lib.dll", CharSet=..., SetLastError=true)]` decorator on an `extern static` method signature. CLR marshals managed types to unmanaged counterparts (string→LPWSTR under Unicode, IntPtr for HANDLE, `ref` for pointer-in, `out` for pointer-out). `SetLastError=true` enables `Marshal.GetLastWin32Error()` retrieval. P/Invoke signatures are static, compile-time visible, and show up in tools like pestudio — a key detection surface.

6. **Type Marshalling**
   The 99% auto-marshalled path uses `[MarshalAs(UnmanagedType.LPWStr)]` only when explicit control is required (e.g. D/Invoke manual paths, ANSI/Unicode ambiguity, custom blittable layouts). Reference: Microsoft's "Marshaling Data with Platform Invoke" table. `IntPtr` is the universal HANDLE-equivalent; `LayoutKind.Sequential` is mandatory for structs that cross the boundary.

7. **Ordinals — Static Signature Evasion**
   Each DLL export has both a name and an ordinal (numeric Primary Key). `[DllImport("user32.dll", EntryPoint="#2155")]` calls MessageBoxW by ordinal, allowing the C# method name to be arbitrary (`TotallyLegitAPI`) and removing the literal string `"MessageBoxW"` from the binary. Ordinals are NOT stable across Windows versions — must verify against target OS build with PEview. This is the simplest, oldest P/Invoke signature evasion trick; the vault's T-006 (Phantom Stubs), T-004 (PEB Walker), and T-002 (4-stage SSN cascade) all supersede it operationally.

8. **VBA `Declare PtrSafe` — Office Macro Tradecraft**
   VBA exposes the same Win32 surface via `Declare PtrSafe Function <name> Lib "lib.dll" (...)`. Required for 64-bit Office. Struct definitions use `Type ... End Type`. Unicode strings must be `StrConv(s, vbUnicode)` because VBA strings are ANSI by default. This is the same primitive used by every Office maldoc that shells out to Win32.

9. **D/Invoke — Dynamic API Resolution**
   TheWover's DInvoke.dll replaces static P/Invoke signatures with runtime resolution. Two primary primitives: `Generic.DynamicAPIInvoke("lib","Func", typeof(Delegate), ref object[] args)` for one-shot calls; and `Generic.GetLibraryAddress("lib", "Func"|ordinal)` + `Marshal.GetDelegateForFunctionPointer` for repeated calls. Delegates are decorated with `[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=...)]`. pestudio cannot see the API names because the imports list is empty. **Vault supersession**: T-004 (PEB Walker) implements the same manual module+export resolution directly in Rust via gs:[0x60] + DJB2 hash, removing the .NET dependency entirely; T-002 + T-006 cover the syscall-wrapper feature of D/Invoke with significantly stronger OPSEC (indirect syscalls, MEM_IMAGE-backed stubs).

## Operational Techniques

### C++ Direct WinAPI Call (MessageBox / CreateProcess)
- **What**: The baseline, most-detectable but simplest way to invoke Win32 from native code.
- **When to use**: Native payload development (Rust/C/C++ shellcode runners, loaders, implants) where P/Invoke signature detection does not apply. Foundation for the entire vault's Rust crate `dark_crystal`.
- **How**:
  1. `#include <Windows.h>`
  2. Declare STARTUPINFO si; PROCESS_INFORMATION pi;
  3. Set `si.cb = sizeof(si)` (mandatory per CreateProcessW docs)
  4. ZeroMemory both structs
  5. Call `CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, ...)` with the desired creation flags (note: 0 here means no CREATE_SUSPENDED — for T-007/T-012 etc. you'd pass `CREATE_SUSPENDED` = 0x4)
  6. Check BOOL return; on failure call `GetLastError()`
- **Vault link**: T-014 (NtCreateUserProcess) is the operational upgrade — bypasses CreateProcessW entirely by calling the Native API directly via indirect syscall. T-015 (PPID Spoofing) wraps the same call with STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
- **Tool/code**:
  ```cpp
  #include <Windows.h>
  STARTUPINFO si; si.cb = sizeof(si); ZeroMemory(&si, sizeof(si));
  PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
  CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, 0, 0, FALSE,
                 0, NULL, L"C:\\Windows\\System32", &si, &pi);
  ```
- **OPSEC**: Trivially detected by EDR via NtCreateUserProcess kernel callbacks (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutine). Vault's T-012 Early Cascade and T-015 PPID spoofing partially mitigate parent-process and early-thread telemetry. Native API direct calls (T-001/T-002/T-014) avoid ntdll hooks but not kernel callbacks.

### .NET P/Invoke (MessageBox / CreateProcess)
- **What**: Static, compile-time-resolved Win32 imports in C# via `[DllImport]`.
- **When to use**: Rapid tooling, C2 plugins, post-exploitation .NET assemblies (Rubeus-style, SharpHound-style), situations where iteration speed > signature OPSEC.
- **How**:
  1. Define structs with `[StructLayout(LayoutKind.Sequential)]` — STARTUPINFO, PROCESS_INFORMATION, SECURITY_ATTRIBUTES
  2. `[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]` on `extern static bool CreateProcessW(...)` — `ref` for pointer-in args, `out` for pointer-out
  3. `var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);` — equivalent of sizeof in C++
  4. Call, check return, `Marshal.GetLastWin32Error()` on failure
- **Vault link**: Superseded for any operation where the binary itself will be inspected. T-004 (PEB Walker) provides Rust-based manual module resolution with DJB2 hashing — no .NET, no metadata, no `extern` signatures. For .NET-only tradecraft contexts (Cobalt Strike execute-assembly, in-memory assemblies), D/Invoke (next technique) remains the standard.
- **Tool/code**:
  ```csharp
  [StructLayout(LayoutKind.Sequential)]
  public struct STARTUPINFO { public int cb; /* ... */ public IntPtr hStdError; }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine,
      ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
      bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
      string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation);
  ```
- **OPSEC**: pestudio, AMSI, ETW, and AssemblyLoad traces all surface the DllImport table. Names like `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` are heuristic flags for injection. Mitigations: ordinals (below), D/Invoke (next), or move the tooling out of .NET into Rust (vault approach).

### Ordinal-based DllImport (Static Signature Evasion)
- **What**: Replace `EntryPoint` with a numeric ordinal so the API name string does not appear in the binary and the C# method name can be arbitrary.
- **When to use**: Quick static-evasion bump against signature-based AV/EDR without rewriting tooling. Useful for .NET assembly duck tests.
- **How**:
  1. Open target DLL in PEview.exe
  2. Navigate to EXPORT Address Table
  3. Locate desired export (e.g. MessageBoxW)
  4. Read ordinal hex (e.g. `086B`), convert to decimal (e.g. `2155`)
  5. Rewrite DllImport as `[DllImport("user32.dll", EntryPoint = "#2155", CharSet = CharSet.Unicode)]`
  6. Rename method to anything benign
- **Vault link**: Vault's T-004 PEB Walker resolves exports by DJB2 hash of name, not ordinal — version-stable and not vulnerable to ordinal drift. T-006 Phantom Stubs generate MEM_IMAGE-backed syscall stubs that don't depend on ntdll export resolution at all. Ordinal trick is mostly superseded but still has niche value when you must stay in .NET and can't pull in D/Invoke.
- **Tool/code**:
  ```csharp
  [DllImport("user32.dll", EntryPoint = "#2155", CharSet = CharSet.Unicode)]
  static extern int TotallyLegitAPI(IntPtr hWnd, string lpText, string lpCaption, uint uType);
  ```
- **OPSEC**: Defeats simple string-match signatures. Does NOT defeat: behavioral telemetry (AMSI, ETW), kernel callbacks, memory scanners. Ordinals are not guaranteed stable across Windows builds — must re-verify per target OS.

### VBA Declare PtrSafe (Office Macro Win32 Calls)
- **What**: Office VBA equivalent of DllImport for calling Win32 from macro-enabled documents.
- **When to use**: Initial access via maldoc, Outlook rules, VBA-based loaders, legacy macro tradecraft. Pair with ScriptControl / VBA stomping for OPSEC.
- **How**:
  1. `Declare PtrSafe Function <name> Lib "lib.dll" (ByVal param As Type, ...) As ReturnType`
  2. Define structs with `Type ... End Type` (LongPtr for HANDLE on x64 Office)
  3. Convert string args with `StrConv(s, vbUnicode)` when calling `*W` variants (VBA strings are ANSI)
  4. Call from a Sub
- **Vault link**: No direct equivalent — the vault's persistence module (T-017) covers COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist; macro-based initial access is out of scope. However, VBA `Declare` is the canonical bootstrap that loads a stager which then hands off to vault primitives.
- **Tool/code**:
  ```vba
  Declare PtrSafe Function MessageBoxW Lib "user32.dll" (ByVal hWnd As LongPtr, _
      ByVal lpText As String, ByVal lpCaption As String, ByVal uType As Integer) As Integer

  Sub Test()
      Dim result As Integer
      result = MessageBoxW(0, StrConv("P/Invoke from MS Word!", vbUnicode), _
                            StrConv("Hello World", vbUnicode), 0)
  End Sub
  ```
- **OPSEC**: AMSI scans VBA on Office 2016+. Macro security warnings, VBA logging (Office 365 ATP), and parent-process telemetry (winword.exe → cmd.exe) are high-signal. Pair with AMSI bypass (vault T-016 covers `amsiPageGuard` and `amsiHbp` — HW breakpoint based, no memory patching).

### D/Invoke Dynamic API Resolution
- **What**: Runtime Win32 API resolution via PEB walk + export parsing, removing static DllImport signatures from .NET assemblies.
- **When to use**: .NET tooling that will be inspected by pestudio/AMSI/Defender static analysis; tradecraft contexts where you can't port to Rust but need P/Invoke-equivalent capability.
- **How**:
  1. Reference DInvoke.dll (prebuilt at `C:\Tools\DInvoke\DInvoke\DInvoke\bin\Debug\DInvoke.dll`, or compile from `C:\Tools\DInvoke` source)
  2. Define delegate with `[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=CharSet.Unicode)]`
  3. For one-shot calls: `Generic.DynamicAPIInvoke("user32.dll", "MessageBoxW", typeof(MessageBoxW), ref parameters)` where `parameters` is `object[]`
  4. For repeated calls: `var p = Generic.GetLibraryAddress("user32.dll", "MessageBoxW")` (or `GetLibraryAddress("user32.dll", 2155)` for ordinal overload), then `Marshal.GetDelegateForFunctionPointer(p, typeof(MessageBoxW))`
- **Vault link**: T-004 PEB Walker is the Rust-native equivalent — implements PEB walk via `gs:[0x60]`, LDR enumeration, DJB2 hash-based export resolution. T-006 Phantom Stubs extends this to generate MEM_IMAGE-backed syscall stubs for indirect syscall dispatch (no ntdll .text patching). T-001 RecycledGate and T-003 VEH Gate cover the syscall-wrapper feature of D/Invoke with far stronger OPSEC. **The training explicitly notes pestudio cannot see MessageBoxW after D/Invoke — the vault achieves this for ALL native APIs without a .NET dependency.**
- **Tool/code**:
  ```csharp
  [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
  delegate int MessageBoxW(IntPtr hWnd, string lpText, string pCaption, uint uType);

  // One-shot
  var parameters = new object[] { IntPtr.Zero, "My first D/Invoke!", "Hello World", (uint)0 };
  Generic.DynamicAPIInvoke("user32.dll", "MessageBoxW", typeof(MessageBoxW), ref parameters);

  // Repeated
  var address = Generic.GetLibraryAddress("user32.dll", "MessageBoxW");
  var messageBoxW = (MessageBoxW) Marshal.GetDelegateForFunctionPointer(address, typeof(MessageBoxW));
  messageBoxW(IntPtr.Zero, "Box 1", "Box 1", 0);
  ```
- **OPSEC**: Defeats pestudio and basic signature scanners. Does NOT defeat: AMSI (still scans .NET in-memory), ETW, runtime API hooking by EDR on ntdll, kernel-level callbacks. For full-spectrum evasion, vault's T-002 + T-001 combination (PEB walk → SSN cascade → indirect syscall via ntdll gadget) is the operational standard.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `<Windows.h>` header | C/C++ WinAPI declarations | Required for native tooling; no signature impact on native binaries |
| `STARTUPINFO` / `PROCESS_INFORMATION` | CreateProcess input/output structs | `cb` must be `sizeof(struct)`; zero-init mandatory |
| `ZeroMemory(&x, sizeof(x))` | Struct zeroing before WinAPI calls | Skipped = UB; deterministic failure |
| `Marshal.SizeOf(si)` | C# equivalent of `sizeof` for managed structs | Use for `cb` field init |
| `Marshal.GetLastWin32Error()` | Retrieve last error after P/Invoke (requires `SetLastError=true`) | Always set attribute, always check |
| `[DllImport(..., CharSet=CharSet.Unicode)]` | Static .NET Win32 import | Visible to pestudio, AMSI, ETW |
| `[StructLayout(LayoutKind.Sequential)]` | C# struct marshalling layout | Mandatory for structs crossing managed/unmanaged boundary |
| `[MarshalAs(UnmanagedType.LPWStr)]` | Explicit string marshalling | Only needed for manual / D-Invoke paths |
| `ref` / `out` keywords | C# pointer-in / pointer-out semantics | Maps to C++ `&` and `&` (out param) |
| `PEview.exe` | Inspect DLL exports & ordinals | Use to find ordinals; verify per Windows build |
| `EntryPoint = "#NNNN"` | DllImport by ordinal | Defeats name-based signatures; ordinals are OS-version dependent |
| `Declare PtrSafe Function` | VBA Win32 import | Required for x64 Office; ANSI strings by default |
| `StrConv(s, vbUnicode)` | VBA ANSI→Unicode conversion | Mandatory when calling `*W` variants from VBA |
| `Type ... End Type` | VBA struct definition | Equivalent to C# struct with StructLayout |
| DInvoke.dll | Dynamic API resolution library | Add as reference; pestudio-blind for API names |
| `[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=...)]` | D/Invoke delegate decorator | Required for dynamic API call dispatch |
| `Generic.DynamicAPIInvoke(lib, name, delegateType, ref args)` | One-shot D/Invoke call | Hides API name from imports table |
| `Generic.GetLibraryAddress(lib, name\|ordinal)` | Resolve export address | Overload accepts ordinal int directly |
| `Marshal.GetDelegateForFunctionPointer(addr, typeof(D))` | Convert fn ptr to callable delegate | For repeated D/Invoke calls |
| pestudio | Static .NET assembly analyzer (defender-side) | Detects DllImport signatures — D/Invoke evades it |

## Gaps & Extensions

### What the vault covers that this training does not
- **Indirect syscalls (T-001 RecycledGate, T-003 VEH Gate)** — the training notes stop at D/Invoke's syscall-wrapper feature; the vault implements full indirect syscall dispatch via ntdll .text gadgets and HW-breakpoint-mediated exception handlers, which D/Invoke does not provide.
- **4-stage SSN resolution cascade (T-002 Hell's/Halo's/Tartarus Gate + FreshyCalls)** — D/Invoke generates syscall wrappers via metadata parsing; the vault handles hooked-stub scenarios (Halo's Gate), randomized SSN order (Tartarus), and runtime-fresh SSN capture (FreshyCalls). D/Invoke is brittle against EDR hooks; the vault is not.
- **PEB Walker in Rust (T-004)** — direct gs:[0x60] access, LDR walking, DJB2 hash export resolution; the D/Invoke C# equivalent is observable via .NET runtime hooks.
- **Phantom Stubs (T-006)** — MEM_IMAGE-backed syscall stubs that look like legitimate ntdll code; D/Invoke delegates live in RWX/RX private memory.
- **Full EDR evasion suite (T-016)** — stack spoofing, arg spoofing, AMSI HW-bp bypass, ETW muffling, PEB unlink, NTDLL unhooking, KiUserException StepOver, block-DLL, ACG, handle blocking. The training only mentions "userland API hooking" as motivation, no actual bypass tradecraft.
- **15 process injection methods (T-007–T-014)** — the training covers `CreateProcess` (the prerequisite) but none of the actual injection primitives that consume the STARTUPINFO/PROCESS_INFORMATION outputs.
- **Sleep obfuscation (T-005 Ekko ROP)** — entirely out of scope for this training batch.

### What this training covers that the vault does not
- **VBA `Declare PtrSafe` macro tradecraft** — the vault assumes initial access is solved; this is the canonical maldoc bootstrap path for engagements that start with a phishing document. Useful as a vault entry-point reference.
- **PEview ordinal lookup workflow** — concrete tradecraft for finding export ordinals; the vault's PEB Walker uses DJB2 hash instead, but for one-off C# tools targeting a specific Windows build, ordinal lookup via PEview is faster.
- **pestudio as a defender-side static analyzer** — the vault references pestudio implicitly when motivating D/Invoke-style evasion but never describes how to use it as a self-check tool. Operators can use pestudio to verify their own pre-deployment binaries.
- **Type marshalling reference table (Microsoft)** — useful for any operator bridging .NET tooling to native APIs in hybrid tradecraft.
- **`MarshalAs` explicit attribute usage** — relevant when accessing native APIs via D/Invoke paths where auto-marshalling fails (e.g. variant arrays, COM interfaces).

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| WinAPI → Native API layering (OpenProcess → NtOpenProcess) | T-001 RecycledGate, T-002 Hells/Halo/Tartarus Gate, T-003 VEH Gate | Vault operationalizes the "call Native directly" motivation with indirect syscall dispatch — the next layer beyond this training |
| kernel32.dll / advapi32.dll base services | T-016 EDR Evasion Suite (AMSI, ETW, unhooking) | These are the DLLs the vault's evasion module patches unhooks |
| ntdll.dll as usermode syscall trampoline | T-002 SSN cascade, T-006 Phantom Stubs, T-016 NTDLL unhook | Central to vault syscall dispatch and unhooking tradecraft |
| CreateProcess / STARTUPINFO / PROCESS_INFORMATION | T-007 Pool Party, T-009 Ghosting, T-010 Herpaderping, T-011 Dirty Vanity, T-012 Early Cascade, T-014 NtCreateUserProcess, T-015 PPID Spoofing | Foundation primitive; every vault injection technique consumes these structures |
| P/Invoke + DllImport static signature detection | T-004 PEB Walker, T-006 Phantom Stubs | Vault eliminates static signatures entirely by moving to Rust + manual resolution |
| Type marshalling (managed → unmanaged) | T-021 Crypto & Obfuscation (FFI patterns) | Vault's `Rust Patterns` doc covers the Rust-side equivalent (windows_targets::link!, FFI) |
| Ordinals (#2155) for API-name evasion | T-004 PEB Walker (DJB2 hash) | Vault uses name hashing instead of ordinals — version-stable, no per-OS lookup needed |
| VBA `Declare PtrSafe` | (no direct vault equivalent) | Training-only; macro-based initial access is out of vault scope |
| D/Invoke `DynamicAPIInvoke` | T-004 PEB Walker | Rust equivalent: PEB walk + module + export resolution; no .NET dependency, no AMSI surface |
| D/Invoke `GetLibraryAddress` (incl. ordinal overload) | T-004 PEB Walker | Same operation, performed via gs:[0x60] inline; vault's resolve.rs |
| D/Invoke syscall wrappers | T-001 RecycledGate, T-002 Hells Gate, T-003 VEH Gate, T-006 Phantom Stubs | Vault replaces with indirect syscalls (not direct) — never transitions through ntdll syscall stub from caller's own stack |
| pestudio as static analyzer | (referenced implicitly throughout T-016) | Operator-side verification tool for own binaries |
| CreateProcess → PROCESS_INFORMATION output (hProcess, hThread, dwPID, dwTID) | T-007 Pool Party (TP_WORK items), T-012 Early Cascade (pre-LdrInitializeThunk APC), T-015 PPID Spoofing (STARTUPINFOEX) | Vault techniques consume these outputs as injection vectors not available through vanilla CreateProcess |

---

**Bottom line for operators**: This module is the prerequisite vocabulary. If you can write a clean `CreateProcessW` in C++ and P/Invoke it from C#, you have the foundation to read every vault technique card T-001 through T-023. The D/Invoke section is operationally superseded by the vault's Rust-native PEB Walker + indirect syscall stack — but D/Invoke remains the right tool for engagements constrained to .NET tradecraft (Cobalt Strike execute-assembly, in-memory .NET assemblies, post-ex tooling where iteration speed dominates).