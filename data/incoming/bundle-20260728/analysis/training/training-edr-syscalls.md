---
id: RTO-edr-bypass-tradecraft
name: EDR Bypass Tradecraft (Hooking, Syscalls, BYOVD)
source: Red Team Ops / Zero-Point Security
category: edr-bypass
analyzed_by: glm-5.2
analysis_date: 2026-05-18
vault_references: [T-001, T-002, T-003, T-004, T-006, T-016, T-018]
tags: [edr, hooking, iat-hooking, inline-hooking, unhooking, manual-mapping, syscalls, syswhispers, udrl, artifactkit, blockdlls, kernel-callbacks, byovd, dse-bypass, gdrv, ci-g_cioptions]
---

# EDR Bypass Tradecraft — Training Reference

## TL;DR
This module covers the EDR detection model from the ground up — how vendors hook Win32/Nt APIs in userland via IAT and inline hooking, how those hooks surface in ETW telemetry, and how an operator bypasses each layer (manual ntdll mapping, syscall stubs, SysWhispers2 + Artifact Kit, Block-DLL mitigation, kernel callback patching, and BYOVD-based DSE bypass). It is the conceptual prequel to the vault's syscall dispatch (T-001/T-002/T-003) and EDR evasion (T-016) cards — the training explains *why* these techniques exist, while the vault implements hardened, modernized versions.

## Key Concepts

1. **EDR architecture** — A userland DLL is injected by a kernel driver into every spawned process, where it hooks Nt* APIs in `ntdll.dll` and emits telemetry via ETW. Hooking happens at the lowest userland layer (`Nt*` not `kernel32!*`) so a single hook catches sibling APIs (e.g., `MiniDumpWriteDump` → `NtOpenProcess`).

2. **IAT hooking** — EDR walks the target PE's Import Address Table and overwrites API pointers with detour addresses inside the EDR DLL. Trivially defeated by resolving APIs dynamically (GetProcAddress / PEB walk) — which is exactly why modern EDRs prefer inline hooks. Cross-ref: vault T-004 PEB Walker is the operational answer to IAT hook avoidance.

3. **Inline (trampoline) hooking** — The first bytes of the API in `ntdll` (typically the `mov r10, rcx; mov eax, <SSN>` prologue) are patched with a `jmp` to a detour. This is the dominant detection mechanism against which all syscall techniques (T-001, T-002, T-003) are designed.

4. **Hook detection via prologue inspection** — Matt Hand's HookDetector pattern: read first 4 bytes of each Nt* export from the in-memory ntdll and check for the `4C 8B D1` (`mov r10, rcx`) + `B8` (`mov eax, ...`) signature. A `E9` (`jmp`) in byte 0 = hooked. The vault's T-002 Tartarus Gate uses the same prologue inspection as the trigger for fallback to Halo's Gate (sort by SSN) on hooked stubs.

5. **Block-DLL mitigation policy** — `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` (passed via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` in `STARTUPINFOEX`) prevents unsigned/non-MS DLLs (i.e., the EDR's injected DLL) from loading into a spawned child. Beacon's `blockdlls` command exposes this for fork-and-run post-ex. Vault T-016 implements the same policy natively.

6. **Syscall hierarchy** — Win32 API (kernel32/user32) → Nt API (ntdll) → `syscall` instruction with SSN in EAX. SSNs are version-specific; j00ru's syscall table is the canonical reference. The training teaches direct syscalls via SysWhispers2; vault T-002 layers FreshyCalls + Hell's Gate + Halo's Gate + Tartarus Gate for runtime SSN discovery that survives hooking.

7. **Kernel callbacks** — Drivers register notification routines (`PsSetCreateProcessNotifyRoutineEx`, `PsCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`) stored in kernel arrays (e.g., `PspCreateProcessNotifyRoutine`). These are the *telemetry source* EDRs use when userland hooks are bypassed — syscalls do NOT evade kernel callbacks. Removal requires a kernel R/W primitive, typically via BYOVD.

8. **Driver Signature Enforcement (DSE)** — `CI!g_CiOptions` (in `ci.dll`) holds the runtime code-integrity policy. With a kernel arbitrary-write primitive (e.g., gdrv.sys CVE-2018-19320/19321), flip bit 1 to disable signing enforcement temporarily, load your unsigned driver, then restore. The kernel bug-checks against the boot policy, so the window must be tight. Vault T-018 BYOVD covers this end-to-end.

9. **UDRL (User Defined Reflective Loader)** — A Cobalt Strike kit that replaces Beacon's built-in reflective loader (used in payload artifacts AND post-ex like `execute-assembly`/`powerpick`). Public UDRLs (BokuLoader, KaynStrike, ElusiveMice) supersede Malleable C2 directives like `userwx`. Not represented in the vault — CS-specific tradecraft.

10. **InlineWhispers2** — SysWhispers2's raw output is incompatible with Beacon BOFs/Artifacts because of how it references the syscall stubs. InlineWhispers2 (Sh0ckFR) post-processes SysWhispers2 output into a form that drops into the Artifact Kit's `src-common/`. Required workflow for CS syscall integration.

## Operational Techniques

### IAT Hooking (Detection Concept)
- **What**: EDR overwrites IAT entries of a loaded PE to redirect API calls to EDR-controlled detours.
- **When to use**: Understand as a defender mechanism; you do not "use" it, but you must recognize when an EDR is doing it (vs. inline).
- **How**: EDR DLL injected into process → walks loaded PE IAT → swaps `ntdll!NtOpenProcess` pointer with `edr!NtOpenProcessDetour` → detour inspects args, optionally logs via ETW, forwards to original.
- **Vault link**: T-004 PEB Walker — dynamic resolution via `gs:[0x60]` PEB walk bypasses IAT hooking entirely because no IAT entry exists for the resolved function. T-016 IAT Camouflage is the inverse (we *plant* a fake IAT).
- **Tool/code**: `CFF Explorer` (static IAT view), `WinDbg` (`dps` on IAT range in running process).
- **OPSEC**: If EDR uses IAT hooks only, dynamic API resolution defeats it cleanly with no integrity alert (no hook tampering occurs).

### Inline Hooking (Detection Concept)
- **What**: EDR patches first bytes of Nt* API in `ntdll` with `jmp <edr_detour>`.
- **When to use**: Recognize as the dominant modern EDR mechanism.
- **How**: EDR resolves ntdll export → writes `E9 xx xx xx xx` (rel32 jmp) at function start → preserves original prologue in a trampoline for later re-invocation. Visible in WinDbg: original `sub rsp, X` replaced with `jmp`.
- **Vault link**: This is *the* threat model T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, and T-003 VEH Gate are designed to defeat — by never entering the hooked stub.
- **Tool/code**: WinDbg `u ntdll!NtOpenProcess`.
- **OPSEC**: N/A — this is detection-side.

### Hook Detection (HookDetector Pattern)
- **What**: Scan in-memory ntdll exports to identify which Nt* APIs are inline-hooked before deciding on a bypass strategy.
- **When to use**: Pre-engagement recon on a host with an unknown EDR; pick injection primitives that route around hooked APIs.
- **How**:
  1. Get ntdll base via `GetModuleHandleA("ntdll.dll")` (or PEB walk).
  2. For each Nt* export of interest, read first 4 bytes.
  3. Compare to expected signature `4C 8B D1 B8` (`mov r10, rcx; mov eax, ...`).
  4. If byte 0 == `E9` (or any deviation from signature) → HOOK DETECTED.
- **Vault link**: T-002 implements this exact check as the *trigger* for cascading to Halo's Gate — if a stub is hooked, fall back to scanning nearby unhooked stubs to deduce the SSN. The vault operationalizes HookDetector rather than just reporting it.
- **Tool/code**: `matterpreter/OffensiveCSharp/HookDetector` (C# reference implementation).
- **OPSEC**: Pure read of self-process memory — no API calls, no integrity violation. Safe to run pre-injection.

### Manual Mapping of ntdll (D/Invoke)
- **What**: Map a fresh copy of `ntdll.dll` from disk into the calling process and invoke Nt* exports from the unhooked instance.
- **When to use**: When you must call specific hooked Nt* APIs (e.g., `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) and want to avoid ETW-side detection.
- **How**:
  1. `var ntdll = Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");` (D/Invoke).
  2. Inspect in debugger — new region appears in random memory, not as a loaded module.
  3. Build `OBJECT_ATTRIBUTES` and `CLIENT_ID` parameter objects.
  4. `Generic.CallMappedDLLModuleExport(ntdll.PEINFO, ntdll.ModuleBase, "NtOpenProcess", typeof(NtOpenProcessDelegate), parameters, false)`.
  5. Repeat for `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`.
  6. `Map.FreeModule(ntdll)` to clean up (leftover mapped ntdll is an IoC).
- **Vault link**: Superseded by **T-016 NTDLL unhook** (restores `.text` from a fresh on-disk copy into the *existing* ntdll, no second mapping) and by **T-001 RecycledGate** (no need to invoke Nt* via ntdll at all — direct indirect syscall). Vault approach is cleaner and avoids D/Invoke's own use of `NtAllocateVirtualMemory`/`NtWriteVirtualMemory` to map (which itself trips hooks).
- **Tool/code**: D/Invoke `Map.MapModuleToMemory`, `Generic.CallMappedDLLModuleExport`, `Map.FreeModule`.
- **OPSEC**: The mapped ntdll in random memory with no file backing is a strong memory-scanning IoC. D/Invoke's internal allocation calls can themselves trip hooks. Free after use.

### GetSyscallStub (D/Invoke)
- **What**: Copy the original syscall stub for an Nt* API from on-disk ntdll into a private executable buffer in the calling process.
- **When to use**: Targeted bypass of one or two specific hooked stubs without a full syscall framework.
- **How**:
  1. `IntPtr p = Generic.GetSyscallStub("NtOpenProcess");`
  2. `var del = Marshal.GetDelegateForFunctionPointer(p, typeof(NtOpenProcessDelegate));`
  3. Invoke delegate with normal parameters.
  4. (If long-lived) free the stub buffer via `NtFreeVirtualMemory` — leftover stubs are an IoC.
- **Vault link**: Superseded by **T-001 RecycledGate** (gadget-resolved indirect syscall, no per-stub allocation, no stub buffer IoC) and **T-006 Phantom Stubs** (MEM_IMAGE-backed stubs that look like legitimate ntdll pages). The D/Invoke approach is detectable via private RX regions.
- **Tool/code**: D/Invoke `Generic.GetSyscallStub`, `Marshal.GetDelegateForFunctionPointer`.
- **OPSEC**: Each stub is a private RWX/RX allocation — classic memory-scanner IoC. Must free after use.

### SysWhispers2 + InlineWhispers2
- **What**: Generate masm/C stubs for direct `syscall` invocation with runtime SSN resolution (SysWhispers2); post-process for Beacon Artifact Kit compatibility (InlineWhispers2).
- **When to use**: Building C++ payload artifacts that must avoid ntdll stubs entirely; integrating syscalls into Cobalt Strike's Artifact Kit.
- **How**:
  1. `python3 syswhispers.py -p common -a x64 -l masm -o syscalls` (produces `syscalls.h`, `syscalls.c`, `syscallsstubs.x64.asm`).
  2. `python3 syswhispers.py -p all -o syscalls_all` (full set).
  3. `python3 InlineWhispers2.py` (consumes SysWhispers2 output, emits BOF/Artifact-compatible `syscalls.c`, `syscalls.h`, `syscalls-asm.h`).
  4. Drop output files into `cobaltstrike/arsenal-kit/kits/artifact/src-common/`.
  5. `#include "syscalls.c"` above the `spawn()` function in `patch.c`.
  6. Replace `VirtualAlloc`/`VirtualProtect`/`CreateThread` with `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`/`NtCreateThreadEx`.
  7. Patch `build.sh`: add `-masm=intel` to `c_options` in `build_artifacts64`; comment out `build_artifacts` call (x86) if only x64 stubs were generated.
  8. `./build.sh pipe VirtualAlloc 271360 5 true false /tmp/artifact`.
  9. Copy artifacts + `artifact.cna` to CS team server, load aggressor script.
- **Vault link**: Superseded by **T-002 Hell's/Halo's/Tartarus Gate + FreshyCalls** — 4-stage cascade including RVA-sort SSN resolution that survives both hooked stubs and ASLR randomization. SysWhispers2's runtime SSN scan is roughly equivalent to Hell's Gate alone; it has no Halo's (handle hooked stub by scanning neighbors) or Tartarus (sort by Zw* RVA) fallback. Vault dispatches via **T-001 RecycledGate** (indirect) which avoids `syscall` originating from implant memory.
- **Tool/code**: SysWhispers2 (`/home/ubuntu/SysWhispers2`), InlineWhispers2 (`/home/ubuntu/InlineWhispers2`), `pscp -i Desktop\ssh.ppk ...`, `cobaltstrike/arsenal-kit/kits/artifact/build.sh`.
- **OPSEC**: Direct `syscall` instruction in implant `.text` is a static IoC (memory scanner finds `0F 05` outside ntdll). Vault's RecycledGate indirect dispatch executes `syscall` from inside ntdll's `.text`, sidestepping this.

### Process Mitigation Policy (Block-DLL)
- **What**: Spawn child processes with `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` to prevent the EDR's userland DLL from being injected.
- **When to use**: Any fork-and-run post-ex (Beacon `execute-assembly`, `powerpick`, `execute` sacrificial process). Especially valuable when staging reflective payloads or running .NET assemblies that would otherwise inherit EDR hooks.
- **How**:
  1. Initialize `STARTUPINFOEX` and `PROC_THREAD_ATTRIBUTE_LIST`.
  2. `DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;`
  3. `UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);`
  4. `CreateProcess(..., EXTENDED_STARTUPINFO_PRESENT, ...)`.
  5. Verify in Process Hacker → Process tab → Mitigation tab → "Block non-MS binaries".
- **Vault link**: **T-016 Block-DLL** — same policy, same flag, same workflow. Also **T-015 PPID Spoofing** (same `UpdateProcThreadAttribute` plumbing, often combined — block-DLL + PPID spoof + ACG in one `lpAttributeList`).
- **Tool/code**: Beacon `blockdlls start` / `blockdlls stop` (CS built-in), `UpdateProcThreadAttribute`, `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`.
- **OPSEC**: Requires Windows 10+ / Server 2012+. The mitigation is visible in Process Explorer/Process Hacker — analysts aware of CS tradecraft will recognize the pattern. EDR may also flag "child of suspicious parent with block-dll enabled".

### Kernel Callback Patching (evil-driver)
- **What**: Disable or remove kernel notification routines (process/thread/image-load callbacks) by patching the routine pointer or the routine's first instruction with `RET` (`0xC3`).
- **When to use**: After gaining a kernel R/W primitive (typically via BYOVD); needed to blind Sysmon/EDR *kernel-side* telemetry that survives userland unhooking.
- **How**:
  1. Load `evil.sys` via SCM: `sc create evilDriver type= kernel binPath= C:\Tools\evil-driver\evil.sys` → `sc start evilDriver`.
  2. `evil.exe -l` lists all process (`PspCreateProcessNotifyRoutine`), thread, and image-load callbacks with their owning driver.
  3. To blind a process-create callback: `evil.exe -pp <index>` — patches first instruction with `RET` (0xC3) so the routine returns immediately without logging.
  4. To blind a thread-create callback entirely (delete, not patch): `evil.exe -dt <index>` — removes the entry from the array. DebugView shows `[evilDrv] Callback Removed!`.
  5. Restore with `evil.exe -rp <index>` (rolls back the RET patch to original bytes).
- **Vault link**: **T-018 BYOVD** — full pipeline (vulnerable driver identification, SCM service registration, kernel R/W primitive exposed to userland, callback patching utility). The training's `evil.sys` is a from-scratch driver; the vault's BYOVD module catalogues known-vulnerable signed drivers (gdrv, RTCore64, etc.) for opsec-friendly kernel primitives without writing your own driver.
- **Tool/code**: `sc.exe`, `evil.exe -l|-pp|-dt|-rp`, DebugView with Capture → Kernel Capture enabled, Sysmon Event Viewer at `Applications and Service Logs > Microsoft > Windows > Sysmon > Operational` (EID 1).
- **OPSEC**: Requires kernel R/W. The `evil.sys` driver itself is unsigned → needs DSE bypass first (see next). Patched callback array entries are a forensic IoC if the defender dumps the kernel callback table. RET patch is more reversible than array deletion; deletion leaves a null entry.

### DSE Bypass via gdrv.sys (BYOVD)
- **What**: Disable Driver Signature Enforcement at runtime by flipping bits in `CI!g_CiOptions` via a vulnerable signed driver, then load your unsigned kernel driver.
- **When to use**: Pre-req for kernel callback patching (and any custom driver tradecraft) on production systems where test-signing is not enabled.
- **How**:
  1. Confirm `evil.sys` is unsigned: `Get-AuthenticodeSignature C:\evil.sys` → `UnknownError`.
  2. Confirm `gdrv.sys` is signed by Gigabyte (valid cert, 2017) — `Get-AuthenticodeSignature C:\gdrv.sys` → `Valid`.
  3. Register + start the legitimate-but-vulnerable driver: `sc.exe create gigabyte type= kernel binPath= C:\gdrv.sys` → `sc.exe start gigabyte` (CVE-2018-19320 & CVE-2018-19321 → arbitrary kernel R/W from userland).
  4. Locate `g_CiOptions` via the `gCli.exe` tool: `gCli.exe -l` → prints `CI.dll` base, `Ci!CiInitialize`, `CI!g_CiOptions` (offset-based, no export).
  5. Disable signing: `gCli.exe -d` → flips the policy value in memory.
  6. Immediately: `sc.exe start evilDriver` — loads the unsigned driver.
  7. Immediately: `gCli.exe -e` → restore original `g_CiOptions`. The kernel bug-checks `g_CiOptions` against the boot policy periodically; mismatch → BSOD. Restore ASAP.
- **Vault link**: **T-018 BYOVD** — the vault formalizes this as a full module with driver catalog + SCM service + IOCTL interface. The vault covers additional drivers beyond `gdrv.sys` (e.g., RTCore64, qwwinona) and the SCM service lifecycle (T-018 `service.rs`).
- **Tool/code**: `Get-AuthenticodeSignature`, `sc.exe create/start`, `gCli.exe -l|-d|-e`, `evilCli.exe -l`. DSE policy location: `FFFFF80772D5C004 (CI!g_CiOptions)` (sample offset — recompute per-host).
- **OPSEC**: `gdrv.sys` (Gigabyte) is well-known and on most EDR blocklists. Vault's BYOVD catalog rotates through less-flagged drivers. The `g_CiOptions` flip-and-restore window is the highest-risk moment — prolonged disablement → BSOD → host-down → immediate IR response. Patched `g_CiOptions` is also a forensic IoC on memory capture.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `drvLoader.exe -i` / `-u` | Load/unload training EDR driver + start ETW trace | Lab-only; real EDR uses signed driver + persistence |
| `CFF Explorer` | Static PE / IAT inspection | Offline analysis, no footprint |
| `WinDbg` (`u`, `dps`) | Inspect in-memory IAT and API prologues | Attaches as debugger — anti-debug aware |
| `matterpreter/HookDetector` | Scan ntdll exports for inline hooks | Pure self-read, no API surface — safe pre-engagement |
| D/Invoke `Map.MapModuleToMemory` | Map fresh ntdll from disk for unhooked calls | Private mapping in random memory = IoC; D/Invoke itself uses hooked APIs to map |
| D/Invoke `Generic.GetSyscallStub` | Copy original stub to private buffer | Private RX region = memory scanner IoC; free after use via NtFreeVirtualMemory |
| D/Invoke `Generic.CallMappedDLLModuleExport` | Invoke Nt* from mapped (unhooked) module | Cleaner than GetSyscallStub but still uses hooked APIs underneath |
| `SysWhispers2` (`python3 syswhispers.py -p common -a x64 -l masm -o syscalls`) | Generate direct syscall stubs (runtime SSN scan) | Static `syscall` instruction in implant = scanner IoC |
| `InlineWhispers2` (`python3 InlineWhispers2.py`) | Post-process SysWhispers2 output for CS Artifact Kit / BOFs | Required for CS integration |
| Beacon `blockdlls start` / `blockdlls stop` | Apply Block-DLL mitigation to fork-and-run children | Visible in Process Hacker Mitigation tab |
| `UpdateProcThreadAttribute` + `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` | Apply Block-DLL programmatically | Same as above |
| `evil.exe -l -pp -dt -rp` | List / patch RET / delete / restore kernel callbacks | Needs loaded evil.sys → needs DSE bypass |
| `sc create evilDriver type= kernel binPath= ...` / `sc start evilDriver` | SCM service for unsigned driver | Fails without DSE bypass |
| `gdrv.sys` (Gigabyte, CVE-2018-19320/19321) | Vulnerable signed driver for kernel R/W | On most EDR blocklists; vault T-018 has rotating catalog |
| `gCli.exe -l -d -e` | List / disable / enable CI!g_CiOptions | BSOD if not restored quickly; match boot policy |
| `Get-AuthenticodeSignature` | Verify driver signature status | Pure read |
| DebugView (Capture → Kernel Capture) | View kernel debug messages from drivers | Passive observation only |
| Sysmon Event Viewer (EID 1 = ProcessCreate) | Validate callback blinding worked | Should see no new EID 1 events after `-pp` patch |
| j00ru's syscall table | SSN reference by Windows version | Online reference |
| `cobaltstrike/arsenal-kit/kits/artifact/build.sh` | Build CS artifacts with syscall integration | Patch `c_options` with `-masm=intel`; disable x86 builds if x64-only stubs |
| BokuLoader / KaynStrike / ElusiveMice | Public UDRLs for Cobalt Strike | Public → fingerprintable; consider forking and modifying |

## Gaps & Extensions

### What the vault covers that this training does not
- **Indirect syscalls** (T-001 RecycledGate, T-003 VEH Gate): the training's syscall techniques all execute `syscall` from implant memory; the vault dispatches from inside ntdll's `.text` via gadgets or HW-breakpoint-mediated VEH handlers — eliminates the static `0F 05` scanner IoC.
- **4-stage SSN cascade** (T-002): training stops at SysWhispers2 = Hell's Gate equivalent. The vault adds Halo's Gate (scan neighbors when target stub is hooked) and Tartarus Gate (sort by Zw* RVA when entire region is hooked) + FreshyCalls (cleaner SSN discovery). These matter against EDRs that hook broad contiguous ranges of ntdll.
- **Advanced stack spoofing & multi-frame spoofing** (T-016): training has no equivalent. Modern EDRs walk call stacks during suspicious API calls; vault spoofs return addresses back through legitimate ntdll frames.
- **AMSI/ETW patching** (T-016): training shows EDR *using* ETW for telemetry but doesn't teach muffling ETW or patching AMSI. The vault covers both, including the HBP-based AMSI bypass that survives integrity scans.
- **Arg spoofing, PEB unlink, KiUserExceptionDispatcher StepOver, handle blocking, ACG** (T-016): not in training.
- **PEB walker dynamic resolution** (T-004): training uses `GetModuleHandle` and `GetProcAddress` (both hookable). The vault walks `gs:[0x60]` → PEB → Ldr → module → EAT → DJB2 hash.
- **Phantom Stubs** (T-006): MEM_IMAGE-backed syscall stubs that look like legitimate ntdll pages to scanners. The training's GetSyscallStub produces private RX regions.
- **Sleep obfuscation** (T-005 Ekko ROP): training has no equivalent — vault encrypts the implant in-place during sleep with a 6-frame ROP chain.
- **Process injection diversity** (T-007 through T-015): training only covers `CreateRemoteThread` + Nt equivalent. Vault has 15 injection methods including Pool Party, Threadless, Ghosting, Herpaderping, Dirty Vanity, Early Cascade, NtCreateUserProcess.
- **Persistence, anti-analysis, networking, client capabilities** (T-017 through T-023): out of scope for this training module.

### What this training covers that the vault does not (or only partially)
- **IAT hooking as a concept**: the vault's T-016 IAT Camouflage covers the *inverse* (planting fake IAT entries) but doesn't document the defensive mechanism. The training's WinDbg walkthroughs of IAT swaps and inline `jmp` patches are valuable mental models.
- **HookDetector workflow** (matterpreter): the vault's T-002 Tartarus Gate uses the prologue check as a cascade trigger, but doesn't expose a standalone "scan and report all hooked APIs" tool. HookDetector is a useful recon utility in its own right.
- **D/Invoke Map.MapModuleToMemory / GetSyscallStub**: not used by the vault (superseded by RecycledGate + Phantom Stubs), but worth knowing for engagement contexts where you inherit a C# toolchain or can't introduce a Rust binary.
- **InlineWhispers2 + Artifact Kit integration**: CS-specific tradecraft not in the vault (the vault is CS-agnostic). If you operate against CS team servers, this workflow is essential.
- **UDRL kit**: Cobalt Strike specific. The vault's `dark_crystal` framework has its own loader architecture but does not interoperate with CS UDRLs. Public UDRLs (BokuLoader, KaynStrike, ElusiveMice) are operationally relevant when CS Beacon is the implant.
- **Kernel callback array internals** (`PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`): the vault's T-018 BYOVD module operates at the IOCTL/driver level; this training's `evil.exe -l/-pp/-dt/-rp` is a cleaner userland interface to the same primitives. The RET-patch (`0xC3`) vs array-deletion (`-dt`) distinction is operationally useful and not spelled out in the vault.
- **`CI!g_CiOptions` offset derivation from `CiInitialize`**: vault T-018 covers the BYOVD pipeline but the specific offset-derivation trick for the non-exported `g_CiOptions` symbol is documented here as a concrete procedure.
- **Beacon `blockdlls` command**: the vault implements Block-DLL natively (T-016), but operators using CS Beacon should know the `blockdlls start`/`stop` UX.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| EDR IAT hooking | T-004 PEB Walker | Vault defeats IAT hooks by not using IAT — dynamic PEB→Ldr→EAT resolution |
| EDR inline hooking (jmp at ntdll prologue) | T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate | All three vault techniques bypass by never entering the hooked stub |
| HookDetector prologue scan (`4C 8B D1 B8` vs `E9`) | T-002 Tartarus Gate trigger | Vault reuses the same check as cascade trigger; training exposes it as a standalone recon tool |
| Manual ntdll mapping (D/Invoke `MapModuleToMemory`) | T-016 NTDLL unhook | Vault restores `.text` in-place on existing ntdll instead of mapping a second copy — no private-mapping IoC |
| `GetSyscallStub` (private RX stub buffer) | T-001 RecycledGate, T-006 Phantom Stubs | Vault dispatches from inside ntdll (RecycledGate) or from MEM_IMAGE-backed stubs (Phantom) — both eliminate the private-RX IoC |
| SysWhispers2 runtime SSN scan | T-002 Hell's Gate (stage 1) | Training ≈ Hell's Gate alone; vault adds Halo's (neighbor scan) + Tartarus (RVA sort) + FreshyCalls |
| Direct `syscall` instruction in implant `.text` | T-001 RecycledGate (indirect) | Vault executes `syscall` from a gadget inside ntdll's `.text`, not from implant memory — defeats static `0F 05` scanning |
| `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` Block-DLL | T-016 Block-DLL | Same technique, identical flag, identical `UpdateProcThreadAttribute` plumbing |
| Beacon `blockdlls start/stop` | (none — CS UX) | Vault is CS-agnostic; vault equivalent is direct Win32 in T-016 |
| Kernel callback patching (`evil.exe -pp/-dt`) | T-018 BYOVD (callback patching utility) | Vault formalizes the BYOVD pipeline; training's `evil.exe` is a cleaner userland interface to the same primitives |
| `gdrv.sys` CVE-2018-19320/19321 kernel R/W | T-018 BYOVD driver catalog | Vault catalogues multiple vulnerable signed drivers; gdrv is one entry, often blocklisted — vault rotates |
| `CI!g_CiOptions` flip via `gCli.exe -d/-e` | T-018 BYOVD module | Vault's BYOVD service module handles DSE bypass end-to-end; training shows the manual procedure |
| InlineWhispers2 → Artifact Kit integration | (none — CS-specific) | Vault framework is CS-agnostic; CS operators must use this training workflow |
| UDRL (BokuLoader / KaynStrike / ElusiveMice) | (none — CS-specific) | Same as above — vault has its own loader (`dark_crystal`) but no CS UDRL interop |
| DSE test-signing mode | (covered conceptually in T-018) | Vault BYOVD avoids test-signing entirely (uses signed vulnerable driver instead) |