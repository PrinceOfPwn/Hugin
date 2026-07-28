---
id: RTO-defensive-telemetry-evasion
name: Defensive Telemetry & Detection Evasion
source: Red Team Ops / Zero-Point Security
category: evasion
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-016, T-020, T-022]
tags: [sysmon, etw, lolbas, wdac, malleable-c2, named-pipes, image-load, clr, dotnet, telemetry-evasion, cobalt-strike]
---

# Defensive Telemetry & Detection Evasion — Training Reference

## TL;DR
A five-note module covering the telemetry surfaces an operator must understand to operate quietly on a monitored Windows host: WDAC-bypassing LOLBAS, Sysmon network/image-load/pipe events, and ETW .NET introspection. The actionable takeaway is a set of operator-side mitigations — spawnto selection, pipe name randomization, and `EtwEventWrite` in-memory patching — that map directly to the vault's T-016 (EDR Evasion Suite) and T-022 (Network Suite / Malleable C2).

## Key Concepts

1. **LOLBAS as WDAC bypass surface.** Windows ships signed binaries (MSBuild, csc, regsvcs, etc.) that can execute arbitrary code. WDAC policies that trust Windows-signed binaries inherit this bypass surface unless the maintainer explicitly adds Microsoft's [recommended blocklist](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules). The bypass catalog lives at [bohops/UltimateWDACBypassList](https://github.com/bohops/UltimateWDACBypassList). Cross-ref **T-020** (Kaguya module provides LOtL binary inventory + EDR detection engine — enumerates the same surface from the offensive side).

2. **Sysmon EID 3 (Network connection).** Every outbound connection logs process, PID, user, src/dst IP+port, protocol, `Initiated` flag. A `sleep 0` Beacon floods these events. No "magic bypass" — OPSEC is about making the connection match the pretext of the host process (e.g., route HTTP/S beacons through a browser-process spawnto). Cross-ref **T-022** (Network Suite: malleable C2 profile, HTTP poll transport, multi-chain vault).

3. **Sysmon EID 7 (Image load / DLL load).** Loading the .NET CLR (`clr.dll`) into a native spawnto (e.g., `notepad.exe`) is a strong anomaly — native binaries rarely load the CLR. `execute-assembly` in Cobalt Strike spawns the spawnto, loads CLR, runs assembly, exits. Mitigation: set spawnto to a .NET assembly (e.g., `Microsoft.Workflow.Compiler.exe`, `vbc.exe`, etc.). Cross-ref **T-016** (EDR Evasion Suite — PE stomping, IAT camouflage touch the same surface).

4. **Sysmon EID 17/18 (Pipe creation / connection).** Cobalt Strike default pipe names: `postex_####` (post-ex fork-and-run), `postex_ssh_####` (SSH agent), `status_##` (SMB stager), `msagent_##` (SMB Beacon C2). `####` = random hex. Most Sysmon configs only log known-bad pipe names — randomizing via `set pipename` in the `post-ex` block (or `pipename_stager` / `ssh_pipename` global directives) defeats the common case. Cross-ref **T-022** (henge.rs malleable C2 profile engine; NT sockets via AFD driver in `nt_sockets.rs` for handle-pipe-free IPC).

5. **ETW .NET runtime introspection.** The `Microsoft-Windows-DotNETRuntime` ETW provider emits `AssemblyLoad`, `ModuleLoad`, and `ILStub/StubGenerated` events with the fully-qualified assembly name, PDB build path, and interop namespaces — enough to fingerprint an in-memory .NET assembly (e.g., Rubeus) without ever touching disk. SilkETW wraps consumption with YARA matching. Cross-ref **T-016** (`etw.rs` — ETW muffling; `amsi_hbp.rs` — AMSI HW breakpoint bypass which is the spiritual sibling technique).

6. **`EtwEventWrite` in-memory patch.** `advapi32!EventWrite` → `ntdll!EtwEventWrite`. Patching the first byte to `0xC3` (RET) at the ntdll export kills ETW emission process-wide. Procedure mirrors the AMSI patch (VirtualProtect → write `RET` → restore). On x86 you must fix the stack first. Cross-ref **T-016** (`etw.rs` — vault's canonical ETW muffling implementation).

7. **`COMPlus_ETWEnabled=0` env var.** Quick-and-dirty process-wide ETW kill for any .NET assembly launched from a shell. Set the variable before launching the EXE. No code, no patch — but obviously visible in process environment block. Cross-ref **T-016** (vault has more surgical alternatives: in-memory patch, HW breakpoints on `EtwEventWrite`).

8. **Malleable C2 spawnto / pipename directives.** `post-ex { set pipename "x, y_##"; }` accepts a comma-separated list with `#` for hex randomization. `pipename_stager` and `ssh_pipename` are global. Spawnto selection is the single highest-leverage knob for image-load OPSEC. Cross-ref **T-022** (henge.rs is the vault's malleable profile engine; T-016 PE stomping/arg spoofing also affects spawnto behavior).

## Operational Techniques

### LOLBAS Enumeration for WDAC Bypass

- **What**: Identify a Windows-signed native binary capable of arbitrary code execution that is missing from the target's WDAC policy blocklist.
- **When to use**: Initial access / execution on a WDAC-enforced host where unsigned or third-party binaries are blocked.
- **How**:
  1. Enumerate the WDAC policy in effect (e.g., via `CiTool.exe -lp` or by reading the binary policy on disk).
  2. Cross-reference the policy's `<FileRules>` against the Microsoft recommended blocklist and the [Ultimate WDAC Bypass List](https://github.com/bohops/UltimateWDACBypassList).
  3. For each candidate (MSBuild, csc/vbc, regsvcs/regasm, mshta, wscript/cscript, Microsoft.Workflow.Compiler, MSExchangeSyncAppPool, etc.) confirm it isn't denied by `FileName` + `MinimumFileVersion="65535.65535.65535.65535"`.
  4. Attempt invocation — e.g., `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe /?`. A "Device Guard" block message confirms the rule is in effect; success means the rule is missing.
  5. Stage a payload in the LOLBAS-supported format (MSBuild inline task, csc source file, regsvcs-aligned .NET assembly with `RegSERVICES` registration, etc.).
- **Vault link**: **T-020** (Kaguya LOtL binary inventory + EDR detection). Kaguya automates discovery; this training emphasizes the manual policy-arbitration path. The vault extends this by also enumerating EDR presence — useful when choosing which LOLBAS to invoke.
- **Tool/code**: `CiTool.exe -lp` (Win11 22H2+); `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`; manual binary policy parse.
- **OPSEC**: LOLBAS execution is loud on Sysmon (process creation, image load, network if the LOLBAS fetches a remote resource). Pick a LOLBAS whose telemetry blends with the host (build server → MSBuild; dev workstation → csc/vbc).

### Spawnto Selection for .NET CLR Image-Load OPSEC

- **What**: Configure the C2's spawnto to a .NET assembly so that `execute-assembly`-style CLR loads look native.
- **When to use**: Any engagement where the defender runs Sysmon EID 7 with CLR-load rules (very common in mature SOCs).
- **How**:
  1. Identify .NET assemblies present on every supported Windows build: `Microsoft.Workflow.Compiler.exe`, `vbc.exe`, `csc.exe`, `PresentationFontCache.exe`, `mscorcfg.msc`-launched hosts, etc.
  2. Set spawnto in the C2 config (Cobalt Strike: `spawnto_x64` / `spawnto_x86` Malleable C2 process block).
  3. Validate by running `execute-assembly` and observing (or having a defender buddy observe) that `clr.dll` load no longer stands out.
- **Vault link**: **T-016** (vault covers IAT camouflage and PE stomping — complementary, deeper techniques). The vault does not need to enumerate spawnto candidates because it solves the problem differently (in-process assembly execution via custom loader), but the tradecraft is identical in spirit.
- **Tool/code**: Cobalt Strike Malleable C2 `spawnto_x64` / `spawnto_x86`; for custom loaders, see T-013 module overloading / phantom stubs (T-006).
- **OPSEC**: Ensure ppid and spawnto match a coherent pretext. A `vbc.exe` running under `services.exe` is anomalous; under an interactive `devenv.exe` parent it's normal.

### Named Pipe Randomization

- **What**: Override Cobalt Strike's default pipe names (`postex_####`, `msagent_##`, `status_##`, `postex_ssh_####`) with custom/randomized names.
- **When to use**: Always — default names are on every public Sysmon config.
- **How**:
  1. Edit the Malleable C2 profile `post-ex` block:
     ```
     post-ex {
         set pipename "totally_not_beacon, legitPipe_##";
     }
     ```
  2. For global directives: `set pipename_stager` and `set ssh_pipename` outside any block.
  3. Use `#` for hex randomization; comma-separated lists rotate names per-use.
  4. Optionally mask as legitimate app pipes (e.g., Chrome's `mojo` pipes) — but **only** if ppid + spawnto match the same pretext.
- **Vault link**: **T-022** (henge.rs malleable C2 profile engine). The vault's runtime supports profile-driven pipe naming the same way. The vault additionally offers `nt_sockets.rs` (AFD driver IPC) as a pipe-free alternative.
- **Tool/code**: Malleable C2 `set pipename` directive in `post-ex`; global `pipename_stager` / `ssh_pipename`.
- **OPSEC**: A pipe named `\mojo_1234` created by `notepad.exe` under `explorer.exe` is more anomalous than the default `msagent_##` — naming consistency with spawnto is mandatory.

### `EtwEventWrite` In-Memory Patch (Process-Wide)

- **What**: Patch the prologue of `ntdll!EtwEventWrite` with `0xC3` (RET) so the function returns immediately without emitting any ETW event.
- **When to use**: Just before loading/executing a .NET assembly in-memory (Rubeus, SharpHound, Seatbelt, etc.) where the in-memory loader controls the host process.
- **How**:
  1. `LoadLibrary("ntdll.dll")` to ensure it's mapped (it always is).
  2. `GetProcAddress(hModule, "EtwEventWrite")` — or use D/Invoke `Generic.GetLibraryAddress()` to avoid `GetProcAddress` IAT fingerprinting.
  3. `VirtualProtect(addr, 1, PAGE_READWRITE=0x04, &old)`.
  4. Write `byte[]{ 0xC3 }` at the function start (x64). For x86 use `0xC2 0x14 0x00` (`ret 0x14`) to fix the 5-arg stack.
  5. `VirtualProtect(addr, 1, old, &_)` to restore.
- **Vault link**: **T-016** (`etw.rs` — vault's canonical ETW muffling, identical procedure). Vault adds a hardened variant using HW breakpoints (see `amsi_hbp.rs` pattern applied to ETW) which avoids the RWX-write signature. **Use the HWBP variant when VirtualProtect-based patching is itself detected.**
- **Tool/code**: Boilerplate C# snippet provided in the notes (LoadLibrary / GetProcAddress / VirtualProtect / Marshal.Copy); D/Invoke `Generic.GetLibraryAddress()`.
- **OPSEC**: VirtualProtect on ntdll .text is itself a detection signal (memory permission change on a known module). Prefer HWBP variant when available. Patched `EtwEventWrite` produces a uniform "no events" gap that defenders correlating across providers can spot — pair with selective event fakes if you need a fuller stealth profile.

### `COMPlus_ETWEnabled=0` Quick ETW Kill

- **What**: Setting the environment variable `COMPlus_ETWEnabled=0` disables .NET runtime ETW emission for any process inheriting the variable.
- **When to use**: Ad-hoc execution of a .NET binary from a shell where you control the environment but not the binary's source.
- **How**: `set COMPlus_ETWEnabled=0` (cmd) or `$env:COMPlus_ETWEnabled=0` (PowerShell) before launching the EXE.
- **Vault link**: **T-016**. Vault does not document this trick explicitly — operators should treat it as a fallback when in-memory patching isn't feasible. It is significantly noisier in process-environment telemetry than the patch.
- **Tool/code**: Native shell `set` / PowerShell `$env:`.
- **OPSEC**: Visible in `PROCESS_ENVIRONMENT` collection (Sysmon doesn't natively capture env vars by default, but EDRs like Elastic Endpoint and CrowdStrike Falcon do). Trivial to detect via YARA/Sigma rule: `COMPlus_ETWEnabled` string in process env block.

### SilkETW Detection Testing (Red-Team Validation)

- **What**: Use SilkETW + YARA to validate that a .NET assembly-in-memory is (or is not) detectable.
- **When to use**: During tradecraft development / before fielding a new in-memory tool.
- **How**:
  1. Launch SilkETW collector: `SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\path\etw.json -f EventName -fv Loader/AssemblyLoad -y C:\YARA -yo Matches`
  2. Execute the in-memory assembly.
  3. Review JSON for: `FullyQualifiedAssemblyName`, `ManagedPdbBuildPath`, `ILStub/StubGenerated` namespace strings.
  4. Author YARA rules matching your tool's identity strings:
     ```
     rule Rubeus_FullyQualifiedAssemblyName {
         strings: $fqan = "Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" ascii nocase wide
         condition: $fqan
     }
     rule Rubeus_ProgramDatabase {
         strings: $pdb = "Rubeus.pdb" ascii nocase wide
         condition: $pdb
     }
     rule Rubeus_Interop {
         strings:
             $tic = "Rubeus.Interop/TOKEN_INFORMATION_CLASS" ascii nocase wide
             $lsa = "Rubeus.Interop/LSA_STRING" ascii nocase wide
         condition: any of them
     }
     ```
  5. Iterate on the loader / patch / obfuscation until no YARA rule fires.
- **Vault link**: **T-020** (Diagnostic test harness — vault has a built-in `diagnostic.rs` for technique verification; this is the operator-side equivalent for ETW). **T-016** (`etw.rs` patches the provider so no events fire — the validation target of this exercise).
- **Tool/code**: `SilkETW.exe` flags: `-t user` (user-mode trace), `-pn` (provider name), `-uk` (keyword mask; `0x2038` = default .NET runtime keywords), `-ot file`, `-p` (output path), `-f EventName -fv Loader/AssemblyLoad` (filter), `-y` (YARA dir), `-yo Matches` (output mode).
- **OPSEC**: This is a defensive-side tool — running SilkETW on target during an engagement is itself anomalous (you'd only run it on your own tradecraft-validation host).

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `MSBuild.exe` (lolbas) | Inline-task C# execution; primary WDAC bypass candidate | On MS recommended blocklist; many orgs forget to add the rule |
| `CiTool.exe -lp` | Enumerate live WDAC policy (Win11 22H2+) | Read-only; safe on target |
| [Microsoft Recommended Block Rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules) | Defender-side reference for LOLBAS blocklist | Use to identify what *should* be blocked |
| [UltimateWDACBypassList (bohops)](https://github.com/bohops/UltimateWDACBypassList) | Curated WDAC bypass techniques per LOLBAS | Public catalog — defenders also read it |
| `Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` | Confirm WDAC enforcement + policy options | WMI query; visible in ETW WMI provider |
| Sysmon EID 3 | Network connection telemetry | Pick spawnto that legitimately makes outbound connections (e.g., browser) |
| Sysmon EID 7 | Image (DLL) load telemetry | `clr.dll` load into native spawnto is the classic tell |
| Sysmon EID 17 / 18 | Pipe creation / connection | Default CS pipe names are universally flagged |
| `SilkETW.exe` | ETW consumer with YARA matching | Run on tradecraft-validation host, not on target |
| `Microsoft-Windows-DotNETRuntime` provider | .NET runtime introspection (AssemblyLoad / ModuleLoad / ILStub) | Keyword mask `0x2038` covers default events |
| `advapi32!EventWrite` / `ntdll!EtwEventWrite` | ETW emission API — patch target | `0xC3` (x64) / `0xC2 0x14 0x00` (x86) RET prologue |
| `COMPlus_ETWEnabled=0` | Process-wide .NET ETW disable (env var) | Visible in PEB env; worse OPSEC than patching |
| D/Invoke `Generic.GetLibraryAddress()` | Resolve API w/o `GetProcAddress` IAT entry | Use to keep `GetProcAddress(ntdll, "EtwEventWrite")` off the IAT |
| `post-ex { set pipename "x, y_##"; }` | Override default CS pipe names in post-ex | Use `#` for hex randomization; list rotates per use |
| `pipename_stager`, `ssh_pipename` (global MC2 directives) | Override SMB stager / SSH agent pipe names | Global, outside any block |
| `spawnto_x64`, `spawnto_x86` (MC2 directives) | Set spawnto for fork-and-run | Must be a .NET assembly to mask CLR loads |

## Gaps & Extensions

**Training covers that the vault does not (or covers lightly):**
- The explicit operator intuition for **spawnto selection** (which .NET assemblies are safe defaults on every Windows build) — the vault solves this architecturally (in-process loaders) rather than by spawnto camouflage.
- The `COMPlus_ETWEnabled=0` environment-variable trick — vault T-016 prefers in-memory patching and HWBP; this is a useful fallback for ad-hoc execution.
- The defensive-side workflow (SilkETW + YARA iteration) — the vault's diagnostic harness (`diagnostic.rs` in `dark_crystal/crowd`) is operator-side; this complements it as a pre-fielding validation methodology.
- The MS Recommended Blocklist and `UltimateWDACBypassList` references — operator-curated external catalogs not present in the vault.

**Vault covers that the training does not:**
- **AMSI bypass via HW breakpoints** (T-016 `amsi_hbp.rs`) and **PAGE_GUARD-based AMSI bypass** (`amsi_page_guard.rs`) — strictly more advanced than the in-memory RET patch taught here.
- **Advanced multi-frame stack spoofing** (T-016 `advanced_stack.rs`) — training has nothing on stack-spoofing the post-ex fork-and-run child.
- **NTDLL unhooking via suspended process** (T-016 `ntdll_unhook.rs`) — full .text restoration from a clean ntdll, not just RET patches on single APIs.
- **NT sockets via AFD driver** (T-022 `nt_sockets.rs`) — pipe-free IPC that sidesteps EID 17/18 entirely; training only addresses pipe renaming.
- **Malleable C2 profile engine** (T-022 `henge.rs`) — vault generalizes the Cobalt Strike-specific `post-ex { set pipename }` directive into a runtime profile system.
- **PEB unlink, arg spoofing, proxy DLL, block-DLL, ACG, KiUserException StepOver** (T-016) — none of these are covered in this training batch.
- **Anti-VM suite (10 checks)** and **API hammering (3M FPU/SIMD)** (T-020) — out of scope for this batch.
- **Kaguya LOtL inventory + EDR detection** (T-020) — automates what this training teaches as a manual exercise.

**Specifically outdated in the training:**
- The `EtwEventWrite` RET-patch technique is correct but **sub-optimal vs. HWBP bypass** in T-016. VirtualProtect-on-ntdll-.text is itself a Sysmon EID 10 (ProcessAccess) signal in hardened configs. Use the patch for tradecraft simplicity; use HWBP for engagement-grade OPSEC.
- The MS Recommended Blocklist URL is correct as of writing but Microsoft has reorganized this doc; current canonical path is under `Windows Security / Threat protection / Application & control`.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| LOLBAS enumeration for WDAC bypass | T-020 (Kaguya LOtL inventory + EDR detection) | Vault automates discovery; training provides the manual policy-arbitration procedure |
| Sysmon EID 3 network connection telemetry | T-022 (Network Suite: HTTP poll, multi-chain vault, peer relay) | Vault provides transport-layer alternatives that change the EID 3 footprint (e.g., NT sockets via AFD) |
| Sysmon EID 7 .NET CLR load anomaly | T-016 (IAT camouflage, PE stomping) | Vault solves differently — in-process loaders avoid spawnto CLR load entirely |
| Cobalt Strike default pipe names (`postex_####`, `msagent_##`, etc.) | T-022 (malleable C2 profile engine `henge.rs`) | Vault generalizes the MC2 `set pipename` directive into a runtime profile system |
| Pipe randomization via `set pipename` | T-022 (henge.rs); T-022 `nt_sockets.rs` | Vault also offers pipe-free IPC via AFD driver — eliminates EID 17/18 surface entirely |
| `Microsoft-Windows-DotNETRuntime` ETW introspection | T-016 (`etw.rs` — ETW muffling) | Vault's patch is the same technique (`EtwEventWrite` RET); training provides the defensive validation workflow |
| `EtwEventWrite` in-memory RET patch | T-016 (`etw.rs`) | Identical technique; vault adds HWBP-hardened variant (`amsi_hbp.rs` pattern) |
| `COMPlus_ETWEnabled=0` env var | T-016 (ETW muffling — vault prefers in-memory patch) | Vault does not document this fallback; add to operator runbook as ad-hoc option only |
| SilkETW + YARA validation workflow | T-020 (Diagnostic test harness `diagnostic.rs`) | Different toolchains, same goal: pre-fielding technique verification |
| Spawnto selection for image-load OPSEC | T-016 (PE stomping, IAT camouflage), T-006 (Phantom Stubs) | Vault bypasses the spawnto problem by in-process execution; training addresses it via Malleable C2 directives |
| D/Invoke `Generic.GetLibraryAddress()` for API resolution | T-004 (PEB Walker — `gs:[0x60]` manual resolution) | Vault's PEB walker is the lower-level primitive; D/Invoke builds on the same concept |