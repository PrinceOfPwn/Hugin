---
id: T-127
name: PowerShell Constrained Language Mode Detection and Bypass
category: edr-evasion
tier: A
crate: none
source_file: none
mitre: T1059.001
mitre_secondary: [T1562.001]
tags: [powershell-clm, language-mode, wdac, applocker, device-guard, ci-policy, runspace, com-bypass, edr-evasion]
origin: atlas-synthesis
member_notes: ['lgtm:clm-detection-and-bypass-coverage']
---

# PowerShell Constrained Language Mode Detection and Bypass — Recognizing and Escaping WDAC/AppLocker-Enforced Confinement

## Summary

PowerShell Constrained Language Mode (CLM) is a runtime restriction enforced by the PowerShell engine itself when its host policy probe (`SystemPolicy.GetSystemLockdownPolicy` in `System.Management.Automation.Security`) reports that a Code Integrity / Device Guard / AppLocker policy is in enforce mode. Unlike `Get-ExecutionPolicy` — which only governs whether scripts may launch — CLM governs *what a running script can do*: it disables `Add-Type` (no dynamic compilation), blocks arbitrary .NET type instantiation via `New-Object` on non-whitelisted types, blocks PSSnapin loading, and forces the script compiler to route method binding through a strict type-conversion path that throws on non-whitelisted invocations. Detection is a one-liner: `$ExecutionContext.SessionState.LanguageMode` returns the string `ConstrainedLanguage` under lockdown, `FullLanguage` otherwise. A secondary probe — `[Math]::Pow(2,10)` — succeeds in FullLanguage and throws `MethodInvocationException` in ConstrainedLanguage because the dynamic-binding path is intercepted. CLM triggers at host startup when one of three conditions is true: (a) a WDAC/CIG policy binary is loaded by the kernel Code Integrity component (`CI.dll`) and visible via `Win32_DeviceGuard`; (b) AppLocker (`AppIDSvc`) is in Enforce mode and the policy contains an EXE rule set covering the PowerShell image path; (c) a Device Guard UMCI policy is active. CLM is entirely distinct from `Set-ExecutionPolicy` semantics — `powershell -ExecutionPolicy Bypass` does nothing to lift CLM, because the lockdown decision is read from `HKLM\System\CurrentControlSet\Control\CI\Config` and the AppLocker policy cache, not from the ExecutionPolicy hive at `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`. Four bypass surfaces are operationally viable: (1) disabling the triggering WDAC policy via the `HKLM\System\CurrentControlSet\Control\CI\Policy` hive (requires SYSTEM + reboot or CI service restart); (2) running inside a process that is not on the AppLocker EXE rule path — a custom Runspace hosted in a non-PowerShell .exe bypasses the AppLocker trigger but not WDAC UMCI; (3) instantiating COM objects through default-installer hosts (e.g. `InstallUtil.exe`, `mmc20.application`, or the IE Execute host) that load .NET and construct a Runspace with `PSLanguageMode.FullLanguage` before the SystemPolicy probe runs; (4) LOLBIN-abusing WDAC-signed binaries that the policy permits to load arbitrary .NET assemblies. The vault's T-016 card documents hook-based AMSI/EDR evasion, but does not cover language-mode confinement; T-023 covers in-memory AMSI bypass, which composes with CLM bypass as the second wall of post-exploitation telemetry defeat.

## Mechanism

### Variant 1: Detection Primitives

1. Probe the LanguageMode property directly:
   ```powershell
   $ExecutionContext.SessionState.LanguageMode
   # "FullLanguage"        -> unconstrained
   # "ConstrainedLanguage" -> CLM is in effect
   # "RestrictedLanguage"  -> (rare) very strict mode
   ```
   `$ExecutionContext` is a built-in variable bound to the `EngineIntrinsics` instance; its `SessionState` property exposes a `SessionState` object whose `LanguageMode` member is an enum of type `System.Management.Automation.LanguageMode`. `ConstrainedLanguage = 2` is the lockdown state.

2. Secondary type-binding probe:
   ```powershell
   try { [Math]::Pow(2,10) } catch { "CLM detected: $($_.Exception.Message)" }
   ```
   Under CLM the binding path that converts integer literals to `double` arguments for the method invocation is intercepted by the host's type-coercion logic. The error is unmistakable: "Binding an unknown method is disallowed in ConstrainedLanguage mode" (a `MethodInvocationException`). In modern builds where `System.Math` is whitelisted, this probe may be replaced by `Add-Type` (throws "Compilation of a type is not supported in ConstrainedLanguage mode") or `[System.Diagnostics.Process]::Start("notepad")` (throws "Cannot invoke method. Method invocation is supported only in FullLanguage mode").

3. Distinguish CLM from ExecutionPolicy (the common misidentification):
   ```powershell
   Get-ExecutionPolicy                                # RemoteSigned, Bypass, AllSigned, Unrestricted
   $ExecutionContext.SessionState.LanguageMode        # the actual language mode
   ```
   A target can have `Bypass` ExecutionPolicy and still be in CLM — this is the default under any WDAC/Device Guard deployment. Treating ExecutionPolicy as the security boundary leads operators to waste a step on `-ExecutionPolicy Bypass` when CLM is the actual blocker.

4. Probe for AppLocker specifically (not WDAC):
   ```powershell
   Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
   ```
   This returns the merged AppLocker XML if `AppIDSvc` is running and a policy is published. Absence of XML here means the trigger is WDAC, not AppLocker.

5. Probe WDAC policy presence:
   ```powershell
   Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
     Select-Object SecurityServicesConfigured, SecurityServicesRunning,
                   CodeIntegrityPolicyEnforcementStatus, VirtualizationBasedSecurityStatus
   ```
   `SecurityServicesConfigured` is a bitmask: bit 0 = CredentialGuard, bit 1 = HypervisorEnforcedCodeIntegrity (HVCI), bit 2 = UMCI. `SecurityServicesRunning` is the same bitmask for what is actually active in the kernel. `CodeIntegrityPolicyEnforcementStatus`: 0 = Off, 1 = Audit, 2 = Enforced. CLM tracks the latter — Audit mode does not trigger CLM.

6. Read the CI registry hive directly to determine the lockdown state without invoking PowerShell's policy probe:
   ```powershell
   Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CI\Config" |
     Select-Object VulnerableDriverBlocklistEnable, VerifyOnLoad
   Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CI\Policy" |
     Select-Object VerifiedAndAudit, VerifiedAndAllowed
   ```
   The presence of `VerifiedAndAllowed = 1` on the policy key indicates the CI policy is loaded and active in Enforce mode. `VerifiedAndAudit = 1` with `VerifiedAndAllowed = 0` indicates Audit-mode WDAC, which does NOT trigger CLM.

### Variant 2: WDAC Policy Disable (Requires SYSTEM + Reboot)

7. Take ownership of the WDAC policy registry path. The subkey `HKLM\System\CurrentControlSet\Control\CI\Policy` is owned by `SYSTEM` and protected by an SACL that denies write to Administrators. Enable `SeTakeOwnershipPrivilege` (LUID `0x1E`) and `SeRestorePrivilege` (LUID `0x1D`), then call `RtlAdjustPrivilege` to enable them in the calling token. Open the key with `RegOpenKeyEx` + `WRITE_OWNER`, then `RegSetKeySecurity` to set the owner SID to the caller.

8. Set the unload flag on the active policy:
   ```
   HKLM\System\CurrentControlSet\Control\CI\Policy\VerifiedAndAllowed = 0
   HKLM\System\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable = 0
   ```
   Setting `VerifiedAndAllowed = 0` marks the policy as inactive in the registry mirror, but does not unload it from the kernel until the Code Integrity component re-reads on next boot. The CI service (`cexecsvc.dll` hosted in `services.exe`) cannot be cleanly restarted via SCM while WDAC is enforcing, because `services.exe` is itself protected by the policy.

9. Delete the persisted policy binary:
   ```powershell
   Remove-Item -Force "$env:SystemRoot\System32\CodeIntegrity\*.cip"
   Remove-Item -Force "$env:SystemRoot\System32\CodeIntegrity\Sipolicy.p7b"
   ```
   The `.cip` file is the new-format binary policy (WDAC, multi-policy format); `Sipolicy.p7b` is the legacy single-policy p7b format. Both can be present; remove both. Rebooting after deletion ensures no policy is loaded at boot by `CiInitialize`.

10. Confirm post-reboot:
    ```powershell
    $ExecutionContext.SessionState.LanguageMode   # should now be FullLanguage
    ```
    This bypass requires SYSTEM and a reboot, which limits its operational utility — but for a long-haul persistence host, the cost is acceptable.

### Variant 3: Custom Runspace Host (AppLocker-Only Environments)

11. Build a .NET assembly (C# or F#) that hosts PowerShell and constructs a Runspace explicitly with FullLanguage:
    ```csharp
    var iss = InitialSessionState.CreateDefault();
    iss.LanguageMode = PSLanguageMode.FullLanguage;
    var rs = RunspaceFactory.CreateRunspace(iss);
    rs.Open();
    using (var ps = PowerShell.Create())
    {
        ps.Runspace = rs;
        ps.AddScript("[Math]::Pow(2,10)").Invoke();
    }
    ```
    `PSLanguageMode.FullLanguage = 0`. The override in the `InitialSessionState` is honored by the host — but only if the *process* hosting the Runspace is not itself subject to a WDAC UMCI policy.

12. Critical distinction: **AppLocker CLM triggers on the PowerShell binary path** (`powershell.exe`, `pwsh.exe`). A custom host process (`MyLoader.exe`) that is not on the AppLocker EXE rule list is not subject to AppLocker CLM, because PowerShell's `SystemPolicy` probe consults the AppLocker (AppId) policy cache only for processes whose image path matches an EXE rule. A custom host that links `System.Management.Automation.dll` directly bypasses the AppLocker-only CLM trigger entirely.

13. WDAC is binary-agnostic. If UMCI is in Enforce mode, the host process itself must be signed by a signer in the WDAC signer rule set — and the language-mode lockdown is propagated to any `System.Management.Automation` instance loaded into a WDAC-protected process. A custom host process not signed by a WDAC-trusted signer will fail to even start with `STATUS_INVALID_IMAGE_HASH = 0xC0000428`. Variant 3 is therefore operationally useful in **AppLocker-only** environments, or in WDAC environments where a Microsoft-signed LOLBIN (`InstallUtil.exe`, `MSBuild.exe`, `regasm.exe`, `AppInstaller.exe`) is on the default signer allow list and can be coerced into loading the host assembly.

14. Embed the host binary via a LOLBIN if needed: `InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll` invokes the `Uninstall` method on the assembly's `System.Configuration.Install.Installer`-derived type — within that method, construct the Runspace with FullLanguage and execute arbitrary PowerShell. `InstallUtil.exe` is signed by Microsoft and is typically on the WDAC allow list by default.

### Variant 4: COM Default-Installer Host Pattern

15. The COM pattern exploits the fact that several Microsoft-signed COM hosts launch out-of-process servers that are not on the AppLocker EXE rule path and that load .NET in a context where SystemPolicy has not yet probed:
    - `mmc20.application` — the Microsoft Management Console COM class. The `Document.ActiveView.ExecuteShellCommand` method accepts an executable path and arguments; calling it from a non-CLM context (cscript.exe, which is itself AppLocker-allowed) launches a child process outside the constrained path.
    - `InternetExplorer.Application` — historically hosted script that could invoke `IHostSupportsRestrictedError` and similar interfaces; patched in modern builds but illustrative of the pattern.
    - `WindowsInstaller.Installer` — the MSI COM class; custom-action JScript/VBScript embedded in an MSI runs in `msiexec.exe`, which is AppLocker-allowed and not subject to CLM.

16. The key insight: **CLM is enforced by the host's policy probe, not by the kernel**. Any code path that bypasses the host's `SystemPolicy.GetSystemLockdownPolicy()` initialization is a viable bypass. COM hosts that launch as out-of-process servers in `SysWOW64` or `System32` and that have not been image-path-restricted by AppLocker provide such a path.

17. The COM pattern was substantially closed by Microsoft in late 2017 cumulative updates that added a check in `SystemPolicy` ensuring that any COM host that loads `System.Management.Automation.dll` triggers the same probe. The pattern remains useful in legacy environments and against AppLocker-only deployments that do not include the COM hosts in their EXE rule set.

## OS Internals Context

PowerShell's language mode is decided once per runspace at creation time and is read on every script-binding operation by the script compiler. The decision tree is anchored in `SystemPolicy.GetSystemLockdownPolicy()` (the static method in `System.Management.Automation.Security.SystemPolicy`), which consults three sources: WDAC policy state, AppLocker policy state, and a cached bit in `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`. The WDAC path queries the `Win32_DeviceGuard` WMI class, which reads from the `Microsoft.Windows.DeviceGuard` registry hive and the live CI kernel state. The AppLocker path queries the AppId service (`AppIDSvc`) for the active EXE rule set; if AppLocker is in Audit mode, CLM is *not* triggered (only Enforce triggers CLM). The result is cached in a static field for the lifetime of the process — changing the policy does not change the language mode of an already-running PowerShell process. A reboot or process restart is required to re-probe.

Once `GetSystemLockdownPolicy` returns `SystemEnforcementMode.Enforce`, the host sets the runscape's `SessionState.LanguageMode = ConstrainedLanguage`. The script compiler reads this on every binding operation. When CLM is active, the compiler's binding path routes through the constrained converter, which adds a type-compatibility check that throws on any non-whitelisted method invocation. The whitelist is a hard-coded set in the `System.Management.Automation.Language.CompilerServices` namespace — core BCL types (`System.Math`, `System.String`, `System.IO.FileInfo`) are present, but the dynamic-invoke surface (`System.Reflection`, `System.Runtime.InteropServices.Marshal`, `System.Diagnostics.Process.Start`) is not. The `[Math]::Pow(2,10)` probe throws because the integer-to-`double` argument coercion path for a non-whitelisted invocation is intercepted; the canonical `$ExecutionContext.SessionState.LanguageMode` probe reads the property directly and is the most reliable indicator.

The kernel side of the WDAC trigger: the Code Integrity component (`CI.dll` loaded by `ntoskrnl.exe`) reads the active policy from the boot-time `g_CIPolicy` global. The policy binary is loaded from `%SystemRoot%\System32\CodeIntegrity\Sipolicy.cip` (new multi-policy format) or `Sipolicy.p7b` (legacy single-policy format) at boot by `CiInitialize`. The policy is parsed into a `CIPolicy` structure, and the rules are evaluated by `CiValidateImageHeader` for each image load via `MiLoadImageSection`. The `CiSystemFlags` global contains bits for audit mode (bit 0) and enforce mode (bit 1). When `CiSystemFlags & 0x2` is set, every image load is checked against the policy; unsigned or non-compliant images are rejected with `STATUS_INVALID_IMAGE_HASH = 0xC0000428` (the same status returned when the image's signing certificate hashes to a value not in the policy's allow list). The PowerShell host reads this state via `Win32_DeviceGuard` (the user-mode WMI bridge to the kernel state) and sets CLM accordingly.

AppLocker, by contrast, is purely a user-mode service. `AppIDSvc` (the Application Identity service) hosts the policy evaluator in `appid.dll`. When a process is created, the SCM (Service Control Manager in `services.exe`) calls into AppLocker via `SaferIdentifyLevel` and `SaferRecordEventLog` to determine whether the binary path matches an EXE rule. The result is cached in the AppLocker cache (managed by the AppLocker RPC interface). PowerShell's `SystemPolicy` probe consults this cache; if the calling process's image path is matched by a Deny or Allow rule, AppLocker is considered "active" and CLM is set. The CLM trigger here is process-binary-path-based, which is why Variant 3 (custom host) bypasses it — the custom host's image path is not on the AppLocker EXE rule list, so the cache lookup returns "no policy match" and the AppLocker arm of the probe returns `Audit` (effectively inactive).

The registry hive `HKLM\System\CurrentControlSet\Control\CI\Policy` is the live policy state mirror. The `VerifiedAndAllowed` value is `REG_DWORD`, set by CI during boot to indicate the policy was loaded and verified against the binary's signature. The corresponding file on disk (`Sipolicy.cip`) contains the actual rule binary; the registry hive is a state mirror that user-mode code reads to determine the kernel's current enforcement posture. Setting `VerifiedAndAllowed = 0` does not unload the policy from the kernel — the policy is held in `ntoskrnl.exe` memory until next boot — but it changes what the *next* process's `SystemPolicy` probe reads, because that probe reads the registry state, not the kernel state. This is the source of the reboot requirement in Variant 2.

The custom-Runspace path (Variant 3) bypasses the AppLocker CLM trigger because the AppLocker trigger is path-based: `SystemPolicy.GetAppLockerPolicy` calls into the AppId RPC interface with the calling process's `ImagePath` (read from `PEB.ProcessParameters.ImagePathName`). A custom host process at `C:\Tools\MyLoader.exe` is not on the AppLocker EXE rule list (which typically only restricts `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `C:\Program Files\PowerShell\7\pwsh.exe`). The host then loads `System.Management.Automation.dll`, and constructs a Runspace with `LanguageMode = FullLanguage`. The PowerShell engine honors this because, at the engine level, `LanguageMode` is a property of `SessionStateInternal` that is honored by the script compiler unless the `SystemPolicy` probe has overridden it. The override path only fires on the AppLocker-triggered process.

The `PEB.ProcessParameters.ImagePathName` field (at offset `0x20` in `RTL_USER_PROCESS_PARAMETERS` on x64, accessible via `PEB.ProcessParameters` at `PEB+0x20` where `PEB` is at `TEB+0x60` for the current thread) is what AppLocker consults to determine the rule set. This is also why WOW64 boundary matters: 32-bit PowerShell on a 64-bit Windows host is subject to CLM under the same triggers. The CI kernel component polices both 32-bit and 64-bit image loads; the AppLocker service evaluates both `SysWOW64` and native `System32` paths. There is no "32-bit gets a free pass" behavior.

The `Win32_DeviceGuard` WMI class fields deserve careful reading: `SecurityServicesConfigured` is "what the firmware/registry has set as available"; `SecurityServicesRunning` is "what is actually active in the kernel." CLM tracks the latter. A common diagnostic error is to read `SecurityServicesConfigured` and conclude CLM is active, when in fact `SecurityServicesRunning` shows the service is not actually running (e.g., HVCI requires VBS to be running, which requires firmware and hypervisor cooperation). Always cross-reference both fields with the `LanguageMode` property.

## Key Implementation Details

Privileges required vary by variant. Variant 2 requires `SeTakeOwnershipPrivilege` (LUID `0x1E`) and `SeRestorePrivilege` (LUID `0x1D`) to take ownership of `HKLM\System\CurrentControlSet\Control\CI\Policy` — a right that, by default, is held only by `SYSTEM`. An elevated Administrator token has the take-ownership privilege enabled in the token's `Privileges` array (the `LUID_AND_ATTRIBUTES` array in the `TOKEN` structure), but must explicitly take ownership of the key (the default owner is `NT SERVICE\cexecsvc` or `SYSTEM`) before writing. Variant 3 requires no special privileges if the custom host is signed (for WDAC) or simply absent from AppLocker's rule list; if the host is unsigned and WDAC is in Enforce mode, the host cannot load — Variant 3 is therefore limited to AppLocker-only or no-WDAC environments, unless paired with a Microsoft-signed LOLBIN loader.

The most common operational pitfall is conflating `Get-ExecutionPolicy` with `Get-SystemLockdownPolicy`. An operator runs `Get-ExecutionPolicy`, sees `RemoteSigned`, concludes "PowerShell is locked down," then attempts to bypass with `-ExecutionPolicy Bypass`, re-runs the payload, and finds it still fails — because CLM was the actual blocker. The diagnostic one-liner is always `$ExecutionContext.SessionState.LanguageMode` first.

The `Get-CimInstance Win32_DeviceGuard` WMI class has surprising behavior under WOW64: a 32-bit PowerShell process querying this class receives the result through the WOW64 fast-path, and the `SecurityServicesRunning` bitmask can report services that are *configured* but not *running* — always cross-reference `SecurityServicesRunning` vs `SecurityServicesConfigured`. The `CodeIntegrityPolicyEnforcementStatus` field is the canonical CLM predictor: `2` = Enforced, `1` = Audit, `0` = Off. Only status `2` triggers CLM.

Session 0 considerations: a service running in Session 0 under `NT AUTHORITY\SYSTEM` is still subject to WDAC and AppLocker. There is no "session 0 bypass" for CLM. The host's `SystemPolicy` probe runs regardless of session, because it consults kernel and registry state that is session-agnostic.

The `[Math]::Pow(2,10)` probe can return false negatives in modern builds where `System.Math` is on the type whitelist — in those builds, use `Add-Type` (which always throws under CLM with "Compilation of a type is not supported in ConstrainedLanguage mode") or `[System.Diagnostics.Process]::Start("notepad.exe")` (which throws with "Method invocation is supported only in FullLanguage mode"). The `$ExecutionContext.SessionState.LanguageMode` property is canonical and reliable across all builds.

## Why It Matters

CLM is the most common reason a payload that "works in dev" fails on a hardened target. The detection primitive is a single line, but distinguishing CLM from ExecutionPolicy is a 60-second diagnostic that determines whether the operator needs a bypass or simply a flag. In a typical enterprise, 30–60% of endpoints run some form of WDAC or AppLocker; the assumption "PowerShell is locked" should default to "CLM is in effect until proven otherwise."

The bypass variant choice depends entirely on which trigger is active. AppLocker-only environments are trivially defeated by Variant 3 (custom Runspace host or LOLBIN-hosted Runspace); WDAC environments require either Variant 2 (policy disable, high-cost, requires reboot) or a WDAC-signed LOLBIN that loads a .NET assembly which the policy permits to host a Runspace. In engagements where the operator cannot reboot the target, Variant 2 is off the table, and the engagement reduces to finding a Microsoft-signed binary that loads arbitrary .NET (`InstallUtil`, `MSBuild`, `regasm`, or `AppInstaller`). The vault's T-016 card documents the hook-based AMSI/EDR bypass that composes downstream of this technique; the vault's T-023 documents the AMSI bypass that, combined with a CLM bypass, defeats the two principal post-exploitation telemetry surfaces on Windows. Without a CLM bypass, even an AMSI-bypassed payload cannot invoke `Add-Type` or instantiate the .NET types that post-exploitation tooling depends on.

## Detection Considerations

- **Telemetry sources**: The `Microsoft-Windows-PowerShell` ETW provider (GUID `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`) emits `EventID 4104` (ScriptBlock) on script execution and `EventID 4103` (Pipeline Execution) on module/cmdlet invocation. When CLM is active, the `4104` event carries the literal text the operator executed, including the diagnostic probe `$ExecutionContext.SessionState.LanguageMode` — the presence of this string in a `4104` event is itself a high-signal indicator of reconnaissance. The `Microsoft-Windows-CodeIntegrity/Operational` event channel emits `EventID 3076` (Audit-mode block) and `3077` (Enforce-mode block) on every image load that violates WDAC; a sudden drop in `3077` events after the operator disables the policy is itself an indicator. AppLocker emits to the `Microsoft-Windows-AppLocker/EXE and DLL` event log under `EventID 8002` (Allowed), `8004` (Denied), `8007` (Audit-mode denial).

- **Bypass options**: Variant 2 (registry disable) is detectable as a write to `HKLM\System\CurrentControlSet\Control\CI\Policy` — monitor with Sysmon `EventID 13` (RegistryValueSet) on `TargetObject` matching `*\Control\CI\Policy\*` or `*\Control\CI\Config\*`. Variant 3 (custom Runspace) is detectable as a non-PowerShell process loading `System.Management.Automation.dll` — Sysmon `EventID 7` (ImageLoaded) with `ImageLoaded` matching `*System.Management.Automation.dll` and `Image` not matching `powershell.exe|pwsh.exe` is a high-signal indicator. ETW `Microsoft-Windows-DotNETRuntime` (GUID `{e18c9e3f-7caf-4d3f-8c0e-cb7a4d1c8c4f}`) emits assembly load events that catch the same indicator. Variant 4 (COM host) is detectable via Sysmon `EventID 1` (ProcessCreate) showing `mmc.exe`, `msiexec.exe`, or `iexplore.exe` spawning PowerShell child processes, or `cscript.exe`/`wscript.exe` invoking COM objects — this pattern is anomalous in most enterprise baselines.

- **Residual artifacts**: After Variant 2, the registry values `VerifiedAndAllowed=0` and the absent `Sipolicy.cip` file are persistent forensic artifacts; the `Microsoft-Windows-CodeIntegrity/Operational` log will show a single `EventID 3099` (Policy Changed) at the next boot. After Variant 3, the custom host binary remains on disk (unless loaded reflectively from memory); the AppLocker log will show `EventID 8002` for the custom host's image path. The `Microsoft-Windows-Sysmon/Operational` log `EventID 7` will record the `System.Management.Automation.dll` load. After Variant 4, a `Microsoft-Windows-Application-Experience/Program-Telemetry` event will show the COM instantiation. In all variants, the post-bypass `FullLanguage` mode persists only for the lifetime of the host process — restarting PowerShell re-evaluates the lockdown and CLM returns.

## Variant Comparison Table

| Variant | Trigger Defeated | Privilege Required | Persistence | Reboot Required | Detection Surface |
|---------|-----------------|--------------------|-------------|-----------------|-------------------|
| Detection Only | N/A | None | N/A | No | ScriptBlock 4104 contains the probe string |
| V2: Policy Disable | WDAC | SYSTEM + TakeOwnership | Until restored | Yes | Registry write, CI Policy 3099, file deletion |
| V3: Custom Runspace | AppLocker (only) | None (if signed host) | None (per-process) | No | SMA.dll load by non-PS process (Sysmon 7) |
| V4: COM Default Installer | AppLocker (legacy) | None | None (per-process) | No | mmc.exe/msiexec.exe spawning child, COM instantiation |

## Composition with Other Techniques

A realistic post-exploitation kill chain on a hardened target composes this card with T-016 (hook-based AMSI/EDR bypass) and T-023 (AMSI bypass):

1. Initial access executes an in-memory PowerShell loader. CLM triggers (`SystemPolicy` reports Enforce). The operator's payload fails — `Add-Type` throws, `New-Object` for .NET types throws.
2. Operator runs the detection one-liner: `$ExecutionContext.SessionState.LanguageMode` → `ConstrainedLanguage`.
3. Operator queries `Get-CimInstance Win32_DeviceGuard` to identify the trigger: `SecurityServicesRunning = @{2}` (UMCI bit set) → WDAC, not AppLocker.
4. Variant 2 is ruled out (no reboot available, target is a production server). The operator pivots to finding a WDAC-signed LOLBIN that loads .NET: `InstallUtil.exe` is signed by Microsoft and is typically on the default signer allow list.
5. Operator stages the payload as a .NET assembly (`payload.dll`) with an `Installer`-derived type whose `Uninstall` method constructs a `Runspace` with `LanguageMode = FullLanguage` (Variant 3, executed via `InstallUtil.exe /U payload.dll`).
6. Inside the InstallUtil-hosted code, the operator constructs the Runspace and executes arbitrary PowerShell. InstallUtil is the host process, not PowerShell; CLM does not trigger for InstallUtil because InstallUtil does not invoke `SystemPolicy.GetSystemLockdownPolicy()`.
7. The payload still needs to defeat AMSI (the second telemetry surface) — compose with T-023 (AMSI bypass via `amsi.dll!AmsiScanBuffer` patching in the host process) before invoking `IEX` or `Invoke-Mimikatz`. AMSI is independent of CLM and still scans script blocks even in FullLanguage.
8. Compose with T-016 (hook-based EDR evasion) to defeat the EDR's user-mode hooks on `NtCreateThreadEx`, `VirtualProtectEx`, `NtAllocateVirtualMemory` before reflective DLL loading.

End state: arbitrary PowerShell execution under FullLanguage, AMSI bypassed, EDR hooks bypassed, with only the residual artifact of `InstallUtil.exe` loading a custom `payload.dll` — detectable by Sysmon `EventID 7` but indistinguishable from a legitimate installer invocation without signature analysis of the loaded DLL.

## Common Mistakes

1. **Conflating ExecutionPolicy with CLM**: Running `powershell -ExecutionPolicy Bypass` when CLM is the active restriction does nothing. The two settings live in different registry hives (`HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy` vs `HKLM\System\CurrentControlSet\Control\CI\Policy`) and are enforced by different code paths. Always diagnose with `$ExecutionContext.SessionState.LanguageMode` first.

2. **Forgetting that Audit-mode WDAC does not trigger CLM**: An operator probes `Win32_DeviceGuard` and sees `CodeIntegrityPolicyEnforcementStatus = 1` (Audit), assumes CLM is in effect, and searches for a bypass — but the `LanguageMode` probe returns `FullLanguage` because CLM is only set under Enforce (status 2). Always cross-reference `SecurityServicesRunning` with `LanguageMode` directly.

3. **Setting the CI registry keys but not rebooting**: Variant 2 writes `VerifiedAndAllowed=0` and expects CLM to lift immediately. It does not — the `SystemPolicy` probe reads the cached state for already-running processes; only new processes (after CI re-reads on next boot) get the new state. Without a reboot, the bypass silently fails and the operator concludes "the technique doesn't work" when in fact they skipped the propagation step.

4. **Spawning a custom Runspace host that is itself unsigned**: Variant 3 in a WDAC environment fails at the loader — the host process is rejected by CI with `STATUS_INVALID_IMAGE_HASH = 0xC0000428` before any .NET code runs. Variant 3 is operationally limited to AppLocker-only environments, or to WDAC environments where a Microsoft-signed LOLBIN is used as the host loader. Forgetting this distinction burns the engagement and may trigger a `Microsoft-Windows-CodeIntegrity/Operational` `EventID 3077`.

5. **Using `[Math]::Pow(2,10)` as the sole detection primitive**: While reliable in many configurations, modern builds where `System.Math` is on the type whitelist may not throw on this probe. The canonical probe is `$ExecutionContext.SessionState.LanguageMode`; use `Add-Type` as the secondary (always throws under CLM). Using only `[Math]::Pow` can produce false negatives that lead the operator to conclude CLM is not active when it is.

6. **Forgetting that AppLocker Audit mode does not trigger CLM**: AppLocker audit-mode rules are unblocking by design; the operator wastes time probing for AppLocker CLM when the AppLocker event log shows `8002` (Allowed) on every execution — meaning AppLocker is in Audit mode and is not the CLM trigger. The CLM trigger is then WDAC, and the bypass surface shifts from Variant 3 to Variant 2 or Variant 4.

## Related Techniques

- **T-016 Hook-Based AMSI/EDR Evasion** — composes downstream: once CLM is bypassed via Variant 3 and a FullLanguage runspace is established, the host process still needs hook-based evasion to defeat the EDR's user-mode inline hooks on `NtCreateThreadEx`, `VirtualProtectEx`, and the like, before reflective DLL loading or thread injection.
- **T-023 AMSI Bypass** — composes directly: CLM bypass produces a FullLanguage runspace, but the script-block content is still scanned by AMSI via `amsi.dll!AmsiScanBuffer`; T-023 patches the function to return `S_OK` without scanning, defeating the second telemetry wall.
- **T1059.001 (MITRE PowerShell)** — the parent technique that this card refines; this card is the operational response when the parent technique is blocked by CLM confinement rather than by ExecutionPolicy.
- **T1562.001 (MITRE Disable or Modify Tools)** — Variant 2 (registry disable of WDAC policy via `HKLM\System\CurrentControlSet\Control\CI\Policy`) is a direct instance of this MITRE technique; the policy disable is a tool-modification action against the Code Integrity subsystem.