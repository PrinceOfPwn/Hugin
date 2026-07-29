<!-- BEGIN CARD T-115 -->
---
id: T-115
name: SilentProcessExit Registry Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.012
tags: [persistence, silent-process-exit, registry, ifeo, globalflag, process-termination, event-driven]
origin: atlas-synthesis
member_notes: [lgtm:silent-process-exit-persistence, lgtm:ifeo-persistence-coverage-gap]
---

# SilentProcessExit Registry Persistence — Process-Termination-Triggered Execution

## Summary

SilentProcessExit is a registry-driven persistence mechanism that triggers configurable follow-up actions when a monitored process terminates. It exploits the Windows Error Reporting (WER) infrastructure's silent process exit monitoring feature, originally designed to capture diagnostic data when processes exit unexpectedly. An operator configures the GlobalFlag value under the Image File Execution Options (IFEO) registry key for a target binary to enable silent process exit monitoring, then sets the ReportingMode and MonitorProcess values under the SilentProcessExit registry key to specify that a follow-up process should launch when the target exits. The primary detection surface is registry writes to the IFEO and SilentProcessExit key trees, which are monitored by Sysmon and EDR rules.

## Mechanism

1. Identify a target binary that the victim process will execute and terminate normally — common choices include notepad.exe, svchost.exe, or any legitimate binary that runs transiently.
2. Open `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target_binary>` and set the `GlobalFlag` value (REG_DWORD) to `0x200` (`FLG_MONITOR_SILENT_PROCESS_EXIT`). This flag enables the silent process exit monitoring infrastructure for the specified binary.
3. Create the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target_binary>`.
4. Under the SilentProcessExit\<target_binary> key, set `ReportingMode` (REG_DWORD) to `0x1` (`LAUNCH_MONITOR_PROCESS`). Other valid values include `0x2` (`SET_EVENT`) and `0x4` (`CREATE_DUMP`), and these can be combined via bitwise OR.
5. Under the same key, set `MonitorProcess` (REG_SZ) to the full path of the payload to execute — for example, `C:\Users\Public\payload.exe` or a PowerShell one-liner wrapper.
6. When the target binary runs and subsequently exits, the Windows Error Reporting service detects the termination, reads the SilentProcessExit registry configuration, and launches the MonitorProcess executable.
7. The launched process inherits the security context of the process that triggered the monitoring — if the target binary ran as SYSTEM (e.g., a service-hosted binary), the payload executes at SYSTEM integrity.

## OS Internals Context

The SilentProcessExit mechanism is part of the Windows Error Reporting (WER) infrastructure, implemented in werkernel.dll and dispatched through the kernel's process exit notification path. When a process exits, the kernel raises a process exit notification via `PsSetCreateProcessNotifyRoutine`. If the exiting process has the `FLG_MONITOR_SILENT_PROCESS_EXIT` flag (0x200) set in its IFEO GlobalFlag value, the WER infrastructure reads the corresponding SilentProcessExit registry key and performs the configured actions.

The `GlobalFlag` value is a 32-bit bitmask stored under `IFEO\<binary>\GlobalFlag`. The flag `FLG_MONITOR_SILENT_PROCESS_EXIT` (0x200) is distinct from `FLG_APPLICATION_PAGE_HEAP` (0x40000) and the IFEO `Debugger` value (which triggers on process launch). When this flag is set, the kernel's process exit path calls into the silent process exit monitoring code, which reads configuration from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<binary>`.

The `ReportingMode` bitmask determines the action: bit 0 (0x1) launches the `MonitorProcess` value as a new process, bit 1 (0x2) signals an event, and bit 2 (0x4) creates a minidump. The `MonitorProcess` value is a REG_SZ containing the command line to execute.

This mechanism is paired with the IFEO Debugger value, which triggers on process launch rather than exit. The `Debugger` value under `IFEO\<binary>\Debugger` causes the system to launch the specified debugger instead of the target binary. Together, the Debugger value (launch trigger) and SilentProcessExit (exit trigger) provide complementary coverage — an operator can execute on both process start and process termination.

The IFEO GlobalFlag value is read by the kernel during process creation (`NtCreateUserProcess` → `PspAllocateProcess` → `PspSetupUserProcessImage`), while the SilentProcessExit configuration is read during process termination. This means the GlobalFlag must be set before the target process starts — setting it after the process is already running does not trigger monitoring for that instance.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would write the three registry values (`GlobalFlag`, `ReportingMode`, `MonitorProcess`) using `RegCreateKeyExW`/`RegSetValueExW` or the NT registry APIs (`NtCreateKey`/`NtSetValueKey`). The `edo_tensei.rs` module in dark_crystal/crowd/src/ demonstrates registry-based soul storage using `RegCreateKeyExW`/`RegSetValueExW` under `HKCU\Software\Classes\CLSID\{...}\Config`, which could serve as a code pattern for the SilentProcessExit registry writes under HKLM. The implementation would need to handle the HKLM elevation requirement — either running from a high-integrity context or using SeTakeOwnershipPrivilege to modify the IFEO keys.

## Why It Matters

SilentProcessExit fills the event-driven persistence gap that T-017's five-layer suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not cover. While scheduled tasks trigger on time and COM hijacks trigger on CLSID activation, SilentProcessExit triggers on process termination — a different trigger surface. This is operationally complementary to IFEO Debugger persistence (which triggers on launch), and the shared GlobalFlag enablement makes the two variants naturally paired for launch-and-exit coverage. SEC670 Lab 4.3 (IFEOPersisto) documents both variants as a single lab exercise, reflecting their operational coupling.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 (Registry Value Set) captures writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*` and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\GlobalFlag`. Sysmon Event ID 12 (RegistryEvent Object) captures key creation. EDR products with registry monitoring rules alert on writes to the SilentProcessExit key tree.
- **Bypass options**: Using NT registry APIs (`NtCreateKey`/`NtSetValueKey`) instead of the Win32 `Reg*` APIs avoids the user-mode RPC path that some EDRs hook. Writing the values from a SYSTEM-integrity process avoids UAC elevation prompts for HKLM writes.
- **Residual artifacts**: The three registry values persist until manually removed. The launched `MonitorProcess` binary creates a new process with a parent of the silent process exit monitor service (typically WerFault.exe or a WER-related svchost instance), which is an anomalous parent-child relationship that process lineage monitoring can detect.

## Related Techniques

- **T-017 Five-Layer Persistence** — SilentProcessExit fills the event-driven termination trigger gap not covered by the five persistence layers in T-017's suite.

## References

- Atlas material: atlas-post-exploit-part13.md, atlas-post-exploit-part17.md
- MITRE ATT&CK: T1546.012 (https://attack.mitre.org/techniques/T1546/012)
- LGTM notes: lgtm:silent-process-exit-persistence, lgtm:ifeo-persistence-coverage-gap
- Public references: SEC670 Lab 4.3 IFEOPersisto

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-115 -->

<!-- BEGIN CARD T-116 -->
---
id: T-116
name: UAC Bypass Discovery Methodology and Tradecraft
category: privesc
tier: A
crate: none
source_file: none
mitre: T1548.002
tags: [uac, uac-bypass, autoelevate, fusion, uacme, process-monitor, discovery-methodology, com-hijack]
origin: atlas-synthesis
member_notes: [lgtm:gap-uac-bypass-research-methodology, lgtm:cross-source-convergence-uac-tradecraft, lgtm:uac-bypass-research-methodology-convergence]
---

# UAC Bypass Discovery Methodology and Tradecraft — Systematic autoElevate Binary Analysis

## Summary

UAC bypass discovery is a systematic methodology for identifying new privilege escalation paths through User Account Control by analyzing auto-elevate manifests in System32 binaries, observing COM handler interactions via Process Monitor, and weaponizing attacker-controllable COM registry paths. The methodology moves beyond using known bypass IDs from the UACMe project (hfire_f0x) to finding novel bypasses when existing techniques are detected or patched. The primary detection surface is the COM registry writes under `HKCU\Software\Classes\CLSID\` that redirect InprocServer32 or LocalServer32 values to attacker-controlled DLLs, plus the execution of auto-elevated binaries that trigger the weaponized COM handlers.

## Mechanism

1. Enumerate all executables in `C:\Windows\System32\` and related directories (SysWOW64). For each binary, extract the embedded PE manifest resource.
2. Manifest extraction uses either mt.exe (`mt -inputresource:<binary> -out:<manifest.xml>`) or direct PE resource parsing: locate the `RT_MANIFEST` resource (type 24) in the binary's resource section via `FindResource`/`LoadResource`, then read the XML content.
3. Parse the manifest XML for the `autoElevate` attribute set to `true` in the `windowsSettings` node: `<autoElevate xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</autoElevate>`. This attribute instructs the Windows UAC subsystem to auto-elevate the binary without a consent prompt when launched by an administrator in split-token mode.
4. For each auto-elevate binary identified, run it under Process Monitor (ProcMon) with a filter capturing registry reads/writes and file accesses. Capture COM class registrations that the binary queries — specifically CLSID lookups under `HKCU\Software\Classes\CLSID\` and `HKCR\CLSID\`.
5. Identify COM CLSIDs that the binary resolves from HKCU (user-writable) rather than HKLM (admin-only). The Fusion subsystem (Windows SxS COM activation) checks `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` before `HKLM\Software\Classes\CLSID\{GUID}\InprocServer32`.
6. Write a malicious DLL path to `HKCU\Software\Classes\CLSID\{target_GUID}\InprocServer32\(Default)`, set the `ThreadingModel` value to `Apartment` or `Both` to match the expected threading model.
7. Launch the auto-elevate binary. When the binary calls `CoCreateInstance` for the hijacked CLSID, the Fusion subsystem finds the HKCU registration first, loads the attacker DLL, and executes it in the context of the auto-elevated process — which runs at High integrity with the elevated token.
8. The payload DLL's `DllMain` or a COM interface method executes at elevated integrity, achieving privilege escalation without a UAC consent prompt.

## OS Internals Context

UAC auto-elevation is governed by the application compatibility and Fusion (Side-by-Side assembly) subsystem. When an executable's manifest declares `autoElevate="true"` and the launching user is a member of the Administrators group running with a filtered (split) token, the Windows loader (`AiLaunchProcess` → `AiCheckExeForUac`) detects the auto-elevate attribute and performs a silent elevation: the process is launched with the full (unfiltered) token at High integrity level, without displaying the Secure Desktop consent prompt.

The Fusion COM activation path checks registry locations in a specific order. For InprocServer32 (in-process DLL servers), the lookup order is: `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` first (if present), then `HKLM\Software\Classes\CLSID\{GUID}\InprocServer32`. Because HKCU is writable by standard users, an attacker can shadow a HKLM-registered COM class by writing a competing HKCU entry. When the auto-elevated binary calls `CoCreateInstance` for that CLSID, the COM resolver finds the HKCU entry first and loads the attacker's DLL instead of the legitimate one.

The UACMe project (hfire_f0x) indexes 80+ numbered bypass techniques, each corresponding to a specific auto-elevate binary and COM CLSID combination. Examples include: Method 33 (`computerdefaults.exe` + `{0b29f25f-3fbc-4d9c-a5c0-0e4a0e8b6c0a}`), Method 41 (`sdclt.exe` + `{A0BB6A0B-8C84-4048-BE98-E0B1D4DBCA04}`), Method 56 (`fodhelper.exe` + `{0fcb1fdb-2e2e-41d1-9d2a-ee3e063e4ab4}`), and Method 63 (`eventvwr.exe` + `{015410C5-5681-4707-9D62-28D696CF5F2F}`).

The elevation prompt color coding serves as a trust indicator: blue/yellow prompts indicate a signed Microsoft binary requesting elevation (auto-elevate or consent), while orange/red prompts indicate unsigned or non-Microsoft binaries. Auto-elevated binaries produce no prompt at all — the elevation is silent.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the discovery methodology. The HUGIN source tree contains UAC bypass implementations (`client_rust/src/uac_cmstp.rs` for CMSTP bypass, `dark_crystal/crates/core/src/escalation/uac.rs` for slui.exe registry bypass), but these implement specific bypass instances rather than the discovery methodology. An implementation of the discovery pipeline would enumerate System32 binaries via `FindFirstFile`/`FindNextFile`, parse PE resource sections for `RT_MANIFEST` (type 24), extract and parse the manifest XML for the `autoElevate` attribute, and present identified auto-elevate binaries as targets for COM hijack weaponization.

## Why It Matters

T-021 and T-023 document the CMSTP UAC bypass as a finished technique — one bypass instance out of 80+ in the UACMe corpus. SEC670's Lab 3.7 documents the broader discovery methodology that produces new bypasses. When existing bypasses are detected by EDR or patched by Microsoft updates, operators need the methodology to identify new auto-elevate binaries and COM shadow opportunities. The methodology represents the difference between using a technique and finding one: the vault's CMSTP bypass is one output of this process, but the process itself was not previously documented. The convergence of SEC670 with the vault's existing implementations on the same autoElevate + Fusion + UACMe mental model indicates strong tradecraft consensus across SANS, the source corpus, and the broader red-team community.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 (Registry Value Set) captures writes to `HKCU\Software\Classes\CLSID\*\InprocServer32\(Default)`. Sysmon Event ID 7 (Image Load) captures DLL loads into auto-elevated processes. EDR products monitor for COM registry shadowing patterns. Process Monitor itself, if running on the target system, generates significant I/O telemetry that can indicate reconnaissance activity.
- **Bypass options**: Using the NT registry APIs (`NtCreateKey`/`NtSetValueKey`) for the HKCU CLSID writes avoids the Win32 `Reg*` API surface. Registering the COM class well before triggering the auto-elevate binary separates the registry write from the elevation event temporally. Using a legitimate-looking DLL name and path blends with normal COM registrations.
- **Residual artifacts**: The `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` registry entry persists until manually removed. The loaded DLL appears in the auto-elevated process's loaded module list. The auto-elevated binary runs at High integrity, which is visible in process token enumeration.

## Related Techniques

- **T-021 Crypto & Obfuscation** — Documents the CMSTP UAC bypass as a specific instance of the methodology documented here.
- **T-023 Client Capabilities** — Documents the CMSTP UAC bypass in the client_rust crate as another instance.

## References

- Atlas material: atlas-privesc-part1.md, atlas-privesc-part2.md, atlas-privesc-part3.md
- MITRE ATT&CK: T1548.002 (https://attack.mitre.org/techniques/T1548/002)
- LGTM notes: lgtm:gap-uac-bypass-research-methodology, lgtm:cross-source-convergence-uac-tradecraft, lgtm:uac-bypass-research-methodology-convergence
- Public references: UACMe project (hfire_f0x), SEC670 Lab 3.7, Process Monitor (Sysinternals)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. The HUGIN source contains specific bypass instances (client_rust/src/uac_cmstp.rs, dark_crystal/crates/core/src/escalation/uac.rs) but not the discovery methodology pipeline.
<!-- END CARD T-116 -->

<!-- BEGIN CARD T-117 -->
---
id: T-117
name: Windows Privilege Escalation Primitives Admin to SYSTEM
category: privesc
tier: A
crate: none
source_file: none
mitre: T1134
tags: [privesc, admin-to-system, se-debug, se-load-driver, se-take-ownership, se-create-token, token-manipulation, privilege-abuse]
origin: atlas-synthesis
member_notes: [lgtm:cross-source-convergence-admin-to-system-privilege-set, lgtm:coverage-gap-windows-privesc-primitives]
---

# Windows Privilege Escalation Primitives (Admin to SYSTEM) — Canonical Five-Privilege Escalation Set

## Summary

Windows privilege escalation from local administrator to SYSTEM leverages five canonical privilege primitives documented across SEC670, MalDev Academy, and CRTO. Each privilege — SeTakeOwnership, SeTcb, SeCreateToken, SeLoadDriver, and SeDebug — provides a distinct escalation path from administrator to SYSTEM or kernel context. The prerequisite for several paths is programmatic enablement of these privileges via the standard token adjustment API sequence (LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges). The primary detection surface is process handle acquisition on SYSTEM processes (OpenProcess with PROCESS_ALL_ACCESS) and token duplication operations (DuplicateTokenEx).

## Mechanism

1. Enable the target privilege programmatically. Call `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)` to obtain the current process token. Call `LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)` to resolve the LUID for the privilege. Construct a `TOKEN_PRIVILEGES` structure with `PrivilegeCount=1`, `Luid=luid`, `Attributes=SE_PRIVILEGE_ENABLED`. Call `AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)` to enable it. This sequence works for SeDebug, SeTakeOwnership, SeLoadDriver, and other privileges present in the admin token.

2. SeDebugPrivilege path: Call `OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)` on a SYSTEM process (`winlogon.exe`, `lsass.exe`, or a SYSTEM-service-hosted process). With SeDebug enabled, the access check succeeds regardless of the caller's integrity relative to the target. Call `OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hSystemToken)`. Call `DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)`. Call `CreateProcessWithTokenW(hDupToken, 0, NULL, cmdline, ..., &si, &pi)` to spawn a process at SYSTEM integrity.

3. SeTakeOwnershipPrivilege path: Identify a SYSTEM-owned service binary or service configuration path. Call `SetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &admin_sid, NULL, NULL, NULL)` to take ownership of the target file or registry key. Then write a DACL granting full control, replace the binary with a payload, and restart the service via SCM (`StartService` or `ControlService` with `SERVICE_CONTROL_CONTINUE`). The service starts the payload as SYSTEM.

4. SeTcbPrivilege path: Open a SYSTEM process via `ZwOpenProcess`. Call `NtCreateThreadEx(threadHandle, ..., hSystemProcess, startRoutine, arg, ...)` to create a thread inside the SYSTEM process address space. The thread executes the payload code in the context of the SYSTEM process. SeTcb grants the ability to operate on any process's address space — historically named for "Terminal Server Base" but functionally representing trusted computing base privileges.

5. SeCreateTokenPrivilege path: Call `NtCreateToken(...)` with a `TOKEN_USER` structure specifying the SYSTEM SID (`S-1-5-18`) in the `User` field. This produces a primary token that claims SYSTEM identity. Use `CreateProcessWithTokenW` or `ImpersonateLoggedOnUser` with the fabricated token. This is the most direct path — no target process handle is required.

6. SeLoadDriverPrivilege path: Write the driver's image path to `HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath` (REG_EXPAND_SZ). Call `NtLoadDriver` to load the driver. The driver runs in kernel context and can call `PsSetCreateProcessNotifyRoutineEx` to register process creation callbacks, or directly manipulate `EPROCESS` structures for token theft. This is the BYOVD (Bring Your Own Vulnerable Driver) escalation path.

## OS Internals Context

Windows privileges are stored in the token's `PRIVILEGE_SET` structure, which is an array of `LUID_AND_ATTRIBUTES` entries. The LUID (Locally Unique Identifier) maps to a specific privilege, and the `Attributes` field contains `SE_PRIVILEGE_ENABLED` (0x2) or `SE_PRIVILEGE_DISABLED` (0x0). The kernel's `SeAccessCheck` function consults these during access validation.

SeDebugPrivilege bypasses the standard security descriptor check: when the caller's token has SeDebug enabled, `SeAccessCheck` grants `PROCESS_ALL_ACCESS` regardless of the DACL on the target process. This is implemented in `SepAccessCheck` via a special case for `SeDebugPrivilege`. The privilege is present in administrator tokens by default but disabled — `AdjustTokenPrivileges` must enable it before use.

SeTakeOwnershipPrivilege grants `WRITE_OWNER` access to any securable object, bypassing the DACL. `SetSecurityInfo` with `OWNER_SECURITY_INFORMATION` changes the owner SID in the object's security descriptor. Once owner, the caller can write a new DACL granting full control.

SeCreateTokenPrivilege grants the broadest capability set of any Windows privilege. `NtCreateToken` is an undocumented NT API (not in ntdll.dll export table) that constructs a token object from caller-supplied data. The `TOKEN_USER` structure's `User.Sid` field specifies the identity the token claims. By supplying the SYSTEM SID (`S-1-5-18`), the resulting token authenticates as SYSTEM. The kernel does not validate that the caller is actually SYSTEM — it trusts the `SeCreateTokenPrivilege` as sufficient authorization for token creation.

SeTcbPrivilege is present only in SYSTEM tokens. It grants the ability to create threads in other processes (`NtCreateThreadEx`), attach to other process address spaces (`NtMapViewOfSection` cross-process), and perform other operations requiring the trusted computing base attribute. On modern Windows, SeTcb is only present in SYSTEM tokens, making it available only after escalation to SYSTEM via another path — it functions more as a SYSTEM-to-SYSTEM persistence mechanism than an admin-to-SYSTEM escalation primitive.

The standard privilege adjustment sequence (`LookupPrivilegeValue` → `OpenProcessToken` → `AdjustTokenPrivileges`) operates entirely in user mode. `AdjustTokenPrivileges` calls `NtAdjustPrivilegesToken`, which updates the token's privilege flags in kernel space. The change is per-token and persists until the token is closed or the privileges are adjusted again.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the privilege escalation primitives as foundational knowledge. The HUGIN source tree contains related implementations: BYOVD (`dark_crystal/crowd/src/byovd.rs`, `dark_crystal/crates/core/src/experimental/evasion/byovd/`) for the SeLoadDriver path, and process injection techniques (`dark_crystal/crowd/src/early_bird.rs`, `process_hollow.rs`) that use SeDebug to open SYSTEM processes. An implementation of the SeDebug → `DuplicateTokenEx` → `CreateProcessWithTokenW` chain would use the `windows-sys` or `winapi` crate bindings for `OpenProcess`, `OpenProcessToken`, `DuplicateTokenEx`, and `CreateProcessWithTokenW`, with the privilege adjustment sequence in a helper function.

## Why It Matters

The vault documents LSASS credential harvest (T-023) and BYOVD (T-022) as standalone capabilities, but neither card documents the prerequisite privilege enablement. An operator attempting T-023's LSASS dump via `MiniDumpWriteDump` cannot open the `lsass.exe` handle without first enabling SeDebugPrivilege. T-022's BYOVD path requires SeLoadDriverPrivilege to call `NtLoadDriver`. This card surfaces the five canonical escalation paths as cross-cutting prerequisites that connect the vault's higher-level techniques to the foundational privilege manipulation that makes them operationally viable. The convergence of SEC670, MalDev Academy, and CRTO on the same five-privilege set indicates strong tradecraft consensus that this is the canonical answer to admin-to-SYSTEM escalation.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 4656 (A handle to an object was requested) captures `OpenProcess` calls on SYSTEM processes when object access auditing is enabled. Sysmon Event ID 4608 (Special Privileges) logs when SeDebug, SeTcb, or SeCreateToken are enabled. EDR products monitor `AdjustTokenPrivileges` calls that enable SeDebug or SeTakeOwnership. Kernel callbacks (`ObRegisterCallbacks` for process handle pre-operation) intercept `OpenProcess` on protected processes.
- **Bypass options**: Direct NT API calls (`NtOpenProcess`, `NtOpenProcessToken`, `NtDuplicateToken`, `NtCreateProcessEx`) bypass user-mode hooks on the Win32 API equivalents. Indirect syscalls (T-001 RecycledGate) bypass ntdll hooks on the NT APIs. Token duplication from a process that already holds the SYSTEM token (e.g., a service host) avoids the `OpenProcess` + `OpenProcessToken` sequence.
- **Residual artifacts**: The spawned SYSTEM process appears in the process list with a SYSTEM security context. The parent process is the escalator (`CreateProcessWithTokenW` caller), creating an anomalous parent-child relationship. The privilege adjustment on the caller's token is visible via `NtQueryInformationToken(TokenPrivileges)`. Registry writes for SeLoadDriver path create entries under `HKLM\SYSTEM\CurrentControlSet\Services\`.

## Related Techniques

- **T-013 Remaining Methods** — Documents process hollowing and injection techniques that require SeDebugPrivilege for handle acquisition on SYSTEM processes.
- **T-022 Network Suite** — Contains the BYOVD module that relies on SeLoadDriverPrivilege for driver loading.
- **T-016 EDR Evasion Suite** — Documents argument spoofing and stack spoofing techniques applicable to the privilege adjustment API sequence.
- **T-023 Client Capabilities** — LSASS dump capability requires SeDebugPrivilege enablement as a prerequisite.
- **T-021 Crypto & Obfuscation** — UAC bypass achieves admin-to-High; this card covers the subsequent High-to-SYSTEM escalation.

## References

- Atlas material: atlas-privesc-part1.md, atlas-privesc-part2.md
- MITRE ATT&CK: T1134 (https://attack.mitre.org/techniques/T1134)
- LGTM notes: lgtm:cross-source-convergence-admin-to-system-privilege-set, lgtm:coverage-gap-windows-privesc-primitives
- Public references: SEC670 privilege escalation module, MalDev Academy, CRTO

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Related implementations exist in the HUGIN source tree (dark_crystal/crowd/src/byovd.rs for SeLoadDriver, dark_crystal/crowd/src/early_bird.rs for SeDebug-based process access).
<!-- END CARD T-117 -->

<!-- BEGIN CARD T-118 -->
---
id: T-118
name: GUI Syscall Path via win32u and win32k
category: syscalls
tier: A
crate: none
source_file: none
mitre: T1106
tags: [syscalls, win32u, win32k, gui-syscall-path, edr-hooking, thread-initialization, w32thread]
origin: atlas-synthesis
member_notes: [lgtm:win32u-gui-syscall-hook-coverage, lgtm:gui-vs-native-syscall-path-awareness]
---

# GUI Syscall Path via win32u.dll and win32k.sys — Dual Syscall Surface and Thread Type Enforcement

## Summary

Windows splits the syscall routing architecture into two distinct paths: native syscalls dispatched through ntdll.dll into the executive (ntoskrnl.exe), and GUI syscalls dispatched through win32u.dll into the kernel's windowing subsystem (win32k.sys). EDR products hook both ntdll.dll and win32u.dll to capture the full syscall surface, but the vault's T-016 NTDLL unhook documentation only addresses the native path. GUI functions such as `NtUserOpenClipboard`, `NtUserFindWindowEx`, and `NtUserMessageCall` are routed through win32u.dll, so an operator who unhooks only ntdll remains visible to EDR for all windowing, clipboard, and input-related operations. Additionally, the calling thread must be GUI-initialized — a thread without an associated W32THREAD structure will be rejected by win32k.sys when issuing GUI syscalls.

## Mechanism

1. The Windows syscall surface is partitioned into two dispatch paths. Native syscalls (`NtCreateFile`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, etc.) are exported by ntdll.dll and transition to the executive via the `syscall` instruction, entering ntoskrnl.exe through `KiSystemServiceTable`.

2. GUI syscalls (`NtUserOpenClipboard`, `NtUserFindWindowEx`, `NtUserGetMessage`, `NtUserMessageCall`, `NtUserSetClipboardData`, `NtGdiBitBlt`, etc.) are exported by win32u.dll and transition to win32k.sys through a separate system service table (the shadow SSDT or win32k syscall table). On Windows 10 1703+, win32u.dll replaced the previous user32.dll direct syscall stubs.

3. EDR products that hook user-mode syscall stubs must hook both ntdll.dll and win32u.dll. Hooking only ntdll.dll leaves the entire GUI syscall surface unmonitored — an EDR cannot observe clipboard access, window enumeration, or input injection through ntdll hooks alone.

4. Thread type enforcement: win32k.sys rejects GUI syscalls from threads that have not been initialized for GUI use. A thread becomes GUI-initialized when it calls a function that triggers Win32k thread initialization — typically through `User32!Win32InitializeThunk` or by calling a win32k API that forces thread attribute initialization.

5. The kernel tracks per-thread GUI state via the THREADINFO structure (also called W32THREAD), accessed through the `ETHREAD→Tcb→Win32Thread` field. When this field is NULL, the thread has no associated W32THREAD and GUI syscalls return `STATUS_INVALID_THREAD`.

6. Operators issuing GUI syscalls (for clipboard access via T-023 capabilities, window enumeration, input injection) must ensure the calling thread has been GUI-initialized. This means either calling a user32.dll API that triggers thread initialization, or manually calling the internal initialization function.

## OS Internals Context

The win32u.dll module was introduced in Windows 10 version 1703 as part of the User32 subsystem refactoring. Prior to win32u.dll, GUI syscall stubs were embedded directly in user32.dll (and the internal user32full.dll). The refactoring extracted these stubs into win32u.dll, which contains only the `syscall` instruction sequences — no additional logic. This mirrors the ntdll.dll pattern where syscall stubs are minimal wrappers around the `syscall` instruction.

The win32k.sys driver is the kernel-mode component of the Windows GUI subsystem. It maintains the Desktop heap, window objects, message queues, clipboard, and input processing. GUI syscalls enter win32k.sys through the `KeServiceDescriptorTableShadow` (the shadow SSDT), which is distinct from the `KeServiceDescriptorTable` used by native syscalls. The shadow table is only accessible to GUI-initialized threads — this is the enforcement mechanism for the thread type check.

The THREADINFO (W32THREAD) structure is allocated by win32k.sys when a thread first calls a GUI API. It is stored in the ETHREAD's Tcb (KTHREAD) `Win32Thread` field. The structure contains per-thread GUI state: a pointer to the thread's message queue, a pointer to the thread's desktop, the window station handle, and clipboard-related state. When `Win32Thread` is NULL, the win32k syscall dispatcher (the internal `NtUserThunk` or `Win32kApiCallout`) rejects the call with `STATUS_INVALID_THREAD` before any work is performed.

EDR hooking on win32u.dll follows the same inline hook pattern used on ntdll.dll: the EDR overwrites the first bytes of the syscall stub with a JMP to the EDR's hook function. The hook function inspects the syscall parameters, logs the call, and either passes through to the original syscall or blocks it. An operator who restores ntdll.dll's .text section from a known-good on-disk copy (the T-016 NTDLL unhook technique) does not affect win32u.dll hooks — these are separate modules with separate .text sections.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the architectural distinction between native and GUI syscall paths. The HUGIN source tree's syscall techniques (`dark_crystal/crowd/src/sys_recycled.rs` for RecycledGate, `dark_crystal/crowd/src/veh_gate.rs` for VEH Gate, `dark_crystal/crowd/src/hells_gate.rs` for SSN resolution) all target the ntdll.dll native syscall surface. An implementation extending these to win32u.dll would require: (1) resolving win32u.dll's base address via the PEB `InMemoryOrderModuleList` walk (the existing `resolve.rs` PEB walker can find win32u.dll by module name), (2) parsing win32u.dll's export table to locate GUI syscall stubs by name (`NtUserOpenClipboard`, `NtUserFindWindowEx`, etc.), (3) applying the same SSN extraction and indirect dispatch techniques used for ntdll syscalls. The client_rust crate's GUI capabilities (`clipboard.rs`, `input.rs`, `cursor_hider.rs`, `overlay.rs`) all use Win32 APIs that eventually route through win32u.dll — these are the operations that remain visible to EDR even after ntdll unhooking.

## Why It Matters

The vault's syscall dispatch techniques (T-001 RecycledGate, T-002 Hell's Gate, T-003 VEH Gate) and evasion suite (T-016) all focus on the ntdll.dll native syscall surface. T-023's client capabilities (clipboard monitoring, input injection, screen capture, cursor hiding) depend on GUI APIs that route through win32u.dll. Without addressing win32u.dll hooks, an operator who unhooks ntdll to evade detection on native syscalls remains fully visible for all GUI operations. This card documents the gap and the architectural reason it exists: Windows has two syscall dispatch paths, and evading one does not evade the other.

## Detection Considerations

- **Telemetry sources**: EDR products hook win32u.dll syscall stubs for `NtUserOpenClipboard`, `NtUserGetMessage`, `NtUserSetClipboardData`, `NtUserFindWindowEx`, and other GUI functions. ETW providers (`Microsoft-Windows-Win32k`) emit events for GUI operations. The kernel's win32k.sys callbacks (`SetWinEventHook` callbacks, window hook callbacks) provide visibility into GUI operations from kernel mode.
- **Bypass options**: Applying the same indirect syscall technique (T-001 RecycledGate) to win32u.dll stubs — resolving the SSN from win32u.dll's stub bytes and dispatching through a gadget — bypasses user-mode hooks on win32u.dll. This requires extending the SSN extraction to parse win32u.dll's stub format, which may differ from ntdll.dll's stub layout. Restoring win32u.dll's .text section from a known-good on-disk copy mirrors the T-016 NTDLL unhook approach but targets a different module.
- **Residual artifacts**: Thread initialization for GUI use creates a W32THREAD structure visible in kernel thread objects. win32u.dll module resolution via PEB walk is visible to memory scanners that monitor module enumeration patterns. GUI operations produce kernel-level ETW events from win32k.sys that user-mode hook bypasses do not suppress.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall dispatch targeting ntdll.dll stubs; the same technique must be extended to win32u.dll for GUI syscall coverage.
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution cascade for ntdll syscalls; GUI syscall SSNs require similar extraction from win32u.dll stubs.
- **T-016 EDR Evasion Suite** — NTDLL unhook restores only the native syscall surface; win32u.dll remains hooked.
- **T-023 Client Capabilities** — Clipboard, input, screen capture, and cursor hiding capabilities route through win32u.dll GUI syscalls.

## References

- Atlas material: atlas-edr-evasion-part2.md, atlas-edr-evasion-part4.md
- MITRE ATT&CK: T1106 (https://attack.mitre.org/techniques/T1106)
- LGTM notes: lgtm:win32u-gui-syscall-hook-coverage, lgtm:gui-vs-native-syscall-path-awareness
- Public references: SEC670 EDR evasion module

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. The HUGIN source tree's syscall implementations (dark_crystal/crowd/src/sys_recycled.rs, src/veh_gate.rs, src/hells_gate.rs) target ntdll.dll; win32u.dll coverage requires extending the SSN extraction and dispatch to the GUI syscall module.
<!-- END CARD T-118 -->

<!-- BEGIN CARD T-119 -->
---
id: T-119
name: x64 ABI Shadow Space Syscall Stubs
category: syscalls
tier: B
crate: none
source_file: none
mitre: T1106
tags: [x64-abi, calling-convention, shadow-space, fastcall, syscall-stubs, rop-frames, argument-spilling]
origin: atlas-synthesis
member_notes: [lgtm:x64-calling-convention-stub-constraint, lgtm:x64-abi-syscall-stub-construction, lgtm:cross-source-convergence-shadow-store-and-rop]
---

# x64 ABI, Shadow Space, and Calling Convention for Syscall Stubs — Register and Stack Layout Constraints

## Summary

The x64 Application Binary Interface (ABI) on Windows constrains how syscall stubs and Return-Oriented Programming (ROP) frames must be constructed. Integer arguments flow in RCX, RDX, R8, R9 in order, with remaining arguments on the stack. The caller must reserve a 32-byte shadow store at RSP+0 through RSP+0x1F for the callee to spill the first four register arguments into. Syscall stubs that load a System Service Number (SSN) into EAX and execute the `syscall` instruction must honor this convention even when they do not explicitly use the shadow store — the kernel's syscall dispatcher and any intervening hook functions expect the layout. ROP frame construction for syscall gadgets must similarly allocate the shadow store before the gadget's epilogue reads back spilled arguments. The shadow store is distinct from the Intel CET Hardware Shadow Stack, which is a separate security feature enforcing return address integrity.

## Mechanism

1. The x64 calling convention (Microsoft x64 ABI) assigns the first four integer arguments to RCX, RDX, R8, R9 in left-to-right order. Floating-point arguments use XMM0 through XMM3. Arguments beyond the fourth are placed on the stack at RSP+0x28, RSP+0x30, RSP+0x38, etc. (relative to the caller's RSP before the CALL instruction).

2. Before executing a CALL instruction, the caller must allocate a 32-byte (0x20) region on the stack at RSP+0 through RSP+0x1F. This shadow store exists so the callee can spill RCX, RDX, R8, R9 into memory if it needs to use those registers for other purposes. The callee is not required to spill — the space is reserved whether or not it is used.

3. After the CALL instruction pushes the 8-byte return address, the callee's RSP points to the return address at RSP+0x0, and the caller's shadow store spans RSP+0x8 through RSP+0x27 (from the callee's perspective). Stack arguments begin at RSP+0x28.

4. Syscall stubs in ntdll.dll follow a consistent pattern: `mov r10, rcx` (copy the first argument to R10 because the `syscall` instruction clobbers RCX), `mov eax, <SSN>` (load the system service number), `syscall` (transition to kernel), `ret` (return to caller). The `mov r10, rcx` instruction exists because the kernel's syscall entry (`KiSystemCall64`) reads the first argument from R10, not RCX — this is an ABI convention specific to the syscall interface.

5. An indirect syscall stub (T-001 RecycledGate) must replicate this pattern: load the SSN into EAX, move RCX to R10, and execute `syscall` — but from a non-ntdll address (a gadget in a legitimate module). The stub must not corrupt the shadow store because the caller (the operator's code) expects to find its spilled arguments intact after the stub returns.

6. ROP frame construction for sleep obfuscation (T-005 Ekko) builds virtual call frames for `RtlCaptureContext`, `SetWaitableTimerEx`, and `WaitForSingleObjectEx`. Each frame must include the 32-byte shadow store in the correct position relative to the simulated return address, because the target function's prologue may spill RCX/RDX/R8/R9 into it. If the shadow store is not allocated or is positioned incorrectly, the function overwrites adjacent stack data, corrupting the ROP chain.

7. Stack alignment: the x64 ABI requires RSP to be 16-byte aligned before a CALL instruction. Since CALL pushes an 8-byte return address, the callee's entry RSP is misaligned by 8 bytes (RSP mod 16 == 8). The callee's prologue typically includes a `SUB RSP,` instruction that realigns the stack to 16 bytes. ROP frames must account for this: the RSP value at the simulated call site must be 16-byte aligned, and the gadget's return address must be placed at the aligned RSP.

## OS Internals Context

The Microsoft x64 ABI is documented in the Windows SDK and the AMD64 Software Developer's Manual. The 32-byte shadow store is a design decision from the x64 ABI specification: it simplifies code generation by giving the callee a guaranteed scratch area for the first four arguments without requiring a stack frame allocation in leaf functions. The shadow store is distinct from the hardware Shadow Stack introduced with Intel Control-flow Enforcement Technology (CET). The hardware Shadow Stack is a separate hardware-managed stack that stores return addresses separately from the data stack, providing hardware-enforced return address integrity. The x64 ABI shadow store is a software convention for argument spilling — it has no hardware enforcement.

The `syscall` instruction (opcode 0F 05) transitions to the kernel's `KiSystemCall64` handler, which reads the SSN from EAX and the first argument from R10. The R10 register is used instead of RCX because the `SYSCALL` instruction does not push a return address (it stores it in RCX) and does not save the stack pointer (it stores it in R11). By moving the first argument to R10 before the `SYSCALL` instruction, the stub preserves the argument across the kernel transition. This is an x64-specific convention: on x86, the `SYSENTER` instruction uses different register conventions.

The CONTEXT structure (used by `RtlCaptureContext`, exception handling, and `GetThreadContext`) stores the full x64 register state, including RAX, RCX, RDX, R8, R9, RSP, RIP, and the XMM registers. When a VEH handler or exception handler modifies the CONTEXT to redirect execution (as in T-003 VEH Gate), the handler must set RIP, RSP, and any argument registers according to the x64 ABI. The shadow store in the CONTEXT's stack frame must be writable because the redirected function will spill its arguments there.

## Key Implementation Details

The provided source files do not implement syscall stub construction. The `amsi_page_guard.rs` file in `dark_crystal/crowd/src/` demonstrates shadow space awareness in its VEH handler implementation. The `return_address_from_ctx` helper reads the return address from `[RSP]` after an exception (`*(ctx.Rsp as *const u64)`), and the handler comment documents that "arg6 is at [RSP + 0x30] (shadow space + 5th slot)" — this correctly identifies that the 6th argument of `AmsiScanBuffer` sits at the callee's RSP+0x30, which accounts for the 8-byte return address at RSP+0x0, the 32-byte shadow store spanning RSP+0x8 through RSP+0x27, the 5th argument at RSP+0x28, and the 6th argument at RSP+0x30. The handler code uses `(ctx.Rsp as *const u64).add(6)` to access this offset, correctly applying the ABI layout.

The HUGIN source tree contains the actual syscall stub implementations in `dark_crystal/crowd/src/sys_recycled.rs` (RecycledGate inline assembly stubs), `dark_crystal/crates/core/src/sys_indirect.rs` (universal syscall dispatcher), and `dark_crystal/crowd/src/veh_gate.rs` (VEH syscall dispatch). These files construct inline assembly that must honor the x64 ABI's shadow store convention. An implementation honoring the ABI would: allocate 32 bytes of shadow space before each simulated CALL in the ROP frame (`SUB RSP, 0x20`), place arguments in RCX/RDX/R8/R9 for the first four and on the stack for the rest, ensure RSP is 16-byte aligned before the target address, and preserve R10 for the syscall argument convention.

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

## Why It Matters

The x64 ABI is the foundational constraint that governs every syscall stub and ROP frame in the vault. T-001 (RecycledGate), T-002 (Hell's Gate), T-003 (VEH Gate), T-005 (Ekko ROP Sleep), and T-006 (Phantom Stubs) all construct inline assembly or ROP chains that implicitly depend on the shadow store being correctly allocated. The SEC670 material explains why stack arguments start at RSP+0x28 (the callee's shadow store plus return address), why syscall stubs copy RCX to R10, and why Ekko's ROP frames must include 32 bytes of padding before each target function — knowledge that source code alone does not convey. Documenting the ABI as an explicit concept node lets operators cross-navigate from any stub implementation back to the underlying convention that makes it work. The convergence between calling-convention fundamentals and the vault's ROP/sleep-obfuscation techniques is implicit in the source code but never surfaced as a shared concept.

## Detection Considerations

Training material does not discuss detection for this technique. The x64 ABI is a specification, not an evasion technique. Memory scanners that analyze ROP frame layouts may flag anomalous stack frame constructions that deviate from ABI-compliant patterns — for example, missing shadow store allocation or incorrect stack alignment before function pointers.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall stubs must allocate and preserve the shadow store for the caller's argument spill.
- **T-002 Hell's/Halo's/Tartarus Gate** — SSN resolution reads syscall stub bytes that include the `mov r10, rcx` convention.
- **T-003 VEH Syscall Gate** — Exception handler CONTEXT modification must set argument registers and RSP according to the x64 ABI.
- **T-005 Ekko ROP Sleep** — ROP frame construction allocates 32-byte shadow stores for `RtlCaptureContext`, `SetWaitableTimerEx`, and `WaitForSingleObjectEx`.
- **T-006 Phantom Stubs** — MEM_IMAGE-backed syscall stubs must replicate the ntdll stub layout including shadow store preservation.
- **T-016 EDR Evasion Suite** — Argument spoofing must place spoofed arguments in the correct registers and stack positions per the x64 ABI.

## References

- Atlas material: atlas-binary-analysis-part6.md, atlas-binary-analysis-part7.md, atlas-binary-analysis-part9.md
- MITRE ATT&CK: T1106 (https://attack.mitre.org/techniques/T1106)
- LGTM notes: lgtm:x64-calling-convention-stub-constraint, lgtm:x64-abi-syscall-stub-construction, lgtm:cross-source-convergence-shadow-store-and-rop
- Public references: SEC670 binary analysis module, Microsoft x64 ABI documentation, AMD64 Software Developer's Manual

## Source Reference

No current implementation in the provided source files. The amsi_page_guard.rs file demonstrates shadow space awareness in its VEH handler (`return_address_from_ctx` function, arg6-at-[RSP+0x30] comment). Actual syscall stub implementations reside in dark_crystal/crowd/src/sys_recycled.rs and dark_crystal/crates/core/src/sys_indirect.rs (not provided in this batch for verification).
<!-- END CARD T-119 -->