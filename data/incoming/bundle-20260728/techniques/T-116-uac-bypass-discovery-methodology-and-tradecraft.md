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