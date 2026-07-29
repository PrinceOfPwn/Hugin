---
id: T-034
name: IFEO GlobalFlag and SilentProcessExit Registry Persistence
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.012
mitre_secondary: [T1112]
tags: [persistence, ifeo, silent-process-exit, globalflag, registry-persistence, debugger-hijack, event-driven, hklm, process-lifecycle]
origin: atlas-synthesis
member_notes: ['lgtm:ifeo-silent-process-exit-persistence', 'lgtm:ifeo-debugger-persistence', 'lgtm:proposed-ifeo-persistence', 'lgtm:ifeo-persistence-card', 'lgtm:proposed-ifeo-persistence-suite', 'lgtm:ifeo-silentprocessexit-persistence-card', 'lgtm:silentprocessexit-trigger-persistence', 'lgtm:proposed-silent-process-exit-persistence']
---

# IFEO GlobalFlag and SilentProcessExit Registry Persistence — Process start and exit triggers via the IFEO registry subtree

## Summary

IFEO persistence converts two documented Windows debugging facilities into event-driven persistence: the Image File Execution Options `Debugger` value, which substitutes an attacker binary whenever a chosen image launches, and the `GlobalFlag`/`SilentProcessExit` pair, which executes a configured monitor command when a chosen image terminates. Both live entirely in the HKLM hive under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>` and the sibling `SilentProcessExit` key, so the configuration survives reboot and requires no scheduler, service, or WMI subscription. Operators use the Debugger variant to catch process-start events and the SilentProcessExit variant to catch process-exit events on a watched process, with the material giving `userinit.exe` as the example target for boot-early execution. Setup is a single registry write for the Debugger variant or three writes for the exit variant (`GlobalFlag=512`, `ReportingMode=1`, `MonitorProcess=<path>`) via reg.exe or the Win32 Registry API, gated on Administrator or SYSTEM because basic users cannot modify the required HKLM keys. The training material does not discuss detection telemetry for this technique; the residual artifacts are the registry values themselves and the on-disk payload binary.

## Mechanism

1. Select a target image name. IFEO matches on the image file name only, not a full path. The material's stated rationale is to pick a process that starts early in the boot sequence or is guaranteed to execute — `userinit.exe` is the given example. The cluster notes extend the same mechanism to accessibility binary hijacks (sethc.exe, utilman.exe), security tool redirects, and arbitrary target images.

2. Variant A (process-start trigger): create or open the subkey `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<ImageName>` and set the `Debugger` (REG_SZ) value to the implant path. The material describes this variant as redirecting the target executable's launch to an attacker-specified binary.

3. Trigger A behavior: on every subsequent process creation for that image, the create-process path reads IFEO, finds the `Debugger` value, and launches the debugger binary in place of the target image. Per the documented IFEO debugging contract, the original image path and command line are appended to the debugger invocation; the intended image does not run unless the substituted binary chooses to run it.

4. Variant B (process-exit trigger), step one: set the monitor flag on the watched image — `reg add HKLM\...\Image File Execution Options\<ImageName> /v GlobalFlag /t REG_DWORD /d 512` (command verbatim from the material).

5. Variant B, step two: `reg add HKLM\...\SilentProcessExit\<ImageName> /v ReportingMode /t REG_DWORD /d 1`.

6. Variant B, step three: `reg add HKLM\...\SilentProcessExit\<ImageName> /v MonitorProcess /d "C:\Path\To\implant.exe"`.

7. Trigger B behavior: when the watched image exits, the system honors the monitor contract and launches the `MonitorProcess` command line. The material frames the roles as: Image is the process to "watch"; Monitor is the "watching" process.

8. Setup routes documented in the material: interactive reg.exe from a shell; the Win32 Registry APIs `RegOpenKeyExA`, `RegCreateKeyExA`, and `RegSetValueEx` for a programmatic implant; or the GUI route via gflags.exe, which ships with the Windows SDK at `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64` and exposes Kernel, Image File, and Silent Process Exit tabs. The material also names GflagsX by Pavel Yosifovich as a modern replacement for the legacy tool, and states that the GUI items can be implemented programmatically.

9. Permissions check: Administrator or SYSTEM is required. The material states that a basic user "will be denied access when trying to modify the HKLM Registry keys needed for the IFEO persistence method."

10. Persistence properties: the configuration is registry-resident, survives reboot, and fires on each future launch (Variant A) or exit (Variant B) of the watched image with no timer, task, or service component.

11. Removal: reverse the registry modifications. The material calls out reversing registry changes during post-exploitation cleanup and suggests building an uninstall command into the implant for this purpose.

## OS Internals Context

The IFEO subtree is a per-image-name options store consulted by the process-creation path. When a process is created, the system checks for a subkey of `Image File Execution Options` matching the image file name and applies whatever values it finds. The material defines IFEO as "a Windows Registry key that enables the debugging or tracing of a process when it is started," giving "having a debugger launch when the process does" as the example action, and notes the mechanism is effective for EXE images rather than DLLs.

The `Debugger` value semantics are the documented IFEO debugging contract repurposed: when present, the system launches the debugger image and passes the original image path and command line to it as arguments. The create call succeeds while the attacker binary occupies the launch slot of the target. No hook, patch, or driver is involved — the substitution is a first-class feature of the create-process path.

The `GlobalFlag` DWORD under an image's IFEO subkey carries the same FLG_* bit meanings as the system-wide global flags. At process creation, the per-image bits are merged into the process's global flags (reflected in `PEB.NtGlobalFlag`); this merge is how gflags per-image settings take effect at all. The value 512 (0x200) is the silent-process-exit monitor bit, publicly documented as `FLG_MONITOR_SILENT_PROCESS_EXIT`. Because the merge happens at creation, the flag must be in place before the watched process starts; instances already running when the value is written are unaffected.

On termination, a process carrying the monitor bit is treated as a reportable "silent exit" — a process that ends without a fault. The system then consults `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<ImageName>`; `ReportingMode=1` requests a monitor launch and `MonitorProcess` supplies the command line. MSDN documents this contract under "Monitoring Silent Process Exit" as a Windows Error Reporting reporting mode, available since Windows 7. The atlas material does not specify which OS component performs the monitor spawn, and this card does not assert one.

The kernel/user boundary posture is why the technique deploys and removes so cheaply: configuration is pure user-mode registry I/O, while consumption happens entirely inside OS-controlled paths (create-process for the Debugger value and GlobalFlag merge, termination handling for the silent-exit check). The only access barrier is the HKLM hive's default DACL, which grants write access to Administrators and SYSTEM — the limiting factor the material calls out in its module summary.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations via reg.exe commands, the Win32 Registry API, and gflags.

Verification of the grep-matched sources: `src/client_rust/src/browser_hook.rs` implements browser extension persistence (shortcut patching, HKCU Run key, scheduled task, protocol handler patching) — none of its persistence layers touch the IFEO or SilentProcessExit keys. `src/dark_crystal/crowd/src/edo_tensei.rs` performs registry I/O (`RegCreateKeyExW`/`RegSetValueExW` against an HKCU CLSID Config key) for generation-index soul storage, not IFEO configuration. `src/dark_crystal/crowd/src/kaguya.rs` inventories LOtL binaries and contains no IFEO logic. The existing `dark_crystal/crowd/src/persist/` module tree (com_hijack, ntfs_ea, schtask, tls_cb, phantom_restart) has no IFEO layer.

An implementation would be a `persist/ifeo.rs` module beside the existing persistence layers: wide-string `RegCreateKeyExW`/`RegSetValueExW` calls following the winapi pattern already used in `edo_tensei.rs`, parameterized on target image name and payload path, with one routine writing the `Debugger` value and a second writing the `GlobalFlag`/`ReportingMode`/`MonitorProcess` triple. The module would need an Administrator/SYSTEM privilege check before attempting HKLM writes and a removal routine that deletes the created values, matching the material's uninstall-command guidance.

## Why It Matters

T-017's five layers are boot-, logon-, load-, or shutdown-triggered; none of them key off the lifecycle of a specific victim process. IFEO contributes two per-process event triggers — launch redirection via `Debugger` and exit monitoring via `SilentProcessExit` — that are configured with registry writes alone and leave no service, task, or WMI subscription on the host. The exit-triggered variant is the only exit-triggered persistence primitive documented in the vault. Eight member notes across five atlas batches converge on the same registry sequence and permission model, which is the strongest cross-source signal in this clustering round for a missing persistence layer.

## Detection Considerations

Training material does not discuss detection for this technique.

What the material does document:

- **Telemetry sources**: none named in the material. Sysmon appears in the same course section only in the context of WMI attack detection, not IFEO.
- **Bypass options**: none discussed. The material's stated limiting factor is the permission model — deployment fails for basic users against HKLM — rather than any monitoring control.
- **Residual artifacts**: the mechanism's own configuration data, all named in the material's setup commands — the `Debugger` or `GlobalFlag` value under `Image File Execution Options\<ImageName>`, the `ReportingMode` and `MonitorProcess` values under `SilentProcessExit\<ImageName>`, and the on-disk payload binary those values reference. The material directs operators to reverse the registry modifications during cleanup and suggests an uninstall command in the implant for that purpose.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — IFEO Debugger and SilentProcessExit are the event-driven registry layers the five-layer suite lacks; same Admin/SYSTEM HKLM persistence class, but triggered by victim process launch/exit instead of logon, COM instantiation, DLL load, or shutdown.

## References

- Atlas material: atlas-edr-evasion-part2.md (gflags, GlobalFlag, Silent Process Exit units), atlas-methodology-part4.md (Section 4 roadmap, IFEO/IFEOPersisto TOC), atlas-misc-part1.md (IFEO module, GlobalFlag/gflags, lab purpose), atlas-post-exploit-part7.md (IFEO module: definition, reg.exe sequence, userinit.exe rationale, permissions, source review), atlas-post-exploit-part12.md (IFEO objectives, permissions, manual implementation, module summary), atlas-post-exploit-part15.md (Lab 4.3 IFEOPersisto, process-start vs silent-exit variants), atlas-labs-part1.md (SilentProcessExit termination-monitoring review question)
- MITRE ATT&CK: T1546.012 — Event Triggered Execution: Image File Execution Options Injection (https://attack.mitre.org/techniques/T1546/012/); secondary T1112 — Modify Registry (https://attack.mitre.org/techniques/T1112/)
- LGTM notes: lgtm:ifeo-silent-process-exit-persistence, lgtm:ifeo-debugger-persistence, lgtm:proposed-ifeo-persistence, lgtm:ifeo-persistence-card, lgtm:proposed-ifeo-persistence-suite, lgtm:ifeo-silentprocessexit-persistence-card, lgtm:silentprocessexit-trigger-persistence, lgtm:proposed-silent-process-exit-persistence
- Public references named in the material: gflags.exe (Windows SDK Debugging Tools); GflagsX by Pavel Yosifovich — https://github.com/zodiacon; SANS SEC670 Lab 4.3 IFEOPersisto

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.