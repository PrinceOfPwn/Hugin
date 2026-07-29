---
id: T-067
name: AppCert DLL Injection Persistence
category: persistence
tier: B
crate: none
source_file: none
mitre: T1546.009
tags: [persistence, appcertdlls, registry-persistence, dll-injection, csrss, session-manager, host-activity-triggered, createprocess-hook]
origin: atlas-synthesis
member_notes: [lgtm:appcert-dll-persistence]
---

# AppCert DLL Injection Persistence — csrss-Mediated DLL Loading at Process Creation

## Summary

AppCertDlls is a Session Manager registry mechanism that forces a designated DLL into the address space of every process created through the Win32 process-creation APIs. An operator writes a `REG_SZ` value naming an arbitrary value and pointing at a DLL path under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`; thereafter the Client/Server Runtime Subsystem (`csrss.exe`) maps that DLL into each new process during its subsystem registration handshake. Unlike scheduled-task or boot-time persistence, the trigger is host activity: any user, service, or installer calling `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogonW`, `CreateProcessWithTokenW`, or `WinExec` loads the operator's code. Installation requires administrative rights and, per the training material, a reboot for reliable activation. The detection surface is a cataloged autostart registry location plus a single non-Microsoft DLL image loading into an abnormally large population of processes.

## Mechanism

1. With administrative privileges, the operator opens or creates the key `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` via `RegCreateKeyExW`.
2. `RegSetValueExW` writes a value whose name is arbitrary (for example, a plausible certificate-related name) with type `REG_SZ` and data set to the absolute path of the payload DLL on disk.
3. The system is rebooted. Per the training material this is required for reliable installation: `csrss.exe` reads the AppCertDlls list during subsystem initialization, so additions to a running system are not honored until restart.
4. On each subsequent process creation through the Win32 APIs, the newly created process connects to the Win32 subsystem server during early initialization. The BaseSrv component of `csrss.exe` processes the new-process registration and maps each DLL listed under AppCertDlls into the new process's address space.
5. The DLL must export a function named `CreateProcessNotify`. `csrss` invokes this export with the new process's image information and a reason code during the creation handshake. The export's return value can veto the process creation — the mechanism's legitimate purpose is enterprise application certification, where uncertified binaries are blocked from launching.
6. Operator code executes either in `DllMain` on `DLL_PROCESS_ATTACH` or inside `CreateProcessNotify`, running in the context, token, and integrity level of whatever process triggered the load.
7. Because the load recurs for every created process, the payload gates re-entry — a named mutex, process-name allowlist, or parent-chain check — to avoid uncontrolled propagation into hundreds of short-lived processes.

## OS Internals Context

The AppCertDlls key lives under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`, the same branch that holds `BootExecute`, `KnownDLLs`, and `PendingFileRenameOperations`. Keys in this branch are consumed by `smss.exe` and `csrss.exe` during boot and subsystem startup, which is why a reboot is the reliable activation path: the list is not reparsed on each process creation from a live registry read.

The loading path runs through subsystem registration. On modern Windows, `CreateProcessW` resolves to `NtCreateUserProcess` in `ntdll.dll`, which performs the kernel-side process object creation. The new process must still register with the Win32 subsystem: it connects to the `csrss` SbApiPort (an ALPC port) and the BaseSrv server-side component completes the client initialization. AppCert DLL mapping occurs inside this handshake, before the new process's entry point executes. The timing is significant — the payload runs during the same initialization window as other subsystem setup, ahead of any user code in the target.

The `CreateProcessNotify` export contract is the distinguishing feature. `csrss` requires this named export and invokes it during creation; the return value gates whether creation proceeds. This gives the mechanism a dual nature: a persistence vector (code executes in every new process) and a process-creation gatekeeper (the DLL can abort launches it disapproves of). Operators abusing it for persistence return success unconditionally to avoid breaking host behavior.

Contrast with AppInit_DLLs (T-038) clarifies the loader paths. AppInit DLLs load from `user32.dll` initialization (gated by the `LoadAppInit_DLLs` value), so only processes that load `user32.dll` receive them — console services and non-GUI processes are excluded. AppCert DLLs load via `csrss` for every process created through the Win32 creation APIs regardless of which subsystem DLLs the process imports. Both are HKLM registry-driven mass-injection mechanisms; they differ in the consuming component and coverage profile.

Coverage has defined edges. Processes created without Win32 subsystem registration — minimal processes, Pico processes, or direct `NtCreateUserProcess` invocations that skip the `csrss` handshake — bypass the mechanism. Architecture mismatch also excludes targets: a 64-bit DLL cannot map into a 32-bit Wow64 process, so mixed-environment coverage requires shipping both DLL architectures or accepting partial propagation. Because `csrss` runs as SYSTEM and maps the DLL into processes at every integrity level, the payload executes inside low-integrity sandboxes and SYSTEM services alike.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would add a `persist/appcert.rs` module alongside the existing `persist/com_hijack.rs`, `persist/schtask.rs`, and sibling layers. The registry write path can reuse the `winapi::um::winreg` call pattern already present in the codebase — `edo_tensei.rs` performs `RegCreateKeyExW`/`RegSetValueExW` against HKCU for soul storage, and the AppCert variant differs only in hive (HKLM), key path, and value payload. The companion DLL requires a `CreateProcessNotify` export and a re-entry gate; its on-disk placement inherits the same operational considerations as any persistence binary (signature, path plausibility, timestamp hygiene).

## Why It Matters

The five layers in T-017 trigger on boot, logon, schedule, or binary execution of a specific target; AppCertDlls triggers on ambient host activity — any process creation by any principal. That trigger profile complements rather than duplicates the existing stack: a host that reboots rarely but spawns processes constantly exercises this layer continuously. It is also one registry write away from the process-veto gatekeeper behavior, a capability no other vault persistence layer offers. The mechanism earns its own card because its loader path (`csrss` subsystem registration) and export contract are distinct from every documented layer.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 (registry value set) captures writes under the AppCertDlls path, which is a monitored autostart location in standard Sysmon configurations and in Autoruns. Sysmon Event ID 7 (image loaded) exposes the behavioral signature: the same non-Microsoft DLL loading into dozens of unrelated processes is a strong correlation analytic.
- **Bypass options**: naming the value and DLL to blend with legitimate certificate software reduces triage priority; code-signing the DLL lowers image-load heuristic scores; gating propagation to a narrow process allowlist shrinks the image-load fan-out that correlation rules detect.
- **Residual artifacts**: the registry value, the on-disk DLL, and Prefetch/Amcache entries recording the DLL's load across many host processes. The reboot requirement creates a detection window between installation and activation.

The atlas material for this technique does not discuss detection; the sources above reflect standard Windows and Sysmon telemetry.

## Related Techniques

- **T-017 Five-Layer Persistence** — AppCertDlls functions as a sixth, host-activity-triggered layer alongside COM hijack, NTFS EA, scheduled task, TLS callback, and PhantomPersist.
- **T-038 AppInit_DLLs Registry Persistence** — the parallel registry-driven mass DLL injection mechanism; differs in loader path (`user32.dll` initialization versus `csrss` subsystem registration) and process coverage.

## References

- Atlas material: atlas-edr-evasion-part2.md (unit 2)
- MITRE ATT&CK: [T1546.009 — Event Triggered Execution: AppCert DLLs](https://attack.mitre.org/techniques/T1546/009/)
- LGTM notes: lgtm:appcert-dll-persistence

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.