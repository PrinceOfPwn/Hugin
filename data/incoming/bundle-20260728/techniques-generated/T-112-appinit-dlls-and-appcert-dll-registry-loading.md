---
id: T-112
name: AppInit DLLs and AppCert DLL Registry Loading
category: persistence
tier: A
crate: none
source_file: none
mitre: T1546.010
mitre_secondary: [T1546.009]
tags: [persistence, appinit-dlls, appcert-dlls, registry, user32, create-process, dll-loading, secure-boot]
origin: atlas-synthesis
member_notes: ['lgtm:appinit-and-appcert-persistence', 'lgtm:registry-dll-loading-mechanisms']
---

# AppInit DLLs and AppCert DLL Registry Loading — Subsystem-Triggered DLL Injection via Registry

## Summary

AppInit_DLLs and AppCertDlls are two registry-driven DLL loading mechanisms that inject specified DLLs into processes based on subsystem events rather than logon or boot triggers. AppInit_DLLs causes user32.dll to load listed DLLs into any process that imports user32.dll, providing broad-scope persistence across GUI processes. AppCertDlls loads listed DLLs into processes that invoke CreateProcess-family APIs, targeting process creation rather than GUI initialization. SEC670 treats these as distinct from Run/RunOnce keys because they trigger on subsystem events rather than at logon, and cites APT28 and T9000 as historical AppInit_DLLs operators. Modern Windows versions progressively restrict both mechanisms: RequireSignedAppInit_DLLs enforces signature verification, and Secure Boot disables AppInit_DLLs entirely on supported systems.

## Mechanism

1. For AppInit_DLLs persistence, the operator writes a DLL path (or semicolon-separated list of paths) to the registry value HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs as a REG_SZ string.
2. The operator optionally sets HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\RequireSignedAppInit_DLLs to 0 (REG_DWORD) to disable signature verification, or to 1 to require Authenticode-signed DLLs. On systems with Secure Boot enabled, AppInit_DLLs is disabled regardless of this registry value.
3. When any process loads user32.dll (which occurs for any process that creates a window or uses GDI/User32 functions), user32.dll's DllMain routine reads the AppInit_DLLs registry value and calls LoadLibrary on each listed DLL path. The loaded DLL's DllMain executes within the host process's context.
4. For AppCertDlls persistence, the operator creates a registry value under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls. Each value name is an arbitrary string, and the value data is a REG_SZ path to the DLL.
5. When any process calls CreateProcess, CreateProcessAsUser, or CreateProcessWithTokenW, the kernel-mode subsystem routing invokes each AppCertDlls entry's exported CreateProcessNotify or equivalent callback. The DLL's NotifyRoutine executes before the new process begins, allowing the DLL to inspect, modify, or block the process creation.
6. Both mechanisms provide persistence across reboots via registry storage. AppInit_DLLs re-triggers on every user32.dll load. AppCertDlls re-triggers on every CreateProcess call.
7. The loaded DLL can perform arbitrary actions within its DllMain (AppInit) or NotifyRoutine (AppCert) callback, including spawning threads, establishing C2 channels, or modifying the host process's behavior.

## OS Internals Context

The AppInit_DLLs mechanism is implemented within user32.dll's initialization code. When user32.dll is loaded into a process (via implicit import, explicit LoadLibrary, or delayed load), its DllMain function with DLL_PROCESS_ATTACH reason reads the AppInit_DLLs and RequireSignedAppInit_DLLs registry values from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows. For each path in the AppInit_DLLs value (semicolon-delimited), user32.dll calls LoadLibraryExW to load the DLL. The loaded DLL's DllMain executes within the host process's address space, inheriting its token, integrity level, and privilege context.

A documented hazard exists with AppInit_DLLs: if the loaded DLL's DllMain itself imports or loads user32.dll (directly or transitively), an infinite recursion occurs. User32.dll loads the AppInit DLL, which loads user32.dll, which loads the AppInit DLL again. This causes a stack overflow and process termination. The operator's DLL must avoid re-loading user32.dll during its DllMain — typically by deferring user32-dependent operations to a separate thread created within DllMain.

The RequireSignedAppInit_DLLs registry value, introduced in Windows Vista, controls whether user32.dll verifies the Authenticode signature of each AppInit DLL before loading. When set to 1, only Authenticode-signed DLLs are loaded. When set to 0, unsigned DLLs are loaded without verification. On systems with Secure Boot enabled (UEFI Secure Boot + Windows 8.1 or later), AppInit_DLLs is disabled entirely — user32.dll skips the registry read regardless of the RequireSignedAppInit_DLLs value. This makes AppInit_DLLs persistence ineffective on modern Secure Boot systems.

The AppCertDlls mechanism operates at a different layer. The registry key HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls stores DLL paths that the Windows subsystem (winsrv.dll in session 0, or the kernel-mode portion of CreateProcess routing) loads into any process that calls the CreateProcess family. Each AppCertDlls DLL must export a function (historically named CreateProcessNotify) that receives information about the process being created. This mechanism is less commonly abused than AppInit_DLLs because it requires a reboot to take effect (the DLL list is read at subsystem initialization) and operates at a broader scope.

On 64-bit Windows, the AppInit_DLLs registry value is subject to WOW64 redirection. A 32-bit process loading user32.dll reads from the WOW6432Node registry view (HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs), while a 64-bit process reads from the native view. An operator targeting both architectures must write to both registry views.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An AppInit_DLLs implementation would write the DLL path to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs via RegSetValueExW, set RequireSignedAppInit_DLLs to 0 if the DLL is unsigned, and ensure the DLL's DllMain avoids re-loading user32.dll by deferring payload execution to a spawned thread. The DLL must be placed at a path accessible to the processes that will load user32.dll. For AppCertDlls, the implementation would write the DLL path under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls and export the required notification function.

## Why It Matters

AppInit_DLLs and AppCertDlls provide DLL-loading persistence triggered by subsystem events rather than logon, giving them a different execution profile from Run/RunOnce keys. AppInit_DLLs in particular has historical significance as a persistence vector used by APT28 and T9000 per SEC670 material. The mechanisms are distinct from registry autostart because they inject into already-running processes rather than launching a new process, providing in-process execution context that can hook or modify host process behavior. The progressive restriction of AppInit_DLLs on modern Windows (signature requirements, Secure Boot disablement) limits its current applicability but does not eliminate it on non-Secure Boot systems.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 7 (image load) captures unexpected DLLs loaded into processes via the AppInit mechanism, with the image loaded by user32.dll rather than the process itself. Registry monitoring on HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows detects AppInit_DLLs value changes. Registry monitoring on HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls detects AppCertDlls additions. Autoruns detects both in its AppInit DLLs and AppCertDlls categories.
- **Bypass options**: Signing the DLL with a valid or stolen Authenticode certificate allows operation with RequireSignedAppInit_DLLs=1. Writing to the WOW6432Node view targets 32-bit processes, which may be less monitored. Naming the DLL to mimic a legitimate application component reduces visual anomaly.
- **Residual artifacts**: The registry value persists until manually deleted. The DLL file on disk remains at the specified path. The loaded DLL appears in the module list of every process that imports user32.dll, creating a broad detection footprint.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-112 fills the AppInit/AppCert gap absent from T-017's suite
- **T-038 AppInit_DLLs Registry Persistence** — existing vault card covering the AppInit_DLLs mechanism
- **T-067 AppCert DLL Injection Persistence** — existing vault card covering the AppCertDlls mechanism
- **T-108 Registry Run/RunOnce Key Persistence** — companion card covering shell-launch registry persistence as distinct from subsystem-triggered DLL loading

## References

- Atlas material: atlas-post-exploit-part1.md, atlas-post-exploit-part11.md
- MITRE ATT&CK: T1546.010 — https://attack.mitre.org/techniques/T1546/010/
- LGTM notes: lgtm:appinit-and-appcert-persistence, lgtm:registry-dll-loading-mechanisms

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.