---
id: T-077
name: Native Application NT_main Execution Surface
category: anti-analysis
tier: B
crate: none
source_file: none
mitre: T1106
tags: [native-application, nt-main, early-boot, smss, ntdll-only, bootexecute, subsystem-native, ntapi-entry, minimal-surface, image-subsystem]
origin: atlas-synthesis
member_notes: [lgtm:native-application-execution-surface, lgtm:native-application-entry-point]
---

# Native Application NT_main Execution Surface — Pre-Subsystem Execution via Native Entry Point

## Summary

SEC670 documents the native Windows application execution mode, distinguished by the entry signature NTSTATUS NTAPI NT_main(int argc, char* argv[]) and the PE optional header Subsystem field set to IMAGE_SUBSYSTEM_NATIVE (value 1). Native applications execute before the Win32 subsystem (csrss.exe and win32k.sys) is fully initialized and are invoked by the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image path. They have no Win32 API surface — all I/O must use ntdll exports exclusively (NtCreateFile, NtCreateKey, NtSetValueKey, NtWriteFile, NtReadFile). This execution mode is operationally valuable for early-boot persistence via BootExecute registry entries, for SurvivableProtectedProcess launchers, and for minimal recon droppers that avoid the Win32 API surface monitored by most EDR products.

## Mechanism

1. The PE optional header's Subsystem field (located at offset 0x44 in the IMAGE_OPTIONAL_HEADER64 structure on x64) is set to IMAGE_SUBSYSTEM_NATIVE (value 1) rather than IMAGE_SUBSYSTEM_WINDOWS_GUI (2) or IMAGE_SUBSYSTEM_WINDOWS_CUI (3). This signals to the image loader that the executable does not require the Win32 subsystem.
2. The entry point function uses the signature NTSTATUS NTAPI NT_main(int argc, char* argv[]), returning an NTSTATUS code rather than a Win32 DWORD exit code. The NTAPI calling convention maps to __stdcall on x86 and the standard x64 calling convention on x64, matching the ntdll export convention.
3. The image's import table contains entries only from ntdll.dll — no kernel32.dll, kernelbase.dll, user32.dll, or advapi32.dll imports. The image loader (LdrpInitializeProcess in ntdll.dll) resolves only ntdll exports for native applications, because no other subsystem DLLs are loaded at the time of execution.
4. For early-boot execution, the image path is registered in HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute as a REG_MULTI_SZ value. The default value is "autocheck autochk *". The operator appends their native application name to this multi-string.
5. During boot, smss.exe (the Session Manager Subsystem) reads the BootExecute value after performing its initial setup (creating the KnownDlls object directory, initializing the registry transaction log) and invokes each listed executable via the internal process creation path before csrss.exe is started for the session.
6. The native application performs its operations using ntdll exports: NtCreateKey/NtSetValueKey for registry access, NtCreateFile/NtWriteFile for file I/O, NtAllocateVirtualMemory for memory allocation, NtCreateSection/NtMapViewOfSection for section operations, NtQueryInformationProcess for process information.
7. The application exits by returning an NTSTATUS from NT_main. A return value of STATUS_SUCCESS (0x00000000) indicates successful completion. smss.exe interprets the return status and proceeds to the next BootExecute entry or continues the boot sequence.

## OS Internals Context

The Windows boot sequence proceeds through a fixed chain of user-mode processes. The kernel (ntoskrnl.exe) loads smss.exe as the first user-mode process during the Session Manager initialization phase. smss.exe runs in native mode — it uses only ntdll exports and executes before any Win32 subsystem components are available. smss.exe reads the BootExecute registry value from HKLM\System\CurrentControlSet\Control\Session Manager and executes each program listed there using an internal process creation routine that calls NtCreateUserProcess (or its equivalent internal call path).

The PE loader (ntdll.dll's LdrpInitializeProcess function) checks the Subsystem field in the image's IMAGE_OPTIONAL_HEADER. For IMAGE_SUBSYSTEM_NATIVE (1), the loader does not attempt to initialize the Win32 subsystem — it does not load csrss.exe, does not initialize user32.dll or gdi32.dll, and does not create a window station or desktop object for the process. The process has no access to Win32 GUI functions, no console subsystem, and no standard environment block beyond what smss.exe or the process creator provides via RTL_USER_PROCESS_PARAMETERS.

The entry point calling convention for native applications differs from the standard C runtime entry point (mainCRTStartup or WinMainCRTStartup). The standard C runtime performs initialization — CRT heap creation, atexit registration, TLS callback invocation, I/O stream initialization — before calling main or WinMain. Native applications bypass this entirely. NT_main is called directly by the loader after minimal LdrpInitializeProcess setup, with argc and argv parsed from the command line string stored in the RTL_USER_PROCESS_PARAMETERS structure referenced by the PEB's ProcessParameters field.

The RTL_USER_PROCESS_PARAMETERS structure (defined in ntdll.h, approximately 0x420 bytes on x64) contains the CommandLine field (a UNICODE_STRING at a known offset), which native applications parse using RtlCommandLineToArgvW or an equivalent ntdll parsing routine. This structure is populated by the loader based on the parameters passed to NtCreateUserProcess via the PROCESS_CREATE_INFO structure or, in the case of BootExecute, by smss.exe's internal process creation logic.

The def.rs file in the HUGIN VEH module defines the PEB, RTL_USER_PROCESS_PARAMETERS, and related structures (PebLoaderData, LoaderDataTableEntry). These definitions mirror the ntdll internal structures and are used for VEH syscall gate functionality, not for native application execution. The structures demonstrate the layout of process parameters and PEB fields that a native application would access directly.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate's main.rs uses standard Win32 entry conventions (linking against kernel32/kernelbase via windows_targets::link!) and the crowd crate's entry points use standard Rust main. The def.rs file in the VEH module (src/experimental/evasion/veh/def.rs) defines PEB, RTL_USER_PROCESS_PARAMETERS, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and LDR_DATA_TABLE_ENTRY structures, but these serve the VEH syscall gate implementation, not native application execution.

An implementation would require: (1) setting IMAGE_SUBSYSTEM_NATIVE in the PE optional header via a custom linker configuration (#pragma comment(linker, "/SUBSYSTEM:NATIVE") in MSVC or a custom linker script for the Rust toolchain); (2) defining the entry point as NTSTATUS NT_main with the correct signature, bypassing the C runtime startup; (3) replacing all kernel32/kernelbase API calls with ntdll equivalents (the dark_crystal crate already implements many ntdll calls via wrappers.rs); (4) for BootExecute persistence, writing the image path to HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute using NtSetValueKey.

## Why It Matters

Native application execution provides an execution surface that most EDR products do not monitor with the same depth as Win32 applications. EDR products typically hook ntdll functions in user mode and register kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) for process and handle operations. Native applications that run during early boot via BootExecute may execute before the EDR's filter driver or user-mode service is fully initialized, creating a monitoring gap. The absence of a Win32 subsystem import surface also reduces the behavioral fingerprint — no kernel32 imports, no user32 imports, no standard C runtime initialization patterns in the import table. SEC670 identifies this as operationally valuable for early-boot persistence and minimal-footprint droppers that avoid the Win32 API surface.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 (Process Create) captures native application launches, including the image path and parent process (smss.exe for BootExecute launches). Process creation kernel callbacks (PsSetCreateProcessNotifyRoutineEx) fire for native applications regardless of subsystem. EDR products that monitor ntdll API calls via inline hooks will observe NtCreateFile, NtCreateKey, and other calls made by the native application.
- **Bypass options**: The primary advantage of native applications is reduced EDR coverage during early boot, not complete invisibility. EDR products that load their filter driver as a Boot Start driver (SERVICE_BOOT_START) may still monitor native application activity from the earliest boot phase. Some EDR products do not install their user-mode hooks until the Win32 subsystem initializes, creating a window of reduced monitoring for native applications that execute via BootExecute before csrss.exe starts.
- **Residual artifacts**: BootExecute persistence leaves a registry entry in HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute, enumerable via reg query or NtEnumerateKey. The native application binary on disk has IMAGE_SUBSYSTEM_NATIVE (1) in its PE optional header, detectable via static analysis of the Subsystem field. The absence of kernel32.dll in the import table is itself an indicator of a non-standard application, as nearly all legitimate Win32 executables import from kernel32.

## Related Techniques

- **T-017 Five-Layer Persistence** — BootExecute is an early-boot persistence mechanism distinct from the five layers in T-017 (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but operates in the same persistence category
- **T-020 Anti-Analysis Suite** — Native application execution avoids the Win32 API surface that anti-analysis checks and EDR hooks target, reducing the behavioral fingerprint

## References

- Atlas material: atlas-binary-analysis-part5.md (unit 32), atlas-binary-analysis-part8.md (unit 30)
- MITRE ATT&CK: T1106 — https://attack.mitre.org/techniques/T1106/
- LGTM notes: lgtm:native-application-execution-surface, lgtm:native-application-entry-point

## Source Reference

No current implementation. See atlas material for SEC670 coverage of native application entry conventions. The def.rs file in the VEH module (src/experimental/evasion/veh/def.rs) defines PEB and RTL_USER_PROCESS_PARAMETERS structures that mirror the internal layouts a native application would access.