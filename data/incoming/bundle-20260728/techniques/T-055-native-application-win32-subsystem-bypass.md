---
id: T-055
name: Native Application Win32 Subsystem Bypass
category: discovery
tier: B
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1055]
tags: [native-application, nt-process-startup, peb, subsystem-bypass, minimal-footprint, nt-api, image-loader, pe-subsystem]
origin: atlas-synthesis
member_notes: ['lgtm:native-application-development']
---

# Native Application Win32 Subsystem Bypass — Direct PEB Entry Point

## Summary

Native applications are PE executables compiled with `IMAGE_SUBSYSTEM_NATIVE` (value 1) in the optional header, causing the Windows image loader to bypass Win32 subsystem initialization entirely and invoke the entry point with the PEB passed directly as a parameter. The entry point signature `NTSTATUS NtProcessStartup(PPEB peb)` replaces the standard Win32 CRT startup chain — no `kernel32!BaseThreadInitThunk`, no CRT initialization, no Win32 thread environment block setup. Only `ntdll.dll` is loaded into the process address space at startup. This eliminates the userland hook surface that EDR products install in Win32 API functions and reduces the volume of ETW events from Win32 providers, producing a minimal-footprint execution environment for implant code that requires only NT API access.

## Mechanism

1. A PE executable is compiled and linked with the optional header's `Subsystem` field set to `IMAGE_SUBSYSTEM_NATIVE` (1). This field resides at offset 68 (0x44) from the start of the `IMAGE_OPTIONAL_HEADER` structure.

2. The linker sets the `AddressOfEntryPoint` field in the `IMAGE_FILE_HEADER` to the native entry point function. No CRT startup object (`crt0.obj` or equivalent) is linked.

3. No Win32 libraries (`kernel32.dll`, `user32.dll`, `gdi32.dll`, `advapi32.dll`) are linked or imported. The IAT contains only `ntdll.dll` exports.

4. When the image loader (`ntdll!LdrpInitializeProcess`) processes the executable, it reads the `Subsystem` field from the PE optional header. Recognizing `IMAGE_SUBSYSTEM_NATIVE`, it takes a different initialization path from Win32 GUI/CUI executables.

5. The loader does not initialize the Win32 thread environment. `kernel32.dll` is not loaded unless explicitly requested. The `BaseThreadInitThunk` trampoline that normally wraps the user entry point is not invoked.

6. The loader passes the PEB pointer directly to the entry point function. On x64, the PEB pointer is passed in `RCX` per the x64 calling convention. The entry point signature is `NTSTATUS NtProcessStartup(PPEB peb)`.

7. The native application accesses `peb->Ldr->InLoadOrderModuleList` to enumerate loaded modules. At process start, `ntdll.dll` is the only module in the list. The `LDR_DATA_TABLE_ENTRY` for `ntdll.dll` provides the `DllBase` field, which the application uses to resolve `Nt*` function addresses by walking the export directory.

8. All system service calls go through `ntdll.dll` `Nt*` stubs (which contain the `syscall` instruction on x64) or through direct `syscall` instructions if the application implements its own SSN resolution.

9. To access Win32 APIs if needed, the native application calls `NtLoadDriver` or manually maps `kernel32.dll` via `NtCreateSection` and `NtMapViewOfSection`, then walks the export table to resolve function pointers. This is a manual operation with no loader support for dependency resolution.

10. `NtCreateUserProcess` can spawn additional native applications by specifying the process parameters. The `RTL_USER_PROCESS_PARAMETERS` structure passed to `NtCreateUserProcess` does not require Win32 subsystem initialization for native target images.

11. The entry point returns an `NTSTATUS` value. The loader interprets the return value: `STATUS_SUCCESS` (0x00000000) causes normal process termination. A nonzero status causes process termination with the specified exit code. There is no `ExitProcess` call — the loader calls `NtTerminateProcess` directly.

## OS Internals Context

The `IMAGE_OPTIONAL_HEADER.Subsystem` field determines how the image loader initializes the process. For `IMAGE_SUBSYSTEM_WINDOWS_GUI` (2) and `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3), the loader initializes the Win32 subsystem: it loads `kernel32.dll` and `user32.dll` (for GUI), calls `kernel32!BaseDllInitialize`, sets up the Win32 thread environment block (`TEB.ProcessEnvironmentBlock` is populated, but the Win32-specific `TEB` fields such as `ReservedForOleActivation` and the thread-local storage slots are also initialized), and wraps the entry point call through `kernel32!BaseThreadInitThunk`.

For `IMAGE_SUBSYSTEM_NATIVE` (1), the loader skips the Win32 initialization path. The `PEB` is constructed and populated by the loader before the entry point is called — `PEB->ImageBaseAddress` points to the native executable's base, `PEB->Ldr` is initialized with the `ntdll.dll` module entry, and `PEB->ProcessParameters` contains the `RTL_USER_PROCESS_PARAMETERS` structure. However, the Win32-specific fields of the PEB (such as `PEB->KernelCallbackTable`, which holds the Win32 kernel callback dispatch table) are not populated.

The canonical native application on Windows is `smss.exe` (Session Manager Subsystem). It is the first user-mode process launched by the kernel and runs as a native application to initialize the session manager before any Win32 subsystem process starts. `autochk.exe` (the disk-checking utility that runs during boot) is another native application. These examples demonstrate that native applications can perform I/O, create processes, and interact with the kernel entirely through `ntdll.dll` exports.

The `PEB->Ldr` pointer leads to the `PEB_LDR_DATA` structure, which contains three doubly-linked lists: `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList`. For a native application at startup, all three lists contain exactly one entry: the `LDR_DATA_TABLE_ENTRY` for `ntdll.dll`. The `DllBase` field in this entry provides the base address needed for export table walking to resolve `Nt*` function pointers.

The `TEB` (Thread Environment Block) is accessible via the `GS` segment register on x64 (`gs:[0x30]` for the TEB self-pointer, `gs:[0x60]` for the PEB pointer). Native applications can use the PEB parameter passed to the entry point directly, but they can also access the PEB via `gs:[0x60]` at any time — the TEB is set up by the kernel before the entry point is called regardless of subsystem.

ETW providers that depend on Win32 subsystem initialization (such as `Microsoft-Windows-Kernel-Process` for process/thread events, and the various `.NET` and Win32-specific providers) emit events during the Win32 initialization path. Native applications skip this path, so the initial ETW event volume is lower. The kernel-level ETW providers (such as `NT Kernel Logger`) still emit events for native application process creation and system calls, since these operate at the kernel level regardless of subsystem.

## Key Implementation Details

**No current implementation in the HUGIN source.** An implementation would set `IMAGE_OPTIONAL_HEADER.Subsystem` to `IMAGE_SUBSYSTEM_NATIVE` (1) in the PE header during the build process, link only against `ntdll.dll` exports, and define the entry point as `extern "C" fn nt_process_startup(peb: *mut PEB) -> NTSTATUS`. API resolution would walk `peb->Ldr->InLoadOrderModuleList` to locate the `ntdll.dll` `LDR_DATA_TABLE_ENTRY`, then parse the export directory (`IMAGE_EXPORT_DIRECTORY`) at `ntdll_base + export_dir_rva` to resolve `Nt*` function addresses by name or by hash. System calls would go through the resolved `Nt*` stubs or through a direct syscall mechanism (T-001 RecycledGate or T-002 Hell's Gate) using SSN values extracted from the `Nt*` stubs. The `#![no_std]` attribute and `#![no_main]` attribute in Rust would prevent the standard library's Win32 initialization code from being linked. A minimal `link.exe` or `lld-link` invocation with `/SUBSYSTEM:NATIVE` and `/ENTRY:nt_process_startup` would produce the correct PE header.

## Why It Matters

Native applications eliminate the entire Win32 subsystem initialization chain, removing the userland hook surface that EDR products install in `kernel32.dll` and `user32.dll` API functions. A native application never calls `kernel32!CreateProcessW`, never loads `user32.dll`, and never initializes the Win32 thread environment. This reduces the loaded module list to a single entry (`ntdll.dll`), eliminates TLS callbacks from Win32 DLLs, and minimizes the ETW events generated during process startup. The tradeoff is that native applications cannot use any Win32 API without manually loading the DLL and resolving its exports, which adds implementation complexity for operations that require Win32 functionality such as GUI interaction or COM initialization.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 (Process Create) includes the process's image path and can be correlated with the PE subsystem field. The absence of `kernel32.dll` in the loaded module list is visible in Sysmon Event ID 7 (Image Loaded). ETW `Microsoft-Windows-Kernel-Process` provider still emits process creation events for native applications at the kernel level. Memory scanning tools can detect native PE images by reading the optional header and checking the `Subsystem` field.
- **Bypass options**: The technique itself is a bypass of Win32 telemetry. An operator can further reduce visibility by avoiding `ntdll.dll` `Nt*` stubs in favor of direct `syscall` instructions (T-001, T-002, T-003), which removes `ntdll.dll` from the call stack. Loading `kernel32.dll` later via `NtCreateSection`/`NtMapViewOfSection` avoids the loader's dependency resolution and associated ETW events.
- **Residual artifacts**: The PE file on disk has `IMAGE_SUBSYSTEM_NATIVE` in the optional header. The process's loaded module list contains only `ntdll.dll` at startup. The PEB's `ImageBaseAddress` points to the native executable. The `KernelCallbackTable` field in the PEB is null (uninitialized for native subsystem).

## Related Techniques

- **T-014 NtCreateUserProcess** — direct NT process creation; `NtCreateUserProcess` can spawn native applications by providing a native subsystem image path, which the loader initializes without Win32 setup.
- **T-004 PEB Walker** — native applications receive the PEB directly as an entry point parameter, eliminating the need for `gs:[0x60]` PEB access for module resolution at startup.

## References

- Atlas material: atlas-post-exploit-part13.md
- MITRE ATT&CK: T1106 — https://attack.mitre.org/techniques/T1106/
- LGTM notes: lgtm:native-application-development

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.