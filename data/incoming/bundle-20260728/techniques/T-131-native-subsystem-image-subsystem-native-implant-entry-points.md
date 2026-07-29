---
id: T-131
name: Native Subsystem (IMAGE_SUBSYSTEM_NATIVE) Implant Entry Points
category: exploit-primitive
tier: S
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1574, T1036]
tags: [native-subsystem, pe-manipulation, win32-loader-bypass, peb-walk, direct-syscalls, defense-evasion, no-crt, entry-point, ntapi]
origin: atlas-synthesis
member_notes: ['lgtm:native-subsystem-implant-entry-point']
---

# Native Subsystem (IMAGE_SUBSYSTEM_NATIVE) Implant Entry Points — Executing Implants That Skip the Win32 Loader

## Summary

Windows executables carry a `Subsystem` field in `IMAGE_OPTIONAL_HEADER` that tells the NT loader (`ntdll!LdrpInitializeProcess`) which environment-init path to run before calling the image's entry point. Setting this field to `IMAGE_SUBSYSTEM_NATIVE` (value `1`, a `WORD` at offset `0x44` from the start of `IMAGE_OPTIONAL_HEADER` in both PE32 and PE32+) produces a process that the loader treats as a standalone native image — no `kernel32.dll`, no `user32.dll`, no `gdi32.dll`, no CRT, no `BaseDllInitialize` calls, no Win32 subsystem registration. The entry-point signature changes from `int mainCRTStartup()` to `NTSTATUS NTAPI NtProcessStartup(PPEB Peb)`, where the PEB pointer arrives in `RCX` on x64 (or `[ESP+4]` on x86) as the sole argument. The implant must resolve every function it needs by walking `PEB->Ldr->InLoadOrderModuleList` to locate `ntdll.dll`'s base, then parsing its export directory — exactly the pattern used in position-independent shellcode, but packaged as a standalone PE that the kernel and loader accept as a first-class process image.

Only four legitimate Windows binaries ship with `IMAGE_SUBSYSTEM_NATIVE`: `smss.exe` (Session Manager), `csrss.exe` (Client/Server Runtime), `wininit.exe` (Windows Startup Application), and `autochk.exe` (boot-time disk check). Any other native-subsystem image on a live system is anomalous by definition. The technique bypasses every user-mode telemetry channel that depends on Win32 DLL load events — Sysmon EID 7 for `kernel32`/`user32`/`gdi32`, ETW `Microsoft-Windows-Kernel-Image` for those same images, and EDR user-mode hooks on `ntdll!LdrLoadDll` / `kernel32!LoadLibraryExW`. Kernel-level process-creation callbacks (`PsSetCreateProcessNotifyRoutineEx`) still fire, so the technique is not invisible — it is selectively deaf to Win32-layer instrumentation. The vault's T-004 card documents PEB walking for export resolution; this card covers the PE-format and loader-path mechanics that make a standalone native process possible. T-022 covers PE-header patching techniques that can be used to set the Subsystem field post-link.

## Mechanism

### Variant 1: Compile-from-scratch Native Implant

1. Set `#![no_std]` and `#![no_main]` in the Rust crate (or `/NODEFAULTLIB` and `/ENTRY:NtProcessStartup` in MSVC). The standard CRT depends on `kernel32!HeapAlloc`, `kernel32!GetCommandLineA`, `kernel32!ExitProcess` — none of which will be available.
2. Define the entry point: `#[no_mangle] pub extern "C" fn NtProcessStartup(peb: *mut PEB) -> NTSTATUS`. The symbol name must match what the linker writes into `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint`; the calling convention must be the platform default (`__stdcall` on x86, default x64 ABI on x64).
3. Configure the linker to emit `IMAGE_SUBSYSTEM_NATIVE` in the PE header. With `lld-link` / `link.exe`: pass `/SUBSYSTEM:NATIVE,6.0` (the `6.0` is `MajorSubsystemVersion`; the loader rejects images with `MajorSubsystemVersion` below the kernel's expected minimum on newer Windows builds). With `rustc`: set `// -C link-args=/SUBSYSTEM:NATIVE` in `.cargo/config.toml`.
4. At runtime, retrieve the PEB pointer from the function argument (`RCX` on x64). Alternatively, read it directly from the TEB: `__readgsqword(0x60)` on x64 (TEB is at `GS:[0x30]`, `TEB.ProcessEnvironmentBlock` at offset `0x60`), or `__readfsdword(0x30)` on x86.
5. Walk `PEB->Ldr` (a `PEB_LDR_DATA*` at `PEB+0x18` on x64, `PEB+0x0C` on x86). The `InLoadOrderModuleList` is a `LIST_ENTRY` at `PEB_LDR_DATA+0x10`. Iterate the doubly-linked list; each entry is a `LDR_DATA_TABLE_ENTRY` whose `BaseDllName` (a `UNICODE_STRING` at offset `0x58` on x64) identifies the module. Find the entry where `BaseDllName.Buffer` points to `"ntdll.dll"` (case-insensitive).
6. Read `LDR_DATA_TABLE_ENTRY.DllBase` (offset `0x30` on x64) — this is ntdll's mapped base address. Cast it to `*mut IMAGE_DOS_HEADER` and parse the PE export directory.
7. Follow `e_lfanew` (`IMAGE_DOS_HEADER` offset `0x3C`, a `DWORD`) to `IMAGE_NT_HEADERS64`. Read `OptionalHeader.DataDirectory[0]` (`IMAGE_DIRECTORY_ENTRY_EXPORT`, at `IMAGE_NT_HEADERS64` offset `0x70+0x00` = the export directory RVA and size). Convert RVA to VA by finding the section containing the RVA (`VirtualAddress <= rva < VirtualAddress + VirtualSize`) and applying `PointerToRawData + (rva - VirtualAddress)` — but for a mapped image, RVA-to-VA is simply `DllBase + rva` because sections are mapped at their `VirtualAddress`.
8. Parse `IMAGE_EXPORT_DIRECTORY`: `AddressOfNames` (RVA to array of name RVA pointers), `AddressOfNameOrdinals` (RVA to array of `WORD` ordinals), `AddressOfFunctions` (RVA to array of function RVA pointers). For each needed export (e.g., `"NtAllocateVirtualMemory"`, `"NtWriteVirtualMemory"`, `"NtCreateThreadEx"`), linear-search `AddressOfNames`, use the index into `AddressOfNameOrdinals` to get the ordinal, then index into `AddressOfFunctions` to get the function RVA. Add `DllBase` to get the VA.
9. Optionally parse the SSN from the first bytes of each `Nt*` stub (`mov eax, imm32` at offset `0x04` from function start, the SSN is in the `imm32` operand) for direct-syscall inlining — see T-004 for the full PEB-walk-and-syscall-extract procedure.
10. Execute the payload using only `Nt*` / `Rtl*` functions. Use `NtAllocateVirtualMemory` for heap, `NtCreateFile` / `NtWriteFile` for I/O, `NtDeviceIoControlFile` (to `\Device\Afd` for raw sockets), `NtCreateThreadEx` for thread creation, `NtTerminateProcess` for exit.
11. Return an `NTSTATUS` from `NtProcessStartup`. The loader uses this as the process exit code (passed to `NtTerminateProcess` internally if the entry returns without calling it).

### Variant 2: Post-Link Subsystem Patch

1. Take any existing PE32+ executable (including a Rust binary compiled as a normal CUI binary with `--target x86_64-pc-windows-msvc`).
2. Read `IMAGE_DOS_HEADER.e_lfanew` at file offset `0x3C` to locate `IMAGE_NT_HEADERS64`.
3. Navigate to `IMAGE_OPTIONAL_HEADER64.Subsystem` at absolute file offset `e_lfanew + 0x18 + 0x44` = `e_lfanew + 0x5C`. For a typical MSVC binary with `e_lfanew = 0xF0`, the Subsystem `WORD` sits at file offset `0x14C`.
4. Overwrite the `WORD` from `0x0003` (`IMAGE_SUBSYSTEM_WINDOWS_CUI`) or `0x0002` (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) to `0x0001` (`IMAGE_SUBSYSTEM_NATIVE`).
5. **Critical**: the original entry point (`AddressOfEntryPoint` at `IMAGE_OPTIONAL_HEADER` offset `0x10`) points to `mainCRTStartup` in the CRT, which calls `kernel32!GetCommandLineA`, `kernel32!GetStartupInfoW`, and `kernel32!ExitProcess`. Since the loader will not pre-load `kernel32` for a native image, these calls fault immediately. Patch `AddressOfEntryPoint` to point to a custom `NtProcessStartup` stub, or inject a shellcode-style bootstrap that performs the PEB walk and then jumps to the original code after manually loading `kernel32` via `ntdll!LdrLoadDll`.
6. Alternatively, keep the CRT entry point but add `kernel32.dll` to the import table's `IMAGE_IMPORT_DESCRIPTOR` array (which the loader processes regardless of subsystem). This partially defeats the telemetry bypass — `kernel32` will appear in the loaded-module list and Sysmon EID 7 will fire for it — but avoids the need to rewrite the entry point.
7. Update the `CheckSum` field (at `IMAGE_OPTIONAL_HEADER` offset `0x40`) if the target validates it. Most user-mode loaders do not, but `NtCreateProcessEx` with certain flags can trigger a checksum verification path.
8. Test by launching from an elevated command prompt: `start /b myimplant.exe`. If the Subsystem patch is correct and the entry point is valid, the process runs without `kernel32` in its module list.

### Variant 3: Boot-Time Native Execution

1. Place the native executable in a path that `smss.exe` or `wininit.exe` will execute during boot. The standard mechanism is the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` value (`REG_MULTI_SZ`, default `"autocheck autochk *"`). Append the native exe's name and arguments.
2. `smss.exe` (itself a native subsystem binary) reads `BootExecute` during `SMSS` initialization phase and calls `NtCreateProcessEx` / `RtlCreateUserProcess` to launch each entry.
3. The child native process inherits `smss.exe`'s session (Session 0) and runs with `SYSTEM` integrity. No user session exists yet.
4. The implant can use `NtCreateThreadEx` to spawn additional work, `NtCreateFile` for disk I/O, and `NtDeviceIoControlFile` to `\Device\Tcpip` or `\Device\Afd` for network I/O — all before any user logs in.
5. **Prerequisite**: the binary must be signed or placed in a location that `smss.exe` trusts. `smss.exe` does not validate signatures on `BootExecute` entries, but `Code Integrity` (if HVCI is enabled) will block unsigned native images loaded before the CI policy is fully initialized. On standard (non-HVCI) systems, unsigned native images execute freely during boot.

## OS Internals Context

When `NtCreateUserProcess` (or the legacy `NtCreateProcessEx`) creates a new process, the kernel (`PspAllocateProcess`) builds the `EPROCESS`, calls `MmCreateProcessAddressSpace` to initialize the page-table hierarchy, and allocates the PEB at a user-mode address via `MmCreatePeb`. The PEB is populated with pointers to `KUSER_SHARED_DATA` (the read-only page at `0x7FFE0000` that mirrors time, tick count, and system parameters), the process's `ImageBaseAddress`, and an empty `PEB_LDR_DATA` structure. The kernel then maps the main executable image by calling `MmMapViewOfSection` with the image's section object (`SEC_IMAGE = 0x01000000`), honoring the `IMAGE_OPTIONAL_HEADER.ImageBase` field (relocating if the preferred base is unavailable). Critically, the kernel also maps `ntdll.dll` into every process unconditionally — it is the only DLL that exists in every process regardless of subsystem, and its presence is guaranteed before the loader's user-mode code begins.

The initial thread is created with its `CONTEXT` pointing to `ntdll!LdrInitializeThunk`. When the thread first transitions to user mode, it lands in `LdrInitializeThunk`, which calls `LdrpInitialize` → `LdrpInitializeProcess`. This function reads `PEB->ImageSubSystem` (copied from the PE's `IMAGE_OPTIONAL_HEADER.Subsystem` by `MmCreatePeb`) and branches accordingly. For `IMAGE_SUBSYSTEM_NATIVE` (`1`), the loader skips the entire Win32 initialization path: no `kernel32!BaseDllInitialize`, no `user32!_UserClientDllInitialize`, no `gdi32!GdiDllInitialize`, no `win32u!Win32uClientDllInitialize`. The `PEB->KernelCallbackTable` field (offset `0x58` on x64) — which `user32.dll` populates with a pointer to a dispatch table for `NtUserCallNoParam` / `NtUserCallOneParam` etc. — remains `NULL`. The `PEB->SubSystemData` (offset `0x48`) also stays `NULL`.

What the loader *does* still do for native processes:

- **Import resolution**: The `IMAGE_IMPORT_DESCRIPTOR` array (pointed to by `DataDirectory[1]` at `IMAGE_NT_HEADERS64` offset `0x70+0x08`) is processed. If the PE imports from `ntdll.dll`, those thunks are resolved. If it imports from `kernel32.dll`, the loader will attempt to load `kernel32.dll` via `LdrpLoadDll` → `NtOpenFile` / `NtCreateSection` / `NtMapViewOfSection`. This is the nuance: setting `Subsystem = NATIVE` does not prevent imported DLLs from loading; it prevents the loader from *automatically* loading the Win32 subsystem DLLs. A native PE with zero imports from `kernel32` will never have `kernel32` in its address space.
- **TLS callbacks**: The `IMAGE_TLS_DIRECTORY` (pointed to by `DataDirectory[9]` at `IMAGE_NT_HEADERS64` offset `0x70+0x48`) is honored. Each callback in `AddressOfCallBacks` is called via `LdrpCallTlsInitializers` before the entry point, with `DLL_PROCESS_ATTACH` (reason `1`) as the third argument. This runs even for native subsystem images — an implant can use TLS callbacks to execute code before `NtProcessStartup` is reached.
- **Relocations**: The `IMAGE_BASE_RELOCATION` table (`DataDirectory[5]`) is applied if the image was not loaded at its preferred `ImageBase`.
- **SEH tables**: On x64, the `IMAGE_RUNTIME_FUNCTION_ENTRY` array (`DataDirectory[3]`) is registered with `RtlAddFunctionTable` so that `RtlpExecuteHandlerForException` can unwind through the implant's functions.

After all initialization phases complete, the loader calls the entry point. The call mechanism on x64 is:

```
mov rcx, [peb_pointer]     ; first argument = PEB
xor rdx, rdx               ; second argument = 0 (reserved)
call [ImageBase + AddressOfEntryPoint]
; return value (NTSTATUS) is passed to NtTerminateProcess
```

The PEB pointer itself comes from the TEB. The TEB is allocated by `PspAllocateThread` and its `ProcessEnvironmentBlock` field (offset `0x60` on x64) is set to the PEB address. The entry point can retrieve it via `__readgsqword(0x60)` — but it does not need to, because the loader passes it in `RCX`.

The `PEB_LDR_DATA` structure (pointed to by `PEB->Ldr` at `PEB+0x18` on x64) contains three doubly-linked lists: `InLoadOrderModuleList` (offset `0x10`), `InMemoryOrderModuleList` (offset `0x20`), and `InInitializationOrderModuleList` (offset `0x30`). For a native process with no imports, only `ntdll.dll` appears in these lists. Each node is a `LDR_DATA_TABLE_ENTRY`:

- `InLoadOrderLinks` (offset `0x00`, a `LIST_ENTRY`) — links the `InLoadOrderModuleList`
- `InMemoryOrderLinks` (offset `0x10`) — links `InMemoryOrderModuleList`
- `DllBase` (offset `0x30` on x64) — mapped base address of the module
- `EntryPoint` (offset `0x38` on x64) — `DllMain` address (or `NULL` for exe entry)
- `SizeOfImage` (offset `0x40` on x64)
- `FullDllName` (offset `0x48`, a `UNICODE_STRING`) — full path
- `BaseDllName` (offset `0x58`, a `UNICODE_STRING`) — filename only

The `UNICODE_STRING` structure is `{ USHORT Length; USHORT MaximumLength; PWSTR Buffer; }` — 16 bytes on x64. `Length` is in bytes (not characters), and `Buffer` points to a UTF-16LE string. To compare `BaseDllName` against `"ntdll.dll"`, use `RtlEqualUnicodeString` or a hand-rolled case-insensitive UTF-16 compare (`ntdll.dll` vs `NTDLL.DLL` vs `Ntdll.Dll` — all valid).

`ntdll.dll`'s export directory (`IMAGE_EXPORT_DIRECTORY`) at `DllBase + DataDirectory[0].VirtualAddress` contains:

- `NumberOfNames` (offset `0x18` in the struct) — count of named exports
- `AddressOfFunctions` (offset `0x1C`) — RVA to `DWORD[]` of function RVAs
- `AddressOfNames` (offset `0x20`) — RVA to `DWORD[]` of name RVAs (sorted ascending by string compare)
- `AddressOfNameOrdinals` (offset `0x24`) — RVA to `WORD[]` of ordinals

The lookup procedure: linear-scan `AddressOfNames[i]`, compare the string at `DllBase + AddressOfNames[i]` against the target name; on match, read `ordinal = AddressOfNameOrdinals[i]`; the function VA is `DllBase + AddressOfFunctions[ordinal]`. Binary search is valid because names are sorted, but the linear scan is simpler and `ntdll` exports are ~2,000 entries.

Each `Nt*` syscall stub in ntdll follows a predictable pattern on x64:

```
4C 8B D1                    mov r10, rcx           ; save first arg
B8 xx xx 00 00              mov eax, <SSN>          ; syscall number
F6 04 25 08 03 FE 7F 01     test byte [0x7FFE0308], 1  ; KUSER_SHARED_DATA.SystemCall
75 03                       jne +3                  ; if set, use indirect path
0F 05                       syscall
C3                          ret
CD 03                       int 3                   ; alternate path
0F C7 7? F?                  ...                     ; syscall instr after alternative
```

The SSN (`imm32` at stub offset `0x04`, the `B8 xx xx 00 00` operand) can be extracted and inlined into a direct-syscall stub, bypassing the ntdll wrapper entirely. This eliminates the `ntdll!Nt*` function call from stack traces and avoids any user-mode hooks placed on ntdll's export table.

## Byte-Level Layout

The `Subsystem` field in a PE32+ image:

```
Offset from file start:
  0x00: IMAGE_DOS_HEADER
        ...
  0x3C: e_lfanew (DWORD) → e.g., 0xF0 0x00 0x00 0x00 (points to 0xF0)
        ...
  0xF0: IMAGE_NT_HEADERS64
        0xF0: Signature (DWORD) = 0x00004550 ("PE\0\0")
        0xF4: IMAGE_FILE_HEADER (20 bytes)
              0xF4: Machine (WORD) = 0x8664 (IMAGE_FILE_MACHINE_AMD64)
              0xF6: NumberOfSections (WORD)
              0xF8: TimeDateStamp (DWORD)
              0xFC: PointerToSymbolTable (DWORD)
              0x100: NumberOfSymbols (DWORD)
              0x104: SizeOfOptionalHeader (WORD) = 0xF0 (240)
              0x106: Characteristics (WORD)
        0x108: IMAGE_OPTIONAL_HEADER64 (240 bytes)
              0x108: Magic (WORD) = 0x020B (PE32+)
              ...
              0x140: CheckSum (DWORD)
              0x144: Subsystem (WORD) = 0x0001 (IMAGE_SUBSYSTEM_NATIVE) ← target field
              0x146: DllCharacteristics (WORD)
              ...
```

To patch a GUI exe (`Subsystem = 0x0002`) to native, write `0x01 0x00` at file offset `e_lfanew + 0x5C`:

```python
# e_lfanew at 0x3C, Subsystem at e_lfanew + 0x5C
import struct
with open("implant.exe", "r+b") as f:
    f.seek(0x3C)
    e_lfanew = struct.unpack("<I", f.read(4))[0]
    f.seek(e_lfanew + 0x5C)
    old = struct.unpack("<H", f.read(2))[0]
    f.seek(e_lfanew + 0x5C)
    f.write(struct.pack("<H", 1))  # IMAGE_SUBSYSTEM_NATIVE
    print(f"Subsystem: 0x{old:04X} → 0x0001")
```

## Key Implementation Details

**Entry-point signature**: The loader calls `AddressOfEntryPoint` with one argument (the PEB pointer) on x64. The return type is `NTSTATUS` — a `LONG` (32-bit signed). The loader passes the return value to `NtTerminateProcess(CurrentProcess, status)` if the entry point returns without calling it. On x86, the argument is at `[ESP+4]` (the return address occupies `[ESP]`). Rust's `extern "C"` maps to the x64 default calling convention (`__fastcall` variant with `RCX/RDX/R8/R9` for the first four integer args), so `extern "C" fn NtProcessStartup(peb: *mut PEB) -> i32` is the correct signature. Use `#[no_mangle]` to prevent name decoration.

**Linker flags**: With `lld-link` (the linker used by `x86_64-pc-windows-msvc`), pass `/SUBSYSTEM:NATIVE,6.0` in `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/SUBSYSTEM:NATIVE,6.0", "-C", "link-arg=/NODEFAULTLIB", "-C", "link-arg=/ENTRY:NtProcessStartup"]
```

`/NODEFAULTLIB` prevents the linker from pulling in the CRT (which imports from `kernel32`). The `6.0` is `MajorSubsystemVersion`; Windows 10 build 14393+ requires `MajorSubsystemVersion >= 6` or the loader rejects the image with `STATUS_INVALID_IMAGE_NOT_MZ` during `NtCreateUserProcess`. `MinorSubsystemVersion` is optional (default `0`).

**WOW64 boundary**: A 32-bit native exe on a 64-bit Windows runs under the WOW64 emulator. The PEB pointer passed to the entry point is the 32-bit PEB (at the `PEB32` address, typically `0x7FFD0000`-range). The 64-bit PEB (at `0x7FFD4000`-range on some builds) is accessible via `NtQueryInformationProcess(ProcessWow64Information)` but is not directly useful for a 32-bit implant. The `InLoadOrderModuleList` walk works identically — WOW64 maps `ntdll.dll` (32-bit) into the process.

**`MajorSubsystemVersion` gotcha**: Windows 10 1607 (build 14393) introduced a loader check that rejects images with `MajorSubsystemVersion < 6` or `MajorSubsystemVersion > current_os_major`. If you hand-patch the PE and leave `MajorSubsystemVersion` at `0` (as some packers do), the loader returns `STATUS_INVALID_IMAGE_FORMAT` (`0xC000007B`). Verify `IMAGE_OPTIONAL_HEADER.MajorSubsystemVersion` at offset `0x28` within the optional header is set to `6` or `10`.

**Import table design**: The cleanest native implant has zero imports — the entry point resolves everything via PEB walk. If you must import from `ntdll.dll` (e.g., for `RtlAllocateHeap`, `RtlInitUnicodeString`), the import descriptor is safe: the loader resolves ntdll exports without loading any additional DLLs. Any import from `kernel32.dll`, `user32.dll`, or `advapi32.dll` will cause those DLLs to load, defeating the telemetry bypass. Use `dumpbin /imports implant.exe` or `pe-bear` to verify the import table before deployment.

**Module list forensics**: A native implant's loaded-module list (queryable via `NtQueryInformationProcess` with `ProcessBasicInformation` → `PEB` → `Ldr`) will show only `ntdll.dll` and the main image. An EDR that enumerates modules will see this absence. Deliberately loading `kernel32.dll` via `LdrLoadDll` (with `L"kernel32.dll"` as the `DllPath` argument) to produce a more normal-looking module list is a tradeoff: it restores the expected `kernel32` entry but triggers `LdrLoadDll` telemetry and `Image Load` ETW events.

## Why It Matters

Native subsystem implants occupy a niche that standard process-injection and shellcode techniques do not: they are first-class processes with a normal `EPROCESS`, a valid `PEB`, a legitimate parent (whatever spawned them), and a standard process-creation callback trail — yet they execute entirely within the NT API surface, never touching the Win32 layer that most EDR instrumentation monitors. This makes them ideal for early-boot persistence (alongside `autochk.exe` in `BootExecute`), for Session 0 implants that run before any user session exists, and for environments where EDR coverage is concentrated on Win32 API hooks (`kernel32!CreateFileW`, `kernel32!VirtualAllocEx`, `user32!SetWindowsHookExW`).

The technique composes naturally with direct-syscall inlining (T-004) — once the PEB walk resolves `ntdll`'s base, the SSN extraction and inline `syscall` stub pattern eliminates even the ntdll-level function-call trace. It also composes with PE-header patching (T-022) for post-link conversion of existing tooling. The primary limitation is operational: any non-Windows binary with `IMAGE_SUBSYSTEM_NATIVE` is a high-signal static finding, so the implant must either avoid being captured on disk (execute from memory via `NtCreateSection` + `NtMapViewOfSection`, then `NtCreateProcessEx`) or use a packer that restores the Subsystem field at runtime before the loader inspects it — which is itself a nontrivial engineering challenge because the loader reads the Subsystem from the mapped image during `LdrpInitializeProcess`, before user code runs.

## Detection Considerations

- **Telemetry sources**: `PsSetCreateProcessNotifyRoutineEx` fires unconditionally — the kernel calls every registered callback with `PS_CREATE_NOTIFY_INFO` containing the image path. The `IMAGE_OPTIONAL_HEADER.Subsystem` field is readable from the mapped image via `NtQueryInformationProcess(ProcessImageFileName)` → open the file → parse PE headers. ETW `Microsoft-Windows-Kernel-Process` (Event ID 1) and Sysmon EID 1 both capture process creation. Sysmon EID 7 (Image Load) will show `ntdll.dll` loading but **not** `kernel32.dll` / `user32.dll` / `gdi32.dll` — the absence is itself a signal. ETW `Microsoft-Windows-Kernel-Image` (Image Load / Image Unload events) shows the same pattern.
- **Bypass options**: To suppress the "no kernel32" signal, call `LdrLoadDll` with `L"kernel32.dll"` early in the implant — this loads `kernel32` and produces the expected module list, at the cost of generating `Image Load` events and populating `PEB->Ldr` with the Win32 DLL entries. To evade static analysis of the Subsystem field, execute from memory: create a native image in a `SEC_COMMIT` section, map it, and call `NtCreateProcessEx` — the on-disk artifact never exists with `Subsystem = NATIVE`. Alternatively, use a polymorphic packer that stores the real PE encrypted and decrypts in a TLS callback, but the loader still reads `Subsystem` from the mapped image, so the field must be `NATIVE` in the in-memory copy.
- **Residual artifacts**: Process tree entry with the native exe's path (captured by Sysmon EID 1 and `PsSetCreateProcessNotifyRoutineEx`). Prefetch entry for the on-disk binary (`.pf` file in `C:\Windows\Prefetch\`). If the implant touches the registry, `NtSetValueKey` produces registry transaction log entries (`.LOG1`/`.LOG2` for the target hive). The `EPROCESS.ImageFileName` field (offset `0x5A8` on Windows 10 1903 x64, varies by build) stores the 15-char truncated image name for kernel callbacks. `MmPfnDatabase` entries for the image's pages carry the section object pointer and `PrototypePte` references that persist until the process exits. If HVCI (hypervisor-protected code integrity) is enabled, unsigned native images are blocked and the block is logged in `Microsoft-Windows-CodeIntegrity` ETW.

## Composition with Other Techniques

A realistic kill chain using native subsystem execution:

1. **Initial access** delivers a staged native PE via a phishing document's macro or a browser exploit. The stager runs as shellcode (standard position-independent code) in the exploited process.
2. **Memory deployment**: The shellcode calls `NtCreateSection` (`SEC_COMMIT`, `PAGE_EXECUTE_READWRITE = 0x40` initially) → `NtMapViewOfSection` to allocate executable memory → `RtlMoveMemory` copies the native PE bytes into the section → `NtProtectVirtualMemory` changes the view to `PAGE_EXECUTE_READ` (`0x20`). The shellcode then calls `NtCreateProcessEx` with `ProcessParameters` pointing to a minimal `RTL_USER_PROCESS_PARAMETERS` (created via `RtlCreateProcessParametersEx`), and the section handle as the image section.
3. **Thread creation**: `NtCreateThreadEx` on the new process, starting at `ntdll!LdrInitializeThunk` (the kernel sets this automatically — actually, `NtCreateProcessEx` does not create a thread; the operator must call `NtCreateThreadEx` with `StartAddress = entry_point_RVA + image_base` or use `NtCreateUserProcess` instead which handles thread creation).
4. **Native implant executes**: The new process's entry point (`NtProcessStartup`) receives the PEB, walks the loader list, resolves `ntdll` exports, and begins C2 via `NtDeviceIoControlFile` to `\Device\Afd` (raw TCP socket) or `\Device\Tcpip` (direct TDI/TCP interface).
5. **Persistence**: The implant writes to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` (via `NtCreateKey` / `NtSetValueKey`) to schedule itself for boot-time execution as a native process launched by `smss.exe`.
6. **Concealment**: Composes with T-022 (PE patching) to ensure the on-disk copy has `Subsystem = NATIVE` and minimal imports, and with T-004 (PEB walk + direct syscalls) to eliminate all ntdll-level function-call traces.

## Common Mistakes

1. **Leaving CRT imports in the PE**: The most frequent failure. A Rust binary compiled without `#![no_std]` imports `kernel32!HeapAlloc`, `kernel32!GetLastError`, `kernel32!ExitProcess` from the CRT's runtime. The linker succeeds (because `/SUBSYSTEM:NATIVE` doesn't prevent kernel32 imports — it just doesn't auto-load kernel32). At runtime, the loader resolves the kernel32 import by loading kernel32.dll, which fires `Image Load` telemetry. The binary "works" but the telemetry bypass is voided. Fix: use `#![no_std]` and provide a custom `#[panic_handler]` that calls `NtTerminateProcess` directly.
2. **Wrong `MajorSubsystemVersion`**: Setting `Subsystem = 1` but leaving `MajorSubsystemVersion = 0` (common in hand-assembled PEs) causes the loader to reject the image with `STATUS_INVALID_IMAGE_FORMAT` on Windows 10 1607+. The loader checks `MajorSubsystemVersion >= 6` during `MiVerifyImageHeader`. Fix: set `IMAGE_OPTIONAL_HEADER.MajorSubsystemVersion` to `6` or `10`.
3. **Forgetting TLS callbacks run before entry**: If the PE has a TLS directory with callbacks (some linkers insert a default TLS callback for CRT initialization), those callbacks run *before* `NtProcessStartup`. If the callback calls `kernel32!TlsAlloc`, it faults. Fix: strip the TLS directory (`DataDirectory[9].VirtualAddress = 0` and `DataDirectory[9].Size = 0`) or ensure callbacks only use ntdll functions.
4. **x86 entry-point argument retrieval**: On x86, the PEB is at `[ESP+4]` after the `CALL` instruction that enters `NtProcessStartup`. But if the compiler inserts a prologue (`push ebp; mov ebp, esp`) before reading arguments, the offset shifts to `[EBP+8]`. Use `__readfsdword(0x30)` instead of relying on the stack layout — it reads `TEB.ProcessEnvironmentBlock` at `FS:[0x30]` and is immune to prologue interference.
5. **Case sensitivity in `BaseDllName` comparison**: `ntdll`'s `LDR_DATA_TABLE_ENTRY.BaseDllName` may be `"ntdll.dll"`, `"NTDLL.DLL"`, or `"Ntdll.Dll"` depending on the boot path. A byte-exact compare against `"ntdll.dll"` will fail on some systems. Use `RtlEqualUnicodeString` with `CaseInSensitive = TRUE` or implement a case-insensitive UTF-16 compare.
6. **Assuming `kernel32` is never loaded**: Setting `Subsystem = NATIVE` does not prevent the loader from loading `kernel32` if the import table references it. The subsystem field controls *automatic* subsystem DLL initialization, not import resolution. An import from `kernel32!ExitProcess` in the PE's import table will cause `kernel32.dll` to load, regardless of the subsystem field. Verify with `dumpbin /headers` and `dumpbin /imports` before deployment.

## Related Techniques

- **T-004 PEB Walk / Direct Syscall Extraction** — The export-resolution procedure documented here (walk `InLoadOrderModuleList`, parse `IMAGE_EXPORT_DIRECTORY`, extract SSN from stub bytes) is the same primitive. This card covers the PE-format and loader-path mechanics that make it a standalone process; T-004 covers the PEB-walk details in the context of injected shellcode.
- **T-022 PE Header Patching** — Post-link Subsystem field modification is a specific instance of PE-header patching. T-022 covers the broader patching toolkit (checksum recalculation, section-header manipulation, import-table reconstruction) that the post-link variant of this technique depends on.
- **T-095 NTDLL Unhook Typology** — Native implants that use ntdll's `Nt*` exports directly are affected by ntdll unhooking. If an EDR has placed `jmp` trampolines in ntdll's syscall stubs, the SSN extracted from the stub bytes is still correct (the `mov eax, imm32` is preserved even in hooked stubs), but calling the ntdll wrapper triggers the hook. Direct syscalls bypass this; T-095 documents the unhooking landscape.
- **T-034 IFEO / SilentProcessExit** — Boot-time native execution via `BootExecute` is conceptually parallel to IFEO debugger injection: both hijack a legitimate process-launch path to execute attacker code early in the boot sequence. IFEO targets Win32 processes; `BootExecute` targets native processes spawned by `smss.exe`.