---
id: T-138
name: UACMe Auto-Elevation DLL Search-Order Hijack
category: privesc
tier: A
crate: none
source_file: none
mitre: T1548.002
mitre_secondary: [T1574.001]
tags: [uac-bypass, autoelevate-manifest, dll-search-order, fusion-loader, sxs-private-assembly, ifileoperation, system32-plant, medium-integrity-admin, privesc]
origin: atlas-synthesis
member_notes: ['lgtm:uacme-dll-search-order-hijack']
---

# UACMe Auto-Elevation DLL Search-Order Hijack — Silent-elevation via planted DLLs on auto-elevated System32 binaries

## Summary

The UACMe FusionScanDirectory technique bypasses User Account Control by hijacking the DLL resolution path of an auto-elevated binary resident in `%SystemRoot%\System32\`. A binary qualifies as auto-elevated when its embedded application manifest (resource type `RT_MANIFEST` = `MAKEINTRESOURCE(24)`, ID `1`) carries the Windows-Settings flag `<autoElevate xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</autoElevate>`. When such a binary is launched from a medium-integrity caller whose token is a member of the local Administrators group, the Application Information Service (`appinfo.dll`, hosted in `svchost.exe -k appinfo` running as LocalSystem) silently elevates the process — no consent dialog, no `secure desktop` switch, no `consent.exe` invocation. The operator enumerates the binary's directory for plantable DLL names using `FindFirstFileW` / `FindNextFileW` against a `WIN32_FIND_DATAW` structure cleared by `RtlSecureZeroMemory` between iterations, matches candidates against the target binary's `IMAGE_IMPORT_DESCRIPTOR` table (or its manifest `<dependentAssembly>` list), plants a malicious DLL with the matching name into a path the loader probes before — or in place of — the legitimate copy, then triggers the binary. The planted `DllMain` executes at high integrity, yielding elevated code execution. Planting itself requires a second auto-elevated primitive: by default the `IFileOperation` COM interface (CLSID `{3AD50546-6716-4FC0-8B71-E2B5B5C5C6E8}`, IID `IID_IFileOperation`, invoked via the `Elevation:Administrator!new:{...}` moniker with a `BIND_OPTS3` whose `dwClassContext = CLSCTX_LOCAL_SERVER`) writes the DLL into `System32` (or a sub-directory the Fusion loader probes) without a prompt. Common exemplar targets include `slui.exe`, `dccw.exe`, `eventvwr.exe`, and `ComputerDefaults.exe`. Unlike T-021 (COM CLSID Hijack), which mutates `HKCU\Software\Classes\CLSID\{...}\InProcServer32` to redirect a `CoCreateInstance` call without planting a file, this card covers file-system planting coupled with the loader's directory-probing behavior; the two techniques compose when a hijacked CLSID is used to launch the auto-elevated binary that then loads the planted DLL. T-023 covers a complementary registry-side auto-elevation primitive; together they cover both halves of the auto-elevate threat surface.

## Mechanism

### Variant 1: Direct System32 Plant via IFileOperation (classic slc.dll / sppcomapi.dll / dismcore.dll hijacks)

1. Identify the target auto-elevated binary. Confirm the `autoElevate` manifest flag by extracting the `RT_MANIFEST` resource with `FindResource(NULL, MAKEINTRESOURCE(1), RT_MANIFEST)` followed by `LoadResource` + `LockResource`, then parsing the XML for the `<autoElevate>true</autoElevate>` element.
2. Resolve the binary's import table: walk `IMAGE_DOS_HEADER.e_lfanew` (offset `0x3C`) → `IMAGE_NT_HEADERS64` (signature `0x00004550`) → `OptionalHeader.DataDirectory[1]` (Import Directory). Iterate `IMAGE_IMPORT_DESCRIPTOR` entries until `OriginalFirstThunk == 0` and `Name == 0`. Each `Name` RVA points to a null-terminated DLL name string. Filter out `ntdll.dll`, `kernel32.dll`, `KERNELBASE.dll`, and any DLL whose name is unqualified (e.g., `slc.dll`, `sppcomapi.dll`, `dismcore.dll`, `winsat.exe`'s sub-loaded dependencies) — these are candidates.
3. Cross-reference candidate imports against actual files in `System32`:
   ```c
   WIN32_FIND_DATAW fd;
   RtlSecureZeroMemory(&fd, sizeof(fd));   // 592 bytes on x64
   HANDLE h = FindFirstFileW(L"C:\\Windows\\System32\\*.dll", &fd);
   if (h != INVALID_HANDLE_VALUE) {
       do {
           // match fd.cFileName against candidate import list
           RtlSecureZeroMemory(&fd, sizeof(fd));
       } while (FindNextFileW(h, &fd));
       FindClose(h);
   }
   ```
   `RtlSecureZeroMemory` between iterations is non-negotiable: `FindNextFileW` only writes the fields it populates, so residual data from the previous entry (e.g., a long file name in `cFileName[260]`) would otherwise leak into the next comparison and produce false matches.
4. Select a candidate DLL name that the binary loads via `LoadLibrary("name.dll")` — i.e., the IAT entry's `Name` string is unqualified, not a full path. Verify by attaching a debugger or static analysis of `IMAGE_IMPORT_DESCRIPTOR.FirstThunk` post-load.
5. Generate the malicious DLL with matching name. If the binary actually calls exports from the hijacked DLL (vs. just loading it for side effects), include an export-forwarding stub: `.def` file with `EXPORTS slcFunc1 = C:\\Windows\\System32\\slc_orig.dll.slcFunc1` or, at runtime, parse the original DLL's `IMAGE_EXPORT_DIRECTORY` and forward each `IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[i]` entry via `GetProcAddress(GetModuleHandle(L"slc_orig"), name)`. Without forwarding, the binary's first call to a missing export will fault.
6. Build the payload's `DllMain` to:
   - Persist itself (optional: copy to a stable location via `MoveFileExW` with `MOVEFILE_DELAY_UNTIL_REBOOT`)
   - Perform the high-integrity action (token theft, service installation, registry mutation under `HKLM`, scheduled task creation via `ITaskService` at `\\ROOT\Microsoft\Windows\TaskScheduler`)
   - Return `TRUE` from `DllMain` immediately; do not block on network I/O or the loader lock will deadlock (`LdrpLoaderLock` held during `DLL_PROCESS_ATTACH`).
7. Plant the DLL using `IFileOperation`:
   ```c
   BIND_OPTS3 bo = {0};
   bo.cbStruct = sizeof(BIND_OPTS3);
   bo.dwClassContext = CLSCTX_LOCAL_SERVER;
   IFileOperation *pfo;
   CoGetObject(L"Elevation:Administrator!new:{3AD50546-6716-4FC0-8B71-E2B5B5C5C6E8}",
              (BIND_OPTS*)&bo, &IID_IFileOperation, (void**)&pfo);
   pfo->lpVtbl->SetOperationFlags(pfo, FOF_NOCONFIRMATION | FOF_SILENT);
   IShellItem *src;
   SHCreateItemFromParsingName(L"C:\\Users\\Public\\payload\\slc.dll", NULL,
                              &IID_IShellItem, (void**)&src);
   pfo->lpVtbl->CopyItem(pfo, src, dest_folder, L"slc.dll", NULL);
   pfo->lpVtbl->PerformOperations(pfo);
   ```
   The moniker binding causes `ole32!CoGetObject` → `ole32!BindMoniker` → `ole32!ResolveMoniker` to invoke the elevation path, which (since the AppID of `IFileOperation` has `ElevationEnabled=1` under `HKCR\AppID\{<AppID>}`) hands the request to `appinfo.dll`, which spawns an elevated `svchost`-hosted instance without a consent prompt.
8. If `System32\<name>.dll` is in use (rare for licensing DLLs but possible for `sppcomapi.dll` when the Software Protection service is active), first rename the original via `IFileOperation::RenameItem` to a `.bak` extension, then plant the payload under the original name.
9. Trigger the auto-elevated binary:
   ```c
   SHELLEXECUTEINFOW sei = {0};
   sei.cbSize = sizeof(sei);
   sei.fMask = SEE_MASK_NOCLOSEPROCESS;
   sei.lpFile = L"C:\\Windows\\System32\\ComputerDefaults.exe"; // or slui.exe, dccw.exe
   ShellExecuteExW(&sei);
   ```
   `ShellExecuteExW` routes through `shell32!ShellExecuteExW` → `shell32!ExecuteRunAsVerb` when the binary's manifest requests elevation, sending the request to `appinfo.dll` via the `RAiLaunchUmsThread`/`RAiElevationCheck` RPC.
10. `appinfo.dll` validates: (a) caller's token is medium integrity (`SECURITY_MANDATORY_MEDIUM_RID`), (b) caller is a member of `S-1-5-32-544` (Administrators), (c) binary path is under a "secure" directory (`%SystemRoot%\System32`, `%SystemRoot%\SysWOW64`, `%ProgramFiles%`, `%ProgramFiles(x86)%`), (d) binary's manifest `autoElevate=true`, (e) binary is signed by a Microsoft-trusted cert (default config) or caller has approved the publisher. All conditions met → silent elevation.
11. `appinfo.dll` calls `NtCreateUserProcess` (or `NtCreateProcessEx` on legacy builds) with the elevated token obtained from `SeExchangePrimaryToken` against the caller's linked token (`TOKENLinked`). The new process starts at high integrity (`SECURITY_MANDATORY_HIGH_RID`) with `TOKEN_MANDATORY_LABEL.TokenIntegrityLevel = SECURITY_MANDATORY_HIGH_RID`.
12. The loader (`ntdll!LdrpInitializeProcess`) resolves the binary's imports. For `slc.dll` (or whatever candidate), it follows the default search order. With SafeDllSearchMode enabled (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1`, the default since XP SP2), the order is: (1) the directory the executable loaded from — `System32` itself — so the planted DLL wins. The legitimate copy was either renamed or overwritten.
13. The planted DLL's `DllMain` executes at high integrity. The host process is now compromised.

### Variant 2: SxS / Fusion Private-Assembly Subdirectory Probe

1. Identify an auto-elevated binary whose manifest contains a `<dependentAssembly>` entry referencing an assembly name that is **not** present in the WinSxS store (`%SystemRoot%\WinSxS\`). Such manifests reference external assemblies — frequently the `Microsoft.Windows.Common-Controls` or application-private assemblies — but the operator targets manifests whose `<assemblyIdentity>`'s `name` attribute resolves to a directory that doesn't yet exist under `System32`.
2. The Fusion/SxS loader (invoked by `ntdll!LdrpInitializeProcess` via `sxs.dll!SxsActivationContextCache` and `sxs.dll!SxsProber`) probes in this order for a private assembly:
   - `%SystemRoot%\WinSxS\<assemblyName>\<assemblyName>.manifest` (and policies under `WinSxS\Policies`)
   - `<binarydir>\<assemblyName>.manifest`
   - `<binarydir>\<assemblyName>\<assemblyName>.manifest`
   - `<binarydir>\<assemblyName>\<assemblyName>.dll`
   where `<binarydir>` is `C:\Windows\System32` for our exemplars.
3. If the assembly name does not exist in WinSxS, the loader falls back to private probing and will look at `C:\Windows\System32\<assemblyName>\<assemblyName>.dll`. This subdirectory does not exist by default and is not created by Windows.
4. Use `IFileOperation` (the Variant 1 step 7 pattern) to:
   - Create `C:\Windows\System32\<assemblyName>\` (via `IFileOperation::NewItem` with `FILE_ATTRIBUTE_DIRECTORY`)
   - Copy the malicious DLL to `C:\Windows\System32\<assemblyName>\<assemblyName>.dll`
5. Trigger the binary. The Fusion loader fails to find the assembly in WinSxS, fails to find a private `.manifest` file, falls back to the `<assemblyName>.dll` probe in the private subdirectory, and loads the planted DLL.
6. The DLL's `DllMain` executes inside the elevated process. Note that exports are not required: the Fusion loader calls `LoadLibraryEx` with `LOAD_LIBRARY_AS_IMAGE_RESOURCE` semantics in some assembly-loading paths, but for private `<assemblyName>.dll` probes the standard `LdrLoadDll` path applies, and `DllMain` runs normally.

This variant is more surgical than Variant 1 — the planted file lives in a subdirectory whose name is unique to the manifest's assembly reference, so it doesn't overwrite any legitimate file and leaves the system in a fully recoverable state.

### Variant 3: LoadLibraryEx with LOAD_WITH_ALTERED_SEARCH_PATH (edge cases)

1. Identify an auto-elevated binary that calls `LoadLibraryExW(L"<relative_path>\\name.dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH)`. The `LOAD_WITH_ALTERED_SEARCH_PATH` flag (`0x8`) changes the search order so the directory of the `lpLibFileName` parameter (not the application directory) is searched first.
2. If the binary passes a path that resolves to a user-writable location (e.g., `.\plugins\somedll.dll` resolved against the current working directory), the operator plants the DLL at that resolved path.
3. Trigger the binary with the current working directory set to the writable location via `CreateProcessW(..., lpCurrentDirectory = L"C:\\Users\\Public\\payload", ...)`.
4. The loader resolves `.\plugins\somedll.dll` against the working directory, finds the planted DLL, and executes it at high integrity.

This variant is rare — most auto-elevated binaries don't use `LoadLibraryEx` with `LOAD_WITH_ALTERED_SEARCH_PATH` and unqualified paths. It exists mainly on binaries that load shell extensions or MMC snap-ins.

## OS Internals Context

### The auto-elevation flow

When `ShellExecuteExW` is called against a binary in a secure location, `shell32!ShellExecuteExW` inspects the binary's manifest. If `autoElevate=true` is detected and the caller is medium-integrity admin, `shell32` does not call `CreateProcessW` directly; it sends an RPC to the Application Information Service via `appinfo!RAiLaunchUmsThread` (and `RAiElevationCheck` for the pre-flight probe). The AppInfo service runs as a `svchost.exe` group `appinfo` instance under `LocalSystem`; its process image is `appinfo.dll`. The RPC interface UUID is `{e60c73e6-4f23-47f8-b3a0-7b3e6c8e9bdc}` (illustrative; verify against `appinfo.idl` in the WDK).

`RAiElevationCheck` performs the following:

- Extracts the binary's manifest resource (`FindResource(NULL, MAKEINTRESOURCE(1), RT_MANIFEST)` → `LoadResource` → `LockResource`). The manifest is XML; the parser (in `appinfo.dll`, using a custom `CXMLElement`-style walker) hunts for the `<autoElevate>` element in the `http://schemas.microsoft.com/SMI/2005/WindowsSettings` namespace and reads its text content.
- Calls `NtQueryInformationProcess` with the (then-current) caller's `ProcessBasicInformation` to obtain the caller's `PEB`, from which it reads `PEB->ProcessParameters->ImagePathName` to verify the launching image.
- Verifies the binary's path is under a "secure" prefix (`%SystemRoot%\System32\`, `%SystemRoot%\SysWOW64\`, `%ProgramFiles%\`, `%ProgramFiles(x86)%\`).
- Calls `WinVerifyTrust(NULL, WINTRUST_ACTION_GENERIC_VERIFY_V2, &wtData)` to verify the binary's Authenticode signature. The publisher is checked against the `HKLM\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher` store (and the user's `Cert:\CurrentUser\TrustedPublisher`).
- Calls `SeGetElevationFilter` / internally invokes `ZwQueryInformationToken` with `TokenLinked` (`TOKEN_INFORMATION_CLASS = 19`, value `TokenLinked`) on the caller's token. The linked token is the elevated counterpart of a split token; for a medium-integrity admin it carries `DISCRETIONARY_ACL` with the Admin SID and integrity level `SECURITY_MANDATORY_HIGH_RID`.
- Constructs the new process via `NtCreateUserProcess` with the linked (elevated) token as the primary token. The new `EPROCESS` gets `TokenObject` pointing to the duplicated linked token.

The `autoElevate` mechanism is gated by `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` (`DWORD`, must be `1`) and `EnableVirtualization`. When `EnableLUA=0`, UAC is disabled entirely and all processes inherit the parent's integrity — there is nothing to bypass.

### Manifest parsing & the autoElevate flag

The manifest XML namespace `http://schemas.microsoft.com/SMI/2005/WindowsSettings` carries several SMI (System-Management-Information) settings; `autoElevate` is one of them. The element looks like:

```xml
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Microsoft.Windows.ComputerDefaults" version="10.0.0.0"/>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <autoElevate xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</autoElevate>
    </windowsSettings>
  </application>
</assembly>
```

The parser walks `application → windowsSettings → autoElevate` (or `dpiAware`, `longPathAware`, etc., same namespace). The text content `true` (case-insensitive) enables the flag. Note that the `autoElevate` element does **not** exist in the public SMI schema documentation; it is internal to the AppInfo elevation logic.

To enumerate auto-elevated binaries, the operator can scan all executables in `System32` and `SysWOW64` for this manifest pattern. The UACMe project's `FusionScanDirectory` routine performs a related enumeration: it scans `System32` with `FindFirstFileW(L"*.dll", ...)` to identify DLL candidates, then checks the target binary's manifest for `<dependentAssembly>` entries whose `<assemblyIdentity>` name matches one of the file names found — these are the SxS private-assembly hijack candidates described in Variant 2.

### Fusion / SxS loader probing

The Side-by-Side (SxS) assembly resolution is implemented in `sxs.dll`, loaded during `ntdll!LdrpInitializeProcess`. The process is:

1. `ntdll!LdrpInitializeProcess` phase 0 calls `sxs.dll!SxsInit` and registers the process-default activation context.
2. The binary's `RT_MANIFEST` resource is read via `Nt mapped section` (the binary is already mapped as `SEC_IMAGE`). The XML is parsed into an `ACTCTX`-derived internal structure.
3. The activation context (`ACTIVATION_CONTEXT`) is built by `sxs.dll!SxsActivationContextCache` (cache hit) or `sxs.dll!RtlCreateActivationContext` (cache miss). The cache is global per-process under `ntdll!LdrpManifestCache`.
4. For each `<dependentAssembly>`, the loader queries `sxs.dll!SxsProber` (specifically `SxsResolveAssemblyReference`) which checks:
   - WinSxS store: `RtlAssemblyEnumerationStart` / `RtlAssemblyEnumerationNext` walks the manifest directories under `%SystemRoot%\WinSxS\`. The store uses directory names encoded with assembly name, version, architecture, language, and a hash. The lookup matches via `SxsLookupAssemblyInStore`.
   - Private probe: as listed in Variant 2. The probing paths are coded in `sxs.dll!SxsProbePath`.
5. If the assembly is found in WinSxS, the loader uses the `<file>` entries in the resolved manifest to map each DLL to a full path (the WinSxS directory plus the policy-resolved version). If only a private `.dll` is found, it is loaded directly via `LdrLoadDll`.

The private-probe paths are **not** subject to `SafeDllSearchMode`. They are absolute paths constructed by the Fusion loader, so the standard search order does not apply. This is the key property that makes Variant 2 work: even with `SafeDllSearchMode=1`, the loader will probe `C:\Windows\System32\<assemblyName>\<assemblyName>.dll` directly.

### Default DLL search order (Variant 1)

When `SafeDllSearchMode=1` (default), `LoadLibrary` resolves an unqualified DLL name in this order:

1. Directory the executable loaded from (for `ComputerDefaults.exe`, this is `C:\Windows\System32`)
2. `%SystemRoot%\System32`
3. `%SystemRoot%\SysWOW64` (for 32-bit callers) or 16-bit system directory
4. `%SystemRoot%`
5. Current working directory
6. `%SystemRoot%\System32\` directories listed in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls` (the `KnownDlls` cache redirects specific names — `user32`, `kernel32`, `ntdll` etc. — to pre-mapped section objects, defeating hijacks)
7. Directories in the `PATH` environment variable

Variant 1 exploits step 1: planting the DLL in `System32` itself guarantees the loader resolves to the planted file, since `System32` is the binary's own directory. The only defense is the `KnownDlls` cache, which protects ~30 specific system DLLs but not licensing or app-specific DLLs like `slc.dll`, `sppcomapi.dll`, `dismcore.dll`.

### IFileOperation auto-elevation

The `IFileOperation` interface is hosted in `shell32.dll` and exposed as a Co-creatable COM class. Its CLSID is `{3AD50546-6716-4FC0-8B71-E2B5B5C5C6E8}`. The AppID is registered under `HKCR\AppID\{<AppID>}` with `ElevationEnabled=dword:1`. When the `Elevation:Administrator!new:` moniker is bound with `dwClassContext = CLSCTX_LOCAL_SERVER`, the COM runtime (`ole32!CoGetObject` → `ole32!CoGetClassObject` → `ole32!InternalGetClassObject`) detects the elevation attribute and asks AppInfo to launch a new `dllhost.exe` (the COM surrogate) running under the linked (elevated) token.

The surrogate process loads `shell32.dll` and instantiates the `IFileOperation` object; all subsequent method calls (`CopyItem`, `MoveItem`, `NewItem`, `RenameItem`, `PerformOperations`) execute in the elevated surrogate, and file operations apply to the elevated token's security context — meaning the operator can write to `System32`. The RPC channel between the caller and the surrogate is the standard COM marshaling infrastructure.

### FindFirstFile / FindNextFile

`FindFirstFileW(L"<path>\\<pattern>", &fd)` opens a directory handle via `NtCreateFile` with `FILE_LIST_DIRECTORY | SYNCHRONIZE` access, then issues `NtQueryDirectoryFile` with `FileBothDirectoryInformation` (info class `3`) or `FileIdBothDirectoryInformation` (info class `37`) to fill the user's `WIN32_FIND_DATAW`. The first matching entry is returned in the structure; the handle is kept open for `FindNextFileW`, which calls `NtQueryDirectoryFile` again with the same handle to fetch subsequent entries.

The `WIN32_FIND_DATAW` structure is 592 bytes on x64. `NtQueryDirectoryFile` only writes the fields it needs; for `FileBothDirectoryInformation` it writes a `FILE_BOTH_DIR_INFORMATION` structure which `kernel32` translates to `WIN32_FIND_DATAW`. Fields past the end of the actual file name are not zeroed by the kernel, so leftover data from a previous call persists in the structure. This is why UACMe calls `RtlSecureZeroMemory(&fd, sizeof(fd))` between iterations — without it, `fd.cFileName` may contain residual characters from the previous file name appended to the new one, producing false matches during the candidate-scan loop.

`FindClose` issues `NtClose` on the directory handle.

### Token / privilege requirements

The caller's token must satisfy:

- Medium integrity: `TOKEN_MANDATORY_LABEL.TokenIntegrityLevel.IntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID` (`0x2000`)
- Group membership includes `S-1-5-32-544` (Administrators) with `SE_GROUP_ENABLED | SE_GROUP_MANDATORY` attributes (the typical split-token admin state)
- `SeImpersonatePrivilege` is not required (the COM surrogate handles cross-process marshaling via the RPC endpoint mapper)
- The process must not be running under `AppLocker` or `WDAC` (Windows Defender Application Control) policies that block unsigned DLL loads into elevated processes — `WDAC` with `Option 6: Whitney` would block the planted DLL from loading into the elevated `ComputerDefaults.exe`.

## Key Implementation Details

**Export forwarding is the silent killer.** Most operators plant a DLL whose only export is `DllMain`. The host binary (e.g., `ComputerDefaults.exe` calling `slc.dll!SLGetWindowsInformationDWORDWrapper`) will then fault at the first call to a missing export, crashing the elevated process and burning the technique. The fix is one of: (a) parse the original DLL's `IMAGE_EXPORT_DIRECTORY` (at `OptionalHeader.DataDirectory[0].VirtualAddress`, with `NumberOfNames` and `AddressOfNames` arrays) and forward every export via a generated module-definition file (`.def`) that emits `EXPORTS func1 = path\\orig.dll.func1`, (b) implement `DllMain` to walk the original DLL's export table at runtime, load the original (renamed) copy via `LoadLibraryExW(L"C:\\Windows\\System32\\slc_orig.dll", NULL, 0)`, and patch `ImageDirectoryEntryToData`-resolved export pointers — but this requires post-load IAT patching, which is fragile. The .def approach is preferred.

**Plant destination race.** If the legitimate `slc.dll` (or the equivalent target) is mapped into the Software Protection Platform service process (`sppsvc.exe`) when you attempt to overwrite it, `IFileOperation::CopyItem` will fail with `ERROR_SHARING_VIOLATION` (`0x20`). Mitigations: rename the original first (rename does not require exclusive access to a mapped file as long as the rename target doesn't collide), then plant under the original name. The rename trick uses `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` semantics via `IFileOperation::RenameItem`.

**Don't sleep in `DllMain`.** `DllMain` runs under `ntdll!LdrpLoaderLock` — a process-wide recursive critical section. Any call that requires the loader (e.g., `LoadLibrary`, `FreeLibrary`, certain COM activations that trigger DLL loads) will deadlock. Spawn a worker thread from `DllMain` (`CreateThread` with `CREATE_SUSPENDED`, set its priority, then `ResumeThread`) and return `TRUE` immediately; the worker performs the high-integrity action asynchronously. The elevated process will continue to run normally and the worker will execute payloads such as token duplication, service creation, or named-pipe implantation.

**Manifest namespace correctness.** When extracting the binary's manifest to verify the `autoElevate` flag, the parser must handle the SMI 2005 namespace correctly. Many PE tools fail to recognize that `<autoElevate>` is in `http://schemas.microsoft.com/SMI/2005/WindowsSettings`, not the default assembly namespace. A naive `<autoElevate>true</autoElevate>` lookup without the namespace qualifier will miss the flag entirely.

**WOW64 boundary.** 32-bit auto-elevated binaries in `SysWOW64` have the same `autoElevate` mechanism but resolve DLLs against `SysWOW64`, not `System32`. The planted DLL must be a 32-bit PE (`OptionalHeader.Magic = 0x10B` not `0x20B`) and exports must match the 32-bit calling convention. Most modern exemplars are 64-bit, but some legacy auto-elevated binaries remain 32-bit.

**Defender ATP / WDAC.** When `WDAC` is configured in `Enforce` mode with code-integrity rules requiring Microsoft-signing for loaded modules into system processes, the planted DLL will be rejected by `ci.dll`'s policy check at `LdrpLoadDllInternal` → `CiValidateImageHeader`. The operator must verify the absence of `WDAC` enforcement before deploying this technique. `AppLocker` with DLL rules has a similar but weaker effect.

## Why It Matters

This technique is the load-bearing UAC bypass primitive for red teams on stock Windows 10 / 11 hosts without EDR-tamper capabilities. Unlike consent-prompt bypasses that require UI automation or secure-desktop subversion, auto-elevation DLL hijacking works headlessly, from `wusa.exe`-style scheduled execution, and from beacon post-exploitation contexts where no interactive desktop is available. The file-system plant is also robust: it survives reboots (until the operator restores the original DLL) and yields high-integrity code execution without any process injection step that would attract EDR attention.

It composes naturally with T-021 (COM CLSID Hijack): T-021 mutates `HKCU\Software\Classes\CLSID\{...}\InProcServer32` to redirect a `CoCreateInstance` call toward a payload DLL; this card plants a DLL to be loaded by an auto-elevated binary. The two together enable the operator to choose the file-system side or the registry side of the auto-elevate surface, and to use one as a fallback when the other is monitored.

The technique is niche versus generic DLL search-order hijacking (T-1574.001) because the auto-elevation context is what makes it operationally valuable — without `autoElevate=true` in the binary's manifest, planting a DLL would just yield code execution at the caller's (medium) integrity, which is rarely the operator's goal.

## Detection Considerations

- **Telemetry sources**: `Sysmon` Event ID 11 (FileCreate) catching writes to `%SystemRoot%\System32\*.dll` or new subdirectories under `System32`; `Sysmon` Event ID 7 (ImageLoad) catching DLL loads from unusual paths inside `System32\<subdir>\`; `ETW Microsoft-Windows-Kernel-Process` for the AppInfo elevation events (`EventID 1` process create with parent `svchost.exe` (appinfo) and `Integrity Level = High`); `Microsoft-Windows-Complus` / `Microsoft-Windows-DistributedCOM` for `IFileOperation` surrogate launches (`dllhost.exe` started by `svchost.exe` in the `appinfo` group); `Microsoft-Windows-Image-Load` events for DLL loads from `System32` subdirectories that don't exist on a clean baseline.
- **Bypass options**: use a low-prevalence auto-elevated binary instead of `ComputerDefaults.exe` (operator pre-enumeration of obscure exemplars can dodge signatures); plant the DLL under a subdirectory name that doesn't match the binary's known assembly references (Variant 2 with a target manifest that hasn't been catalogued); avoid `IFileOperation` and instead use a custom auto-elevated COM interface (each AppID with `ElevationEnabled=1` is a candidate) or a direct `IFileOperation` replacement via `SHCreateItemFromParsingName` followed by `SHFileOperation` (less common, evades `IFileOperation`-specific rules); pre-stage the planted DLL via a separate persistence mechanism (e.g., a `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT` from a prior low-int foothold, so the file appears during the next boot before any EDR file monitor is fully initialized).
- **Residual artifacts**: the planted DLL file itself in `System32` or a new subdirectory under `System32`; renamed original (`.bak` extension); elevated process creation event from `appinfo.dll`'s surrogate; `dllhost.exe` instance as the COM surrogate parent; if `IFileOperation` is used, an event in `Microsoft-Windows-Shell-Core-Operational` log; on cleanup, restoration of the original file via a second `IFileOperation` cycle.

## Variant Comparison Table

| Variant | Plant location | Privilege required | Loader mechanism | Recovers original DLL? | Best for |
|---|---|---|---|---|---|
| 1. Direct System32 plant | `%SystemRoot%\System32\<name>.dll` (overwrite/rename original) | Medium IL admin | Default search order, app dir first | Optional (rename-to-`.bak`) | Licensing DLLs not in `KnownDlls`, e.g., `slc.dll`, `sppcomapi.dll`, `dismcore.dll` |
| 2. SxS private-assembly probe | `%SystemRoot%\System32\<assemblyName>\<assemblyName>.dll` | Medium IL admin | `sxs.dll` private-assembly probing | Yes (no original touched) | Binaries whose manifests reference absent assemblies |
| 3. Altered search path | Path resolved from binary's `LoadLibraryEx` arg | Medium IL admin (or just user, depending on target) | `LOAD_WITH_ALTERED_SEARCH_PATH` (`0x8`) | Yes | Rare; specific binaries that call `LoadLibraryEx` with relative paths |

## Composition with Other Techniques

**Composition A — T-021 + this card (file-system + registry dual hijack)**: Use T-021 to plant a CLSID entry at `HKCU\Software\Classes\CLSID\{<GUID>}\InProcServer32` whose `(Default)` value is `C:\Windows\System32\<planted.dll>`. Then use this card (Variant 1) to plant `<planted.dll>` into `System32` via `IFileOperation`. When any elevated process calls `CoCreateInstance(CLSID_<GUID>, ...)`, it loads the planted DLL. This composition distributes the payload across both file-system and registry artifacts, making cleanup detection require both surfaces to be inspected.

**Composition B — This card + T-023 (registry-side auto-elevation)**: T-023 covers registry-based auto-elevation hijacking (e.g., `HKCU\Software\Classes\ms-settings\Shell\Open\command` manipulation that triggers `fodhelper.exe` to execute a command). Use T-023 to launch the auto-elevated binary with an arbitrary command line, while this card plants a DLL that the binary loads. The two techniques achieve different objectives — T-023 lets you run an arbitrary command as elevated; this card gives you a DLL running in-process. Combine them when you need both in-process cover (the planted DLL's `DllMain` runs under the binary's identity for token / handle theft) and arbitrary command execution.

**Composition C — This card → process injection → lateral movement**: Plant `slc.dll` → trigger `ComputerDefaults.exe` → `DllMain` creates a high-intensity beacon via named-pipe impersonation (`ImpersonateNamedPipeClient` against a pipe you've planted via `\\.\pipe\`), then transition to T-1055 process injection into `explorer.exe` or `svchost.exe` for persistence that survives `ComputerDefaults.exe` exit.

## Common Mistakes

1. **Forgetting export forwarding** — the planted DLL has no exports matching the binary's IAT, the first call crashes the elevated process, the technique is burned. Always parse the original DLL's `IMAGE_EXPORT_DIRECTORY` and emit a `.def` file with `EXPORTS func1 = C:\\Windows\\System32\\<orig_renamed>.dll.func1` for every entry in `AddressOfNames`.
2. **Planting into an in-use DLL** — `sppcomapi.dll` is often mapped by `sppsvc.exe`; `IFileOperation::CopyItem` returns `0x80070020` (`ERROR_SHARING_VIOLATION`). Use `IFileOperation::RenameItem` to rename the original first; rename doesn't require exclusive access.
3. **Leaving `WIN32_FIND_DATAW` un-zeroed** between `FindNextFileW` calls — the kernel only writes the fields it needs; residual `cFileName` data from the previous entry concatenates with the new, producing false-positive candidate matches and corrupted DLL names.
4. **Calling `LoadLibrary` from `DllMain`** — `ntdll!LdrpLoaderLock` is held; you'll deadlock the elevated process. Spawn a worker thread with `CREATE_SUSPENDED`, return `TRUE` from `DllMain`, then `ResumeThread` on the worker.
5. **Targeting a binary whose `autoElevate` flag was patched** — Microsoft has removed `autoElevate=true` from some binaries in Windows 11 22H2+ (notably a fewMMC-based ones). Verify the manifest after every Windows feature update.
6. **Planting a 32-bit DLL into a 64-bit binary's load path** — the loader rejects it with `STATUS_INVALID_IMAGE_FORMAT` (`0xC000007B`). Verify `OptionalHeader.Magic` (`0x10B` for PE32, `0x20B` for PE32+) matches the target binary.

## Historical Context

The auto-elevated binary DLL-hijacking class was systematized by the UACMe project, which catalogues 70+ auto-elevation methods across multiple Windows builds. The `FusionScanDirectory` routine (the seed for this card) represents the generic DLL-probing facet of that catalogue: rather than rely on a single known binary/DLL pair, the operator enumerates `System32` and matches candidates against the binary's manifest and imports, producing a dynamic bypass that adapts as Microsoft retires specific exemplars.

Microsoft has shipped partial mitigations: the `KnownDlls` registry under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls` pre-maps ~30 system DLLs to section objects that bypass the search order, defeating classic `user32.dll` / `kernel32.dll` hijacks. Licensing DLLs, MMC snap-in DLLs, and app-specific DLLs are not in this list and remain viable. Windows 11 22H2+ removed `autoElevate=true` from a handful of binaries (notably some MMC-based snap-ins), but the bulk of exemplars (`slui.exe`, `dccw.exe`, `ComputerDefaults.exe`, `eventvwr.exe`) retain the flag because their UI workflows require silent elevation for normal user experience. WDAC code-integrity policies remain the strongest mitigation; on hosts without WDAC enforcement, this technique is reliably effective on default Windows 10 / 11 configurations.

## Related Techniques

- **T-021 COM CLSID Hijack** — alternative path that mutates `HKCU\Software\Classes\CLSID\{...}\InProcServer32` instead of planting files; the two compose for dual-surface persistence.
- **T-023 Registry Auto-Elevation Hijack** — covers the registry-side equivalent (e.g., `ms-settings` shell-open hijack triggering `fodhelper.exe`); composes with this card when both arbitrary command and in-DLL execution are required.
- **T-034 IFEO / SilentProcessExit Debugger** — adjacent persistence primitive that uses `HKLM\...\Image File Execution Options\<image>\Debugger`; useful for ensuring the auto-elevated binary's respawn path is redirected after first execution.
- **T-095 NTDLL Unhook typology** — useful post-elevation to prepare the planted DLL's runtime for EDR-hook evasion once it has executed inside the elevated process.