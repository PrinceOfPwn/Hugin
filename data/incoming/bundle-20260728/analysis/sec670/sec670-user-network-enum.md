---
id: RTO-sec670-host-enumeration
name: SEC670 Host Enumeration APIs — Directory, User, Service, Network, Registry
source: Red Team Ops / SANS SEC670
category: telemetry
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T023-client-capabilities, T020-anti-analysis, T017-persistence-suite, T016-edr-evasion]
tags: [host-recon, winapi, registry, file-enumeration, user-enum, service-enum, network-enum, com, iphlpapi, situational-awareness, sec670]
---

# SEC670 Host Enumeration APIs — Training Reference

## TL;DR
SEC670 Section 2 ("Getting to Know Your Target") teaches the canonical Win32 API surface for building an operator-grade host survey tool: directory walks (`FindFirstFile`/`FindNextFile`), user/group enumeration (`NetUserEnum`/`NetLocalGroupEnum`), service/task enumeration (`EnumServicesStatusEx` + COM `ITaskScheduler`), NIC/IP enumeration (`GetAdaptersAddresses` family from `iphlpapi.h`), and Registry walking (`RegOpenKeyEx`/`RegEnumKeyEx`/`RegEnumValue`/`RegQueryInfoKey`/`RegNotifyChangeKeyValue`). The training is explicitly framed as "building the recon phase of your own Meterpreter-equivalent implant." The vault already implements equivalent capability in `client_rust/src/sysinfo_collect.rs`, `byakugan.rs`, and `discovery.rs` (T-023); this training provides the underlying Win32 API reference and operational rationale that the vault assumes.

## Key Concepts

1. **Directory enumeration is benign-appearing by design**
   `FindFirstFile`/`FindNextFile`/`FindClose` are imported by countless legitimate binaries in `System32` (Explorer, cmd, PowerShell, etc.). The training explicitly notes that walking directories is "not malicious, nor should it even be deemed as suspicious." Operator takeaway: directory walks are a low-telemetry recon primitive, but recursive walks from root (`C:\`) are time-expensive and may trip behavioral rules on noisy filesystem access patterns.

2. **NTFS directory tables vs. APIs**
   Each directory has an NTFS-internal table of file entries; hard links are additional entries for the same file. Operators do not need to parse the table directly — the `Find*` APIs abstract this. The `WIN32_FIND_DATA` struct exposes `dwFileAttributes`, three `FILETIME`s (creation/last-access/last-write), file size (high/low DWORD), 8.3 short name (`cAlternateFileName[14]`), and the long name (`cFileName[MAX_PATH]`).

3. **User/group recon drives downstream decisions**
   Identifying local Administrators, Domain Admins logged into a box (a "jackpot" per the training), or service accounts shapes privilege escalation (T-017 UAC bypass paths) and lateral movement. `GetUserName` reflects the *impersonation* context of the calling thread, not necessarily the process owner — important when chaining with token manipulation / `arg_spoof` (T-016).

4. **Services and svchost.exe shared address space model**
   Windows services are special processes with no GUI; multiple services can cohabit a single `svchost.exe` (shared address space — one crashes all). `SERVICE_WIN32_OWN_PROCESS` indicates an isolated service in its own `svchost.exe`. This taxonomy matters for T-007 process injection target selection (a shared `svchost` is a high-value injection host because killing the host kills multiple services, but isolated services give cleaner isolation).

5. **COM-based Scheduled Task enumeration**
   The v1.0 Task Scheduler API path is `CoInitialize` → `CoCreateInstance(CLSID_TaskScheduler)` → `ITaskScheduler::Enum` → `IEnumWorkItems::Next` → `CoTaskMemFree`. The training warns that *creating* new tasks raises the OPSEC profile; *hijacking* existing tasks by appending an action is quieter. Maps directly to the persistence layer in T-017 (`persist/schtask.rs`).

6. **iphlpapi.h is the API family for network recon**
   `GetAdaptersAddresses` (IPv4 + IPv6, supports `AF_UNSPEC` to enumerate both) is the workhorse; `GetInterfaceInfo` returns only IPv4-enabled adapters and *excludes the loopback*; `GetNumberOfInterfaces` *includes* the loopback and logical interfaces (so a 2-NIC box may report ~18). `GetIpStatistics` returns the `MIB_IPSTATS` struct that backs `netstat -e`-equivalent output. Dual-homed systems (DMZ + intranet NIC) are flagged as high-value pivot targets.

7. **Registry is read at 4 critical times — and by extension is a telemetry-rich surface**
   Initial boot, kernel boot, logon, application startup. Polling the registry repeatedly is itself a detection signal (idle systems should have minimal registry access). Operators should prefer `RegNotifyChangeKeyValue` (event-driven) over tight-loop polling. Maps to T-017 (registry-based persistence) and T-016 (NTDLL unhook detection via `HKLM\SYSTEM\CurrentControlSet\...` style reads).

8. **Two-call pattern for variable-size registry values**
   Pass `NULL` for `lpData` and a non-NULL `lpcbData` on the first `RegQueryValueEx` call to learn the required size; allocate; call again with the proper buffer. This is the same idiom used throughout Win32 (e.g., `GetUserProfileDirectory`, `GetAdaptersAddresses`, `EnumServicesStatusEx`) and the vault's Rust `OnceLock` + sized-buffer patterns (T-021).

9. **`RegNotifyChangeKeyValue` is single-shot**
   The notification fires once per call; for continuous monitoring, the operator must re-arm in a loop (typically a worker thread). `REG_NOTIFY_THREAD_AGNOSTIC` decouples registration lifetime from the calling thread — useful for implants that spawn short-lived worker threads. Maps to T-017's resilience monitor concept.

10. **`HKEY_PERFORMANCE_DATA` is not visible in `regedit.exe`**
    Performance counters are exposed only via `RegQueryValueEx` programmatically (or via `pdh.dll`). This is an under-documented recon channel that avoids the typical registry-access telemetry generated by `regedit`-style enumeration.

## Operational Techniques

### Directory Walk via FindFirstFile / FindNextFile / FindClose
- **What**: Walk a directory tree to locate files/subdirectories using the same APIs Meterpreter's `ls` command uses.
- **When to use**: Pre-drop reconnaissance (verify a target folder is empty before staging), loot collection (locate documents/credentials), and recursive inventory of high-value paths (`%USERPROFILE%\Documents`, `C:\ProgramData`, etc.).
- **How**:
  1. `hSearch = FindFirstFileA(lpFileName, &FindData)` — supports wildcards (`*`, `?`). Returns `INVALID_HANDLE_VALUE` on failure.
  2. Wrap the body in a `do { ... } while (FindNextFileA(hSearch, &FindData) != 0);` loop.
  3. Inspect `FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY` to filter dirs vs. files.
  4. Read `FindData.cFileName` (long name) and `FindData.cAlternateFileName` (8.3 short name, e.g., `BACKUP~1.JPG`).
  5. Use `FindData.ftLastWriteTime` for triage (recently modified files are usually more interesting).
  6. Call `FindClose(hSearch)` when done. Always check `GetLastError()` on failure — common codes include `ERROR_NO_MORE_FILES` (loop termination) and `ERROR_PATH_NOT_FOUND`.
- **Vault link**: T-023 `sysinfo_collect.rs` and `amaterasu.rs` (exfil engine) handle file enumeration for loot. The vault assumes the operator has Win32 directory walk primitives; this training provides the canonical reference implementation. Complements the vault's `winhttp_dl.rs` (T-019) which is the inverse operation (download, not enumerate).
- **Tool/code**:
  ```c
  HANDLE hSearch = INVALID_HANDLE_VALUE;
  WIN32_FIND_DATA FindData;
  hSearch = FindFirstFileA(Dir, &FindData);
  if (hSearch == INVALID_HANDLE_VALUE) return;
  do {
      // filter, collect, recurse on subdirs
  } while (FindNextFileA(hSearch, &FindData) != 0);
  FindClose(hSearch);
  ```
  Variants: `FindFirstFileEx` (extra attributes), `FindFirstFileTransacted` (deprecated — avoid).
- **OPSEC**: Low individual-call risk, but recursive walks from `C:\` generate significant filesystem I/O telemetry and may trigger EDR heuristics for "mass file enumeration" patterns. Restrict recursion depth and skip system directories (`C:\Windows\WinSxS`, `C:\Windows\Installer`).

### User / Group Enumeration
- **What**: Identify the current user, all local accounts, profile paths, and local group memberships.
- **When to use**: Initial post-foothold recon, target selection for privilege escalation (find Administrators group members), and lateral movement planning (Domain Admin hunting).
- **How**:
  1. `GetUserNameA(lpBuffer, &cbSize)` — returns the *impersonated* user (relevant if you've stolen a token; see T-016 arg spoofing). Initialize `cbSize = 32767`.
  2. `GetUserProfileDirectoryA(hToken, lpProfileDir, &lpcchSize)` — requires a token handle from `OpenProcessToken`/`OpenThreadToken`. Two-call pattern: pass NULL on first call to learn size.
  3. `NetUserEnum(NULL, level, filter, &bufptr, MAX_PREFERRED_LENGTH, &entriesread, &totalentries, NULL)` — enumerate all accounts. Levels: 0 (names), 1 (details), 2 (+logon), 3 (+profile), 10 (names + comments), 11 (detailed), 20 (attributes). **Always** call `NetApiBufferFree(bufptr)` even on failure.
  4. `NetLocalGroupEnum(NULL, level, &bufptr, MAX_PREFERRED_LENGTH, &entriesread, &totalentries, NULL)` — enumerate local groups. Levels: 0 (names) or 1 (names + comments).
  5. Companion APIs in `lmaccess.h`: `NetGroupGetUsers`, `NetLocalGroupGetMembers` (membership of a specific group — useful for "who is in Administrators?"). `lmuse.h`: `NetUseEnum`, `NetUseGetInfo` (network resource connections — pivot indicators).
- **Vault link**: T-023 `sysinfo_collect.rs` covers similar ground; T-016 covers the impersonation/token side that affects `GetUserName` semantics. T-020 anti-analysis covers AD enumeration via `byakugan.rs` (network recon module).
- **Tool/code**: Link against `netapi32.lib` for `Net*` APIs, `userenv.lib` for `GetUserProfileDirectory`.
- **OPSEC**: `NetUserEnum`/`NetLocalGroupEnum` are the programmatic equivalents of `net user` / `net localgroup` — well-known to EDRs as recon indicators. Prefer registry-based profile enumeration (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`) for lower-noise user enumeration; the SIDs in subkey names give you the account list without touching `netapi32`.

### Service Enumeration
- **What**: List all installed services with status, type, and process info.
- **When to use**: Identify AV/EDR services (high-impact for T-016 evasion decisions), find vulnerable services for privilege escalation, or locate candidate `svchost.exe` instances for T-007 injection.
- **How**:
  1. `OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE)` — get `hSCManager`.
  2. `EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &lpServicesReturned, &lpResumeHandle, NULL)` — two-call pattern; first call with `cbBufSize = 0` returns `ERROR_MORE_DATA` and the required size. `dwServiceType` filters: `SERVICE_WIN32_OWN_PROCESS` (isolated) vs. `SERVICE_WIN32_SHARE_PROCESS` (shared `svchost`). `dwServiceState`: `SERVICE_ACTIVE`, `SERVICE_INACTIVE`, or `SERVICE_STATE_ALL`.
  3. For each returned `ENUM_SERVICE_STATUS_PROCESS` entry, optionally call `QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, lpBuffer, cbBufSize, &pcbBytesNeeded)` to get the hosting PID (`SERVICE_STATUS_PROCESS.dwProcessId`).
  4. `CloseServiceHandle(hSCManager)`.
- **Vault link**: T-023 recon capabilities; T-007 injection (svchost target selection via shared-process detection); T-016 evasion (AV/EDR service fingerprinting); T-018 BYOVD pipeline uses SCM service registration (`byovd/service.rs`).
- **Tool/code**: Link `advapi32.lib`. PowerShell equivalent: `Get-Service`, `Get-CimInstance Win32_Service`. CLI: `sc.exe query type= service state= all`.
- **OPSEC**: `EnumServicesStatusEx` is benign-appearing (used by `services.msc`), but querying for *just* AV-vendor service names is a known detection pattern. Enumerate all services and filter client-side.

### Scheduled Task Enumeration via COM (Task Scheduler v1.0)
- **What**: Enumerate all registered scheduled tasks.
- **When to use**: Recon for hijackable tasks (existing task → append action), evidence of prior attacker persistence, or pre-persistence situational awareness.
- **How**:
  1. `CoInitialize(NULL)` — initialize COM.
  2. `CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (void**)&pITS)` — get the `ITaskScheduler` interface.
  3. `pITS->Enum(&pIEnum)` — get `IEnumWorkItems` enumerator.
  4. Loop `pIEnum->Next(1, &rgpwszNames, &pceltFetched)` until `S_FALSE`. Each `rgpwszNames` is a `.job` filename in `%SystemRoot%\Tasks\`.
  5. `CoTaskMemFree(rgpwszNames)` for each batch.
  6. `pIEnum->Release(); pITS->Release(); CoUninitialize();`.
- **Vault link**: T-017 Five-Layer Persistence — `persist/schtask.rs` implements the *creation* side via the v2.0 COM API (`ITaskService`). The training's v1.0 path is legacy but still works for *enumeration* on all Windows versions.
- **Tool/code**: Modern alternative is the v2.0 COM API (`ITaskService` → `GetFolder("\")` → `GetTasks(0)`). XML files in `%SystemRoot%\System32\Tasks\` are also directly enumerable via the `Find*` APIs from the previous technique.
- **OPSEC**: Reading the `.job` files directly from disk (via `FindFirstFile` on `C:\Windows\Tasks\*` and `C:\Windows\System32\Tasks\*`) avoids COM initialization telemetry. The COM path is louder (RPC activity in ETW).

### Network / NIC Enumeration (iphlpapi)
- **What**: Enumerate adapters, IP addresses (v4/v6), statistics, and interface counts.
- **When to use**: Identify dual-homed systems (pivot opportunity), confirm subnet/VLAN placement, validate outbound path before C2 channel selection (T-019).
- **How**:
  1. `GetNumberOfInterfaces(&dwCount)` — fast count incl. loopback and logical interfaces (often surprising: ~18 on a 2-NIC box).
  2. `GetInterfaceInfo(pIfTable, &dwOutBufLen)` — IPv4-only adapters, no loopback. Two-call pattern. Returns `IP_INTERFACE_INFO` with `NumAdapters` and `IP_ADAPTER_INDEX_MAP` array.
  3. `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, pAdapterAddresses, &SizePointer)` — the workhorse. Returns a linked list of `IP_ADAPTER_ADDRESSES`. Two-call pattern (returns `ERROR_BUFFER_OVERFLOW` on first call). Enumerates v4 + v6, gateways, DNS suffixes, etc.
  4. `GetIpStatistics(&Stats)` — fills `MIB_IPSTATS` (`dwInReceives`, `dwOutRequests`, `dwInHdrErrors`, etc.) — equivalent to `netstat -e -s`.
- **Vault link**: T-023 `byakugan.rs` covers ARP, TCP, and AD enumeration; this training provides the foundation for an `ipconfig`/`netstat`/`arp` clone. T-019 networking suite (`kamui.rs` SOCKS5, `juubi.rs` peer relay) consumes this data for pivot planning.
- **Tool/code**: Link `iphlpapi.lib`. PowerShell: `Get-NetAdapter`, `Get-NetIPConfiguration`, `Get-NetAdapterHardwareInfo`. Error codes to handle: `ERROR_INSUFFICIENT_BUFFER`, `ERROR_INVALID_PARAMETER`, `ERROR_NO_DATA`, `ERROR_NOT_SUPPORTED`, `ERROR_ADDRESS_NOT_ASSOCIATED`, `ERROR_NOT_ENOUGH_MEMORY`.
- **OPSEC**: `GetAdaptersAddresses` is benign (used by countless apps). Avoid `GetIpForwardTable` + manual RTNetStance parsing unless needed — it's noisier in ETW.

### Registry Walking
- **What**: Read, enumerate keys/subkeys/values, and monitor changes in the Windows Registry.
- **When to use**: Recon for installed software (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`), user profile enumeration (`HKLM\...\ProfileList`), persistence point selection (T-017), AV/EDR detection via vendor keys, and watchdog for AV install during an operation.
- **How**:
  1. `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\...", 0, KEY_READ | KEY_WOW64_64KEY, &hKey)` — open with explicit `KEY_WOW64_64KEY` to bypass registry virtualization on 64-bit. Return type `LSTATUS` (no `GetLastError` — the code IS the error).
  2. `RegQueryValueExW(hKey, L"ValueName", NULL, &dwType, lpData, &lpcbData)` — two-call pattern. First call with `lpData = NULL` to learn `lpcbData`. Handles `REG_DWORD`, `REG_BINARY`, `REG_SZ`, `REG_MULTI_SZ`, etc.
  3. `RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &cSubKeys, &cbMaxSubKeyLen, NULL, &cValues, &cbMaxValueNameLen, &cbMaxValueLen, NULL, NULL)` — get dimensions for buffer pre-allocation before enumerating. Often skipped but eliminates re-allocation in tight loops.
  4. `RegEnumKeyExW(hKey, dwIndex, lpName, &lpcchName, NULL, NULL, NULL, &ftLastWriteTime)` — enumerate subkeys. Requires `KEY_ENUMERATE_SUB_KEYS` access mask. Increment `dwIndex` until `ERROR_NO_MORE_ITEMS`.
  5. `RegEnumValueW(hKey, dwIndex, lpValueName, &lpcchValueName, NULL, &lpType, lpData, &lpcbData)` — enumerate values. Requires `KEY_QUERY_VALUE`. Same index-until-`ERROR_NO_MORE_ITEMS` pattern.
  6. `RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, TRUE)` — async watch. Pass an event handle and `fAsynchronous = TRUE` to return immediately; signal occurs on change. **Single-shot** — must re-arm in a loop. `REG_NOTIFY_THREAD_AGNOSTIC` decouples lifetime from the calling thread.
  7. `RegCloseKey(hKey)` — always close.
- **Vault link**: T-017 Five-Layer Persistence — `persist/com_hijack.rs` (HKLM/HKCU `Software\Classes\CLSID`), `persist/ntfs_ea.rs`, `persist/tls_cb.rs` all consume registry APIs. T-016 evasion reads `HKLM\SYSTEM\CurrentControlSet\Services\<edr>` for service fingerprinting. T-020 anti-VM reads hardware/dev-node keys.
- **Tool/code**: Predefined root keys: `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS`, `HKEY_CURRENT_CONFIG`. Note: `HKEY_PERFORMANCE_DATA` is **only** accessible via API, not `regedit.exe`. Use `FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, ...)` to stringify LSTATUS codes.
- **OPSEC**: Avoid tight-loop polling — idle systems should not have continuous registry access. Prefer `RegNotifyChangeKeyValue` async + event handle. Be aware that `RegOpenKeyEx` on `HKLM\SAM` and `HKLM\SECURITY` requires `SYSTEM` privileges (not even Administrator has access by default). The `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ProfileList` subkey gives SIDs of all profiles — quieter than `NetUserEnum` for user recon.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `FindFirstFileA`/`FindNextFileA`/`FindClose` (kernel32) | Directory walk, file enumeration | Low individual risk; recursive walks from root trigger behavioral heuristics |
| `FindFirstFileEx` (kernel32) | Extended attribute filtering | Same as above |
| `WIN32_FIND_DATA` struct | Per-file metadata (attrs, times, sizes, 8.3 + long name) | N/A — struct only |
| `GetUserNameA` (advapi32) | Current (impersonated) user name | Reflects thread impersonation context |
| `GetUserProfileDirectoryA` (userenv) | Profile path from token | Requires `OpenProcessToken` first |
| `NetUserEnum` (netapi32) | All local user accounts | Equivalent to `net user` — known recon signature |
| `NetLocalGroupEnum` (netapi32) | All local groups | Equivalent to `net localgroup` |
| `NetGroupGetUsers` / `NetLocalGroupGetMembers` (netapi32, lmaccess.h) | Membership enumeration | Useful for "Administrators members" recon |
| `NetUseEnum` / `NetUseGetInfo` (netapi32, lmuse.h) | Network resource connections | Pivot indicators |
| `EnumServicesStatusExA` (advapi32) | Service enumeration | Benign-appearing; filter client-side |
| `QueryServiceStatusEx` (advapi32) | Per-service status + PID | Used by `services.msc` |
| `ITaskScheduler::Enum` / `IEnumWorkItems::Next` (COM, mstask.dll) | Scheduled task enumeration (v1.0) | COM init generates ETW RPC events |
| `GetNumberOfInterfaces` (iphlpapi) | Quick NIC count (incl. loopback + logical) | Benign |
| `GetInterfaceInfo` (iphlpapi) | IPv4-only adapters (no loopback) | Benign |
| `GetAdaptersAddresses` (iphlpapi) | Full adapter+IP enumeration (v4+v6+gateways) | Workhorse; benign |
| `GetIpStatistics` (iphlpapi) | IP traffic stats (netstat -e equivalent) | Benign |
| `RegOpenKeyExW` (advapi32) | Open registry key handle | Returns LSTATUS (not via GetLastError) |
| `RegQueryValueExW` (advapi32) | Read value data | Two-call pattern for size discovery |
| `RegEnumKeyExW` (advapi32) | Enumerate subkeys | Needs `KEY_ENUMERATE_SUB_KEYS` mask |
| `RegEnumValueW` (advapi32) | Enumerate values | Needs `KEY_QUERY_VALUE` mask |
| `RegQueryInfoKeyW` (advapi32) | Key metadata for buffer pre-allocation | Eliminates re-allocs in loops |
| `RegNotifyChangeKeyValue` (advapi32) | Single-shot async change notification | Re-arm in loop; `REG_NOTIFY_THREAD_AGNOSTIC` decouples from thread lifetime |
| `RegCloseKey` (advapi32) | Close key handle | Always pair with `RegOpenKeyEx` |
| `HKEY_PERFORMANCE_DATA` | Performance counters (API-only, no regedit) | Under-documented recon channel |
| `FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM)` | Stringify LSTATUS codes | Replaces `GetLastError` for registry APIs |
| `CoInitialize`/`CoCreateInstance`/`CoTaskMemFree` (ole32) | COM lifecycle | Required for Task Scheduler v1.0 enumeration |
| `KUSER_SHARED_DATA` (`0x7FFE0000` user-mode mapping) | Bonus: system info without API calls | Direct memory read — bypasses typical API hooks (T-020 anti-analysis) |
| `GetProductInfo`, `GetWindowsDirectory`, `GetComputerName`, `GetNativeSystemInfo` (kernel32) | Bootcamp: OS info enumeration | Benign; standard sysinfo primitives |

## Gaps & Extensions

**What the vault covers that SEC670 does not:**
- **Direct syscall / SSN resolution for recon APIs**: T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate. SEC670 assumes flat `kernel32.dll`/`advapi32.dll`/`netapi32.dll` static imports — these light up EDR user-mode hooks immediately. The vault routes equivalent functionality through indirect syscalls (`ntdll`-level), giving the same enumeration data without inline hook detection.
- **PEB-walker dynamic API resolution** (T-004): SEC670 uses static `#pragma comment(lib, ...)` linking. The vault resolves `netapi32`/`iphlpapi`/`advapi32` exports via DJB2 hash + `LdrpInvertedFunctionTable` walk — no IAT footprint for these recon DLLs.
- **Stack spoofing during recon** (T-016 advanced multi-frame): SEC670 recon calls leave legitimate-looking return stacks but don't actively spoof them. The vault wraps recon calls with `ThreadStackSpoof` frames so even memory-scanning EDRs see decoy call origins.
- **IAT camouflage** (T-020): The vault's 3-profile IAT camouflage (`iat_camo.rs`) lets an implant import `FindFirstFile` etc. without those strings appearing in the static IAT — SEC670's lab binaries have these imports plainly visible.
- **Anti-VM gating before recon** (T-020): SEC670 executes recon unconditionally. The vault runs 10 anti-VM checks *before* any recon to abort on sandbox detection.
- **Network recon depth** (T-023 `byakugan.rs`): SEC670's `iphlpapi` enumeration is host-local. The vault's `byakugan.rs` does ARP table enumeration (`GetIpNetTable`), TCP table walks (`GetTcpTable2`/`GetExtendedTcpTable`), and Active Directory LDAP enumeration — far richer network situational awareness.
- **Dead-drop C2 discovery** (T-019 `discovery.rs`): SEC670 does not cover C2 server URL discovery via `rentry.co` + Sepolia Ethereum contract reads — the vault treats discovery as a first-class operational phase.

**What SEC670 covers that the vault does not (or covers less explicitly):**
- **`RegNotifyChangeKeyValue` watchdog pattern**: The vault's T-017 persistence module has a 30-min resilience monitor (`phantom_restart.rs`) but does not document the underlying `RegNotifyChangeKeyValue` + event-handle + `REG_NOTIFY_THREAD_AGNOSTIC` re-arm loop. This is genuinely useful operational knowledge for any registry-state-aware implant (e.g., self-deletion trigger when AV is installed mid-operation).
- **`HKEY_PERFORMANCE_DATA` recon channel**: Programmatic-only performance counter access is not covered in the vault. Useful as an EDR-evasive data source for system load / process activity inference.
- **`KUSER_SHARED_DATA` direct read**: Mentioned as a "bonus" bootcamp challenge. The vault's T-020 anti-VM module references `KUSER_SHARED_DATA` but doesn't fully exploit the direct-mapped (no-syscall, no-API) system info read at `0x7FFE0000`. This is a high-value, low-telemetry recon primitive the vault should adopt.
- **Task Scheduler v1.0 COM enumeration path** (`ITaskScheduler`/`IEnumWorkItems`): The vault's `persist/schtask.rs` uses v2.0 COM. The v1.0 path is operationally useful for legacy enumeration and is not currently in the vault.
- **Two-call buffer-sizing idiom (Win32)**: SEC670 documents this exhaustively across `GetUserProfileDirectory`, `EnumServicesStatusEx`, `GetInterfaceInfo`, `GetAdaptersAddresses`, `RegQueryValueEx`, `RegQueryInfoKey`. The vault's Rust patterns use `OnceLock` + sized buffers, but the canonical Win32 idiom is worth noting for FFI-bound calls.
- **`FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM)` for LSTATUS**: Not in the vault — useful for debugging registry operations without manual error-code lookup.

**Specific additions the vault could adopt:**
1. `RegNotifyChangeKeyValue` async watchdog as a `dark_crystal` evasion utility — useful for self-deletion triggers when AV appears mid-operation.
2. Direct `KUSER_SHARED_DATA` mapping for `SystemTime`, `TickCount`, `CryptoSeed` without `NtQuerySystemTime`/`GetTickCount` syscalls.
3. `HKEY_PERFORMANCE_DATA` enumeration for process count / IO rate inference as an anti-sandbox check (sandboxes typically have near-zero perf counters).
4. `NetLocalGroupGetMembers` for "who is in Administrators" enumeration via `netapi32` — the vault's `byakugan.rs` does AD enum via LDAP but lacks local-group-membership enumeration.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `FindFirstFile`/`FindNextFile` directory walk | T-023 `sysinfo_collect.rs`, `amaterasu.rs` | Vault consumes the same APIs for file loot collection; this training provides canonical reference impl |
| `GetUserName` (impersonation-aware) | T-016 arg spoofing, T-015 PPID spoofing | Training explicitly notes `GetUserName` reflects thread impersonation — directly informs token-manipulation OPSEC in vault |
| `GetUserProfileDirectory` | T-023 `sysinfo_collect.rs` | Vault uses equivalent; this training documents the two-call size-discovery pattern |
| `NetUserEnum` / `NetLocalGroupEnum` | T-020 `byakugan.rs` (AD enum via LDAP), T-023 `sysinfo_collect.rs` | Vault prefers LDAP/registry over `netapi32`; this training documents the noisier-but-simpler `netapi32` path |
| `EnumServicesStatusEx` / `QueryServiceStatusEx` | T-007 Pool Party / svchost injection target selection, T-016 EDR service fingerprinting | Service enumeration directly informs which `svchost.exe` to target for shared-process injection and which services belong to AV/EDR products |
| `ITaskScheduler` v1.0 COM enumeration | T-017 `persist/schtask.rs` (v2.0 COM creation) | Vault implements v2.0 persistence; this training documents v1.0 enumeration as complementary recon |
| `GetNumberOfInterfaces` / `GetInterfaceInfo` / `GetAdaptersAddresses` / `GetIpStatistics` | T-023 `byakugan.rs` (ARP, TCP, AD recon), T-019 `kamui.rs` SOCKS5 / `juubi.rs` peer relay | Vault's network recon module is richer (ARP/TCP/AD); this training documents the foundational `iphlpapi` layer the vault assumes |
| Dual-homed system detection | T-019 multi-chain vault / peer relay | Pivot target identification; vault's relay infrastructure consumes this signal |
| `RegOpenKeyEx` / `RegQueryValueEx` / `RegEnumKeyEx` / `RegEnumValue` / `RegQueryInfoKey` | T-017 `persist/com_hijack.rs`, T-016 EDR service fingerprinting, T-020 anti-VM hardware keys | Vault's persistence and evasion modules consume registry APIs; this training documents the canonical enumeration primitives |
| `RegNotifyChangeKeyValue` async watchdog | T-017 `persist/phantom_restart.rs` (30-min resilience monitor) | Vault has the monitor concept; this training provides the underlying `RegNotifyChangeKeyValue` + `REG_NOTIFY_THREAD_AGNOSTIC` re-arm pattern the vault should document |
| `HKEY_PERFORMANCE_DATA` programmatic-only access | (not in vault) | **New capability** — vault could adopt for perf-counter-based anti-sandbox and system-load inference |
| `KUSER_SHARED_DATA` direct read (`0x7FFE0000`) | T-020 `experimental/evade_vm.rs` (references KUSER_SHARED_DATA) | Vault mentions but doesn't fully exploit; this training flags it as a no-syscall system info primitive |
| Two-call buffer sizing pattern | T-021 Rust Patterns (`OnceLock` + sized buffers) | Vault's Rust idiom is the equivalent; this training documents the canonical Win32 FFI pattern |
| `FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM)` for LSTATUS | (not in vault) | **New capability** — error stringification for registry ops debugging |
| Registry profile-list user enumeration (`HKLM\...\ProfileList`) | T-023 `sysinfo_collect.rs` | Lower-noise alternative to `NetUserEnum`; vault should prefer this path |
| `WIN32_FIND_DATA.cAlternateFileName` (8.3 short names) | (not in vault) | Marginally useful for legacy path access; vault uses long-path APIs |
| `SERVICE_WIN32_OWN_PROCESS` vs `SERVICE_WIN32_SHARE_PROCESS` | T-007 Pool Party (svchost target selection) | Service-type taxonomy directly informs injection target isolation properties |
| COM lifecycle (`CoInitialize`/`CoCreateInstance`/`CoTaskMemFree`) | T-017 `persist/com_hijack.rs`, T-023 `html_overlay.rs` (WebView2) | Vault heavily uses COM; this training documents the canonical init/teardown sequence |
| Bootcamp: `GetProductInfo`, `GetWindowsDirectory`, `GetComputerName`, `GetNativeSystemInfo` | T-023 `sysinfo_collect.rs` | Standard sysinfo primitives; both training and vault cover equivalents |

---

**Operator Summary**: SEC670 Section 2 provides the foundational Win32 recon API surface that any operator-grade implant needs. The vault (T-023, T-020, T-017, T-016) implements equivalent or richer capability, but routes through indirect syscalls (T-001/T-002/T-003), dynamic resolution (T-004), and stack spoofing (T-016) — meaning the vault's versions are EDR-evasive where SEC670's are not. The training's most valuable *unique* contributions are: (1) the `RegNotifyChangeKeyValue` async watchdog pattern, (2) `HKEY_PERFORMANCE_DATA` programmatic-only access, (3) `KUSER_SHARED_DATA` direct mapping as a no-API system info source, and (4) the Task Scheduler v1.0 COM enumeration path. These four items warrant adoption into the vault as new utility primitives.