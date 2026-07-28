```yaml
---
id: RTO-host-survey-recon
name: Host Survey & Reconnaissance — OS Info, Process Enum, Software Discovery
source: SANS SEC670.2 — Red Teaming Tools: Developing Windows Implants, Shellcode, C2
category: winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-004, T-016, T-020, T-023]
tags: [recon, host-survey, os-info, kuser-shared-data, process-enumeration, wua-com, installed-software, directory-walk, native-api, go-nogo]
---

# Host Survey & Reconnaissance — Training Reference

## TL;DR
SEC670.2 covers the foundational host-survey capabilities every Windows implant needs: OS version/architecture detection, hotfix/patch enumeration via WUA COM APIs, process enumeration across four API families (EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcessesEx, NtQuerySystemInformation), installed-software discovery, and recursive directory walking. The standout tradecraft is the undocumented **KUSER_SHARED_DATA** read at fixed VA `0x7FFE0000` — zero API calls, zero hooks, zero telemetry — which complements the vault's PEB walker (T-004) as another direct-user-shared-memory recon primitive.

## Key Concepts

1. **KUSER_SHARED_DATA at 0x7FFE0000** — A massive structure mapped into nearly every process at the same virtual address. Reading specific offsets (Major Version @ `0x26C`, Minor Version @ `0x270`, Build Number @ `0x260`) gives you OS fingerprinting with **no API call at all** — no `GetVersionEx`, no hookable surface. This is the same class of "go around the API" tradecraft as T-004 PEB Walker, just a different shared region. See Geoff Chappell's docs and Vergilius Project for full structure layouts per build.

2. **GetVersionEx deprecation & manifest behavior** — `GetVersionExA/W` caps at major 6, minor 2 (Windows 8) unless the binary's manifest declares compatibility with Windows 10+. Without manifest work, the API lies. Microsoft deprecated it in favor of version helpers (`IsWindows10OrGreater`, etc.). Operator takeaway: never trust `GetVersionEx` blindly — pair it with KUSER_SHARED_DATA or `RtlGetVersion`.

3. **WUA COM API chain for patch enumeration** — PowerShell `Get-HotFix` and `wmic qfe list` only query `Win32_QuickFixEngineering`, which **misses updates**. The complete picture requires the Windows Update Agent (WUA) COM family: `IUpdateSession` → `CreateUpdateSearcher` → `IUpdateSearcher::Search("IsInstalled=1 or IsHidden=1")` → `ISearchResult::get_Updates` → `IUpdateCollection` → iterate `get_Item` + `get_Title` + `get_KBArticleIDs`. Headers: `wuapi.h` + `wuapi.lib` (course says `Wuguid.lib` — typo, correct is `Wuapi.lib`).

4. **EPROCESS / KPROCESS linked list** — Kernel tracks every process via `ActiveProcessLinks` (`_LIST_ENTRY` at offset `0x448` in EPROCESS on the documented build). `Get-Process`/`tasklist` walk this list. DKOM (Direct Kernel Object Manipulation) attacks unlink entries to hide processes from these tools — relevant context when validating vault injection target selection (T-007 through T-015).

5. **Four-tier process enumeration strategy** — `EnumProcesses` (simplest, PIDs only) → `CreateToolhelp32Snapshot` (richer `PROCESSENTRY32`, but stale snapshot) → `WTSEnumerateProcessesEx` (remote-capable, cross-session, `WTS_PROCESS_INFO_EX` with thread/handle/memory stats) → `NtQuerySystemInformation` with `SystemProcessInformation` (undocumented, richest, single native call). Selection depends on OPSEC tolerance and target Windows version.

6. **WTSEnumerateProcessesEx cross-session capability** — The WTS API family enables enumerating processes in **other sessions**, which is the foundation for cross-session process injection. The course flags this explicitly. Vault T-007 Pool Party / T-012 Early Cascade could be extended with this for Session 0 → Session 1 injection paths.

7. **NtQuerySystemInformation as a recon primitive** — Single native API returns a linked list of `SYSTEM_PROCESS_INFORMATION` structs with `NumberOfThreads`, `WorkingSetSize`, `UserTime`, `KernelTime`, `HandleCount`, `SessionId`, `UniqueProcessId`, `InheritedFromUniqueProcessId` (parent PID), and an embedded `SYSTEM_THREAD_INFORMATION[1]` array. Two-call pattern (size query then fetch) required. Native APIs carry breakage risk across Windows versions but bypass Win32 API hooks.

8. **GO/NOGO decision framework** — Operational pre-briefs should establish abort criteria based on recon output: known-detective applications, unfamiliar software with no research time, EDR/AV cloud-analysis risk. The course frames this as a decision-tree output of the survey phase, not an afterthought.

9. **Install location conventions** — 64-bit apps: `C:\Program Files` (8.3 short name `C:\Progra~1`); 32-bit apps: `C:\Program Files (x86)` (`C:\Progra~2`); edge cases at `C:\` root (e.g., legacy Python 2.7). User-chosen install paths (Documents, Downloads) require recursive directory walking to catch — `C:\Program Files` enumeration alone is insufficient.

## Operational Techniques

### KUSER_SHARED_DATA OS Fingerprinting
- **What**: Read OS major/minor/build version directly from the user-shared data page without invoking any Win32 or native API.
- **When to use**: Anytime you need OS/architecture info and want zero EDR telemetry — pairs naturally with T-004 PEB Walker for module resolution since both leverage shared memory regions.
- **How**:
  1. Treat VA `0x7FFE0000` as a `KUSER_SHARED_DATA*` pointer (no `MmMapIoSpace`/`VirtualAlloc` needed — already mapped by the loader).
  2. Read `MajorVersion` at offset `+0x26C`, `MinorVersion` at `+0x270`, `BuildNumber` at `+0x260` (offsets valid for Windows 10 2004 and adjacent builds — re-validate per target build via Vergilius Project).
  3. Decode: `(10, 0)` = Win10/Server 2016+, `(6, 3)` = Win8.1/Server 2012 R2, `(6, 1)` = Win7/2008 R2, etc.
  4. For architecture, use `GetNativeSystemInfo` (one API call) or read `KUSER_SHARED_DATA` `ImageNumberLow`/`ImageNumberHigh` fields.
- **Vault link**: T-004 PEB Walker — same "go around the API" tradecraft class. PEB gives module list; KUSER_SHARED_DATA gives OS metadata. A real implant should use both: PEB for `ntdll.dll`/`kernel32.dll` resolution (T-004) and KUSER_SHARED_DATA for OS version gating (no vault card yet — candidate for new T-024 extension).
- **Tool/code**: Direct pointer dereference in C: `PKUSER_SHARED_DATA sd = (PKUSER_SHARED_DATA)0x7FFE0000; ULONG major = sd->NtMajorVersion;` — structure definition in `ntddk.h`.
- **OPSEC**: None — no API call, no hook, no telemetry. The only risk is offset drift across builds; mitigate by pinning offsets via a build→offset table or runtime validation against `GetVersionEx` once on a known-good dev box.

### WUA COM-Based Patch Enumeration
- **What**: Enumerate installed hotfixes/updates via the Windows Update Agent COM API family to get a complete picture beyond what `Win32_QuickFixEngineering` returns.
- **When to use**: Pre-exploitation recon — confirm a target CVE is unpatched before launching an exploit, or verify an EDR vendor's signature update currency.
- **How**:
  1. `CoInitialize(NULL)` on the calling thread.
  2. `CoCreateInstance(CLSID_UpdateSession, ..., (PVOID*)&upSsn)` to get `IUpdateSession*`.
  3. `upSsn->CreateUpdateSearcher(&upSearch)` to obtain `IUpdateSearcher*`.
  4. Build criteria BSTR: `L"IsInstalled=1 or IsHidden=1"` — catches hidden updates too.
  5. `upSearch->Search(criteria, &results)` → `ISearchResult*`.
  6. `results->get_Updates(&upList)` → `IUpdateCollection*`.
  7. `upList->get_Count(&upSize)` then iterate: `upList->get_Item(index, &upItem)` → `upItem->get_Title(&upName)` (and `get_KBArticleIDs`, `get_Type` for enrichment).
  8. Cleanup: `WTSFreeMemory`-equivalent release of BSTRs and interface refs; `CoUninitialize`.
- **Vault link**: No direct vault card — vault's T-020 anti-analysis suite covers VM detection and IAT camouflage but does not yet implement patch-level recon. This is the canonical reference for adding KB-by-KB patch enumeration to the `byakugan.rs` recon module (T-023).
- **Tool/code**: `wuapi.h` + `Wuapi.lib` (course text says `Wuguid.lib` — that is incorrect; the correct lib is `Wuapi.lib`, GUIDs are in `wuapi.h`).
- **OPSEC**: COM instantiation + RPC to WUA service generates event log entries (`Microsoft-Windows-WindowsUpdateClient` operational log). EDRs that monitor COM instantiation may flag `IUpdateSearcher` usage in non-WU-host processes. Use only when reconning for patch state; don't loop on it.

### EnumProcesses (PID-Only Snapshot)
- **What**: Return an array of process IDs currently mapped in the system.
- **When to use**: Quick PID harvest when you don't need names/paths (e.g., bulk OpenProcess probing for handle privilege enumeration).
- **How**:
  1. Allocate a `DWORD` array sized conservatively (e.g., 1024 entries).
  2. `EnumProcesses(dwProcList, sizeof(dwProcList), &dwRealSize)`.
  3. Compute count: `dwCount = dwRealSize / sizeof(DWORD)`.
  4. For each PID, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)` then `QueryFullProcessImageName`/`GetProcessImageFileName` to enrich.
- **Vault link**: No direct mapping. Useful as a pre-filter before selecting injection targets for T-007 Pool Party / T-008 Threadless / T-012 Early Cascade — filter by architecture, session, and parent PID before committing to a target.
- **Tool/code**: `psapi.h` + `Psapi.lib`. `K32EnumProcesses` on Win7+ (the `EnumProcesses` macro).
- **OPSEC**: `EnumProcesses` is unmonitored by most EDRs. `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is also low-signal. Risky rights (`PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`) come later during actual injection and are what trip telemetry.

### CreateToolhelp32Snapshot Process Walk
- **What**: Take a snapshot of processes/threads/modules/heaps and iterate via `Process32First`/`Process32Next`.
- **When to use**: Default choice for implant `ps` command — returns `PROCESSENTRY32` with `szExeFile`, `th32ProcessID`, `th32ParentProcessID`, `cntThreads`, `pcPriClassBase`.
- **How**:
  1. `HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` — `0` for all processes, or a PID for that process + its threads/modules/heaps.
  2. Error-check against `INVALID_HANDLE_VALUE`.
  3. `PROCESSENTRY32 pe32 = { .dwSize = sizeof(PROCESSENTRY32) }`.
  4. `Process32First(snap, &pe32)` then `do { ... } while (Process32Next(snap, &pe32));`.
  5. `CloseHandle(snap)` when done.
- **Vault link**: Useful for parent-PID-based process tree analysis before T-015 PPID Spoofing — knowing the legitimate parent of `explorer.exe` or `svchost.exe` lets you spoof believable lineages.
- **Tool/code**: `tlhelp32.h`. Flags: `TH32CS_SNAPPROCESS`, `TH32CS_SNAPTHREAD`, `TH32CS_SNAPMODULE`, `TH32CS_SNAPHEAPLIST`, `TH32CS_SNAPMODULE32` (cross-arch from 64→32).
- **OPSEC**: Snapshot is a stale view — newly created processes after the snapshot won't appear. This is fine for `ps` but inadequate for race-condition scenarios (use WTS or NtQuerySystemInformation instead). `CreateToolhelp32Snapshot` is monitored by some EDRs for `TH32CS_SNAPMODULE` (DLL listing) — process-only snapshots are lower signal.

### WTSEnumerateProcessesEx (Remote + Cross-Session)
- **What**: Enumerate processes locally or on a remote RDS-configured host with detailed per-process metrics including session ID.
- **When to use**: Session-aware process selection — picking an injection target in a specific user's session for token theft, or pivoting to another host over RDP/RPC.
- **How**:
  1. `HANDLE hServer = WTSOpenServer(L"HOSTNAME")` or `WTS_CURRENT_SERVER_HANDLE` for local.
  2. `WORD level = 1;` (1 = `WTS_PROCESS_INFO_EX`).
  3. `WTSEnumerateProcessesEx(hServer, &level, WTS_ANY_SESSION, &pProcInfo, &count)`.
  4. Iterate `pProcInfo[i]` — each entry gives `ProcessId`, `sid`, `pDomainName`, `pUserName`, `pProcessName`, `NumberOfThreads`, `HandleCount`, `PagefileUsage`, `WorkingSetSize`, `UserTime`, `KernelTime`.
  5. `WTSFreeMemoryEx(WTSTypeProcessInfo, pProcInfo, count)` — not the plain `WTSFreeMemory`, the `Ex` variant for level 1.
  6. `WTSCloseServer(hServer)`.
- **Vault link**: Direct enabler for cross-session injection paths in T-007 Pool Party / T-012 Early Cascade. The vault's existing techniques assume same-session; combining them with WTS session enumeration opens lateral session-hopping primitives not yet documented.
- **Tool/code**: `wtsapi32.h` + `Wtsapi32.lib`. Remote query requires the target's `fDisableTSConnectDisable` registry policy to permit remote interrogation.
- **OPSEC**: Remote WTS calls are loud — they authenticate to `RPCSS` on the target and show up as `WTSOpenServer`/`WTSEnumerateProcesses` events. Local calls are quieter. Pair with T-016 stack spoofing if you must call remotely to mask the calling thread's stack.

### NtQuerySystemInformation (SystemProcessInformation)
- **What**: Single native API call returning a linked list of `SYSTEM_PROCESS_INFORMATION` structs with thread-level detail embedded.
- **When to use**: When you want maximum process detail in one call and can tolerate native-API breakage risk; preferred for stealth implants that want to avoid Win32 surface area.
- **How**:
  1. Resolve `NtQuerySystemInformation` from `ntdll.dll` via `GetProcAddress` (or vault's T-004 PEB Walker for full avoidance of `kernel32`/`GetProcAddress`).
  2. First call: `NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnLength)` to learn required buffer size (returns `STATUS_INFO_LENGTH_MISMATCH`).
  3. `VirtualAlloc` a buffer of `returnLength` bytes.
  4. Second call: `NtQuerySystemInformation(SystemProcessInformation, buf, returnLength, NULL)`.
  5. Cast `buf` to `PSYSTEM_PROCESS_INFORMATION`, walk via `NextEntryOffset` until `0`.
  6. Per entry, extract `ImageName` (UNICODE_STRING), `UniqueProcessId`, `InheritedFromUniqueProcessId`, `NumberOfThreads`, `HandleCount`, `SessionId`, `WorkingSetSize`, `UserTime`, `KernelTime`, and embedded `Threads[]` of `SYSTEM_THREAD_INFORMATION`.
  7. `VirtualFree(buf)`.
- **Vault link**: This is the **foundational native API** the vault's other native techniques build on. T-001 RecycledGate / T-002 Hell's-Halo's-Tartarus Gate / T-003 VEH Gate all resolve syscalls from the same `ntdll.dll` this API lives in. Operationally, after resolving SSNs (T-002/T-003) for direct `NtQuerySystemInformation` syscall, you'd avoid even the resolved `GetProcAddress` path — pure indirect syscall dispatch.
- **Tool/code**: `winternl.h` for the partial prototype; full `SYSTEM_PROCESS_INFORMATION` layout from x64dbg's `ntdll.h` (referenced in course: `github.com/x64dbg/x64dbg/.../ntdll.h`). Enum value for `SystemProcessInformation` is `5` (or use `SystemExtendedProcessInformation` = 57 for `UniqueProcessKey`).
- **OPSEC**: Native API — bypasses Win32-layer hooks (most EDRs hook `CreateToolhelp32Snapshot`, `EnumProcesses`, WTS). If an EDR hooks `ntdll.dll`'s `NtQuerySystemInformation` export, fall back to vault's T-001/T-002/T-003 indirect syscall dispatch. The two-call pattern is normal and not specifically flagged.

### Installed Software Survey
- **What**: Walk the conventional install directories to inventory installed applications.
- **When to use**: First-pass application inventory; identify EDR/AV products, dev tools, vulnerable/known-bad versions.
- **How**:
  1. Resolve system drive via `GetSystemDirectory` or `SHGetKnownFolderPath(FOLDERID_Windows)`, strip to root.
  2. Enumerate `<drive>:\`, `<drive>:\Program Files`, `<drive>:\Program Files (x86)`.
  3. For each subdirectory, identify the executable and version via `GetFileVersionInfoEx` + `VerQueryValueW` on `\\FileDescription`, `\\ProductName`, `\\ProductVersion`.
  4. Cross-reference vendor signatures against a pre-briefed NOGO list (e.g., known EDR vendor names).
- **Vault link**: T-023 Client Capabilities — `sysinfo_collect.rs` should incorporate this. T-020 Anti-Analysis Suite overlaps for EDR detection; combining app inventory with anti-VM checks gives a fuller go/no-go picture.
- **Tool/code**: `SHGetKnownFolderPath` (Win Vista+), `GetFileVersionInfoExW`, `VerQueryValueW`. 8.3 short names: `C:\Progra~1`, `C:\Progra~2` for path-length-constrained contexts.
- **OPSEC**: Directory enumeration generates normal file-system access; `FindFirstFileEx`/`FindNextFile` are not heavily monitored. Reading `VersionInfo` resources is also low-signal. The risk is reading a sentinel file (honeypot) — use `GetFileAttributesEx` first to skip names on a denylist.

### Recursive Directory Walk (dirwalk)
- **What**: Recursively enumerate a directory tree to locate a specific file or build a complete inventory.
- **When to use**: Locate user-installed apps (Documents, Downloads), find config/secrets files, build file inventory for exfil triage.
- **How**:
  1. `FindFirstFileEx(root, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH)`.
  2. Loop with `FindNextFile`:
     - Skip `.` and `..`.
     - If `fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY`: recurse with subpath.
     - Else: match against target pattern (`PathMatchSpec` or manual wildcard).
  3. `FindClose(hFind)` to leak the handle.
- **Vault link**: T-023 Client Capabilities — `FileFinder` capability. T-020 anti-analysis includes IAT camouflage; dirwalk provides the corpus against which to match camouflage targets (e.g., find a `msvcr100.dll` to impersonate).
- **Tool/code**: `FindFirstFileEx`, `FindNextFile`, `FindClose`, `PathMatchSpec`. For large trees, `FindExInfoBasic` + `FIND_FIRST_EX_LARGE_FETCH` reduces round-trips.
- **OPSEC**: Recursive `C:\` walks are noisy — volume of `FindFirstFile`/`FindNextFile` calls is anomalous. Constrain depth and target directories (`%USERPROFILE%\Downloads`, `C:\Users\<user>\AppData`) instead of full-system walks. Consider `NtQueryDirectoryFile` (native) to bypass Win32 hook points.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `KUSER_SHARED_DATA @ 0x7FFE0000` | OS version/arch without API call | Zero telemetry; validate offsets per build via Vergilius Project |
| `GetVersionExA/W` | Documented OS version query | Deprecated; manifest-gated to ≤ 6.2 unless declared |
| `GetNativeSystemInfo` | Processor architecture (PROCESSOR_ARCHITECTURE_*) | Low signal; use to confirm x86 vs x64 vs ARM64 before payload selection |
| `Get-HotFix` (PowerShell) | Quick hotfix query via Win32_QuickFixEngineering | **Incomplete** — misses non-QFE updates; uses PowerShell = high signal |
| `wmic qfe list` | Same as Get-HotFix via WMIC | WMIC is being deprecated by Microsoft; flagged by some EDRs |
| WUA COM family (`IUpdateSession`/`IUpdateSearcher`/`ISearchResult`/`IUpdateCollection`/`IUpdate`) | Complete installed-update enumeration | Headers: `wuapi.h`, lib: `Wuapi.lib` (course's `Wuguid.lib` is wrong). Generates WUA client operational-log events |
| `EnumProcesses` (psapi.h/Psapi.lib) | Simple PID array | Low signal; for richer info, follow with `OpenProcess` + `QueryFullProcessImageName` |
| `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32First`/`Process32Next` | Snapshot-based process walk with PROCESSENTRY32 | Stale view; `TH32CS_SNAPMODULE` variant is more EDR-monitored |
| `WTSEnumerateProcessesEx` + `WTS_PROCESS_INFO_EX` (wtsapi32.h/Wtsapi32.lib) | Detailed local/remote process info, cross-session | Remote calls require RDS-enabled target + authenticate to RPCSS; `WTSFreeMemoryEx` for level-1 cleanup |
| `NtQuerySystemInformation(SystemProcessInformation)` (winternl.h, ntdll.dll) | Richest single-call enumeration | Native API; bypasses Win32 hooks; pair with vault T-001/T-002/T-003 for indirect-syscall variant |
| `SYSTEM_PROCESS_INFORMATION` struct (x64dbg ntdll.h) | Layout for NtQuerySystemInformation results | `NextEntryOffset`-linked list; embedded `SYSTEM_THREAD_INFORMATION[1]` array |
| `_EPROCESS` / `_KPROCESS` (ntoskrnl; view via `dt nt!_EPROCESS` in KD) | Kernel structures behind process list | `ActiveProcessLinks` (`_LIST_ENTRY`) at `+0x448` is the DKOM unlink target |
| `CoInitialize`/`CoCreateInstance` | WUA COM bootstrap | Generates COM activation events; some EDRs flag IUpdateSearcher from non-system processes |
| 8.3 short names (`C:\Progra~1`, `C:\Progra~2`) | Path-length-safe access to install dirs | Useful in tooling where `MAX_PATH` is a constraint |

## Gaps & Extensions

**What the vault covers that this training does not:**
- **T-004 PEB Walker** — the vault already has a `gs:[0x60]`-based manual module resolution primitive. SEC670 doesn't touch PEB at all; the course teaches `GetProcAddress`-style resolution implicitly. Operators should default to T-004 for any ntdll/kernel32 export lookup.
- **T-001 RecycledGate / T-002 Hell's-Halo's-Tartarus Gate / T-003 VEH Gate** — vault's indirect-syscall primitives let you call `NtQuerySystemInformation` (and `NtQueryDirectoryFile`, `NtOpenProcess`, etc.) without going through `ntdll.dll`'s hooked exports. The course's native-API discussion stops at `GetProcAddress("NtQuerySystemInformation")` — that is the **hookable** path. Upgrade with T-001–T-003.
- **T-016 EDR Evasion Suite** — vault's stack spoofing, PEB unlink, NTDLL unhook, arg spoofing all directly enhance the recon primitives covered here. SEC670 makes no mention of evasion layers; combine freely.
- **T-020 Anti-Analysis Suite** — anti-VM checks (10 of them) and IAT camouflage belong alongside the recon phase. SEC670's GO/NOGO framework is conceptually incomplete without T-020's anti-VM gate.
- **T-023 Client Capabilities** — `byakugan.rs` already does ARP/TCP/AD recon; `sysinfo_collect.rs` already does system info collection. This training describes the C-side primitives the Rust crates should wrap.

**What this training covers that the vault does not:**
- **KUSER_SHARED_DATA offset reads** — not currently in any vault card. Strong candidate for a new T-024 "KUSER_SHARED_DATA Recon" card or an extension to T-004. The vault's T-004 PEB Walker accesses the PEB at `gs:[0x60]`; the natural complement is `KUSER_SHARED_DATA` at the fixed VA `0x7FFE0000`. Both are user-shared-memory primitives with zero API surface.
- **WUA COM API patch enumeration** — no vault card currently documents this. Patch-state recon is foundational for go/no-go on exploit selection. Should be folded into T-023 client capabilities (`byakugan.rs` or `sysinfo_collect.rs`).
- **Four-API process enumeration tradeoff matrix** — the vault's injection cards (T-007–T-015) assume the operator already knows the target PID. SEC670's enumeration ladder (EnumProcesses → Toolhelp → WTS → NtQuerySystemInformation) is the missing prerequisite. Worth a dedicated "Process Enumeration Tradeoffs" reference even if not a technique card.
- **GO/NOGO decision framework** — operational decision-making is absent from the vault (it's pure tradecraft/technique). SEC670's framing — abort on unknown detective apps, pre-brief criteria — is good red-team process and worth preserving in an ops-runbook card.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| KUSER_SHARED_DATA @ 0x7FFE0000 for OS info | T-004 PEB Walker | Same tradecraft class (user-shared memory, zero API); complementary primitives — PEB for modules, KUSER_SHARED_DATA for OS metadata. Candidate for vault extension. |
| `NtQuerySystemInformation(SystemProcessInformation)` | T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate | Training uses `GetProcAddress` path (hookable); vault provides indirect-syscall dispatch to make the same call unhooked. Training's two-call size-then-fetch pattern carries over directly. |
| WUA COM `IUpdateSearcher::Search` for patch enumeration | (no vault card) | New capability — candidate for inclusion in T-023 client capabilities (extend `byakugan.rs` or `sysinfo_collect.rs`). |
| `CreateToolhelp32Snapshot` process walk | T-015 PPID Spoofing | Training enumerates parent PIDs; vault spoofs them. Toolhelp output (`th32ParentProcessID`) is the recon input T-015 consumes. |
| `WTSEnumerateProcessesEx` cross-session enumeration | T-007 Pool Party, T-012 Early Cascade | Training enumerates sessions; vault injects same-session. Combining enables session-hopping injection (not yet vault-documented). |
| `EnumProcesses` + `OpenProcess` enrichment | T-007–T-015 injection family | PID harvest is the pre-filter for any injection technique. |
| `_EPROCESS`/`_KPROCESS` + `ActiveProcessLinks` DKOM | T-016 PEB unlink, T-020 anti-analysis | Same concept (unlinking from kernel-tracked list); vault does the user-mode analog (PEB unlink) — DKOM is the kernel-mode analog covered conceptually in training. |
| GO/NOGO decision framework | T-020 Anti-Analysis Suite | Training supplies the decision-making overlay; vault supplies the detection-evading techniques that inform the decision. Combine both. |
| `GetNativeSystemInfo` architecture query | T-021 shellcode encoding (IPv4/IPv6/MAC/UUID/words) | Architecture check before payload selection — vault's encoders don't gate by arch; SEC670's `wProcessorArchitecture` field (9=AMD64, 0=INTEL, 12=ARM64) is the gate. |
| Installed-software survey at `C:\Program Files*` | T-020 Anti-Analysis (Kaguya LOtL inventory) | Training does manual directory walk; vault's Kaguya does LOtL-binary inventory + EDR detection. Overlap on the "what's installed?" question, complementary approaches. |
```

Let me verify the document is complete and properly formatted before finalizing... The YAML frontmatter is complete with all required fields. The structure follows the system prompt: TL;DR, Key Concepts (9 items), Operational Techniques (7 techniques with full What/When/How/Vault link/Tool/OPSEC breakdown), Tool & Tradecraft Reference table, Gaps & Extensions, Cross-Reference Matrix. All good.