---
id: RTO-token-escalation-services-uac
name: Token Escalation, Services, Pipes, and UAC Bypass
source: Red Team Ops / SEC670 (SANS)
category: privilege-escalation
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-015, T-017, T-018, T-021, T-023]
tags: [token-impersonation, scm, services, named-pipes, uac-bypass, autoelevate, uacme, lpe, privilege-escalation, manifest-parsing, fusion]
---

# Token Escalation, Services, Pipes, and UAC Bypass — Training Reference

## TL;DR
SEC670 Module 12 walks through three classic Windows LPE tradecraft vectors: token theft (the API chain behind Meterpreter's `getsystem`), programmatic SCM/service manipulation (enumerate, query, modify, create, install), and UAC bypass research via embedded-manifest `autoElevate` parsing using the UACME project. The training is heavily Win32 API focused and complements vault cards T-015 (PPID Spoofing) and T-017/T-023 (persistence and UAC bypass) by providing the underlying API mechanics the vault's Rust implementations build on.

## Key Concepts

1. **Token theft as LPE primitive**
   The API chain `OpenProcess` → `OpenProcessToken` → `DuplicateTokenEx` → `CreateProcessWithTokenW` (or `ImpersonateLoggedOnUser` + `NtCreateThreadEx`) is the foundation of Meterpreter's `getsystem` and any custom privilege escalation. The vault does not have a dedicated token-theft card; this training fills that gap.
   *Vault link*: Related to T-015 (PPID Spoofing) — both manipulate process creation attributes for privilege context, but tokens vs. parent PID are distinct primitives.

2. **SCM database and the Services registry hive**
   All services are tracked in `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`. Each subkey contains `ImagePath`, `Start`, `Type`, `ErrorControl`, `ObjectName`. SCM is an RPC server — remotely queryable. Each service start triggers: SCM DB lookup → account logon → profile load → suspended process start → token assignment → resume.
   *Vault link*: T-017 (Five-Layer Persistence) uses `schtask` persistence which is SCM-mediated; the underlying `CreateService` API is the same primitive.

3. **Service attributes (Type / Start / ErrorControl)**
   - `dwServiceType`: `SERVICE_WIN32_OWN_PROCESS` (0x10) vs `SERVICE_WIN32_SHARE_PROCESS` (0x20)
   - `dwStartType`: `AUTO_START` (2), `DEMAND_START` (3), `DISABLED` (4)
   - `dwErrorControl`: `IGNORE` (0), `NORMAL` (1), `SEVERE` (2), `CRITICAL` (3)
   For malware, `OWN_PROCESS` + `AUTO_START` + `NORMAL` failure action (or restart-on-failure trigger via `ChangeServiceConfig2`) is the standard.

4. **Unquoted service path LPE**
   When `ImagePath` contains spaces and isn't quoted, Windows walks the path left-to-right trying each truncation as an executable. Drop `SEC.exe` in `C:\Users\student\` and a service whose ImagePath is `C:\Users\student\SEC 670\Labs\...exe` will execute your binary as the service account (often SYSTEM).
   *Vault link*: Not covered in vault — useful recon primitive for engagement pre-assessment.

5. **Anonymous vs. Named pipes**
   - **Anonymous** (`CreatePipe`): local only, parent/child only, one-way, handle inheritance required
   - **Named** (`CreateNamedPipe`): duplex, network-accessible (with `Server` service), any process can connect via `\\ComputerName\pipe\PipeName`, supports multiple instances
   Named pipes are the backbone of `getsystem`'s impersonation chain ( Meterpreter's named-pipe impersonation).

6. **UAC is not a security boundary**
   UAC is a user convenience + a soft defense, not a hard boundary. `autoElevate=TRUE` in an embedded manifest lets signed Microsoft binaries elevate without a consent prompt — these are the bypass targets. The UACME project (hfiref0x) catalogs 80+ methods and provides manifest-parsing tooling.
   *Vault link*: T-021 (Crypto & Obfuscation) and T-023 (Client Capabilities) both reference UAC bypass via CMSTP — this training provides the more general `autoElevate` discovery workflow.

7. **Fusion / Activation Context for manifest parsing**
   Embedded manifests (resource type `RT_MANIFEST`) are loaded via `LdrResSearchResource` → activation context created → queried with `RtlQueryActivationContextApplicationSettings` for the `autoElevate` element. UACME's `fusion.c` implements this scanning pipeline (`FusionScanDirectory` → `FusionScanFiles` → `FusionCheckFile`).

## Operational Techniques

### Token Theft (TokenThief pattern)
- **What**: Steal a privileged process's primary token and use it to spawn a new process under the stolen identity.
- **When to use**: You have local code execution as medium-IL user, target is a high-IL or SYSTEM process (e.g., `winlogon.exe`, `lsass.exe`).
- **How**:
  1. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid)` — target a SYSTEM process
  2. `OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)`
  3. `DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hDupToken)` — `SecurityImpersonation` is sufficient if not crossing to another host
  4. (Option A) `CreateProcessWithTokenW(hDupToken, ..., lpCommandLine, ...)` — requires `SE_IMPERSONATE_NAME` (typically medium+ IL)
  5. (Option B) `ImpersonateLoggedOnUser(hDupToken)` then `NtCreateThreadEx` in current process — stealthier, no child proc
  6. (Option C — getsystem classic) Named-pipe impersonation: create pipe, lure SYSTEM process to connect, `ImpersonateNamedPipeClient` steals its token
- **Vault link**: T-015 (PPID Spoofing) covers `STARTUPINFO`-level attribute spoofing; this is the complementary token-level primitive. The vault lacks a dedicated token-theft card — this training material is the canonical reference.
- **Tool/code**: Lab 3.5 "TokenThief" (eWorkbook); Meterpreter `getsystem` source on GitHub as reference.
- **OPSEC**: `CreateProcessWithTokenW` is loud — observed by EDR via `CreateProcess` telemetry in unusual caller context. `ImpersonateLoggedOnUser` + in-proc thread injection is quieter. Handle duplication leaves audit trail if `SeAuditPrivilege` is missing.

### Service Enumeration
- **What**: Programmatically enumerate the SCM database to find LPE targets (unquoted paths, weak permissions, writable binary paths).
- **When to use**: Initial recon on a compromised host, looking for misconfigured services.
- **How**:
  1. `OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE)`
  2. `EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &cbNeeded, &svcsReturned, &resume, NULL)` — first call fails with `ERROR_INSUFFICIENT_BUFFER`
  3. Allocate `cbNeeded` bytes (capped at 256KB max per API contract)
  4. Re-call with allocated buffer; iterate `ENUM_SERVICE_STATUS_PROCESS[]`
  5. For each service: `OpenService(hSCM, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)`
  6. `QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, ...)` → get PID
  7. `QueryServiceConfig(hSvc, &cfg, 8192, &cbNeeded)` → inspect `lpBinaryPathName` for spaces / missing quotes
- **Vault link**: Not directly covered in vault — the vault's persistence card T-017 builds services for persistence, not for recon. This enumeration flow complements vault tradecraft.
- **Tool/code**: `wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\"` for quick LOtL recon.
- **OPSEC**: `EnumServicesStatusEx` is non-noisy (used by `services.msc`, `sc query`, Defender itself). Safe to call.

### Service Configuration Modification (LPE via weak permissions)
- **What**: Modify an existing service's `lpBinaryPathName` to point at your payload, then restart the service.
- **When to use**: You've found a service whose ACL grants `SERVICE_CHANGE_CONFIG` to your user (CVE-2019-1322 UsoSvc pattern).
- **How**:
  1. Enumerate services (see above) to find candidate
  2. Verify ACL with `GetSecurityInfo` on the `SC_HANDLE` or PowerShell `Get-Acl`
  3. `OpenService(hSCM, name, SERVICE_CHANGE_CONFIG | SERVICE_START)`
  4. `ChangeServiceConfig(hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, "C:\\path\\to\\payload.exe", NULL, NULL, NULL, NULL, NULL, NULL)` — pass `SERVICE_NO_CHANGE` for the first 3 params, `NULL` for the rest to preserve them
  5. `StartService(hSvc, 0, NULL)` — service executes your binary in the service's configured account context (often LocalSystem)
- **Vault link**: T-017's `schtask` persistence uses the parallel `ITaskScheduler` COM interface, not `ChangeServiceConfig`. Both land in the SCM DB. T-018 (Edo Tensei) resurrection engine could incorporate service-modification as a re-spawn technique.
- **Tool/code**: `sc config <svc> binpath= "..."` for one-shot LOtL; programmatic via `ChangeServiceConfigA`.
- **OPSEC**: Service config change generates Event ID 7045 (Service Install) and 7040 (Service Config Changed). Use a service name that blends with installed software (e.g., `gupdate`, `iphlpsvc`-adjacent).

### Malicious Service Creation (Persistence)
- **What**: Install a custom service binary as `SERVICE_WIN32_OWN_PROCESS` with `AUTO_START`.
- **When to use**: Persistence phase — survives reboot, runs as LocalSystem, no user logon required.
- **How**:
  1. Compile service binary implementing `ServiceMain` + `HandlerEx`
  2. `ServiceMain` must: `RegisterServiceCtrlHandlerEx(name, HandlerEx, ctx)` → set `SERVICE_RUNNING` via `SetServiceStatus` → enter work loop
  3. Service installer (separate binary, per OPSEC best practice) calls `OpenSCManager` then `CreateService(hSCM, "name", "Display", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, AUTO_START, NORMAL_ERROR, "C:\\path\\to\\svc.exe", NULL, NULL, NULL, NULL, NULL)`
  4. Optionally `ChangeServiceConfig2` to set failure action = restart
- **Vault link**: T-017 (Five-Layer Persistence) documents persistence layers including schtask — services are a natural sixth layer not explicitly covered. The vault's module-overload / proxy-DLL techniques (T-008, T-016) could be used to host the service binary in a stealthier backing than a standalone EXE.
- **Tool/code**: `sc create notevil binPath= "C:\path\to\notevil.exe" type= own start= auto`; `sc query notevil` to verify.
- **OPSEC**: New service → Event ID 7045. Name should mimic vendor update services. Set `FAILURE_ACTION_RESTART` with 60s delay to avoid restart-loop noise. Service binary should NOT self-install (separate installer is the SEC670-recommended OPSEC pattern).

### Named Pipe C2 / Impersonation Substrate
- **What**: Create a named pipe server to lure privileged clients (for token theft) or for IPC with injected payloads.
- **When to use**: When you need duplex IPC with unrelated processes, or when targeting SYSTEM processes that connect to predictable pipe names.
- **How**:
  1. `CreateNamedPipeA("\\\\.\\pipe\\myPipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa)`
  2. `ConnectNamedPipe(hPipe, NULL)` — blocking wait
  3. For impersonation: `ImpersonateNamedPipeClient(hPipe)` after client writes — steals client's token
  4. For IPC: `ReadFile`/`WriteFile` on `hPipe`
  5. Client side: `CreateFileA("\\\\ServerName\\pipe\\myPipe", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)`
- **Vault link**: Not explicitly covered as a card, but related to T-022 (Network Suite) — `nt_sockets` and SOCKS5 are network-side siblings. Pipe-based C2 is missing from the vault.
- **Tool/code**: Lab source "Creating Pipes" (eWorkbook). `CallNamedPipe` for one-shot client.
- **OPSEC**: Predictable pipe names (e.g., `\\.\pipe\status`, `\\.\pipe\srvsvc`) get monitored by some EDRs. Use random GUIDs per-session. `CreateNamedPipe` itself is a known IOA.

### UAC Bypass Discovery (autoElevate scanning)
- **What**: Find signed Microsoft binaries with `autoElevate=TRUE` in their embedded manifest, then identify a co-located DLL planting / IPC / registry-manipulation vector to weaponize a silent elevation chain.
- **When to use**: You're a medium-IL admin user and need high-IL execution without a UAC prompt.
- **How**:
  1. Pull UACME source: `https://github.com/hfiref0x/UACME`
  2. Run `Yuubari\FusionScanDirectory` against `C:\Windows\System32\` to enumerate autoElevate binaries
  3. For each candidate binary, run Process Monitor trace during launch — observe registry/file/COM accesses that could be hijacked
  4. Identify a writable target (per-user registry key, per-user DLL search path, COM hijack victim)
  5. Place payload at the hijack target, run the autoElevate binary → it elevates silently, triggers payload in high-IL
  6. (Training lab path) Reference `https://github.com/Yet-Zio/WusaBypassUAC` for a worked example
- **Vault link**: T-021 (Crypto & Obfuscation) and T-023 (Client Capabilities) both list `uac_cmstp.rs` (CMSTP bypass). This training extends that with the general `autoElevate` discovery methodology — the vault has one specific bypass (CMSTP), the training has the discovery workflow for arbitrary new bypasses.
- **Tool/code**: UACME's `fusion.c` (`FusionScanDirectory` / `FusionScanFiles` / `FusionCheckFile`); underlying NT APIs `NtCreateFile`, `NtCreateSection`, `NtMapViewOfSection`, `LdrResSearchResource`, `RtlQueryActivationContextApplicationSettings`; `RtlSecureZeroMemory`, `HeapAlloc`/`HeapFree`, `FindFirstFile`/`FindNextFile`.
- **OPSEC**: autoElevate binaries themselves are benign. Detection pivots on the hijack target — e.g., per-user registry write under `HKCU\Software\Classes\...` immediately before launching a known autoElevate binary is a known IOA. Use this for one-shot elevation then revert the hijack.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `OpenSCManager` / `EnumServicesStatusEx` / `QueryServiceConfig` / `ChangeServiceConfig` / `CreateService` / `StartService` | SCM enumeration, modification, creation | Mostly quiet; ETW `Microsoft-Windows-ServiceControlManager` events |
| `OpenProcess` / `OpenProcessToken` / `DuplicateTokenEx` / `CreateProcessWithTokenW` / `ImpersonateLoggedOnUser` | Token theft LPE chain | Loud when crossing IL; requires `SE_IMPERSONATE_NAME` |
| `CreatePipe` | Anonymous pipe (parent/child IPC) | Local-only; minimal IOA |
| `CreateNamedPipe` / `ConnectNamedPipe` / `ImpersonateNamedPipeClient` | Named pipe IPC + token impersonation | Predictable pipe names are IOA; randomize per-session |
| `wmic service get name,pathname,displayname,startmode \| findstr /i auto \| findstr /i /v "C:\\Windows\\"` | LOtL unquoted service path recon | WMI event log noise; harmless |
| `sc.exe create / config / query / start` | Service install / control wrapper | Event 7045 on create, 7040 on config change |
| UACME (hfiref0x) — `Yuubari/fusion.c` | Manifest `autoElevate` scanning | Recon only — no direct detection |
| `LdrResSearchResource` + `RtlQueryActivationContextApplicationSettings` | RT_MANIFEST extraction & element query | Quiet; uses documented loader path |
| `FindFirstFile` / `FindNextFile` / `HeapAlloc` / `HeapFree` | Directory enumeration (UACME Fusion) | Standard pattern |
| `NtCreateFile` + `NtCreateSection` + `NtMapViewOfSection` | Memory-map target EXE for manifest parsing | NT API use bypasses user-mode hooks on `CreateFile`-wrappers |
| `RtlSecureZeroMemory` | Secure buffer zeroing | Best-practice hygiene |
| Process Monitor (Sysinternals) | Trace autoElevate binary behavior | Recon tool, not on-target |
| WusaBypassUAC (Yet-Zio) | Reference UAC bypass example | Education only |
| Meterpreter `getsystem` source | Reference token-theft / named-pipe impersonation | Education reference |

## Gaps & Extensions

**Training covers that vault doesn't:**
- **Token theft / impersonation as a primitive** — no dedicated card in the vault covers `OpenProcessToken` → `DuplicateTokenEx` → `CreateProcessWithTokenW` or named-pipe impersonation. This is a significant gap.
- **SCM enumeration and service-config-based LPE** — the vault's T-017 persistence uses `ITaskScheduler` (schtask) but not the `CreateService` / `ChangeServiceConfig` family for either LPE or persistence.
- **Named-pipe IPC as a C2 substrate** — vault networking (T-022) is TCP / HTTP / SOCKS5 / NT-sockets; named-pipe C2 is absent.
- **UAC bypass discovery methodology** — vault has one concrete bypass (CMSTP, in T-021/T-023) but not the general autoElevate scanning workflow that lets an operator find novel bypasses per-engagement.
- **Manifest / activation-context parsing** — useful for IAT camouflage, target-binary profiling, and dynamic API resolution pre-flight; not in T-020 (Anti-Analysis).

**Vault covers that training doesn't:**
- **Modern injection primitives** — Pool Party, Threadless, Ghosting, Herpaderping, Dirty Vanity, Early Cascade, Vectored Overloading (T-007 through T-013) are entirely absent from SEC670 Module 12.
- **Sleep obfuscation (Ekko ROP, T-005)** — SEC670 services module has no equivalent.
- **EDR evasion suite (T-016)** — AMSI / ETW patching, stack spoofing, unhooking, ACG, block-DLL are not in this training module.
- **Direct / indirect syscalls (T-001 through T-006)** — SEC670 uses standard Win32 (`CreateService`, `OpenProcessToken`, etc.) with no syscall-level evasion.
- **PPID spoofing (T-015)** — SEC670 creates services the standard way; no `STARTUPINFOEX` attribute-list manipulation.
- **Five-layer persistence (T-017)** including COM hijack, NTFS EA, TLS callback, PhantomPersist — far beyond SEC670's single-layer service install.
- **BYOVD (T-022)** — kernel-level elevation via vulnerable driver load; SEC670 only covers user-mode token/service/UAC LPE.
- **Polymorphic resurrection (T-018 Edo Tensei)** — service install in SEC670 is static; no resurrection across technique stacks.

**Where training adds genuinely new knowledge:**
- The complete SCM API surface (`EnumServicesStatusEx`, `QueryServiceConfig`, `ChangeServiceConfig`, `CreateService`) is the canonical reference for any service-related tradecraft and should be added as a new vault card (proposed: **T-024 Service Manipulation Suite**).
- The autoElevate scanning methodology (UACME Fusion pipeline) extends T-021 / T-023's single-bypass coverage into a discovery framework — operators can find fresh per-engagement bypasses instead of relying on the static CMSTP technique.
- Token theft as a primitive bridges T-015 (PPID spoofing) — together they form a complete process-creation-context manipulation suite (parent PID + primary token).

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Token theft (`OpenProcessToken` / `DuplicateTokenEx` / `CreateProcessWithTokenW`) | (gap) | Not covered in vault; training is canonical reference |
| Named-pipe impersonation (`getsystem` pattern) | (gap) | Not covered in vault; suggested new card |
| SCM enumeration (`EnumServicesStatusEx`) | (gap) | Not covered in vault; suggested new card |
| Service config modification for LPE (`ChangeServiceConfig`) | T-017 Five-Layer Persistence | Vault uses `ITaskScheduler` (schtask) instead of `CreateService`; training adds `ChangeServiceConfig` path |
| Malicious service creation (`CreateService` + `ServiceMain` + `HandlerEx`) | T-017 Five-Layer Persistence | Vault's schtask persistence is the sibling; service-based persistence is not in vault |
| Service failure restart (`ChangeServiceConfig2`) | T-018 Edo Tensei | Vault has resurrection via technique-stack polymorphism; training's restart-on-failure is a simpler primitive |
| Unquoted service path LPE | (gap) | Not in vault; recon primitive |
| Named-pipe C2 / IPC | T-022 Network Suite | Vault has NT-sockets and TCP/SOCKS5/HTTP; named-pipe transport absent |
| Anonymous pipes (`CreatePipe`) | (gap) | Not covered; standard IPC primitive |
| Manifest `autoElevate=TRUE` scanning | T-021 Crypto & Obfuscation, T-023 Client Capabilities | Vault has CMSTP-specific bypass; training has general discovery workflow |
| UACME `FusionScanDirectory` / `FusionScanFiles` / `FusionCheckFile` | (gap) | Manifest-scanning framework not in vault |
| `LdrResSearchResource` / `RtlQueryActivationContextApplicationSettings` | T-020 Anti-Analysis (IAT camouflage) | Vault uses IAT camouflage; training's RT_MANIFEST parsing extends to resource-based recon |
| `NtCreateFile` / `NtCreateSection` / `NtMapViewOfSection` for image mapping | T-004 PEB Walker, T-007 Pool Party | Vault uses these NT APIs internally; training shows direct use for manifest parsing |
| Manifest XML parsing (`supportedOS`, `heapType`, `autoElevate`) | (gap) | Not in vault; useful for target profiling |
| `StartServiceCtrlDispatcher` / `RegisterServiceCtrlHandlerEx` / `SetServiceStatus` | (gap) | Service-side skeleton not in vault |
| High-IL vs Medium-IL vs Low-IL token context | T-015 PPID Spoofing | T-015 manipulates parent process context; training manipulates token context — complementary |
| Service failure action (`ChangeServiceConfig2`) | T-018 Edo Tensei (resurrection engine) | Vault's resurrection is at the technique-stack layer; training's restart is at the SCM layer — could compose |
| `wmic service` recon | T-020 Anti-Analysis (Kaguya LOtL) | Kaguya does LOtL inventory; this wmic one-liner is the specific service variant |