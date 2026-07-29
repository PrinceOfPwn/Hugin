---
id: T-044
name: Service-Based Local Privilege Escalation via SCM Enumeration
category: privesc
tier: A
crate: none
source_file: none
mitre: T1543.003
mitre_secondary: [T1574.009, T1574.010, T1574.011, T1007]
tags: [privesc, windows-services, scm, unquoted-path, service-dacl, sddl, imagepath-hijack, weak-binary-permissions, service-enumeration]
origin: atlas-synthesis
member_notes: ['lgtm:proposed-technique-service-lpe-enumeration', 'lgtm:service-based-lpe-proposed-technique']
---

# Service-Based Local Privilege Escalation via SCM Enumeration — Converting Weak Service Configuration into SYSTEM Execution

## Summary

Service-based local privilege escalation enumerates the Service Control Manager (SCM) database, identifies services that execute as LocalSystem yet expose a configuration weakness, and converts that weakness into code execution under the service account. The technique targets the service-control architecture itself: the SCM database, per-service security descriptors expressed in SDDL, the ImagePath values under `HKLM\SYSTEM\CurrentControlSet\Services`, CreateProcess command-line tokenization for unquoted paths, and NTFS ACLs on service binaries. Operators use it because services start at boot without an interactive logon and frequently run with the most powerful local token on the host, so a single misconfiguration is a direct path from a medium-integrity user to SYSTEM. The weakness classes the material covers are unquoted service paths, writable service binaries, and service DACLs that grant low-privileged principals SERVICE_CHANGE_CONFIG, WRITE_DAC, or WRITE_OWNER. The principal interaction surface is the Win32 service API set (OpenSCManager, EnumServicesStatus, QueryServiceConfig, ChangeServiceConfig) and its sc.exe / PowerShell equivalents, all of which marshal to the services.exe RPC server.

## Mechanism

1. Acquire a handle to the SCM database with `OpenSCManager(lpMachineName, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)`. The material frames three handle types in SCM tradecraft: the SCManager handle, per-service Service handles, and the database lock handle obtained via LockServiceDatabase for serialized modification.
2. Enumerate services with `EnumServicesStatus(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL, ...)`, using the two-pass convention: first call sizes the buffer through `pcbBytesNeeded`, the second fills an array of `ENUM_SERVICE_STATUS` containing `lpServiceName`, `lpDisplayName`, and a `SERVICE_STATUS`. The material names EnumServicesStatus and QueryServiceStatus as the pair every service-recon tool implements.
3. For each entry, call `OpenService(hSCM, lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL)`, then `QueryServiceConfig` to retrieve the `QUERY_SERVICE_CONFIG`: `lpBinaryPathName` (the BINARY_PATH_NAME field shown by `sc.exe qc`), `dwStartType`, and `lpServiceStartName`. `QueryServiceStatus` returns the current run state.
4. Filter to high-value targets: services whose `lpServiceStartName` is LocalSystem (or another privileged account), start type `SERVICE_AUTO_START` (0x2), and ideally already running.
5. Test for an unquoted service path: `lpBinaryPathName` contains spaces and lacks surrounding quotes, e.g. `C:\Program Files\Vendor\svc.exe`. Because CreateProcess tokenizes an unquoted command line by probing progressively longer prefixes with `.exe` appended (`C:\Program.exe`, then `C:\Program Files\Vendor.exe`, then the full path), each prefix location is a candidate drop point. Test write access on the directory of every prefix earlier than the real binary.
6. Test binary permissions on the resolved ImagePath. CRTO demonstrates this with `Get-Acl` on the service path and flags `Allow: Modify, Synchronize` for the operator's SID or broad groups (Everyone, Authenticated Users, BUILTIN\Users). The programmatic equivalent is `GetNamedSecurityInfoA` with `SE_FILE_OBJECT`, which the material documents as supporting NTFS objects, services, keys, shares, and file-mapping objects.
7. Test the service object DACL with `sc.exe sdshow <service>` (the material uses BITS as the worked example) or `GetNamedSecurityInfoA` with the service object type. Parse the resulting SDDL using the ACE string grammar the material lays out: ace_type (`A` access-allowed, `D` access-denied, `OA`/`OD` object variants, `AU` audit), ace_flags (`CI`, `OI`, `NP`, `IO`, `ID`, `SA`), rights letters, and account SID constants (`IU` interactive user, `SU` service user, `BA` built-in administrators, `SY` local system).
8. Flag descriptors that grant a low-privileged principal any of: `DC` (SERVICE_CHANGE_CONFIG), `WD` (WRITE_DAC), `WO` (WRITE_OWNER), or the trigger combination `RP`+`WP` (start and stop). The material's worked exercise decodes a hardened service DACL into deny ACEs `DCLCWPDTSD` for IU/SU/BA and allow ACEs `CCLCSWLOCRRC` for IU/SU with the wider set `CCLCSWRPWPDTLOCRRC` for SY, demonstrating manual SDDL interpretation with sc.exe and Get-Service.
9. Exploit through whichever weakness is present: (a) unquoted path — drop a payload at a resolvable prefix in a writable directory; (b) weak binary ACL — replace or patch the binary in place; (c) SERVICE_CHANGE_CONFIG — call `ChangeServiceConfig` (or `sc.exe config <svc> binPath= "<command>"`) to repoint `lpBinaryPathName` at the payload; (d) weak ACL on `HKLM\SYSTEM\CurrentControlSet\Services\<name>` — rewrite the `ImagePath` value directly, the registry hive the material ties service configuration to.
10. Trigger execution: `StartService` / `sc start` when RP (SERVICE_START) is granted, `ControlService` stop followed by start when WP+RP are both granted, or passive wait for the next boot or crash-recovery restart of an auto-start service.
11. On start, services.exe spawns the configured binary under the service account's token. For a LocalSystem target the payload executes as NT AUTHORITY\SYSTEM in session 0. The material cites CVE-2019-1322 as a worked example of this service-configuration LPE class.

## OS Internals Context

The SCM (services.exe) is a user-mode RPC server, not a kernel subsystem. The Win32 service APIs exported by advapi32/sechost.dll are client stubs that marshal parameters to services.exe over local RPC (ncalrpc). The handles returned by OpenSCManager and OpenService are RPC context handles bound to the caller's access token; access checks execute inside services.exe against stored security descriptors, not in the Object Manager. Service objects are database records, not kernel objects — they cannot be opened through NtOpen* primitives.

Two distinct security descriptors govern the attack surface. The SCM database object has its own DACL controlling SC_MANAGER_* rights: SC_MANAGER_CONNECT (0x1), SC_MANAGER_CREATE_SERVICE (0x2), SC_MANAGER_ENUMERATE_SERVICE (0x4), SC_MANAGER_LOCK (0x8). The default descriptor permits authenticated and interactive users to enumerate, which is why the reconnaissance phase of this technique works from an unprivileged token. Each service then carries its own security descriptor, persisted in the registry at `HKLM\SYSTEM\CurrentControlSet\Services\<name>` in the `Security` value; when absent, SCM applies a default DACL granting full control to Administrators and LocalSystem and read-level access to interactive users. The deny-ACE exercise DACL in the material is an example of a hardened custom descriptor written with `sc.exe sdset`.

Service-specific SDDL rights letters map to access masks: `CC` = SERVICE_QUERY_CONFIG (0x0001), `DC` = SERVICE_CHANGE_CONFIG (0x0002), `LC` = SERVICE_QUERY_STATUS (0x0004), `SW` = SERVICE_ENUMERATE_DEPENDENTS (0x0008), `RP` = SERVICE_START (0x0010), `WP` = SERVICE_STOP (0x0020), `DT` = SERVICE_PAUSE_CONTINUE (0x0040), `LO` = SERVICE_INTERROGATE (0x0080), `CR` = SERVICE_USER_DEFINED_CONTROL (0x0100), with standard rights `RC`, `SD`, `WD`, `WO` carrying their usual meanings. WRITE_DAC on a service object lets the operator grant themselves SERVICE_CHANGE_CONFIG outright; WRITE_OWNER lets them seize ownership first and then rewrite the DACL, which is why both are escalation-sufficient even when DC itself is denied.

The unquoted-path primitive is documented CreateProcessW behavior rather than a service-specific flaw: when `lpApplicationName` is NULL and the command line is unquoted with embedded spaces, the loader probes progressively longer whitespace-delimited prefixes with `.exe` appended until an existing image is found. SCM launches services through this path using the `ImagePath` value (`REG_EXPAND_SZ`) as the command line, so any writable prefix directory resolves before the legitimate binary. The fourth surface, the registry key ACL itself, is independent of the service object DACL: the ACE grammar's registry rights letters (`KA` all, `KR` read, `KW` write, `KX` execute) apply to the service key, and SCM reads configuration from that key at start time.

Service processes execute in session 0 under session-0 isolation; LocalSystem (`ObjectName` = "LocalSystem") holds near-unrestricted local authority. Post-elevation token manipulation uses the same privilege-adjustment primitives the material covers elsewhere in the same module — LookupPrivilegeValue, OpenProcessToken, AdjustTokenPrivileges — for enabling present-but-disabled privileges such as SeDebugPrivilege.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (Win32 service APIs) and in sc.exe / PowerShell (`Get-Acl`) command lines.

An implementation would follow the two-pass RPC-buffer pattern throughout: `EnumServicesStatusExW` with `SC_ENUM_PROCESS_INFO` to recover PID and state in one call, `QueryServiceConfigW` for the `QUERY_SERVICE_CONFIG`, `GetNamedSecurityInfoA` with the service object type for the DACL, and `GetEffectiveRightsFromAcl` or AccessCheck to test the caller token against binary DACLs. Unquoted-path probing maps onto HUGIN's existing Nt* style: attempt `NtCreateFile`/`NtOpenFile` with FILE_WRITE_DATA against each prefix directory rather than calling Win32. The exploitation leg uses `ChangeServiceConfigW` plus `StartServiceW`, or a direct registry write to `ImagePath` when only the key ACL is weak. One structural constraint shapes any port into this codebase: the service APIs are RPC client stubs, not syscall wrappers, so they cannot be dispatched through RecycledGate — an implementation must either PEB-walk advapi32/sechost and call the stubs, or emit the SCM RPC protocol directly. The three grep-matched source files (`byakugan.rs`, `api_hammering.rs`, `kaguya.rs`) were reviewed and do not implement SCM enumeration or service exploitation: byakugan is network reconnaissance, api_hammering walks the Services registry key only as an anti-sandbox time sink, and kaguya inventories LOtL binaries.

## Why It Matters

This is the vault's only card treating services as an elevation surface; T-017 uses service-adjacent mechanisms for persistence, which is a different operational goal — one-shot token elevation versus durable re-entry. The tradecraft surface is discrete: ImagePath enumeration, BINARY_PATH_NAME inspection, service-descriptor SDDL analysis, and prefix-writability probing appear in no injection or evasion card. The technique also degrades gracefully for the operator: enumeration succeeds from a medium-integrity token with read-only rights, and each weakness class (unquoted path, binary ACL, service DACL, registry key ACL) is independently exploitable, so the workflow adapts to whichever misconfiguration the target exposes rather than depending on a single primitive.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-017 Five-Layer Persistence with Resilience Monitor** — persistence complement: T-017 installs durable re-entry (including scheduled-task and registry-based layers), while T-044 is the one-shot elevation step; several T-017 layers that touch HKLM become writable only after a service-LPE-style elevation succeeds.
- **T-020 Anti-Analysis Suite** — T-020's Kaguya module inventories living-off-the-land binaries and profiles security products on target; service LPE enumeration executes in the same on-target reconnaissance pattern and depends on native tooling (sc.exe, Get-Acl, PowerShell) whose availability and monitoring exposure Kaguya-style inventory characterizes.
- **T-023 Client Capabilities Suite** — T-023's sysinfo_collect and recon modules gather host state for operator tasking; SCM service enumeration is the privilege-escalation-oriented extension of that same client-side recon surface.

## References

- Atlas material: atlas-privesc-part2.md (units 9–16, 35–39), atlas-privesc-part3.md (units 1–2, 11, 15–18)
- MITRE ATT&CK: T1543.003 (https://attack.mitre.org/techniques/T1543/003/); secondary: T1574.009, T1574.010, T1574.011, T1007
- LGTM notes: lgtm:proposed-technique-service-lpe-enumeration, lgtm:service-based-lpe-proposed-technique
- Public references: SANS SEC670 *Red Teaming Tools: Developing Custom Tools for Windows* (Jonathan Reiter, named in the atlas material); *CRTO Book*; CVE-2019-1322, cited by the SEC670 material as an example service-configuration LPE; tooling named in the material: sc.exe (`sdshow`/`sdset`/`config`), Get-Acl, Get-Service

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Grep-matched files (`client_rust/src/byakugan.rs`, `dark_crystal/crates/core/src/experimental/api_hammering.rs`, `dark_crystal/crowd/src/kaguya.rs`) were verified as non-implementations of this technique.