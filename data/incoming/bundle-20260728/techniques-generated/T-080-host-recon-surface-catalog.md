---
id: T-080
name: Host Recon Surface Catalog
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1012, T1047, T1007]
tags: [host-recon, registry, wmi, kuser-shared-data, sddl, sc-exe, api-selection, recon-surface, opsec]
origin: atlas-synthesis
member_notes: ['lgtm:host-recon-surface-catalog-gap', 'lgtm:cross-source-recon-api-selection-consensus']
---

# Host Recon Surface Catalog (Registry, WMI, KUSER, SDDL, sc.exe) — Windows Data Source Taxonomy for Implant Reconnaissance

## Summary

Host reconnaissance surfaces on Windows form a catalog of distinct data sources that an implant can query for situational awareness, each with different API entry points, detection profiles, and information granularity. SEC670 material consolidates these surfaces into six categories: registry hives (ProfileList, SAM, SECURITY\Cache, SYSTEM services, SOFTWARE uninstall keys, HKCU user apps), WMI Win32 provider classes (Win32_Process, Win32_Service, Win32_Registry, Win32_OperatingSystem, Win32_NetworkAdapterConfiguration), KUSER_SHARED_DATA direct reads, ProfileList SID enumeration, sc.exe security descriptor extraction via sdshow, and the API selection tradeoffs between functionally equivalent enumeration interfaces. The catalog enables operators to select recon primitives matching their evasion posture rather than defaulting to the most verbose API. The primary detection surface varies by surface: registry access auditing for hive queries, WMI-Activity ETW for WMI provider calls, and process creation logging for sc.exe invocation.

## Mechanism

1. **Registry hive enumeration** targets six key locations:
   - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` — enumerates user SIDs via ProfileImagePath values. Each subkey named with a SID contains a `ProfileImagePath` (REG_SZ) pointing to the user's home directory. This reveals all users who have logged on to the host, including domain users whose profiles were loaded during interactive logon.
   - `HKLM\SAM\SAM\Domains\Account\Users` — contains local account password hashes (NTLM hashes). Access requires SYSTEM privileges because the SAM hive is ACL-restricted to SYSTEM by default at the Configuration Manager level.
   - `HKLM\SECURITY\Cache` — contains cached domain credentials (mscash2 format) from the last approximately 10 domain logons. Requires SYSTEM privileges.
   - `HKLM\SYSTEM\CurrentControlSet\Services` — enumerates installed services and drivers. Each subkey contains ImagePath, Start type (boot/system/auto/demand/disabled), and ServiceDll for svchost-hosted services. Readable by all authenticated users.
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` — lists installed products with DisplayName, DisplayVersion, Publisher, and UninstallString. Readable by all users.
   - `HKCU\Software` — user-installed applications and per-user configuration. Readable by the current user without elevation.

2. **WMI Win32 provider queries** use COM interfaces (IWbemServices::ExecQuery) to query the CIM repository via the WMI service:
   - `Win32_Process` — returns process name, ProcessId, CommandLine, ExecutablePath, and ParentProcessId. More detailed than CreateToolhelp32Snapshot (which lacks CommandLine) but requires WMI service activation and cimwin32.dll provider loading.
   - `Win32_Service` — returns service Name, DisplayName, State, StartMode, and PathName. Equivalent to sc.exe enum but programmatically accessible without process creation.
   - `Win32_Registry` — returns registry quota and consumed space. Low operational value but demonstrates WMI surface coverage.
   - `Win32_OperatingSystem` — returns Caption (OS version string), BuildNumber, InstallDate, LastBootUpTime, and RegisteredUser. Alternative to GetVersionEx and KUSER_SHARED_DATA for OS identification.
   - `Win32_NetworkAdapterConfiguration` — returns IPAddress, MACAddress, DNSServerSearchOrder, DHCPServer, and DefaultIPGateway per adapter. Alternative to GetAdapterAddresses with different telemetry characteristics.

3. **KUSER_SHARED_DATA direct read** dereferences the fixed virtual address 0x7FFE0000 to read system time, tick count, OS version, and processor count without any API call. This is a separate technique (T-081) but is part of the host recon surface catalog as one surface with zero telemetry footprint.

4. **ProfileList SID enumeration** reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` and iterates subkeys to extract SID values. Each SID subkey's ProfileImagePath identifies the user's home directory path, and the Sid subkey (REG_BINARY) contains the raw SID structure. This maps SIDs to usernames for token impersonation planning and identifies domain vs. local accounts via the SID prefix (S-1-5-21 for domain, S-1-5 for local built-ins).

5. **sc.exe sdshow** extracts service security descriptors in SDDL format. The command `sc.exe sdshow <servicename>` returns the service's DACL and SACL in SDDL string format, revealing which accounts can start, stop, or modify the service. This identifies services with weak ACLs that permit modification by non-admin users — a privilege escalation vector documented in T-044.

6. **API selection tradeoffs** documented across SEC670 and CRTO converge on the principle that recon API choice is consequential:
   - **Network adapters**: `GetAdapterAddresses` (returns IP, subnet, gateway, DNS suffix, WINS — most detail, documented API) vs `GetNumberOfInterfaces` (returns count only — minimal detail, minimal telemetry) vs `GetIpStatistics` (returns aggregate packet counters, no per-adapter data). Each invokes a different code path: GetAdapterAddresses calls through iphlpapi.dll into the NSI driver, GetNumberOfInterfaces queries a simple counter, and GetIpStatistics reads MIB structures.
   - **Process enumeration**: `CreateToolhelp32Snapshot` (snapshot-based, walks PEB chains via TH32CS_SNAPPROCESS, generates a snapshot handle observable via handle enumeration) vs `WTSEnumerateProcesses` (queries the Terminal Services subsystem via RPC to TermSrv, returns SessionId and UserSid per process) vs `NtQuerySystemInformation(SystemProcessInformation)` (native syscall, returns linked-list buffer, most evasion-friendly as documented in T-082). Each returns different fields, hits different subsystems, and has different detection profiles.
   - The selection principle: operators should choose the API that returns the minimum required fields with the lowest detection footprint, rather than defaulting to the most verbose interface. Using GetAdapterAddresses when only an IP address is needed generates unnecessary telemetry for marginal information gain over GetNumberOfInterfaces.

## OS Internals Context

The registry hive architecture is central to this catalog. Each hive is a separately allocated memory region managed by the Configuration Manager (CM). The CM exposes hive data through the NtQueryValueKey and NtEnumerateKey syscalls, which perform access checks against the hive's security descriptor. SAM and SECURITY hives have restrictive ACLs that deny access to non-SYSTEM processes. These ACLs are enforced at the CM level when NtQueryValueKey is called with a handle opened on those hive roots — the CM calls SeAccessCheck with the caller's token and the hive key's security descriptor. A process running as SYSTEM (via token theft or service execution) bypasses these checks because the SYSTEM token (S-1-5-18) is the owner of these hives.

WMI's architecture involves the WMI service (wmiprvse.exe) as a host process for WMI providers. When an implant calls IWbemServices::ExecQuery against Win32_Process, the query is dispatched via DCOM/RPC to the Win32 process provider (cimwin32.dll) running inside wmiprvse.exe. The provider obtains process information by calling NtQuerySystemInformation or Process32First/Next internally — the WMI layer adds latency, a separate process context, and DCOM traffic, but does not change the underlying data source. The WMI-Activity ETW provider ({1418ef04-b0b9-4623-bb8a-6c8a2d3a6e9c}) logs provider calls and can be monitored by EDR to detect WMI-based reconnaissance.

ProfileList is stored in the SOFTWARE hive and is readable by all authenticated users. The registry key's subkeys are named with string SIDs (e.g., `S-1-5-21-1234567890-1234567890-1234567890-1001`), and the Sid value (REG_BINARY) contains the raw SID structure. The ProfileImagePath value is used by the user profile loading code in winlogon.exe and userenv.dll during logon to locate and load the user's NTUSER.DAT hive.

The sc.exe sdshow command internally calls QueryServiceObjectSecurity, which returns the service's security descriptor in self-relative format. The SCM (services.exe) stores service security descriptors in the SERVICES hive and enforces them when OpenService is called. SDDL strings encode the DACL in a textual format where ACEs specify trustee SIDs and access rights — for example, `(A;;RPWPCR;;;S-1-5-32-544)` grants Read/Write/Delete/Control permissions to the Administrators group (S-1-5-32-544), while `(A;;RP;;;S-1-5-32-545)` grants only Read to the Users group. An operator analyzing the SDDL string identifies services where non-admin accounts hold Write or Control permissions, indicating privilege escalation opportunities.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `byakugan.rs` module in client_rust performs some reconnaissance functions (ARP, TCP, AD enumeration) and `sysinfo_collect.rs` collects system information, but the comprehensive host recon surface catalog documented in SEC670 — with the specific API selection tradeoffs, per-surface detection profiles, and the taxonomy of six surface categories — is not implemented as a unified module. An implementation would provide a trait-based recon surface abstraction where each surface (registry hive reader, WMI query provider, KUSER_SHARED_DATA reader, sc.exe security descriptor parser) implements a common interface returning structured JSON. The framework would select surfaces based on the current evasion posture: WMI queries when WMI-Activity monitoring is absent, registry reads when registry auditing is disabled, KUSER_SHARED_DATA direct reads when syscall hooks are present, and targeted sc.exe calls when process creation logging is not a concern.

## Why It Matters

The API selection tradeoff is the operational principle that elevates this card above a simple enumeration of data sources. SEC670 and CRTO independently converge on the conclusion that recon API choice is consequential: different APIs return different fields, generate different telemetry, and have different noise profiles. By documenting these tradeoffs as a catalog, operators can make informed decisions about which recon surfaces to query based on the host's monitoring posture, the required information granularity, and the acceptable detection footprint. The catalog also prevents the common mistake of using the most verbose API by default, which generates maximum telemetry for marginal information gain over a more targeted interface.

## Detection Considerations

- **Telemetry sources**: Registry access auditing (Event ID 4663 — object access, if enabled via SACL on the target key) captures value reads. WMI-Activity ETW provider logs Win32 provider query execution including the query string and provider GUID. Sysmon Event ID 7 (image loaded) captures cimwin32.dll loading when WMI is used. Process creation logging (Event ID 4688 or Sysmon Event ID 1) captures sc.exe execution including the command line with the service name queried. KUSER_SHARED_DATA direct reads generate no telemetry.
- **Bypass options**: Registry reads use RegQueryValueEx or NtQueryValueKey, which are less commonly hooked by EDR than WMI's DCOM path. WMI queries can be replaced with direct registry reads for service enumeration — `HKLM\SYSTEM\CurrentControlSet\Services` provides the same data as Win32_Service without DCOM traffic. KUSER_SHARED_DATA direct reads bypass all API-level hooks and ETW providers. sc.exe sdshow can be replaced with QueryServiceObjectSecurity API calls that avoid spawning a process.
- **Residual artifacts**: Registry key handles remain open in the implant's handle table until closed. WMI queries may create wbemess.log entries and CIM repository access records. sc.exe invocation appears in process creation logs with the command line including the service name. Each surface leaves different artifact types, and an operator can select surfaces whose artifacts are least likely to be reviewed.

## Related Techniques

- **T-023 Client Capabilities** — byakugan.rs and sysinfo_collect.rs implement reconnaissance; this card documents the surface catalog and API selection tradeoffs above the implementation
- **T-024 Host Survey and Situational Awareness** — unified reconnaissance; this card decomposes the host survey into individual surfaces with per-surface detection profiles
- **T-027 KUSER_SHARED_DATA Direct-Read System Information** — one surface in this catalog, documented as a standalone technique in the vault
- **T-029 Security Descriptor and SDDL Reconnaissance** — the sc.exe sdshow surface, documented as a standalone technique

## References

- Atlas material: atlas-recon-part3.md, atlas-recon-part6.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:host-recon-surface-catalog-gap, lgtm:cross-source-recon-api-selection-consensus

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.