<!-- BEGIN CARD T-079 -->
---
id: T-079
name: Domain and Active Directory Recon from Standard User
category: discovery
tier: A
crate: none
source_file: none
mitre: T1018
mitre_secondary: [T1087.002, T1069.002]
tags: [domain-recon, active-directory, powerview, adsearch, ldap, integrity-level, standard-user, lateral-movement, tradecraft]
origin: atlas-synthesis
member_notes: ['lgtm:domain-recon-standard-user', 'lgtm:active-directory-recon-coverage-gap']
---

# Domain and Active Directory Recon from Standard User — Standard-User AD Enumeration for Lateral Movement Planning

## Summary

Active Directory enumeration from a standard domain user context enables mapping of domain computers, users, groups, Group Policy Objects, domain controllers, and user session locations without requiring local elevation on the enumeration host. The technique leverages LDAP queries against domain controllers that default Active Directory ACLs permit for all authenticated domain users. CRTO material explicitly warns that running domain recon from a high-integrity process is operationally detrimental because it associates the recon footprint with an elevated token, increasing EDR scrutiny and conflating reconnaissance with post-exploitation activity. PowerView cmdlets (Get-DomainComputer, Get-DomainUser, Get-DomainGPO, Get-DomainController, Find-DomainUserLocation) and ADSearch with custom LDAP filters are the primary tooling vectors documented in the CRTO curriculum. The primary detection surface is LDAP query logging on domain controllers and PowerShell script block logging on the enumeration host.

## Mechanism

1. An implant operating as a standard domain user holds a Kerberos Ticket-Granting Ticket (TGT) obtained during initial authentication. This TGT permits LDAP binds to domain controllers using the user's standard-domain-user token, with no local elevation required on the enumeration host.

2. LDAP queries target the domain controller's Directory Information Tree (DIT) over TCP port 389 (LDAP) or 636 (LDAPS). Active Directory's default security descriptor on the domain partition grants "Authenticated Users" (well-known SID S-1-5-11) read access to most object attributes, including computer accounts, user accounts, group memberships, and GPO link information. No special privileges are required beyond domain membership.

3. PowerView cmdlets wrap System.DirectoryServices.DirectorySearcher or System.DirectoryServices.ActiveDirectory.Domain objects to construct LDAP filters and enumerate AD objects:
   - `Get-DomainComputer` — queries `objectCategory=computer`, returns DNS host names, operating system versions, SPNs, and last logon timestamps. Used for lateral movement target selection.
   - `Get-DomainUser` — queries `objectCategory=person` with optional filters for `samAccountType`, `memberOf`, or `userAccountControl` flags. Identifies privileged accounts, service accounts, and Kerberoastable targets.
   - `Get-DomainGPO` — queries `objectCategory=groupPolicyContainer`, returns GPO display names, GUIDs, and linked OUs. Maps policy enforcement boundaries.
   - `Get-DomainController` — queries `objectCategory=computer` with `(userAccountControl:1.2.840.113556.1.4.803:=8192)` to identify domain controllers. Determines LDAP bind targets and Kerberos KDC endpoints.
   - `Find-DomainUserLocation` — iterates every computer returned by Get-DomainComputer and queries active sessions via NetSessionEnum or remote WMI. This cmdlet is operationally expensive because it generates a network connection to every machine in the domain, producing high-volume share access and RPC traffic.

4. ADSearch provides a lightweight alternative to PowerView using direct LDAP filter syntax. Custom filters such as `(&(objectCategory=computer)(operatingSystem=*Server*))` or `(&(objectCategory=user)(servicePrincipalName=*))` allow targeted enumeration with minimal tooling footprint. ADSearch runs as a single compiled binary with no .NET framework dependency, reducing PowerShell-based telemetry exposure.

5. The integrity-level tradeoff is the core tradecraft decision: performing AD enumeration from the initial standard-user process context (Medium integrity level, IL=2) avoids associating the LDAP query traffic with an elevated or high-integrity token. If recon is performed from a high-integrity process — after UAC bypass or token theft — the EDR sees LDAP queries originating from a process with an anomalous integrity level, which may trigger detection rules that flag elevated processes performing network reconnaissance. The elevated token also carries additional groups or privileges that change the access check results and log details on the domain controller.

6. Enumeration results feed directly into lateral movement planning: computer accounts with recent `lastLogon` timestamps become targets for remote service deployment or WMI execution; user accounts with SPNs become Kerberoasting targets; GPO boundaries inform which machines share security configuration; domain controller locations determine where DCSync or NTDS.dit extraction would be attempted.

## OS Internals Context

Active Directory is implemented as an LDAP directory service backed by the Extensible Storage Engine (ESE) database (NTDS.dit) on domain controllers. The domain controller's lsass.exe process hosts the Active Directory Domain Services (AD DS) service, which services LDAP requests via the LDAP handler in lsass.exe.

Default ACLs on the Active Directory domain partition grant "Authenticated Users" (well-known SID S-1-5-11) read access to most object classes. This is a deliberate design choice: domain users need to query AD for logon script locations, GPO application, and service endpoint discovery during normal operation. The specific extended rights that require elevated permissions — such as replicating directory changes (DS-Replication-Get-Changes) — are controlled by separate ACLs on the domain root object and are not needed for enumeration.

From the Windows security token perspective, a standard domain user process holds a token with Integrity Level 2 (Medium). The token contains the user's SID, group SIDs (including Domain Users S-1-5-21-...-513), and privileges limited to SeChangeNotifyPrivilege and SeShutdownPrivilege (if interactive). When LDAP binds occur, the domain controller performs access checks against this token. The resulting security event log entries (Event ID 4662 — "An operation was performed on an object") contain the caller's subject SID and the object's security descriptor reference. If the caller's token includes elevated groups or higher integrity, the 4662 events carry that information, making the recon traffic distinguishable from normal domain user query patterns.

PowerView's LDAP queries flow through the System.DirectoryServices namespace, which internally uses the wldap32.dll LDAP client. The LDAP bind operation uses either GSS-SPNEGO (Kerberos) or NTLM authentication, depending on SPN resolution and security configuration. Each LDAP search operation generates one or more Event ID 4662 audit entries on the domain controller if Directory Service Access auditing is enabled via SACL on the domain partition.

Find-DomainUserLocation's session enumeration uses NetSessionEnum (netapi32.dll) or remote WMI queries against each target machine. NetSessionEnum hits the LanmanServer service via RPC, generating Event ID 5140 (network share access) and 5145 (detailed file share access) on each queried machine. This produces a high volume of network connections and log entries proportional to the domain size — a single run against a 500-machine domain generates 500 RPC connections and corresponding log entries.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `byakugan.rs` module in the client_rust crate performs network reconnaissance including ARP scanning, TCP port scanning, and AD enumeration, and the `protocol.rs` file defines `MSG_BYAKUGAN_SCAN_RESULT` (0x40) for transmitting scan results, but the specific AD enumeration primitives documented in CRTO (PowerView cmdlet equivalents, ADSearch LDAP filters, the integrity-level tradeoff guidance) are not verified in the provided source. An implementation would consist of: (1) constructing LDAP filters as Rust string literals, (2) binding to a domain controller via the `ldap` crate or direct FFI to wldap32.dll, (3) issuing paged LDAP searches for computer, user, and GPO objects with the filters documented above, and (4) returning JSON-serialized results via the MSG_BYAKUGAN_SCAN_RESULT protocol message. The integrity-level guidance would manifest as a design constraint: the recon module must execute in the initial process context before any elevation is performed, with the operational framework ensuring that elevation occurs only after reconnaissance completes.

## Why It Matters

The integrity-level tradeoff is the central operational insight this card captures. Standard domain user AD enumeration is the bridge between initial access and lateral movement — it maps the attack surface without requiring exploitation or elevation. CRTO material explicitly flags that performing this enumeration from an elevated context is a tradecraft error because it associates reconnaissance traffic with an elevated token, creating a detectable anomaly. Documenting this as a distinct technique ensures operators understand that the timing and integrity context of AD recon is as important as the enumeration itself.

## Detection Considerations

- **Telemetry sources**: Domain controller Event ID 4662 (directory service access) captures LDAP queries when Directory Service Access auditing is enabled via SACL on the domain partition. Event ID 5140/5145 on target machines captures Find-DomainUserLocation's session enumeration via NetSessionEnum. PowerShell Script Block Logging (Event ID 4104) captures PowerView cmdlet execution and the full LDAP filter strings. Microsoft-Windows-PowerShell/Operational ETW provider logs cmdlet invocations.
- **Bypass options**: ADSearch avoids PowerShell telemetry entirely by using direct LDAP via wldap32.dll FFI or a native LDAP library, producing no PowerShell script block events. Running enumeration from the initial standard-user process avoids integrity-level anomalies that trigger elevated-process network activity rules. Targeted LDAP filters — querying specific OUs or object types — reduce the volume of 4662 events compared to broad wildcard queries.
- **Residual artifacts**: LDAP bind records in DC security logs contain the source IP and caller SID. PowerShell command history (if PowerView is used) stores cmdlet invocations. Network connections from the enumeration host to the DC on TCP 389/636 appear in firewall logs. Find-DomainUserLocation leaves connections to every queried machine in network logs and NetSessionEnum access records.

## Related Techniques

- **T-023 Client Capabilities** — byakugan.rs implements network reconnaissance including AD enumeration; this card documents the tradecraft layer and integrity-level guidance above the implementation
- **T-024 Host Survey and Situational Awareness** — host-level reconnaissance complements domain-level enumeration; together they form the full situational awareness picture from single host to domain scope

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part6.md
- MITRE ATT&CK: T1018 — https://attack.mitre.org/techniques/T1018/
- LGTM notes: lgtm:domain-recon-standard-user, lgtm:active-directory-recon-coverage-gap

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling (PowerView, ADSearch).
<!-- END CARD T-079 -->

<!-- BEGIN CARD T-080 -->
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
<!-- END CARD T-080 -->

<!-- BEGIN CARD T-081 -->
---
id: T-081
name: KUSER_SHARED_DATA Direct Read Recon
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: []
tags: [kuser-shared-data, direct-read, telemetry-evasion, sysinfo, os-fingerprinting, shared-user-data, no-syscall, fixed-address]
origin: atlas-synthesis
member_notes: ['lgtm:kuser-shared-data-recon', 'lgtm:coverage-kuser-shared-data-access']
---

# KUSER_SHARED_DATA Direct Read Recon — Telemetry-Free System Information via Fixed User-Mode Page

## Summary

KUSER_SHARED_DATA is a read-only page mapped at the fixed virtual address 0x7FFE0000 in every user-mode process, containing system time, tick count, OS version, time zone bias, product type, and suite mask fields that the kernel maintains and updates directly. Direct memory reads from this page obtain system information without invoking NtQuerySystemInformation, GetSystemTime, GetVersionEx, or any other documented sysinfo API, generating no syscall, no ETW event, and no userland hook contact. SEC670 presents this as the undocumented alternative path for OS fingerprinting and timestamp retrieval, framing it as critical for evasive reconnaissance. The technique exploits the Windows kernel's design decision to share a read-only data page with user mode for performance — originally intended to allow ntdll.dll's time functions to read system time without the syscall overhead of NtQuerySystemTime. The detection surface is minimal: direct memory reads from a fixed address produce no side effects observable by any standard telemetry channel.

## Mechanism

1. The KUSER_SHARED_DATA structure (also known as SharedUserData or USER_SHARED_DATA) is a single page (4096 bytes) that the memory manager maps into every user-mode process at the fixed virtual address 0x7FFE0000 during process creation. The mapping is established by the memory manager during `MmInitializeProcessAddressSpace` and exposed to user mode via a VAD (Virtual Address Descriptor) entry with PAGE_READONLY protection. The physical page backing this virtual address is a single canonical copy shared across all processes — the kernel maintains the master copy and maps it read-only into each process address space.

2. To read a field, an implant computes the field's address as `0x7FFE0000 + offset` and performs a direct pointer dereference. For example, reading SystemTime at offset 0x14 involves treating address `0x7FFE0014` as a pointer to a `KSYSTEM_TIME` structure and reading the 8-byte LARGE_INTEGER value. No API call, no `syscall` instruction, and no library function invocation occurs. The CPU executes a single MOV instruction.

3. High-value fields and their documented offsets on x64 Windows 10/11:
   - **SystemTime** (offset 0x14, KSYSTEM_TIME containing LARGE_INTEGER) — current system time in FILETIME format (100-nanosecond intervals since January 1, 1601). Updated by the kernel on each clock interrupt. Alternative to GetSystemTimeAsFileTime or NtQuerySystemTime.
   - **TickCount** (offset 0x320, KSYSTEM_TIME) — tick count since boot, derived from the kernel's tick counter. Alternative to GetTickCount or GetTickCount64.
   - **TimeZoneBias** (offset 0x20, KSYSTEM_TIME) — UTC offset in 100-nanosecond intervals. Combined with SystemTime to compute local time without calling GetTimeZoneInformation.
   - **NtMajorVersion** (offset 0x260, ULONG) — major version number (10 for Windows 10/11). Alternative to GetVersionEx or RtlGetVersion.
   - **NtMinorVersion** (offset 0x264, ULONG) — minor version number (0 for Windows 10/11).
   - **ProductType** (ULONG) — VER_NT_WORKSTATION (1), VER_NT_DOMAIN_CONTROLLER (2), or VER_NT_SERVER (3). Alternative to GetVersionEx's wProductType field. Offset varies by Windows version.
   - **SuiteMask** (USHORT) — bitfield indicating installed product suites (VER_SUITE_ENTERPRISE, VER_SUITE_DATACENTER, VER_SUITE_PERSONAL). Offset varies by Windows version.
   - **NumberOfPhysicalPages** (offset 0x60, ULONG) — total physical memory in pages. Alternative to GlobalMemoryStatusEx.
   - **Cookie** (offset 0x330 on x64 Windows 10 builds) — stack cookie value used by /GS compiled code. Reading this field provides the security cookie value, relevant for stack-based exploit development.

4. The read operation is a simple memory access that the CPU executes as a single MOV instruction. The TLB entry for 0x7FFE0000 is populated at process creation and remains valid for the process lifetime, so the access does not fault. The page's PAGE_READONLY protection allows reads but prevents writes from user mode — attempted writes cause STATUS_ACCESS_VIOLATION (0xC0000005), which is the same exception used by the VEH syscall gate (T-003) for other purposes.

5. SEC670 frames the direct-read approach as a BONUS undocumented method that avoids the documented sysinfo syscall path entirely. The technique is useful when EDR products hook NtQuerySystemInformation in ntdll.dll, when the implant's syscall stub has been modified to avoid specific SSNs, or when the operator wants to minimize the syscall surface area to reduce kernel callback exposure.

## OS Internals Context

KUSER_SHARED_DATA has its roots in the Windows NT design philosophy of sharing certain kernel-maintained data with user mode to avoid syscall overhead for frequently accessed values. The structure is defined in ntddk.h as `KUSER_SHARED_DATA` (kernel-side) and is exposed to user mode at the fixed address `MM_SHARED_USER_DATA_VA` (0x7FFE0000 on both x86 and x64). The kernel maintains a separate writable copy at a kernel address and maps the user-mode copy as read-only via a prototype PTE.

The kernel updates KUSER_SHARED_DATA fields at specific intervals:
- **SystemTime** is updated on every clock interrupt (approximately every 15.6ms on standard x64 systems with the periodic timer, or more frequently with dynamic tick / HPET). The update writes the 64-bit value atomically using an interlocked operation, ensuring that user-mode reads of the 8-byte value do not observe a torn update.
- **TickCount** is updated on each clock interrupt by incrementing the tick count fields and adjusting the corresponding KSYSTEM_TIME structure.

The page mapping is established during process creation in `MmInitializeProcessAddressSpace`. The PTE for 0x7FFE0000 is set up as a prototype PTE pointing to the physical page containing the shared data. This means the physical page is shared across all processes with copy-on-write disabled — there is one canonical copy of the data that every process reads. The VAD entry for this region is marked as committed, read-only, and cannot be unmapped or remapped by user-mode code.

The structure layout has evolved across Windows versions. On Windows XP, the structure was 4096 bytes with fewer fields. Windows 7 added fields for extended tick count support and improved timekeeping. Windows 10 added fields related to system call interception and CET (Control-flow Enforcement Technology) shadow stack support. An implant reading specific offsets must account for layout differences across versions, though the offsets for SystemTime (0x14), TimeZoneBias (0x20), NtMajorVersion (0x260), and NtMinorVersion (0x264) have remained stable since Windows NT 4.0 because they are referenced by compiled user-mode binaries that depend on specific offsets.

The PEB structure (used by T-004 PEB Walker) is related but distinct: the PEB contains per-process data (image base, loader data, process parameters) at a process-specific address obtained from the TEB (gs:[0x60] on x64). KUSER_SHARED_DATA is at a fixed address in every process and contains system-wide data. Some PEB fields — OsMajorVersion, OsMinorVersion, OsBuildNumber, NumberOfProcessors — are populated from KUSER_SHARED_DATA during process creation by the kernel's `MmCreatePeb` function. Reading the PEB provides the same version information but through a different access path with different detection characteristics: PEB access requires walking the TEB segment register, while KUSER_SHARED_DATA access is a direct dereference of a known constant address.

The `def.rs` source file in the HUGIN codebase (`dark_crystal/crates/core/src/experimental/evasion/veh/def.rs`) defines a `PEB` structure with `os_major_version`, `os_minor_version`, `os_build_number`, and `number_of_processors` fields. These PEB fields mirror KUSER_SHARED_DATA values but are accessed via the PEB pointer obtained from the TEB, not via direct read from 0x7FFE0000. The file defines PE structures (ImageDosHeader, ImageNtHeaders, ImageExportDirectory) and PEB/LDR structures for the VEH syscall gate module. It does not define a KUSER_SHARED_DATA structure or implement direct reads from the shared page.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `def.rs` file in the VEH module defines PEB and related structures but does not define KUSER_SHARED_DATA or implement direct reads from 0x7FFE0000. The PEB fields for OS version (os_major_version, os_minor_version, os_build_number) provide similar information through a different access path. An implementation would define a `#[repr(C)]` struct matching the KUSER_SHARED_DATA layout with fields at their documented offsets, create a raw pointer to 0x7FFE0000, and perform volatile reads of the required fields. In Rust, this would use `core::ptr::read_volatile` on a pointer constructed as `0x7FFE0000 as *const KUSER_SHARED_DATA`, wrapped in an `unsafe` block. The `read_volatile` is necessary to prevent the compiler from optimizing away the memory access or reordering it relative to other operations. The implementation would provide accessor functions for SystemTime, OS version, tick count, and processor count, returning values without any function call into ntdll.dll or kernel32.dll.

## Why It Matters

KUSER_SHARED_DATA direct reads represent a class of reconnaissance primitive that is structurally invisible to conventional detection mechanisms. The page exists in every process, is mapped by the kernel during process creation, and reading it is a normal memory access that produces no side effects. No documented Windows telemetry channel — ETW providers, kernel callbacks (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutine), userland hooks on ntdll.dll, or Sysmon — captures direct memory reads from this address. The technique fills a gap in the vault's recon coverage by documenting a primitive that bypasses the entire API-layer detection stack, including both documented syscalls and their Win32 wrappers. For implants that need OS version information for conditional technique selection or system time for beacon interval timing, KUSER_SHARED_DATA provides these values with zero syscall surface.

## Detection Considerations

- **Telemetry sources**: No standard telemetry channel captures direct memory reads from 0x7FFE0000. ETW providers do not instrument memory reads at the page level. Sysmon does not monitor memory access patterns. Kernel callbacks do not fire on memory reads. The page is PAGE_READONLY and mapped by the kernel, so access violations do not occur on valid reads within the page.
- **Bypass options**: The technique is inherently a bypass — it avoids all API-layer telemetry by design. An EDR could theoretically implement a page-guard trap on the 0x7FFE0000 page to detect access via STATUS_GUARD_PAGE exceptions, but this would break legitimate code: ntdll.dll's own time functions (NtQuerySystemTime, GetSystemTimeAsFileTime) read this page directly, and the kernel's clock interrupt handler does not coordinate with page-guard traps. Memory scanning could detect code patterns that compute the constant 0x7FFE0000, but this produces false positives on any binary that legitimately reads system time through the shared page.
- **Residual artifacts**: No files, registry keys, handles, or network connections are produced. The only artifact is the MOV instruction in the implant's code section referencing the address 0x7FFE0000, which is indistinguishable from any other memory read without instruction-level tracing or code analysis.

## Related Techniques

- **T-004 PEB Walker** — uses the same family of fixed user-mode structures (TEB/PEB) accessed via segment registers; KUSER_SHARED_DATA extends the pattern to system-wide data at a fixed virtual address known at compile time
- **T-027 KUSER_SHARED_DATA Direct-Read System Information** — existing vault card covering the same primitive; this card adds the offset table, OS internals context, and SEC670's deeper tradecraft framing
- **T-023 Client Capabilities** — reconnaissance module; KUSER_SHARED_DATA reads are a primitive within the broader recon surface catalog
- **T-016 EDR Evasion Suite** — KUSER_SHARED_DATA bypasses userland hooks on sysinfo APIs, complementing the hook-bypass techniques in the evasion suite

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part4.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:kuser-shared-data-recon, lgtm:coverage-kuser-shared-data-access

## Source Reference

No current implementation. The `def.rs` file in the VEH module (`dark_crystal/crates/core/src/experimental/evasion/veh/def.rs`) defines PEB structures with version fields but does not define or read KUSER_SHARED_DATA. See atlas material and Windows Internals 7ed for the structure layout.
<!-- END CARD T-081 -->

<!-- BEGIN CARD T-082 -->
---
id: T-082
name: NtQuerySystemInformation Process Enumeration
category: discovery
tier: A
crate: none
source_file: none
mitre: T1057
mitre_secondary: []
tags: [ntquerysysteminformation, process-enumeration, native-api, evasion, system-process-information, linked-list, two-pass-allocation, syscall-level]
origin: atlas-synthesis
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---

# NtQuerySystemInformation Process Enumeration — Native System Process List via Undocumented Information Class

## Summary

NtQuerySystemInformation with SystemProcessInformation (information class 5) enumerates all processes and threads on the system through a single native syscall, returning a linked-list buffer of SYSTEM_PROCESS_INFORMATION structures that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next enumeration path EDR products commonly monitor. The technique replaces three Win32 API calls — snapshot creation plus first and next iteration — with a single NtQuerySystemInformation invocation followed by linked-list traversal within the returned buffer. The two-pass allocation pattern, calling with a NULL buffer to obtain required size then allocating and retrying, is the standard idiom for variable-length system information queries. The buffer contains process name, PID, thread count, handle count, parent PID, and creation timestamp for every process in the system. The primary detection surface is NtQuerySystemInformation itself if hooked by EDR, but the technique avoids the layered Win32 toolhelp API and its associated telemetry.

## Mechanism

1. The implant calls NtQuerySystemInformation with the `SystemProcessInformation` information class (value 5), a NULL output buffer pointer, and a buffer length of zero. The call returns STATUS_INFO_LENGTH_MISMATCH (0xC0000004) and sets the `ReturnLength` output parameter to the total byte count required to hold the full process list at the moment of the call.

2. The implant allocates a buffer of `ReturnLength` bytes using NtAllocateVirtualMemory or HeapAlloc. The buffer must be contiguous because the returned data is a linked list where each entry's `NextEntryOffset` field is a relative byte offset from the current entry to the next entry within the same buffer. Implants typically allocate `ReturnLength + 4096` to account for the race condition where new processes appear between the size-query call and the data-fill call.

3. The implant retries NtQuerySystemInformation with `SystemProcessInformation`, the allocated buffer, and the buffer length. On success, the call returns STATUS_SUCCESS (0x00000000) and the buffer is populated with a sequence of SYSTEM_PROCESS_INFORMATION structures.

4. The implant walks the linked list starting at the buffer base address:
   - Read `NextEntryOffset` (ULONG at offset 0x00) of the current entry.
   - If `NextEntryOffset` is 0, the current entry is the last entry — stop traversal.
   - Otherwise, advance the read pointer by `NextEntryOffset` bytes (not by `sizeof(SYSTEM_PROCESS_INFORMATION)`) to reach the next entry. This variable-length encoding accommodates entries with longer image names, because the UNICODE_STRING buffer for ImageName is appended to each fixed-size structure and the total entry size varies.

5. Per entry, the implant extracts the following fields on x64:
   - **UniqueProcessId** (HANDLE at offset 0x80) — the process ID.
   - **ImageName** (UNICODE_STRING at offset 0x88) — the process image name (e.g., `lsass.exe`). The UNICODE_STRING's Buffer pointer references memory within the same system information buffer, so the string data is valid for the lifetime of the buffer.
   - **NumberOfThreads** (ULONG at offset 0x278) — count of threads in this process.
   - **HandleCount** (ULONG at offset 0x288) — number of open handles in the process handle table.
   - **CreateTime** (LARGE_INTEGER at offset 0x98) — process creation timestamp in FILETIME format.
   - **InheritedFromUniqueProcessId** (HANDLE at offset 0x140) — parent process PID.

6. The enumeration results feed injection target selection: processes with known DLL loading patterns (notepad.exe, svchost.exe, explorer.exe) become injection candidates; processes with specific integrity levels or session IDs inform cross-session injection planning (T-047); the parent PID map reveals process ancestry for PPID spoofing (T-015).

7. For per-process detail beyond what SystemProcessInformation provides, the implant pairs this enumeration with NtQueryInformationProcess(ProcessBasicInformation, information class 0) on individual process handles obtained via OpenProcess. ProcessBasicInformation returns a PROCESS_BASIC_INFORMATION structure containing the PEB address (PebBaseAddress field), which enables direct PEB reading for module list enumeration, command line extraction via ProcessParameters, and process path retrieval — all through native NT APIs without invoking any Win32 process enumeration function.

## OS Internals Context

NtQuerySystemInformation is exported by ntdll.dll and performs a syscall into the kernel via the syscall number assigned to NtQuerySystemInformation on the current Windows build. The kernel-side implementation resides in ntoskrnl.exe, function `ExpQuerySystemInformation`, which dispatches to the appropriate information class handler based on the `SystemInformationClass` parameter. For SystemProcessInformation (class 5), the handler iterates the active process list — linked via the `ActiveProcessLinks` LIST_ENTRY field in each EPROCESS structure — and serializes each process's information into the output buffer.

The SYSTEM_PROCESS_INFORMATION structure is variable-length because the ImageName field is a UNICODE_STRING containing a pointer to a variable-length buffer. The kernel writes the name buffer immediately after the fixed portion of each structure entry, and the `NextEntryOffset` field accounts for this variable size. This design means the implant cannot use `sizeof(SYSTEM_PROCESS_INFORMATION)` to advance between entries — it must use the `NextEntryOffset` relative offset, because consecutive entries are not necessarily `sizeof(SYSTEM_PROCESS_INFORMATION)` apart.

The contrast with CreateToolhelp32Snapshot is architectural: CreateToolhelp32Snapshot creates a snapshot handle via an internal NtCreateSnapshot call, then Process32First and Process32Next iterate using that handle. The snapshot mechanism copies process information at snapshot creation time into a kernel-allocated buffer, while NtQuerySystemInformation(SystemProcessInformation) queries the live process list at call time. The Win32 toolhelp path involves multiple syscalls (create snapshot, then first, then next per iteration — one syscall per process in the list), while the NtQuerySystemInformation path involves one or two syscalls total (query for size, then query for data). The reduced syscall count reduces the hook surface area and the number of EDR interception points. Additionally, the snapshot handle itself is observable: EDR can enumerate process handles and detect a snapshot handle with the specific type and access mask that toolhelp creates.

WTSEnumerateProcesses provides a third enumeration path that queries the Terminal Server service (TermSrv) via RPC. It returns process information including session IDs and user SIDs — fields not present in SYSTEM_PROCESS_INFORMATION — but requires the WTS service to be running and generates RPC traffic to the TermSrv endpoint, which is observable via RPC ETW providers.

The two-pass allocation pattern is necessary because the process list is dynamic: between the first call (which returns the required size) and the second call (which fills the buffer), new processes may appear or existing processes may exit. The kernel handles this by truncating the output at the buffer boundary and returning STATUS_INFO_LENGTHMismatch if the buffer is still too small for the current process list. Implants account for this race condition by over-allocating or by retrying in a loop until STATUS_SUCCESS is returned.

The SYSTEM_PROCESS_INFORMATION structure also contains per-thread information: the `Threads` array (starting at offset 0x2D0 on x64) contains SYSTEM_THREAD_INFORMATION entries, each with StartAddress, ClientId (thread TID + PID), Priority, and State. This provides thread-level enumeration in the same buffer without separate calls to NtQueryInformationThread — useful for thread hijack target selection (T-073) because the StartAddress field identifies threads whose start address points into a loaded module's code section, indicating a stable thread for context hijack.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `def.rs` file in the VEH module defines PEB, LDR_DATA_TABLE_ENTRY, ImageDosHeader, ImageNtHeaders, and related structures but does not define SYSTEM_PROCESS_INFORMATION or invoke NtQuerySystemInformation for process enumeration. The `protocol.rs` file defines `MSG_PROCESS_LIST` (0x0A) as a message type for sending process list data from client to server, indicating the client protocol supports process list reporting, but the enumeration logic that would populate this message is not present in the provided source files. An implementation would: (1) resolve NtQuerySystemInformation's SSN via the HUGIN syscall resolution cascade (T-002 Hell's Gate / Tartarus Gate or T-001 RecycledGate for indirect dispatch), (2) define a `#[repr(C)]` struct matching the SYSTEM_PROCESS_INFORMATION layout with fields at the offsets documented above, (3) implement the two-pass allocation pattern using the resolved syscall, (4) walk the linked list via `NextEntryOffset` using raw pointer arithmetic, and (5) serialize the extracted process entries as JSON into a MSG_PROCESS_LIST message for transmission to the C2 server via the `build_message` function in `protocol.rs`.

## Why It Matters

Process enumeration is the prerequisite step for nearly every process injection technique in the vault (T-007 through T-013). The choice of enumeration API determines which detection channels observe the enumeration: CreateToolhelp32Snapshot generates a snapshot handle that EDRs can detect via handle enumeration; WTSEnumerateProcesses generates RPC traffic to the Terminal Server; NtQuerySystemInformation generates a single native syscall that may be hooked but does not produce the layered telemetry of the Win32 path. SEC670 explicitly frames NtQuerySystemInformation as the evasion-friendlier alternative to the documented Win32 enumeration APIs, placing it alongside NtQueryInformationProcess and other native NT enumeration functions as tools for reducing the implant's API footprint. Documenting this as a distinct technique ensures operators can select the enumeration path that matches their evasion posture rather than defaulting to CreateToolhelp32Snapshot, which is the most commonly detected enumeration interface.

## Detection Considerations

- **Telemetry sources**: If EDR hooks NtQuerySystemInformation in ntdll.dll (common practice for process-monitoring EDRs), the call is intercepted and the parameters are inspected. The Microsoft-Windows-Kernel-Process ETW provider ({22fb2cd6-0e7b-422b-a12c-984e92ed35d6}) can capture process enumeration events if enabled. Sysmon does not specifically capture NtQuerySystemInformation calls. The Microsoft-Windows-Kernel-General ETW provider may log system information queries at high verbosity levels.
- **Bypass options**: Using indirect syscalls (T-001 RecycledGate) to invoke NtQuerySystemInformation bypasses ntdll.dll hooks by executing the syscall instruction from a MEM_IMAGE-backed gadget rather than from the ntdll.dll stub. Using the VEH syscall gate (T-003) dispatches the call through a hardware breakpoint-mediated exception handler, avoiding the ntdll.dll stub entirely. Reading the process list via EPROCESS walking through a loaded kernel driver (BYOVD, T-018) avoids the syscall entirely by reading kernel memory directly.
- **Residual artifacts**: No files or registry entries are created. The allocated buffer for the system information data is a user-mode memory allocation with no kernel handle table entry. The only observable artifact is the syscall instruction execution, captured only if the EDR instruments the syscall instruction itself via kernel callbacks or if it hooks the ntdll.dll stub. The two-pass pattern — a failed call followed by a successful call with a large buffer — is a recognizable behavioral pattern if the EDR correlates sequential NtQuerySystemInformation calls.

## Related Techniques

- **T-007 Pool Party and Process Injection** — process enumeration is the prerequisite for injection target selection; this card documents the enumeration primitive that feeds the injection family
- **T-020 Anti-Analysis Suite** — anti-analysis checks may require process list access for detecting analysis tooling; NtQuerySystemInformation provides the evasion-friendlier enumeration path
- **T-023 Client Capabilities** — the client's recon module performs process enumeration; this card documents the native API path as an alternative to Win32 toolhelp
- **T-064 Undocumented NT Enumeration as Syscall-Level Evasion Primitive** — documents the broader pattern of using undocumented NT enumeration classes; this card is the process-list-specific instance of that general principle

## References

- Atlas material: atlas-binary-analysis-part2.md, atlas-edr-evasion-part1.md
- MITRE ATT&CK: T1057 — https://attack.mitre.org/techniques/T1057/
- LGTM notes: lgtm:native-process-enumeration-coverage, lgtm:undocumented-native-api-process-enum

## Source Reference

No current implementation. The `protocol.rs` file defines `MSG_PROCESS_LIST` (0x0A) indicating the protocol supports process list messages, but the enumeration logic using NtQuerySystemInformation is not present in the provided source files. See atlas material and Windows Internals 7ed for the SYSTEM_PROCESS_INFORMATION structure layout.
<!-- END CARD T-082 -->