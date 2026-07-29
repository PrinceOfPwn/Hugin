Let me analyze the task:

1. I need to produce a T-024 technique card for "Host Survey and Situational Awareness: Unified Reconnaissance"
2. Category: discovery
3. Tier: A
4. Member notes: 5 LGTM notes listed
5. Related techniques: T-023, T-020, T-016, T-022, T-007

Source files included:
- `src/client_rust/src/byakugan.rs` — Byakugan network reconnaissance engine. Does this implement host survey? Let me check. It does ARP scan, TCP port scan, banner grab, AD enumeration, passive discovery. This is NETWORK reconnaissance, not host survey per se. The T-024 card is about host survey: OS version, patch status, process enum, installed software, services, NIC config, registry, user accounts. Byakugan does AD enumeration (net user /domain, net group /domain, nltest) and ARP/network interface parsing. There's overlap: byakugan does network adapter info (ipconfig parsing) and user enumeration (net user /domain). But the card's core mechanism — the unified host survey as described in SEC670 Book 2 — is not what byakugan implements. Byakugan is network reconnaissance (already covered in T-023 under "Network Reconnaissance — Byakugan"). 

Actually, let me think carefully. The verification test: "for the file to count as an implementation of this technique, at least ONE function in it must implement the primary mechanism the card describes." The primary mechanism of T-024 is unified host survey: OS version, hotfixes, process enumeration, installed software, services/tasks, network adapters, registry, user enumeration. Byakugan does:
- ARP scan (network recon, not host survey)
- Port scan (network recon)
- Banner grab (network recon)
- AD enum: net user /domain, net group /domain, nltest /dsgetdc — this is domain user enumeration, partially overlapping with "user account enumeration" domain of the survey
- Passive discovery (network recon)
- parse_local_interfaces: parses ipconfig /all for NIC info — overlaps with "network adapters and IP configuration" domain

Hmm. Byakugan implements a subset of survey domains (NIC info, user/domain enumeration) but via shelling out to system commands (arp -a, ipconfig, net user, nltest, nbtstat) rather than the Win32/NT API surface the SEC670 material describes (WTSEnumerateProcessesEx, NtQuerySystemInformation, GetAdaptersAddresses, etc.). The card describes a unified host survey capability — a coordinated first-phase action aggregating OS, patch, process, software, service, network, registry, user data. Byakugan is a network reconnaissance engine — it's already documented in T-023 and T-022 contexts.

The manifest maps byakugan.rs to T-023 and T-021. So attributing byakugan.rs as the implementation of T-024 would be wrong. The honest call: partial overlap exists (Byakugan covers the network-adapter and domain-user slices via command execution rather than API calls), but there is no unified host survey implementation in the source. I should state that in Key Implementation Details: no current unified implementation; Byakugan covers adjacent network-recon ground but via spawned system commands, not the API-surface survey the material describes.

- `src/client_rust/src/main.rs` — entry point, calls sysinfo_collect for HELLO message. sysinfo_collect gathers hostname, OS, CPU, RAM, disk, network adapters. That's a sysinfo collection for the HELLO message — a subset of host survey. But main.rs itself is not a survey implementation. sysinfo_collect.rs is not included in the inputs. The manifest maps sysinfo_collect.rs to T-023. So again — no dedicated unified survey.

- `src/client_rust/src/protocol.rs` — message constants only. Not an implementation.

So the correct call: `source_file: none`, `crate: none`. And in Key Implementation Details, note that no unified survey implementation exists; the closest existing capabilities are sysinfo_collect (HELLO payload) and byakugan (network recon via command spawning), both documented under T-023, but neither implements the API-surface survey the SEC670 material describes.

Wait — the frontmatter `crate` enum is dark_crystal|client_rust|none. Since no implementation, `crate: none` and `source_file: none`.

MITRE: The best fit for host survey / discovery aggregation. Candidates:
- T1033 System Owner/User Discovery
- T1057 Process Discovery
- T1082 System Information Discovery
- T1018 Remote System Discovery
- T1087 Account Discovery
- T1518 Software Discovery
- T1016 System Network Configuration Discovery
- T1012 Query Registry
- T1007 System Service Discovery

The technique spans many, but the single best-fit parent for a unified host survey... T1082 System Information Discovery is probably the most central (the survey's core is system info gathering). Then mitre_secondary could list T1057, T1518, T1087, T1016, T1007, T1012. The template says mitre_secondary can be a list. I'll use T1082 as primary with secondary list. That's defensible: the survey aggregates, but its primary is system information discovery.

Actually, the consolidated description says "Unified host survey encompassing OS version/build, service pack/patch status, process enumeration..., installed software discovery, services and scheduled tasks, network adapters and IP configuration, registry hive structure, user account enumeration..." MITRE has a technique "T1082 System Information Discovery" — and there's also the Discovery tactic TA0007. The best single technique is T1082. I'll go with that and list secondaries: T1057 (Process Discovery), T1518.001 (Software Discovery: Security Software Discovery — relevant given AV/EDR detection emphasis), T1087 (Account Discovery), T1016 (System Network Configuration Discovery), T1007 (System Service Discovery), T1012 (Query Registry).

Now the material. Key facts from the atlas:

1. SEC670 Book 2 "Getting to Know Your Target" dedicates Section 2 to host survey: OS info, hotfixes/SPs, process enum, installed software, user info, services/tasks, network info, registry info. Labs 2.1-2.5: OS Info, ProcEnum, CreateToolhelp, WTSEnum, FileFinder.

2. OS info:
   - Why: payload compatibility (x86 vs x86_64), service pack affects exploit compatibility (Metasploit target specification), kernel version (ntoskrnl.exe at C:\Windows\System32), API availability varies across versions.
   - Windows version mapping table: XP 5.1, Server 2003 5.2, Vista/2008 6.0, 7/2008R2 6.1, 8/2012 6.2, 8.1/2012R2 6.3, 10/2016 10.
   - GetNativeSystemInfo: VOID return, LPSYSTEM_INFO out param. SYSTEM_INFO fields: dwPageSize (VirtualAlloc relies on it), lpMinimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask (bits 0-31 per processor), dwNumberOfProcessors (GetLogicalProcessorInformation relies), dwAllocationGranularity, wProcessorLevel, wProcessorRevision. wProcessorArchitecture distinguishes WoW64 vs native x64.
   - Undocumented method: KUSER_SHARED_DATA.
   - Bootcamp: GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo, bonus KUSER_SHARED_DATA.

3. Hotfixes/Service Packs:
   - Hotfix = QFE (Quick Fix Engineering); hot patching while running, some need reboot.
   - Service packs bundle hotfixes; affect exploit compatibility.
   - Query methods: Get-HotFix (PowerShell, queries WMI Win32_QuickFixEngineering class), wmic qfe list (same class — may not give full view of all updates), C/C++ WMI query or Windows Update Agent (WUA) APIs.
   - WUA APIs: introduced with Windows XP; COM interfaces in Wuaapi.h, Wuguid.lib. UpdateSession → CreateUpdateSearcher → IUpdateSearcher::Search(criteria, &results) → ISearchResult::get_Updates → IUpdateCollection::get_Count. Used for determining available/installed updates, WSUS integration.

4. Process enumeration (three documented + one undocumented):
   - EnumProcesses: easiest, doesn't return detailed info.
   - CreateToolhelp32Snapshot: "perhaps one of the more common APIs used in malware"; returns more detail than EnumProcesses. Downside: snapshot lag — can miss newly created processes after snapshot taken.
   - WTSEnumerateProcesses / WTSEnumerateProcessesEx (wtsapi32.h): can query remote systems and multiple sessions on local computer; returns relevant process info. WTSEnumerateProcessesExA signature: (HANDLE hServer, WORD *pLevel, DWORD SessionId, LPSTR *ppProcessInfo, DWORD *pCount), BOOL return. WTS_PROCESS_INFO_EXA struct fields: NumberOfThreads, HandleCount, PagefileUsage, PeakPagefileUsage, WorkingSetSize, PeakWorkingSetSize, UserTime, KernelTime. Remote queries need specific registry keys. Memory freed with WTSFreeMemory (material says "memory must be freed using WTSEnumerateProcessesEx" — likely a garbled reference to WTSFreeMemory; I should be careful. The material says "It also notes that memory must be freed using WTSEnumerateProcessesEx." That's clearly garbled. I'll just note buffer management requirement without inventing the exact free function... Actually WTSFreeMemory is well-established Windows API documented on MSDN. I can mention it as the documented free function per MSDN — rule 4 allows well-established Windows internals documentation (MSDN). Fine.)
   - Undocumented: NtQuerySystemInformation with SYSTEM_INFORMATION_CLASS (SystemProcessInformation) — "more stealthy", "native APIs are risky but might be worth the risk due to what they return".
   - Kernel structures for representing processes in system address space (EPROCESS — material says "structures the kernel uses to represent processes in system address space" without naming EPROCESS; I can name EPROCESS/KPROCESS from Windows Internals knowledge as context).

5. Installed software:
   - Locations: C:\Program Files (64-bit), C:\Program Files (x86) (32-bit), C:\ root (e.g., Python), user-specific folders.
   - Purpose inference: development software → dev machine; Notepad++, Process Hacker, VMware → research VM indicators → operational decision whether to continue/abort.
   - Directory walks: FindFirstFile + FindNextFile (two main APIs; three total involved), recursive walk from system root can take a while but yields info. Lab 2.5 FileFinder.
   - NTFS directory entries: each directory has a table of file name entries; CreateDirectory/CreateDirectoryEx/CreateDirectoryTransacted.

6. User information:
   - net user, net localgroup from cmd; finding Administrators group members; Domain Admin logged in = high value.
   - lmaccess.h / lmuse.h: NetGroupGetUsers, NetUseEnum, NetLocalGroupGetMembers, NetUseGetInfo (sampling, not exhaustive).

7. Services and tasks:
   - Why enumerate: awareness (vulnerable services, AV/EDR services), purpose (DHCP/DNS/FTP → server role), high vs low visibility target.
   - SCM APIs involved for enumerating services and tasks (material doesn't name specific APIs like EnumServicesStatusEx — it just says "the APIs involved for enumerating services and tasks". I can mention EnumServicesStatusEx/OpenSCManager from general knowledge carefully — but rule 4 says material is authority; general Windows docs allowed. I'll mention SCM with care: the material says "enumerating services and tasks via SCM" in note 2's summary. The LGTM note says "services/tasks enumeration via SCM". So I can reference SCM-based enumeration (OpenSCManager, EnumServicesStatusEx) as the standard documented API family per MSDN.)

8. Network/NIC info (IP Helper API ladder):
   - GetAdaptersAddresses: IPv4+IPv6; signature (Family, Flags, Reserved, AdapterAddresses, SizePointer), ULONG return. Primary API for adapter→IP mapping. Includes logical interfaces? Review question: "What API includes logical interfaces in its results? A GetAdapterAddresses B GetNumberOfInterfaces C GetIpStatistics" — unit 38 of part2 says GetNumberOfInterfaces includes logical interfaces and loopback adapters. Hmm: part2 unit 33-34: GetNumberOfInterfaces "will write the number of interfaces discovered on the local machine" and unit 34 notes "differences between this function and others like GetAdaptersInfo and GetInterfaceInfo regarding loopback interface inclusion". The review answer in part7 unit 5 asks which includes logical interfaces — the answer isn't explicitly shown in the excerpt. Unit 33 says GetNumberOfInterfaces includes logical interfaces and loopback adapters (key cues: "loopback adapter, logical interfaces"). I'll state: GetNumberOfInterfaces count includes logical interfaces and loopback; GetInterfaceInfo returns IPv4-enabled devices (IP_INTERFACE_INFO with NumAdapters + IP_ADAPTER_INDEX_MAP array, ERROR_INSUFFICIENT_BUFFER two-call sizing pattern); GetAdaptersAddresses for IPv4/IPv6 adapter addresses; GetIpStatistics (PMIB_IPSTATS). The LGTM note 5 describes "network-adapter API ladder (GetAdapterAddresses > GetNumberOfInterfaces > GetIpStatistics)". So the ladder: GetAdaptersAddresses is the most capable/preferred, then GetNumberOfInterfaces quick count, then GetIpStatistics for aggregate stats.
   - Also PowerShell Get-NetAdapter, netstat -e, ipconfig as command-line alternatives.

9. Registry:
   - Five predefined root keys: HKEY_USERS, HKEY_CLASSES_ROOT*, HKEY_CURRENT_USER*, HKEY_LOCAL_MACHINE, HKEY_CURRENT_CONFIG* (* = link or merged view). HKEY = handle to key.
   - HKCR: file extension associations, COM class registrations, UAC virtualization root; merged view of HKCU\SOFTWARE\Classes + HKLM\SOFTWARE\Classes; roaming profiles influence.
   - HKU: subkey per user profile (HKCU links here), HKU\.Default system profile used by Winlogon; ProfileList key → enumerate user profiles by SID.
   - HKCU: per-login config, points to \Users\<username>\Ntuser.dat; subkeys Console, Software, Control Panel, Identities, Printers, Keyboard Layout; service processes running as a user load that user's HKCU.
   - HKLM: BCD00000000 (boot entries), COMPONENTS (CBS), HARDWARE, SAM (account passwords), SECURITY (policy), SOFTWARE.
   - HKCC: link to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current; backwards compatibility.
   - HKEY_PERFORMANCE_DATA: not accessible via regedit; programmatic via RegQueryValueEx; data technically not stored in registry, provided by external providers; Pdh.dll preferred.
   - Value types: 12 types, 3 common: REG_DWORD (numbers/booleans), REG_BINARY (>32-bit numbers or encrypted passwords, raw data), REG_SZ (Unicode/ANSI strings).
   - Registry read at four critical times: initial boot, kernel boot, logon, application startup; also app installs and polling.
   - Some keys require admin; much accessible to basic users.

10. SDDL inspection flow (from note 5): sc.exe sdshow to view a service's security descriptor (e.g., BITS), interpreted with SDDL and ace_strings.

11. Survey as coordinated action (note 1, units 19-21 of part1): "Survey the host and determine where you are. Knowing the system that you are on is vital to the success of your operation. A host survey tool can query various components and report back its findings that can then be used to determine the next action." Identifying AV/EDR, privilege escalation paths. Survey output gates evasion/injection/persistence selection.

Detection considerations: The material discusses detection only obliquely: hotfix awareness "to avoid detection during exploitation" (unit 27-28 part1: "awareness of which hotfixes have been applied before attempting an exploit to avoid detection"). Undocumented NtQuerySystemInformation as "more stealthy". The material doesn't give ETW providers/Sysmon IDs for recon. Per rule: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.'" But the material does touch on detection-adjacent trade-offs: documented vs undocumented API choice (hookability trade-off mentioned in LGTM note tags: "snapshot lag, hookability, remote-vs-local"), stealth rationale for NtQuerySystemInformation. I can write a Detection Considerations section covering what the material says: documented Win32 APIs are "safe and reliable" but commonly hooked; undocumented native APIs are "risky but stealthier"; snapshot-based methods miss new processes. I should not invent ETW GUIDs or Sysmon IDs. I'll frame the trade-offs as the material presents them and explicitly note the material does not enumerate specific telemetry providers.

Related techniques (from would_relate_to: T-023, T-020, T-016, T-022, T-007):
- T-023 Client Capabilities — sysinfo_collect (HELLO payload) and Byakugan recon currently carry fragments of the survey; this card elevates the survey to a coordinated phase. Byakugan documented there.
- T-020 Anti-Analysis — Kaguya LOtL inventory + EDR detection is a survey consumer/relative: Kaguya inventories binaries and detects security products via NtQuerySystemInformation, which is one of the survey's enumeration APIs. Anti-VM checks overlap with research-VM indicators from installed-software survey.
- T-016 EDR Evasion — survey identifies which EDR is present, gating selection of AMSI/ETW/unhook techniques.
- T-022 Networking — network reconnaissance (Byakugan is client-side network recon; survey's NIC enumeration via IP Helper complements).
- T-007 Process Injection — process enumeration output is the target-selection input for injection (which process to inject into).

Now Key Implementation Details. Verify the Rust sources:

byakugan.rs: implements ARP scan (arp -a parsing), port scan, banner grab, AD enum (nltest, net user /domain, net group /domain), passive discovery. These are network/domain reconnaissance, implemented via spawning system commands (tokio::process::Command) rather than calling the Win32/NT/WTS API surface. The AD enum touches user-account enumeration (domain users, Domain Admins) and parse_local_interfaces touches NIC config. But the primary mechanism of T-024 — the unified local host survey across OS/patch/process/software/service/registry/user domains via the documented API catalog — is not implemented. main.rs collects sysinfo via sysinfo_collect (not provided) for HELLO. protocol.rs is constants.

Per rule 8's explicit test: at least ONE function must implement the primary mechanism. handle_ad_enum implements part of user enumeration but via `net` command execution, not the lmaccess.h NetAPI family the material catalogs. That's adjacent, not the technique as described. I'll declare no current implementation for the unified survey, note the adjacent overlap explicitly, and describe what an implementation would look like per the template's required paragraph.

Actually, let me reconsider. The template says: "If matching Rust source is included in your inputs AND you verified it implements this technique". The conservative, correct answer per the system prompt's repeated warnings is: no unified implementation; Byakugan covers the network-recon slice already documented in T-023. I'll write the "No current implementation" paragraph and describe the implementation shape. I will also accurately describe the overlap so the reader knows byakugan exists (cross-referenced in Related Techniques via T-023).

crate: none. source_file: none.

Tags (5-10 kebab-case): host-survey, discovery, process-enumeration, ip-helper-api, wts-api, ntquerysysteminformation, registry-hives, wua-com, situational-awareness, edr-detection. That's 10.

Tier: A (proposed).

Now word count: target 1200-1800 words body. Let me plan sections:

- Summary: 4 sentences.
- Mechanism: numbered steps covering the survey sequence: OS version/arch → patch status → process enum → installed software → users → services/tasks → network/NIC → registry → aggregate and decide.
- OS Internals Context: SYSTEM_INFO fields, KUSER_SHARED_DATA, SYSTEM_INFORMATION_CLASS, WTS_PROCESS_INFO_EXA, IP_ADAPTER_ADDRESSES two-call buffer pattern, registry hive structure (HKCR merged view, HKU ProfileList/SID, Ntuser.dat, HKLM SAM/BCD), WUA COM object model, EPROCESS kernel representation, version-number mapping table.
- Key Implementation Details: no current implementation paragraph + what it would look like + note byakugan adjacency.
- Why It Matters: survey gates technique selection; vault distributes recon across T-023/T-020/T-022 without a coordinated survey phase; SEC670 devotes Book 2 to it.
- Detection Considerations: documented vs undocumented API trade-off (hookability), snapshot lag, remote-vs-local registry key requirement for WTS, material doesn't enumerate ETW/Sysmon — say so.
- Related Techniques: 5 entries.
- References: atlas parts 1,2,4,5,7; MITRE T1082 URL; LGTM notes; public references: SEC670 course itself (named in material).
- Source Reference: no current implementation.

Careful with banned words: elegant, beautiful, clever, textbook, impressive, clean, slick, neat, well-crafted, robust, solid, nice, brilliant, sophisticated, notable, remarkable. Banned phrases: "but wait", "interestingly", "worth noting", "the key insight", "it is important to note", "as you can see", "essentially", "at its core". No first person, no rhetorical questions, no exclamation marks.

Also avoid "key" as in "key innovation"? The banned list includes specific phrases; "key" alone is fine but I'll be measured.

Let me draft the card.

Frontmatter:

```yaml
---
id: T-024
name: Host Survey and Situational Awareness
category: discovery
tier: A
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1057, T1518.001, T1087, T1016, T1007, T1012]
tags: [host-survey, discovery, process-enumeration, ip-helper-api, wts-api, ntquerysysteminformation, registry-hives, wua-com, situational-awareness, edr-detection]
origin: atlas-synthesis
member_notes: ['lgtm:host-survey-script-primitive', 'lgtm:proposed-recon-survey-card', 'lgtm:proposed-host-survey-card', 'lgtm:proposed-host-survey-recon-card', 'lgtm:recon-enumeration-api-surface']
---
```

Name should be 4-8 words: "Host Survey and Situational Awareness: Unified Reconnaissance" is 8 words with colon. The canonical name from spec. I'll use "Host Survey and Situational Awareness: Unified Reconnaissance" — hmm, frontmatter name vs h1. Template: name: <Human Readable Name — 4-8 words>. "Host Survey and Situational Awareness" is 6 words; use that as name, and h1 can carry the fuller purpose line. Actually let me keep the canonical name in the h1 and a slightly shortened name in frontmatter. The spec says "Canonical name: Host Survey and Situational Awareness: Unified Reconnaissance". I'll use name: Host Survey and Situational Awareness (6 words) — wait, simpler to use the full canonical: "Host Survey and Situational Awareness: Unified Reconnaissance" = Host(1) Survey(2) and(3) Situational(4) Awareness(5) Unified(6) Reconnaissance(7) — 7 words. Fits 4-8. Good.

H1: `# Host Survey and Situational Awareness — Unified Pre-Action Reconnaissance`

Mechanism steps (from material):

1. Determine OS version and architecture: GetNativeSystemInfo → SYSTEM_INFO (wProcessorArchitecture reveals WoW64 vs native); map numeric version (5.1 XP ... 10 = Win10/2016); kernel version from ntoskrnl.exe. Optional undocumented: KUSER_SHARED_DATA. Bootcamp APIs: GetProductInfo, GetWindowsDirectory, GetComputerName.
2. Query patch status: WMI Win32_QuickFixEngineering (Get-HotFix / wmic qfe list both query this class; may be incomplete) or WUA COM APIs (UpdateSession → CreateUpdateSearcher → Search → ISearchResult::get_Updates → IUpdateCollection::get_Count).
3. Enumerate processes: choose among EnumProcesses (simple, thin detail), CreateToolhelp32Snapshot (common in malware, richer detail, snapshot lag — misses processes created after the snapshot), WTSEnumerateProcessesEx (remote-capable via WTSOpenServer handle, multi-session, WTS_PROCESS_INFO_EXA detail; remote requires registry configuration), or undocumented NtQuerySystemInformation(SystemProcessInformation) (stealthier, risky).
4. Inventory installed software: walk C:\Program Files (64-bit), C:\Program Files (x86) (32-bit), C:\ root, user folders; FindFirstFile/FindNextFile directory walks; infer system role and research-VM indicators (Notepad++, Process Hacker, VMware) → continue/abort decision.
5. Enumerate users/groups: net utility or lmaccess.h/lmuse.h family (NetGroupGetUsers, NetLocalGroupGetMembers, NetUseEnum, NetUseGetInfo); hunt Administrators members and logged-on Domain Admins.
6. Enumerate services and tasks via SCM: identify server roles (DHCP/DNS/FTP), vulnerable services, AV/EDR services; sc.exe sdshow for service security descriptors (SDDL).
7. Gather NIC/network configuration via IP Helper: GetAdaptersAddresses (IPv4+IPv6, adapter→address), GetInterfaceInfo (IPv4 devices), GetNumberOfInterfaces (quick count incl. logical + loopback), GetIpStatistics (MIB_IPSTATS).
8. Survey the registry: five root keys; HKLM (SAM, SECURITY, SOFTWARE, BCD), HKU ProfileList → per-SID profiles, HKCR merged Classes view; 12 value types (REG_DWORD/REG_BINARY/REG_SZ common); some hives need admin, much is readable by basic users.
9. Aggregate findings into a survey report; use it to gate evasion selection, injection target selection, persistence method, and continue/abort decisions.

OS Internals Context:

- KUSER_SHARED_DATA: undocumented, read-only user-mode mapping at a fixed address (0x7FFE0000 on x86 / 0x7FFE0000...; on x64 it's 0x7FFE0000 too — actually KUSER_SHARED_DATA is at 0x7FFE0000 in user mode on both. I should be careful — material just says "undocumented method using KUSER_SHARED_DATA". I'll mention the fixed mapping address as documented in Windows internals references (shared user data page mapped at 0x7FFE0000 in every process) — that's well-established. NtSystemRoot/NtBuildNumber/NtMajorVersion/NtMinorVersion fields. I'll keep it short and not over-claim specific field usage beyond version.)
- SYSTEM_INFO field-level notes from unit 4 part7: dwPageSize used by VirtualAlloc; dwActiveProcessorMask bits 0-31 per processor; dwNumberOfProcessors feeds GetLogicalProcessorInformation; lpMinimum/MaximumApplicationAddress bound usermode address space.
- NtQuerySystemInformation + SYSTEM_INFORMATION_CLASS: undocumented enum, community-documented; SystemProcessInformation returns linked list of SYSTEM_PROCESS_INFORMATION (I can name the struct from well-established documentation).
- WTS: WTS_PROCESS_INFO_EXA fields (NumberOfThreads, HandleCount, PagefileUsage, WorkingSetSize, UserTime, KernelTime...); hServer from WTSOpenServer; remote enumeration requires specific registry keys (material says this without naming them — don't invent key paths).
- CreateToolhelp32Snapshot: snapshot semantics — point-in-time copy; TH32CS_SNAPPROCESS; PROCESSENTRY32 iteration via Process32First/Next (material mentions snapshot lag; the flags come from general docs — keep minimal).
- EPROCESS: material references "structures the kernel uses to represent processes in system address space" — name EPROCESS/KPROCESS per Windows Internals.
- Registry internals: HKCR merged view mechanics, HKU↔HKCU link, Ntuser.dat backing file, HKLM SAM/SECURITY ACL'd to SYSTEM, HKCC link to Hardware Profiles\Current, HKEY_PERFORMANCE_DATA not stored in hive (provider-supplied, regedit-invisible, Pdh.dll preferred).
- WUA COM: Wuaapi.h/Wuguid.lib, UpdateSession/UpdateSearcher/SearchResult object chain, WSUS vs Windows Update source.
- Buffer-size idiom: GetInterfaceInfo/GetAdaptersAddresses two-call pattern with ERROR_INSUFFICIENT_BUFFER (material shows SAL annotations and error code).

Detection Considerations:

The material frames detection as API-selection trade-offs:
- Documented Win32 APIs are "safe and reliable" but sit at the commonly hooked layer (LGTM note tags: hookability). The material describes NtQuerySystemInformation as "more stealthy" but risky.
- Snapshot lag (CreateToolhelp32Snapshot) is an operational limitation, not detection per se, but affects fidelity.
- WTSEnumerateProcessesEx remote use requires registry keys on the target — a configuration artifact.
- Material does not enumerate ETW providers, Sysmon IDs, or specific telemetry for survey APIs → state that.
- Hotfix-awareness rationale: unpatched-exploit attempts on patched systems cause crashes/detection — survey reduces self-inflicted detection.

Why It Matters: The vault fragments recon across T-023 (sysinfo, Byakugan), T-020 (Kaguya), T-022 (network). SEC670 dedicates Book 2 to the survey as a coordinated first-phase action whose output gates evasion (T-016), injection target selection (T-007), persistence, and abort decisions (research-VM indicators). Without a survey card, the decision flow linking enumeration to technique selection is undocumented. Also documents the per-API trade-off catalog (snapshot lag, hookability, remote-vs-local) that operators weigh when assembling recon tradecraft.

References:
- Atlas: atlas-recon-part1.md, atlas-recon-part2.md, atlas-recon-part4.md, atlas-recon-part5.md, atlas-recon-part7.md
- MITRE T1082 + URL
- LGTM notes: the five
- Public: SANS SEC670 "Red Teaming Tools: Developing Custom Tools for Windows", Book 2 "Getting to Know Your Target" (named in material)

Word budget check — I should aim ~1400-1600 words body. Let me write it now.

One more check on frontmatter rules: mitre_secondary format "[<additional ATT&CK IDs...>]" — I'll list T1057, T1518.001, T1087, T1016, T1007, T1012. T1518.001 is Security Software Discovery — fits the AV/EDR detection emphasis. Good.

For the "no current implementation" required text: "**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in <source language/tool>." — The material's reference implementations are C/C++ (SEC670 labs: ProcEnum, CreateToolhelp, WTSEnum, FileFinder). So: "See the atlas material for reference implementations in C/C++ (SEC670 Labs 2.1-2.5)."

Then describe what an implementation would look like, one paragraph. Then note the byakugan adjacency accurately.

Structure check — exactly 11 sections in order. Write it.

Length control: Mechanism ~9 detailed steps, OS Internals ~6 paragraphs, that's the bulk. Let me write.