<!-- BEGIN CARD T-057 -->
---
id: T-057
name: Registry Enumeration Pattern for Target Discovery
category: discovery
tier: B
crate: none
source_file: none
mitre: T1012
mitre_secondary: [T1546.015, T1547.001]
tags: [registry, enumeration, recon, com-hijack, autostart, regenumvalue, discovery, fingerprint]
origin: atlas-synthesis
member_notes: [lgtm:registry-enumeration-fingerprint]
---

# Registry Enumeration Pattern — COM Hijack Discovery and Autostart Targeting

## Summary

The canonical Advapi32 registry enumeration pattern — RegOpenKeyExW to open a parent key, RegQueryInfoKeyW to size buffers from key metadata, then an index-based RegEnumKeyExW / RegEnumValueW loop terminating on ERROR_NO_MORE_ITEMS — is the reusable primitive behind COM-hijack candidate discovery, autostart location inventory, and registry-based reconnaissance. It exploits nothing; it exercises the documented Win32 registry API contract, which the Configuration Manager services through NT native calls. An operator uses it to locate CLSID registrations whose InprocServer32 binaries are missing or shadowable, and to inventory Run-key and policy autostart values for both targeting and change detection. The primary detection surface is not Sysmon, which logs no registry reads by default, but kernel registry callbacks (CmRegisterCallbackEx) and behavioral heuristics that flag high-volume sequential key opens from a process that is not a registry tool.

## Mechanism

1. Open the parent key with RegOpenKeyExW — for example `HKEY_CLASSES_ROOT\CLSID`, `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`, or a machine-hive equivalent — requesting KEY_READ (decomposed as STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY). The return is LSTATUS; only ERROR_SUCCESS (0) yields a valid handle in phkResult.
2. Call RegQueryInfoKeyW on the handle. The call returns the subkey count (lpcSubKeys), the longest subkey name (lpcbMaxSubKeyLen), the value count (lpcValues), the longest value name (lpcbMaxValueNameLen), the largest value payload (lpcbMaxValueDataLen), and the key's last-write time as a FILETIME.
3. Allocate the value-name buffer as lpcbMaxValueNameLen + 1 wide characters — the returned maximum excludes the null terminator — and a data buffer of lpcbMaxValueDataLen bytes. The last-write FILETIME is retained; it feeds timestomping-aware baselining.
4. Enumerate subkeys with RegEnumKeyExW starting at dwIndex 0, incrementing per call. Each successful call fills the subkey name and its last-write time. Terminate the loop on ERROR_NO_MORE_ITEMS (259). Handle ERROR_MORE_DATA (234) by growing the buffer and retrying the same index — key contents can change between steps 2 and 4, invalidating the sizing.
5. For each subkey of interest — a CLSID GUID, a TreatAs target, a ProgID — open it with a fresh RegOpenKeyExW and enumerate its values with RegEnumValueW from dwIndex 0. The (Default) value arrives with an empty name string. Terminate on ERROR_NO_MORE_ITEMS; treat ERROR_ACCESS_DENIED on the re-open as a skippable entry, not a fatal error.
6. Dispatch on lpType: REG_SZ and REG_EXPAND_SZ yield path strings (expand REG_EXPAND_SZ with ExpandEnvironmentStringsW before filesystem testing); REG_DWORD yields a numeric flag; REG_BINARY and REG_MULTI_SZ are captured raw.
7. Close every handle with RegCloseKey. Per-user hive handles must not be cached across logoff, because hive unload invalidates them.
8. COM-hijack application: for each CLSID containing an InprocServer32 subkey, record the (Default) path and ThreadingModel. Test the referenced binary for existence on disk. Check whether a corresponding HKLM\Software\Classes\CLSID entry exists — a per-user-only registration or a registration pointing at a deleted binary is a hijack candidate. Cross-reference CLSIDs consumed by scheduled task XML (ComHandler actions) and autorun entries.
9. Autostart application: enumerate Run, RunOnce, RunOnceEx, and Policies\Explorer\Run under both HKLM and HKCU, plus the Wow6432Node variants, capturing value name, data, and parent-key last-write time to build a change-detection baseline.

## OS Internals Context

The Advapi32 Reg* functions are thunks over NT native registry APIs. RegOpenKeyExW becomes NtOpenKeyEx against the Object Manager namespace rooted at `\Registry\Machine` and `\Registry\User`. RegEnumKeyExW maps to NtEnumerateKey with KeyBasicInformation (name only) or KeyNodeInformation (name plus class); RegEnumValueW maps to NtEnumerateValueKey with KeyValueBasicInformation or KeyValueFullInformation. RegQueryInfoKeyW maps to NtQueryKey with KeyFullInformation plus KeyCachedInformation.

Enumeration is index-based, not cursor-based. The Configuration Manager stores a key's subkeys as cell indexes in hash lists (lf/lh/ri cells) hanging off the parent key node (nk cell) inside the hive. Index order follows hash-bucket layout, so enumeration order is not alphabetical and is unstable across subkey addition and deletion; an operator enumerating while another thread mutates the key can see duplicates or misses. This is why the pattern re-queries metadata rather than assuming stability.

The hive itself is a file (SAM, SECURITY, SOFTWARE, SYSTEM under System32\config; NTUSER.DAT and UsrClass.dat per user) mapped into kernel memory and organized into 4096-byte-aligned bins (HBIN) containing variable-length cells. Key nodes carry the signature "nk", value cells "vk"; small value data is stored inline in the value cell when the size field's high bit is set.

WOW64 redirection intersects enumeration: a 32-bit process sees the redirected view under Wow6432Node unless it passes KEY_WOW64_64KEY (0x0100) or KEY_WOW64_32KEY (0x0200) in samDesired. Reconnaissance that must cover both views opens the key twice with explicit flags rather than relying on the default reflection behavior.

LSTATUS values are Win32 error codes, not NTSTATUS; advapi32 performs the translation. The two codes that define the loop contract are ERROR_NO_MORE_ITEMS (259) for termination and ERROR_MORE_DATA (234) for buffer resize. Treating any non-zero code as fatal is the most common implementation bug in this pattern.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would live in a recon module using `windows-sys` Win32::System::Registry bindings: a generic enumerator parameterized on root handle, subkey path, and desired access, returning a vector of (name, type, data, last-write) tuples. Two consumers would sit on top: a COM-hijack scanner that walks HKCR\CLSID (or the per-user classes hive directly), filters to entries with InprocServer32, and tests binary existence plus HKLM-shadowability; and an autostart auditor that walks the Run-key family across both hives and both WOW64 views, emitting a baseline for diffing on subsequent runs. Buffer sizing should call RegQueryInfoKeyW per key rather than using fixed buffers, and the loop must treat ERROR_MORE_DATA as a resize signal.

## Why It Matters

Single-key lookups answer questions an operator already knows to ask; enumeration answers questions the operator has not yet formed. Consolidating the three-call contract, its error semantics, and its detection fingerprint into one card prevents re-derivation of the same loop across COM-hijack targeting, autostart inventory, and installed-software reconnaissance, and it makes the behavioral signature — bulk sequential key opens — an explicit, weighable cost rather than an accident.

## Detection Considerations

- **Telemetry sources**: Sysmon event IDs 12, 13, and 14 cover registry create, value-set, and rename operations but log no reads, so pure enumeration is invisible to default Sysmon configs. Visibility comes from the ETW provider Microsoft-Windows-Kernel-Registry (rarely enabled at scale due to volume), from EDR kernel callbacks registered via CmRegisterCallbackEx observing RegNtPreEnumerateKey, RegNtPreEnumerateValueKey, and RegNtPreQueryKey operations, and from behavioral rules: a non-registry-editor process opening thousands of distinct CLSID subkeys within seconds matches the profile of autorun auditors and hijack scanners.
- **Bypass options**: Replace broad enumeration with targeted RegQueryValueExW calls against candidate keys derived from other sources — scheduled task XML, service configurations, known CLSID lists. Spread enumeration across time to stay under rate-based heuristics. Call the NT native enumeration APIs directly to bypass user-mode hooks on the advapi32 thunks.
- **Residual artifacts**: None on disk; the registry tracks last-write but not last-read. Residue is purely behavioral — timing correlation between enumeration bursts and subsequent persistence writes (Sysmon 13 on HKCU classes keys) is the strongest retroactive indicator.

## Related Techniques

- **T-017 Five-Layer Persistence** — the COM hijack layer consumes exactly this enumeration output to locate shadowable per-user CLSID registrations.
- **T-023 Client Capabilities** — recon and sysinfo collection reuse the same loop contract for installed-software and configuration inventory.
- **T-020 Anti-Analysis Suite** — environment checks such as installed security-product discovery and LotL binary inventory enumerate registry keys with this pattern.
- **T-059 Registry Merged Views and Link Semantics** — the structural rules that determine which keys the enumeration actually sees and where a given registration physically lives.

## References

- Atlas material: atlas-binary-analysis-part6.md
- MITRE ATT&CK: T1012 (https://attack.mitre.org/techniques/T1012/), T1546.015 (https://attack.mitre.org/techniques/T1546/015/), T1547.001 (https://attack.mitre.org/techniques/T1547/001/)
- LGTM notes: lgtm:registry-enumeration-fingerprint

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-057 -->

<!-- BEGIN CARD T-058 -->
---
id: T-058
name: svchost Hosting Model Analysis for Injection Targeting
category: discovery
tier: B
crate: none
source_file: none
mitre: T1007
mitre_secondary: [T1055]
tags: [svchost, services, target-selection, process-injection, service-hosting, opsec, blast-radius, discovery]
origin: atlas-synthesis
member_notes: [lgtm:svchost-hosting-model-target-selection]
---

# svchost Hosting Model — Injection Target Selection via Shared vs Isolated Services

## Summary

Windows hosts most services inside generic svchost.exe processes, and whether a given service shares its host process with other services determines the blast radius of an injection failure. Shared services (SERVICE_WIN32_SHARE_PROCESS, co-hosted under one `svchost.exe -k <group>`) share address space, heap state, and crash fate; isolated services run in a dedicated svchost. An operator selecting a process-injection host uses this distinction to avoid destabilizing co-tenant services unrelated to the objective, and to match the target's token and protection level to the operation. The selection step itself is low-noise — service enumeration is routine system behavior — but the downstream injection telemetry (Sysmon 8, ETW-TI) and any induced service-crash events (System log 7034) are where the decision pays or costs.

## Mechanism

1. Connect to the Service Control Manager with OpenSCManagerW and call EnumServicesStatusExW with SC_ENUM_PROCESS_INFO. The returned ENUM_SERVICE_STATUS_PROCESS array maps every service to its hosting PID via SERVICE_STATUS_PROCESS.dwProcessId.
2. Group the results by PID. Multiple service entries resolving to the same dwProcessId identify a shared svchost instance; a PID with exactly one entry identifies an isolated host.
3. Correlate with the group definition in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`, where each REG_MULTI_SZ value names a group and lists its member services, and with QueryServiceConfigW output — a shared host's lpBinaryPathName takes the form `C:\Windows\System32\svchost.exe -k <group>`.
4. Read each candidate service's configuration from `HKLM\SYSTEM\CurrentControlSet\Services\<name>`: the Type value (0x10 SERVICE_WIN32_OWN_PROCESS versus 0x20 SERVICE_WIN32_SHARE_PROCESS), the ServiceDll under the Parameters subkey, and any SvcHostSplitDisable override that forces sharing on builds that would otherwise split.
5. Account for the Windows 10 1703 service-splitting change: on hosts with sufficient RAM, services that historically shared a group each receive a dedicated svchost, so most svchost processes on modern builds are already single-service. Classification must be performed per host, not assumed from version alone.
6. Filter candidates by execution context: open the host process token and distinguish LocalSystem, LocalService, and NetworkService identities; confirm the process is not protected (GetProcessInformation with ProcessProtectionLevelInfo) — PPL-hosted services reject external handle access regardless of the caller's privileges.
7. Score co-tenancy risk. An unhandled exception in injected code terminates the host process; in a shared svchost every co-hosted service dies with it, the SCM marks each as unexpectedly stopped, and recovery actions or watchdogs fire. Select an isolated svchost whose loss affects exactly one non-critical service.
8. Hand the selected PID, service name, token class, and hosting-model annotation to the injection dispatcher as target metadata.

## OS Internals Context

The SCM (services.exe) owns the service database and tracks which process hosts which service; the EnumServicesStatusExW path is a local RPC client call into the SCM's interface, which is why enumeration produces no suspicious driver-level activity. The svchost grouping mechanism predates Vista and historically concentrated dozens of services into groups such as netsvcs, LocalServiceNetworkRestricted, and netsvcs-style composites. Service splitting, introduced in Windows 10 version 1703 for machines with more than 3.5 GB of RAM, inverted the default: services get their own svchost unless the per-service SvcHostSplitDisable value or a group definition forces sharing. Split hosts frequently appear on the command line as `svchost.exe -k <group> -p`; the `-p` switch is undocumented, with public research indicating it marks the host as dedicated to a single service.

Crash fate sharing is a consequence of process granularity, not a service mechanism: the EPROCESS is the protection and accounting boundary, and every hosted service's DLLs execute on threads inside that one EPROCESS. When the process dies, the SCM's notification of process exit walks its record of services running in that PID and transitions each to a failed state, emitting Event 7034 per service into the System log and scheduling any configured recovery actions. A shared host therefore converts one injection defect into a burst of service-failure telemetry.

Session placement also matters: services execute in Session 0, so reaching an svchost from an interactive-session implant crosses the session boundary, which constrains handle acquisition and UI-adjacent techniques. Protection level is orthogonal: an isolated but PPL-protected svchost is a worse target than a shared unprotected one. The classification step must therefore evaluate hosting model, token, session, and protection level as a tuple, not hosting model in isolation.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would be a recon module producing an annotated process list: for each svchost PID, the set of hosted service names (from EnumServicesStatusExW correlation), the group name, the service Type flags, the token identity, and the protection level. Injection selection in the dispatch layer would then filter on `hosted_services.len() == 1`, exclude protected processes, and prefer hosts whose single tenant is restartable and non-critical. The module requires only read access to the SCM and registry, making it safe to run early in the kill chain.

## Why It Matters

Injection technique cards describe how to enter a process; this card describes which process to enter. Mis-selecting a shared svchost converts a recoverable injection failure into a multi-service outage with clustered event-log entries — an operator-visible, defender-alerting cascade. The 1703 service-splitting change means the optimal target set differs materially between legacy and modern hosts, so the distinction must be computed, not remembered.

## Detection Considerations

- **Telemetry sources**: The enumeration phase rides benign APIs and produces little signal. Detection weight falls on the injection itself: Sysmon Event ID 8 (CreateRemoteThread) with source and target images, the ETW Threat-Intelligence provider reporting cross-process memory writes and thread creation, and kernel image-load callbacks catching unsigned modules mapped into svchost (Sysmon 7). Induced failures emit System-log Event 7034 (unexpected termination) per co-hosted service, plus WER artifacts.
- **Bypass options**: Choose an isolated, non-PPL svchost whose tenant is a restartable, non-critical service with a matching token. Prefer injection paths that avoid CreateRemoteThread — thread-pool manipulation, thread hijack, or APC-based entry — so the hosting decision is not undermined by a high-fidelity thread-creation alert.
- **Residual artifacts**: Injected allocations inside the host's address space, a 7034 cluster if the host crashes, and service recovery activity if SCM restarts the tenant. On split hosts the crash signature is a single-service failure, which blends with routine service flakiness far better than a multi-service group death.

## Related Techniques

- **T-007 Pool Party** — thread-pool injection requires a live host process; hosting-model classification supplies the target with bounded crash blast radius.
- **T-013 Remaining Injection Methods** — hollowing, hijacking, and stomping variants inherit the same co-tenant crash-fate constraint when aimed at service hosts.

## References

- Atlas material: atlas-methodology-part3.md
- MITRE ATT&CK: T1007 (https://attack.mitre.org/techniques/T1007/), T1055 (https://attack.mitre.org/techniques/T1055/)
- LGTM notes: lgtm:svchost-hosting-model-target-selection

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-058 -->

<!-- BEGIN CARD T-059 -->
---
id: T-059
name: Registry Merged Views and Link Semantics
category: discovery
tier: C
crate: none
source_file: none
mitre: T1546.015
mitre_secondary: [T1012]
tags: [registry, hkcr, hkcc, merged-view, com-hijack, windows-internals, registry-links, per-user-persistence]
origin: atlas-synthesis
member_notes: [lgtm:windows-registry-internals-deep-dive]
---

# Registry Merged Views and Link Semantics — Structural Basis for Per-User Persistence

## Summary

The registry's predefined root handles are not independent stores: HKEY_CLASSES_ROOT is a merged view over machine-wide and per-user class registrations, HKEY_CURRENT_USER is an alias into HKEY_USERS, and HKEY_CURRENT_CONFIG is entirely a link into the HKLM subtree with no storage of its own. Merge precedence — per-user classes override machine-wide ones for the querying session — is the structural fact that makes per-user COM hijack persistence work without administrative rights. An operator implementing persistence or interpreting reconnaissance output must understand which hive a registration physically lands in and which view a consumer resolves against. The detection surface concentrates on writes to the per-user classes hive (UsrClass.dat), visible as Sysmon Event 13 against `HKU\<SID>_Classes` paths, and on merged-view discrepancies detectable by diffing HKCR against HKLM alone.

## Mechanism

1. At boot and logon, the Configuration Manager loads hives: machine hives (SAM, SECURITY, SOFTWARE, SYSTEM) from `%SystemRoot%\System32\config`, and per-user hives — NTUSER.DAT and UsrClass.dat — for each interactive profile. The hive inventory is exposed at `HKLM\SYSTEM\CurrentControlSet\Control\hivelist`.
2. The Object Manager namespaces the registry under `\Registry\Machine` and `\Registry\User`. HKEY_LOCAL_MACHINE opens the former; HKEY_USERS opens the latter.
3. HKEY_CURRENT_USER is an alias to `\Registry\User\<SID>` — the caller's loaded profile hive. No HKCU storage exists independently; a HKCU write is an HKU\<SID> write through a convenience handle.
4. HKEY_CLASSES_ROOT is a merged view composed of `HKLM\Software\Classes` (machine-wide registration) and `HKCU\Software\Classes` (per-user registration, physically resident in UsrClass.dat since Vista). Reads and enumerations return the union; on name collision the per-user entry wins.
5. Writes to HKCR follow the caller's privilege: a standard user writing `HKCR\CLSID\{...}\InprocServer32` silently lands in HKCU\Software\Classes; an elevated caller can write the machine-wide portion. This write redirection is the documented behavior that enables per-user COM registration without admin.
6. Deletes on a merged key remove the per-user copy first; if a machine-wide copy exists underneath, it resurfaces in subsequent reads once the shadowing per-user key is gone. Cleanup logic must delete both copies to fully remove a registration.
7. HKEY_CURRENT_CONFIG is a pure link to `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current` — every HKCC read is an HKLM read through a symbolic link. It holds the active hardware profile and has no per-user dimension.
8. Link resolution recurses: CurrentControlSet itself is a link to ControlSet00x, selected by the Select\Current value. The Configuration Manager resolves REG_LINK symbolic links at parse time during object lookup.
9. COM activation consumes the merged view: CoCreateInstance resolves the CLSID through HKCR, so a per-user InprocServer32 registration shadows the machine-wide server for that user's session only, redirecting activation to an operator-controlled binary without touching HKLM.

## OS Internals Context

A hive is a file-backed memory image organized into 4096-byte-aligned bins (HBIN), each containing variable-length cells addressed by cell index. Key nodes carry the "nk" signature and hold the parent cell index, subkey list, value list, security descriptor cell reference, and class name; value cells carry "vk" and store small payloads inline when the data-size high bit is set. Subkey lists are hash structures (lf/lh/ri cells), which is why enumeration order is hash-determined rather than lexical. Loaded hives are tracked per key control block in a hash table the CM maintains for fast name lookup, and modified cells are flushed to the hive file by the lazy writer on a periodic schedule, so a crash can strand very recent writes.

Merged-view behavior is implemented in the CM's key lookup: when a key participates in the classes merge, queries consult both the machine and per-user branches and apply precedence. The operational consequences that matter to an operator are the documented ones — per-user wins on collision, enumeration returns the union, unprivileged writes redirect to the per-user hive, and deletes peel the per-user layer first.

Registry symbolic links (REG_LINK) are a distinct mechanism from the merged view. HKCC and CurrentControlSet are links; creating new links is effectively restricted to kernel-mode callers, so operators consume links rather than mint them. Link resolution happens transparently in the namespace parse path, meaning a handle opened against HKCC\...\Current is indistinguishable from one opened against the HKLM target.

WOW64 intersects both mechanisms: the registry redirector splits portions of the classes hive for 32-bit processes (the Wow6432Node\CLSID view), so a 32-bit consumer of HKCR sees a different merged view than a 64-bit consumer on the same machine. Persistence aimed at 32-bit COM servers must account for the redirected branch. Per-user classes under HKU\<SID>_Classes follow the same shadowing rules, and because UsrClass.dat roams with the profile, per-user registrations can follow a domain user across machines — a persistence property with no machine-hive equivalent.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation drawing on this knowledge would not be a standalone module but a set of structural rules baked into registry-writing code: the COM-hijack persistence layer should write per-user registrations to HKCU\Software\Classes directly (rather than HKCR, to make the physical landing explicit), should treat enumeration of HKCR as a merged-view read when auditing for shadow conflicts, and should delete both the per-user and machine copies during cleanup. Verification tooling should resolve HKCR and HKLM\Software\Classes separately to expose shadowing.

## Why It Matters

Merged-view and link semantics explain, at the structure level, why per-user persistence requires no elevation and why cleanup so often fails — the machine registration resurfaces after a per-user delete. They also prevent operator error: writing to HKCR while assuming an HKLM write, or auditing HKCR and mis-attributing a per-user shadow to the machine hive. Surfacing this as a dedicated concept card gives the persistence and reconnaissance cards a fixed reference for the behavior they depend on.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 13 captures value writes under `HKU\<SID>_Classes\CLSID`, exposing per-user registrations; Event 12 covers key creation. ETW's Microsoft-Windows-Kernel-Registry provider and CmRegisterCallbackEx callbacks give EDRs the same visibility. Autorun-style hunting tools diff the HKCR merged view against the HKLM-only view to surface shadow registrations.
- **Bypass options**: There is no way to make a functional per-user registration invisible to the merged view — the shadow must exist to work. Operators reduce noise by writing only the minimal key set (CLSID plus InprocServer32, skipping ProgID where possible) and by shadowing CLSIDs already consumed by a legitimate, frequently activated component so the registration blends with expected activation traffic.
- **Residual artifacts**: UsrClass.dat entries persist across reboot and roam with the profile; the shadow survives until the per-user key is explicitly deleted. Forensic acquisition of UsrClass.dat reveals the full per-user registration set.

## Related Techniques

- **T-017 Five-Layer Persistence** — the COM hijack layer depends directly on per-user classes shadowing machine registrations in the HKCR merged view.
- **T-057 Registry Enumeration Pattern** — the enumeration primitive operates over the merged view; precedence and redirection rules determine what its reads return and where its consumers' writes land.

## References

- Atlas material: atlas-recon-part6.md
- MITRE ATT&CK: T1546.015 (https://attack.mitre.org/techniques/T1546/015/), T1012 (https://attack.mitre.org/techniques/T1012/)
- LGTM notes: lgtm:windows-registry-internals-deep-dive

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-059 -->