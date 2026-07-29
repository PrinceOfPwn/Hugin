Let me analyze the three cluster specs and the provided source files.

**T-057: Registry Enumeration Pattern: COM Hijack Discovery and Autostart Targeting**
- Category: discovery
- Tier: B
- Member notes: lgtm:registry-enumeration-fingerprint
- Origin: atlas-binary-analysis-part6
- The pattern: RegOpenKeyExW → RegQueryInfoKey → RegEnumValue loop with LSTATUS checking and ERROR_NO_MORE_ITEMS termination
- Related to T-017 (persistence suite - COM hijack), T-023 (client capabilities - recon), T-020 (anti-analysis)
- No Rust source provided implements this. The provided files are html_overlay.rs, lib.rs, tls_cb.rs — none implement registry enumeration. So source_file: none.

**T-058: svchost Shared vs Isolated Service Hosting as Injection Target Selection**
- Category: discovery
- Tier: B
- Member notes: lgtm:svchost-hosting-model-target-selection
- Origin: atlas-methodology-part3
- Related to T-007 (Pool Party / process injection), T-013 (remaining injection methods)
- Content: shared services share address space in one svchost, isolated services have dedicated svchost. Targeting shared svchost risks collateral damage to co-tenant services.
- No Rust source implements this selection criterion. source_file: none.

**T-059: Windows Registry Internal Structure and Link Semantics**
- Category: discovery
- Tier: C
- Member notes: lgtm:windows-registry-internals-deep-dive
- Origin: atlas-recon-part6
- Related to T-017
- Content: HKCR merged view of HKLM\Software\Classes and HKCU\Software\Classes, per-user classes override machine-wide, HKCC entirely linked to HKLM\System\CurrentControlSet\Control\Class (wait — HKCC is HKEY_CURRENT_CONFIG, which is linked to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current). Actually HKEY_CURRENT_CONFIG is a link to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current. Hmm, but the note says "HKCC entirely linked to HKLM" — HKCC could also mean HKEY_CLASSES_ROOT... no, HKCR is HKEY_CLASSES_ROOT. HKCC is HKEY_CURRENT_CONFIG. The tags say ['registry', 'hkcr', 'hkcc', 'com-hijack', 'persistence', 'windows-internals']. So the material discusses HKCR merged-view semantics and HKCC link semantics. HKCC = HKEY_CURRENT_CONFIG → link to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current. The material says "HKCC is entirely linked to HKLM" — that's consistent.
- source_file: none.

The provided Rust files (html_overlay.rs, lib.rs, tls_cb.rs) don't match any of these three cards. They're context noise. I must verify: does tls_cb.rs implement registry enumeration? No — it's PE patching for TLS callback injection. html_overlay.rs is WebView2 overlay. lib.rs is module declarations. None implement registry enumeration, svchost target selection, or registry structure. So all three cards get source_file: none and "No current implementation in the HUGIN source."

Wait — but T-057 relates to T-017 which includes com_hijack.rs in crowd/persist. The file manifest shows dark_crystal/crowd/src/persist/com_hijack.rs exists. But the actual file isn't provided in my inputs — only the manifest references it. Rule 8: "If a `.rs` file is in your inputs: do not assume..." — the file is NOT in my inputs as content, only mentioned in the manifest. I should not cite line ranges for files I can't read. I can mention that com_hijack.rs exists per the manifest? The rules say source_file should be a "verified real path". Since I can't read com_hijack.rs content, I can't verify it implements the enumeration pattern. Safer: source_file: none, and note no current implementation verified. Actually, I could mention in Key Implementation Details that persistence modules exist but the enumeration primitive itself isn't verified. Better to be conservative: "No current implementation in the HUGIN source" for the enumeration pattern itself.

MITRE IDs:
- T-057: Registry enumeration for discovery — best fit is T1012 (Query Registry). That's a real ATT&CK technique: "Query Registry" T1012. Confidence: high.
- T-058: svchost target selection for injection — it's a discovery/selection methodology. Best fit... The technique informs process injection (T1055). As a discovery card, maybe T1057 (Process Discovery)? The note is about selecting injection targets based on service hosting model. Enumerating services would be T1007 (System Service Discovery). But the core is target selection for injection. Given category discovery, T1007 System Service Discovery seems the best fit — discovering which services share svchost instances. mitre: T1007, secondary T1055. That's defensible.
- T-059: Registry internals — structural knowledge underpinning COM hijack persistence. Best fit: T1546.015 (Component Object Model Hijacking)? Actually T1546.015 is COM hijacking. But the card is about registry structure, not the hijack itself. Since it underpins T-017 COM hijack persistence... The note relates to T-017. MITRE: T1112 (Modify Registry) is about modifying registry. Hmm. The card is conceptual structural knowledge. Since it underpins COM hijack, T1546.015 could work as primary with T1012 secondary. Or T1012 primary (understanding registry for discovery). Let me think: category is discovery. The material is recon part6. I'd go T1012 (Query Registry) as primary since reading/understanding registry structure is recon-oriented, secondary T1546.015 (COM Hijacking) since that's what it underpins. Actually T1546.015 — let me verify: T1546 is Event Triggered Execution; .015 is Component Object Model Hijacking. Yes, that's correct.

Tags for each (5-10 kebab-case):
- T-057: registry, enumeration, recon, com-hijack-discovery, autostart, regopenkeyex, regenumvalue, fingerprint
- T-058: svchost, services, target-selection, injection, service-hosting, shared-service, isolated-service, opsec
- T-059: registry, hkcr, hkcc, merged-view, com-hijack, persistence, windows-internals, registry-links

Now depth: 800 words minimum, target 1200-1800 per card. Three cards at ~1200+ words each. Let me write carefully.

**T-057 content details:**

Mechanism of the canonical enumeration pattern:
1. RegOpenKeyExW(hKey, lpSubKey, ulOptions=0, samDesired=KEY_READ, phkResult) — returns LSTATUS, ERROR_SUCCESS on success. Opens key like HKCR\CLSID or HKCU\Software\Classes\CLSID.
2. RegQueryInfoKeyW — retrieves class string, number of subkeys (lpcSubKeys), max subkey name length (lpcbMaxSubKeyLen), number of values (lpcValues), max value name length (lpcbMaxValueNameLen), max value data length (lpcbMaxValueDataLen), security descriptor length, last write time (FILETIME). Used to size buffers for enumeration.
3. RegEnumKeyExW loop for subkeys: index-based, dwIndex from 0, until ERROR_NO_MORE_ITEMS (259L). Note: do NOT cache the subkey count across iterations if keys are being modified; index shifts.
4. RegEnumValueW loop: index-based, lpValueName buffer sized lpcbMaxValueNameLen+1, lpData buffer, lpcbData, lpType (REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ).
5. Every call returns LSTATUS; loop terminates on ERROR_NO_MORE_ITEMS; other errors (ERROR_ACCESS_DENIED, ERROR_MORE_DATA=234) handled distinctly.
6. RegCloseKey.

Operational applications:
- COM hijack discovery: enumerate HKCU\Software\Classes\CLSID\{...}\InprocServer32 to find (Default) values pointing to DLLs; check missing files or absent HKLM counterparts → hijack candidates. Enumerate TreatAs, or find CLSIDs referenced by scheduled tasks / autoruns but whose server binaries are missing.
- Autostart enumeration: HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run, RunOnce, RunEx, Policies\Explorer\Run, Wow6432Node variants, etc.
- Inventory: Installed software via Uninstall keys.

Detection fingerprint: registry ETW provider Microsoft-Windows-Kernel-Registry, Sysmon Event ID 12 (RegistryEvent — object create/delete), 13 (value set), 14 (rename). Reads are not logged by Sysmon by default. Mass sequential enumeration of CLSID keys is a signature (e.g., tools like PowerShell Get-ChildItem HKCU:\... loops, or CIM hunting). Kernel registry callbacks (CmRegisterCallbackEx) with RegNtPreEnumerateValueKey / RegNtPreQueryKey. EDR can flag a non-registry-editor process enumerating thousands of CLSID subkeys in short time.

OS internals: 
- Advapi32 Reg* APIs are wrappers over NT native: NtOpenKeyEx, NtQueryKey (KeyFullInformation / KeyBasicInformation / KeyNodeInformation), NtEnumerateKey, NtEnumerateValueKey. 
- Object Manager paths: \Registry\Machine\... and \Registry\User\<SID>\...
- Configuration Manager (CM) in kernel: hives, cells (HCELL), cell indexes, key control blocks (KCBs) in a hash table per hive.
- KEY_READ = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY.
- ERROR_NO_MORE_ITEMS = 259. ERROR_MORE_DATA = 234.
- RegQueryInfoKey must be called to size buffers since max lengths account for the longest name; registry value names can be up to 16,383 chars, data up to 1MB per value in memory.
- Wow64 redirection: KEY_WOW64_64KEY / KEY_WOW64_32KEY flags in samDesired.

Why it matters: single-call lookups are common; iterative enumeration with proper termination is the reusable primitive for discovery tasks. Consolidating the fingerprint allows both reuse and detection awareness.

**T-058 content details:**

Mechanism:
1. Enumerate services: EnumServicesStatusExW(SC_MANAGER_ENUM_PROCESS_INFO) → ENUM_SERVICE_STATUS_PROCESS gives ServiceStatusProcess.dwProcessId, mapping services → PIDs.
2. For each service, query config: QueryServiceConfigW / QueryServiceConfig2W → lpBinaryPathName. Shared: C:\Windows\System32\svchost.exe -k <group> (e.g., -k netsvcs, -k LocalServiceNetworkRestricted). Isolated: svchost.exe -k <group> also but group of one — determined by the service's ServiceDll in HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters and the group membership in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost (multi-string value per group listing service names).
3. Alternatively, per-service isolation can be forced: ServiceType SERVICE_WIN32_OWN_PROCESS (0x10) vs SERVICE_WIN32_SHARE_PROCESS (0x20) in the service's Type value.
4. Classify candidate svchost PIDs: those hosting many services (netsvcs group can host dozens) vs single-service svchost (e.g., some hardened services run with -k <name> with single member, or "svchost.exe -k <group> -p" on Windows 10 1703+ where per-service splitting became default on machines with >3.5GB RAM).
5. Windows 10 1703+ change: service splitting — each service gets its own svchost by default on systems with sufficient RAM; shared groups remain for legacy/low-integrity. This changes target selection: on modern hosts most svchost processes are single-service.
6. Target selection implications: injecting into shared svchost → crash kills all co-tenant services (fate sharing), possible service recovery via SCM (RestartService), detection via service failure telemetry; injecting into isolated svchost limits blast radius. Also consider: chosen svchost's token/context (LocalSystem vs LocalService vs NetworkService), Session 0 isolation, protected process status (PsProtectedSignerAntimalware for MsMpEng's NisSrv etc.), and PPL.

OS internals:
- SCM (services.exe) RPC interface, service database, SERVICE_STATUS_PROCESS.
- svchost groups registry key; SvcHostSplitDisable in... there's HKLM\SYSTEM\CurrentControlSet\Control\ServiceHostSplitDisable? Actually the value is in HKLM\SYSTEM\CurrentControlSet\Services\<name> — "SvcHostSplitDisable" DWORD. And policy. Let me be careful: per-service value SvcHostSplitDisable=1 keeps it shared. This exists per documentation (e.g., used by threat actors and documented in service splitting research). I'll mention it cautiously.
- Session 0 isolation: services run in session 0; injection from user session requires crossing session boundary (relevant to T-047 cross-session injection).
- EPROCESS, token implications.

Detection: Sysmon 8 (CreateRemoteThread), ETW-TI, service crash telemetry (WER), SCM restart events (Event 7036, 7040 in System log), unexpected service stop/start.

**T-059 content details:**

Mechanism (structure):
1. Hive layout: hives are files (SAM, SECURITY, SOFTWARE, SYSTEM under %SystemRoot%\System32\config; NTUSER.DAT per user; UsrClass.dat per user under AppData\Local\Microsoft\Windows).
2. Predefined handles as view aliases: HKLM, HKU, HKCR, HKCU, HKCC.
3. HKCR merged view: NT 4.0-era merged view of HKLM\Software\Classes (machine-wide) and HKCU\Software\Classes (per-user, backed by UsrClass.dat). Per-user entries override machine-wide for the same subkey. Deletion semantics: deleting a merged key deletes the per-user copy or creates... actually deletion removes the per-user key; if only machine exists, delete fails unless machine deleted. Merged view implemented by CM via "merged keys" — NtQueryKey with KeyHandleTagsInformation? Hmm, I should keep this at documented level: HKCR is a merged view; writes default to per-user hive when run as standard user (virtualization-like behavior? No — writes to HKCR go to HKCU\Software\Classes if caller lacks admin, since Vista UAC; prior writes failed with access denied). Let me be careful: On Vista+, standard users can write to HKCR — the write lands in HKCU\Software\Classes. This is documented behavior (per-user COM registration).
4. HKCU: link/alias to HKU\<SID> (the loaded profile hive, NTUSER.DAT).
5. HKCC: HKEY_CURRENT_CONFIG is a link to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current — entirely a link to HKLM subtree (no independent storage). Contains current hardware profile.
6. Link semantics: registry symbolic links (REG_LINK type, KeySymbolicLinkInformation); CM resolves links at open time. Keys like CurrentControlSet are themselves links to ControlSet00x.
7. Implications for COM hijack (T-017): per-user CLSID registration in HKCU\Software\Classes\CLSID shadows HKLM\Software\Classes\CLSID for the interactive user → hijack without admin; per-user persistence.

OS internals:
- CM: hives composed of bins (HBIN, 4KB-aligned), cells, cell indexes (CM_CELL_INDEX), key nodes (CM_KEY_NODE), value cells (CM_KEY_VALUE), key control blocks cached in KCB hash, name compression.
- Hive files mapped into kernel pool/memory via section objects; dirty hive flushed by hive lazy writer (every 5 seconds? The lazy writer flushes periodically — documented as every 5 seconds for registry).
- Object Manager namespace: \Registry\Machine and \Registry\User; hive list in HKLM\SYSTEM\CurrentControlSet\Control\hivelist.
- REG_LINK and link target resolution.
- Merged view read semantics: NtEnumerateKey over a merged key returns union; per-user wins on name collision.

Detection: writes to HKCU\Software\Classes\CLSID — Sysmon 13; COM hijack hunting via comparing HKCR merged view vs HKLM-only view; monitoring UsrClass.dat writes. Reads are low telemetry.

Length check: each card needs 800+ words body. I'll aim ~1100-1400 each.

References sections:
- T-057: atlas-binary-analysis-part6.md; MITRE T1012 https://attack.mitre.org/techniques/T1012/; lgtm:registry-enumeration-fingerprint. Public references: none explicitly in material — skip or mention none.
- T-058: atlas-methodology-part3.md; MITRE T1007 https://attack.mitre.org/techniques/T1007/ and T1055 secondary; lgtm:svchost-hosting-model-target-selection.
- T-059: atlas-recon-part6.md; MITRE T1012 primary? Hmm — decide. For T-059, the note's would_relate_to is T-017 (persistence/COM hijack). Primary MITRE: since the card is structural knowledge underpinning COM hijack, I could use T1546.015 as primary with T1012 secondary. But is that right? The card itself doesn't perform hijacking. The rule says "single best-fit ATT&CK technique ID". Given the material underpins per-user persistence and COM hijack, and category discovery... Honestly T1012 (Query Registry) fits "registry structure knowledge" as recon. But T1012 is about querying, and this card is about structure/semantics. ATT&CK doesn't have a "registry internals" technique. I'll use T1012 primary, T1546.015 secondary. Hmm, alternatively primary T1546.015 since the operational relevance is COM hijack. The cluster's would_relate_to is T-017 only. The note says "underpins COM hijack persistence (T-017) and per-user persistence generally". I'll go with T1546.015 as primary since that's the offensive technique this knowledge directly enables, secondary T1012. Actually — think about a reader: this card documents registry internals for an operator implementing per-user persistence. MITRE primary = what the card enables = T1546.015 Component Object Model Hijacking. Yes. Confident T1546.015 exists: Event Triggered Execution: Component Object Model Hijacking. Correct.

Crate: none for all three.

Now cross-check banned words and phrases. Avoid: elegant, clever, textbook, notable, etc. Write third-person declarative.

Section structure exactly: frontmatter, h1, Summary, Mechanism, OS Internals Context, Key Implementation Details, Why It Matters, Detection Considerations, Related Techniques, References, Source Reference.

Related Techniques:
- T-057: T-017 Five-Layer Persistence (COM hijack layer uses this enumeration to find targets), T-023 Client Capabilities (recon/sysinfo collection), T-020 (IAT camouflage? no — T-020 is crypto/obfuscation per vault index... wait). Let me check vault index: T-020 is "Anti-Analysis Suite" in the index (T-020: Anti-Analysis Suite). But the cluster spec says would_relate_to T-020. In the file manifest, "T020-crypto" appears... The index says T-020 Anti-Analysis Suite (anti-VM, API hammering, IAT camouflage, self-deletion, Kaguya LOtL, WinHTTP download, diagnostic harness) and T-021 Crypto & Obfuscation. The manifest uses T020-crypto inconsistently. The cluster note says registry enumeration supports "recon collection (T-023)" and relates to T-020. For T-020 relationship: anti-analysis suite includes Kaguya LOtL binary inventory and EDR detection — registry enumeration could check installed EDR products (Uninstall keys). That's a plausible relationship: anti-analysis checks enumerate installed software via registry. I'll state that.

- T-058: T-007 Pool Party / process injection (target selection), T-013 Remaining injection methods (hollowing etc. need host selection). Also could relate to T-047 cross-session but not in would_relate_to — restraint, use only T-007 and T-013.

- T-059: T-017 Five-Layer Persistence (COM hijack layer depends on HKCR merged-view semantics). Maybe also T-057? Both are registry cards in same batch; justifiable? T-059's spec doesn't list T-057. Rule 9: only cross-references justified from provided inputs. T-057 isn't in would_relate_to for T-059. But T-059's knowledge directly underpins T-057's enumeration of HKCR... The inputs don't justify it explicitly. Rule says 2 well-justified beat 8 speculative. For T-059 I'll list T-017 only, and arguably T-057 as the enumeration primitive that operates over these structures — that's reasonably justified since both are registry-focused and T-057 enumerates HKCR per its description. Hmm, the cluster spec for T-057 says "COM-hijack target discovery" which operates on HKCR merged view documented in T-059. I think adding T-057 to T-059's related is justifiable. And T-059 to T-057's related? T-057's would_relate_to is T-017, T-023, T-020. I could add T-059 to T-057 as structural underpinning. I'll add it to both with clear justification since they directly complement. Actually, restraint: the instructions say cross-references from would_relate_to "or cards provided". T-059 and T-057 are both provided in this batch and directly related (registry). I'll include them — it's defensible.

For html_overlay.rs etc. — none relate to these cards. I verify: no registry enumeration in provided sources. tls_cb.rs does PE file patching, no registry APIs. So all source_file: none.

Also member_notes exact: T-057 ['lgtm:registry-enumeration-fingerprint'], T-058 ['lgtm:svchost-hosting-model-target-selection'], T-059 ['lgtm:windows-registry-internals-deep-dive'].

Word counts: Let me draft each card carefully with sufficient depth. I'll count roughly as I write — aim 1200+ words body per card.

Let me write T-057 now.

Draft T-057:

Frontmatter:
```yaml
---
id: T-057
name: Registry Enumeration Pattern for Discovery
category: discovery
tier: B
crate: none
source_file: none
mitre: T1012
mitre_secondary: [T1546.015, T1068?] 
```
Hmm secondary: T1546.015 (COM hijack, which the enumeration discovers targets for), T1068? no. Maybe T1553? no. Keep [T1546.015]. Also maybe T1082? Autostart targeting... The pattern is also used for autostart enumeration (persistence T1547.001 Registry Run Keys). Secondary: [T1546.015, T1547.001]. Good.

name: "Registry Enumeration Pattern for COM and Autostart Discovery" — 4-8 words: "Registry Enumeration Pattern for Discovery and Targeting"? Canonical name is "Registry Enumeration Pattern: COM Hijack Discovery and Autostart Targeting". The `name` field: "Registry Enumeration Pattern for Target Discovery" (6 words). OK.

Summary: 3-5 sentences. The technique: canonical three-call Advapi32 registry enumeration loop (RegOpenKeyExW → RegQueryInfoKeyW → RegEnumValueW/RegEnumKeyExW) with LSTATUS checking and ERROR_NO_MORE_ITEMS termination, used to discover COM hijack candidates (CLSID InprocServer32 registrations with missing binaries or shadowable per-user registrations) and autostart locations. Primary detection surface: ETW registry provider and CmRegisterCallbackEx kernel callbacks observing high-volume sequential key/value enumeration from a non-registry-tool process.

Mechanism steps — I'll write ~10 steps covering open, query info, buffer sizing, subkey loop, value loop, type dispatch, error contract, close, application to CLSID hunting, application to Run keys.

OS Internals: NT native mapping (NtOpenKeyEx, NtEnumerateKey with KeyBasicInformation/KeyNodeInformation, NtEnumerateValueKey with KeyValueFullInformation), CM structures (hive, bin, cell, CM_KEY_NODE, CM_KEY_VALUE, KCB), access masks KEY_READ decomposition, WOW64 redirection flags, error codes, last write time FILETIME from RegQueryInfoKey useful for timestomping detection... last-write time helps identify recently modified keys.

Key Implementation Details: No current implementation. Describe what implementation would look like: a recon module using windows-sys Win32::System::Registry bindings, generic over key path + closure, returning Vec of (name, type, data); used by com_hijack discovery and autostart audit.

Why It Matters: enumerating differs from single lookups; provides reusable primitive; the fingerprint is recognizable, so consolidation lets operator weigh detection.

Detection: ETW Microsoft-Windows-Kernel-Registry (rarely collected due to volume), Sysmon 12/13/14 don't cover reads; kernel callbacks RegNtPreEnumerateValueKey etc.; heuristic: process opening thousands of HKCR\CLSID subkeys; bypass: slow enumeration, targeted queries instead of enumeration, use of RegQueryValue on known candidate CLSIDs gathered from other sources (scheduled tasks XML), WoW64 considerations. Residual artifacts: minimal — read-only, last access not tracked (registry has no last-access), so artifacts are behavioral only.

References: atlas-binary-analysis-part6.md, MITRE T1012 URL, T1546.015 URL maybe, lgtm note. Public references: none named in material — omit.

Source Reference: No current implementation. See atlas material and MITRE reference.

Draft T-058:

name: "svchost Hosting Model Analysis for Injection Targeting" (6 words). Or keep closer to canonical: "svchost Shared vs Isolated Hosting Target Selection". 6-7 words fine.

mitre: T1007 (System Service Discovery), secondary T1055.

Summary: distinction between shared-process services (SERVICE_WIN32_SHARE_PROCESS, co-hosted in one svchost -k group) and isolated (SERVICE_WIN32_OWN_PROCESS or split svchost). For injection target selection: co-tenant fate sharing, crash blast radius, token context. Detection surface: service enumeration itself is low-noise but the downstream injection (CreateRemoteThread, ETW-TI) is where telemetry fires; also service crash telemetry.

Mechanism:
1. OpenSCManager, EnumServicesStatusExW with SC_ENUM_PROCESS_INFO → map service names to PIDs.
2. Count services per PID: multiple SERVICE_STATUS_PROCESS entries sharing dwProcessId = shared svchost.
3. Read HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost values → group → service list; correlate with QueryServiceConfigW lpBinaryPathName "-k group".
4. Read per-service Type value (0x10 own, 0x20 share) and SvcHostSplitDisable.
5. Windows 10 1703+ service splitting behavior on >3.5GB RAM hosts; check build via RtlGetVersion.
6. Select isolated svchost (single service PID) to limit blast radius; confirm token (QueryServiceObjectSecurity / OpenProcessToken) for LocalSystem vs LocalService; verify not PPL (GetProcessInformation ProcessProtectionLevelInfo? or via PS API) — keep documented.
7. Avoid co-tenant critical services (e.g., schedule, rpcss-hosted groups) where a crash cascades to system instability.

OS internals: services.exe SCM, service database, SCM recovery options (SERVICE_FAILURE_ACTIONS — cross-ref T-040 conceptually? not in spec; skip), svchost grouping history, Session 0 isolation, EPROCESS token, PPL (PsProtectedSignerAntimalware-Light), service splitting change documented by MS in 1703. netsvcs group composition. Crash behavior: unhandled exception in shared svchost terminates process → SCM marks all services in group stopped → RestartService recovery or 7034 events. Also mention that some services (e.g., Schedule) can't be stopped; injecting into svchost hosting critical services risks bugcheck? No — user-mode crash doesn't bugcheck, but crashing e.g. wininit-adjacent services... svchost crashing doesn't bugcheck. Keep accurate.

Key Implementation Details: no implementation. Would look like: recon module producing target list with hosting-model annotation consumed by injection selection (T-007 Pool Party dispatcher).

Why It Matters: prevents self-inflicted DoS / detection from mass service failure; modern service splitting changes calculus.

Detection: service enumeration low noise (RPC to SCM over \pipe\ntsvcs? actually SCM uses RPC endpoint; local enumeration via EnumServicesStatusEx is in-process RPC client call), telemetry: Sysmon 8 CreateRemoteThread into svchost, ETW-TI kernel provider, service crash 7034/7031 System event log, WER, SCM recovery actions firing (cross-ref T-040 residual), EDR behavioral rule "unsigned module in svchost address space" via image load callbacks (Sysmon 7). Bypass: pick isolated, non-PPL, non-critical svchost with matching token; prefer threadless/Pool Party style injection avoiding CreateRemoteThread (T-007). Residual: injected memory regions, event log crash entries.

Draft T-059:

name: "Registry Merged Views and Link Semantics" (6 words).

mitre: T1546.015 primary? Hmm wait — reconsider. The card documents structural knowledge. Category discovery. Material origin atlas-recon. Primary ATT&CK... Options: T1012 Query Registry (recon-oriented reading of registry), T1546.015 COM hijack (what it enables). The note: "structural knowledge underpins COM hijack persistence (T-017) and per-user persistence generally". I'll set mitre: T1012 and secondary [T1546.015]? Or primary T1546.015? The rule: "single best-fit ATT&CK technique ID". The card is about registry structure semantics — closest real technique is T1012 Query Registry. But it's not about querying, it's about structure. Given the vault maps concept clusters to nearest technique, and the operational purpose is per-user COM hijack persistence, T1546.015 is the offensive technique that this knowledge directly serves. I think T1546.015 is more honest as "what this enables", while T1012 fits category discovery. Hmm.

Let me look at precedent: T-059's neighbors — T-057 got T1012 as discovery card about registry enumeration. T-059 is also category discovery per spec. To avoid two adjacent cards with same MITRE and to reflect the note's emphasis ("underpins COM hijack persistence"), I'll use T1546.015 primary, T1012 secondary. Confident T1546.015 = Component Object Model Hijacking. Yes.

Summary: The registry presents five predefined root handles that are not independent stores: HKCR is a merged view of machine and per-user class registrations, HKCU is an alias to the user's subkey under HKU, HKCC is a pure link into HKLM. Understanding merge precedence (per-user overrides machine) explains why per-user COM hijack works without admin and why HKCR writes from standard users land in HKCU\Software\Classes. Detection: writes to per-user classes hive (UsrClass.dat) visible via Sysmon 13; merged-view discrepancies detectable by comparing HKCR view vs HKLM-only view.

Mechanism:
1. CM loads hives: machine hives from System32\config, per-user NTUSER.DAT and UsrClass.dat at logon.
2. OM namespace \Registry\Machine, \Registry\User; hive list key.
3. HKCU → \Registry\User\<SID> alias (and _Classes for UsrClass).
4. HKCR merged view: union of HKLM\Software\Classes and HKCU\Software\Classes; per-user wins on collision; enumeration returns union with per-user precedence.
5. Write semantics: standard user writing HKCR\CLSID\... creates under HKCU\Software\Classes (UsrClass.dat); admin writing may go to HKLM.
6. Delete semantics: deleting merged key with both copies deletes per-user first (documented behavior: delete removes the per-user key; machine copy resurfaces after per-user removed).
7. HKCC: link to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current; REG_LINK link semantics; CurrentControlSet itself a link to ControlSet001.
8. Symbolic links via REG_LINK / KeySymbolicLinkInformation; resolved at parse time by CM.
9. Implication for COM: CoCreateInstance resolves CLSID via HKCR merged view → per-user InprocServer32 shadows machine registration for that user's session only.

OS internals: hive/bin/cell anatomy (hbin 4096-byte alignment, cell index, CM_KEY_NODE signature "nk", CM_KEY_VALUE "vk"), KCB cache, hive lazy writer flush interval, UsrClass.dat introduced Vista for per-user COM without admin, link resolution during ObParseObject via CM's parse routine, WOW64 redirection intersecting (HKLM\Software\Classes\CLSID vs Wow6432Node\CLSID for 32-bit), REG_LINK creation restricted (kernel only / RegCreateKeyEx with REG_OPTION_CREATE_LINK requires privileges).

Key Implementation Details: no implementation; crowd's com_hijack.rs exists per manifest but not verified here. Describe what verification/implementation would look like — actually rule: if no source verified, write the "No current implementation" line + one paragraph. The manifest lists persist/com_hijack.rs as T-008/T-017 persistence — that's the COM hijack layer, not this structural doc. So T-059: no implementation.

Why It Matters: explains mechanics behind per-user persistence without admin; prevents operator errors (writing to HKCR expecting HKLM write; enumerating HKCR and mis-attributing ownership); guides detection evasion (per-user writes are quieter? debatable — state facts: per-user hive writes still logged by Sysmon 13 with HKU\<SID>_Classes paths).

Detection: Sysmon 12/13 on HKU\<SID>_Classes\CLSID writes; autoruns-style diffing of HKCR vs HKLM; ETW registry provider; hunting for HKCU-registered CLSIDs referenced by system components. Residual artifacts: UsrClass.dat entries persist across reboot; merged-view shadow survives until per-user key deleted.

References: atlas-recon-part6.md, MITRE T1546.015 URL, T1012 URL, lgtm note.

Now let me make sure body word counts. I'll write generously. Let me estimate as I go — each section ~150-300 words × 8 sections ≈ 1200-1800.

Also must avoid banned words. Check: "canonical" is fine. Avoid "key insight", "notable". Avoid "it is important to note".

Let me write the final cards.

One more check on tags: 5-10 kebab-case each.

T-057 tags: [registry, enumeration, recon, com-hijack, autostart, regenumvalue, discovery, fingerprint] — 8.
T-058 tags: [svchost, services, target-selection, process-injection, service-hosting, opsec, blast-radius, discovery] — 8.
T-059 tags: [registry, hkcr, hkcc, merged-view, com-hijack, windows-internals, registry-links, per-user-persistence] — 8.

origin: atlas-synthesis for all.

Write the cards now. Keep prose technical and dense.

For T-057 Mechanism, concrete steps:

1. Open the parent key with RegOpenKeyExW (e.g., HKEY_CLASSES_ROOT\CLSID or HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run) requesting KEY_READ (or KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE); the wide API maps to NtOpenKeyEx against the OM path \Registry\...; handle returned in phkResult; LSTATUS checked against ERROR_SUCCESS.
2. Call RegQueryInfoKeyW on the open handle to retrieve cSubKeys, cbMaxSubKeyLen, cValues, cbMaxValueNameLen, cbMaxValueDataLen, and the key's last-write FILETIME.
3. Allocate the value-name buffer as cbMaxValueNameLen + 1 WCHARs (the returned length excludes the terminator) and a data buffer of cbMaxValueDataLen bytes.
4. Loop RegEnumKeyExW from dwIndex 0: each call fills the subkey name and last-write time; on ERROR_NO_MORE_ITEMS (259) exit loop; on ERROR_MORE_DATA the buffer was undersized (possible if keys changed since step 2) — reallocate and retry; treat ERROR_ACCESS_DENIED on a subkey re-open as skippable.
5. For each subkey of interest (e.g., a CLSID GUID), open it and enumerate values with RegEnumValueW from dwIndex 0: name, type (REG_SZ etc.), data; (Default) value arrives with empty name; terminate on ERROR_NO_MORE_ITEMS.
6. Dispatch on type: REG_SZ/REG_EXPAND_SZ → path string (expand environment strings via ExpandEnvironmentStringsW when needed); REG_DWORD → numeric; REG_BINARY → raw bytes.
7. Close each handle with RegCloseKey; never cache handle across reboot/logoff (per-user hive unload invalidates).
8. COM-hijack application: for each CLSID with InprocServer32, record (Default) path and ThreadingModel; test file existence; check for absence of corresponding HKLM\Software\Classes\CLSID entry (per-user-only registration or missing binary = hijack candidate); cross-reference CLSIDs consumed by scheduled tasks and autorun entries.
9. Autostart application: enumerate Run/RunOnce/RunOnceEx/Policy Run keys under both HKLM and HKCU plus Wow6432Node variants, capturing value name, data, and key last-write time for change detection baselining.

OS internals for T-057: NtEnumerateKey classes (KeyBasicInformation returns name; KeyNodeInformation name+class; KeyFullInformation counts), NtEnumerateValueKey KeyValueBasicInformation/KeyValueFullInformation; index-based enumeration semantics — CM assigns subkeys indexes via hash order in the parent key cell's subkey list (hash table), so order is not alphabetical and is unstable across add/delete; CM hive structures: HBIN bins, nk/vk cells, subkey lists "lf"/"lh"/"ri"; KCB; access masks; WOW64 flags KEY_WOW64_64KEY 0x0100 / 32KEY 0x0200; ERROR_MORE_DATA 234; LSTATUS vs NTSTATUS mapping in advapi32; REG_OPTION_ flags; volitile keys REG_OPTION_VOLATILE.

Detection detail for T-057:
- Telemetry: ETW Microsoft-Windows-Kernel-Registry (high volume, rarely enabled), kernel CmRegisterCallbackEx (RegNtPreEnumerateKey, RegNtPreEnumerateValueKey, RegNtPreQueryKey), Sysmon does not log registry reads (12/13/14 are create/set/rename/delete only) — so pure enumeration has thin default telemetry; detection leans on EDR kernel callbacks and behavioral heuristics (thousands of distinct CLSID key opens from one process within seconds, typical of ACL/autorun auditing tools).
- Bypass: replace broad enumeration with targeted RegQueryValueExW on candidate keys derived from other sources (task XML, service configs); spread enumeration over time; use native NtEnumerateKey directly to skip advapi32 ETW? (There is Microsoft-Windows-Threat-Intelligence and advapi ETW? Keep to documented: direct NT calls bypass some user-mode hooking.)
- Residual: none on disk; behavioral only.

For T-058 OS internals: SERVICE_WIN32_OWN_PROCESS 0x10, SHARE_PROCESS 0x20; svchost group registry; ServiceDll under Parameters; ServiceDllUnloadOnStop; SCM database; services.exe RPC (scmr); session 0; service splitting in RS3 (1709? it was 1703, build 15063? Service splitting introduced Windows 10 Creators Update 1703 for systems with >3.5 GB RAM — documented widely). SvcHostSplitDisable per-service override. -p flag (privacy? "svchost.exe -k netsvcs -p" — the -p relates to... In 1703+, many services run "svchost.exe -k <name> -p". The -p flag means... documented by researchers as "split/personal"? Microsoft hasn't officially documented -p; research (e.g., Geoff Chappell, others) suggests -p restricts to a single service ("private"?). Hmm — material says nothing about -p. Rule 4: material wins; but I can include well-established Windows internals. -p semantics: undocumented; commonly stated that -p = "process splitting" requiring exactly one service in group. I should be cautious: describe it as "an undocumented switch observed on split services; research indicates it marks the host as dedicated to one service". That's hedged and factual.

Also EPROCESS/EPROCESS.Token, PPL levels PsProtectedSignerAntimalware(-Light), GetProcessInformation with ProcessProtectionLevelInfo (PROCESS_PROTECTION_LEVEL_INFORMATION) — documented Win32 API, safe.

Crash cascade: unhandled exception → werfault, process exits → SCM detects process exit, marks all services hosted in that process as stopped/failed → logs Event 7034 per service; recovery actions may restart (T-040 documents SERVICE_FAILURE_ACTIONS — could cross-ref but not in would_relate_to; restraint, but T-040 is in the vault and directly relevant to crash-recovery cascade... rule 9 says only justified from provided inputs; would_relate_to gives T-007, T-013. I'll stick to those two.)

T-059 OS internals details:
- Hive files: SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT, NTUSER.DAT, UsrClass.dat (since Vista, stores per-user classes and file associations).
- hivelist: \Registry\Machine\SYSTEM\CurrentControlSet\Control\hivelist maps \REGISTRY\MACHINE\SOFTWARE → \Device\HarddiskVolumeX\Windows\System32\config\SOFTWARE.
- Bin/cell: bins are 4KB multiples; cells variable; nk cell: flags (KEY_HIVE_ENTRY etc.), parent cell index, subkey list, value list, security cell, class name; vk cell: name, data (inline if small — if data size high bit set, data stored inline in the cell's data field).
- Merged view implementation: CM_KEY_NODE flag? The merged class view: CM handles "virtualized" merged keys via CM_KEY_BODY referencing two KCBs? Documented behaviorally: HKCR merge semantics documented by MS ("Merged View of HKEY_CLASSES_ROOT"). I'll describe documented behavior rather than fabricate internals: merge at query/enumerate time, per-user precedence, write redirection for non-admins.
- Link: REG_LINK value type; NtCreateKey with REG_OPTION_CREATE_LINK requires SeCreateSymbolicLinkPrivilege? Creating registry symbolic links requires kernel-mode or specific privilege; standard tools can't create them via advapi. HKCC link: HKEY_CURRENT_CONFIG handle opens \Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current. CurrentControlSet → ControlSet00x link determined by Select\Current.
- WOW64: 32-bit view redirects HKLM\Software\Classes → HKLM\Software\Classes\Wow6432Node? Actually class registration redirection for WOW64: HKCR\CLSID shared for some, HKCR\Wow6432Node\CLSID for 32-bit. Documented: registry redirector splits HKLM\SOFTWARE\Classes into shared and redirected portions; CLSID registration for 32-bit goes under Wow6432Node. Mention briefly and accurately: "the registry redirector reflects/redirects portions of the classes hive for 32-bit processes (Wow6432Node), so enumeration from a WOW64 process sees a different merged view."

OK. Now write. Target each card ~1300 words body.

Also ensure Related Techniques format: "- **T-NNN Name** — one-line relationship".

T-057 related:
- **T-017 Five-Layer Persistence** — its COM hijack layer consumes exactly this enumeration output to locate shadowable CLSID registrations.
- **T-023 Client Capabilities** — recon/sysinfo collection reuses the same loop contract for installed-software and configuration inventory.
- **T-020 Anti-Analysis Suite** — environment checks (installed security products, LOtL inventory) enumerate registry keys with this pattern.
- **T-059 Registry Merged Views** — structural semantics that determine which keys the enumeration sees and where writes land. (justified: same batch, registry structural underpinning)

T-058 related:
- **T-007 Pool Party** — thread-pool injection requires a host process; hosting-model classification feeds target choice.
- **T-013 Remaining Injection Methods** — hollowing/hijacking variants inherit the same co-tenant crash-fate constraint.

T-059 related:
- **T-017 Five-Layer Persistence** — COM hijack persistence depends on per-user classes shadowing machine registrations in the merged view.
- **T-057 Registry Enumeration Pattern** — the enumeration primitive operates over the merged view; precedence rules explain what it returns.

Word count vigilance. Write now.

Also h1 format: "# <Technique Name> — <One-Line Purpose>".

T-057 h1: "# Registry Enumeration Pattern — COM Hijack Discovery and Autostart Targeting"
T-058 h1: "# svchost Hosting Model — Injection Target Selection via Shared vs Isolated Services"
T-059 h1: "# Registry Merged Views and Link Semantics — Structural Basis for Per-User Persistence"

Begin writing final output. No text outside delimiters.

Length check while writing: I'll count roughly. Each card: Summary ~120, Mechanism ~350, OS Internals ~300, Key Impl ~120, Why ~80, Detection ~200, Related ~60, References ~50, Source ~30 → ~1300+. Good.