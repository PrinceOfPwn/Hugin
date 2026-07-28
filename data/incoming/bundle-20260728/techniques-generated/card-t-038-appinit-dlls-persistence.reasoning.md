Let me analyze the inputs for T-038: AppInit_DLLs Registry Persistence.

Cluster spec gives:
- ID: T-038
- Name: AppInit_DLLs Registry Persistence
- Category: persistence
- Tier: A
- would_relate_to: T-017, T-013
- member_notes: lgtm:appinit-dlls-persistence-card, lgtm:proposed-appinit-dlls-persistence-card, lgtm:proposed-appinit-dlls-persistence

Source files included: browser_hook.rs (browser extension persistence, not AppInit), chain.rs (chain orchestration, no AppInit), edo_tensei.rs (resurrection engine, no AppInit). None of these implement AppInit_DLLs. So `crate: none`, `source_file: none`. I must verify: browser_hook.rs does registry Run key persistence — that's Run key, not AppInit_DLLs. chain.rs has persist module but the persist layers are COM hijack, NTFS EA, schtask, TLS callback — no AppInit. edo_tensei.rs — no AppInit. So no current implementation.

Atlas material:
- atlas-edr-evasion-part6 unit 14: SEC670 review question — "What technique should be used for processes linked against User32.dll?" — AppInit (vs AppCert, RunOnce).
- atlas-exploit-dev-part24 unit 22: Lab 4.5 "InitToWinInit" — create AppInit_DLLs key, use malicious DLL, watch out for infinite loading situations. Book 4 "Persistence: Die Another Day".
- atlas-misc-part1 units 5, 6, 8, 9: AppInit_DLLs registry key details:
  - LoadAppInit_DLLs (REG_DWORD) — when enabled, each newly created user mode process linked against User32.dll will load DLLs in the AppInit_DLLs list.
  - AppInit_DLLs (REG_SZ) — comma-separated list.
  - HKLM registry keys.
  - Admin privileges required.
  - Infinite loop prevention discussed.
  - Historical use: APT39, CherryPicker, T9000.

MITRE: T1546.010 (Event Triggered Execution: AppInit DLLs). That's the correct ATT&CK ID. Yes, T1546.010 is AppInit DLLs. Confident.

Registry path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows — values AppInit_DLLs (REG_SZ), LoadAppInit_DLLs (REG_DWORD), and there's also RequireSignedAppInit_DLLs (REG_DWORD) on later Windows. The material mentions "AppInit_Dlls bypass mitigation via LoadAppInit_DLLs=0" and "LoadAppInit_DLLs=0 by default on recent builds" from the LGTM notes. The note says "modern-Windows applicability (LoadAppInit_DLLs=0 by default on recent builds)". Also the cluster description says "Gated on LoadAppInit_DLLs registry value (admin required)".

WOW64 consideration: on 64-bit Windows, 32-bit processes use HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows. This is well-established Windows knowledge — the AppInit_DLLs key is reflected under WOW6432Node for 32-bit processes. I can state that as established Windows documentation knowledge.

Also well-documented: starting with Windows 8, AppInit_DLLs is disabled when Secure Boot is enabled; and RequireSignedAppInit_DLLs value. These are documented by MSDN ("AppInit_DLLs in Windows 7 and Windows Server 2008 R2" KB article). I should be careful — the material doesn't mention Secure Boot or RequireSignedAppInit_DLLs explicitly. The LGTM notes mention "LoadAppInit_DLLs=0 by default on recent builds" — that's in the notes, so I can use it. Should I mention RequireSignedAppInit_DLLs? It's well-established Windows documentation (MSDN KB197571). Rule 4 allows "Well-established Windows internals documentation (Windows Internals 7ed, MSDN, ntdll headers)". MSDN documents RequireSignedAppInit_DLLs and the Secure Boot behavior. I think it's safe to include briefly as established documentation, but I should be conservative. The main gate the material emphasizes is LoadAppInit_DLLs.

Infinite loading hazard: the DLL gets loaded into every user32-linked process. If the DLL itself spawns a process (e.g., calls CreateProcess) or if DllMain does something that triggers loading again, infinite recursion/loading situations occur. Material says "Watch out for infinite loading situations." Also DllMain loader lock considerations apply — AppInit DLLs are loaded during user32.dll initialization, which is within the loader lock context, so DllMain must be minimal. That's established Windows knowledge (loader lock).

Mechanism steps:
1. Operator writes malicious DLL to disk (e.g., %SystemRoot%\System32 or another path).
2. Set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs (REG_DWORD) = 1 — requires admin.
3. Set AppInit_DLLs (REG_SZ) to DLL path(s), comma-separated (space or comma delimited per MSDN — material says comma separated).
4. For 32-bit processes on x64, mirror under WOW6432Node.
5. On each new process creation: process initializes, ntdll maps image, kernel32 loads, user32.dll loaded (if linked). During user32.dll's initialization (DllMain / ClientThreadSetup), it reads the AppInit_DLLs registry value and calls LoadLibrary on each listed DLL.
6. DLL's DllMain runs with DLL_PROCESS_ATTACH in the context of the new process.
7. Persistence achieved: every subsequent user32-linked process launch loads the DLL until the key is removed or LoadAppInit_DLLs set to 0.

Actual internals: user32.dll!ClientThreadSetup is the function historically responsible for loading AppInit DLLs — it's called during user32 initialization when a thread first converts to a GUI thread. Actually, the loading happens in user32's initialization path: when user32.dll loads, it reads AppInit_DLLs from the registry and LoadLibrary's each DLL. The precise mechanism: kernel32!BaseThreadInitThunk → for GUI processes, user32 initialization via USER32!_UserClientDllInitialize (the DllMain of user32), which processes the AppInit_DLLs list. In older documentation (and per Geoff Chappell / others), it's user32.dll that reads the registry key and loads the DLLs. This is well-established. I'll describe it as user32.dll's initialization routine reading the value and calling LoadLibrary — careful to note this is the documented behavior.

Note: not all processes link user32 — console-only processes that don't load user32.dll won't get the DLL. The material emphasizes "user mode process that is linked against User32.dll". So GUI processes primarily. That's the "user32-conditional" profile.

MITRE ATT&CK T1546.010 - Event Triggered Execution: AppInit DLLs. URL: https://attack.mitre.org/techniques/T1546/010/

Related techniques:
- T-017 Five-Layer Persistence — sibling persistence suite; AppInit_DLLs is a registry-resident layer not included in the five; complementary; also AppInit could be monitored by the resilience monitor conceptually. The would_relate_to lists T-017.
- T-013 Remaining injection methods — hmm, why relate to T-013? Note 3 lists T-013 as would_relate_to. T-013 covers injection methods including Module Stomping and Reflective PE Loader. The relationship: AppInit_DLLs is a registry-driven DLL injection vector — a persistence mechanism that doubles as a system-wide DLL injection primitive, contrast with the in-memory injection methods in T-013 (which don't require disk-resident DLL or registry). The DLL loaded via AppInit is a disk-resident DLL loaded via the OS loader, versus T-013's memory-only techniques. Also T-016 was listed in note 1's would_relate_to but the cluster spec's final would_relate_to is only ['T-017', 'T-013']. I should only reference those two per rule 9 (only cards from the would_relate_to list or explicitly discussed in related cards). Stick with T-017 and T-013.

Detection:
- Material doesn't deeply discuss detection for AppInit_DLLs. The notes mention "AppInit_Dlls bypass mitigation via LoadAppInit_DLLs=0" — i.e., the defender mitigation. Historical use by APT39, CherryPicker, T9000 (documented by MITRE). Sysmon Event ID 13 (RegistryEvent — Value Set) would observe registry writes to the key. ETW: Microsoft-Windows-Kernel-Registry or the Sysmon registry provider. Autoruns lists AppInit DLLs. These are well-established detection facts — Sysmon Event ID 13 for registry value set is well documented. Rule 4 says don't fabricate Sysmon event IDs — Sysmon 12/13/14 (registry key create/delete, value set, key rename) are well-established. I'm confident Event ID 13 is "RegistryEvent (Value Set)". Autoruns coverage of AppInit is well-established (Sysinternals Autoruns has AppInit tab category). MITRE T1546.010 page mentions monitoring the registry paths. I think stating Sysmon 13 and Autoruns is defensible as established knowledge. The material itself doesn't discuss detection, so I could write the "Training material does not discuss detection" line — but the rule says if material doesn't cover detection write that line and don't invent. Hmm. But the template also says to cover telemetry sources the material describes. The material doesn't describe detection. However, the LGTM note mentions "AppInit_Dlls bypass mitigation via LoadAppInit_DLLs=0" — that's a mitigation, arguably detection-adjacent. I'll write: material does not provide detection content; then note only the mitigation documented in material (LoadAppInit_DLLs=0), plus residual artifacts which are inherent to the mechanism (registry values, DLL on disk) — those are facts of the mechanism, not invented detections. I can frame residual artifacts as mechanism-derived. I should be careful with Sysmon/ETW GUIDs — I'll say the material does not discuss detection and limit to what's defensible: registry values themselves are the artifact, the DLL file on disk, and the LoadAppInit_DLLs gate as the defender-side mitigation named in the notes. I could mention Autoruns as public knowledge — it's named in MITRE T1546.010 mitigation/detection... Actually MITRE detection for T1546.010: "Monitor DLL loads by processes that load user32.dll" and registry monitoring. Autoruns does flag AppInit entries — well established. I'll keep it minimal: state material doesn't discuss detection, then give the mechanism-inherent artifacts (registry values, on-disk DLL, LoadLibrary events in every GUI process) and the documented mitigation. Avoid inventing Sysmon IDs — though Event 13 is well established... The rule says "Do not fabricate... Sysmon event IDs". Sysmon Event ID 13 = Registry Value Set is not fabrication; it's documented Microsoft Sysmon schema. I'm confident. I'll include it cautiously as "Sysmon Event ID 13 (registry value set)" — this is established. And ETW provider Microsoft-Windows-Kernel-Registry... I won't give a GUID. Fine.

Word count: need 800+ body words minimum, target 1200-1800. Let me draft with adequate depth.

Tags: 5-10 kebab-case: [appinit-dlls, persistence, registry, user32, dll-injection, hklm, loadappinit-dlls, gui-processes, loader-lock, autoruns-detectable] — pick ~8: appinit-dlls, registry-persistence, user32-loading, dll-injection, hklm, loadappinit-gate, gui-process-scope, wow6432node.

mitre: T1546.010. No secondary needed, though T1055.001 (DLL injection) could be secondary. I'll add mitre_secondary: [T1055.001]? The technique is persistence with injection side-effect. The template allows omitting. I'll include T1055.001 as secondary since loading a DLL into every GUI process is process injection (dynamic-link library injection). Actually T1055.001 is "Dynamic-link Library Injection" — reasonable. Keep it.

Frontmatter:
- id: T-038
- name: AppInit_DLLs Registry Persistence
- category: persistence
- tier: A
- crate: none
- source_file: "none"
- mitre: T1546.010
- mitre_secondary: [T1055.001]
- tags: [appinit-dlls, registry-persistence, user32-loading, dll-injection, hklm-hive, loadappinit-gate, gui-process-scope, wow6432node]
- origin: atlas-synthesis
- member_notes: [lgtm:appinit-dlls-persistence-card, lgtm:proposed-appinit-dlls-persistence-card, lgtm:proposed-appinit-dlls-persistence]

H1: # AppInit_DLLs Registry Persistence — User32-Conditional DLL Loading via HKLM

Sections:

Summary: AppInit_DLLs is a registry-resident persistence mechanism that forces every newly created user-mode process linked against user32.dll to LoadLibrary a comma-separated list of DLLs from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows. Gated by LoadAppInit_DLLs REG_DWORD. Admin required. Loading occurs inside every GUI process at user32 initialization — giving both persistence and system-graph-wide code execution without remote thread creation. Detection surface: registry value writes + on-disk DLL + DLL load events in every GUI process.

Mechanism — numbered steps:
1. Drop DLL on disk.
2. Enable gate: LoadAppInit_DLLs=1 (REG_DWORD) under HKLM\...\Windows — needs admin (HKLM write).
3. Populate AppInit_DLLs (REG_SZ) with path(s), comma-separated per material.
4. On x64, mirror values under WOW6432Node for 32-bit processes.
5. New process created → ntdll maps image, loader resolves imports.
6. If process links user32.dll (statically or via delayed load when GUI thread created), user32 initialization reads AppInit_DLLs value and calls LoadLibrary on each entry.
7. DllMain(DLL_PROCESS_ATTACH) executes under loader lock in the new process context.
8. Repeats for every subsequent GUI process — recursion hazard if DLL spawns processes.
9. Persistence survives reboot (HKLM hive).

OS Internals Context:
- Registry location: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows — same key family holding other Windows subsystem settings (e.g., SharedSection, which configures desktop heaps — this key is the Windows subsystem configuration key read by the kernel/win32k at init). Values: AppInit_DLLs (REG_SZ), LoadAppInit_DLLs (REG_DWORD), and (per MSDN) RequireSignedAppInit_DLLs.
- Loader side: loading performed by user32.dll during its client initialization, i.e., the DLL is loaded by the OS loader via LoadLibrary — appears in PEB loader lists (InLoadOrderModuleList etc.) as a normal MEM_IMAGE module, unlike T-013 reflective loading which is invisible to PEB.
- Loader lock: DllMain runs under loader lock; only safe operations.
- user32-conditional scope: processes not linking user32 (native apps, pure console services) never load the DLL. GUI subsystem processes trigger it. Consoles that later load user32 (e.g., via MessageBox) also trigger.
- WOW64: 32-bit processes read WOW6432Node-reflected key.
- Version differences: on modern builds LoadAppInit_DLLs defaults to 0 (per material); MSDN documents Secure Boot disabling AppInit DLLs (Windows 8+). I'll mention the material's claim and the MSDN-documented signing requirement carefully.
- Contrast with AppCert DLLs (different key, creation-time callback into every process via kernel32) and Run keys (single execution at logon) — material explicitly frames AppInit as the correct answer for user32-linked processes vs AppCert/RunOnce (SEC670 review Q).

Key Implementation Details: No current implementation. Describe what implementation would look like: registry writes via NtSetValueKey through RecycledGate to be consistent with crowd's syscall-only style, DLL dropped to disk, DllMain guarded against recursion (check for own mutex / GetModuleHandle of self), and integration with persist::PersistConfig as a sixth layer. One paragraph.

Why It Matters: fills gap — T-017's five layers don't include registry-resident user32-conditional loading; distinct trigger profile (process creation of any GUI app vs logon/COM invocation); documented in SEC670 across multiple units + Lab 4.5; historical APT use (APT39, CherryPicker, T9000) means defenders watch it — but it provides coverage T-017 lacks: execution inside arbitrary privileged GUI processes (e.g., an elevated installer) without injection APIs.

Detection Considerations: state material doesn't discuss detection deeply; notes document the LoadAppInit_DLLs=0 mitigation. Then: telemetry — Sysmon EID 13 (registry value set) on the Windows key; Autoruns enumerates AppInit; DLL load events (Sysmon EID 7 Image Load) of the unsigned DLL into many processes. Hmm — Sysmon EID 7 = Image loaded. That's also established. I'll keep both but carefully. Actually rule: "Do not fabricate ... Sysmon event IDs". IDs 13 (value set) and 7 (image load) are standard documented Sysmon schema — I'm confident in both. Include. ETW-TI (Microsoft-Windows-Threat-Intelligence) sees LoadLibrary? No — ETW-TI is for memory/injection telemetry; a normal LoadLibrary of a disk file is not an ETW-TI event. Don't overreach. Kernel image-load callbacks (PsSetLoadImageNotifyRoutine) see every load — EDRs use that. That's established.

Bypass options per material: none discussed; the note mentions LoadAppInit_DLLs=0 as a bypass mitigation (defender side). I'll say material documents the defender mitigation (default-disabled on recent builds) and no operator-side bypass is discussed.

Residual artifacts: two registry values (plus WOW6432Node mirror), DLL file on disk, module presence in PEB loader lists of every GUI process, Autoruns entry.

Related Techniques:
- T-017 Five-Layer Persistence with Resilience Monitor — sibling suite; AppInit_DLLs is a registry-resident sixth candidate; T-017's resilience monitor model applies; none of T-017's layers provide user32-conditional load into arbitrary new GUI processes.
- T-013 Additional Injection Methods — contrast: T-013 methods are memory-only injections into chosen targets (no disk DLL, no registry); AppInit achieves DLL execution graph-wide through the OS loader, leaving the module visible in PEB lists — the opposite OPSEC profile of T-013's Reflective PE Loader.

References:
- Atlas: atlas-edr-evasion-part6.md (unit 14), atlas-exploit-dev-part24.md (unit 22), atlas-misc-part1.md (units 5, 6, 8, 9)
- MITRE: T1546.010 https://attack.mitre.org/techniques/T1546/010/
- LGTM: the three IDs
- Public: MSDN KB197571 "Working with the AppInit_DLLs registry value"? The material doesn't name it. Public references named in material: APT39, CherryPicker, T9000 (threat actors/tools — MITRE attributes AppInit use to these). Material names them, so I can reference "documented use by APT39, CherryPicker, T9000 (per material and MITRE T1546.010)". Also GflagsX/Pavel Yosifovich not relevant. SEC670 Lab 4.5 InitToWinInit — named in material, can cite as lab reference.

Source Reference: No current implementation. See atlas material and MITRE reference.

Length: aim ~1300-1500 words body. Write it now, third person, no banned words. Avoid "elegant", "notably", etc. Careful with "notable" — banned. Avoid "worth noting". Avoid "essentially", "at its core".

Draft:

---

Summary paragraph: ~4 sentences.

Mechanism steps: ~9 steps.

OS Internals: several paragraphs.

Key Implementation: no implementation paragraph + hypothetical sketch.

Why It Matters: 3 sentences.

Detection: bullets.

Related: 2 entries.

References: list.

Let me write carefully and count words roughly to exceed 1200.