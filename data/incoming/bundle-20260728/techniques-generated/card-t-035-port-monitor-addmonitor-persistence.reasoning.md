Let me analyze the inputs carefully.

The cluster spec assigns:
- ID: T-035
- Canonical name: Port Monitor (AddMonitor) Persistence via Print Spooler
- Category: persistence
- Tier: A
- Member notes: 6 LGTM notes
- would_relate_to: ['T-017']

Source files provided:
1. `src/client_rust/src/browser_hook.rs` — browser extension sideloading with multi-layer persistence. This is NOT port monitor persistence. It hit keyword grep probably on "persistence" but it does not implement AddMonitor or print spooler port monitor. Verified: no `AddMonitor` call, no spooler interaction. Does NOT implement the technique.
2. `src/client_rust/src/commands.rs` — command dispatch. Contains "BROWSER_HOOK_PERSIST" etc. Not port monitor. Does NOT implement the technique.
3. `src/dark_crystal/crowd/src/main.rs` — the crowd loader with persist module (FASE 6: COM-Hijack → NTFS-EA → SchedTask → TLS-CB → Resilience-Monitor). No port monitor code. Does NOT implement the technique.

So: no current implementation in the HUGIN source. source_file: none, crate: none.

Now the atlas material grounding:

From atlas-binary-analysis-part5.md, Unit 18: "AddMonitor; Used to install a local port monitor; Has a BOOL return type; typedef struct _MONITOR_INFO_2" — describes the AddMonitor function and _MONITOR_INFO_2 structure.

From atlas-exploit-dev-part22.md, Unit 19/20: "Port Monitor Source Code — source code review" — SEC670 dedicates a module to Port Monitor source code review.

From atlas-exploit-dev-part24.md, Unit 25: "Port Monitor Source Code — Source code review!" — from Book 4 - Persistence Die Another Day, page 73.

From atlas-exploit-dev-part4.md, Unit 31: Detailed AddMonitor API:
```
BOOL AddMonitor(
  _In_ LPTSTR pName,
  _In_ DWORD Level,
  _In_ LPBYTE pMonitors
);
typedef struct _MONITOR_INFO_2 {
  LPTSTR pName;
  LPTSTR pEnvironment;
  LPTSTR pDLLName;
} MONITOR_INFO_2, *PMONITOR_INFO_2;
```
"The AddMonitor API is used when you need to create and install a port monitor on the local machine. The API will fail if your monitor does not match the architecture of the system you are targeting. This means that for a 64-bit system, your envir[onment...]" — environment string must match architecture ("Windows x64" for 64-bit).

From atlas-labs-part1.md, Unit 35: Review question — "What API is called to create a new port monitor? A CreateNewMonitor B AddMonitor C AddNewMonitor" — the correct answer is AddMonitor (per the LGTM note: "Unit 35 explicitly identifies AddMonitor (vs. CreateNewMonitor or AddNewMonitor) as the correct API").

From atlas-post-exploit-part12.md:
- Unit 24: "Objectives — Define and discuss port monitors; what they are and what they are used for. Next, we will look at the APIs involved with the implementation of this method before we move into exploring how useful it might be for our persistence needs." (page 68)
- Unit 25: "Port Monitors — Windows has two type of print monitors: language monitor and port monitor. Port monitors do what they say by monitoring a printer port and bridging the physical connection to the printer queue... a port monitor acts like a bridge of sorts from user-mode to kernel-mode. The user-mode side comes from the spoolsv.exe image and it communicates with a port driver that resides in the kernel. The spoolsv.exe is a Windows service known as the Windows Print S[pooler]" (page 69)
- Unit 26: "Abusing Port Monitors: The Registry — Method one: Registry; Key holds the port monitors in place; Need local admin; Registry Editor" (page ~70)
- Unit 28: "The point of this lab was to introduce you to another persistence technique that can be done programmatically. There was only one API that we needed to learn, and it was not a complicated one at all. We just had to set up a few things inside a structure, and everything was ready to execute." (page 75)
- Unit 29: "Module Summary — Defined and described port monitors; Looked at two ways to implement the method; Discussed the permissions required"

From the LGTM notes:
- Note 4: "AddMonitor with MONITOR_INFO_2 as a persistence mechanism that loads an attacker DLL into spoolsv.exe (SYSTEM context) on every print spooler start... its own detection surface (Sysmon Event 7 on spoolsv.exe loading a non-driver-store DLL) and reboot survival in a SYSTEM process"
- Note 6: "registering a malicious DLL as a port monitor under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors to gain spoolsv.exe-hosted execution at service startup... historical weight (PrintNightmare lineage)"
- Note 3: "Given Stuxnet used this exact mechanism and the spooler runs at SYSTEM with auto-restart semantics, it warrants standalone coverage with detection surface and cleanup tradeoffs."

Detection considerations from material:
- Sysmon Event 7 (Image Loaded) on spoolsv.exe loading a non-driver-store DLL (from Note 4)
- Registry key HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors (from Note 6)
- Two implementation methods: registry (manual) and AddMonitor API (programmatic) (from atlas units 26, 28, 29)
- Requires local admin (Unit 26)

MITRE mapping: The best-fit ATT&CK technique for port monitor persistence is T1547.010 — Boot or Logon Autostart Execution: Port Monitors. Let me verify: Yes, MITRE ATT&CK T1547.010 is "Port Monitors" under Boot or Logon Autostart Execution. This is well-established. The technique involves AddMonitor API and is documented in ATT&CK as used by Stuxnet (which the material also mentions). I'm confident about T1547.010.

Secondary MITRE: could include T1112 (Modify Registry) for the registry-based installation method. That's reasonable given the material explicitly documents the registry method (reg add under HKLM\...\Print\Monitors). I could include that.

Now, the mechanism details. Let me reconstruct from Windows knowledge + material:

1. Attacker obtains local admin privileges (material: "Need local admin").
2. Two installation methods documented in SEC670 Book 4:
   - Method one: Registry — manually create key under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName> with a "Driver" value pointing to the malicious DLL.
   - Method two: Programmatic — call AddMonitor(NULL, 2, (LPBYTE)&monitorInfo2) with MONITOR_INFO_2 filled: pName (monitor name), pEnvironment ("Windows x64" on 64-bit — must match system architecture or the call fails), pDLLName (path to the DLL).
3. The DLL is copied to a location accessible to the spooler (typically System32).
4. On spooler service start (or restart), spoolsv.exe enumerates registered port monitors from the registry key and loads each monitor's DLL with LoadLibrary.
5. The DLL executes in spoolsv.exe context as NT AUTHORITY\SYSTEM.
6. Persistence survives reboot because the spooler service starts at boot (auto-start) and re-enumerates monitors every start.

Port monitor DLL contract: A port monitor DLL exports specific functions. From Windows docs, port monitors must export functions like InitializePrintMonitor2 (for port monitors) — actually, the language monitor vs port monitor distinction: language monitors export InitializePrintMonitor, port monitors export InitializePrintMonitor2. The material (Unit 25) mentions the two types: language monitor and port monitor. The SEC670 Port Monitor source code review (units 19-20 in part22, unit 25 in part24) covers implementing the DLL. I should mention that the DLL must export the monitor entry point (InitializePrintMonitor2 for port monitors per Microsoft documentation; DllMain also runs at load time so payload can simply live in DllMain). I need to be careful not to fabricate — InitializePrintMonitor2 is well-established MSDN documentation for port monitor DLLs. Material says "we just had to set up a few things inside a structure, and everything was ready to execute" — describing the installer side.

Environment string: "Windows x64" for 64-bit, "Windows NT x86" for 32-bit. The material says "The API will fail if your monitor does not match the architecture of the system you are targeting. This means that for a 64-bit system, your envir[onment must match]". Well-established: the pEnvironment field is "Windows x64" or "Windows NT x86". I can state this.

Registry structure: HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>\Driver = "<dll name>". Well-established from MSDN and the LGTM note 6 names the key HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors.

Also environments: HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors — not needed here.

Detection:
- Sysmon Event ID 7 (ImageLoaded) — spoolsv.exe loading a DLL outside the driver store / non-standard location (from Note 4: "Sysmon Event 7 on spoolsv.exe loading a non-driver-store DLL").
- Registry monitoring: writes to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors (Sysmon Event 12/13 — registry object add/delete and value set). Careful: Event 12 is RegistryEvent (object create/delete), Event 13 is RegistryEvent (value set). These are well-established Sysmon IDs. The material doesn't explicitly cite 12/13 but rule 4 says do not invent Sysmon event IDs. Event 7 is explicitly cited in Note 4. For registry, I can name the key path as residual artifact without inventing an event ID — or mention Sysmon registry events generically? Better to say "registry value creation under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors (observable via registry auditing / Sysmon registry events)" — hmm, safest: name the artifact, and only cite Event 7 explicitly as the material does. Actually Sysmon Event 12/13 are extremely well-established (12 = create/delete key, 13 = value set). Rule 4 allows "well-established Windows internals documentation." Sysmon event IDs 12 and 13 are documented by Microsoft Sysinternals. But to be cautious, I'll say the material only names Event 7 and I'll present the registry key as a residual artifact. I could mention ETW Microsoft-Windows-Kernel-Registry? Not documented in material. Keep it simple: Event 7 from material, registry key + DLL on disk as residual artifacts, service restart (Event 7036 from Service Control Manager?) — that's a Windows event log ID, well established (7036 service state change). Hmm, rule says don't invent Sysmon event IDs specifically; Windows event IDs are also telemetry. I'll be conservative and only cite what the material cites plus generic telemetry source categories. Actually, I can frame: "Sysmon Event 7 (Image Loaded) is the primary telemetry source named in the training material" and then describe the artifacts. For bypass options — material does not discuss bypasses for this technique. Per the system prompt: "If the material does not cover detection for this technique, write: 'Training material does not discuss detection for this technique.'" But the material DOES cover detection partially (Note 4 names Sysmon Event 7). So I document what's there and state bypass options are not discussed in the material.

Cleanup tradeoffs: Note 3 mentions "detection surface and cleanup tradeoffs". Removal requires deleting the registry key + restarting the spooler or reboot; DeleteMonitor API exists. I can mention DeleteMonitor as the documented removal API — is that in the material? Not explicitly. MSDN documents DeleteMonitor as the counterpart. It's safe as well-established. But keep restraint — the card documents the technique. A brief mention in residual artifacts is fine.

OS Internals Context:
- spoolsv.exe is the Print Spooler service, runs as NT AUTHORITY\SYSTEM under svchost? No — spoolsv.exe is its own standalone service process (not svchost-hosted). It runs as SYSTEM, auto-start. From material unit 25: "The spoolsv.exe is a Windows service known as the Windows Print Spooler". 
- Port monitor DLL is loaded by spoolsv.exe via LoadLibrary at service start; spooler reads monitors from the registry key.
- Two monitor types: language monitor and port monitor (material unit 25).
- The monitor DLL bridges user-mode spooler to kernel-mode port driver (material unit 25).
- Architecture constraint: environment string must match (material unit 31 part4).
- Loading occurs inside spoolsv.exe as SYSTEM; DllMain executed on load; the spooler holds the DLL loaded for service lifetime.
- The spooler auto-restarts on failure (SERVICE_FAILURE_ACTIONS appears in the material nearby, but that's about services generally; Note 3 says "the spooler runs at SYSTEM with auto-restart semantics"). I can say the service is configured for automatic startup and failure recovery by default. Careful: default failure actions for Print Spooler — restart on first/second failure is default. Note 3 says "auto-restart semantics" — material-based claim, OK.

Why It Matters:
- Distinct from all 5 layers of T-017 (COM hijack HKCU, NTFS EA, schtask COM, TLS callback, PhantomPersist shutdown intercept): different trigger (service startup of spoolsv.exe), different context (SYSTEM), different install primitive (AddMonitor/registry), different detection surface (Sysmon Event 7).
- Historical weight: Stuxnet used port monitors (Note 3), PrintNightmare lineage (Note 6).
- Requires admin; grants SYSTEM.

Related Techniques:
- T-017 Five-Layer Persistence — complementary persistence suite; port monitor is a distinct sixth-style layer not covered there; differs in trigger, privilege context, and detection surface.

That's the only justified relation from the would_relate_to list. Should I add T-023 (client capabilities)? No, not justified. Keep restraint: just T-017.

Tier: A (proposed). Category: persistence. Crate: none. source_file: none.

Tags: 5-10 kebab-case: persistence, port-monitor, print-spooler, addmonitor, spoolsv, system-context, registry-persistence, dll-load, monitor-info-2. That's 9. Good.

mitre: T1547.010. mitre_secondary: T1112 (Modify Registry) — justified by the registry installation method. 

Name in frontmatter: "Port Monitor Persistence via Print Spooler" — 4-8 words. The h1: "Port Monitor (AddMonitor) Persistence — Print Spooler DLL Load into spoolsv.exe at Service Start" — keep it reasonable.

member_notes list exact:
['lgtm:port-monitor-print-spooler-persistence', 'lgtm:proposed-port-monitor-persistence', 'lgtm:proposed-port-monitor-persistence-card', 'lgtm:port-monitor-addmonitor-persistence', 'lgtm:port-monitor-persistence', 'lgtm:port-monitor-persistence-card']

References:
- Atlas material: atlas-binary-analysis-part5.md, atlas-exploit-dev-part22.md, atlas-exploit-dev-part24.md, atlas-exploit-dev-part4.md, atlas-labs-part1.md, atlas-post-exploit-part12.md
- MITRE ATT&CK: T1547.010 https://attack.mitre.org/techniques/T1547/010/
- LGTM notes: the 6 IDs
- Public references: SEC670 Book 4 "Persistence: Die Another Day" (the source material itself); Stuxnet usage is named in the notes. I can mention "Stuxnet (named in atlas notes as historical user of this mechanism)". Also Joshua Wright's SDDL? No that's for service hiding, different technique — do not include. Keep: SANS SEC670 Book 4 pages 68-77 (the material itself). No invented blog posts.

Mechanism section — numbered steps:

1. Gain local administrator privileges (required — HKLM write + spooler registry; material: "Need local admin").
2. Build the monitor DLL for the target architecture (x64 DLL for 64-bit; the environment string must match or AddMonitor fails).
3. Copy DLL to a spooler-accessible path (System32 convention).
4. Install via one of two documented methods:
   a. Registry: create HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name> with Driver value = DLL name.
   b. AddMonitor API: fill MONITOR_INFO_2 {pName, pEnvironment="Windows x64", pDLLName} and call AddMonitor(NULL, 2, &mi2) — returns BOOL.
5. Restart spooler or wait for reboot; spoolsv.exe at startup enumerates Monitors key and LoadLibrary's each Driver DLL.
6. DLL executes in spoolsv.exe as SYSTEM — DllMain runs at load; monitor init export called by spooler.
7. Persistence: every spooler start (boot, service restart, crash recovery) reloads the DLL.

OS Internals:
- Two monitor types: language and port; port monitor bridges user-mode spooler to kernel port driver (material).
- spoolsv.exe = Print Spooler service, SYSTEM, auto start.
- Registry-backed enumeration: spooler reads HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors at service init; each subkey's Driver value is loaded.
- MONITOR_INFO_2 contract: pName (monitor name = registry subkey), pEnvironment (must match "Windows x64"/"Windows NT x86"; mismatch → AddMonitor fails), pDLLName (driver DLL).
- Level parameter = 2 (structure version).
- Load context: LoadLibrary into spoolsv.exe → standard loader, DllMain DLL_PROCESS_ATTACH; DLL stays mapped for service lifetime; runs before/without user logon (service at boot).
- No user-session dependency: fires in session 0, pre-logon — unlike HKCU COM hijack (T-017 Layer 1) which needs user logon.
- Note on the port monitor DLL interface: monitor DLLs implement a defined export set; material points to the SEC670 "Port Monitor Source Code" module for the reference implementation; minimal persistence payloads can execute from DllMain.

Key Implementation Details:
- No current implementation. Then describe what an implementation would look like: a Rust installer calling AddMonitorW via winspool.drv (windows crate Win32 Printing feature), MONITOR_INFO_2W struct, DLL copy to System32, optional direct registry write via NtSetValueKey through RecycledGate for consistency with the vault's syscall approach, plus the monitor DLL itself (cdylib) exporting the monitor entry. One paragraph. Careful: the system prompt says "Then briefly describe what an implementation would look like (data structures, syscalls, roughly one paragraph)." OK. winspool.drv exports AddMonitor — well-established (AddMonitor is in winspool.drv/spoolss). Fine.

The provided .rs files: I verified browser_hook.rs implements browser extension persistence (shortcuts, Run key, schtask, protocol handler) — not port monitor. commands.rs — command dispatch, includes BROWSER_HOOK_PERSIST etc. main.rs (crowd) — FASE 6 persistence: COM-Hijack → NTFS-EA → SchedTask → TLS-CB → Resilience-Monitor (per T-017). None call AddMonitor or touch Print\Monitors. State that explicitly and concisely.

Word count target: 1200-1800 body words. Let me draft.

Also formatting: no banned words. Check: avoid "elegant", "notable", etc. Avoid "essentially", "at its core". Avoid first person.

Frontmatter format: name "Port Monitor Persistence via Print Spooler" (6 words). H1: "# Port Monitor (AddMonitor) Persistence via Print Spooler — SYSTEM-Context DLL Load at Spooler Start".

Summary first sentence standalone: "Port Monitor persistence registers an attacker-controlled DLL as a print port monitor so that the Print Spooler service (spoolsv.exe) loads it with NT AUTHORITY\SYSTEM privileges every time the service starts."

Detection Considerations:
- Telemetry: Sysmon Event ID 7 (Image Loaded) — material names this explicitly: spoolsv.exe loading a DLL outside the driver store. Process/service telemetry around spooler restarts. Registry monitoring of HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors.
- Bypass: material does not discuss bypass options for this technique → say so.
- Residual artifacts: registry subkey + Driver value; DLL on disk (System32); loaded module inside spoolsv.exe address space; requires service restart or reboot to activate (timing artifact). Removal via deleting key + DeleteMonitor counterpart... DeleteMonitor is documented MSDN; mention as removal API.

Length check: aim ~1400-1600 words body.

Write it now.

Structure check per template:
1. Frontmatter ✓
2. H1 ✓
3. Summary
4. Mechanism
5. OS Internals Context
6. Key Implementation Details
7. Why It Matters
8. Detection Considerations
9. Related Techniques
10. References
11. Source Reference

Tags list: [persistence, port-monitor, print-spooler, addmonitor, spoolsv, system-context, registry, dll-sideload, monitor-info-2] — 9 tags. "dll-sideload"? It's a LoadLibrary load, not exactly sideloading. Use "dll-load". Let me pick: [persistence, port-monitor, print-spooler, spoolsv, addmonitor, monitor-info-2, system-context, registry-persistence, service-start-trigger] — 9 tags, kebab-case. Good.

mitre_secondary: [T1112] — Modify Registry for the registry install method. Reasonable.

Word the mechanism steps concretely:

1. Attacker obtains local administrator (or SYSTEM) privileges on the target — required to write under HKLM and to register a monitor (SEC670: "Need local admin").
2. Attacker compiles the monitor DLL matching the target architecture; on a 64-bit system the environment string must be "Windows x64", otherwise AddMonitor fails (SEC670 AddMonitor unit).
3. The DLL is placed on disk in a path the spooler can read — conventionally a System32 path given in pDLLName.
4a. Method one (registry): create subkey HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName> and set the Driver value to the DLL file name — documented in SEC670 as the manual method.
4b. Method two (programmatic): populate MONITOR_INFO_2 {pName = monitor name, pEnvironment = "Windows x64", pDLLName = DLL path} and call AddMonitor(NULL, 2, (LPBYTE)&mi2). The API writes the same registry state and returns BOOL. SEC670 explicitly distinguishes AddMonitor from the non-existent CreateNewMonitor/AddNewMonitor decoys in its review questions.
5. The monitor is dormant until the spooler (re)initializes: reboot, `net stop/start spooler`, or service crash recovery.
6. At service startup, spoolsv.exe enumerates the Monitors key and loads each Driver DLL with the standard image loader; DllMain(DLL_PROCESS_ATTACH) and the monitor's initialization export execute inside spoolsv.exe.
7. Code now runs as NT AUTHORITY\SYSTEM in session 0, before any user logon, and re-executes on every subsequent spooler start until the key is removed.

OS internals:

- Print Spooler architecture: two monitor types (language, port). Port monitor = user-mode component hosted by spoolsv.exe bridging to kernel port driver (material).
- spoolsv.exe: standalone service process (Print Spooler), LocalSystem, automatic start; recovery options restart the service after failure — the material's notes describe auto-restart semantics.
- Registry-backed enumeration: Monitors key persists across reboots in the SYSTEM hive; spooler reads it during initialization.
- MONITOR_INFO_2 contract + Level=2 version selector; pEnvironment values "Windows x64" / "Windows NT x86"; architecture enforcement.
- Loader behavior: DLL mapped as MEM_IMAGE, stays resident for service lifetime; standard LoadLibrary telemetry applies (hence Sysmon 7).
- Session 0 / pre-logon execution: unlike HKCU hijacks, no user session needed.
- Comparison with service-based persistence: no new service in SCM database, no service binary path — the module appears only as a DLL load inside a legitimate, expected Microsoft process.

Why it matters:
- Own card vs footnote on T-017: distinct trigger (spooler service start), distinct install primitive (AddMonitor/MONITOR_INFO_2), distinct context (SYSTEM, session 0), distinct detection (Sysmon 7 on spoolsv.exe). T-017's five layers all use userland or boot-time triggers (COM hijack HKCU, NTFS EA, schtask, TLS callback, shutdown intercept). None of them ride a service-hosted monitor DLL.
- Historical: Stuxnet used this mechanism; PrintNightmare lineage keeps defender attention on the spooler — which is itself an operational consideration.
- Requires admin; trades stealthier user-context persistence for SYSTEM permanence.

References:
- Atlas: atlas-binary-analysis-part5.md (unit 18), atlas-exploit-dev-part22.md (units 19-20), atlas-exploit-dev-part24.md (unit 25), atlas-exploit-dev-part4.md (unit 31), atlas-labs-part1.md (unit 35), atlas-post-exploit-part12.md (units 24-29)
- MITRE: T1547.010 URL
- LGTM: six IDs
- Public: SANS SEC670 Book 4 "Persistence: Die Another Day" (port monitor module, pp. 68-77); Stuxnet's use of port monitors (as named in the atlas notes).

Source Reference: No current implementation. The three Rust files provided (client_rust/src/browser_hook.rs, client_rust/src/commands.rs, dark_crystal/crowd/src/main.rs) were keyword-grep matches on persistence terms; verified none implement AddMonitor or Print\Monitors registration. See atlas material and MITRE for public tooling.

Let me now write final output, watching word count. I'll count roughly. Aim ~1500 body words.

One more check on banned words while writing: avoid "notable", "elegant", "clever", "textbook", "robust", "simply" is allowed? "simply" is not banned but keep minimal. Avoid "essentially". Avoid "worth noting". Avoid "interestingly". Avoid "the key insight".

Also rule: no rhetorical questions, no first person, declarative.

For the h1 one-line purpose: "Port Monitor (AddMonitor) Persistence — SYSTEM-Context DLL Execution via Print Spooler Service Startup".

Write it.