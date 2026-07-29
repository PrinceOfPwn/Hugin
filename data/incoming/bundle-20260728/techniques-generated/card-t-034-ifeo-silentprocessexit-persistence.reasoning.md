Let me analyze the inputs carefully.

The task: produce a technique card for T-034 — IFEO GlobalFlag and SilentProcessExit Registry Persistence.

Key facts from the material:

1. **IFEO (Image File Execution Options)** — a Windows Registry key that enables debugging/tracing of a process when started. Located at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>`. Two variants documented:
   - **Debugger value** (process start variant): redirects target executable launch to an attacker-specified Debugger binary. Triggered on process creation/launch.
   - **GlobalFlag + SilentProcessExit** (process exit variant): 
     - `reg add HKLM\...\Image File Execution Options\ProcessName /v GlobalFlag /t REG_DWORD /d 512`
     - `reg add HKLM\...\SilentProcessExit\ProcessName /v ReportingMode /t REG_DWORD /d 1`
     - `reg add HKLM\...\SilentProcessExit\ProcessName /v MonitorProcess /d "C:\Path\To\implant.exe"`

2. **GlobalFlag value 512** — 512 = 0x200 = FLG_MONITOR_SILENT_PROCESS_EXIT. This is a well-documented value in Windows internals. The material explicitly gives the `GlobalFlag=512 → ReportingMode=1 → MonitorProcess=<path>` registry sequence.

3. **SilentProcessExit key** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<ProcessName>` with:
   - `ReportingMode` (REG_DWORD) = 1
   - `MonitorProcess` (REG_SZ) = path to monitor binary

4. **Permissions**: Admin or SYSTEM required — basic users cannot modify HKLM keys. From atlas-post-exploit-part12 unit 38: "if we only have permissions as a basic user, then we will be denied access when trying to modify the HKLM Registry keys needed for the IFEO persistence method."

5. **Target selection**: userinit.exe recommended for boot-early execution — "We should choose one that kicks off when the system is starting up. A good possibility that fits into that role would be userinit.exe" (atlas-post-exploit-part7 unit 18/20).

6. **Gflags.exe** — bundled with Windows SDK, located at `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`. MSDN describes it as enabling advanced debugging. GflagsX by Pavel Yosifovich (github.com/zodiacon) is a modern take.

7. **Manual implementation via reg.exe** — from atlas-post-exploit-part12 unit 35 and atlas-post-exploit-part7 unit 16:
   ```
   reg add HKLM\...\Image File Execution Options\ProcessName /v GlobalFlag /t REG_DWORD /d 512
   reg add HKLM\...\SilentProcessExit\ProcessName /v ReportingMode /t REG_DWORD /d 1
   reg add HKLM\...\SilentProcessExit\ProcessName /v MonitorProcess /d "C:\Path\To\implant.exe"
   ```
   Can also be done via APIs: RegOpenKeyExA, RegCreateKeyExA, RegSetValueEx.

8. **Programmatic implementation** — Win32 Registry API implementation mentioned in note 4: "Win32 Registry API implementation, target process selection rationale (userinit.exe for boot-early execution), and Admin/SYSTEM permission requirements."

9. **Concept of Image vs Monitor**: "Image: Process to 'watch'; Monitor: The 'watching' process" (atlas-post-exploit-part7 unit 14).

10. **Survives reboot** — registry-resident. Event-driven — triggers on victim process launch/exit events rather than time or boot (note 6).

11. **Detection**: The material mentions Sysmon generically in the context of WMI attacks, but not specifically for IFEO. The material discusses "Observed limiting factors such as permissions for IFEO" — permissions are the main limiting factor discussed. The material does NOT discuss specific IFEO detection (ETW providers, Sysmon event IDs). Rule: "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections."

    However, the Detection Considerations section template says to describe telemetry sources, bypass options, residual artifacts "the training material describes for this technique". The material describes:
    - Permissions as a limiting factor (not detection per se)
    - Registry keys left behind (residual artifacts — these are documented in the material: the IFEO key, SilentProcessExit key, and the implant binary on disk)
    - The material mentions Sysmon detecting WMI attacks but that's a different technique — not IFEO. I should not import it.
    
    So for Detection Considerations: I can state what the material covers (registry artifacts are the residual; permissions limit deployment), and explicitly note that the training material does not discuss detection telemetry for this technique. The residual artifacts (registry keys, payload binary path) ARE derivable from the mechanism description in the material — that's fair game since it's describing what the technique leaves behind, which the material itself documents (the material shows the exact reg add commands). Actually, careful: the rule says "Detection surface the training material describes for this technique". The material doesn't discuss detection. But residual artifacts — the registry keys created — are inherent to the mechanism and the material lists them as the setup steps. I think it's fair to note residual artifacts as the registry keys themselves since that's factual from the mechanism, but I should be careful about inventing "memory-scan heuristics" or ETW providers. I'll structure it as: training material does not discuss detection telemetry; it does note permission constraints; residual artifacts are the documented registry keys and on-disk payload. Let me write that carefully.

    Actually re-reading the template:
    - **Telemetry sources**: which ETW providers, Sysmon event IDs, kernel callbacks, or memory-scan heuristics observe this
    - **Bypass options**: what the material says operators do to reduce observability
    - **Residual artifacts**: files, registry keys, handles, network signatures the technique leaves behind
    "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.` Do not invent detections."

    The cleanest compliant approach: state "Training material does not discuss detection for this technique." then note residual artifacts that are inherent (registry keys listed in the material's own setup commands, payload binary). The registry keys ARE in the material — they're the setup mechanism. Calling them "residual artifacts" is a factual reframing, not invention. I'll do that with care. The material also mentions cleanup — "importance of cleaning up artifacts by reversing registry modifications during a post-exploitation phase" (atlas-post-exploit-part12 unit 38) and "suggests building an uninstall command into the implant to revert registry modifications" (atlas-post-exploit-part7 unit 21). Those are operator-side cleanup actions — that's "what the material says operators do" — so I can include those.

12. **Labs**: Lab 4.2 Sauron, Lab 4.3 IFEOPersisto. Wait — careful! atlas-post-exploit-part15 units 3-5 say Lab 4.2 Sauron is "Implement a port monitor for persistence". But the LGTM notes and cluster spec say "Lab 4.2 (Sauron IFEO)". Looking at the course roadmap tables of contents: "Lab 4.1: PersistentService, Port Monitors, Lab 4.2: Sauron, IFEO, Lab 4.3: IFEOPersisto". Hmm, the TOC listing in atlas-methodology-part4 unit 9: "67 Port Monitors 74 Lab 4.2: Sauron 79 IFEO 90 Lab 4.3: IFEOPersisto". So Sauron appears right after Port Monitors in the TOC at page 74, and IFEO section starts at 79, IFEOPersisto at 90. atlas-post-exploit-part15 unit 3 explicitly: "Lab 4.2: Sauron Implement a port monitor for persistence". So Sauron is actually the port monitor lab, and IFEOPersisto is the IFEO lab. The LGTM notes claim Lab 4.2 is "Sauron IFEO" but the atlas material itself (part15 units 3-5, page 74) says Sauron = port monitor lab. 

    Rule 4: "If the material contradicts what your general knowledge says, the material wins for descriptive claims." The atlas material is the authority. So I should describe Lab 4.3 (IFEOPersisto) as the IFEO lab, and note Lab 4.2 Sauron is the port monitor lab — or just avoid misattributing. The safest: reference Lab 4.3 (IFEOPersisto) for IFEO persistence, per the atlas TOC ("79 IFEO / 90 Lab 4.3: IFEOPersisto") and part15 units 9-11. I won't claim Sauron is an IFEO lab since atlas directly contradicts that. I can just mention IFEOPersisto.

13. **IFEO Debugger variant details**: The notes mention "accessibility binary hijacks (sethc, utilman), security tool redirects" (note 2). The atlas material excerpt for the IFEO definition: "IFEO is a Windows Registry key that enables the debugging or tracing of a process when it is started... The options can be any number of actions, like having a debugger launch when the process does" (atlas-post-exploit-part7 unit 13). The material notes IFEO "is primarily effective for EXE files rather than DLLs" (unit 13). 

    The Debugger value: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>\Debugger` = path to debugger binary. When the target image launches, Windows instead launches the Debugger value's binary with the original command line appended. This is well-established Windows behavior (documented in MSDN IFEO documentation / Windows Internals). The atlas material describes the mechanism at a high level; the specific registry path HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options is given in the cluster spec consolidated description. The cluster spec is a directive derived from the notes, so the path is sanctioned.

14. **GlobalFlag = 512 = 0x200**: In Windows internals, GlobalFlag is a REG_DWORD under the IFEO key whose bits correspond to FLG_* kernel flags. 0x200 is FLG_MONITOR_SILENT_PROCESS_EXIT. Is that documented in well-established Windows internals? Yes — the FLG_MONITOR_SILENT_PROCESS_EXIT flag value 0x00000200 is documented in public references (e.g., the "Silent Process Exit" mechanism documented by Microsoft in the context of WerFault/reporting, and Geoff Chappell's / various public documentation). ntdll's RtlFlsAlloc... no. The global flags are documented in "Windows Internals" and in the debugger documentation for gflags. However, the specific bit name FLG_MONITOR_SILENT_PROCESS_EXIT — I'm fairly confident this is correct; it's used in public PoCs for SilentProcessExit persistence (e.g., the 2018 research by "SilentProcessExit" — actually the technique was publicized around 2018-2019). The rule says don't fabricate flag combinations I'm unsure about. I am confident 0x200 = FLG_MONITOR_SILENT_PROCESS_EXIT; this is well-established (documented in ntdef.h-ish public sources and used consistently in public SilentProcessExit persistence writeups). But to be safe, I can present 512 (0x200) as the value the material specifies, and mention it corresponds to the silent-process-exit monitor flag as documented publicly. I'll phrase carefully: "512 (0x200), the flag bit documented publicly as FLG_MONITOR_SILENT_PROCESS_EXIT" — hmm, is that name real? Let me think. Public documentation: the gflags tool lists "Monitor silent process exit" as a checkbox for image files. The symbolic name... In the ReactOS / wine headers there's FLG_MONITOR_SILENT_PROCESS_EXIT 0x00000200. Yes, I'm confident. It's in ntregapi / ntexapi public headers lists of FLG bits. Geoff Chappell's documentation of GlobalFlag bits includes FLG_MONITOR_SILENT_PROCESS_EXIT as 0x00000200 (Vista+). OK, I'll include it but keep it brief.

15. **How SilentProcessExit works internally**: When a process whose IFEO GlobalFlag has the monitor bit set terminates, the kernel (PspExitProcess / PspProcessDelete path) checks the SilentProcessExit registry key for the image name. If ReportingMode is set, it launches the MonitorProcess (via WER/wermgr? or directly?). Public research (e.g., "Silent Process Exit" persistence writeups) describes: on process exit, if GlobalFlag & 0x200, the system reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<image> and if ReportingMode=1 (or dump flags), it launches MonitorProcess with arguments (process name, PID, exit code?). Actually the public description: the monitor process is launched by svchost/wer? Let me recall the documented internals: 

    From public research (e.g., the "Persistence – Silent Process Exit" blog posts): When a process with the flag exits, PspExitThread/PspExitProcess checks NtGlobalFlag or the per-process flags... Actually the mechanism: the GlobalFlag IFEO value is copied into the process's EPROCESS/PEB at creation (NtGlobalFlag in PEB gets the image-file global flags OR'd in). On process termination, the kernel checks whether the silent process exit monitoring flag is set; if so it queries the SilentProcessExit registry key and if ReportingMode is 1 (LaunchMonitorProcess? values: 0 = no monitoring? Actually ReportingMode values: 1 = launch monitor process; 2 = ?; 4 = dump?), it launches the MonitorProcess command line via ... The kernel queues a work item that launches through WER service (WerSvc) — the reporting is handled by Windows Error Reporting. Hmm.

    Precisely: The documented flow (from public sources, e.g., oddvarmoe/atc-c4 writeups and Microsoft's "Monitor silent process exit" docs): 
    - GlobalFlag 0x200 under IFEO\<image>
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<image> with ReportingMode (DWORD), MonitorProcess (string), also DumpFolder, DumpType, LocalDumpFolder for dumps.
    - ReportingMode values: 1 = launch monitor process; 2 = ? Actually I recall: ReportingMode is a bitmask: 1 = MiniDump? no...
    
    Let me be careful. The material only specifies ReportingMode=1 and MonitorProcess=<path>. The material does NOT document the other values or the internal kernel flow. Rule 4 says every claim must trace to material, related cards, source, or well-established Windows internals docs. I should keep the internals claims to what I'm confident about:
    - IFEO GlobalFlag values are read at process creation and merged into the process's PEB NtGlobalFlag field (this is established Windows behavior — the image-file global flags are OR'd into NtGlobalFlag at process creation; documented in Windows Internals).
    - On process termination, the kernel's process-exit path checks for the silent-process-exit monitoring flag and consults the SilentProcessExit key; the Windows Error Reporting service launches the configured MonitorProcess. The monitor process is typically launched as SYSTEM (public writeups say the monitor process is spawned by the WER service, which runs as SYSTEM... actually WerSvc runs in a svchost as LocalSystem? Windows Error Reporting service runs as LocalSystem in a shared svchost. Public PoCs note the MonitorProcess executes with SYSTEM privileges. Hmm, but is that solidly documented? The ATC-c4 / "SilentProcessExit persistence" public writeups note the monitor command executes in the context of the WER service. I believe the monitor process is spawned by the kernel via WER fault reporting path. I need to be careful not to fabricate.

    Given the rule "Do not fabricate API calls or flag combinations you are unsure about", I'll describe the kernel-side flow at the level the material supports plus conservatively-established internals:
    - IFEO key is consulted by the process manager at image load (this is how Debugger works — the create-process path reads IFEO before mapping; well documented).
    - The GlobalFlag DWORD under the image's IFEO subkey is merged into the process's global flags at creation (PEB.NtGlobalFlag), which is documented behavior (this is exactly how gflags per-image settings take effect).
    - At process termination, the exit path checks the silent-process-exit flag and reads the SilentProcessExit\<image> key; ReportingMode=1 with MonitorProcess set causes the configured command to be launched. The material documents Image/Monitor roles ("Image: Process to watch; Monitor: The watching process").
    
    I'll avoid claiming which component spawns it (kernel work item vs WER service) beyond a cautious statement, or I can say "handled through the Windows Error Reporting infrastructure" — hmm. Is that safe? Microsoft's own documentation "Monitoring Silent Process Exit" (MSDN, "Monitoring Silent Process Exit" page) documents the SilentProcessExit key with values ReportingMode, MonitorProcess, DumpFolder, DumpType, LocalDumpFolder, MonitorCommandLine — and states the monitor is launched "by the Windows Error Reporting service" I believe. Actually the MSDN page "Monitoring Silent Process Exit" says: "Beginning with Windows 7, you can use the Silent Process Exit tab... to enable monitoring... The monitor process is launched when the monitored process exits silently." It documents ReportingMode values: 1 = launch monitor process. And it's in the context of WER. I'm fairly confident the launch is performed by the WER service (WerSvc). Public offensive writeups (e.g., by "Alh4zr3d"/others? and the ATT&CK T1546 page notes) say "the monitor process is spawned under svchost.exe (WerSvc) as SYSTEM". Hmm — ATT&CK T1546 mentions... I don't remember precisely. To stay safe: I'll say termination handling is performed through Windows Error Reporting infrastructure, and note the material itself does not detail which component spawns the monitor. Actually, better approach per rules: keep the OS Internals section focused on (a) IFEO read at process creation by the process manager/loader, (b) GlobalFlag merge into PEB.NtGlobalFlag, (c) exit-path check + SilentProcessExit key consultation, (d) note the Debugger value semantics (debugger launched in place of the image with original command line appended — this is well-documented IFEO Debugger behavior). For (d): when a Debugger value exists, CreateProcess launches the debugger binary and appends the original image path and command line as arguments. This is textbook IFEO behavior (Windows Internals 7ed covers IFEO Debugger). I'm confident in that.

16. **Implementation in HUGIN source**: Check the provided .rs files:
    - `browser_hook.rs` — browser extension persistence (shortcut patching, Run key, schtask, protocol handler). NOT IFEO. Does not implement T-034.
    - `edo_tensei.rs` — polymorphic resurrection; has registry soul storage (RegCreateKeyExW/RegSetValueExW on HKCU CLSID Config key). Uses registry but NOT IFEO/SilentProcessExit. Does not implement T-034.
    - `kaguya.rs` — LOtL inventory. NOT IFEO.
    None implement IFEO or SilentProcessExit. So: `crate: none`, `source_file: none`, state no current implementation.

    Wait — check the file manifest for anything IFEO-related: `persist/*` has com_hijack, ntfs_ea, schtask, tls_cb, phantom_restart. No IFEO module. Confirmed no implementation.

17. **Frontmatter fields**:
    - id: T-034
    - name: "IFEO GlobalFlag and SilentProcessExit Registry Persistence" — the canonical name is long; frontmatter name should be the human readable name 4-8 words. "IFEO GlobalFlag and SilentProcessExit Registry Persistence" = 7 words (IFEO(1) GlobalFlag(2) and(3) SilentProcessExit(4) Registry(5) Persistence(6)) = 6 words. Fine.
    - category: persistence
    - tier: A
    - crate: none
    - source_file: none
    - mitre: T1546.012 (Event Triggered Execution: Image File Execution Options Injection). That's the precise ATT&CK sub-technique for IFEO Debugger abuse AND it covers SilentProcessExit? ATT&CK T1546.012 "Image File Execution Options Injection" — description mentions IFEO Debugger and also GlobalFlag/SilentProcessExit. Yes, T1546.012 covers both: "Adversaries may establish persistence... through IFEO... IFEOs can also be used ... GlobalFlag... SilentProcessExit". I'm confident T1546.012 is the best fit. 
    - mitre_secondary: T1547? Hmm. IFEO Debugger for sethc.exe accessibility is sometimes mapped to T1546.008 (Accessibility Features) — but the material doesn't focus on accessibility hijacks; note 2 mentions them as reuse examples. I could add T1546.008? The notes mention sethc/utilman as reuse targets, but the card is about IFEO registry persistence generally. Also, IFEO-based injection for defense evasion maps to T1055? No — keep it simple: mitre T1546.012, and maybe secondary T1057? no. Secondary: T1546.012 covers it; maybe also T1112 (Modify Registry) as the modification primitive. T1112 Modify Registry is a reasonable secondary since the whole mechanism is registry modification. I'll include mitre_secondary: [T1112]. That's defensible. Hmm, rule says pick ones I'm confident about. T1112 is real and applies. OK.
    - tags: 5-10 kebab-case: [persistence, ifeo, silent-process-exit, globalflag, registry, debugger-hijack, event-driven, gflags, hklm] — that's 9. Good.
    - origin: atlas-synthesis
    - member_notes: the 8 exact IDs.

18. **Sections**:

    **Summary** (3-5 sentences): IFEO registry persistence with two trigger variants: Debugger value redirects target image launch to attacker binary (process-start trigger); GlobalFlag=512 + SilentProcessExit ReportingMode=1/MonitorProcess executes a monitor command when the watched process exits (process-exit trigger). Registry-resident under HKLM, requires Admin/SYSTEM, survives reboot, event-driven (no scheduler). Detection surface: the material doesn't discuss; primary constraint is permissions; residual artifacts are the registry keys and payload binary.

    **Mechanism** (numbered steps): cover both variants concretely with the reg add commands from the material, the API path (RegOpenKeyExA/RegCreateKeyExA/RegSetValueEx), gflags.exe GUI alternative (SDK path), target selection (userinit.exe), trigger behavior for each variant, and cleanup (uninstall reversal of registry modifications per material).

    **OS Internals Context**: 
    - IFEO subtree read during process creation by the process manager/loader path; Debugger value semantics (launch debugger binary, append original command line).
    - GlobalFlag DWORD merged into PEB.NtGlobalFlag at process creation (this is how gflags image settings take effect) — 512 (0x200) is the silent-process-exit monitor bit (FLG_MONITOR_SILENT_PROCESS_EXIT).
    - On termination, exit path checks the flag, consults SilentProcessExit\<image>; ReportingMode=1 → launch MonitorProcess. The material frames Image vs Monitor roles. Keep cautious on which component spawns it.
    - IFEO effective for EXE not DLL (material).
    - HKLM hive requires Admin/SYSTEM (material).
    
    **Key Implementation Details**: No current implementation. Describe what an implementation would look like: persist/ifeo.rs module, wide-string registry writes via RegCreateKeyExW/RegSetValueExW (winapi patterns already used in edo_tensei.rs), target binary name, payload path; both variants behind feature gates; uninstall command per material's cleanup guidance.

    **Why It Matters**: Two distinct event-driven triggers (start vs exit) not covered by T-017's five layers (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist); registry-only setup beyond payload; survives reboot; no scheduler/service; Admin/SYSTEM-gated. 8-note cross-source signal with concrete registry sequence.

    **Detection Considerations**: Material does not discuss detection telemetry for this technique. It does note permission constraints (access denied for basic users on HKLM). Residual artifacts: the three documented registry modifications + IFEO Debugger value + on-disk payload binary path; material advises reversing registry modifications for cleanup (uninstall command in implant). Do not invent Sysmon IDs.

    **Related Techniques**: T-017 Five-Layer Persistence — IFEO is the sixth, event-driven layer not in the suite; shares HKLM registry-resident persistence model; Edo Tensei (T-018)? would_relate_to only lists T-017. The provided related card is only T-017. Rule 9: only cross-reference justified ones. T-017 only.

    **References**: Atlas material: atlas-edr-evasion-part2.md, atlas-methodology-part4.md, atlas-misc-part1.md, atlas-post-exploit-part7.md, atlas-post-exploit-part12.md, atlas-post-exploit-part15.md, atlas-labs-part1.md. MITRE: T1546.012 URL https://attack.mitre.org/techniques/T1546/012/. LGTM notes: the 8 IDs. Public references named in material: gflags.exe (Windows SDK), GflagsX by Pavel Yosifovich (github.com/zodiacon). Those are named in the atlas material, so legit.

    **Source Reference**: No current implementation. See atlas material and MITRE reference for public tooling.

19. **MITRE ID check**: T1546.012 "Event Triggered Execution: Image File Execution Options Injection" — format T1546.012. URL: https://attack.mitre.org/techniques/T1546/012/. Confident.

20. **Length**: target 1200-1800 words body. Let me draft with depth but no padding.

21. **Banned words check**: avoid "elegant", "clever", "textbook", "robust", "notable", "worth noting", "interestingly", "the key insight", "essentially", "at its core", "it is important to note". Avoid first person. No exclamation marks.

22. The h1 format: `# <Technique Name> — <One-Line Purpose>`. E.g., `# IFEO GlobalFlag and SilentProcessExit Registry Persistence — Event-driven registry persistence on process start and exit`.

Mechanism steps draft:

Variant A — Debugger (process-start trigger):
1. Operator selects a target image name (e.g., userinit.exe per material's rationale: starts early in boot / guaranteed to execute).
2. Create/open `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<ImageName>` (reg.exe or RegCreateKeyExA).
3. Set `Debugger` (REG_SZ) to the implant path.
4. On any subsequent launch of <ImageName>, the process-creation path reads IFEO, sees Debugger, and launches the implant instead, passing the original image path and command line as arguments. (Well-documented IFEO semantics.)
5. The Debugger-value binary receives the original command line; a passthrough/stub can chain-launch the real image to avoid breaking the user-visible workflow. Hmm — is passthrough in the material? Note 2 mentions "redirecting target executable launch to an attacker-specified Debugger binary". The material doesn't describe passthrough stubs. Avoid inventing; but the general IFEO Debugger behavior (debugger receives target command line) is well-established. I can state the argument-passing as documented behavior without prescribing a passthrough design. Careful: rule 3 says no variant ideas/suggestions. A passthrough is mechanism description, not a suggestion; but since material doesn't cover it, keep to one clause or omit. I'll state that Windows appends the original command line to the debugger invocation (documented IFEO behavior) — that's mechanism, factual.

Variant B — GlobalFlag + SilentProcessExit (process-exit trigger):
1. Set `GlobalFlag` (REG_DWORD) = 512 under the image's IFEO subkey (per material's reg.exe example).
2. Create `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<ImageName>`.
3. Set `ReportingMode` (REG_DWORD) = 1.
4. Set `MonitorProcess` (REG_SZ) = `"C:\Path\To\implant.exe"`.
5. When the watched image exits, the system launches the MonitorProcess command. Material roles: Image = process to watch; Monitor = watching process.

Setup routes (material): reg.exe interactive; Win32 Registry APIs (RegOpenKeyExA, RegCreateKeyExA, RegSetValueEx); gflags.exe GUI from Windows SDK (`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`); GflagsX (Pavel Yosifovich). Material: "Once you have an understanding you can programmatically implement many of these items on your own."

Permissions step: Admin or SYSTEM; basic users denied on HKLM (material).

Cleanup: reverse the registry modifications; material suggests building an uninstall command into the implant.

OS Internals draft:
- IFEO subtree: consulted whenever the process manager creates a process from an image name match. The key name is the image file name only (not full path). Debugger value semantics: the executive's process creation (via the image file execution options check in the create path) substitutes the debugger as the initial process image and appends the original command line. Documented in Windows Internals.
- GlobalFlag: per-image global flags; read at process creation and merged into PEB.NtGlobalFlag. Bit 512/0x200 corresponds to the silent-process-exit monitor flag (publicly documented as FLG_MONITOR_SILENT_PROCESS_EXIT). Because it is consumed at creation, the flag must be set before the target process starts; changes do not affect already-running instances. (This last clause — is it in material? It's inherent to PEB-merge behavior; well-established. I'll keep it as internals fact, phrased plainly.)
- Exit path: on process termination, the system checks the silent-process-exit monitor flag; if set it reads the SilentProcessExit\<image> key and, for ReportingMode=1, launches the MonitorProcess command line. Material does not specify which OS component performs the launch; do not fabricate — I can say "the monitoring facility handles the launch" — hmm. Actually I'll phrase: "the termination path hands the launch to the monitoring infrastructure" — no. Better: describe at the registry-contract level and explicitly state the material does not detail the spawning component. The MSDN page "Monitoring Silent Process Exit" documents this key for WER-era Windows (Vista+); the reporting goes through Windows Error Reporting service. I'm reasonably confident the launch is performed by the Windows Error Reporting service. But "reasonably confident" vs rule 4's bar... The MSDN doc "Monitoring Silent Process Exit" is real (it documents ReportingMode, MonitorProcess, DumpFolder, DumpType, MonitorCommandLine values) — it describes that WER launches the monitor. Given "well-established Windows internals documentation (Windows Internals 7ed, MSDN...)" is an allowed source, and the MSDN page is exactly this, I'll state: "the SilentProcessExit contract is documented by MSDN (Monitoring Silent Process Exit); the Windows Error Reporting service launches the configured monitor when the watched image exits without a fault." Hmm "without a fault" — silent exit means normal termination without crashing. The MSDN doc: "A silent process exit is when a process terminates without raising an exception" — monitored via this key. I think stating WER involvement is defensible but I'll keep it to one careful sentence and attribute to MSDN. Actually to be extra safe, I could write: "MSDN documents this contract under 'Monitoring Silent Process Exit' as part of the Windows Error Reporting reporting modes." That's accurate — the page exists and documents ReportingMode=1 as "launch a monitor process." Good.

- EXE vs DLL: IFEO matches image file name; material notes effectiveness is for EXE files rather than DLLs.
- Version note: Silent Process Exit monitoring exists since Windows Vista/7 era (MSDN "beginning with Windows 7" for the WER silent-exit monitoring? The MSDN page says "Beginning with Windows 7, you can monitor silent process exits."). The material doesn't discuss versions; MSDN does. One sentence OK.

Key Implementation Details: no implementation. One paragraph describing shape: `persist/ifeo.rs` alongside existing persist modules; wide-string RegCreateKeyExW/RegSetValueExW following the winapi pattern already present in `edo_tensei.rs` registry soul storage; target image name + payload path parameters; Debugger variant vs GlobalFlag/SilentProcessExit variant; Admin/SYSTEM check; uninstall routine per material's cleanup guidance. Since the source verification found no IFEO implementation in browser_hook.rs (registry persistence but browser-extension oriented: Run key, schtask, protocol handler — not IFEO), state that explicitly? The template says write the standard sentence then describe implementation shape. I'll mention that the included browser_hook.rs implements browser extension persistence (Run key/schtask/protocol handler) and does not implement IFEO — verification note. Good for rule 8 compliance.

Why It Matters: T-017 has five layers, all either boot/logon-triggered (schtask ONLOGON, COM hijack on object instantiation, TLS callback on DLL load, PhantomPersist on shutdown) — IFEO adds two per-process event triggers: process start (Debugger) and process exit (SilentProcessExit) of a chosen image. Registry-only configuration beyond the payload binary; no service, task, or WMI subscription. Survives reboot; Admin/SYSTEM gated. Eight member notes across five atlas batches — strong cross-source signal; the exit-trigger variant is the only exit-triggered persistence primitive in the vault (note 8).

Detection Considerations: 
"Training material does not discuss detection for this technique." Then: the material does document operational constraints and artifacts: (a) permission requirement (Admin/SYSTEM; access denied otherwise) — the limiting factor called out in the module summary; (b) residual artifacts inherent to the mechanism: `Debugger` value / `GlobalFlag` value under IFEO\<image>, `ReportingMode` + `MonitorProcess` under SilentProcessExit\<image>, and the on-disk payload binary path; (c) cleanup guidance: reverse the registry modifications; the material suggests building an uninstall command into the implant. Do NOT add Sysmon/ETW inventions. I must be careful: can I mention that these registry keys are visible to registry enumeration tools like Autoruns? The material doesn't say that for IFEO. T-017 mentions Autoruns for NTFS EA invisibility, but that's for EA, not IFEO. Don't import. Keep it to the artifacts themselves.

Related Techniques:
- T-017 Five-Layer Persistence with Resilience Monitor — IFEO Debugger/SilentProcessExit are the event-driven registry layers the suite lacks; same Admin/SYSTEM HKLM persistence class; T-017's resilience monitor pattern (reinstall every 30 min) would wrap these keys the same way. Careful about "would wrap" — that's a suggestion-ish phrasing. State relationship: complements T-017 with process-lifecycle triggers; no scheduler/service artifacts unlike T-017's schtask layer.

References:
- Atlas: atlas-edr-evasion-part2.md (units 7-14 gflags/IFEO GlobalFlag), atlas-methodology-part4.md (unit 9 TOC, IFEO section), atlas-misc-part1.md (units 2, 11, 28 IFEO roadmap/GlobalFlag/lab point), atlas-post-exploit-part7.md (units 13-27 IFEO module), atlas-post-exploit-part12.md (units 31-40), atlas-post-exploit-part15.md (units 8-15 IFEOPersisto lab), atlas-labs-part1.md (unit 36 SilentProcessExit review question).
- MITRE: T1546.012 URL; T1112 URL? Include secondary mapping URL maybe. The template: "MITRE ATT&CK: <T####.### with URL>". I'll give primary with URL; can add secondary line too.
- LGTM notes: 8 IDs.
- Public references named in material: gflags.exe (Windows SDK debugging tools), GflagsX — Pavel Yosifovich, https://github.com/zodiacon. Both named in the atlas material. Good.

Source Reference: "No current implementation. See atlas material and MITRE reference for public tooling."

Word count target 1200-1800. Let me now write it.

One more check on h1 and Summary first sentence standalone.

Also tags: need 5-10 kebab-case: [persistence, ifeo, silent-process-exit, globalflag, registry-persistence, debugger-hijack, event-driven, hklm, process-lifecycle] = 9 tags.

Frontmatter `mitre: T1546.012`, `mitre_secondary: [T1112]`.

Category enum: persistence ✓. Tier A ✓. crate: none. source_file: none.

Let me make sure the member_notes list is exact:
- lgtm:ifeo-silent-process-exit-persistence
- lgtm:ifeo-debugger-persistence
- lgtm:proposed-ifeo-persistence
- lgtm:ifeo-persistence-card
- lgtm:proposed-ifeo-persistence-suite
- lgtm:ifeo-silentprocessexit-persistence-card
- lgtm:silentprocessexit-trigger-persistence
- lgtm:proposed-silent-process-exit-persistence

Name in frontmatter: canonical "IFEO GlobalFlag and SilentProcessExit Registry Persistence".

Now the h1: `# IFEO GlobalFlag and SilentProcessExit Registry Persistence — Process start and exit triggers via the IFEO registry subtree`

Summary draft (3-5 sentences, first standalone):
"IFEO persistence converts two documented Windows debugging facilities into event-driven persistence: the Image File Execution Options Debugger value, which substitutes an attacker binary whenever a chosen image launches, and the GlobalFlag/SilentProcessExit pair, which executes a configured monitor command when a chosen image terminates. Both live entirely in the HKLM registry hive under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>` and the sibling `SilentProcessExit` key, so configuration survives reboot and requires no scheduler, service, or WMI subscription. Operators use the Debugger variant to catch process-start events (userinit.exe is the material's example target for boot-early execution) and the SilentProcessExit variant to catch process-exit events on a watched process. Setup is three registry writes (GlobalFlag=512, ReportingMode=1, MonitorProcess=<path>) or one (Debugger=<path>) via reg.exe or the Win32 Registry API, gated on Administrator or SYSTEM because basic users cannot modify the required HKLM keys. The training material does not discuss detection telemetry for this technique; the residual artifacts are the registry values themselves and the on-disk payload binary."

That's 5 sentences. Good.

Mechanism — numbered, concrete:

1. Select target image. The IFEO key matches on image file name only (not full path). Material rationale: choose a process that starts early in boot or is guaranteed to run — userinit.exe given as example; notes also mention accessibility binaries (sethc.exe, utilman.exe) and security tools as reusable targets. Wait, note 2 mentions sethc/utilman as reuse examples — that's from the LGTM note, which is part of the material (cluster spec). OK to cite.
2. Variant A: create IFEO subkey + Debugger value. Commands: `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>" /v Debugger /t REG_SZ /d "C:\Path\To\implant.exe"` — hmm, is the Debugger reg add line in the material? The material's reg.exe examples show GlobalFlag/ReportingMode/MonitorProcess only. The Debugger variant is described ("process start (debugger redirect on launch)", "redirects launches to malicious binary") but the exact reg command for Debugger isn't shown in the excerpts. I can describe it as: set the `Debugger` (REG_SZ) value under the image's IFEO subkey to the implant path — the value semantics are well-established (Windows Internals IFEO documentation). Fine.
3. Trigger A behavior: on every subsequent process creation for that image, the create path reads IFEO, finds Debugger, and launches the debugger binary in place of the image, appending the original image path and command line to the debugger's invocation. The intended image does not run unless the "debugger" chooses to run it.
4. Variant B step 1: `reg add HKLM\...\Image File Execution Options\<image> /v GlobalFlag /t REG_DWORD /d 512` (material verbatim).
5. Variant B step 2: `reg add HKLM\...\SilentProcessExit\<image> /v ReportingMode /t REG_DWORD /d 1`.
6. Variant B step 3: `reg add HKLM\...\SilentProcessExit\<image> /v MonitorProcess /d "C:\Path\To\implant.exe"`.
7. Trigger B behavior: when the watched image exits, the system honors the monitor contract and launches the MonitorProcess command line. Material's framing: Image is the process to watch; Monitor is the watching process.
8. Programmatic setup: same three/four writes via RegOpenKeyExA / RegCreateKeyExA / RegSetValueEx(ExA/ExW) (material lists these APIs); manual interactive shell via reg.exe (material); GUI route via gflags.exe from the Windows SDK at `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64` (material), or GflagsX (Pavel Yosifovich, named in material). Material states the GUI items can be implemented programmatically.
9. Permissions: Administrator or SYSTEM required; basic users are denied access to the HKLM keys (material: "we will be denied access when trying to modify the HKLM Registry keys").
10. Persistence properties: registry-resident; survives reboot; triggers on each future launch/exit of the watched image with no timer or scheduler component.
11. Cleanup: reverse the registry modifications; the material calls out cleanup during post-exploitation and suggests an uninstall command built into the implant to revert the changes.

That's a thorough mechanism. Maybe merge some steps to keep it tight but the template says don't truncate.

OS Internals Context draft:

- IFEO subtree contract: The Image File Execution Options key is a per-image-name options store read by the process-creation path. When a process is created, the system checks for a subkey matching the image file name and applies values found there (Debugger, GlobalFlag, and others). Material definition: "IFEO is a Windows Registry key that enables the debugging or tracing of a process when it is started... like having a debugger launch when the process does." The mechanism is effective for EXE images rather than DLLs (material).
- Debugger semantics: documented Windows behavior — when Debugger is present, the system launches the debugger image and passes the original image path and command line as arguments to it. This is the documented IFEO debugging contract being repurposed; the create call returns successfully while the attacker binary runs in place of the target.
- GlobalFlag merge: The GlobalFlag DWORD under an image's IFEO subkey carries the same FLG_* bit meanings as the system-wide NtGlobalFlag. At process creation these per-image bits are merged into the process's global flags (reflected in PEB.NtGlobalFlag), which is how gflags per-image settings take effect. 512 (0x200) is the silent-process-exit monitor bit, publicly documented as FLG_MONITOR_SILENT_PROCESS_EXIT. Because the merge happens at creation, the flag must be in place before the watched process starts; already-running instances are unaffected.
- Termination path: With the monitor bit set, process termination is treated as a reportable "silent exit" — a process that ends without a fault. The system then consults `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<image>`; ReportingMode=1 requests launch of the monitor, and MonitorProcess supplies the command line. MSDN documents this contract under "Monitoring Silent Process Exit" as a Windows Error Reporting reporting mode (available since Windows 7). The atlas material does not specify which component performs the spawn.
- Kernel/user boundary: configuration is pure registry I/O in user mode; consumption is split — IFEO Debugger handling and GlobalFlag merge occur in the create-process path, and the silent-exit check occurs in the termination path. No driver, hook, or in-memory patch is involved, which is why the technique needs only registry writes to deploy and only registry deletes to remove.
- HKLM hive security: the keys live under HKLM, whose default DACL grants write access to Administrators and SYSTEM only — the material's stated limiting factor.

Key Implementation Details: no implementation paragraph + note on browser_hook verification + implementation shape.

Detection: as drafted above.

Check banned words throughout. Also avoid "notable", "robust", etc. Avoid "worth noting". Use plain declaratives.

Length check: I think the draft will land ~1300-1600 words. Good.

One thing: the system prompt says for the Detection Considerations, "If the material does not cover detection for this technique, write: `Training material does not discuss detection for this technique.`" I'll include that exact sentence, then subsections on residual artifacts and operator constraints drawn from the material. Hmm — does adding subsections violate "Do not invent detections"? Residual artifacts = the registry keys/payload — these are the technique's own configuration data documented in the material; describing them as what remains on the host is factual. Cleanup guidance is in the material. Permission constraint is in the material. I'll frame under "Residual artifacts" and "Operator constraints from the material" without inventing telemetry. For "Telemetry sources" I'll write that the material does not document any. Actually to keep structure: three bullets: Telemetry sources: not discussed in material. Bypass options: not discussed (permissions noted as deployment constraint, not detection). Residual artifacts: keys + binary, per the material's own setup commands; cleanup per material. And the exact required sentence at the top.

Related Techniques: only T-017. One entry.

References list atlas files. All seven batches: atlas-edr-evasion-part2.md, atlas-methodology-part4.md, atlas-misc-part1.md, atlas-post-exploit-part7.md, atlas-post-exploit-part12.md, atlas-post-exploit-part15.md, atlas-labs-part1.md.

Public references: gflags.exe (Windows SDK Debugging Tools); GflagsX by Pavel Yosifovich — https://github.com/zodiacon (named in material). SEC670 Lab 4.3 IFEOPersisto is course material, belongs in atlas line context, not needed as separate ref.

Write the final file now. Ensure YAML validity: member_notes as flow list with quoted strings. tags flow list.

Also frontmatter `mitre_secondary: [T1112]`.

Double-check no banned phrase "it is important to note", "essentially", "at its core", "the key insight", "interestingly", "worth noting", "but wait", "as you can see". No first person. No exclamation marks. Word "slick/clean/elegant/beautiful/clever/textbook/impressive/neat/well-crafted/robust/solid/nice/brilliant/sophisticated/notable/remarkable" — avoid all. Careful with "clean" in "clean launch/cleanup" — "cleanup" contains "clean" but is a distinct standard term; the banned word is the adjective "clean" used as praise. "cleanup" should be acceptable as it's a standard ops term, but to be safe I could use "removal" mostly. The material itself says "cleaning up artifacts". I'll use "cleanup" sparingly — it's a noun for an ops phase, not praise. Acceptable.

Avoid ratings/percentages. No variant suggestions — the "implementation would look like" paragraph is required by template, that's fine, it's not a variant idea but the template-mandated future-implementation description.

Write it.
